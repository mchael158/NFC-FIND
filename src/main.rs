#![cfg(feature = "cli")]

use nfc_find::core::*;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

use std::thread;
use std::time::{Duration, Instant};

// ---------- Transport impl ----------

struct StdTransport {
    stream: TcpStream,
}

impl StdTransport {
    fn new(stream: TcpStream) -> Self {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
        Self { stream }
    }
}

impl Transport for StdTransport {
    fn send(&mut self, data: &[u8]) -> Result<()> {
        self.stream.write_all(data).map_err(|_| Error::Io)?;
        self.stream.flush().map_err(|_| Error::Io)?;
        Ok(())
    }
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        use std::io::Read;
        self.stream.read(buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::TimedOut {
                Error::Timeout
            } else {
                Error::Io
            }
        })
    }
}

// ---------- NfcReader impls ----------

struct MockReader;

impl NfcReader for MockReader {
    fn connect(&mut self) -> Result<Atr> {
        Ok(Atr(vec![0x3B, 0x8F, 0x80, 0x01]))
    }
    fn transceive(&mut self, apdu: &Apdu) -> Result<Response> {
        if apdu.ins == 0x84 {
            use rand::RngCore;
            let mut data = vec![0u8; apdu.le.unwrap_or(8) as usize];
            rand::thread_rng().fill_bytes(&mut data);
            return Ok(Response { data, sw1: 0x90, sw2: 0x00 });
        }
        Ok(Response { data: vec![], sw1: 0x6D, sw2: 0x00 })
    }
}

#[cfg(feature = "pcsc-backend")]
mod pcsc_impl {
    use super::*;
    use nfc_find::core::{Atr, Apdu, Error, NfcReader, Response};
    use pcsc::{Card, Context, Scope as PcscScope, ShareMode, Protocols};

    pub struct PcscReader {
        ctx: Option<Context>,
        card: Option<Card>,
    }

    impl PcscReader {
        pub fn new() -> Self {
            Self { ctx: None, card: None }
        }
    }

    impl NfcReader for PcscReader {
        fn connect(&mut self) -> Result<Atr> {
            let ctx = Context::establish(PcscScope::User).map_err(|_| Error::Nfc)?;
            let readers = ctx.list_readers_owned().map_err(|_| Error::Nfc)?;
            let reader = readers.first().ok_or(Error::NotFound)?;
            let card = ctx.connect(reader, ShareMode::Shared, Protocols::T0 | Protocols::T1)
                .map_err(|_| Error::Nfc)?;
            let status = card.status2_owned().map_err(|_| Error::Nfc)?;
            let atr = status.atr().to_vec();
            self.ctx = Some(ctx);
            self.card = Some(card);
            Ok(Atr(atr))
        }
        fn transceive(&mut self, apdu: &Apdu) -> Result<Response> {
            let card = self.card.as_mut().ok_or(Error::Nfc)?;
            let mut buf = vec![0u8; 262];
            let resp = card.transmit(&apdu.to_bytes(), &mut buf).map_err(|_| Error::Nfc)?;
            if resp.len() < 2 {
                return Err(Error::Nfc);
            }
            let (data, sw) = resp.split_at(resp.len() - 2);
            Ok(Response {
                data: data.to_vec(),
                sw1: sw[0],
                sw2: sw[1],
            })
        }
    }
}

// ---------- CLI ----------

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "nfc-relay", about = "NFC relay prototype (authorized pentest only)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Reader {
        #[arg(long, default_value = "0.0.0.0:9876")]
        listen: String,
        #[arg(long)]
        use_pcsc: bool,
        #[arg(long)]
        log_file: Option<String>,
    },
    Terminal {
        #[arg(long, default_value = "127.0.0.1:9876")]
        backend: String,
        #[arg(long)]
        apdu_file: Option<String>,
    },
    Crc {
        #[arg(long)]
        hex: String,
    },
    Demo,
}

fn main() {
    // tracing not used; simple stderr logging via eprintln on errors
    let cli = Cli::parse();

    let scope = Scope {
        engagement: std::env::var("NFC_RELAY_ENGAGEMENT").unwrap_or_default(),
        target_environment: std::env::var("NFC_RELAY_ENV").unwrap_or_else(|_| "lab".into()),
        authorized: std::env::var("NFC_RELAY_AUTHORIZED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
            .unwrap_or(false),
    };

    if let Err(e) = run(cli, scope) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

/// Short APDU from the on-wire bytes: header, optional Lc+data, optional Le.
fn parse_apdu(bytes: &[u8]) -> Result<Apdu> {
    if bytes.len() < 4 {
        return Err(Error::InvalidInput);
    }
    let apdu = Apdu {
        cla: bytes[0],
        ins: bytes[1],
        p1: bytes[2],
        p2: bytes[3],
        data: Vec::new(),
        le: None,
    };
    if bytes.len() == 4 {
        return Ok(apdu);
    }
    if bytes.len() == 5 {
        return Ok(Apdu { le: Some(bytes[4]), ..apdu });
    }
    let lc = bytes[4] as usize;
    if lc == 0 {
        return Err(Error::InvalidInput);
    }
    let data_end = 5 + lc;
    if bytes.len() == data_end {
        return Ok(Apdu { data: bytes[5..data_end].to_vec(), ..apdu });
    }
    if bytes.len() == data_end + 1 {
        return Ok(Apdu {
            data: bytes[5..data_end].to_vec(),
            le: Some(bytes[data_end]),
            ..apdu
        });
    }
    Err(Error::InvalidInput)
}

fn run(cli: Cli, scope: Scope) -> Result<()> {
    match cli.cmd {
        Cmd::Reader { listen, use_pcsc, log_file } => {
            scope.require_authorized()?;
            let listener = TcpListener::bind(&listen).map_err(|_| Error::Io)?;
            println!("reader-side listening on {}", listen);
            let mode = if use_pcsc { "pcsc" } else { "mock" };
            println!("mode: {}", mode);

            for incoming in listener.incoming() {
                match incoming {
                    Ok(stream) => {
                        let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                        // avoid unwrap in peer_addr handling already defaulted
                        println!("terminal-side connected: {}", peer);
                        let mut transport = StdTransport::new(stream);
                        let log = log_file.clone();

                        #[cfg(feature = "pcsc-backend")]
                        let mut reader: Box<dyn NfcReader> = if use_pcsc {
                            Box::new(pcsc_impl::PcscReader::new())
                        } else {
                            Box::new(MockReader)
                        };
                        #[cfg(not(feature = "pcsc-backend"))]
                        let mut reader: Box<dyn NfcReader> = {
                            if use_pcsc {
                                eprintln!("pcsc-backend feature not enabled");
                                return Err(Error::InvalidInput);
                            }
                            Box::new(MockReader)
                        };

                        let eng = scope.engagement.clone();
                        let mut on_apdu = move |apdu: &Apdu, resp: &Response| {
                            println!("relay: {} -> {:02X}{:02X} ({} bytes)", apdu, resp.sw1, resp.sw2, resp.data.len());
                            if let Some(path) = &log {
                                use std::io::Write;
                                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                                    let _ = writeln!(f, "APDU {} -> {:02X}{:02X} {}", apdu, resp.sw1, resp.sw2, hex::encode(&resp.data));
                                }
                            }
                        };

                        // handshake
                        if let Err(e) = reader_handshake(&mut transport, &eng) {
                            eprintln!("handshake failed: {}", e);
                            continue;
                        }
                        // connect reader
                        if let Err(e) = reader.connect() {
                            eprintln!("reader connect failed: {}", e);
                            let _ = send_frame(&mut transport, &Frame::Bye);
                            continue;
                        }
                        let mut cb = Some(&mut on_apdu as &mut ApduCallback);
                        let _ = reader_loop(&mut *reader, &mut transport, &mut cb);
                    }
                    Err(e) => eprintln!("accept error: {}", e),
                }
            }
            Ok(())
        }
        Cmd::Terminal { backend, apdu_file } => {
            scope.require_authorized()?;
            // connect with retries
            let mut stream = None;
            for attempt in 1..=5 {
                match TcpStream::connect(&backend) {
                    Ok(s) => { stream = Some(s); break; }
                    Err(_) => {
                        eprintln!("connect attempt {} failed", attempt);
                        thread::sleep(Duration::from_secs(1));
                    }
                }
            }
            let stream = stream.ok_or(Error::Io)?;
            let mut transport = StdTransport::new(stream);

            terminal_handshake(&mut transport, &scope.engagement)?;

            // build probe list
            let probes: Vec<Apdu> = if let Some(path) = apdu_file {
                let file = std::fs::File::open(path).map_err(|_| Error::NotFound)?;
                let reader = BufReader::new(file);
                let mut out = Vec::new();
                for line in reader.lines() {
                    let line = line.map_err(|_| Error::Io)?;
                    let line = line.trim().to_string();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let clean: String = line.chars().filter(|c| !c.is_whitespace()).collect();
                    let bytes = hex::decode(&clean).map_err(|_| Error::InvalidInput)?;
                    out.push(parse_apdu(&bytes)?);
                }
                if out.is_empty() {
                    return Err(Error::InvalidInput);
                }
                out
            } else {
                vec![
                    Apdu { cla: 0x00, ins: 0x84, p1: 0x00, p2: 0x00, data: vec![], le: Some(0x08) },
                    Apdu { cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00, data: b"2PAY.SYS.DDF01".to_vec(), le: Some(0x00) },
                ]
            };

            for apdu in &probes {
                let t0 = Instant::now();
                let resp = terminal_step(&mut transport, apdu)?;
                let dt = t0.elapsed();
                println!("{} -> {:02X}{:02X} ({} bytes) in {:?}", apdu, resp.sw1, resp.sw2, resp.data.len(), dt);
            }
            let _ = send_frame(&mut transport, &Frame::Bye);
            Ok(())
        }
        Cmd::Crc { hex: h } => {
            let bytes = hex::decode(h.trim()).map_err(|_| Error::InvalidInput)?;
            let c = crc16_iso14443a(&bytes);
            println!("CRC-16/ISO14443-A = 0x{:04X}", c);
            Ok(())
        }
        Cmd::Demo => {
            scope.require_authorized()?;
            let addr = "127.0.0.1:19876";
            let listener = TcpListener::bind(addr).map_err(|_| Error::Io)?;
            println!("demo: reader-side listening on {}", addr);

            let handle = thread::spawn(move || {
                // reader in thread
                let scope = Scope {
                    engagement: std::env::var("NFC_RELAY_ENGAGEMENT").unwrap_or_else(|_| "demo".into()),
                    target_environment: "lab".into(),
                    authorized: true,
                };
                if let Ok(stream) = listener.accept().map(|(s, _)| s) {
                    let mut transport = StdTransport::new(stream);
                    let mut reader = MockReader;
                    let eng = scope.engagement.clone();
                    if reader_handshake(&mut transport, &eng).is_ok() && reader.connect().is_ok() {
                        let mut cb: Option<&mut ApduCallback> = None;
                        let _ = reader_loop(&mut reader, &mut transport, &mut cb);
                    }
                }
            });

            thread::sleep(Duration::from_millis(500));
            // terminal in main thread
            let stream = TcpStream::connect(addr).map_err(|_| Error::Io)?;
            let mut transport = StdTransport::new(stream);
            terminal_handshake(&mut transport, &scope.engagement)?;
            let probes = vec![
                Apdu { cla: 0x00, ins: 0x84, p1: 0x00, p2: 0x00, data: vec![], le: Some(0x08) },
                Apdu { cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00, data: b"2PAY.SYS.DDF01".to_vec(), le: Some(0x00) },
            ];
            for apdu in &probes {
                let t0 = Instant::now();
                let resp = terminal_step(&mut transport, apdu)?;
                println!("{} -> {:02X}{:02X} ({} bytes) in {:?}", apdu, resp.sw1, resp.sw2, resp.data.len(), t0.elapsed());
            }
            let _ = send_frame(&mut transport, &Frame::Bye);
            handle.join().ok();
            println!();
            println!("Demo complete: relay + mock card + terminal probes OK.");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_case2_get_challenge_keeps_le() {
        let bytes = hex::decode("0084000008").unwrap();
        let apdu = parse_apdu(&bytes).unwrap();
        assert!(apdu.data.is_empty());
        assert_eq!(apdu.le, Some(0x08));
        assert_eq!(apdu.to_bytes(), bytes);
    }

    #[test]
    fn parse_case3_select_ppse_keeps_lc_out_of_data() {
        let bytes = hex::decode("00A404000E325041592E5359532E4444463031").unwrap();
        let apdu = parse_apdu(&bytes).unwrap();
        assert_eq!(apdu.data, b"2PAY.SYS.DDF01");
        assert_eq!(apdu.le, None);
        assert_eq!(apdu.to_bytes(), bytes);
    }

    #[test]
    fn parse_case4_select_with_le() {
        let bytes = hex::decode("00A404000E325041592E5359532E444446303100").unwrap();
        let apdu = parse_apdu(&bytes).unwrap();
        assert_eq!(apdu.le, Some(0x00));
        assert_eq!(apdu.to_bytes(), bytes);
    }

    #[test]
    fn parse_rejects_truncated_data() {
        let bytes = hex::decode("00A404000E3250").unwrap();
        assert!(parse_apdu(&bytes).is_err());
    }
}
