//! Relay orchestration.
//!
//! `reader_side`: connects to a real card via an NfcReader, accepts one or more
//! terminal-side connections, and forwards APDUs/responses between them.
//! `terminal_side`: drives a probe sequence against the reader-side and reports
//! per-APDU latency (useful for relay-detection research).

use crate::auth::Scope;
use crate::net::{self, Frame};
use crate::nfc::{Apdu, NfcReader};
use anyhow::Result;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

pub async fn reader_side<R>(
    reader: R,
    listen_addr: &str,
    scope: &Scope,
    log_file: Option<String>,
) -> Result<()>
where
    R: NfcReader + Send + 'static,
{
    scope.require_authorized()?;
    let reader = Arc::new(Mutex::new(reader));

    // Connect to the card once, off the async executor.
    {
        let r = reader.clone();
        tokio::task::spawn_blocking(move || {
            let mut g = r.blocking_lock();
            g.connect()
        })
        .await??;
    }

    let listener = net::listen(listen_addr).await?;
    tracing::info!("reader-side listening on {}", listen_addr);

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((mut sock, peer)) => {
                        tracing::info!("terminal-side connected: {}", peer);
                        let reader = reader.clone();
                        let engagement = scope.engagement.clone();
                        let log_file = log_file.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_terminal(&mut sock, reader, &engagement, log_file).await {
                                tracing::warn!("connection {} ended: {:#}", peer, e);
                            }
                            let _ = net::send_frame(&mut sock, &Frame::Bye).await;
                        });
                    }
                    Err(e) => tracing::warn!("accept error: {}", e),
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down reader-side");
                break;
            }
        }
    }
    Ok(())
}

async fn handle_terminal(
    sock: &mut TcpStream,
    reader: Arc<Mutex<impl NfcReader + 'static>>,
    expected_engagement: &str,
    log_file: Option<String>,
) -> Result<()> {
    // Handshake.
    match net::recv_frame(sock).await? {
        Frame::Hello { engagement } => {
            if engagement != expected_engagement {
                net::send_frame(sock, &Frame::Bye).await?;
                anyhow::bail!("engagement mismatch: got '{}', expected '{}'", engagement, expected_engagement);
            }
        }
        other => anyhow::bail!("expected Hello, got {:?}", other),
    }
    net::send_frame(sock, &Frame::Hello { engagement: expected_engagement.to_string() }).await?;

    loop {
        match net::recv_frame(sock).await? {
            Frame::Apdu { cla, ins, p1, p2, data, le } => {
                let apdu = Apdu { cla, ins, p1, p2, data, le };
                let r = reader.clone();
                let apdu_for_log = apdu.clone();
                let resp = tokio::task::spawn_blocking(move || {
                    let mut g = r.blocking_lock();
                    g.transceive(&apdu)
                })
                .await??;

                if let Some(path) = &log_file {
                    use std::io::Write;
                    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                        let _ = writeln!(
                            f,
                            "APDU {} -> {:02X}{:02X} {}",
                            apdu_for_log,
                            resp.sw1,
                            resp.sw2,
                            hex::encode(&resp.data)
                        );
                    }
                }

                tracing::info!(
                    "relay: {} -> {:02X}{:02X} ({} bytes)",
                    apdu_for_log, resp.sw1, resp.sw2, resp.data.len()
                );

                net::send_frame(sock, &Frame::Response {
                    data: resp.data,
                    sw1: resp.sw1,
                    sw2: resp.sw2,
                })
                .await?;
            }
            Frame::Bye => break,
            other => tracing::debug!("unexpected frame: {:?}", other),
        }
    }
    Ok(())
}

pub async fn terminal_side(backend_addr: &str, scope: &Scope, apdu_file: Option<String>) -> Result<()> {
    scope.require_authorized()?;
    let mut sock = None;
    for attempt in 1..=5 {
        match TcpStream::connect(backend_addr).await {
            Ok(s) => { sock = Some(s); break; }
            Err(e) => {
                tracing::warn!("connect attempt {} failed: {}", attempt, e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
    let mut sock = sock.ok_or_else(|| anyhow::anyhow!("could not connect to backend"))?;
    net::send_frame(&mut sock, &Frame::Hello { engagement: scope.engagement.clone() }).await?;
    match net::recv_frame(&mut sock).await? {
        Frame::Hello { engagement } => {
            if engagement != scope.engagement {
                anyhow::bail!("engagement mismatch from backend");
            }
        }
        other => anyhow::bail!("expected Hello ack, got {:?}", other),
    }

    let probes: Vec<Apdu> = if let Some(path) = apdu_file {
        let content = std::fs::read_to_string(&path)?;
        let mut out = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let bytes = hex::decode(line.replace(' ', "")).map_err(|e| anyhow::anyhow!("bad hex '{}': {}", line, e))?;
            if bytes.len() < 4 {
                anyhow::bail!("APDU too short: {}", line);
            }
            out.push(Apdu {
                cla: bytes[0],
                ins: bytes[1],
                p1: bytes[2],
                p2: bytes[3],
                data: bytes[4..].to_vec(),
                le: None,
            });
        }
        if out.is_empty() { anyhow::bail!("no APDUs in file"); }
        out
    } else {
        vec![
            Apdu { cla: 0x00, ins: 0x84, p1: 0x00, p2: 0x00, data: vec![], le: Some(0x08) },
            Apdu { cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00, data: b"2PAY.SYS.DDF01".to_vec(), le: Some(0x00) },
        ]
    };

    for apdu in &probes {
        let t0 = Instant::now();
        net::send_frame(&mut sock, &Frame::Apdu {
            cla: apdu.cla, ins: apdu.ins, p1: apdu.p1, p2: apdu.p2,
            data: apdu.data.clone(), le: apdu.le,
        }).await?;
        match net::recv_frame(&mut sock).await? {
            Frame::Response { data, sw1, sw2 } => {
                tracing::info!(
                    "{} -> {:02X}{:02X} ({} bytes) in {:?}",
                    apdu, sw1, sw2, data.len(), t0.elapsed()
                );
            }
            other => tracing::warn!("unexpected response: {:?}", other),
        }
    }

    net::send_frame(&mut sock, &Frame::Bye).await?;
    Ok(())
}

#[cfg(has_asm)]
extern "C" {
    #[link_name = "crc16_iso14443a"]
    fn crc16_iso14443a_ffi(data: *const u8, len: usize) -> u16;
}

/// CRC-16 / ISO 14443-3 Type A (assembly backend).
#[cfg(has_asm)]
pub fn crc16_iso14443a(data: &[u8]) -> u16 {
    unsafe { crc16_iso14443a_ffi(data.as_ptr(), data.len()) }
}

/// CRC-16 / ISO 14443-3 Type A (pure-Rust fallback).
#[cfg(not(has_asm))]
pub fn crc16_iso14443a(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x6363;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_empty() {
        assert_eq!(crc16_iso14443a(&[]), 0x6363);
    }

    #[test]
    fn crc_known_apdu() {
        let data = hex::decode("00a404000e325041592e5359532e4444463031").unwrap();
        assert_eq!(crc16_iso14443a(&data), 0x5D19);
    }

    #[test]
    fn crc_single_byte() {
        // Reference value computed by the Rust reference implementation.
        let mut crc: u16 = 0x6363;
        let b: u8 = 0x00;
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
        assert_eq!(crc16_iso14443a(&[0x00]), crc);
    }
}
