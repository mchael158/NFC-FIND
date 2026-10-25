//! NFC reader abstraction.
//!
//! A trait keeps the relay logic testable without hardware. The PC/SC backend
//! is feature-gated behind `pcsc-backend`.

use anyhow::Result;
use std::fmt;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Atr(pub Vec<u8>);

#[derive(Debug, Clone)]
pub struct Apdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: Option<u8>,
}

#[allow(dead_code)]
impl Apdu {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.cla, self.ins, self.p1, self.p2];
        if !self.data.is_empty() {
            out.push(self.data.len() as u8);
            out.extend_from_slice(&self.data);
        }
        if let Some(le) = self.le {
            out.push(le);
        }
        out
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Response {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl Response {
    #[allow(dead_code)]
    pub fn ok(&self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
    }
}

impl fmt::Display for Apdu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X} {:02X} {:02X} {:02X}", self.cla, self.ins, self.p1, self.p2)
    }
}

/// Minimal NFC reader interface used by the relay.
#[allow(dead_code)]
pub trait NfcReader: Send {
    fn connect(&mut self) -> Result<Atr>;
    fn transceive(&mut self, apdu: &Apdu) -> Result<Response>;
    fn disconnect(&mut self) -> Result<()>;
}

/// Mock reader for labs / tests: echoes a canned GET CHALLENGE style response.
pub struct MockReader;

impl NfcReader for MockReader {
    fn connect(&mut self) -> Result<Atr> {
        Ok(Atr(vec![0x3B, 0x8F, 0x80, 0x01]))
    }
    fn transceive(&mut self, apdu: &Apdu) -> Result<Response> {
        // Respond to GET CHALLENGE (INS 0x84) with 8 random bytes, mimicking a
        // real card. Other APDUs return 6D00 (INS not supported) like a real card.
        if apdu.ins == 0x84 {
            use rand::RngCore;
            let mut data = vec![0u8; apdu.le.unwrap_or(8) as usize];
            rand::thread_rng().fill_bytes(&mut data);
            return Ok(Response { data, sw1: 0x90, sw2: 0x00 });
        }
        Ok(Response {
            data: vec![],
            sw1: 0x6D,
            sw2: 0x00,
        })
    }
    fn disconnect(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apdu_to_bytes_case1_no_data_no_le() {
        let a = Apdu { cla: 0x00, ins: 0x84, p1: 0x00, p2: 0x00, data: vec![], le: None };
        assert_eq!(a.to_bytes(), vec![0x00, 0x84, 0x00, 0x00]);
    }

    #[test]
    fn apdu_to_bytes_case4_data_and_le() {
        let a = Apdu { cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00, data: b"AB".to_vec(), le: Some(0x00) };
        assert_eq!(a.to_bytes(), vec![0x00, 0xA4, 0x04, 0x00, 0x02, b'A', b'B', 0x00]);
    }

    #[test]
    fn mock_reader_get_challenge() {
        let mut r = MockReader;
        let atr = r.connect().unwrap();
        assert!(!atr.0.is_empty());
        let resp = r.transceive(&Apdu {
            cla: 0x00, ins: 0x84, p1: 0x00, p2: 0x00, data: vec![], le: Some(0x08),
        }).unwrap();
        assert!(resp.ok());
        assert_eq!(resp.data.len(), 8);
    }
}

#[cfg(feature = "pcsc-backend")]
pub mod pcsc_backend {
    use super::*;
    use pcsc::{Card, Context, Scope as PcscScope, ShareMode, Protocols};
    use anyhow::Context as _;

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
            let ctx = Context::establish(PcscScope::User)?;
            let readers = ctx.list_readers_owned()?;
            let reader = readers.first().context("no PC/SC reader found")?;
            let card = ctx.connect(reader, ShareMode::Shared, Protocols::T0 | Protocols::T1)?;
            let status = card.status2_owned()?;
            let atr = status.atr().to_vec();
            self.ctx = Some(ctx);
            self.card = Some(card);
            Ok(Atr(atr))
        }
        fn transceive(&mut self, apdu: &Apdu) -> Result<Response> {
            let card = self.card.as_mut().context("not connected")?;
            let mut buf = [0u8; 262];
            let resp = card.transmit(&apdu.to_bytes(), &mut buf)?;
            if resp.len() < 2 {
                anyhow::bail!("short response");
            }
            let (data, sw) = resp.split_at(resp.len() - 2);
            Ok(Response {
                data: data.to_vec(),
                sw1: sw[0],
                sw2: sw[1],
            })
        }
        fn disconnect(&mut self) -> Result<()> {
            if let Some(c) = self.card.take() {
                let _ = c.disconnect(pcsc::Disposition::LeaveCard);
            }
            self.ctx = None;
            Ok(())
        }
    }
}
