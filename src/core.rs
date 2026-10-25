use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

// ---------- Error ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Io,
    Timeout,
    FrameTooLarge,
    InvalidFrame,
    Auth,
    Nfc,
    InvalidInput,
    NotFound,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io => write!(f, "I/O error"),
            Error::Timeout => write!(f, "timeout"),
            Error::FrameTooLarge => write!(f, "frame too large"),
            Error::InvalidFrame => write!(f, "invalid frame"),
            Error::Auth => write!(f, "authorization error"),
            Error::Nfc => write!(f, "NFC error"),
            Error::InvalidInput => write!(f, "invalid input"),
            Error::NotFound => write!(f, "not found"),
        }
    }
}

pub type Result<T, E = Error> = ::core::result::Result<T, E>;

pub type ApduCallback = dyn FnMut(&Apdu, &Response);

// ---------- NFC types ----------

#[derive(Debug, Clone)]
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

impl Apdu {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.data.len() + 2);
        out.push(self.cla);
        out.push(self.ins);
        out.push(self.p1);
        out.push(self.p2);
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

impl fmt::Display for Apdu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X} {:02X} {:02X} {:02X}", self.cla, self.ins, self.p1, self.p2)
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl Response {
    pub fn ok(&self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
    }
}

pub trait NfcReader {
    fn connect(&mut self) -> Result<Atr>;
    fn transceive(&mut self, apdu: &Apdu) -> Result<Response>;
}

// ---------- Protocol frames ----------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Frame {
    Apdu {
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: Vec<u8>,
        le: Option<u8>,
    },
    Response {
        data: Vec<u8>,
        sw1: u8,
        sw2: u8,
    },
    Hello {
        engagement: String,
    },
    Bye,
}

impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>> {
        match serde_json::to_vec(self) {
            Ok(bytes) => Ok(bytes),
            Err(_) => Err(Error::InvalidFrame),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        match serde_json::from_slice(bytes) {
            Ok(frame) => Ok(frame),
            Err(_) => Err(Error::InvalidFrame),
        }
    }
}

// serde derives (manual via macros? use derive with feature). We'll implement
// Serialize/Deserialize manually is heavy; instead rely on serde derive below.
// The derive attributes are applied at the bottom via a separate impl block
// is not possible. We'll instead make Frame derive by adding attributes here.
// (Attributes must be on the enum definition; add them.)

// ---------- Transport trait ----------

pub trait Transport {
    fn send(&mut self, data: &[u8]) -> Result<()>;
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;

    fn recv_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        let mut off = 0;
        while off < buf.len() {
            let n = self.recv(&mut buf[off..])?;
            if n == 0 {
                return Err(Error::Io);
            }
            off += n;
        }
        Ok(())
    }
}

// ---------- Frame I/O over Transport ----------

pub fn send_frame<T: Transport>(transport: &mut T, frame: &Frame) -> Result<()> {
    let payload = frame.encode()?;
    let len = payload.len() as u32;
    let mut header = [0u8; 4];
    header[0] = (len >> 24) as u8;
    header[1] = (len >> 16) as u8;
    header[2] = (len >> 8) as u8;
    header[3] = len as u8;
    transport.send(&header)?;
    transport.send(&payload)?;
    Ok(())
}

pub fn recv_frame<T: Transport>(transport: &mut T) -> Result<Frame> {
    let mut header = [0u8; 4];
    transport.recv_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    if len > 1 << 20 {
        return Err(Error::FrameTooLarge);
    }
    let mut buf = alloc::vec![0u8; len];
    transport.recv_exact(&mut buf)?;
    Frame::decode(&buf)
}

// ---------- Scope ----------

#[derive(Debug, Clone)]
pub struct Scope {
    pub engagement: String,
    pub target_environment: String,
    pub authorized: bool,
}

impl Scope {
    pub fn require_authorized(&self) -> Result<()> {
        if !self.authorized {
            return Err(Error::Auth);
        }
        if self.engagement.trim().is_empty() {
            return Err(Error::Auth);
        }
        Ok(())
    }
}

// ---------- Relay logic (synchronous) ----------

pub fn reader_handshake<T: Transport>(
    transport: &mut T,
    expected_engagement: &str,
) -> Result<()> {
    match recv_frame(transport)? {
        Frame::Hello { engagement } => {
            if engagement != expected_engagement {
                let _ = send_frame(transport, &Frame::Bye);
                return Err(Error::Auth);
            }
        }
        _ => {
            let _ = send_frame(transport, &Frame::Bye);
            return Err(Error::InvalidFrame);
        }
    }
    send_frame(transport, &Frame::Hello {
        engagement: expected_engagement.into(),
    })?;
    Ok(())
}

pub fn reader_loop<T>(
    reader: &mut dyn NfcReader,
    transport: &mut T,
    on_apdu: &mut Option<&mut ApduCallback>,
) -> Result<()>
where
    T: Transport,
{
    loop {
        match recv_frame(transport) {
            Ok(Frame::Apdu { cla, ins, p1, p2, data, le }) => {
                let apdu = Apdu { cla, ins, p1, p2, data, le };
                let resp = reader.transceive(&apdu)?;
                if let Some(cb) = on_apdu.as_mut() {
                    cb(&apdu, &resp);
                }
                send_frame(transport, &Frame::Response {
                    data: resp.data,
                    sw1: resp.sw1,
                    sw2: resp.sw2,
                })?;
            }
            Ok(Frame::Bye) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = send_frame(transport, &Frame::Bye);
    Ok(())
}

pub fn terminal_handshake<T: Transport>(
    transport: &mut T,
    engagement: &str,
) -> Result<()> {
    send_frame(transport, &Frame::Hello {
        engagement: engagement.into(),
    })?;
    match recv_frame(transport)? {
        Frame::Hello { engagement: e } => {
            if e != engagement {
                return Err(Error::Auth);
            }
        }
        _ => return Err(Error::InvalidFrame),
    }
    Ok(())
}

pub fn terminal_step<T: Transport>(
    transport: &mut T,
    apdu: &Apdu,
) -> Result<Response> {
    send_frame(transport, &Frame::Apdu {
        cla: apdu.cla,
        ins: apdu.ins,
        p1: apdu.p1,
        p2: apdu.p2,
        data: apdu.data.clone(),
        le: apdu.le,
    })?;
    match recv_frame(transport)? {
        Frame::Response { data, sw1, sw2 } => Ok(Response { data, sw1, sw2 }),
        _ => Err(Error::InvalidFrame),
    }
}

// ---------- CRC ----------

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
    use alloc::vec;

    #[test]
    fn crc_empty() {
        assert_eq!(crc16_iso14443a(&[]), 0x6363);
    }

    #[test]
    fn crc_known() {
        let data = hex_decode("00a404000e325041592e5359532e4444463031");
        assert_eq!(crc16_iso14443a(&data), 0x5D19);
    }

    #[test]
    fn apdu_roundtrip() {
        let a = Apdu { cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00, data: vec![0xAB, 0xCD], le: Some(0x00) };
        let b = a.to_bytes();
        assert_eq!(b, vec![0x00, 0xA4, 0x04, 0x00, 0x02, 0xAB, 0xCD, 0x00]);
    }

    #[test]
    fn frame_roundtrip() {
        let f = Frame::Apdu { cla: 1, ins: 2, p1: 3, p2: 4, data: vec![5, 6], le: Some(7) };
        let enc = f.encode().unwrap();
        let dec = Frame::decode(&enc).unwrap();
        match dec {
            Frame::Apdu { cla, ins, p1, p2, data, le } => {
                assert_eq!((cla, ins, p1, p2), (1, 2, 3, 4));
                assert_eq!(data, vec![5, 6]);
                assert_eq!(le, Some(7));
            }
            _ => panic!("wrong variant"),
        }
    }

    // tiny hex decoder for tests (no hex crate in core)
    fn hex_decode(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let bytes = s.as_bytes();
        let mut i = 0;
        while i + 1 < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16).unwrap();
            let lo = (bytes[i + 1] as char).to_digit(16).unwrap();
            out.push(((hi << 4) | lo) as u8);
            i += 2;
        }
        out
    }
}
