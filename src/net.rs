//! Relay transport: length-prefixed JSON frames over TCP.
//!
//! One side (reader-side) captures APDUs from the real card and forwards them;
//! the other (terminal-side) replays them against the payment terminal and
//! returns the responses.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

const IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Frame {
    Apdu { cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>, le: Option<u8> },
    Response { data: Vec<u8>, sw1: u8, sw2: u8 },
    Hello { engagement: String },
    Bye,
}

pub async fn send_frame<S>(stream: &mut S, frame: &Frame) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(frame)?;
    let len = payload.len() as u32;
    timeout(IO_TIMEOUT, async {
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&payload).await?;
        stream.flush().await?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("send timeout"))??;
    Ok(())
}

pub async fn recv_frame<S>(stream: &mut S) -> Result<Frame>
where
    S: tokio::io::AsyncRead + Unpin,
{
    timeout(IO_TIMEOUT, async {
        let mut lenbuf = [0u8; 4];
        stream.read_exact(&mut lenbuf).await?;
        let len = u32::from_be_bytes(lenbuf) as usize;
        if len > 1 << 20 {
            anyhow::bail!("frame too large: {}", len);
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        Ok::<Frame, anyhow::Error>(serde_json::from_slice(&buf)?)
    })
    .await
    .map_err(|_| anyhow::anyhow!("recv timeout"))?
}

pub async fn listen(addr: &str) -> Result<TcpListener> {
    Ok(TcpListener::bind(addr).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn frame_roundtrip() {
        let (mut a, mut b) = duplex(4096);
        let frame = Frame::Apdu {
            cla: 0x00, ins: 0x84, p1: 0x00, p2: 0x00, data: vec![1, 2, 3], le: Some(0x08),
        };
        send_frame(&mut a, &frame).await.unwrap();
        let got = recv_frame(&mut b).await.unwrap();
        match got {
            Frame::Apdu { cla, ins, data, le, .. } => {
                assert_eq!(cla, 0x00);
                assert_eq!(ins, 0x84);
                assert_eq!(data, vec![1, 2, 3]);
                assert_eq!(le, Some(0x08));
            }
            _ => panic!("wrong frame"),
        }
    }

    #[tokio::test]
    async fn hello_roundtrip() {
        let (mut a, mut b) = duplex(4096);
        send_frame(&mut a, &Frame::Hello { engagement: "eng".into() }).await.unwrap();
        let got = recv_frame(&mut b).await.unwrap();
        match got {
            Frame::Hello { engagement } => assert_eq!(engagement, "eng"),
            _ => panic!("wrong frame"),
        }
    }
}
