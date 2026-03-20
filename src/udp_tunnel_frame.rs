//! UDP-over-TCP tunnel framing protocol
//!
//! Binary frame format for tunneling UDP packets inside a TCP stream:
//!
//! ```text
//! +--------+------+----------+----------+---------+
//! | LEN(2) | ATYP | DST.ADDR | DST.PORT | PAYLOAD |
//! +--------+------+----------+----------+---------+
//! ```
//!
//! - LEN: 2 bytes, big-endian, total frame length after LEN field
//! - ATYP: 1 byte (0x01=IPv4, 0x04=IPv6)
//! - DST.ADDR: 4 bytes (IPv4) or 16 bytes (IPv6)
//! - DST.PORT: 2 bytes, big-endian
//! - PAYLOAD: remaining bytes
//!
//! For IPv4: header after LEN = 1+4+2 = 7 bytes
//! For IPv6: header after LEN = 1+16+2 = 19 bytes

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::{anyhow, Result};

/// SOCKS5 custom command for UDP tunnel
pub const SOCKS5_CMD_UDP_TUNNEL: u8 = 0x04;

/// Address type constants (same as SOCKS5)
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x04;

/// Maximum frame size: 65507 = 65535 - 20 (IP header) - 8 (UDP header),
/// the actual maximum UDP payload. Using a value strictly less than u16::MAX
/// ensures the guard `frame_len > MAX_FRAME_SIZE` can actually trigger.
const MAX_FRAME_SIZE: usize = 65507;

/// IPv4 header size after LEN: ATYP(1) + IPv4(4) + PORT(2) = 7
const IPV4_HEADER_SIZE: usize = 7;

/// IPv6 header size after LEN: ATYP(1) + IPv6(16) + PORT(2) = 19
const IPV6_HEADER_SIZE: usize = 19;

/// Read a UDP tunnel frame from a TCP stream.
///
/// Returns the destination address and the UDP payload.
/// Returns `Err` on EOF, malformed frame, or I/O error.
pub async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<(SocketAddr, Vec<u8>)> {
    // Read 2-byte length prefix
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await
        .map_err(|e| anyhow!("UDP tunnel frame: failed to read length: {}", e))?;
    let frame_len = u16::from_be_bytes(len_buf) as usize;

    if frame_len == 0 {
        return Err(anyhow!("UDP tunnel frame: zero-length frame"));
    }
    if frame_len > MAX_FRAME_SIZE {
        return Err(anyhow!("UDP tunnel frame: frame too large: {} bytes", frame_len));
    }

    // Read entire frame body
    let mut frame = vec![0u8; frame_len];
    reader.read_exact(&mut frame).await
        .map_err(|e| anyhow!("UDP tunnel frame: failed to read frame body ({} bytes): {}", frame_len, e))?;

    // Parse ATYP
    let atyp = frame[0];
    let (addr, header_size) = match atyp {
        ATYP_IPV4 => {
            if frame_len < IPV4_HEADER_SIZE {
                return Err(anyhow!("UDP tunnel frame: IPv4 frame too short: {} < {}", frame_len, IPV4_HEADER_SIZE));
            }
            let ip = Ipv4Addr::new(frame[1], frame[2], frame[3], frame[4]);
            let port = u16::from_be_bytes([frame[5], frame[6]]);
            (SocketAddr::new(IpAddr::V4(ip), port), IPV4_HEADER_SIZE)
        }
        ATYP_IPV6 => {
            if frame_len < IPV6_HEADER_SIZE {
                return Err(anyhow!("UDP tunnel frame: IPv6 frame too short: {} < {}", frame_len, IPV6_HEADER_SIZE));
            }
            let mut ipv6_bytes = [0u8; 16];
            ipv6_bytes.copy_from_slice(&frame[1..17]);
            let ip = Ipv6Addr::from(ipv6_bytes);
            let port = u16::from_be_bytes([frame[17], frame[18]]);
            (SocketAddr::new(IpAddr::V6(ip), port), IPV6_HEADER_SIZE)
        }
        _ => {
            return Err(anyhow!("UDP tunnel frame: unsupported ATYP: 0x{:02x}", atyp));
        }
    };

    let payload = frame[header_size..].to_vec();
    if payload.is_empty() {
        return Err(anyhow!("UDP tunnel frame: empty payload"));
    }

    Ok((addr, payload))
}

/// Write a UDP tunnel frame to a TCP stream.
///
/// Serializes the destination address and payload into the binary frame format.
pub async fn write_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    if payload.is_empty() {
        return Err(anyhow!("UDP tunnel frame: cannot write empty payload"));
    }

    let header_size = match addr {
        SocketAddr::V4(_) => IPV4_HEADER_SIZE,
        SocketAddr::V6(_) => IPV6_HEADER_SIZE,
    };

    let frame_len = header_size + payload.len();
    if frame_len > MAX_FRAME_SIZE {
        return Err(anyhow!("UDP tunnel frame: frame too large: {} bytes (max {})", frame_len, MAX_FRAME_SIZE));
    }

    // Build the complete frame: LEN + ATYP + ADDR + PORT + PAYLOAD
    let total_size = 2 + frame_len;
    let mut buf = Vec::with_capacity(total_size);

    // LEN prefix
    buf.extend_from_slice(&(frame_len as u16).to_be_bytes());

    // ATYP + ADDR + PORT
    match addr {
        SocketAddr::V4(v4) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
    }

    // PAYLOAD
    buf.extend_from_slice(payload);

    // Write entire frame atomically
    writer.write_all(&buf).await
        .map_err(|e| anyhow!("UDP tunnel frame: write failed: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn test_roundtrip_ipv4() {
        let addr = "1.2.3.4:1234".parse().unwrap();
        let payload = b"hello world";

        let mut buf = Vec::new();
        write_frame(&mut buf, addr, payload).await.unwrap();

        let mut reader = BufReader::new(&buf[..]);
        let (parsed_addr, parsed_payload) = read_frame(&mut reader).await.unwrap();

        assert_eq!(parsed_addr, addr);
        assert_eq!(&parsed_payload, payload);
    }

    #[tokio::test]
    async fn test_roundtrip_ipv6() {
        let addr = "[2001:db8::1]:443".parse().unwrap();
        let payload = b"test data";

        let mut buf = Vec::new();
        write_frame(&mut buf, addr, payload).await.unwrap();

        let mut reader = BufReader::new(&buf[..]);
        let (parsed_addr, parsed_payload) = read_frame(&mut reader).await.unwrap();

        assert_eq!(parsed_addr, addr);
        assert_eq!(&parsed_payload, payload);
    }

    #[tokio::test]
    async fn test_multiple_frames() {
        let mut buf = Vec::new();

        let addr1: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let addr2: SocketAddr = "[::1]:443".parse().unwrap();

        write_frame(&mut buf, addr1, b"first").await.unwrap();
        write_frame(&mut buf, addr2, b"second").await.unwrap();

        let mut reader = BufReader::new(&buf[..]);

        let (a1, p1) = read_frame(&mut reader).await.unwrap();
        assert_eq!(a1, addr1);
        assert_eq!(&p1, b"first");

        let (a2, p2) = read_frame(&mut reader).await.unwrap();
        assert_eq!(a2, addr2);
        assert_eq!(&p2, b"second");
    }
}
