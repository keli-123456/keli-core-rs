use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use sha2::{Digest, Sha256};

const QUIC_SALT: &[u8] = b"v2ray-quic-salt";

pub(crate) struct QuicPacketUdpSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    security: QuicPacketSecurity,
}

impl QuicPacketUdpSocket {
    pub(crate) fn new(inner: Arc<dyn quinn::AsyncUdpSocket>, security: QuicPacketSecurity) -> Self {
        Self { inner, security }
    }
}

impl fmt::Debug for QuicPacketUdpSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuicPacketUdpSocket")
            .field("security", &self.security.name())
            .finish_non_exhaustive()
    }
}

impl quinn::AsyncUdpSocket for QuicPacketUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        if segment_size == 0 || segment_size >= transmit.contents.len() {
            let packet = self.security.seal_packet(transmit.contents)?;
            let wrapped = quinn::udp::Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &packet,
                segment_size: None,
                src_ip: transmit.src_ip,
            };
            return self.inner.try_send(&wrapped);
        }

        let segment_count = transmit.contents.len().div_ceil(segment_size);
        let wrapped_segment_size = segment_size + self.security.packet_overhead();
        let mut packet = Vec::with_capacity(
            transmit.contents.len() + segment_count * self.security.packet_overhead(),
        );
        for chunk in transmit.contents.chunks(segment_size) {
            self.security.seal_packet_into(chunk, &mut packet)?;
        }
        let wrapped = quinn::udp::Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &packet,
            segment_size: Some(wrapped_segment_size),
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&wrapped)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(read)) => {
                for index in 0..read {
                    if !self.security.open_meta(&mut bufs[index], &mut meta[index]) {
                        meta[index].len = 0;
                        meta[index].stride = 0;
                    }
                }
                Poll::Ready(Ok(read))
            }
            other => other,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

pub(crate) enum QuicPacketSecurity {
    Aes128Gcm(Aes128Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl QuicPacketSecurity {
    pub(crate) fn from_name_and_key(security: &str, key: &str) -> io::Result<Option<Self>> {
        let security = security.trim().to_ascii_lowercase();
        if security.is_empty() || security == "none" {
            return Ok(None);
        }

        let digest = quic_packet_key(key);
        match security.as_str() {
            "aes-128-gcm" | "aes128-gcm" => {
                let cipher = Aes128Gcm::new_from_slice(&digest[..16]).map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
                })?;
                Ok(Some(Self::Aes128Gcm(cipher)))
            }
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => {
                let cipher = ChaCha20Poly1305::new_from_slice(&digest).map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
                })?;
                Ok(Some(Self::ChaCha20Poly1305(cipher)))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("quic outbound security {security} is not supported"),
            )),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Aes128Gcm(_) => "aes-128-gcm",
            Self::ChaCha20Poly1305(_) => "chacha20-poly1305",
        }
    }

    fn nonce_size(&self) -> usize {
        12
    }

    fn tag_size(&self) -> usize {
        16
    }

    fn packet_overhead(&self) -> usize {
        self.nonce_size() + self.tag_size()
    }

    fn seal_packet(&self, input: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(input.len() + self.packet_overhead());
        self.seal_packet_into(input, &mut output)?;
        Ok(output)
    }

    fn seal_packet_into(&self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
        output.extend_from_slice(&nonce);
        let encrypted = match self {
            Self::Aes128Gcm(cipher) => cipher
                .encrypt(AesNonce::from_slice(&nonce), input)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "quic packet seal failed")
                })?,
            Self::ChaCha20Poly1305(cipher) => cipher
                .encrypt(ChaChaNonce::from_slice(&nonce), input)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "quic packet seal failed")
                })?,
        };
        output.extend_from_slice(&encrypted);
        Ok(())
    }

    fn open_packet(&self, input: &[u8]) -> Option<Vec<u8>> {
        if input.len() <= self.packet_overhead() {
            return None;
        }
        let (nonce, payload) = input.split_at(self.nonce_size());
        match self {
            Self::Aes128Gcm(cipher) => cipher.decrypt(AesNonce::from_slice(nonce), payload).ok(),
            Self::ChaCha20Poly1305(cipher) => {
                cipher.decrypt(ChaChaNonce::from_slice(nonce), payload).ok()
            }
        }
    }

    fn open_meta(&self, buffer: &mut IoSliceMut<'_>, meta: &mut quinn::udp::RecvMeta) -> bool {
        let stride = if meta.stride == 0 {
            meta.len
        } else {
            meta.stride
        };
        if stride <= self.packet_overhead() {
            return false;
        }

        let mut input_offset = 0usize;
        let mut output_offset = 0usize;
        let mut output_stride = 0usize;
        let mut segment_count = 0usize;
        while input_offset < meta.len {
            let packet_len = stride.min(meta.len - input_offset);
            if packet_len <= self.packet_overhead() {
                return false;
            }

            let Some(plain) = self.open_packet(&buffer[input_offset..input_offset + packet_len])
            else {
                return false;
            };
            let plain_len = plain.len();
            buffer[output_offset..output_offset + plain_len].copy_from_slice(&plain);
            if segment_count == 0 {
                output_stride = plain_len;
            }
            segment_count += 1;
            input_offset += packet_len;
            output_offset += plain_len;
        }

        meta.len = output_offset;
        meta.stride = if segment_count <= 1 {
            output_offset
        } else {
            output_stride
        };
        true
    }
}

fn quic_packet_key(key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.update(QUIC_SALT);
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;

    #[test]
    fn aes128_gcm_packets_round_trip() {
        let security = QuicPacketSecurity::from_name_and_key("aes-128-gcm", "secret")
            .expect("security")
            .unwrap();
        let packet = security.seal_packet(b"hello-quic").expect("seal");
        assert_ne!(&packet[security.nonce_size()..], b"hello-quic");

        let mut backing = packet;
        let mut iov = IoSliceMut::new(&mut backing);
        let mut meta = quinn::udp::RecvMeta {
            addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443).into(),
            len: iov.len(),
            stride: iov.len(),
            ecn: None,
            dst_ip: None,
        };

        assert!(security.open_meta(&mut iov, &mut meta));
        assert_eq!(meta.len, b"hello-quic".len());
        assert_eq!(&iov[..meta.len], b"hello-quic");
    }

    #[test]
    fn chacha20_poly1305_packets_round_trip() {
        let security = QuicPacketSecurity::from_name_and_key("chacha20-poly1305", "secret")
            .expect("security")
            .unwrap();
        let packet = security.seal_packet(b"hello-quic").expect("seal");
        assert_eq!(security.open_packet(&packet).expect("open"), b"hello-quic");
    }

    #[test]
    fn packet_security_rejects_tampered_packets() {
        let security = QuicPacketSecurity::from_name_and_key("aes-128-gcm", "secret")
            .expect("security")
            .unwrap();
        let mut packet = security.seal_packet(b"hello-quic").expect("seal");
        let last = packet.len() - 1;
        packet[last] ^= 0x01;
        assert!(security.open_packet(&packet).is_none());
    }
}
