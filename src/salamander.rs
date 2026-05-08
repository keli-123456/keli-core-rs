use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

const SALT_LEN: usize = 8;
const KEY_LEN: usize = 32;
const MIN_PSK_LEN: usize = 4;

type Blake2b256 = Blake2b<U32>;

#[derive(Debug)]
pub(crate) struct SalamanderUdpSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    psk: Arc<[u8]>,
}

impl SalamanderUdpSocket {
    pub(crate) fn new(
        inner: Arc<dyn quinn::AsyncUdpSocket>,
        psk: impl Into<Vec<u8>>,
    ) -> io::Result<Self> {
        let psk = psk.into();
        if psk.len() < MIN_PSK_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria2 salamander obfs password must be at least 4 bytes",
            ));
        }

        Ok(Self {
            inner,
            psk: psk.into(),
        })
    }
}

impl quinn::AsyncUdpSocket for SalamanderUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        if segment_size == 0 || segment_size >= transmit.contents.len() {
            let packet = obfuscate_packet(&self.psk, transmit.contents)?;
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
        let wrapped_segment_size = segment_size + SALT_LEN;
        let mut packet = Vec::with_capacity(transmit.contents.len() + segment_count * SALT_LEN);
        for chunk in transmit.contents.chunks(segment_size) {
            obfuscate_packet_into(&self.psk, chunk, &mut packet)?;
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
                    if !deobfuscate_meta(&self.psk, &mut bufs[index], &mut meta[index]) {
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

fn obfuscate_packet(psk: &[u8], input: &[u8]) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len() + SALT_LEN);
    obfuscate_packet_into(psk, input, &mut output)?;
    Ok(output)
}

fn obfuscate_packet_into(psk: &[u8], input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt)
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
    obfuscate_with_salt(psk, &salt, input, output);
    Ok(())
}

fn obfuscate_with_salt(psk: &[u8], salt: &[u8; SALT_LEN], input: &[u8], output: &mut Vec<u8>) {
    let key = salamander_key(psk, salt);
    output.extend_from_slice(salt);
    output.extend(
        input
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key[index % KEY_LEN]),
    );
}

fn deobfuscate_meta(
    psk: &[u8],
    buffer: &mut IoSliceMut<'_>,
    meta: &mut quinn::udp::RecvMeta,
) -> bool {
    if meta.len <= SALT_LEN {
        return false;
    }

    let stride = if meta.stride == 0 {
        meta.len
    } else {
        meta.stride
    };
    if stride <= SALT_LEN {
        return false;
    }

    let mut input_offset = 0usize;
    let mut output_offset = 0usize;
    let mut output_stride = 0usize;
    let mut segment_count = 0usize;
    while input_offset < meta.len {
        let packet_len = stride.min(meta.len - input_offset);
        if packet_len <= SALT_LEN {
            return false;
        }

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buffer[input_offset..input_offset + SALT_LEN]);
        let key = salamander_key(psk, &salt);
        let payload_len = packet_len - SALT_LEN;
        for index in 0..payload_len {
            buffer[output_offset + index] =
                buffer[input_offset + SALT_LEN + index] ^ key[index % KEY_LEN];
        }
        if segment_count == 0 {
            output_stride = payload_len;
        }
        segment_count += 1;
        input_offset += packet_len;
        output_offset += payload_len;
    }

    meta.len = output_offset;
    meta.stride = if segment_count <= 1 {
        output_offset
    } else {
        output_stride
    };
    true
}

fn salamander_key(psk: &[u8], salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
    let mut hasher = Blake2b256::new();
    hasher.update(psk);
    hasher.update(salt);
    let digest = hasher.finalize();
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&digest);
    key
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;

    #[test]
    fn salamander_round_trips_single_packet() {
        let psk = b"obfs-secret";
        let salt = [0, 1, 2, 3, 4, 5, 6, 7];
        let mut packet = Vec::new();
        obfuscate_with_salt(psk, &salt, b"hello-quic", &mut packet);

        assert_eq!(&packet[..SALT_LEN], &salt);
        assert_ne!(&packet[SALT_LEN..], b"hello-quic");

        let mut backing = packet;
        let mut iov = IoSliceMut::new(&mut backing);
        let mut meta = quinn::udp::RecvMeta {
            addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443).into(),
            len: SALT_LEN + b"hello-quic".len(),
            stride: SALT_LEN + b"hello-quic".len(),
            ecn: None,
            dst_ip: None,
        };

        assert!(deobfuscate_meta(psk, &mut iov, &mut meta));
        assert_eq!(meta.len, b"hello-quic".len());
        assert_eq!(&iov[..meta.len], b"hello-quic");
    }

    #[test]
    fn salamander_round_trips_segmented_packets() {
        let psk = b"obfs-secret";
        let first_salt = [0, 1, 2, 3, 4, 5, 6, 7];
        let second_salt = [7, 6, 5, 4, 3, 2, 1, 0];
        let mut packet = Vec::new();
        obfuscate_with_salt(psk, &first_salt, b"one", &mut packet);
        obfuscate_with_salt(psk, &second_salt, b"two", &mut packet);

        let mut backing = packet;
        let mut iov = IoSliceMut::new(&mut backing);
        let mut meta = quinn::udp::RecvMeta {
            addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443).into(),
            len: (SALT_LEN + 3) * 2,
            stride: SALT_LEN + 3,
            ecn: None,
            dst_ip: None,
        };

        assert!(deobfuscate_meta(psk, &mut iov, &mut meta));
        assert_eq!(meta.len, 6);
        assert_eq!(meta.stride, 3);
        assert_eq!(&iov[..meta.len], b"onetwo");
    }

    #[test]
    fn salamander_rejects_short_password() {
        let socket = Arc::new(NullUdpSocket) as Arc<dyn quinn::AsyncUdpSocket>;
        let error =
            SalamanderUdpSocket::new(socket, b"abc".to_vec()).expect_err("short psk should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[derive(Debug)]
    struct NullUdpSocket;

    impl quinn::AsyncUdpSocket for NullUdpSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
            Box::pin(NullPoller)
        }

        fn try_send(&self, _transmit: &quinn::udp::Transmit) -> io::Result<()> {
            Ok(())
        }

        fn poll_recv(
            &self,
            _cx: &mut Context,
            _bufs: &mut [IoSliceMut<'_>],
            _meta: &mut [quinn::udp::RecvMeta],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())
        }
    }

    #[derive(Debug)]
    struct NullPoller;

    impl quinn::UdpPoller for NullPoller {
        fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}
