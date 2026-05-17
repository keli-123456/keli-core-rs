use std::fs;
use std::io::{self, BufReader, Cursor, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey};
use rustls::{ServerConfig, ServerConnection, SignatureAlgorithm, SignatureScheme};

use crate::limits::BandwidthLimiter;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlsHandshakeErrorClass {
    ClientClosed,
    SniRejected,
    InvalidHandshake,
    Io,
}

#[derive(Clone)]
pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
}

pub trait TlsSocket: Read + Write {
    fn peer_addr(&self) -> io::Result<SocketAddr>;
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()>;
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;
}

impl TlsSocket for TcpStream {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::peer_addr(self)
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        TcpStream::set_nonblocking(self, nonblocking)
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        TcpStream::shutdown(self, how)
    }
}

pub struct TlsConnection<S = TcpStream> {
    socket: S,
    connection: ServerConnection,
    tls_record_buf: Vec<u8>,
    tls_record_target_len: Option<usize>,
}

impl TlsAcceptor {
    pub fn from_files(
        cert_file: impl AsRef<Path>,
        key_file: impl AsRef<Path>,
        alpn: &[String],
    ) -> io::Result<Self> {
        Self::from_files_with_sni_policy(cert_file, key_file, alpn, "", false)
    }

    pub fn from_files_with_sni_policy(
        cert_file: impl AsRef<Path>,
        key_file: impl AsRef<Path>,
        alpn: &[String],
        server_name: &str,
        reject_unknown_sni: bool,
    ) -> io::Result<Self> {
        let config =
            server_config_from_files(cert_file, key_file, alpn, server_name, reject_unknown_sni)?;

        Ok(Self {
            config: Arc::new(config),
        })
    }

    pub fn from_der(
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        alpn: &[String],
    ) -> io::Result<Self> {
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(tls_error)?;
        apply_server_security_defaults(&mut config);
        config.alpn_protocols = alpn.iter().map(|value| value.as_bytes().to_vec()).collect();
        Ok(Self {
            config: Arc::new(config),
        })
    }

    pub fn from_der_reality_ed25519(
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        alpn: &[String],
    ) -> io::Result<Self> {
        let builder = ServerConfig::builder().with_no_client_auth();
        let certified_key = reality_ed25519_certified_key(certs, key, builder.crypto_provider())?;
        let mut config =
            builder.with_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key)));
        apply_server_security_defaults(&mut config);
        config.alpn_protocols = alpn.iter().map(|value| value.as_bytes().to_vec()).collect();
        Ok(Self {
            config: Arc::new(config),
        })
    }

    pub fn accept(&self, socket: TcpStream) -> io::Result<TlsConnection> {
        self.accept_stream(socket)
    }

    pub fn accept_stream<S>(&self, socket: S) -> io::Result<TlsConnection<S>>
    where
        S: TlsSocket,
    {
        let mut connection = TlsConnection {
            socket,
            connection: ServerConnection::new(self.config.clone()).map_err(tls_error)?,
            tls_record_buf: Vec::new(),
            tls_record_target_len: None,
        };
        while connection.connection.is_handshaking() {
            connection
                .connection
                .complete_io(&mut connection.socket)
                .map_err(tls_error)?;
        }
        Ok(connection)
    }
}

impl<S> TlsConnection<S>
where
    S: TlsSocket,
{
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.socket.peer_addr()
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.socket.set_nonblocking(nonblocking)
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.socket.shutdown(how)
    }

    fn flush_tls(&mut self) -> io::Result<()> {
        while self.connection.wants_write() {
            match self.connection.write_tls(&mut self.socket) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "tls socket write returned zero",
                    ));
                }
                Ok(_) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn flush_tls_wait(&mut self) -> io::Result<()> {
        loop {
            match self.flush_tls() {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn write_plain_all_wait(&mut self, mut input: &[u8]) -> io::Result<()> {
        while !input.is_empty() {
            let written = self.connection.writer().write(input)?;
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "tls plaintext writer returned zero",
                ));
            }
            input = &input[written..];
            self.flush_tls_wait()?;
        }
        Ok(())
    }

    pub(crate) fn raw_read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.socket.read(output)
    }

    pub(crate) fn raw_write_all_wait(&mut self, mut input: &[u8]) -> io::Result<()> {
        while !input.is_empty() {
            match self.socket.write(input) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "raw tls socket write returned zero",
                    ));
                }
                Ok(written) => input = &input[written..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn read_tls_record_limited(&mut self) -> io::Result<usize> {
        const TLS_HEADER_LEN: usize = 5;
        const MAX_TLS_RECORD_LEN: usize = 18 * 1024;

        if self.tls_record_target_len.is_none() {
            while self.tls_record_buf.len() < TLS_HEADER_LEN {
                let mut chunk = [0u8; TLS_HEADER_LEN];
                let want = TLS_HEADER_LEN - self.tls_record_buf.len();
                match self.socket.read(&mut chunk[..want]) {
                    Ok(0) if self.tls_record_buf.is_empty() => return Ok(0),
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "tls socket closed during record header",
                        ));
                    }
                    Ok(read) => self.tls_record_buf.extend_from_slice(&chunk[..read]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        return Err(error);
                    }
                    Err(error) => return Err(error),
                }
            }

            let content_len =
                (usize::from(self.tls_record_buf[3]) << 8) | usize::from(self.tls_record_buf[4]);
            if content_len > MAX_TLS_RECORD_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("tls record too large: {content_len}"),
                ));
            }
            self.tls_record_target_len = Some(TLS_HEADER_LEN + content_len);
        }

        let target = self
            .tls_record_target_len
            .expect("target length initialized");
        while self.tls_record_buf.len() < target {
            let mut chunk = [0u8; 16 * 1024];
            let want = (target - self.tls_record_buf.len()).min(chunk.len());
            match self.socket.read(&mut chunk[..want]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "tls socket closed during record body",
                    ));
                }
                Ok(read) => self.tls_record_buf.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Err(error),
                Err(error) => return Err(error),
            }
        }

        self.tls_record_target_len = None;
        let record = std::mem::take(&mut self.tls_record_buf);
        let mut cursor = Cursor::new(record);
        self.connection.read_tls(&mut cursor)
    }

    pub(crate) fn close_notify_wait(&mut self) -> io::Result<()> {
        self.connection.send_close_notify();
        self.flush_tls_wait()
    }
}

impl<S> Read for TlsConnection<S>
where
    S: TlsSocket,
{
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }

        loop {
            match self.connection.reader().read(output) {
                Ok(0) => {}
                Ok(read) => return Ok(read),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }

            match self.read_tls_record_limited() {
                Ok(0) => return Ok(0),
                Ok(_) => {
                    self.connection.process_new_packets().map_err(tls_error)?;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Err(error),
                Err(error) => return Err(error),
            }
        }
    }
}

impl<S> Write for TlsConnection<S>
where
    S: TlsSocket,
{
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let written = self.connection.writer().write(input)?;
        self.flush_tls()?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_tls()
    }
}

pub fn relay_tls_stream<S>(
    mut client: TlsConnection<S>,
    mut remote: TcpStream,
    limiter: Option<Arc<BandwidthLimiter>>,
) -> io::Result<(u64, u64)>
where
    S: TlsSocket,
{
    client.set_nonblocking(true)?;
    remote.set_nonblocking(true)?;

    let mut upload = 0u64;
    let mut download = 0u64;
    let mut upload_done = false;
    let mut download_done = false;
    let mut client_buffer = [0u8; 16 * 1024];
    let mut remote_buffer = [0u8; 16 * 1024];
    let mut idle_rounds = 0u8;

    while !upload_done || !download_done {
        if limiter
            .as_deref()
            .map(BandwidthLimiter::is_revoked)
            .unwrap_or(false)
        {
            let _ = client.shutdown(Shutdown::Both);
            let _ = remote.shutdown(Shutdown::Both);
            break;
        }
        let mut progressed = false;

        if !upload_done {
            match client.read(&mut client_buffer) {
                Ok(0) => {
                    upload_done = true;
                    let _ = remote.shutdown(Shutdown::Write);
                    progressed = true;
                }
                Ok(read) => {
                    if let Some(limiter) = limiter.as_deref() {
                        if !limiter.wait_for(read) {
                            upload_done = true;
                            let _ = remote.shutdown(Shutdown::Write);
                            continue;
                        }
                    }
                    write_all_wait(&mut remote, &client_buffer[..read])?;
                    upload = upload.saturating_add(read as u64);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    upload_done = true;
                    let _ = remote.shutdown(Shutdown::Write);
                    progressed = true;
                }
            }
        }

        if !download_done {
            match remote.read(&mut remote_buffer) {
                Ok(0) => {
                    download_done = true;
                    upload_done = true;
                    let _ = client.shutdown(Shutdown::Both);
                    let _ = remote.shutdown(Shutdown::Both);
                    progressed = true;
                }
                Ok(read) => {
                    if let Some(limiter) = limiter.as_deref() {
                        if !limiter.wait_for(read) {
                            download_done = true;
                            upload_done = true;
                            let _ = client.shutdown(Shutdown::Both);
                            let _ = remote.shutdown(Shutdown::Both);
                            continue;
                        }
                    }
                    client.write_plain_all_wait(&remote_buffer[..read])?;
                    download = download.saturating_add(read as u64);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    download_done = true;
                    upload_done = true;
                    let _ = client.shutdown(Shutdown::Both);
                    let _ = remote.shutdown(Shutdown::Both);
                    progressed = true;
                }
            }
        }

        if !progressed {
            relay_idle_sleep(&mut idle_rounds);
        } else {
            idle_rounds = 0;
        }
    }

    let _ = client.shutdown(Shutdown::Both);
    let _ = remote.shutdown(Shutdown::Both);
    Ok((upload, download))
}

fn relay_idle_sleep(idle_rounds: &mut u8) {
    const BACKOFF_MS: [u64; 5] = [1, 2, 4, 8, 16];
    let idx = usize::from((*idle_rounds).min((BACKOFF_MS.len() - 1) as u8));
    thread::sleep(Duration::from_millis(BACKOFF_MS[idx]));
    *idle_rounds = idle_rounds
        .saturating_add(1)
        .min((BACKOFF_MS.len() - 1) as u8);
}

fn reality_ed25519_certified_key(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    provider: &rustls::crypto::CryptoProvider,
) -> io::Result<CertifiedKey> {
    let mut certified_key = CertifiedKey::from_der(certs, key, provider).map_err(tls_error)?;
    certified_key.key = Arc::new(RealityEd25519SigningKey {
        inner: certified_key.key.clone(),
    });
    Ok(certified_key)
}

#[derive(Debug)]
struct RealityEd25519SigningKey {
    inner: Arc<dyn SigningKey>,
}

impl SigningKey for RealityEd25519SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.inner
            .choose_scheme(offered)
            .or_else(|| self.inner.choose_scheme(&[SignatureScheme::ED25519]))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.inner.public_key()
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.inner.algorithm()
    }
}

fn write_all_wait(writer: &mut TcpStream, mut input: &[u8]) -> io::Result<()> {
    while !input.is_empty() {
        match writer.write(input) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "socket write returned zero",
                ));
            }
            Ok(written) => input = &input[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(crate) fn load_certs(path: impl AsRef<Path>) -> io::Result<Vec<CertificateDer<'static>>> {
    let bytes = fs::read(path.as_ref())?;
    let mut reader = BufReader::new(bytes.as_slice());
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls certificate file does not contain certificates",
        ));
    }
    Ok(certs)
}

pub(crate) fn load_private_key(path: impl AsRef<Path>) -> io::Result<PrivateKeyDer<'static>> {
    let bytes = fs::read(path.as_ref())?;
    let mut reader = BufReader::new(bytes.as_slice());
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls private key file does not contain a private key",
        )
    })
}

pub(crate) fn server_config_from_files(
    cert_file: impl AsRef<Path>,
    key_file: impl AsRef<Path>,
    alpn: &[String],
    server_name: &str,
    reject_unknown_sni: bool,
) -> io::Result<ServerConfig> {
    let certs = load_certs(cert_file)?;
    let key = load_private_key(key_file)?;
    let builder = ServerConfig::builder().with_no_client_auth();
    let mut config = if reject_unknown_sni {
        let server_name = server_name.trim();
        if server_name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reject_unknown_sni requires server_name",
            ));
        }
        let certified_key =
            CertifiedKey::from_der(certs, key, builder.crypto_provider()).map_err(tls_error)?;
        builder.with_cert_resolver(Arc::new(SniCertResolver {
            expected_name: server_name.to_ascii_lowercase(),
            certified_key: Arc::new(certified_key),
        }))
    } else {
        builder.with_single_cert(certs, key).map_err(tls_error)?
    };
    apply_server_security_defaults(&mut config);
    config.alpn_protocols = alpn.iter().map(|value| value.as_bytes().to_vec()).collect();
    Ok(config)
}

fn apply_server_security_defaults(config: &mut ServerConfig) {
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
}

#[derive(Debug)]
struct SniCertResolver {
    expected_name: String,
    certified_key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello.server_name()?;
        sni_matches(&self.expected_name, server_name).then(|| self.certified_key.clone())
    }
}

fn sni_matches(expected_name: &str, server_name: &str) -> bool {
    let server_name = server_name.trim().to_ascii_lowercase();
    if expected_name == server_name {
        return true;
    }
    let Some(suffix) = expected_name.strip_prefix("*.") else {
        return false;
    };
    server_name.len() > suffix.len()
        && server_name.ends_with(suffix)
        && server_name.as_bytes()[server_name.len() - suffix.len() - 1] == b'.'
}

fn tls_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

pub(crate) fn classify_tls_handshake_error(error: &io::Error) -> TlsHandshakeErrorClass {
    match error.kind() {
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe => TlsHandshakeErrorClass::ClientClosed,
        io::ErrorKind::InvalidData | io::ErrorKind::PermissionDenied => {
            let message = error.to_string().to_ascii_lowercase();
            if message.contains("no certificates available")
                || message.contains("certificate resolver")
                || message.contains("sni")
            {
                TlsHandshakeErrorClass::SniRejected
            } else {
                TlsHandshakeErrorClass::InvalidHandshake
            }
        }
        _ => TlsHandshakeErrorClass::Io,
    }
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::SignatureScheme;

    use crate::reality::generate_reality_temporary_certificate;

    use super::{
        classify_tls_handshake_error, reality_ed25519_certified_key, server_config_from_files,
        sni_matches, TlsHandshakeErrorClass,
    };

    #[test]
    fn matches_exact_and_wildcard_sni() {
        assert!(sni_matches("node.example.test", "node.example.test"));
        assert!(sni_matches("node.example.test", "NODE.EXAMPLE.TEST"));
        assert!(sni_matches("*.example.test", "node.example.test"));
        assert!(!sni_matches("*.example.test", "example.test"));
        assert!(!sni_matches("node.example.test", "other.example.test"));
    }

    #[test]
    fn reality_ed25519_key_falls_back_when_client_omits_ed25519_scheme() {
        let certificate = generate_reality_temporary_certificate(&[0x42; 32], "www.example.test")
            .expect("temporary certificate");
        let certified_key = reality_ed25519_certified_key(
            vec![CertificateDer::from(certificate.certificate_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificate.private_key_der)),
            &rustls::crypto::ring::default_provider(),
        )
        .expect("certified key");

        let signer = certified_key
            .key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .expect("fallback signer");

        assert_eq!(signer.scheme(), SignatureScheme::ED25519);
    }

    #[test]
    fn tls_server_config_disables_session_tickets_by_default() {
        let cert = generate_reality_temporary_certificate(&[0x24; 32], "tls.example.test")
            .expect("temporary certificate");
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir();
        let cert_path = dir.join(format!("keli-core-tls-ticket-{suffix}.crt"));
        let key_path = dir.join(format!("keli-core-tls-ticket-{suffix}.key"));
        std::fs::write(&cert_path, pem("CERTIFICATE", &cert.certificate_der)).expect("write cert");
        std::fs::write(&key_path, pem("PRIVATE KEY", &cert.private_key_der)).expect("write key");

        let config =
            server_config_from_files(&cert_path, &key_path, &[], "", false).expect("server config");
        assert!(!config.session_storage.can_cache());
        assert!(!config.ticketer.enabled());
        assert_eq!(config.send_tls13_tickets, 0);

        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(key_path);
    }

    #[test]
    fn classifies_tls_handshake_errors() {
        let closed = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "client closed");
        assert_eq!(
            classify_tls_handshake_error(&closed),
            TlsHandshakeErrorClass::ClientClosed
        );

        let sni = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no certificates available for SNI",
        );
        assert_eq!(
            classify_tls_handshake_error(&sni),
            TlsHandshakeErrorClass::SniRejected
        );

        let invalid = std::io::Error::new(std::io::ErrorKind::InvalidData, "bad record");
        assert_eq!(
            classify_tls_handshake_error(&invalid),
            TlsHandshakeErrorClass::InvalidHandshake
        );
    }

    fn pem(label: &str, der: &[u8]) -> String {
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, der);
        let mut body = String::new();
        for chunk in encoded.as_bytes().chunks(64) {
            body.push_str(std::str::from_utf8(chunk).expect("base64 utf8"));
            body.push('\n');
        }
        format!("-----BEGIN {label}-----\n{body}-----END {label}-----\n")
    }
}
