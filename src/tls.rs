use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, ServerConnection};

use crate::limits::BandwidthLimiter;

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

            match self.connection.read_tls(&mut self.socket) {
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

    while !upload_done || !download_done {
        if limiter
            .as_deref()
            .map(BandwidthLimiter::is_revoked)
            .unwrap_or(false)
        {
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
                    let _ = client.close_notify_wait();
                    progressed = true;
                }
                Ok(read) => {
                    if let Some(limiter) = limiter.as_deref() {
                        if !limiter.wait_for(read) {
                            download_done = true;
                            let _ = client.close_notify_wait();
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
                    let _ = client.close_notify_wait();
                    progressed = true;
                }
            }
        }

        if !progressed {
            thread::sleep(Duration::from_millis(1));
        }
    }

    let _ = client.shutdown(Shutdown::Both);
    let _ = remote.shutdown(Shutdown::Both);
    Ok((upload, download))
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
    config.alpn_protocols = alpn.iter().map(|value| value.as_bytes().to_vec()).collect();
    Ok(config)
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

#[cfg(test)]
mod tests {
    use super::sni_matches;

    #[test]
    fn matches_exact_and_wildcard_sni() {
        assert!(sni_matches("node.example.test", "node.example.test"));
        assert!(sni_matches("node.example.test", "NODE.EXAMPLE.TEST"));
        assert!(sni_matches("*.example.test", "node.example.test"));
        assert!(!sni_matches("*.example.test", "example.test"));
        assert!(!sni_matches("node.example.test", "other.example.test"));
    }
}
