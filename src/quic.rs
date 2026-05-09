use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::{OutboundTlsConfig, OutboundTransportConfig};
use crate::socks5::SocksTarget;

const INTERNAL_QUIC_DOMAIN: &str = "quic.internal.v2fly.org";

pub(crate) fn connect_quic_client_stream(
    server: &SocksTarget,
    timeout: Duration,
    tls: Option<&OutboundTlsConfig>,
    transport: Option<&OutboundTransportConfig>,
) -> io::Result<TcpStream> {
    validate_plain_quic_transport(transport)?;

    let (ready_tx, ready_rx) = mpsc::channel();
    let local_listener = std::net::TcpListener::bind(std::net::SocketAddr::from((
        std::net::Ipv4Addr::LOCALHOST,
        0,
    )))?;
    let local_addr = local_listener.local_addr()?;
    let local_client = std::net::TcpStream::connect(local_addr)?;
    let (local_plain, _) = local_listener.accept()?;
    let server = server.clone();
    let tls = tls.cloned();

    thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = ready_tx.send(Err(io_other(error)));
                return;
            }
        };
        let result = runtime.block_on(run_quic_client(
            server,
            timeout,
            tls,
            local_plain,
            ready_tx.clone(),
        ));
        if let Err(error) = result {
            let _ = ready_tx.send(Err(error));
        }
    });

    match ready_rx.recv_timeout(timeout) {
        Ok(Ok(())) => Ok(local_client),
        Ok(Err(error)) => Err(error),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "quic outbound handshake timed out",
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "quic outbound worker exited before handshake",
        )),
    }
}

fn validate_plain_quic_transport(transport: Option<&OutboundTransportConfig>) -> io::Result<()> {
    let Some(transport) = transport else {
        return Ok(());
    };
    let security = transport
        .quic_security
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("none");
    if !security.eq_ignore_ascii_case("none") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("quic outbound security {security} is not supported yet"),
        ));
    }
    let header = transport
        .quic_header_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("none");
    if !header.eq_ignore_ascii_case("none") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("quic outbound header {header} is not supported yet"),
        ));
    }
    if transport
        .quic_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "quic outbound key is supported only with encrypted quic security",
        ));
    }
    Ok(())
}

async fn run_quic_client(
    server: SocksTarget,
    timeout: Duration,
    tls: Option<OutboundTlsConfig>,
    local_plain: TcpStream,
    ready_tx: mpsc::Sender<io::Result<()>>,
) -> io::Result<()> {
    let remote_addr =
        crate::dns::resolve_socket_addr_tokio(&server.host, server.port, timeout).await?;
    let local_addr = quic_local_addr(remote_addr);
    let mut endpoint = quinn::Endpoint::client(local_addr)?;
    let server_name = quic_server_name(&server, tls.as_ref())?;
    endpoint.set_default_client_config(quic_client_config(tls.as_ref())?);
    let connecting = endpoint
        .connect(remote_addr, &server_name)
        .map_err(io_other)?;
    let connection = tokio::time::timeout(timeout, connecting)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "quic handshake timed out"))?
        .map_err(io_other)?;
    let (mut send, mut recv) = tokio::time::timeout(timeout, connection.open_bi())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "quic stream open timed out"))?
        .map_err(io_other)?;

    let _ = ready_tx.send(Ok(()));
    local_plain.set_nonblocking(true)?;
    let local_plain = tokio::net::TcpStream::from_std(local_plain)?;
    let relay_result = relay_local_to_quic(local_plain, &mut recv, &mut send).await;
    endpoint.close(0u32.into(), b"done");
    relay_result
}

async fn relay_local_to_quic(
    local: tokio::net::TcpStream,
    recv: &mut quinn::RecvStream,
    send: &mut quinn::SendStream,
) -> io::Result<()> {
    let (mut local_read, mut local_write) = local.into_split();
    let upload = async {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = local_read.read(&mut buffer).await?;
            if read == 0 {
                let _ = send.finish();
                return Ok::<(), io::Error>(());
            }
            send.write_all(&buffer[..read]).await.map_err(io_other)?;
            send.flush().await.map_err(io_other)?;
        }
    };
    let download = async {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = recv.read(&mut buffer).await.map_err(io_other)?;
            let Some(read) = read else {
                let _ = local_write.shutdown().await;
                return Ok::<(), io::Error>(());
            };
            if read > 0 {
                local_write.write_all(&buffer[..read]).await?;
            }
        }
    };
    let (upload_result, download_result) = tokio::join!(upload, download);
    upload_result?;
    download_result
}

fn quic_client_config(tls: Option<&OutboundTlsConfig>) -> io::Result<quinn::ClientConfig> {
    let allow_insecure = tls.map(|tls| tls.allow_insecure).unwrap_or(true);
    let mut crypto = if allow_insecure {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    if let Some(tls) = tls {
        crypto.alpn_protocols = tls
            .alpn
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
    }
    QuicClientConfig::try_from(crypto)
        .map(|config| quinn::ClientConfig::new(Arc::new(config)))
        .map_err(io_other)
}

fn quic_server_name(server: &SocksTarget, tls: Option<&OutboundTlsConfig>) -> io::Result<String> {
    let value = tls
        .map(|tls| tls.server_name.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            if tls.is_some() {
                server.host.trim()
            } else {
                INTERNAL_QUIC_DOMAIN
            }
        })
        .trim_matches(['[', ']'])
        .to_string();
    ServerName::try_from(value.clone()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "quic tls server_name is invalid",
        )
    })?;
    Ok(value)
}

fn quic_local_addr(remote_addr: SocketAddr) -> SocketAddr {
    if remote_addr.is_ipv6() {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    }
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

fn io_other(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error.to_string())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::time::Duration;

    use quinn::crypto::rustls::QuicServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use crate::config::{OutboundTlsConfig, OutboundTransportConfig};
    use crate::quic::connect_quic_client_stream;
    use crate::socks5::SocksTarget;

    #[test]
    fn quic_client_relays_bidirectional_stream() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate cert");
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
        let server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server cert");
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_crypto).expect("quic server config"),
        ));
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let server_thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async move {
                let endpoint = quinn::Endpoint::server(
                    server_config,
                    "127.0.0.1:0".parse().expect("server addr"),
                )
                .expect("server endpoint");
                addr_tx
                    .send(endpoint.local_addr().expect("server local addr"))
                    .expect("send addr");
                let incoming = endpoint.accept().await.expect("incoming");
                let connection = incoming.await.expect("connection");
                let (mut send, mut recv) = connection.accept_bi().await.expect("stream");
                let mut payload = [0u8; 4];
                recv.read_exact(&mut payload).await.expect("read payload");
                assert_eq!(&payload, b"ping");
                send.write_all(b"pong").await.expect("write payload");
                let _ = send.finish();
                tokio::time::sleep(Duration::from_millis(50)).await;
                endpoint.close(0u32.into(), b"done");
            });
        });
        let addr = addr_rx.recv().expect("server addr");

        let outbound = OutboundTransportConfig {
            network: "quic".to_string(),
            quic_security: Some("none".to_string()),
            quic_header_type: Some("none".to_string()),
            ..OutboundTransportConfig::default()
        };
        let tls = OutboundTlsConfig {
            server_name: "localhost".to_string(),
            allow_insecure: true,
            alpn: Vec::new(),
        };
        let server = SocksTarget {
            host: addr.ip().to_string(),
            port: addr.port(),
        };
        let mut stream = connect_quic_client_stream(
            &server,
            Duration::from_secs(2),
            Some(&tls),
            Some(&outbound),
        )
        .expect("connect quic");
        stream.write_all(b"ping").expect("write quic");
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).expect("read quic");
        assert_eq!(&payload, b"pong");
        server_thread.join().expect("server thread");
    }

    #[test]
    fn quic_client_rejects_encrypted_security_until_wrapped_udp_exists() {
        let outbound = OutboundTransportConfig {
            network: "quic".to_string(),
            quic_security: Some("aes-128-gcm".to_string()),
            quic_header_type: Some("none".to_string()),
            ..OutboundTransportConfig::default()
        };
        let server = SocksTarget {
            host: "127.0.0.1".to_string(),
            port: 443,
        };
        let error =
            connect_quic_client_stream(&server, Duration::from_millis(10), None, Some(&outbound))
                .expect_err("encrypted quic is not native yet");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    }
}
