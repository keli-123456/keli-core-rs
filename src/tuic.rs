use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn::crypto::rustls::QuicServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::limits::{
    BandwidthLimiter, UserBandwidthLimiters, UserSessionGuard, UserSessionTracker,
};
use crate::routing::{RouteDecision, RouteMatcher};
use crate::socks5::SocksTarget;
use crate::tls::{load_certs, load_private_key};
use crate::traffic::TrafficRegistry;
use crate::user::CoreUser;

const VERSION: u8 = 0x05;
const COMMAND_AUTHENTICATE: u8 = 0x00;
const COMMAND_CONNECT: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x02;

#[derive(Clone, Debug)]
pub struct TuicServerConfig {
    pub node_tag: String,
    pub listen: SocketAddr,
    pub users: Vec<CoreUser>,
    pub routes: Vec<crate::RouteRule>,
    pub cert_file: String,
    pub key_file: String,
    pub alpn: Vec<String>,
    pub connect_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct TuicServer {
    config: TuicServerConfig,
    users: Arc<HashMap<[u8; 16], CoreUser>>,
    router: RouteMatcher,
    traffic: Arc<Mutex<TrafficRegistry>>,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
}

impl TuicServer {
    pub fn new(config: TuicServerConfig) -> Self {
        Self::with_shared_limits(
            config,
            Arc::new(Mutex::new(TrafficRegistry::default())),
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        config: TuicServerConfig,
        traffic: Arc<Mutex<TrafficRegistry>>,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
    ) -> Self {
        let users = config
            .users
            .iter()
            .filter_map(|user| {
                parse_uuid_bytes(&user.uuid)
                    .ok()
                    .map(|uuid| (uuid, user.clone()))
            })
            .collect();
        Self {
            router: RouteMatcher::new(config.routes.clone()),
            config,
            users: Arc::new(users),
            traffic,
            sessions,
            bandwidth,
        }
    }

    pub fn bind(&self) -> io::Result<quinn::Endpoint> {
        let certs = load_certs(&self.config.cert_file)?;
        let key = load_private_key(&self.config.key_file)?;
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(io_other)?;
        let alpn = if self.config.alpn.is_empty() {
            vec!["h3".to_string()]
        } else {
            self.config.alpn.clone()
        };
        server_crypto.alpn_protocols = alpn.iter().map(|value| value.as_bytes().to_vec()).collect();
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_crypto).map_err(io_other)?,
        ));
        quinn::Endpoint::server(server_config, self.config.listen)
    }

    pub async fn run(self, endpoint: quinn::Endpoint, stop: Arc<AtomicBool>) {
        loop {
            if stop.load(Ordering::SeqCst) {
                endpoint.close(0u32.into(), b"shutdown");
                break;
            }
            tokio::select! {
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break;
                    };
                    let server = self.clone();
                    tokio::spawn(async move {
                        let _ = server.handle_incoming(incoming).await;
                    });
                }
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
        endpoint.wait_idle().await;
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<crate::traffic::TrafficDelta> {
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .drain_minimum(minimum_bytes)
    }

    async fn handle_incoming(&self, incoming: quinn::Incoming) -> io::Result<()> {
        let connection = incoming.await.map_err(io_other)?;
        let mut auth_stream = connection.accept_uni().await.map_err(io_other)?;
        let user = self.authenticate(&connection, &mut auth_stream).await?;
        let _session = self.acquire_user_session(&user)?;
        let bandwidth = self.bandwidth.limiter_for(Some(&user));

        loop {
            match connection.accept_bi().await {
                Ok(stream) => {
                    let server = self.clone();
                    let user_uuid = user.uuid.clone();
                    let bandwidth = bandwidth.clone();
                    tokio::spawn(async move {
                        let _ = server
                            .handle_connect_stream(stream, user_uuid, bandwidth)
                            .await;
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. })
                | Err(quinn::ConnectionError::LocallyClosed)
                | Err(quinn::ConnectionError::ConnectionClosed(_)) => return Ok(()),
                Err(error) => return Err(io_other(error)),
            }
        }
    }

    async fn authenticate(
        &self,
        connection: &quinn::Connection,
        stream: &mut quinn::RecvStream,
    ) -> io::Result<CoreUser> {
        let mut header = [0u8; 2];
        read_exact(stream, &mut header).await?;
        if header != [VERSION, COMMAND_AUTHENTICATE] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid tuic authentication command",
            ));
        }
        let mut uuid = [0u8; 16];
        let mut token = [0u8; 32];
        read_exact(stream, &mut uuid).await?;
        read_exact(stream, &mut token).await?;

        let Some(user) = self.users.get(&uuid) else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unknown tuic user",
            ));
        };
        if !tuic_token_matches(connection, &uuid, user.credential(), &token)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid tuic token",
            ));
        }
        Ok(user.clone())
    }

    async fn handle_connect_stream(
        &self,
        (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
        user_uuid: String,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        let mut header = [0u8; 2];
        read_exact(&mut recv, &mut header).await?;
        if header != [VERSION, COMMAND_CONNECT] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid tuic connect command",
            ));
        }
        let target = read_address(&mut recv).await?;
        match self.router.decide(&target.host) {
            RouteDecision::Direct => {}
            RouteDecision::Block | RouteDecision::UnsupportedOutbound(_) => return Ok(()),
        }

        let remote = tokio::time::timeout(
            self.config.connect_timeout,
            tokio::net::TcpStream::connect((target.host.as_str(), target.port)),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "target connect timed out"))??;
        let (upload, download) = relay_streams(&mut recv, &mut send, remote, bandwidth).await?;
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .add(self.config.node_tag.clone(), user_uuid, upload, download);
        Ok(())
    }

    fn acquire_user_session(&self, user: &CoreUser) -> io::Result<Option<UserSessionGuard>> {
        self.sessions
            .try_acquire(Some(user))
            .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))
    }
}

async fn relay_streams(
    recv: &mut quinn::RecvStream,
    send: &mut quinn::SendStream,
    remote: tokio::net::TcpStream,
    bandwidth: Option<Arc<BandwidthLimiter>>,
) -> io::Result<(u64, u64)> {
    let (mut remote_read, mut remote_write) = remote.into_split();
    let upload = async {
        let mut total = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = recv.read(&mut buffer).await.map_err(io_other)?;
            let Some(read) = read else {
                let _ = remote_write.shutdown().await;
                return Ok::<u64, io::Error>(total);
            };
            if let Some(limiter) = bandwidth.as_deref() {
                limiter.wait_for(read);
            }
            remote_write.write_all(&buffer[..read]).await?;
            total = total.saturating_add(read as u64);
        }
    };
    let download = async {
        let mut total = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = remote_read.read(&mut buffer).await?;
            if read == 0 {
                let _ = send.finish();
                return Ok::<u64, io::Error>(total);
            }
            send.write_all(&buffer[..read]).await.map_err(io_other)?;
            total = total.saturating_add(read as u64);
        }
    };
    tokio::try_join!(upload, download)
}

async fn read_address(stream: &mut quinn::RecvStream) -> io::Result<SocksTarget> {
    let mut atyp = [0u8; 1];
    read_exact(stream, &mut atyp).await?;
    match atyp[0] {
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len).await?;
            let mut host = vec![0u8; len[0] as usize];
            read_exact(stream, &mut host).await?;
            let host = String::from_utf8(host)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid tuic domain"))?;
            let port = read_port(stream).await?;
            Ok(SocksTarget { host, port })
        }
        ATYP_IPV4 => {
            let mut bytes = [0u8; 4];
            read_exact(stream, &mut bytes).await?;
            let port = read_port(stream).await?;
            Ok(SocksTarget {
                host: Ipv4Addr::from(bytes).to_string(),
                port,
            })
        }
        ATYP_IPV6 => {
            let mut bytes = [0u8; 16];
            read_exact(stream, &mut bytes).await?;
            let port = read_port(stream).await?;
            Ok(SocksTarget {
                host: Ipv6Addr::from(bytes).to_string(),
                port,
            })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported tuic address type",
        )),
    }
}

async fn read_port(stream: &mut quinn::RecvStream) -> io::Result<u16> {
    let mut bytes = [0u8; 2];
    read_exact(stream, &mut bytes).await?;
    Ok(u16::from_be_bytes(bytes))
}

async fn read_exact(stream: &mut quinn::RecvStream, output: &mut [u8]) -> io::Result<()> {
    stream.read_exact(output).await.map_err(io_other)
}

fn tuic_token_matches(
    connection: &quinn::Connection,
    uuid: &[u8; 16],
    credential: &str,
    token: &[u8; 32],
) -> io::Result<bool> {
    let mut expected = [0u8; 32];
    connection
        .export_keying_material(&mut expected, uuid, credential.as_bytes())
        .map_err(io_other)?;
    Ok(expected == *token)
}

fn parse_uuid_bytes(value: &str) -> io::Result<[u8; 16]> {
    let compact = value
        .chars()
        .filter(|value| *value != '-')
        .collect::<String>();
    if compact.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tuic user uuid must be 16 bytes",
        ));
    }
    let mut output = [0u8; 16];
    for index in 0..16 {
        output[index] =
            u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "tuic user uuid is invalid")
            })?;
    }
    Ok(output)
}

fn io_other(error: impl std::fmt::Debug) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{error:?}"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicBool;
    use std::time::{SystemTime, UNIX_EPOCH};

    use quinn::crypto::rustls::QuicClientConfig;
    use rustls::pki_types::CertificateDer;

    use super::*;

    struct TestCert {
        cert_path: PathBuf,
        key_path: PathBuf,
        cert_der: CertificateDer<'static>,
    }

    impl Drop for TestCert {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.cert_path);
            let _ = fs::remove_file(&self.key_path);
        }
    }

    fn test_cert(label: &str) -> TestCert {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self signed cert");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir();
        let cert_path = dir.join(format!("keli-core-rs-tuic-{label}-{nanos}.crt"));
        let key_path = dir.join(format!("keli-core-rs-tuic-{label}-{nanos}.key"));
        fs::write(&cert_path, cert.cert.pem()).expect("write cert");
        fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
        TestCert {
            cert_path,
            key_path,
            cert_der: cert.cert.der().clone(),
        }
    }

    fn user() -> CoreUser {
        CoreUser {
            id: 1,
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            password: Some("tuic-password".to_string()),
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    fn client_endpoint(cert_der: CertificateDer<'static>) -> quinn::Endpoint {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).expect("root cert");
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        endpoint
    }

    fn tuic_server(cert: &TestCert, listen: SocketAddr) -> TuicServer {
        TuicServer::new(TuicServerConfig {
            node_tag: "panel|tuic|1".to_string(),
            listen,
            users: vec![user()],
            routes: Vec::new(),
            cert_file: cert.cert_path.to_string_lossy().to_string(),
            key_file: cert.key_path.to_string_lossy().to_string(),
            alpn: vec!["h3".to_string()],
            connect_timeout: Duration::from_secs(3),
        })
    }

    fn auth_command(connection: &quinn::Connection) -> Vec<u8> {
        let uuid = parse_uuid_bytes(&user().uuid).expect("uuid");
        let mut token = [0u8; 32];
        connection
            .export_keying_material(&mut token, &uuid, b"tuic-password")
            .expect("token");
        let mut command = vec![VERSION, COMMAND_AUTHENTICATE];
        command.extend_from_slice(&uuid);
        command.extend_from_slice(&token);
        command
    }

    fn connect_command(addr: SocketAddr) -> Vec<u8> {
        let mut command = vec![VERSION, COMMAND_CONNECT, ATYP_IPV4];
        let ip = match addr.ip() {
            std::net::IpAddr::V4(ip) => ip,
            std::net::IpAddr::V6(_) => Ipv4Addr::LOCALHOST,
        };
        command.extend_from_slice(&ip.octets());
        command.extend_from_slice(&addr.port().to_be_bytes());
        command
    }

    #[test]
    fn parses_uuid_bytes() {
        assert_eq!(
            parse_uuid_bytes("11111111-1111-1111-1111-111111111111").unwrap(),
            [0x11; 16]
        );
    }

    #[test]
    fn proxies_tuic_tcp_and_records_user_traffic() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let cert = test_cert("tcp");
            let echo = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("echo bind");
            let echo_addr = echo.local_addr().expect("echo addr");
            let echo_task = tokio::spawn(async move {
                let (mut stream, _) = echo.accept().await.expect("echo accept");
                let mut bytes = [0u8; 4];
                stream.read_exact(&mut bytes).await.expect("echo read");
                stream.write_all(&bytes).await.expect("echo write");
            });

            let server = tuic_server(&cert, "127.0.0.1:0".parse().unwrap());
            let endpoint = server.bind().expect("tuic bind");
            let server_addr = endpoint.local_addr().expect("server addr");
            let stop = Arc::new(AtomicBool::new(false));
            let server_task = tokio::spawn(server.clone().run(endpoint, stop.clone()));

            let client_endpoint = client_endpoint(cert.cert_der.clone());
            let connection = client_endpoint
                .connect(server_addr, "localhost")
                .expect("connect")
                .await
                .expect("connection");
            let mut auth = connection.open_uni().await.expect("auth stream");
            auth.write_all(&auth_command(&connection))
                .await
                .expect("auth write");
            auth.finish().expect("auth finish");

            let (mut send, mut recv) = connection.open_bi().await.expect("connect stream");
            send.write_all(&connect_command(echo_addr))
                .await
                .expect("connect command");
            send.write_all(b"ping").await.expect("payload");
            send.finish().expect("finish payload");
            let mut echoed = [0u8; 4];
            recv.read_exact(&mut echoed).await.expect("echoed payload");
            assert_eq!(&echoed, b"ping");
            connection.close(0u32.into(), b"done");
            echo_task.await.expect("echo task");

            tokio::time::sleep(Duration::from_millis(50)).await;
            let records = server.drain_traffic(1);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].node_tag, "panel|tuic|1");
            assert_eq!(records[0].user_uuid, "11111111-1111-1111-1111-111111111111");
            assert_eq!(records[0].upload, 4);
            assert_eq!(records[0].download, 4);

            stop.store(true, Ordering::SeqCst);
            server_task.await.expect("server task");
        });
    }
}
