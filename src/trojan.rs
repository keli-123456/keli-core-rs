use std::collections::HashMap;
use std::io::{self, Read};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha224};

use crate::limits::{
    BandwidthLimiter, UserBandwidthLimiters, UserSessionGuard, UserSessionTracker,
};
use crate::socks5::SocksTarget;
use crate::stream::relay_tcp_streams_limited;
use crate::traffic::TrafficRegistry;
use crate::user::CoreUser;
use crate::{RouteDecision, RouteMatcher};

const COMMAND_TCP: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const TROJAN_PASSWORD_HEX_LEN: usize = 56;

#[derive(Clone, Debug)]
pub struct TrojanServerConfig {
    pub node_tag: String,
    pub listen: SocketAddr,
    pub users: Vec<CoreUser>,
    pub routes: Vec<crate::RouteRule>,
    pub connect_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct TrojanServer {
    config: TrojanServerConfig,
    users: Arc<HashMap<String, CoreUser>>,
    router: RouteMatcher,
    traffic: Arc<Mutex<TrafficRegistry>>,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TrojanRequest {
    password_hash: String,
    user_uuid: String,
    target: SocksTarget,
}

impl TrojanServer {
    pub fn new(config: TrojanServerConfig) -> Self {
        Self::with_traffic(config, Arc::new(Mutex::new(TrafficRegistry::default())))
    }

    pub fn with_traffic(config: TrojanServerConfig, traffic: Arc<Mutex<TrafficRegistry>>) -> Self {
        Self::with_shared_limits(
            config,
            traffic,
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        config: TrojanServerConfig,
        traffic: Arc<Mutex<TrafficRegistry>>,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
    ) -> Self {
        let users = config
            .users
            .iter()
            .filter(|user| !user.is_empty())
            .map(|user| (trojan_password_hash(user.credential()), user.clone()))
            .collect::<HashMap<_, _>>();

        Self {
            router: RouteMatcher::new(config.routes.clone()),
            config,
            users: Arc::new(users),
            traffic,
            sessions,
            bandwidth,
        }
    }

    pub fn bind(&self) -> io::Result<TcpListener> {
        TcpListener::bind(self.config.listen)
    }

    pub fn handle_tcp_client(&self, mut client: TcpStream) -> io::Result<()> {
        let request = self.read_request(&mut client)?;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user)?;
        let bandwidth = self.bandwidth.limiter_for(user);
        let remote = match self.router.decide(&request.target.host) {
            RouteDecision::Direct => connect_target(&request.target, self.config.connect_timeout)?,
            RouteDecision::Block => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "target blocked by route",
                ));
            }
            RouteDecision::UnsupportedOutbound(tag) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("outbound route {tag} is not implemented"),
                ));
            }
        };
        self.relay(client, remote, request, bandwidth)
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<crate::traffic::TrafficDelta> {
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .drain_minimum(minimum_bytes)
    }

    fn read_request<T>(&self, stream: &mut T) -> io::Result<TrojanRequest>
    where
        T: Read,
    {
        let mut hash = [0u8; TROJAN_PASSWORD_HEX_LEN];
        stream.read_exact(&mut hash)?;
        let password_hash = String::from_utf8(hash.to_vec()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid trojan password hash")
        })?;
        read_crlf(stream)?;

        let Some(user) = self.users.get(&password_hash) else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unknown trojan user",
            ));
        };

        let command = read_u8(stream)?;
        if command != COMMAND_TCP {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "only trojan tcp command is supported",
            ));
        }

        let host = match read_u8(stream)? {
            ATYP_IPV4 => {
                let mut bytes = [0u8; 4];
                stream.read_exact(&mut bytes)?;
                Ipv4Addr::from(bytes).to_string()
            }
            ATYP_DOMAIN => {
                let len = read_u8(stream)?;
                read_string(stream, usize::from(len))?
            }
            ATYP_IPV6 => {
                let mut bytes = [0u8; 16];
                stream.read_exact(&mut bytes)?;
                Ipv6Addr::from(bytes).to_string()
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported trojan address type",
                ));
            }
        };

        let mut port = [0u8; 2];
        stream.read_exact(&mut port)?;
        read_crlf(stream)?;

        Ok(TrojanRequest {
            password_hash,
            user_uuid: user.uuid.clone(),
            target: SocksTarget {
                host,
                port: u16::from_be_bytes(port),
            },
        })
    }

    fn relay(
        &self,
        client: TcpStream,
        remote: TcpStream,
        request: TrojanRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        let (upload, download) = relay_tcp_streams_limited(client, remote, bandwidth)?;
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .add(
                self.config.node_tag.clone(),
                request.user_uuid,
                upload,
                download,
            );
        Ok(())
    }

    fn request_user(&self, request: &TrojanRequest) -> Option<&CoreUser> {
        self.users.get(&request.password_hash)
    }

    fn acquire_user_session(
        &self,
        user: Option<&CoreUser>,
    ) -> io::Result<Option<UserSessionGuard>> {
        match self.sessions.try_acquire(user) {
            Ok(guard) => Ok(guard),
            Err(error) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                error.to_string(),
            )),
        }
    }
}

pub fn trojan_password_hash(password: &str) -> String {
    let digest = Sha224::digest(password.as_bytes());
    hex_lower(&digest)
}

fn connect_target(target: &SocksTarget, timeout: Duration) -> io::Result<TcpStream> {
    let addrs = (target.host.as_str(), target.port).to_socket_addrs()?;
    let mut last_error = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "target did not resolve to any socket address",
        )
    }))
}

fn read_u8<R: Read>(reader: &mut R) -> io::Result<u8> {
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte)?;
    Ok(byte[0])
}

fn read_string<R: Read>(reader: &mut R, len: usize) -> io::Result<String> {
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes)?;
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid utf-8"))
}

fn read_crlf<R: Read>(reader: &mut R) -> io::Result<()> {
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf)?;
    if crlf == [b'\r', b'\n'] {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, "missing crlf"))
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0f));
    }
    output
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => unreachable!("hex nibble is always below 16"),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    use crate::trojan::{trojan_password_hash, TrojanServer, TrojanServerConfig};
    use crate::user::CoreUser;

    struct MemoryStream {
        input: Cursor<Vec<u8>>,
    }

    impl MemoryStream {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input: Cursor::new(input),
            }
        }
    }

    impl Read for MemoryStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    fn user() -> CoreUser {
        CoreUser {
            id: 1,
            uuid: "trojan-password".to_string(),
            password: None,
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    fn server() -> TrojanServer {
        TrojanServer::new(TrojanServerConfig {
            node_tag: "panel|trojan|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user()],
            routes: Vec::new(),
            connect_timeout: Duration::from_secs(3),
        })
    }

    fn trojan_request(target: std::net::SocketAddr) -> Vec<u8> {
        let mut input = trojan_password_hash("trojan-password").into_bytes();
        input.extend_from_slice(b"\r\n");
        input.push(0x01);
        input.push(0x01);
        input.extend_from_slice(
            &target
                .ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        input.extend_from_slice(&target.port().to_be_bytes());
        input.extend_from_slice(b"\r\n");
        input
    }

    #[test]
    fn hashes_trojan_password_with_sha224_hex() {
        assert_eq!(
            trojan_password_hash(""),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    #[test]
    fn parses_trojan_tcp_request() {
        let server = server();
        let mut input = trojan_password_hash("trojan-password").into_bytes();
        input.extend_from_slice(b"\r\n");
        input.push(0x01);
        input.push(0x03);
        input.push(11);
        input.extend_from_slice(b"example.com");
        input.extend_from_slice(&443u16.to_be_bytes());
        input.extend_from_slice(b"\r\n");
        let mut stream = MemoryStream::new(input);

        let request = server.read_request(&mut stream).expect("request");

        assert_eq!(request.user_uuid, "trojan-password");
        assert_eq!(request.target.host, "example.com");
        assert_eq!(request.target.port, 443);
    }

    #[test]
    fn rejects_unknown_trojan_user() {
        let server = server();
        let mut input = trojan_password_hash("wrong-password").into_bytes();
        input.extend_from_slice(b"\r\n");
        let mut stream = MemoryStream::new(input);

        let error = server
            .read_request(&mut stream)
            .expect_err("unknown user should fail");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn proxies_tcp_and_records_user_traffic() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            server_clone.handle_tcp_client(stream)
        });

        let mut client = TcpStream::connect(trojan_addr).expect("client connect");
        client
            .write_all(&trojan_request(echo_addr))
            .expect("client request");
        client.write_all(b"ping").expect("client write payload");
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).expect("client read payload");
        assert_eq!(&echoed, b"ping");
        drop(client);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|trojan|1");
        assert_eq!(records[0].user_uuid, "trojan-password");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }
}
