use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::stream::relay_tcp_streams;
use crate::traffic::TrafficRegistry;
use crate::user::CoreUser;
use crate::{RouteDecision, RouteMatcher};

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_PASSWORD: u8 = 0x02;
const AUTH_NO_MATCHING_METHOD: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const STATUS_SUCCESS: u8 = 0x00;
const STATUS_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const STATUS_ADDRESS_NOT_SUPPORTED: u8 = 0x08;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

#[derive(Clone, Debug)]
pub struct Socks5ServerConfig {
    pub node_tag: String,
    pub listen: SocketAddr,
    pub users: Vec<CoreUser>,
    pub routes: Vec<crate::RouteRule>,
    pub connect_timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocksTarget {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct Socks5Server {
    config: Socks5ServerConfig,
    users: Arc<HashMap<String, CoreUser>>,
    router: RouteMatcher,
    traffic: Arc<Mutex<TrafficRegistry>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SocksRequest {
    user_uuid: Option<String>,
    target: SocksTarget,
}

impl Socks5Server {
    pub fn new(config: Socks5ServerConfig) -> Self {
        Self::with_traffic(config, Arc::new(Mutex::new(TrafficRegistry::default())))
    }

    pub fn with_traffic(config: Socks5ServerConfig, traffic: Arc<Mutex<TrafficRegistry>>) -> Self {
        let users = config
            .users
            .iter()
            .filter(|user| !user.is_empty())
            .map(|user| (user.uuid.clone(), user.clone()))
            .collect::<HashMap<_, _>>();

        Self {
            router: RouteMatcher::new(config.routes.clone()),
            config,
            users: Arc::new(users),
            traffic,
        }
    }

    pub fn bind(&self) -> io::Result<TcpListener> {
        TcpListener::bind(self.config.listen)
    }

    pub fn serve_tcp_once(&self, listener: &TcpListener) -> io::Result<()> {
        let (stream, _) = listener.accept()?;
        self.handle_tcp_client(stream)
    }

    pub fn handle_tcp_client(&self, mut client: TcpStream) -> io::Result<()> {
        let request = match self.read_request(&mut client) {
            Ok(request) => request,
            Err(error) => {
                let _ = client.shutdown(Shutdown::Both);
                return Err(error);
            }
        };
        let remote = match self.router.decide(&request.target.host) {
            RouteDecision::Direct => connect_target(&request.target, self.config.connect_timeout)?,
            RouteDecision::Block => {
                write_socks5_response(&mut client, STATUS_COMMAND_NOT_SUPPORTED)?;
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
        write_socks5_response(&mut client, STATUS_SUCCESS)?;
        self.relay(client, remote, request)
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<crate::traffic::TrafficDelta> {
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .drain_minimum(minimum_bytes)
    }

    fn read_request<T>(&self, stream: &mut T) -> io::Result<SocksRequest>
    where
        T: Read + Write,
    {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header)?;
        if header[0] != SOCKS5_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported socks version",
            ));
        }

        let methods = read_exact_vec(stream, usize::from(header[1]))?;
        let selected_method = self.select_auth_method(&methods);
        stream.write_all(&[SOCKS5_VERSION, selected_method])?;

        let user_uuid = match selected_method {
            AUTH_NONE => None,
            AUTH_PASSWORD => Some(self.read_password_auth(stream)?),
            AUTH_NO_MATCHING_METHOD => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "no matching socks auth method",
                ));
            }
            _ => unreachable!("selected auth method is controlled internally"),
        };

        self.read_connect_request(stream, user_uuid)
    }

    fn select_auth_method(&self, methods: &[u8]) -> u8 {
        let required = if self.users.is_empty() {
            AUTH_NONE
        } else {
            AUTH_PASSWORD
        };
        methods
            .iter()
            .copied()
            .find(|method| *method == required)
            .unwrap_or(AUTH_NO_MATCHING_METHOD)
    }

    fn read_password_auth<T>(&self, stream: &mut T) -> io::Result<String>
    where
        T: Read + Write,
    {
        let mut version_and_len = [0u8; 2];
        stream.read_exact(&mut version_and_len)?;
        if version_and_len[0] != 0x01 {
            stream.write_all(&[0x01, 0xff])?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported username/password auth version",
            ));
        }

        let username = read_string(stream, usize::from(version_and_len[1]))?;
        let mut password_len = [0u8; 1];
        stream.read_exact(&mut password_len)?;
        let password = read_string(stream, usize::from(password_len[0]))?;

        match self.users.get(&username) {
            Some(user) if user.credential() == password => {
                stream.write_all(&[0x01, 0x00])?;
                Ok(user.uuid.clone())
            }
            _ => {
                stream.write_all(&[0x01, 0xff])?;
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "invalid username or password",
                ))
            }
        }
    }

    fn read_connect_request<T>(
        &self,
        stream: &mut T,
        user_uuid: Option<String>,
    ) -> io::Result<SocksRequest>
    where
        T: Read + Write,
    {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header)?;
        if header[0] != SOCKS5_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported request version",
            ));
        }
        if header[1] != CMD_CONNECT {
            write_socks5_response(stream, STATUS_COMMAND_NOT_SUPPORTED)?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "only socks connect is supported",
            ));
        }

        let host = match header[3] {
            ATYP_IPV4 => {
                let mut bytes = [0u8; 4];
                stream.read_exact(&mut bytes)?;
                Ipv4Addr::from(bytes).to_string()
            }
            ATYP_IPV6 => {
                let mut bytes = [0u8; 16];
                stream.read_exact(&mut bytes)?;
                Ipv6Addr::from(bytes).to_string()
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len)?;
                read_string(stream, usize::from(len[0]))?
            }
            _ => {
                write_socks5_response(stream, STATUS_ADDRESS_NOT_SUPPORTED)?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported socks address type",
                ));
            }
        };

        let mut port = [0u8; 2];
        stream.read_exact(&mut port)?;
        Ok(SocksRequest {
            user_uuid,
            target: SocksTarget {
                host,
                port: u16::from_be_bytes(port),
            },
        })
    }

    fn relay(&self, client: TcpStream, remote: TcpStream, request: SocksRequest) -> io::Result<()> {
        let (upload, download) = relay_tcp_streams(client, remote)?;
        if let Some(user_uuid) = request.user_uuid {
            self.traffic
                .lock()
                .expect("traffic registry lock poisoned")
                .add(self.config.node_tag.clone(), user_uuid, upload, download);
        }
        Ok(())
    }
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

fn read_exact_vec<R: Read>(reader: &mut R, len: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_string<R: Read>(reader: &mut R, len: usize) -> io::Result<String> {
    let bytes = read_exact_vec(reader, len)?;
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid utf-8"))
}

fn write_socks5_response<W: Write>(writer: &mut W, status: u8) -> io::Result<()> {
    writer.write_all(&[
        SOCKS5_VERSION,
        status,
        0x00,
        ATYP_IPV4,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ])
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    use crate::socks5::{Socks5Server, Socks5ServerConfig};
    use crate::user::CoreUser;

    struct MemoryStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl MemoryStream {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input: Cursor::new(input),
                output: Vec::new(),
            }
        }
    }

    impl Read for MemoryStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for MemoryStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn user() -> CoreUser {
        CoreUser {
            id: 1,
            uuid: "user-a".to_string(),
            password: None,
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    fn server() -> Socks5Server {
        Socks5Server::new(Socks5ServerConfig {
            node_tag: "panel|socks|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user()],
            routes: Vec::new(),
            connect_timeout: Duration::from_secs(3),
        })
    }

    #[test]
    fn parses_authenticated_domain_connect() {
        let server = server();
        let mut input = vec![
            0x05, 0x01, 0x02, 0x01, 0x06, b'u', b's', b'e', b'r', b'-', b'a', 0x06, b'u', b's',
            b'e', b'r', b'-', b'a', 0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p',
            b'l', b'e', b'.', b'c', b'o', b'm',
        ];
        input.extend_from_slice(&443u16.to_be_bytes());
        let mut stream = MemoryStream::new(input);

        let request = server.read_request(&mut stream).expect("request");

        assert_eq!(request.user_uuid.as_deref(), Some("user-a"));
        assert_eq!(request.target.host, "example.com");
        assert_eq!(request.target.port, 443);
        assert_eq!(stream.output, vec![0x05, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn rejects_invalid_password() {
        let server = server();
        let mut input = vec![
            0x05, 0x01, 0x02, 0x01, 0x06, b'u', b's', b'e', b'r', b'-', b'a', 0x03, b'b', b'a',
            b'd',
        ];
        let mut stream = MemoryStream::new(std::mem::take(&mut input));

        let error = server
            .read_request(&mut stream)
            .expect_err("auth should fail");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(stream.output, vec![0x05, 0x02, 0x01, 0xff]);
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
        let listener = server.bind().expect("socks bind");
        let socks_addr = listener.local_addr().expect("socks addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || server_clone.serve_tcp_once(&listener));

        let mut client = TcpStream::connect(socks_addr).expect("client connect");
        client
            .write_all(&[
                0x05, 0x01, 0x02, 0x01, 0x06, b'u', b's', b'e', b'r', b'-', b'a', 0x06, b'u', b's',
                b'e', b'r', b'-', b'a', 0x05, 0x01, 0x00, 0x01,
            ])
            .expect("client greeting");
        client
            .write_all(
                &echo_addr
                    .ip()
                    .to_string()
                    .parse::<std::net::Ipv4Addr>()
                    .expect("ipv4")
                    .octets(),
            )
            .expect("client target ip");
        client
            .write_all(&echo_addr.port().to_be_bytes())
            .expect("client target port");

        let mut response = [0u8; 14];
        client.read_exact(&mut response).expect("client response");
        assert_eq!(&response[0..2], &[0x05, 0x02]);
        assert_eq!(&response[2..4], &[0x01, 0x00]);
        assert_eq!(&response[4..6], &[0x05, 0x00]);

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
        assert_eq!(records[0].node_tag, "panel|socks|1");
        assert_eq!(records[0].user_uuid, "user-a");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }
}
