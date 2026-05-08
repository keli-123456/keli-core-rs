use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::stream::{copy_count_best_effort, relay_tcp_streams};
use crate::traffic::{TrafficDelta, TrafficRegistry};
use crate::user::CoreUser;

#[derive(Clone, Debug)]
pub struct HttpProxyServerConfig {
    pub node_tag: String,
    pub listen: SocketAddr,
    pub users: Vec<CoreUser>,
    pub connect_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct HttpProxyServer {
    config: HttpProxyServerConfig,
    users: Arc<HashMap<String, CoreUser>>,
    traffic: Arc<Mutex<TrafficRegistry>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HttpProxyRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    user_uuid: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HttpTarget {
    host: String,
    port: u16,
}

impl HttpProxyServer {
    pub fn new(config: HttpProxyServerConfig) -> Self {
        Self::with_traffic(config, Arc::new(Mutex::new(TrafficRegistry::default())))
    }

    pub fn with_traffic(
        config: HttpProxyServerConfig,
        traffic: Arc<Mutex<TrafficRegistry>>,
    ) -> Self {
        let users = config
            .users
            .iter()
            .filter(|user| !user.is_empty())
            .map(|user| (user.uuid.clone(), user.clone()))
            .collect::<HashMap<_, _>>();

        Self {
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
        let mut reader = BufReader::new(client.try_clone()?);
        let request = self.read_request(&mut reader)?;
        if request.method.eq_ignore_ascii_case("CONNECT") {
            self.handle_connect(client, request)
        } else {
            self.handle_plain_http(&mut client, request)
        }
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<TrafficDelta> {
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .drain_minimum(minimum_bytes)
    }

    fn read_request<R: BufRead>(&self, reader: &mut R) -> io::Result<HttpProxyRequest> {
        let mut first_line = String::new();
        if reader.read_line(&mut first_line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "empty http request",
            ));
        }
        let first_line = trim_crlf(&first_line);
        let mut parts = first_line.splitn(3, ' ');
        let method = parts.next().unwrap_or_default().to_string();
        let target = parts.next().unwrap_or_default().to_string();
        let version = parts.next().unwrap_or_default().to_string();
        if method.is_empty() || target.is_empty() || version.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed http request line",
            ));
        }

        let mut headers = Vec::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected eof in http headers",
                ));
            }
            let line = trim_crlf(&line);
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_string(), value.trim().to_string()));
            }
        }

        let user_uuid = self.authenticate(&headers)?;
        let content_length = header_value(&headers, "content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body)?;
        }

        Ok(HttpProxyRequest {
            method,
            target,
            version,
            headers,
            body,
            user_uuid,
        })
    }

    fn authenticate(&self, headers: &[(String, String)]) -> io::Result<Option<String>> {
        if self.users.is_empty() {
            return Ok(None);
        }
        let Some(value) = header_value(headers, "proxy-authorization") else {
            return Err(auth_required());
        };
        let Some((username, password)) = parse_basic_auth(value) else {
            return Err(auth_required());
        };
        match self.users.get(&username) {
            Some(user) if user.credential() == password => Ok(Some(user.uuid.clone())),
            _ => Err(auth_required()),
        }
    }

    fn handle_connect(&self, mut client: TcpStream, request: HttpProxyRequest) -> io::Result<()> {
        let target = parse_authority(&request.target, 443)?;
        client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
        let remote = connect_target(&target, self.config.connect_timeout)?;
        let (upload, download) = relay_tcp_streams(client, remote)?;
        self.record_traffic(request.user_uuid, upload, download);
        Ok(())
    }

    fn handle_plain_http(
        &self,
        client: &mut TcpStream,
        request: HttpProxyRequest,
    ) -> io::Result<()> {
        let target = parse_plain_http_target(&request)?;
        let mut remote = connect_target(&target, self.config.connect_timeout)?;
        let outbound = render_plain_http_request(&request, &target)?;
        remote.write_all(&outbound)?;
        let upload = outbound.len() as u64;
        let download = copy_count_best_effort(&mut remote, client);
        self.record_traffic(request.user_uuid, upload, download);
        Ok(())
    }

    fn record_traffic(&self, user_uuid: Option<String>, upload: u64, download: u64) {
        if let Some(user_uuid) = user_uuid {
            self.traffic
                .lock()
                .expect("traffic registry lock poisoned")
                .add(self.config.node_tag.clone(), user_uuid, upload, download);
        }
    }
}

fn connect_target(target: &HttpTarget, timeout: Duration) -> io::Result<TcpStream> {
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

fn parse_basic_auth(value: &str) -> Option<(String, String)> {
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;
    Some((username.to_string(), password.to_string()))
}

fn parse_authority(value: &str, default_port: u16) -> io::Result<HttpTarget> {
    let value = value.trim();
    if value.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty http authority",
        ));
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return Ok(HttpTarget {
                host: host.trim_matches(['[', ']']).to_string(),
                port,
            });
        }
    }
    Ok(HttpTarget {
        host: value.trim_matches(['[', ']']).to_string(),
        port: default_port,
    })
}

fn parse_plain_http_target(request: &HttpProxyRequest) -> io::Result<HttpTarget> {
    if let Some(rest) = request.target.strip_prefix("http://") {
        let authority = rest.split('/').next().unwrap_or(rest);
        return parse_authority(authority, 80);
    }
    if let Some(rest) = request.target.strip_prefix("https://") {
        let authority = rest.split('/').next().unwrap_or(rest);
        return parse_authority(authority, 443);
    }
    if let Some(host) = header_value(&request.headers, "host") {
        return parse_authority(host, 80);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "plain http proxy request must include absolute url or host header",
    ))
}

fn render_plain_http_request(
    request: &HttpProxyRequest,
    target: &HttpTarget,
) -> io::Result<Vec<u8>> {
    let path = origin_form(&request.target);
    let mut output = Vec::new();
    write!(
        output,
        "{} {} {}\r\n",
        request.method, path, request.version
    )?;

    let mut has_host = false;
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        if name.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        write!(output, "{name}: {value}\r\n")?;
    }
    if !has_host {
        write!(output, "Host: {}\r\n", target.host)?;
    }
    output.extend_from_slice(b"Connection: close\r\n\r\n");
    output.extend_from_slice(&request.body);
    Ok(output)
}

fn origin_form(target: &str) -> &str {
    for prefix in ["http://", "https://"] {
        if let Some(rest) = target.strip_prefix(prefix) {
            if let Some(index) = rest.find('/') {
                return &rest[index..];
            }
            return "/";
        }
    }
    target
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn trim_crlf(value: &str) -> String {
    value.trim_end_matches(['\r', '\n']).to_string()
}

fn auth_required() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "proxy authentication required",
    )
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    use crate::http_proxy::{HttpProxyServer, HttpProxyServerConfig};
    use crate::user::CoreUser;

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

    fn server() -> HttpProxyServer {
        HttpProxyServer::new(HttpProxyServerConfig {
            node_tag: "panel|http|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user()],
            connect_timeout: Duration::from_secs(3),
        })
    }

    fn basic_auth_header() -> String {
        format!(
            "Proxy-Authorization: Basic {}\r\n",
            STANDARD.encode("user-a:user-a")
        )
    }

    #[test]
    fn proxies_connect_and_records_traffic() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("proxy bind");
        let proxy_addr = listener.local_addr().expect("proxy addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || server_clone.serve_tcp_once(&listener));

        let mut client = TcpStream::connect(proxy_addr).expect("client connect");
        let request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n{}\r\n",
            echo_addr,
            echo_addr,
            basic_auth_header()
        );
        client
            .write_all(request.as_bytes())
            .expect("connect request");
        let mut response = [0u8; 39];
        client.read_exact(&mut response).expect("connect response");
        assert!(String::from_utf8_lossy(&response).contains("200 Connection established"));
        client.write_all(b"ping").expect("client payload");
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).expect("client echoed");
        assert_eq!(&echoed, b"ping");
        drop(client);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");
        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|http|1");
        assert_eq!(records[0].user_uuid, "user-a");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn forwards_plain_http_request() {
        let origin = TcpListener::bind("127.0.0.1:0").expect("origin bind");
        let origin_addr = origin.local_addr().expect("origin addr");
        let origin_thread = thread::spawn(move || {
            let (mut stream, _) = origin.accept().expect("origin accept");
            let mut buffer = [0u8; 512];
            let read = stream.read(&mut buffer).expect("origin read");
            let text = String::from_utf8_lossy(&buffer[..read]);
            assert!(text.starts_with("GET /hello HTTP/1.1\r\n"));
            assert!(!text.to_ascii_lowercase().contains("proxy-authorization"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .expect("origin response");
        });

        let server = server();
        let listener = server.bind().expect("proxy bind");
        let proxy_addr = listener.local_addr().expect("proxy addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || server_clone.serve_tcp_once(&listener));

        let mut client = TcpStream::connect(proxy_addr).expect("client connect");
        let request = format!(
            "GET http://{}/hello HTTP/1.1\r\nHost: {}\r\n{}\r\n",
            origin_addr,
            origin_addr,
            basic_auth_header()
        );
        client.write_all(request.as_bytes()).expect("plain request");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("plain response");
        assert!(String::from_utf8_lossy(&response).contains("200 OK"));

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        origin_thread.join().expect("origin thread");
        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert!(records[0].upload > 0);
        assert!(records[0].download > 0);
    }

    #[test]
    fn rejects_missing_auth() {
        let server = server();
        let input = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut reader = std::io::BufReader::new(&input[..]);

        let error = server
            .read_request(&mut reader)
            .expect_err("auth should fail");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }
}
