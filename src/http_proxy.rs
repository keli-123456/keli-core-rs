use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::limits::{
    sync_user_limit_delta, BandwidthLimiter, UserBandwidthLimiters, UserSessionGuard,
    UserSessionTracker,
};
use crate::socket_bind::bind_dual_stack_tcp_listener;
use crate::stream::{
    copy_count_best_effort, copy_count_best_effort_limited, relay_tcp_fast_unlimited,
    relay_tcp_limited,
};
use crate::traffic::{SharedTrafficRegistry, TrafficDelta, TrafficRegistry};
use crate::user::{CoreUser, CoreUserDelta, CoreUserDeltaResult, UserStore};
use crate::{RouteDispatcher, SocksTarget};

#[derive(Clone, Debug)]
pub struct HttpProxyServerConfig {
    pub node_tag: String,
    pub listen: SocketAddr,
    pub users: Vec<CoreUser>,
    pub routes: Vec<crate::RouteRule>,
    pub connect_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct HttpProxyServer {
    config: HttpProxyServerConfig,
    users: UserStore,
    auth_required: bool,
    router: RouteDispatcher,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HttpProxyRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    user_uuid: Option<String>,
    user_id: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HttpTarget {
    host: String,
    port: u16,
}

impl HttpProxyServer {
    pub fn new(config: HttpProxyServerConfig) -> Self {
        Self::with_traffic(config, TrafficRegistry::shared())
    }

    pub fn with_traffic(config: HttpProxyServerConfig, traffic: SharedTrafficRegistry) -> Self {
        Self::with_shared_limits(
            config,
            traffic,
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        mut config: HttpProxyServerConfig,
        traffic: SharedTrafficRegistry,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
    ) -> Self {
        let auth_required = !config.users.is_empty();
        let users = UserStore::from_uuid_users(&config.users);
        let router =
            RouteDispatcher::with_connect_timeout(config.routes.clone(), config.connect_timeout);
        config.users.clear();
        config.routes.clear();
        Self {
            router,
            config,
            users,
            auth_required,
            traffic,
            sessions,
            bandwidth,
        }
    }

    pub fn bind(&self) -> io::Result<TcpListener> {
        bind_dual_stack_tcp_listener(self.config.listen)
    }

    pub fn serve_tcp_once(&self, listener: &TcpListener) -> io::Result<()> {
        let (stream, _) = listener.accept()?;
        self.handle_tcp_client(stream)
    }

    pub fn handle_tcp_client(&self, mut client: TcpStream) -> io::Result<()> {
        let mut reader = BufReader::new(client.try_clone()?);
        let request = match self.read_request(&mut reader) {
            Ok(request) => request,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                write_auth_required_response(&mut client)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let user = self.request_user(&request);
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        let _session = self.acquire_user_session(user.as_ref(), &mut client)?;
        let bandwidth = self.bandwidth.limiter_for_limited(user.as_ref());
        if request.method.eq_ignore_ascii_case("CONNECT") {
            self.handle_connect(client, request, bandwidth, client_ip)
        } else {
            self.handle_plain_http(&mut client, request, bandwidth, client_ip)
        }
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<TrafficDelta> {
        self.traffic.drain_minimum(minimum_bytes)
    }

    pub fn replace_users(&self, users: Vec<CoreUser>) {
        self.bandwidth.sync_users(&users);
        self.users.replace_uuid_users(users);
    }

    pub fn replace_routes(&self, routes: Vec<crate::RouteRule>) {
        self.router.replace_routes(routes);
    }

    pub fn apply_user_delta(&self, delta: &CoreUserDelta) -> CoreUserDeltaResult {
        sync_delta_bandwidth(&self.bandwidth, &self.sessions, delta);
        self.users.apply_uuid_delta(delta)
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

        let user = self.authenticate(&headers)?;
        let user_uuid = user.as_ref().map(|user| user.uuid.clone());
        let user_id = user.as_ref().map(|user| user.id);
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
            user_id,
        })
    }

    fn authenticate(&self, headers: &[(String, String)]) -> io::Result<Option<CoreUser>> {
        if !self.auth_required {
            return Ok(None);
        }
        let Some(value) = header_value(headers, "proxy-authorization") else {
            return Err(auth_required());
        };
        let Some((username, password)) = parse_basic_auth(value) else {
            return Err(auth_required());
        };
        match self.users.get(&username) {
            Some(user) if user.credential() == password => Ok(Some(user)),
            _ => Err(auth_required()),
        }
    }

    fn handle_connect(
        &self,
        mut client: TcpStream,
        request: HttpProxyRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
        client_ip: Option<std::net::IpAddr>,
    ) -> io::Result<()> {
        let target = parse_authority(&request.target, 443)?;
        let remote = match self.connect_route_target(&target, "tcp") {
            Ok(remote) => remote,
            Err(error) => {
                write_forbidden_response(&mut client)?;
                return Err(error);
            }
        };
        client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
        let _connection = self
            .bandwidth
            .register_tcp_connection(request.user_uuid.as_deref(), &[&client, &remote])?;
        let (upload, download) = match bandwidth {
            Some(limiter) => relay_tcp_limited(client, remote, limiter)?,
            None => relay_tcp_fast_unlimited(client, remote)?,
        };
        self.record_traffic(
            request.user_uuid,
            request.user_id,
            upload,
            download,
            client_ip,
        );
        Ok(())
    }

    fn handle_plain_http(
        &self,
        client: &mut TcpStream,
        request: HttpProxyRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
        client_ip: Option<std::net::IpAddr>,
    ) -> io::Result<()> {
        let target = parse_plain_http_target(&request)?;
        let mut remote = match self.connect_route_target(&target, "tcp,http") {
            Ok(remote) => remote,
            Err(error) => {
                write_forbidden_response(client)?;
                return Err(error);
            }
        };
        let outbound = render_plain_http_request(&request, &target)?;
        if let Some(limiter) = bandwidth.as_deref() {
            if !limiter.wait_for(outbound.len()) {
                return Ok(());
            }
        }
        remote.write_all(&outbound)?;
        let _connection = self
            .bandwidth
            .register_tcp_connection(request.user_uuid.as_deref(), &[&*client, &remote])?;
        let upload = outbound.len() as u64;
        let download = match bandwidth.as_deref() {
            Some(limiter) => copy_count_best_effort_limited(&mut remote, client, Some(limiter)),
            None => copy_count_best_effort(&mut remote, client),
        };
        self.record_traffic(
            request.user_uuid,
            request.user_id,
            upload,
            download,
            client_ip,
        );
        Ok(())
    }

    fn connect_route_target(
        &self,
        target: &HttpTarget,
        protocol_labels: &str,
    ) -> io::Result<TcpStream> {
        self.router.connect_tcp_with_labels(
            &SocksTarget {
                host: target.host.clone(),
                port: target.port,
            },
            protocol_labels,
        )
    }

    fn record_traffic(
        &self,
        user_uuid: Option<String>,
        user_id: Option<u64>,
        upload: u64,
        download: u64,
        client_ip: Option<std::net::IpAddr>,
    ) {
        if let Some(user_uuid) = user_uuid {
            self.traffic.add_with_user_id(
                self.config.node_tag.clone(),
                user_uuid,
                user_id,
                upload,
                download,
                client_ip,
            );
        }
    }

    fn acquire_user_session(
        &self,
        user: Option<&CoreUser>,
        client: &mut TcpStream,
    ) -> io::Result<Option<UserSessionGuard>> {
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        match self.sessions.try_acquire_for_ip(user, client_ip) {
            Ok(guard) => Ok(guard),
            Err(error) => {
                write_too_many_requests_response(client)?;
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    error.to_string(),
                ))
            }
        }
    }

    fn request_user(&self, request: &HttpProxyRequest) -> Option<CoreUser> {
        request
            .user_uuid
            .as_deref()
            .and_then(|uuid| self.users.get(uuid))
    }
}

fn sync_delta_bandwidth(
    bandwidth: &UserBandwidthLimiters,
    sessions: &UserSessionTracker,
    delta: &CoreUserDelta,
) {
    sync_user_limit_delta(bandwidth, sessions, delta);
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
        if !host.contains(']') {
            let port = port.parse::<u16>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid http authority port")
            })?;
            let host = host.trim_matches(['[', ']']);
            if host.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "empty http authority host",
                ));
            }
            return Ok(HttpTarget {
                host: host.to_string(),
                port,
            });
        }
    }
    if let Some(end) = value.strip_prefix('[').and_then(|rest| rest.find(']')) {
        let host = &value[1..=end];
        let rest = &value[end + 2..];
        let port = rest
            .strip_prefix(':')
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(default_port);
        return Ok(HttpTarget {
            host: host.to_string(),
            port,
        });
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

fn write_auth_required_response(writer: &mut impl Write) -> io::Result<()> {
    writer.write_all(
        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nConnection: close\r\n\r\n",
    )
}

fn write_forbidden_response(writer: &mut impl Write) -> io::Result<()> {
    writer.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
}

fn write_too_many_requests_response(writer: &mut impl Write) -> io::Result<()> {
    writer.write_all(b"HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    use crate::config::{RouteAction, RouteRule};
    use crate::http_proxy::{HttpProxyServer, HttpProxyServerConfig};
    use crate::user::{CoreUser, CoreUserDelta};

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

    fn user_b() -> CoreUser {
        CoreUser {
            id: 2,
            uuid: "user-b".to_string(),
            password: Some("secret-b".to_string()),
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
            routes: Vec::new(),
            connect_timeout: Duration::from_secs(3),
        })
    }

    fn limited_server() -> HttpProxyServer {
        let mut user = user();
        user.device_limit = 1;
        HttpProxyServer::new(HttpProxyServerConfig {
            node_tag: "panel|http|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user],
            routes: Vec::new(),
            connect_timeout: Duration::from_secs(3),
        })
    }

    fn basic_auth_value(username: &str, password: &str) -> String {
        format!(
            "Basic {}",
            STANDARD.encode(format!("{username}:{password}"))
        )
    }

    fn basic_auth_header() -> String {
        format!(
            "Proxy-Authorization: {}\r\n",
            basic_auth_value("user-a", "user-a")
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
        assert_eq!(records[0].user_id, Some(1));
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn deleting_http_user_closes_existing_connect_relay_and_reports_tail() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let (second_payload_tx, second_payload_rx) = mpsc::channel();
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            stream
                .set_read_timeout(Some(Duration::from_millis(300)))
                .expect("echo timeout");
            let mut first = [0u8; 1];
            stream.read_exact(&mut first).expect("first payload");
            stream.write_all(&first).expect("first echo");
            let mut second = [0u8; 1];
            let received_second = stream.read_exact(&mut second).is_ok();
            second_payload_tx
                .send(received_second)
                .expect("send result");
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
        client.write_all(b"x").expect("first write");
        let mut echoed = [0u8; 1];
        client.read_exact(&mut echoed).expect("first echo");
        assert_eq!(echoed, *b"x");

        let result = server.apply_user_delta(&CoreUserDelta {
            deleted: vec!["user-a".to_string()],
            ..CoreUserDelta::default()
        });
        assert_eq!(result.deleted, 1);
        let old_headers = vec![(
            "Proxy-Authorization".to_string(),
            basic_auth_value("user-a", "user-a"),
        )];
        let error = server
            .authenticate(&old_headers)
            .expect_err("deleted user should fail new authentication");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

        assert!(
            tcp_connection_closed_eventually(&client),
            "deleted user's existing HTTP CONNECT relay should close"
        );
        assert!(
            !second_payload_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("echo result"),
            "deleted user's existing HTTP CONNECT relay should stop forwarding new payload"
        );
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
        assert_eq!(records[0].user_id, Some(1));
        assert_eq!(records[0].upload, 1);
        assert_eq!(records[0].download, 1);
    }

    fn tcp_connection_closed_eventually(stream: &TcpStream) -> bool {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(20)));
        for _ in 0..50 {
            let mut probe = [0u8; 1];
            match stream.peek(&mut probe) {
                Ok(0) => return true,
                Ok(_) => return false,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::NotConnected
                            | io::ErrorKind::BrokenPipe
                    ) =>
                {
                    return true;
                }
                Err(_) => return true,
            }
        }
        false
    }

    #[test]
    fn deleting_last_http_user_does_not_enable_no_auth_proxy() {
        let server = server();

        let result = server.apply_user_delta(&CoreUserDelta {
            deleted: vec!["user-a".to_string()],
            ..CoreUserDelta::default()
        });
        assert_eq!(result.deleted, 1);

        let error = server
            .authenticate(&[])
            .expect_err("auth should still be required after deleting all users");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
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

    #[test]
    fn replaces_users_without_rebuilding_http_server() {
        let server = server();

        server.replace_users(vec![user_b()]);

        let old_headers = vec![(
            "Proxy-Authorization".to_string(),
            basic_auth_value("user-a", "user-a"),
        )];
        let error = server
            .authenticate(&old_headers)
            .expect_err("old user should fail after replacement");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

        let new_headers = vec![(
            "Proxy-Authorization".to_string(),
            basic_auth_value("user-b", "secret-b"),
        )];
        let user = server
            .authenticate(&new_headers)
            .expect("new user should authenticate");
        assert_eq!(user.as_ref().map(|user| user.uuid.as_str()), Some("user-b"));
    }

    #[test]
    fn apply_user_delta_updates_http_users() {
        let server = server();
        let mut updated = user();
        updated.password = Some("rotated-http".to_string());
        updated.speed_limit = 64;
        updated.device_limit = 2;

        let result = server.apply_user_delta(&CoreUserDelta {
            added: vec![user_b()],
            updated: vec![updated.clone()],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.added, 1);
        assert_eq!(result.updated, 1);
        assert_eq!(result.active_users, 2);
        let old_headers = vec![(
            "Proxy-Authorization".to_string(),
            basic_auth_value("user-a", "user-a"),
        )];
        assert_eq!(
            server
                .authenticate(&old_headers)
                .expect_err("old credential should fail after update")
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let updated_headers = vec![(
            "Proxy-Authorization".to_string(),
            basic_auth_value("user-a", "rotated-http"),
        )];
        let user = server
            .authenticate(&updated_headers)
            .expect("updated credential should authenticate")
            .expect("updated user");
        assert_eq!(user.speed_limit, 64);
        assert_eq!(user.device_limit, 2);
        let added_headers = vec![(
            "Proxy-Authorization".to_string(),
            basic_auth_value("user-b", "secret-b"),
        )];
        assert!(server.authenticate(&added_headers).is_ok());

        let result = server.apply_user_delta(&CoreUserDelta {
            deleted: vec![updated.uuid],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.deleted, 1);
        assert_eq!(result.active_users, 1);
        assert_eq!(
            server
                .authenticate(&updated_headers)
                .expect_err("deleted user should fail after delta delete")
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn writes_407_for_missing_auth_on_tcp_connection() {
        let server = server();
        let listener = server.bind().expect("proxy bind");
        let proxy_addr = listener.local_addr().expect("proxy addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let _ = server_clone.serve_tcp_once(&listener);
        });

        let mut client = TcpStream::connect(proxy_addr).expect("client connect");
        client
            .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .expect("request");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("response");

        server_thread.join().expect("server thread");
        assert!(String::from_utf8_lossy(&response).contains("407 Proxy Authentication Required"));
    }

    #[test]
    fn writes_403_for_blocked_route() {
        let server = HttpProxyServer::new(HttpProxyServerConfig {
            node_tag: "panel|http|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user()],
            routes: vec![RouteRule {
                targets: vec!["blocked.example.com".to_string()],
                action: RouteAction::Block,
                outbound: None,
            }],
            connect_timeout: Duration::from_secs(3),
        });
        let listener = server.bind().expect("proxy bind");
        let proxy_addr = listener.local_addr().expect("proxy addr");
        let server_thread = thread::spawn(move || {
            let _ = server.serve_tcp_once(&listener);
        });

        let mut client = TcpStream::connect(proxy_addr).expect("client connect");
        let request = format!(
            "GET http://blocked.example.com/ HTTP/1.1\r\nHost: blocked.example.com\r\n{}\r\n",
            basic_auth_header()
        );
        client.write_all(request.as_bytes()).expect("request");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("response");

        server_thread.join().expect("server thread");
        assert!(String::from_utf8_lossy(&response).contains("403 Forbidden"));
    }

    #[test]
    fn writes_403_for_blocked_port_route() {
        let server = HttpProxyServer::new(HttpProxyServerConfig {
            node_tag: "panel|http|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user()],
            routes: vec![RouteRule {
                targets: vec!["port:6881-6889".to_string()],
                action: RouteAction::Block,
                outbound: None,
            }],
            connect_timeout: Duration::from_secs(3),
        });
        let listener = server.bind().expect("proxy bind");
        let proxy_addr = listener.local_addr().expect("proxy addr");
        let server_thread = thread::spawn(move || {
            let _ = server.serve_tcp_once(&listener);
        });

        let mut client = TcpStream::connect(proxy_addr).expect("client connect");
        let request = format!(
            "GET http://example.com:6883/ HTTP/1.1\r\nHost: example.com:6883\r\n{}\r\n",
            basic_auth_header()
        );
        client.write_all(request.as_bytes()).expect("request");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("response");

        server_thread.join().expect("server thread");
        assert!(String::from_utf8_lossy(&response).contains("403 Forbidden"));
    }

    #[test]
    fn writes_403_for_blocked_connect_route() {
        let server = HttpProxyServer::new(HttpProxyServerConfig {
            node_tag: "panel|http|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user()],
            routes: vec![RouteRule {
                targets: vec!["blocked.example.com".to_string()],
                action: RouteAction::Block,
                outbound: None,
            }],
            connect_timeout: Duration::from_secs(3),
        });
        let listener = server.bind().expect("proxy bind");
        let proxy_addr = listener.local_addr().expect("proxy addr");
        let server_thread = thread::spawn(move || {
            let _ = server.serve_tcp_once(&listener);
        });

        let mut client = TcpStream::connect(proxy_addr).expect("client connect");
        let request = format!(
            "CONNECT blocked.example.com:443 HTTP/1.1\r\nHost: blocked.example.com:443\r\n{}\r\n",
            basic_auth_header()
        );
        client.write_all(request.as_bytes()).expect("request");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("response");

        server_thread.join().expect("server thread");
        assert!(String::from_utf8_lossy(&response).contains("403 Forbidden"));
    }

    #[test]
    fn allows_same_ip_to_reuse_device_limit_slot() {
        let target = TcpListener::bind("127.0.0.1:0").expect("target bind");
        let target_addr = target.local_addr().expect("target addr");
        let (release_tx, release_rx) = mpsc::channel();
        let target_thread = thread::spawn(move || {
            let (first, _) = target.accept().expect("first target accept");
            let (second, _) = target.accept().expect("second target accept");
            release_rx.recv().expect("release target");
            let _ = first.shutdown(Shutdown::Both);
            let _ = second.shutdown(Shutdown::Both);
        });

        let server = limited_server();
        let listener = server.bind().expect("proxy bind");
        let proxy_addr = listener.local_addr().expect("proxy addr");

        let first_listener = listener.try_clone().expect("first listener");
        let first_server = server.clone();
        let first_thread = thread::spawn(move || first_server.serve_tcp_once(&first_listener));
        let mut first_client = TcpStream::connect(proxy_addr).expect("first client");
        let first_request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n{}\r\n",
            target_addr,
            target_addr,
            basic_auth_header()
        );
        first_client
            .write_all(first_request.as_bytes())
            .expect("first request");
        let mut first_response = [0u8; 39];
        first_client
            .read_exact(&mut first_response)
            .expect("first response");
        assert!(String::from_utf8_lossy(&first_response).contains("200 Connection established"));

        let second_listener = listener.try_clone().expect("second listener");
        let second_server = server.clone();
        let second_thread = thread::spawn(move || second_server.serve_tcp_once(&second_listener));
        let mut second_client = TcpStream::connect(proxy_addr).expect("second client");
        let second_request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n{}\r\n",
            target_addr,
            target_addr,
            basic_auth_header()
        );
        second_client
            .write_all(second_request.as_bytes())
            .expect("second request");
        let mut second_response = [0u8; 39];
        second_client
            .read_exact(&mut second_response)
            .expect("second response");
        assert!(String::from_utf8_lossy(&second_response).contains("200 Connection established"));
        drop(second_client);
        drop(first_client);
        release_tx.send(()).expect("release target");
        let _ = second_thread.join().expect("second server thread");
        first_thread
            .join()
            .expect("first server thread")
            .expect("first connection should close cleanly");
        target_thread.join().expect("target thread");
    }
}
