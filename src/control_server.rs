use std::fmt;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::Value;

use crate::control::{CoreCommand, CoreController, CoreResponse};

pub const MAX_CONTROL_COMMAND_BYTES: usize = 128 * 1024 * 1024;
pub const CONTROL_TOKEN_ENV: &str = "KELI_CORE_CONTROL_TOKEN";
const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum ControlServerError {
    Bind(io::Error),
    LocalAddr(io::Error),
    Io(io::Error),
    Json(serde_json::Error),
    Controller(String),
}

impl fmt::Display for ControlServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlServerError::Bind(error) => write!(formatter, "bind control server: {error}"),
            ControlServerError::LocalAddr(error) => {
                write!(formatter, "read control server local addr: {error}")
            }
            ControlServerError::Io(error) => write!(formatter, "control server io: {error}"),
            ControlServerError::Json(error) => write!(formatter, "control server json: {error}"),
            ControlServerError::Controller(error) => write!(formatter, "control server: {error}"),
        }
    }
}

impl std::error::Error for ControlServerError {}

#[derive(Debug)]
pub struct ControlServerHandle {
    local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl ControlServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.local_addr);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for ControlServerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn start_control_server(
    addr: &str,
    controller: Arc<Mutex<CoreController>>,
) -> Result<ControlServerHandle, ControlServerError> {
    start_control_server_with_token(addr, controller, control_token_from_env())
}

pub fn start_control_server_with_token(
    addr: &str,
    controller: Arc<Mutex<CoreController>>,
    token: Option<String>,
) -> Result<ControlServerHandle, ControlServerError> {
    let listen = resolve_control_addr(addr)?;
    ensure_secure_control_listen(listen, token.as_deref())?;
    let listener = TcpListener::bind(listen).map_err(ControlServerError::Bind)?;
    listener
        .set_nonblocking(true)
        .map_err(ControlServerError::Io)?;
    let local_addr = listener
        .local_addr()
        .map_err(ControlServerError::LocalAddr)?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let join = thread::spawn(move || {
        serve_control_listener(listener, controller, thread_stop, token);
    });

    Ok(ControlServerHandle {
        local_addr,
        stop,
        join: Some(join),
    })
}

fn ensure_secure_control_listen(
    listen: SocketAddr,
    token: Option<&str>,
) -> Result<(), ControlServerError> {
    if token.map(str::trim).is_some_and(|value| !value.is_empty()) || listen.ip().is_loopback() {
        return Ok(());
    }
    Err(ControlServerError::Controller(format!(
        "control server without token must listen on loopback address, got {listen}"
    )))
}

fn control_token_from_env() -> Option<String> {
    std::env::var(CONTROL_TOKEN_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn resolve_control_addr(addr: &str) -> Result<SocketAddr, ControlServerError> {
    addr.to_socket_addrs()
        .map_err(ControlServerError::Bind)?
        .next()
        .ok_or_else(|| ControlServerError::Controller("empty control listen address".to_string()))
}

fn serve_control_listener(
    listener: TcpListener,
    controller: Arc<Mutex<CoreController>>,
    stop: Arc<AtomicBool>,
    token: Option<String>,
) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let controller = controller.clone();
                let stop = stop.clone();
                let token = token.clone();
                thread::spawn(move || {
                    if let Ok(CoreResponse::Stopped) =
                        serve_control_stream_with_token(stream, controller, token.as_deref())
                    {
                        stop.store(true, Ordering::SeqCst);
                    }
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}

pub fn serve_control_stream(
    stream: TcpStream,
    controller: Arc<Mutex<CoreController>>,
) -> Result<CoreResponse, ControlServerError> {
    serve_control_stream_with_token(stream, controller, control_token_from_env().as_deref())
}

fn serve_control_stream_with_token(
    mut stream: TcpStream,
    controller: Arc<Mutex<CoreController>>,
    required_token: Option<&str>,
) -> Result<CoreResponse, ControlServerError> {
    stream
        .set_read_timeout(Some(CONTROL_IO_TIMEOUT))
        .map_err(ControlServerError::Io)?;
    stream
        .set_write_timeout(Some(CONTROL_IO_TIMEOUT))
        .map_err(ControlServerError::Io)?;
    let command = match read_control_command(&mut stream, required_token) {
        Ok(command) => command,
        Err(error) => {
            let response = CoreResponse::Error {
                message: error.to_string(),
            };
            write_control_response(&mut stream, &response)?;
            return Ok(response);
        }
    };
    let response = controller
        .lock()
        .map_err(|_| ControlServerError::Controller("controller lock poisoned".to_string()))?
        .handle(command);
    write_control_response(&mut stream, &response)?;
    Ok(response)
}

fn read_control_command(
    stream: &mut TcpStream,
    required_token: Option<&str>,
) -> Result<CoreCommand, ControlServerError> {
    read_control_command_with_limit(stream, MAX_CONTROL_COMMAND_BYTES, required_token)
}

fn read_control_command_with_limit(
    stream: &mut TcpStream,
    max_bytes: usize,
    required_token: Option<&str>,
) -> Result<CoreCommand, ControlServerError> {
    let mut reader = BufReader::new(stream);
    let line = read_control_line_with_limit(&mut reader, max_bytes)?;
    if line.trim().is_empty() {
        return Err(ControlServerError::Controller(
            "empty control command".to_string(),
        ));
    }
    let value = serde_json::from_str::<Value>(line.trim()).map_err(ControlServerError::Json)?;
    authenticate_control_command(&value, required_token)?;
    serde_json::from_value(value).map_err(ControlServerError::Json)
}

fn authenticate_control_command(
    value: &Value,
    required_token: Option<&str>,
) -> Result<(), ControlServerError> {
    let Some(required_token) = required_token
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    let provided = value.get("token").and_then(Value::as_str).unwrap_or("");
    if provided == required_token {
        return Ok(());
    }
    Err(ControlServerError::Controller(
        "unauthorized control command".to_string(),
    ))
}

fn read_control_line_with_limit<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<String, ControlServerError> {
    let mut bytes = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(ControlServerError::Io)?;
        if available.is_empty() {
            break;
        }
        let consume = if let Some(position) = available.iter().position(|byte| *byte == b'\n') {
            position + 1
        } else {
            available.len()
        };
        if bytes.len().saturating_add(consume) > max_bytes {
            return Err(ControlServerError::Controller(format!(
                "control command exceeds {max_bytes} bytes"
            )));
        }
        bytes.extend_from_slice(&available[..consume]);
        reader.consume(consume);
        if bytes.ends_with(b"\n") {
            break;
        }
    }
    String::from_utf8(bytes).map_err(|error| {
        ControlServerError::Controller(format!("control command is not utf-8: {error}"))
    })
}

fn write_control_response(
    stream: &mut TcpStream,
    response: &CoreResponse,
) -> Result<(), ControlServerError> {
    let body = serde_json::to_vec(response).map_err(ControlServerError::Json)?;
    stream.write_all(&body).map_err(ControlServerError::Io)?;
    stream.write_all(b"\n").map_err(ControlServerError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Cursor, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    use super::read_control_line_with_limit;
    use crate::config::{
        CoreConfig, DnsConfig, InboundConfig, OutboundConfig, SniffingConfig, StatsConfig,
        TransportConfig,
    };
    use crate::control::{CoreCommand, CoreController, CoreResponse};
    use crate::control_server::{start_control_server, start_control_server_with_token};
    use crate::protocol::Protocol;
    use crate::runtime::CoreStatus;
    use crate::user::CoreUser;

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .expect("bind free port")
            .local_addr()
            .expect("free port addr")
            .port()
    }

    fn config() -> CoreConfig {
        CoreConfig {
            instance_id: "node-a".to_string(),
            log_level: "info".to_string(),
            dns: DnsConfig::default(),
            inbounds: vec![InboundConfig {
                tag: "panel|socks|1".to_string(),
                protocol: Protocol::Socks,
                listen: "127.0.0.1".to_string(),
                port: free_port(),
                users: vec![CoreUser {
                    id: 1,
                    uuid: "user-a".to_string(),
                    password: None,
                    email: None,
                    speed_limit: 0,
                    device_limit: 0,
                }],
                cipher: None,
                flow: String::new(),
                padding_scheme: Vec::new(),
                transport: TransportConfig::default(),
                tls: None,
                sniffing: SniffingConfig::default(),
                routes: Vec::new(),
            }],
            outbounds: vec![OutboundConfig {
                tag: "direct".to_string(),
                protocol: "freedom".to_string(),
                method: None,
                alter_id: None,
                address: None,
                port: None,
                username: None,
                password: None,
                tls: None,
                transport: None,
            }],
            routes: Vec::new(),
            stats: StatsConfig::default(),
        }
    }

    fn send(addr: SocketAddr, command: &CoreCommand) -> CoreResponse {
        let mut stream = TcpStream::connect(addr).expect("connect control");
        let body = serde_json::to_string(command).expect("encode command");
        writeln!(stream, "{body}").expect("write command");
        let mut line = String::new();
        BufReader::new(stream)
            .read_line(&mut line)
            .expect("read response");
        serde_json::from_str(line.trim()).expect("decode response")
    }

    fn send_raw(addr: SocketAddr, command: serde_json::Value) -> CoreResponse {
        let mut stream = TcpStream::connect(addr).expect("connect control");
        writeln!(stream, "{command}").expect("write command");
        let mut line = String::new();
        BufReader::new(stream)
            .read_line(&mut line)
            .expect("read response");
        serde_json::from_str(line.trim()).expect("decode response")
    }

    use std::net::SocketAddr;

    #[test]
    fn control_server_handles_apply_config_command() {
        let controller = Arc::new(Mutex::new(CoreController::new()));
        let mut server = start_control_server("127.0.0.1:0", controller).expect("start control");

        match send(
            server.local_addr(),
            &CoreCommand::ApplyConfig { config: config() },
        ) {
            CoreResponse::Applied {
                decision,
                status,
                listeners,
            } => {
                assert_eq!(decision, "reloaded");
                assert_eq!(status, CoreStatus::Running);
                assert_eq!(listeners.len(), 1);
            }
            response => panic!("unexpected response: {response:?}"),
        }
        assert!(matches!(
            send(server.local_addr(), &CoreCommand::Stop),
            CoreResponse::Stopped
        ));

        server.stop();
    }

    #[test]
    fn control_server_handles_status_traffic_and_stop_commands() {
        let mut controller = CoreController::new();
        let apply = controller.handle(CoreCommand::ApplyConfig { config: config() });
        assert!(matches!(apply, CoreResponse::Applied { .. }));
        let controller = Arc::new(Mutex::new(controller));
        let mut server = start_control_server("127.0.0.1:0", controller).expect("start control");

        match send(server.local_addr(), &CoreCommand::Status) {
            CoreResponse::Status { status, listeners } => {
                assert_eq!(status, CoreStatus::Running);
                assert_eq!(listeners.len(), 1);
            }
            response => panic!("unexpected response: {response:?}"),
        }
        match send(
            server.local_addr(),
            &CoreCommand::DrainTraffic { minimum_bytes: 0 },
        ) {
            CoreResponse::Traffic { records } => assert!(records.is_empty()),
            response => panic!("unexpected response: {response:?}"),
        }
        assert!(matches!(
            send(server.local_addr(), &CoreCommand::Stop),
            CoreResponse::Stopped
        ));

        server.stop();
    }

    #[test]
    fn control_server_returns_error_for_malformed_command() {
        let controller = Arc::new(Mutex::new(CoreController::new()));
        let mut server = start_control_server("127.0.0.1:0", controller).expect("start control");
        let mut stream = TcpStream::connect(server.local_addr()).expect("connect control");
        writeln!(stream, "{{not-json").expect("write malformed command");

        let mut line = String::new();
        BufReader::new(stream)
            .read_line(&mut line)
            .expect("read response");
        match serde_json::from_str::<CoreResponse>(line.trim()).expect("decode response") {
            CoreResponse::Error { message } => {
                assert!(message.contains("control server json"));
            }
            response => panic!("unexpected response: {response:?}"),
        }

        assert!(matches!(
            send(server.local_addr(), &CoreCommand::Stop),
            CoreResponse::Stopped
        ));
        server.stop();
    }

    #[test]
    fn control_server_rejects_missing_token_when_required() {
        let controller = Arc::new(Mutex::new(CoreController::new()));
        let mut server = start_control_server_with_token(
            "127.0.0.1:0",
            controller,
            Some("secret-token".to_string()),
        )
        .expect("start control");

        match send_raw(server.local_addr(), serde_json::json!({"type": "status"})) {
            CoreResponse::Error { message } => {
                assert!(message.contains("unauthorized control command"));
            }
            response => panic!("unexpected response: {response:?}"),
        }
        match send_raw(
            server.local_addr(),
            serde_json::json!({"type": "status", "token": "secret-token"}),
        ) {
            CoreResponse::Status { status, .. } => assert_eq!(status, CoreStatus::Stopped),
            response => panic!("unexpected response: {response:?}"),
        }
        assert!(matches!(
            send_raw(
                server.local_addr(),
                serde_json::json!({"type": "stop", "token": "secret-token"})
            ),
            CoreResponse::Stopped
        ));

        server.stop();
    }

    #[test]
    fn control_server_requires_token_for_non_loopback_listen() {
        let controller = Arc::new(Mutex::new(CoreController::new()));

        let error = start_control_server_with_token("0.0.0.0:0", controller, None)
            .expect_err("non-loopback control should require token");

        assert!(error.to_string().contains("without token"));
        assert!(error.to_string().contains("loopback"));
    }

    #[test]
    fn control_server_allows_non_loopback_listen_with_token() {
        let controller = Arc::new(Mutex::new(CoreController::new()));
        let mut server = start_control_server_with_token(
            "0.0.0.0:0",
            controller,
            Some("secret-token".to_string()),
        )
        .expect("token should allow non-loopback control listen");
        let connect_addr =
            SocketAddr::new("127.0.0.1".parse().unwrap(), server.local_addr().port());

        match send_raw(
            connect_addr,
            serde_json::json!({"type": "status", "token": "secret-token"}),
        ) {
            CoreResponse::Status { status, .. } => assert_eq!(status, CoreStatus::Stopped),
            response => panic!("unexpected response: {response:?}"),
        }
        assert!(matches!(
            send_raw(
                connect_addr,
                serde_json::json!({"type": "stop", "token": "secret-token"})
            ),
            CoreResponse::Stopped
        ));
        server.stop();
    }

    #[test]
    fn control_server_rejects_oversized_command_line() {
        let mut input = Cursor::new(b"{\"type\":\"status\"}\n".to_vec());
        let error = read_control_line_with_limit(&mut input, 4).expect_err("limit error");

        assert!(error
            .to_string()
            .contains("control command exceeds 4 bytes"));
    }
}
