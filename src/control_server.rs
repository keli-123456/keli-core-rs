use std::fmt;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::control::{CoreCommand, CoreController, CoreResponse};

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
    let listen = resolve_control_addr(addr)?;
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
        serve_control_listener(listener, controller, thread_stop);
    });

    Ok(ControlServerHandle {
        local_addr,
        stop,
        join: Some(join),
    })
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
) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let controller = controller.clone();
                let stop = stop.clone();
                thread::spawn(move || {
                    if let Ok(CoreResponse::Stopped) = serve_control_stream(stream, controller) {
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
    mut stream: TcpStream,
    controller: Arc<Mutex<CoreController>>,
) -> Result<CoreResponse, ControlServerError> {
    let command = read_control_command(&mut stream)?;
    let response = controller
        .lock()
        .map_err(|_| ControlServerError::Controller("controller lock poisoned".to_string()))?
        .handle(command);
    write_control_response(&mut stream, &response)?;
    Ok(response)
}

fn read_control_command(stream: &mut TcpStream) -> Result<CoreCommand, ControlServerError> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(ControlServerError::Io)?;
    if line.trim().is_empty() {
        return Err(ControlServerError::Controller(
            "empty control command".to_string(),
        ));
    }
    serde_json::from_str(line.trim()).map_err(ControlServerError::Json)
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
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    use crate::config::{
        CoreConfig, InboundConfig, OutboundConfig, SniffingConfig, StatsConfig, TransportConfig,
    };
    use crate::control::{CoreCommand, CoreController, CoreResponse};
    use crate::control_server::start_control_server;
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
            }],
            outbounds: vec![OutboundConfig {
                tag: "direct".to_string(),
                protocol: "freedom".to_string(),
                address: None,
                port: None,
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

    use std::net::SocketAddr;

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
}
