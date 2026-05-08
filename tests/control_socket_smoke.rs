use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use keli_core_rs::config::{
    CoreConfig, DnsConfig, InboundConfig, OutboundConfig, SniffingConfig, StatsConfig,
    TransportConfig,
};
use keli_core_rs::protocol::Protocol;
use keli_core_rs::user::CoreUser;
use serde_json::{json, Value};

#[test]
fn run_config_control_socket_accepts_apply_config() {
    let control_port = free_port();
    let inbound_port = free_port();
    let dir = temp_test_dir("control-socket-smoke");
    let config_path = dir.join("core.json");
    write_config(&config_path, &config(inbound_port, "user-a"));

    let mut child = ChildGuard::new(
        Command::new(core_binary())
            .args([
                "run-config",
                &config_path.display().to_string(),
                "--control",
                &format!("127.0.0.1:{control_port}"),
            ])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn keli-core-rs run-config"),
    );

    let mut line = String::new();
    BufReader::new(child.inner_mut().stdout.take().expect("child stdout"))
        .read_line(&mut line)
        .expect("read initial apply response");
    let initial: Value = serde_json::from_str(line.trim()).expect("decode initial response");
    assert_eq!(initial["type"], json!("applied"));
    assert_eq!(initial["decision"], json!("reloaded"));
    assert_eq!(initial["status"], json!("running"));
    let local_addr = initial["listeners"][0]["local_addr"].clone();

    let control_addr = format!("127.0.0.1:{control_port}");
    wait_for_control(&control_addr);
    let updated = send_control(
        &control_addr,
        json!({
            "type": "apply_config",
            "config": config(inbound_port, "user-b"),
        }),
    );

    assert_eq!(updated["type"], json!("applied"));
    assert_eq!(updated["decision"], json!("updated"));
    assert_eq!(updated["status"], json!("running"));
    assert_eq!(updated["listeners"][0]["local_addr"], local_addr);

    let stopped = send_control(&control_addr, json!({ "type": "stop" }));
    assert_eq!(stopped["type"], json!("stopped"));
    assert!(child.wait().success());

    let _ = fs::remove_dir_all(dir);
}

fn config(port: u16, user_uuid: &str) -> CoreConfig {
    CoreConfig {
        instance_id: "smoke".to_string(),
        log_level: "info".to_string(),
        dns: DnsConfig::default(),
        inbounds: vec![InboundConfig {
            tag: "panel|socks|1".to_string(),
            protocol: Protocol::Socks,
            listen: "127.0.0.1".to_string(),
            port,
            users: vec![CoreUser {
                id: 1,
                uuid: user_uuid.to_string(),
                password: None,
                email: None,
                speed_limit: 0,
                device_limit: 0,
            }],
            cipher: None,
            flow: String::new(),
            padding_scheme: Vec::new(),
            transport: TransportConfig {
                network: "tcp".to_string(),
                path: None,
                host: None,
                service_name: None,
                proxy_protocol: false,
                up_mbps: 0,
                down_mbps: 0,
                ignore_client_bandwidth: false,
                obfs: None,
                obfs_password: None,
                congestion_control: String::new(),
                zero_rtt_handshake: false,
            },
            tls: None,
            sniffing: SniffingConfig {
                enabled: false,
                dest_override: Vec::new(),
            },
        }],
        outbounds: vec![OutboundConfig {
            tag: "direct".to_string(),
            protocol: "freedom".to_string(),
            address: None,
            port: None,
            username: None,
            password: None,
        }],
        routes: Vec::new(),
        stats: StatsConfig {
            enabled: true,
            per_user: true,
        },
    }
}

fn write_config(path: &Path, config: &CoreConfig) {
    fs::write(
        path,
        serde_json::to_vec_pretty(config).expect("encode config"),
    )
    .expect("write config");
}

fn send_control(addr: &str, command: Value) -> Value {
    let mut stream = TcpStream::connect(addr).expect("connect control");
    writeln!(stream, "{command}").expect("write command");
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .expect("read response");
    serde_json::from_str(line.trim()).expect("decode response")
}

fn wait_for_control(addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("control socket did not open at {addr}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn core_binary() -> String {
    std::env::var("CARGO_BIN_EXE_keli-core-rs").unwrap_or_else(|_| {
        std::env::current_exe()
            .expect("current test exe")
            .parent()
            .expect("deps dir")
            .parent()
            .expect("target profile dir")
            .join(if cfg!(windows) {
                "keli-core-rs.exe"
            } else {
                "keli-core-rs"
            })
            .display()
            .to_string()
    })
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind free port")
        .local_addr()
        .expect("read free port")
        .port()
}

fn temp_test_dir(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("keli-core-rs-{label}-{nanos}"));
    fs::create_dir_all(&path).unwrap();
    path
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn inner_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("child still running")
    }

    fn wait(mut self) -> ExitStatus {
        self.child
            .take()
            .expect("child still running")
            .wait()
            .unwrap()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
