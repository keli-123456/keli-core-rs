use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{json, Value};
use x25519_dalek::{PublicKey, StaticSecret};

const HTTP_BODY: &[u8] = b"keli-ok";
const UDP_PAYLOAD: &[u8] = b"udp-ping";
const UDP_PREFIX: &[u8] = b"udp-ok:";
const USER_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
const USER_PASSWORD: &str = "interop-password";
const SS_PASSWORD: &str = "ss-password";
const TUIC_PASSWORD: &str = "tuic-password";
const REALITY_PRIVATE_KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
const REALITY_SHORT_ID: &str = "6ba85179e30d4fc2";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug)]
enum Probe {
    Tcp,
    Udp,
}

#[derive(Clone, Debug)]
struct InteropCase {
    name: String,
    core_port: u16,
    inbound: Value,
    sing_outbound: Value,
    probes: Vec<Probe>,
}

#[derive(Debug)]
struct Args {
    core: PathBuf,
    sing_box: PathBuf,
    work_dir: PathBuf,
    base_port: u16,
    only: Vec<String>,
    keep: bool,
}

struct ProcessGuard {
    name: String,
    child: Child,
}

impl ProcessGuard {
    fn new(name: impl Into<String>, child: Child) -> Self {
        Self {
            name: name.into(),
            child,
        }
    }

    fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    fn fail_if_exited(&mut self) -> Result<()> {
        if let Some(status) = self.try_wait()? {
            return Err(format!("{} exited early with {status}", self.name).into());
        }
        Ok(())
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct TcpEcho {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl TcpEcho {
    fn start() -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_for_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buffer = [0u8; 4096];
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(700)));
                        let _ = stream.read(&mut buffer);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                            HTTP_BODY.len(),
                            String::from_utf8_lossy(HTTP_BODY)
                        );
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            addr,
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for TcpEcho {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct UdpEcho {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl UdpEcho {
    fn start() -> io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        let addr = socket.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while !stop_for_thread.load(Ordering::SeqCst) {
                match socket.recv_from(&mut buffer) {
                    Ok((read, peer)) => {
                        let mut response = UDP_PREFIX.to_vec();
                        response.extend_from_slice(&buffer[..read]);
                        let _ = socket.send_to(&response, peer);
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            addr,
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for UdpEcho {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(socket) = UdpSocket::bind("127.0.0.1:0") {
            let _ = socket.send_to(b"stop", self.addr);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct TlsDest {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl TlsDest {
    fn start() -> Result<Self> {
        let cert = generate_simple_self_signed(vec!["localhost".to_string()])?;
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der())),
            )?;
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_for_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let config = Arc::clone(&server_config);
                        thread::spawn(move || {
                            let _ = handle_tls_dest_client(stream, config);
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            addr,
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for TlsDest {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn handle_tls_dest_client(stream: TcpStream, config: Arc<ServerConfig>) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_millis(800)))?;
    stream.set_write_timeout(Some(Duration::from_millis(800)))?;
    let connection = ServerConnection::new(config).map_err(io_other)?;
    let mut tls = StreamOwned::new(connection, stream);
    let mut buffer = [0u8; 1024];
    let _ = tls.read(&mut buffer);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("interop matrix failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = parse_args()?;
    if !args.core.exists() {
        return Err(format!(
            "core binary not found at {}; run cargo build --release or pass --core",
            args.core.display()
        )
        .into());
    }
    if !args.sing_box.exists() {
        return Err(format!(
            "sing-box binary not found at {}; pass --sing-box or set SING_BOX",
            args.sing_box.display()
        )
        .into());
    }

    prepare_work_dir(&args.work_dir)?;
    let tcp_echo = TcpEcho::start()?;
    let udp_echo = UdpEcho::start()?;
    let reality_dest = TlsDest::start()?;
    let cert = write_test_cert(&args.work_dir)?;
    let cases = filtered_cases(
        build_cases(
            args.base_port,
            &cert.cert_path,
            &cert.key_path,
            reality_dest.addr,
        ),
        &args.only,
    );
    if cases.is_empty() {
        return Err("no interop cases selected".into());
    }

    let core_config_path = args.work_dir.join("interop-core.json");
    write_core_config(&core_config_path, &cases)?;
    let mut core = start_process(
        "keli-core-rs",
        &args.core,
        &["run-config".into(), core_config_path.display().to_string()],
        &args.work_dir,
    )?;
    wait_for_tcp_case(&cases)?;
    core.fail_if_exited()?;

    println!(
        "interop matrix: {} cases, tcp echo {}, udp echo {}",
        cases.len(),
        tcp_echo.addr,
        udp_echo.addr
    );

    let mut passed = 0usize;
    let mut failed = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        match run_case(index, case, &args, tcp_echo.addr, udp_echo.addr) {
            Ok(()) => {
                passed += 1;
                println!("PASS {}", case.name);
            }
            Err(error) => {
                println!("FAIL {}: {error}", case.name);
                failed.push((case.name.clone(), error.to_string()));
            }
        }
        core.fail_if_exited()?;
    }

    println!("SKIP mieru: no official mieru client is bundled with this matrix");
    println!("SKIP naive: native core intentionally treats Naive as a sidecar");

    if !failed.is_empty() {
        println!(
            "interop matrix summary: {passed} passed, {} failed",
            failed.len()
        );
        for (name, error) in failed {
            println!("  - {name}: {error}");
        }
        return Err("one or more interop cases failed".into());
    }

    println!("interop matrix summary: {passed} passed, 0 failed");
    drop(core);
    if !args.keep {
        let _ = fs::remove_dir_all(&args.work_dir);
    } else {
        println!("kept artifacts at {}", args.work_dir.display());
    }
    Ok(())
}

fn parse_args() -> Result<Args> {
    let mut core = default_core_path();
    let mut sing_box = env::var_os("SING_BOX")
        .map(PathBuf::from)
        .unwrap_or_else(default_sing_box_path);
    let mut work_dir = env::current_dir()?.join("runtime").join("interop-matrix");
    let mut base_port = 23100u16;
    let mut only = Vec::new();
    let mut keep = false;

    let mut iter = env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--core" => {
                core = PathBuf::from(iter.next().ok_or("--core requires a path")?);
            }
            "--sing-box" => {
                sing_box = PathBuf::from(iter.next().ok_or("--sing-box requires a path")?);
            }
            "--work-dir" => {
                work_dir = PathBuf::from(iter.next().ok_or("--work-dir requires a path")?);
            }
            "--base-port" => {
                base_port = iter
                    .next()
                    .ok_or("--base-port requires a value")?
                    .parse::<u16>()?;
            }
            "--only" => {
                only.push(iter.next().ok_or("--only requires a case substring")?);
            }
            "--keep" => keep = true,
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            value => return Err(format!("unknown argument: {value}").into()),
        }
    }

    Ok(Args {
        core,
        sing_box,
        work_dir,
        base_port,
        only,
        keep,
    })
}

fn print_help() {
    println!(
        "Usage: cargo run --example interop_matrix -- --core <keli-core-rs> --sing-box <sing-box> [--only hy2] [--keep]"
    );
    println!("Runs local sing-box client interop against temporary keli-core-rs listeners.");
}

fn default_core_path() -> PathBuf {
    let mut path = env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("target")
        .join("release")
        .join("keli-core-rs");
    if cfg!(windows) {
        path.set_extension("exe");
    }
    path
}

fn default_sing_box_path() -> PathBuf {
    env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("..")
        .join("tools")
        .join("sing-box")
        .join("sing-box-1.12.22-windows-amd64")
        .join(if cfg!(windows) {
            "sing-box.exe"
        } else {
            "sing-box"
        })
}

fn prepare_work_dir(path: &Path) -> io::Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    fs::create_dir_all(path)
}

struct TestCert {
    cert_path: PathBuf,
    key_path: PathBuf,
}

fn write_test_cert(work_dir: &Path) -> Result<TestCert> {
    let cert = generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_path = work_dir.join("interop.crt");
    let key_path = work_dir.join("interop.key");
    fs::write(&cert_path, cert.cert.pem())?;
    fs::write(&key_path, cert.key_pair.serialize_pem())?;
    Ok(TestCert {
        cert_path,
        key_path,
    })
}

fn filtered_cases(cases: Vec<InteropCase>, only: &[String]) -> Vec<InteropCase> {
    if only.is_empty() {
        return cases;
    }
    cases
        .into_iter()
        .filter(|case| {
            only.iter().any(|needle| {
                case.name
                    .to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase())
            })
        })
        .collect()
}

fn build_cases(
    base_port: u16,
    cert: &Path,
    key: &Path,
    reality_dest: SocketAddr,
) -> Vec<InteropCase> {
    let mut port = base_port;
    let mut next_port = || {
        let current = port;
        port = port.saturating_add(1);
        current
    };
    let mut cases = Vec::new();

    cases.push(proxy_case("socks-tcp", next_port(), "socks"));
    cases.push(proxy_case("http-proxy-tcp", next_port(), "http"));
    cases.push(shadowsocks_case(next_port(), vec![Probe::Tcp]));
    cases.push(vless_case(
        next_port(),
        "vless-tcp-none",
        "tcp",
        false,
        "",
        None,
    ));
    cases.push(vless_case(
        next_port(),
        "vless-tcp-tls",
        "tcp",
        true,
        "",
        None,
    ));
    cases.push(vless_case(
        next_port(),
        "vless-tcp-tls-vision",
        "tcp",
        true,
        "xtls-rprx-vision",
        None,
    ));
    cases.push(vless_reality_case(next_port(), reality_dest));
    cases.push(vless_case(
        next_port(),
        "vless-ws-none",
        "ws",
        false,
        "",
        None,
    ));
    cases.push(vless_case(
        next_port(),
        "vless-ws-tls",
        "ws",
        true,
        "",
        None,
    ));
    cases.push(vless_case(
        next_port(),
        "vless-httpupgrade-none",
        "httpupgrade",
        false,
        "",
        None,
    ));
    cases.push(vless_case(
        next_port(),
        "vless-httpupgrade-tls",
        "httpupgrade",
        true,
        "",
        None,
    ));
    cases.push(vless_case(
        next_port(),
        "vless-grpc-none",
        "grpc",
        false,
        "",
        None,
    ));
    cases.push(vless_case(
        next_port(),
        "vless-grpc-tls",
        "grpc",
        true,
        "",
        None,
    ));

    cases.push(vmess_case(next_port(), "vmess-tcp-none", "tcp", false));
    cases.push(vmess_case(next_port(), "vmess-tcp-tls", "tcp", true));
    cases.push(vmess_case(next_port(), "vmess-ws-none", "ws", false));
    cases.push(vmess_case(next_port(), "vmess-ws-tls", "ws", true));
    cases.push(vmess_case(
        next_port(),
        "vmess-httpupgrade-none",
        "httpupgrade",
        false,
    ));
    cases.push(vmess_case(
        next_port(),
        "vmess-httpupgrade-tls",
        "httpupgrade",
        true,
    ));
    cases.push(vmess_case(next_port(), "vmess-grpc-none", "grpc", false));
    cases.push(vmess_case(next_port(), "vmess-grpc-tls", "grpc", true));

    cases.push(trojan_case(next_port(), "trojan-tcp-plain", "tcp", false));
    cases.push(trojan_case(next_port(), "trojan-tcp-tls", "tcp", true));
    cases.push(trojan_case(next_port(), "trojan-ws-plain", "ws", false));
    cases.push(trojan_case(next_port(), "trojan-ws-tls", "ws", true));
    cases.push(trojan_case(
        next_port(),
        "trojan-httpupgrade-plain",
        "httpupgrade",
        false,
    ));
    cases.push(trojan_case(
        next_port(),
        "trojan-httpupgrade-tls",
        "httpupgrade",
        true,
    ));
    cases.push(trojan_case(next_port(), "trojan-grpc-plain", "grpc", false));
    cases.push(trojan_case(next_port(), "trojan-grpc-tls", "grpc", true));

    cases.push(anytls_case(next_port()));
    cases.push(hysteria2_case(next_port(), "hy2-tls", None));
    cases.push(hysteria2_case(
        next_port(),
        "hy2-salamander",
        Some(("salamander", "obfs-password")),
    ));
    cases.push(tuic_case(next_port()));
    cases.push(shadowsocks_udp_case(next_port()));

    for case in &mut cases {
        apply_cert_paths(case, cert, key);
    }
    cases
}

fn apply_cert_paths(case: &mut InteropCase, cert: &Path, key: &Path) {
    if let Some(tls) = case.inbound.get_mut("tls").and_then(Value::as_object_mut) {
        tls.insert(
            "cert_file".to_string(),
            Value::String(cert.display().to_string()),
        );
        tls.insert(
            "key_file".to_string(),
            Value::String(key.display().to_string()),
        );
    }
}

fn proxy_case(name: &str, port: u16, protocol: &str) -> InteropCase {
    let user = user(USER_UUID, Some(USER_PASSWORD));
    let outbound = json!({
        "type": protocol,
        "tag": "proxy",
        "server": "127.0.0.1",
        "server_port": port,
        "username": USER_UUID,
        "password": USER_PASSWORD
    });
    InteropCase {
        name: name.to_string(),
        core_port: port,
        inbound: inbound(name, protocol, port, vec![user], "tcp", None, None, ""),
        sing_outbound: outbound,
        probes: vec![Probe::Tcp],
    }
}

fn shadowsocks_case(port: u16, probes: Vec<Probe>) -> InteropCase {
    InteropCase {
        name: "shadowsocks-tcp".to_string(),
        core_port: port,
        inbound: inbound(
            "shadowsocks-tcp",
            "shadowsocks",
            port,
            vec![user(USER_UUID, Some(SS_PASSWORD))],
            "tcp,udp",
            None,
            Some("aes-128-gcm"),
            "",
        ),
        sing_outbound: json!({
            "type": "shadowsocks",
            "tag": "proxy",
            "server": "127.0.0.1",
            "server_port": port,
            "method": "aes-128-gcm",
            "password": SS_PASSWORD
        }),
        probes,
    }
}

fn shadowsocks_udp_case(port: u16) -> InteropCase {
    let mut case = shadowsocks_case(port, vec![Probe::Udp]);
    case.name = "shadowsocks-udp".to_string();
    case.inbound["tag"] = Value::String("shadowsocks-udp".to_string());
    case.inbound["transport"] = transport("tcp,udp");
    case
}

fn vless_case(
    port: u16,
    name: &str,
    network: &str,
    tls: bool,
    flow: &str,
    extra_transport: Option<Value>,
) -> InteropCase {
    let outbound = with_optional_tls(
        json!({
            "type": "vless",
            "tag": "proxy",
            "server": "127.0.0.1",
            "server_port": port,
            "uuid": USER_UUID,
            "flow": flow,
            "transport": sing_transport(network)
        }),
        tls,
        network,
    );
    let mut inbound_value = inbound(
        name,
        "vless",
        port,
        vec![user(USER_UUID, None)],
        network,
        tls.then(tls_config),
        None,
        flow,
    );
    if let Some(transport) = extra_transport {
        inbound_value["transport"] = transport;
    }
    InteropCase {
        name: name.to_string(),
        core_port: port,
        inbound: inbound_value,
        sing_outbound: outbound,
        probes: vec![Probe::Tcp],
    }
}

fn vless_reality_case(port: u16, reality_dest: SocketAddr) -> InteropCase {
    let mut inbound_value = inbound(
        "vless-reality-vision",
        "vless",
        port,
        vec![user(USER_UUID, None)],
        "tcp",
        Some(reality_tls_config(reality_dest)),
        None,
        "xtls-rprx-vision",
    );
    inbound_value["tls"]["cert_file"] = Value::Null;
    inbound_value["tls"]["key_file"] = Value::Null;

    InteropCase {
        name: "vless-reality-vision".to_string(),
        core_port: port,
        inbound: inbound_value,
        sing_outbound: json!({
            "type": "vless",
            "tag": "proxy",
            "server": "127.0.0.1",
            "server_port": port,
            "uuid": USER_UUID,
            "flow": "xtls-rprx-vision",
            "tls": sing_reality_tls()
        }),
        probes: vec![Probe::Tcp],
    }
}

fn vmess_case(port: u16, name: &str, network: &str, tls: bool) -> InteropCase {
    InteropCase {
        name: name.to_string(),
        core_port: port,
        inbound: inbound(
            name,
            "vmess",
            port,
            vec![user(USER_UUID, None)],
            network,
            tls.then(tls_config),
            None,
            "",
        ),
        sing_outbound: with_optional_tls(
            json!({
                "type": "vmess",
                "tag": "proxy",
                "server": "127.0.0.1",
                "server_port": port,
                "uuid": USER_UUID,
                "security": "aes-128-gcm",
                "alter_id": 0,
                "transport": sing_transport(network)
            }),
            tls,
            network,
        ),
        probes: vec![Probe::Tcp],
    }
}

fn trojan_case(port: u16, name: &str, network: &str, tls: bool) -> InteropCase {
    InteropCase {
        name: name.to_string(),
        core_port: port,
        inbound: inbound(
            name,
            "trojan",
            port,
            vec![user(USER_UUID, Some(USER_PASSWORD))],
            network,
            tls.then(tls_config),
            None,
            "",
        ),
        sing_outbound: with_optional_tls(
            json!({
                "type": "trojan",
                "tag": "proxy",
                "server": "127.0.0.1",
                "server_port": port,
                "password": USER_PASSWORD,
                "transport": sing_transport(network)
            }),
            tls,
            network,
        ),
        probes: vec![Probe::Tcp],
    }
}

fn anytls_case(port: u16) -> InteropCase {
    InteropCase {
        name: "anytls-tls".to_string(),
        core_port: port,
        inbound: inbound(
            "anytls-tls",
            "anytls",
            port,
            vec![user(USER_UUID, Some(USER_PASSWORD))],
            "tcp",
            Some(tls_config()),
            None,
            "",
        ),
        sing_outbound: json!({
            "type": "anytls",
            "tag": "proxy",
            "server": "127.0.0.1",
            "server_port": port,
            "password": USER_PASSWORD,
            "tls": sing_tls("tcp")
        }),
        probes: vec![Probe::Tcp],
    }
}

fn hysteria2_case(port: u16, name: &str, obfs: Option<(&str, &str)>) -> InteropCase {
    let mut core_transport = transport("hysteria");
    core_transport["up_mbps"] = json!(100);
    core_transport["down_mbps"] = json!(100);
    let mut outbound = json!({
        "type": "hysteria2",
        "tag": "proxy",
        "server": "127.0.0.1",
        "server_port": port,
        "password": USER_PASSWORD,
        "up_mbps": 100,
        "down_mbps": 100,
        "tls": sing_tls("hysteria")
    });
    if let Some((obfs_type, password)) = obfs {
        core_transport["obfs"] = json!(obfs_type);
        core_transport["obfs_password"] = json!(password);
        outbound["obfs"] = json!({
            "type": obfs_type,
            "password": password
        });
    }

    InteropCase {
        name: name.to_string(),
        core_port: port,
        inbound: inbound_with_transport(
            name,
            "hysteria2",
            port,
            vec![user(USER_UUID, Some(USER_PASSWORD))],
            core_transport,
            Some(tls_config()),
            None,
            "",
        ),
        sing_outbound: outbound,
        probes: vec![Probe::Tcp, Probe::Udp],
    }
}

fn tuic_case(port: u16) -> InteropCase {
    let mut core_transport = transport("tuic");
    core_transport["congestion_control"] = json!("bbr");
    InteropCase {
        name: "tuic-tls".to_string(),
        core_port: port,
        inbound: inbound_with_transport(
            "tuic-tls",
            "tuic",
            port,
            vec![user(USER_UUID, Some(TUIC_PASSWORD))],
            core_transport,
            Some(tls_config()),
            None,
            "",
        ),
        sing_outbound: json!({
            "type": "tuic",
            "tag": "proxy",
            "server": "127.0.0.1",
            "server_port": port,
            "uuid": USER_UUID,
            "password": TUIC_PASSWORD,
            "congestion_control": "bbr",
            "tls": {
                "enabled": true,
                "server_name": "localhost",
                "insecure": true,
                "alpn": ["h3"]
            }
        }),
        probes: vec![Probe::Tcp, Probe::Udp],
    }
}

fn inbound(
    tag: &str,
    protocol: &str,
    port: u16,
    users: Vec<Value>,
    network: &str,
    tls: Option<Value>,
    cipher: Option<&str>,
    flow: &str,
) -> Value {
    inbound_with_transport(
        tag,
        protocol,
        port,
        users,
        transport(network),
        tls,
        cipher,
        flow,
    )
}

fn inbound_with_transport(
    tag: &str,
    protocol: &str,
    port: u16,
    users: Vec<Value>,
    transport: Value,
    tls: Option<Value>,
    cipher: Option<&str>,
    flow: &str,
) -> Value {
    json!({
        "tag": tag,
        "protocol": protocol,
        "listen": "127.0.0.1",
        "port": port,
        "users": users,
        "cipher": cipher,
        "flow": flow,
        "padding_scheme": [],
        "transport": transport,
        "tls": tls,
        "sniffing": {
            "enabled": false,
            "dest_override": []
        },
        "routes": []
    })
}

fn user(uuid: &str, password: Option<&str>) -> Value {
    json!({
        "id": 1001,
        "uuid": uuid,
        "password": password,
        "email": null,
        "speed_limit": 0,
        "device_limit": 0
    })
}

fn transport(network: &str) -> Value {
    let (path, host, service_name) = match network {
        "ws" => (Some("/ws"), Some("localhost"), None),
        "httpupgrade" => (Some("/upgrade"), Some("localhost"), None),
        "grpc" => (None, None, Some("GunService")),
        _ => (None, None, None),
    };
    json!({
        "network": network,
        "path": path,
        "host": host,
        "service_name": service_name,
        "proxy_protocol": false,
        "up_mbps": 0,
        "down_mbps": 0,
        "ignore_client_bandwidth": false,
        "obfs": null,
        "obfs_password": null,
        "congestion_control": "",
        "zero_rtt_handshake": false
    })
}

fn tls_config() -> Value {
    json!({
        "server_name": "localhost",
        "cert_file": "",
        "key_file": "",
        "alpn": [],
        "reject_unknown_sni": false,
        "reality": null
    })
}

fn reality_tls_config(dest: SocketAddr) -> Value {
    json!({
        "server_name": "localhost",
        "cert_file": null,
        "key_file": null,
        "alpn": [],
        "reject_unknown_sni": false,
        "reality": {
            "dest": dest.to_string(),
            "server_port": null,
            "private_key": REALITY_PRIVATE_KEY,
            "short_id": REALITY_SHORT_ID,
            "xver": 0,
            "mldsa65_seed": null
        }
    })
}

fn with_optional_tls(mut outbound: Value, enabled: bool, network: &str) -> Value {
    if enabled {
        outbound["tls"] = sing_tls(network);
    } else {
        outbound["tls"] = json!({ "enabled": false });
    }
    outbound
}

fn sing_tls(network: &str) -> Value {
    let mut tls = json!({
        "enabled": true,
        "server_name": "localhost",
        "insecure": true
    });
    if network == "grpc" {
        tls["alpn"] = json!(["h2"]);
    } else if network == "hysteria" {
        tls["alpn"] = json!(["h3"]);
    }
    tls
}

fn sing_reality_tls() -> Value {
    json!({
        "enabled": true,
        "server_name": "localhost",
        "utls": {
            "enabled": true,
            "fingerprint": "chrome"
        },
        "reality": {
            "enabled": true,
            "public_key": reality_public_key(),
            "short_id": REALITY_SHORT_ID
        }
    })
}

fn reality_public_key() -> String {
    let private_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(REALITY_PRIVATE_KEY)
        .expect("reality private key");
    let private_key: [u8; 32] = private_key.try_into().expect("reality private key length");
    let secret = StaticSecret::from(private_key);
    let public = PublicKey::from(&secret);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.as_bytes())
}

fn sing_transport(network: &str) -> Value {
    match network {
        "tcp" => Value::Null,
        "ws" => json!({
            "type": "ws",
            "path": "/ws",
            "headers": { "Host": "localhost" }
        }),
        "httpupgrade" => json!({
            "type": "httpupgrade",
            "path": "/upgrade",
            "host": "localhost"
        }),
        "grpc" => json!({
            "type": "grpc",
            "service_name": "GunService"
        }),
        other => json!({ "type": other }),
    }
}

fn io_other(error: impl std::fmt::Debug) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{error:?}"))
}

fn write_core_config(path: &Path, cases: &[InteropCase]) -> Result<()> {
    let config = json!({
        "instance_id": "local-interop-matrix",
        "log_level": "warn",
        "dns": {
            "servers": [],
            "query_strategy": ""
        },
        "inbounds": cases.iter().map(|case| case.inbound.clone()).collect::<Vec<_>>(),
        "outbounds": [],
        "routes": [],
        "stats": {
            "enabled": true,
            "per_user": true
        }
    });
    fs::write(path, serde_json::to_vec_pretty(&config)?)?;
    Ok(())
}

fn start_process(name: &str, exe: &Path, args: &[String], work_dir: &Path) -> Result<ProcessGuard> {
    let stdout = File::create(work_dir.join(format!("{name}.stdout.log")))?;
    let stderr = File::create(work_dir.join(format!("{name}.stderr.log")))?;
    let child = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()?;
    Ok(ProcessGuard::new(name, child))
}

fn wait_for_tcp_case(cases: &[InteropCase]) -> Result<()> {
    let Some(case) = cases.iter().find(|case| {
        !matches!(
            case.inbound
                .get("transport")
                .and_then(|transport| transport.get("network"))
                .and_then(Value::as_str),
            Some("hysteria" | "tuic")
        )
    }) else {
        thread::sleep(Duration::from_millis(600));
        return Ok(());
    };
    wait_for_tcp(("127.0.0.1", case.core_port), Duration::from_secs(8))
}

fn wait_for_tcp(addr: (&str, u16), timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(format!("timed out waiting for {}:{}", addr.0, addr.1).into())
}

fn run_case(
    index: usize,
    case: &InteropCase,
    args: &Args,
    tcp_echo: SocketAddr,
    udp_echo: SocketAddr,
) -> Result<()> {
    let socks_port = args
        .base_port
        .checked_add(1000)
        .and_then(|port| port.checked_add(index as u16))
        .ok_or("local socks port overflow")?;
    let sing_config_path = args.work_dir.join(format!("{}.sing-box.json", case.name));
    write_sing_box_config(&sing_config_path, case, socks_port)?;
    let mut sing_box = start_process(
        &format!("sing-box-{}", case.name),
        &args.sing_box,
        &[
            "run".into(),
            "-c".into(),
            sing_config_path.display().to_string(),
        ],
        &args.work_dir,
    )?;
    wait_for_tcp(("127.0.0.1", socks_port), Duration::from_secs(8))?;
    sing_box.fail_if_exited()?;

    for probe in &case.probes {
        match probe {
            Probe::Tcp => {
                let body = socks_http_probe(socks_port, tcp_echo)?;
                if body.as_bytes() != HTTP_BODY {
                    return Err(format!("unexpected tcp body: {body:?}").into());
                }
            }
            Probe::Udp => {
                let body = socks_udp_probe(socks_port, udp_echo)?;
                let expected = [UDP_PREFIX, UDP_PAYLOAD].concat();
                if body != expected {
                    return Err(format!(
                        "unexpected udp body: {:?}",
                        String::from_utf8_lossy(&body)
                    )
                    .into());
                }
            }
        }
    }
    Ok(())
}

fn write_sing_box_config(path: &Path, case: &InteropCase, socks_port: u16) -> Result<()> {
    let mut outbound = case.sing_outbound.clone();
    remove_nulls(&mut outbound);
    let config = json!({
        "log": {
            "disabled": false,
            "level": "debug"
        },
        "inbounds": [{
            "type": "socks",
            "tag": "local-socks",
            "listen": "127.0.0.1",
            "listen_port": socks_port
        }],
        "outbounds": [outbound],
        "route": {
            "final": "proxy"
        }
    });
    fs::write(path, serde_json::to_vec_pretty(&config)?)?;
    Ok(())
}

fn remove_nulls(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|key, value| {
                !value.is_null() && !(key == "flow" && value.as_str().is_some_and(str::is_empty))
            });
            for value in map.values_mut() {
                remove_nulls(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                remove_nulls(value);
            }
        }
        _ => {}
    }
}

fn socks_http_probe(socks_port: u16, target: SocketAddr) -> Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port))?;
    stream.set_read_timeout(Some(Duration::from_secs(8)))?;
    stream.set_write_timeout(Some(Duration::from_secs(8)))?;
    socks_handshake(&mut stream)?;
    socks_connect_ipv4(&mut stream, target)?;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        target.ip(),
        target.port()
    );
    stream.write_all(request.as_bytes())?;
    read_http_body(&mut stream)
}

fn read_http_body(stream: &mut TcpStream) -> Result<String> {
    let mut response = Vec::new();
    let header_end = loop {
        let mut buffer = [0u8; 1024];
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Err("connection closed before http response headers".into());
        }
        response.extend_from_slice(&buffer[..read]);
        if let Some(index) = find_header_end(&response) {
            break index;
        }
        if response.len() > 16 * 1024 {
            return Err("http response headers too large".into());
        }
    };
    let header = String::from_utf8_lossy(&response[..header_end]);
    let content_length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .ok_or("http response missing content-length")?;
    let body_start = header_end + 4;
    while response.len().saturating_sub(body_start) < content_length {
        let mut buffer = [0u8; 1024];
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Err("connection closed before full http response body".into());
        }
        response.extend_from_slice(&buffer[..read]);
    }
    let body = &response[body_start..body_start + content_length];
    Ok(String::from_utf8(body.to_vec())?)
}

fn find_header_end(response: &[u8]) -> Option<usize> {
    response.windows(4).position(|window| window == b"\r\n\r\n")
}

fn socks_udp_probe(socks_port: u16, target: SocketAddr) -> Result<Vec<u8>> {
    let mut control = TcpStream::connect(("127.0.0.1", socks_port))?;
    control.set_read_timeout(Some(Duration::from_secs(8)))?;
    control.set_write_timeout(Some(Duration::from_secs(8)))?;
    socks_handshake(&mut control)?;
    let relay = socks_udp_associate(&mut control)?;
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(8)))?;
    let mut packet = Vec::new();
    write_socks_udp_packet(&mut packet, target, UDP_PAYLOAD)?;
    socket.send_to(&packet, relay)?;
    let mut buffer = [0u8; 4096];
    let (read, _) = socket.recv_from(&mut buffer)?;
    parse_socks_udp_payload(&buffer[..read])
}

fn socks_handshake(stream: &mut TcpStream) -> Result<()> {
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut response = [0u8; 2];
    stream.read_exact(&mut response)?;
    if response != [0x05, 0x00] {
        return Err(format!("socks handshake rejected: {response:02x?}").into());
    }
    Ok(())
}

fn socks_connect_ipv4(stream: &mut TcpStream, target: SocketAddr) -> Result<()> {
    let SocketAddr::V4(target) = target else {
        return Err("interop matrix supports IPv4 loopback targets only".into());
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request)?;
    read_socks_reply(stream).map(|_| ())
}

fn socks_udp_associate(stream: &mut TcpStream) -> Result<SocketAddr> {
    stream.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
    read_socks_reply(stream)
}

fn read_socks_reply(stream: &mut TcpStream) -> Result<SocketAddr> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != 0x05 || header[1] != 0x00 {
        return Err(format!("socks command failed: {header:02x?}").into());
    }
    let ip = match header[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets)?;
            Ipv4Addr::from(octets)
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name)?;
            let host = String::from_utf8_lossy(&name);
            if host == "localhost" {
                Ipv4Addr::LOCALHOST
            } else {
                return Err(format!("unsupported socks reply domain: {host}").into());
            }
        }
        other => return Err(format!("unsupported socks reply address type: {other}").into()),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port)?;
    let ip = if ip.octets() == [0, 0, 0, 0] {
        Ipv4Addr::LOCALHOST
    } else {
        ip
    };
    Ok(SocketAddr::from((ip, u16::from_be_bytes(port))))
}

fn write_socks_udp_packet(output: &mut Vec<u8>, target: SocketAddr, payload: &[u8]) -> Result<()> {
    let SocketAddr::V4(target) = target else {
        return Err("interop matrix supports IPv4 loopback targets only".into());
    };
    output.extend_from_slice(&[0, 0, 0, 0x01]);
    output.extend_from_slice(&target.ip().octets());
    output.extend_from_slice(&target.port().to_be_bytes());
    output.extend_from_slice(payload);
    Ok(())
}

fn parse_socks_udp_payload(packet: &[u8]) -> Result<Vec<u8>> {
    if packet.len() < 10 || packet[2] != 0 {
        return Err(format!("invalid socks udp packet: {packet:02x?}").into());
    }
    let mut offset = 3usize;
    match packet.get(offset).copied() {
        Some(0x01) => offset += 1 + 4 + 2,
        Some(0x03) => {
            offset += 1;
            let len = *packet
                .get(offset)
                .ok_or("truncated socks udp domain length")? as usize;
            offset += 1 + len + 2;
        }
        Some(other) => return Err(format!("unsupported socks udp address type: {other}").into()),
        None => return Err("truncated socks udp packet".into()),
    }
    if offset > packet.len() {
        return Err("truncated socks udp payload".into());
    }
    Ok(packet[offset..].to_vec())
}
