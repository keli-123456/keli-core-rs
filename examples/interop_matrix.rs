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
    mihomo_proxy: Option<Value>,
    naive_proxy: Option<String>,
    naive_resolve_host: Option<String>,
    probes: Vec<Probe>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientKind {
    SingBox,
    Mihomo,
    NaiveProxy,
}

impl ClientKind {
    fn label(self) -> &'static str {
        match self {
            Self::SingBox => "sing-box",
            Self::Mihomo => "mihomo",
            Self::NaiveProxy => "naive",
        }
    }
}

#[derive(Debug)]
struct Args {
    core: PathBuf,
    sing_box: Option<PathBuf>,
    mihomo: Option<PathBuf>,
    naive: Option<PathBuf>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    naive_server_name: String,
    work_dir: PathBuf,
    base_port: u16,
    only: Vec<String>,
    clients: Vec<ClientKind>,
    probe_rounds: usize,
    probe_interval: Duration,
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
    if args.clients.contains(&ClientKind::SingBox) {
        let Some(sing_box) = args.sing_box.as_ref() else {
            return Err("sing-box client selected but no binary path is configured".into());
        };
        if !sing_box.exists() {
            return Err(format!(
                "sing-box binary not found at {}; pass --sing-box or set SING_BOX",
                sing_box.display()
            )
            .into());
        }
    }
    if args.clients.contains(&ClientKind::Mihomo) {
        let Some(mihomo) = args.mihomo.as_ref() else {
            return Err("mihomo client selected; pass --mihomo <mihomo binary>".into());
        };
        if !mihomo.exists() {
            return Err(format!(
                "mihomo binary not found at {}; pass --mihomo",
                mihomo.display()
            )
            .into());
        }
    }
    if args.clients.contains(&ClientKind::NaiveProxy) {
        let Some(naive) = args.naive.as_ref() else {
            return Err("naive client selected; pass --naive <naive binary>".into());
        };
        if !naive.exists() {
            return Err(format!(
                "naive binary not found at {}; pass --naive",
                naive.display()
            )
            .into());
        }
    }

    prepare_work_dir(&args.work_dir)?;
    let tcp_echo = TcpEcho::start()?;
    let udp_echo = UdpEcho::start()?;
    let reality_dest = TlsDest::start()?;
    let cert = resolve_test_cert(
        &args.work_dir,
        args.tls_cert.as_deref(),
        args.tls_key.as_deref(),
    )?;
    let cases = filtered_cases(
        build_cases(
            args.base_port,
            &cert.cert_path,
            &cert.key_path,
            &args.naive_server_name,
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
    let mut skipped = 0usize;
    let mut failed = Vec::new();
    let mut reports = Vec::new();
    for client in &args.clients {
        for (index, case) in cases.iter().enumerate() {
            let started = Instant::now();
            match run_case(*client, index, case, &args, tcp_echo.addr, udp_echo.addr) {
                Ok(CaseOutcome::Passed) => {
                    passed += 1;
                    println!("PASS {} {}", client.label(), case.name);
                    reports.push(case_report(
                        client.label(),
                        &case.name,
                        "passed",
                        started.elapsed(),
                        args.probe_rounds,
                        None,
                    ));
                }
                Ok(CaseOutcome::Skipped(reason)) => {
                    skipped += 1;
                    println!("SKIP {} {}: {reason}", client.label(), case.name);
                    reports.push(case_report(
                        client.label(),
                        &case.name,
                        "skipped",
                        started.elapsed(),
                        0,
                        Some(&reason),
                    ));
                }
                Err(error) => {
                    println!("FAIL {} {}: {error}", client.label(), case.name);
                    let error = error.to_string();
                    reports.push(case_report(
                        client.label(),
                        &case.name,
                        "failed",
                        started.elapsed(),
                        args.probe_rounds,
                        Some(&error),
                    ));
                    failed.push((format!("{} {}", client.label(), case.name), error));
                }
            }
            core.fail_if_exited()?;
        }
    }

    println!("SKIP mieru: no official mieru client is bundled with this matrix");
    if !args.clients.contains(&ClientKind::NaiveProxy) {
        println!("SKIP naive official-client: pass --client naive --naive <naive> --only naive");
    }

    write_matrix_summary(
        &args.work_dir.join("interop-summary.json"),
        &args,
        &reports,
        passed,
        skipped,
        failed.len(),
    )?;

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

    println!("interop matrix summary: {passed} passed, {skipped} skipped, 0 failed");
    drop(core);
    if !args.keep {
        let _ = fs::remove_dir_all(&args.work_dir);
    } else {
        println!("kept artifacts at {}", args.work_dir.display());
    }
    Ok(())
}

fn case_report(
    client: &str,
    case: &str,
    status: &str,
    duration: Duration,
    probe_rounds: usize,
    error: Option<&str>,
) -> Value {
    json!({
        "client": client,
        "case": case,
        "status": status,
        "duration_ms": duration.as_millis(),
        "probe_rounds": probe_rounds,
        "error": error,
    })
}

fn write_matrix_summary(
    path: &Path,
    args: &Args,
    reports: &[Value],
    passed: usize,
    skipped: usize,
    failed: usize,
) -> Result<()> {
    let summary = json!({
        "passed": passed,
        "skipped": skipped,
        "failed": failed,
        "probe_rounds": args.probe_rounds,
        "probe_interval_ms": args.probe_interval.as_millis(),
        "clients": args.clients.iter().map(|client| client.label()).collect::<Vec<_>>(),
        "only": args.only,
        "cases": reports,
    });
    fs::write(path, serde_json::to_vec_pretty(&summary)?)?;
    Ok(())
}

fn parse_args() -> Result<Args> {
    let mut core = default_core_path();
    let mut sing_box = env::var_os("SING_BOX")
        .map(PathBuf::from)
        .or_else(|| Some(default_sing_box_path()));
    let mut mihomo = env::var_os("MIHOMO").map(PathBuf::from);
    let mut naive = env::var_os("NAIVE").map(PathBuf::from);
    let mut tls_cert = env::var_os("KELI_INTEROP_TLS_CERT").map(PathBuf::from);
    let mut tls_key = env::var_os("KELI_INTEROP_TLS_KEY").map(PathBuf::from);
    let mut naive_server_name =
        env::var("KELI_INTEROP_NAIVE_SERVER_NAME").unwrap_or_else(|_| "localhost".to_string());
    let mut work_dir = env::current_dir()?.join("runtime").join("interop-matrix");
    let mut base_port = 23100u16;
    let mut only = Vec::new();
    let mut clients = Vec::new();
    let mut probe_rounds = env::var("KELI_INTEROP_PROBE_ROUNDS")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(1);
    let mut probe_interval = Duration::from_millis(
        env::var("KELI_INTEROP_PROBE_INTERVAL_MS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()?
            .unwrap_or(0),
    );
    let mut keep = false;

    let mut iter = env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--core" => {
                core = PathBuf::from(iter.next().ok_or("--core requires a path")?);
            }
            "--sing-box" => {
                sing_box = Some(PathBuf::from(
                    iter.next().ok_or("--sing-box requires a path")?,
                ));
            }
            "--mihomo" => {
                mihomo = Some(PathBuf::from(
                    iter.next().ok_or("--mihomo requires a path")?,
                ));
            }
            "--naive" => {
                naive = Some(PathBuf::from(iter.next().ok_or("--naive requires a path")?));
            }
            "--tls-cert" => {
                tls_cert = Some(PathBuf::from(
                    iter.next().ok_or("--tls-cert requires a path")?,
                ));
            }
            "--tls-key" => {
                tls_key = Some(PathBuf::from(
                    iter.next().ok_or("--tls-key requires a path")?,
                ));
            }
            "--naive-server-name" => {
                naive_server_name = iter.next().ok_or("--naive-server-name requires a value")?;
            }
            "--client" => {
                let value = iter
                    .next()
                    .ok_or("--client requires sing-box, mihomo, naive, both, or all")?;
                match value.as_str() {
                    "sing-box" | "sing_box" => clients.push(ClientKind::SingBox),
                    "mihomo" | "clash" => clients.push(ClientKind::Mihomo),
                    "naive" | "naiveproxy" | "naive-proxy" => clients.push(ClientKind::NaiveProxy),
                    "both" => {
                        clients.push(ClientKind::SingBox);
                        clients.push(ClientKind::Mihomo);
                    }
                    "all" => {
                        clients.push(ClientKind::SingBox);
                        clients.push(ClientKind::Mihomo);
                        clients.push(ClientKind::NaiveProxy);
                    }
                    other => return Err(format!("unknown client {other}").into()),
                }
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
            "--probe-rounds" => {
                probe_rounds = iter
                    .next()
                    .ok_or("--probe-rounds requires a value")?
                    .parse::<usize>()?;
            }
            "--probe-interval-ms" => {
                probe_interval = Duration::from_millis(
                    iter.next()
                        .ok_or("--probe-interval-ms requires a value")?
                        .parse::<u64>()?,
                );
            }
            "--keep" => keep = true,
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            value => return Err(format!("unknown argument: {value}").into()),
        }
    }

    if clients.is_empty() {
        clients.push(ClientKind::SingBox);
        if mihomo.is_some() {
            clients.push(ClientKind::Mihomo);
        }
        if naive.is_some() {
            clients.push(ClientKind::NaiveProxy);
        }
    }
    clients.dedup();
    if probe_rounds == 0 {
        return Err("--probe-rounds must be greater than 0".into());
    }

    Ok(Args {
        core,
        sing_box,
        mihomo,
        naive,
        tls_cert,
        tls_key,
        naive_server_name,
        work_dir,
        base_port,
        only,
        clients,
        probe_rounds,
        probe_interval,
        keep,
    })
}

fn print_help() {
    println!(
        "Usage: cargo run --example interop_matrix -- --core <keli-core-rs> --sing-box <sing-box> [--mihomo <mihomo>] [--naive <naive>] [--client sing-box|mihomo|naive|both|all] [--tls-cert <cert.pem> --tls-key <key.pem>] [--naive-server-name <name>] [--only hy2] [--probe-rounds 30] [--probe-interval-ms 1000] [--keep]"
    );
    println!("Runs local real-client interop against temporary keli-core-rs listeners.");
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

#[derive(Debug)]
struct TestCert {
    cert_path: PathBuf,
    key_path: PathBuf,
}

fn resolve_test_cert(
    work_dir: &Path,
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
) -> Result<TestCert> {
    match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => {
            if !cert_path.exists() {
                return Err(format!("tls cert not found at {}", cert_path.display()).into());
            }
            if !key_path.exists() {
                return Err(format!("tls key not found at {}", key_path.display()).into());
            }
            return Ok(TestCert {
                cert_path: cert_path.to_path_buf(),
                key_path: key_path.to_path_buf(),
            });
        }
        (None, None) => {}
        _ => return Err("--tls-cert and --tls-key must be provided together".into()),
    }

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
    naive_server_name: &str,
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
    cases.push(naive_case(next_port(), naive_server_name));
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
        mihomo_proxy: Some(mihomo_proxy_case(protocol, port)),
        naive_proxy: None,
        naive_resolve_host: None,
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
        mihomo_proxy: Some(json!({
            "name": "proxy",
            "type": "ss",
            "server": "127.0.0.1",
            "port": port,
            "cipher": "aes-128-gcm",
            "password": SS_PASSWORD,
            "udp": true
        })),
        naive_proxy: None,
        naive_resolve_host: None,
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
        mihomo_proxy: (network != "httpupgrade")
            .then(|| mihomo_vless_proxy(port, network, tls, flow, None)),
        naive_proxy: None,
        naive_resolve_host: None,
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
        mihomo_proxy: Some(mihomo_vless_proxy(
            port,
            "tcp",
            true,
            "xtls-rprx-vision",
            Some(mihomo_reality_opts()),
        )),
        naive_proxy: None,
        naive_resolve_host: None,
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
        mihomo_proxy: (network != "httpupgrade").then(|| mihomo_vmess_proxy(port, network, tls)),
        naive_proxy: None,
        naive_resolve_host: None,
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
        mihomo_proxy: (tls && network != "httpupgrade").then(|| mihomo_trojan_proxy(port, network)),
        naive_proxy: None,
        naive_resolve_host: None,
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
        mihomo_proxy: None,
        naive_proxy: None,
        naive_resolve_host: None,
        probes: vec![Probe::Tcp],
    }
}

fn naive_case(port: u16, server_name: &str) -> InteropCase {
    let mut tls = tls_config();
    tls["server_name"] = json!(server_name);
    InteropCase {
        name: "naive-h2-tls".to_string(),
        core_port: port,
        inbound: inbound(
            "naive-h2-tls",
            "naive",
            port,
            vec![user(USER_UUID, Some(USER_PASSWORD))],
            "tcp",
            Some(tls),
            None,
            "",
        ),
        sing_outbound: Value::Null,
        mihomo_proxy: None,
        naive_proxy: Some(format!(
            "https://{USER_UUID}:{USER_PASSWORD}@{server_name}:{port}"
        )),
        naive_resolve_host: should_resolve_naive_host(server_name).then(|| server_name.to_string()),
        probes: vec![Probe::Tcp],
    }
}

fn should_resolve_naive_host(host: &str) -> bool {
    !matches!(host, "localhost" | "127.0.0.1" | "::1")
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
        mihomo_proxy: Some(mihomo_hysteria2_proxy(port, obfs)),
        naive_proxy: None,
        naive_resolve_host: None,
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
        mihomo_proxy: Some(mihomo_tuic_proxy(port)),
        naive_proxy: None,
        naive_resolve_host: None,
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

fn mihomo_proxy_case(protocol: &str, port: u16) -> Value {
    let proxy_type = if protocol == "socks" {
        "socks5"
    } else {
        protocol
    };
    json!({
        "name": "proxy",
        "type": proxy_type,
        "server": "127.0.0.1",
        "port": port,
        "username": USER_UUID,
        "password": USER_PASSWORD
    })
}

fn mihomo_vless_proxy(
    port: u16,
    network: &str,
    tls: bool,
    flow: &str,
    reality_opts: Option<Value>,
) -> Value {
    let mut proxy = json!({
        "name": "proxy",
        "type": "vless",
        "server": "127.0.0.1",
        "port": port,
        "uuid": USER_UUID,
        "tls": tls,
        "servername": tls.then_some("localhost"),
        "skip-cert-verify": tls.then_some(true),
        "flow": flow
    });
    mihomo_apply_transport(&mut proxy, network);
    if let Some(reality_opts) = reality_opts {
        proxy["client-fingerprint"] = json!("chrome");
        proxy["reality-opts"] = reality_opts;
    }
    proxy
}

fn mihomo_vmess_proxy(port: u16, network: &str, tls: bool) -> Value {
    let mut proxy = json!({
        "name": "proxy",
        "type": "vmess",
        "server": "127.0.0.1",
        "port": port,
        "uuid": USER_UUID,
        "alterId": 0,
        "cipher": "aes-128-gcm",
        "tls": tls,
        "servername": tls.then_some("localhost"),
        "skip-cert-verify": tls.then_some(true)
    });
    mihomo_apply_transport(&mut proxy, network);
    proxy
}

fn mihomo_trojan_proxy(port: u16, network: &str) -> Value {
    let mut proxy = json!({
        "name": "proxy",
        "type": "trojan",
        "server": "127.0.0.1",
        "port": port,
        "password": USER_PASSWORD,
        "sni": "localhost",
        "skip-cert-verify": true
    });
    mihomo_apply_transport(&mut proxy, network);
    proxy
}

fn mihomo_hysteria2_proxy(port: u16, obfs: Option<(&str, &str)>) -> Value {
    let mut proxy = json!({
        "name": "proxy",
        "type": "hysteria2",
        "server": "127.0.0.1",
        "port": port,
        "password": USER_PASSWORD,
        "sni": "localhost",
        "skip-cert-verify": true,
        "up": "100 Mbps",
        "down": "100 Mbps"
    });
    if let Some((obfs_type, password)) = obfs {
        proxy["obfs"] = json!(obfs_type);
        proxy["obfs-password"] = json!(password);
    }
    proxy
}

fn mihomo_tuic_proxy(port: u16) -> Value {
    json!({
        "name": "proxy",
        "type": "tuic",
        "server": "127.0.0.1",
        "port": port,
        "uuid": USER_UUID,
        "password": TUIC_PASSWORD,
        "sni": "localhost",
        "alpn": ["h3"],
        "skip-cert-verify": true,
        "congestion-controller": "bbr",
        "udp-relay-mode": "native"
    })
}

fn mihomo_reality_opts() -> Value {
    json!({
        "public-key": reality_public_key(),
        "short-id": REALITY_SHORT_ID
    })
}

fn mihomo_apply_transport(proxy: &mut Value, network: &str) {
    match network {
        "tcp" => {}
        "ws" => {
            proxy["network"] = json!("ws");
            proxy["ws-opts"] = json!({
                "path": "/ws",
                "headers": { "Host": "localhost" }
            });
        }
        "httpupgrade" => {
            proxy["network"] = json!("httpupgrade");
            proxy["httpupgrade-opts"] = json!({
                "path": "/upgrade",
                "host": "localhost"
            });
        }
        "grpc" => {
            proxy["network"] = json!("grpc");
            proxy["grpc-opts"] = json!({
                "grpc-service-name": "GunService"
            });
        }
        other => {
            proxy["network"] = json!(other);
        }
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

enum CaseOutcome {
    Passed,
    Skipped(String),
}

fn run_case(
    client: ClientKind,
    index: usize,
    case: &InteropCase,
    args: &Args,
    tcp_echo: SocketAddr,
    udp_echo: SocketAddr,
) -> Result<CaseOutcome> {
    match client {
        ClientKind::SingBox => run_sing_box_case(index, case, args, tcp_echo, udp_echo),
        ClientKind::Mihomo => run_mihomo_case(index, case, args, tcp_echo, udp_echo),
        ClientKind::NaiveProxy => run_naive_proxy_case(index, case, args, tcp_echo, udp_echo),
    }
}

fn run_sing_box_case(
    index: usize,
    case: &InteropCase,
    args: &Args,
    tcp_echo: SocketAddr,
    udp_echo: SocketAddr,
) -> Result<CaseOutcome> {
    if case.sing_outbound.is_null() {
        return Ok(CaseOutcome::Skipped(
            "no sing-box-compatible outbound for this case yet".to_string(),
        ));
    }
    let socks_port = args
        .base_port
        .checked_add(1000)
        .and_then(|port| port.checked_add(index as u16))
        .ok_or("local socks port overflow")?;
    let sing_box_path = args
        .sing_box
        .as_ref()
        .ok_or("sing-box client selected without a binary path")?;
    let sing_config_path = args.work_dir.join(format!("{}.sing-box.json", case.name));
    write_sing_box_config(&sing_config_path, case, socks_port)?;
    let mut sing_box = start_process(
        &format!("sing-box-{}", case.name),
        sing_box_path,
        &[
            "run".into(),
            "-c".into(),
            sing_config_path.display().to_string(),
        ],
        &args.work_dir,
    )?;
    wait_for_tcp(("127.0.0.1", socks_port), Duration::from_secs(8))?;
    sing_box.fail_if_exited()?;

    run_probe_rounds(socks_port, &case.probes, tcp_echo, udp_echo, args)?;
    Ok(CaseOutcome::Passed)
}

fn run_mihomo_case(
    index: usize,
    case: &InteropCase,
    args: &Args,
    tcp_echo: SocketAddr,
    udp_echo: SocketAddr,
) -> Result<CaseOutcome> {
    let Some(_) = case.mihomo_proxy.as_ref() else {
        return Ok(CaseOutcome::Skipped(
            "no mihomo-compatible proxy config for this case yet".to_string(),
        ));
    };
    let socks_port = args
        .base_port
        .checked_add(2000)
        .and_then(|port| port.checked_add(index as u16))
        .ok_or("local mihomo socks port overflow")?;
    let mihomo_path = args
        .mihomo
        .as_ref()
        .ok_or("mihomo client selected without a binary path")?;
    let config_dir = args.work_dir.join(format!("mihomo-{}", case.name));
    fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join("config.yaml");
    write_mihomo_config(&config_path, case, socks_port)?;
    let mut mihomo = start_process(
        &format!("mihomo-{}", case.name),
        mihomo_path,
        &[
            "-d".into(),
            config_dir.display().to_string(),
            "-f".into(),
            config_path.display().to_string(),
        ],
        &args.work_dir,
    )?;
    wait_for_tcp(("127.0.0.1", socks_port), Duration::from_secs(8))?;
    mihomo.fail_if_exited()?;

    run_probe_rounds(socks_port, &case.probes, tcp_echo, udp_echo, args)?;
    Ok(CaseOutcome::Passed)
}

fn run_naive_proxy_case(
    index: usize,
    case: &InteropCase,
    args: &Args,
    tcp_echo: SocketAddr,
    udp_echo: SocketAddr,
) -> Result<CaseOutcome> {
    let Some(proxy) = case.naive_proxy.as_ref() else {
        return Ok(CaseOutcome::Skipped(
            "no NaiveProxy-compatible config for this case".to_string(),
        ));
    };
    let socks_port = args
        .base_port
        .checked_add(3000)
        .and_then(|port| port.checked_add(index as u16))
        .ok_or("local naive socks port overflow")?;
    let naive_path = args
        .naive
        .as_ref()
        .ok_or("naive client selected without a binary path")?;
    let config_path = args.work_dir.join(format!("{}.naive.json", case.name));
    write_naive_proxy_config(&config_path, proxy, socks_port)?;
    let mut naive_args = vec![config_path.display().to_string()];
    if let Some(host) = case.naive_resolve_host.as_ref() {
        naive_args.push(format!("--host-resolver-rules=MAP {host} 127.0.0.1"));
    }
    let mut naive = start_process(
        &format!("naive-{}", case.name),
        naive_path,
        &naive_args,
        &args.work_dir,
    )?;
    wait_for_tcp(("127.0.0.1", socks_port), Duration::from_secs(8))?;
    naive.fail_if_exited()?;

    run_probe_rounds(socks_port, &case.probes, tcp_echo, udp_echo, args)?;
    Ok(CaseOutcome::Passed)
}

fn run_probe_rounds(
    socks_port: u16,
    probes: &[Probe],
    tcp_echo: SocketAddr,
    udp_echo: SocketAddr,
    args: &Args,
) -> Result<()> {
    for round in 0..args.probe_rounds {
        run_probes_with_retry(socks_port, probes, tcp_echo, udp_echo)?;
        if args.probe_rounds > 1 {
            println!("probe round {}/{} passed", round + 1, args.probe_rounds);
        }
        if round + 1 < args.probe_rounds && !args.probe_interval.is_zero() {
            thread::sleep(args.probe_interval);
        }
    }
    Ok(())
}

fn run_probes_with_retry(
    socks_port: u16,
    probes: &[Probe],
    tcp_echo: SocketAddr,
    udp_echo: SocketAddr,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last_error = None;
    while Instant::now() < deadline {
        match run_probes(socks_port, probes, tcp_echo, udp_echo) {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = Some(error.to_string());
                thread::sleep(Duration::from_millis(250));
            }
        }
    }
    Err(last_error
        .unwrap_or_else(|| "probe timed out".to_string())
        .into())
}

fn run_probes(
    socks_port: u16,
    probes: &[Probe],
    tcp_echo: SocketAddr,
    udp_echo: SocketAddr,
) -> Result<()> {
    for probe in probes {
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

fn write_mihomo_config(path: &Path, case: &InteropCase, socks_port: u16) -> Result<()> {
    let mut proxy = case
        .mihomo_proxy
        .clone()
        .ok_or("case does not have a mihomo proxy config")?;
    remove_nulls(&mut proxy);

    let mut output = String::new();
    output.push_str("allow-lan: false\n");
    output.push_str("mode: rule\n");
    output.push_str("log-level: debug\n");
    output.push_str("ipv6: false\n");
    output.push_str("find-process-mode: off\n");
    output.push_str("unified-delay: true\n");
    output.push_str("tcp-concurrent: false\n");
    output.push_str(&format!("socks-port: {socks_port}\n"));
    output.push_str("port: 0\n");
    output.push_str("mixed-port: 0\n");
    output.push_str("redir-port: 0\n");
    output.push_str("tproxy-port: 0\n");
    output.push_str("proxies:\n");
    write_yaml_sequence_item(&mut output, 2, &proxy);
    output.push_str("proxy-groups:\n");
    write_yaml_sequence_item(
        &mut output,
        2,
        &json!({
            "name": "Proxy",
            "type": "select",
            "proxies": ["proxy"]
        }),
    );
    output.push_str("rules:\n");
    output.push_str("  - MATCH,Proxy\n");

    fs::write(path, output)?;
    Ok(())
}

fn write_naive_proxy_config(path: &Path, proxy: &str, socks_port: u16) -> Result<()> {
    let config = json!({
        "listen": format!("socks://127.0.0.1:{socks_port}"),
        "proxy": proxy
    });
    fs::write(path, serde_json::to_vec_pretty(&config)?)?;
    Ok(())
}

fn write_yaml_sequence_item(output: &mut String, indent: usize, value: &Value) {
    let pad = " ".repeat(indent);
    match value {
        Value::Object(map) => {
            output.push_str(&format!("{pad}-\n"));
            for (key, value) in map {
                write_yaml_mapping_entry(output, indent + 2, key, value);
            }
        }
        _ => {
            output.push_str(&format!("{pad}- {}\n", yaml_scalar(value)));
        }
    }
}

fn write_yaml_mapping_entry(output: &mut String, indent: usize, key: &str, value: &Value) {
    let pad = " ".repeat(indent);
    match value {
        Value::Object(map) => {
            output.push_str(&format!("{pad}{key}:\n"));
            for (child_key, child_value) in map {
                write_yaml_mapping_entry(output, indent + 2, child_key, child_value);
            }
        }
        Value::Array(values) => {
            output.push_str(&format!("{pad}{key}:\n"));
            for value in values {
                write_yaml_sequence_item(output, indent + 2, value);
            }
        }
        _ => {
            output.push_str(&format!("{pad}{key}: {}\n", yaml_scalar(value)));
        }
    }
}

fn yaml_scalar(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).expect("quote yaml string"),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(value).expect("json value"),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn naive_case_uses_server_name_and_loopback_host_resolver() {
        let case = naive_case(24443, "naive.example.test");

        assert_eq!(case.name, "naive-h2-tls");
        assert_eq!(case.inbound["protocol"], "naive");
        assert_eq!(case.inbound["tls"]["server_name"], "naive.example.test");
        assert_eq!(
            case.naive_proxy.as_deref(),
            Some("https://123e4567-e89b-12d3-a456-426614174000:interop-password@naive.example.test:24443")
        );
        assert_eq!(
            case.naive_resolve_host.as_deref(),
            Some("naive.example.test")
        );
    }

    #[test]
    fn naive_case_does_not_resolve_loopback_server_names() {
        assert!(naive_case(24443, "localhost").naive_resolve_host.is_none());
        assert!(naive_case(24443, "127.0.0.1").naive_resolve_host.is_none());
        assert!(naive_case(24443, "::1").naive_resolve_host.is_none());
    }

    #[test]
    fn writes_naiveproxy_config_in_official_shape() {
        let dir = unique_temp_dir("naive-config");
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("config.json");

        write_naive_proxy_config(&path, "https://user:pass@example.test:443", 12080)
            .expect("write config");

        let config: Value =
            serde_json::from_slice(&fs::read(&path).expect("read config")).expect("json config");
        assert_eq!(config["listen"], "socks://127.0.0.1:12080");
        assert_eq!(config["proxy"], "https://user:pass@example.test:443");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_test_cert_accepts_existing_pair_and_rejects_partial_pair() {
        let dir = unique_temp_dir("naive-cert");
        fs::create_dir_all(&dir).expect("temp dir");
        let cert = dir.join("test.crt");
        let key = dir.join("test.key");
        fs::write(&cert, "cert").expect("write cert");
        fs::write(&key, "key").expect("write key");

        let resolved = resolve_test_cert(&dir, Some(&cert), Some(&key)).expect("resolve pair");
        assert_eq!(resolved.cert_path, cert);
        assert_eq!(resolved.key_path, key);

        let error = resolve_test_cert(&dir, Some(&resolved.cert_path), None)
            .expect_err("partial pair should fail")
            .to_string();
        assert!(error.contains("--tls-cert and --tls-key"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn writes_interop_summary_without_client_secrets() {
        let dir = unique_temp_dir("summary");
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("summary.json");
        let args = Args {
            core: PathBuf::from("keli-core-rs"),
            sing_box: None,
            mihomo: None,
            naive: Some(PathBuf::from("naive")),
            tls_cert: None,
            tls_key: None,
            naive_server_name: "naive.example.test".to_string(),
            work_dir: dir.clone(),
            base_port: 23100,
            only: vec!["naive".to_string()],
            clients: vec![ClientKind::NaiveProxy],
            probe_rounds: 3,
            probe_interval: Duration::from_millis(250),
            keep: true,
        };
        let reports = vec![case_report(
            "naive",
            "naive-h2-tls",
            "passed",
            Duration::from_millis(12),
            3,
            None,
        )];

        write_matrix_summary(&path, &args, &reports, 1, 0, 0).expect("write summary");

        let body = fs::read_to_string(&path).expect("read summary");
        assert!(body.contains("\"probe_rounds\": 3"));
        assert!(body.contains("\"probe_interval_ms\": 250"));
        assert!(!body.contains("interop-password"));
        assert!(!body.contains("https://"));

        let _ = fs::remove_dir_all(dir);
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        env::temp_dir().join(format!(
            "keli-core-rs-interop-matrix-{label}-{}-{nanos}",
            std::process::id()
        ))
    }
}
