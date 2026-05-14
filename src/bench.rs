use std::collections::HashMap;
use std::fs;
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use bytes::Bytes;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::AsyncReadExt;

use crate::config::OutboundConfig;
use crate::http_proxy::{HttpProxyServer, HttpProxyServerConfig};
use crate::hysteria2::{Hysteria2Server, Hysteria2ServerConfig};
use crate::shadowsocks::{
    connect_shadowsocks_tcp_outbound, ShadowsocksServer, ShadowsocksServerConfig,
};
use crate::socks5::{Socks5Server, Socks5ServerConfig, SocksTarget};
use crate::stream::relay_tcp_fast_unlimited;
use crate::trojan::{trojan_password_hash, TrojanServer, TrojanServerConfig};
use crate::tuic::{TuicServer, TuicServerConfig};
use crate::user::CoreUser;
use crate::vless::{VlessServer, VlessServerConfig};
use crate::vmess::{connect_vmess_tcp_outbound, VmessServer, VmessServerConfig};

const BENCH_USER_UUID: &str = "11111111-1111-1111-1111-111111111111";
const BENCH_USER_BYTES: [u8; 16] = [0x11; 16];
const HY2_PASSWORD: &str = "hy2-password";
const TUIC_PASSWORD: &str = "tuic-password";
const HY2_TCP_REQUEST_ID: u64 = 0x401;
const TUIC_VERSION: u8 = 0x05;
const TUIC_COMMAND_AUTHENTICATE: u8 = 0x00;
const TUIC_COMMAND_CONNECT: u8 = 0x01;
const TUIC_COMMAND_PACKET: u8 = 0x02;
const TUIC_ATYP_DOMAIN: u8 = 0x00;
const TUIC_ATYP_IPV4: u8 = 0x01;
const TUIC_ATYP_IPV6: u8 = 0x02;
const TUIC_ATYP_NONE: u8 = 0xff;
const DEFAULT_STREAMS: usize = 4;
const DEFAULT_REQUESTS: usize = 200;
const DEFAULT_PAYLOAD_SIZE: usize = 1_024;
const MAX_STREAMS: usize = 1024;
const MAX_PAYLOAD_SIZE: usize = 1024 * 1024;
const MAX_UDP_PAYLOAD_SIZE: usize = 65_507;
const MAX_REQUEST_RETRIES: usize = 3;
const UDP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);
const UDP_ECHO_SOCKET_BUFFER_SIZE: usize = 16 * 1024 * 1024;
const DEFAULT_SUITE_COMMANDS: &[&str] = &[
    "direct-tcp-stream",
    "direct-tcp-proxy-stream",
    "http-connect-stream",
    "shadowsocks-tcp-stream",
    "socks-tcp-stream",
    "trojan-tcp-stream",
    "vless-tcp-stream",
    "vmess-tcp-stream",
    "hy2-tcp",
    "hy2-tcp-stream",
    "hy2-udp",
    "tuic-tcp",
    "tuic-tcp-stream",
    "tuic-udp",
];

#[derive(Clone, Debug)]
struct BenchOptions {
    streams: usize,
    requests: usize,
    payload_size: usize,
}

impl Default for BenchOptions {
    fn default() -> Self {
        Self {
            streams: DEFAULT_STREAMS,
            requests: DEFAULT_REQUESTS,
            payload_size: DEFAULT_PAYLOAD_SIZE,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BenchReport {
    protocol: String,
    mode: String,
    streams: usize,
    runtime_workers: Option<usize>,
    requests_per_stream: usize,
    payload_bytes: usize,
    total_requests: usize,
    completed_requests: usize,
    upload_bytes: u64,
    download_bytes: u64,
    retries: usize,
    errors: usize,
    error_rate: f64,
    elapsed_ms: u128,
    requests_per_second: f64,
    roundtrip_mbps: f64,
    latency: LatencyReport,
}

impl BenchReport {
    fn completed(
        protocol: &'static str,
        mode: &'static str,
        options: &BenchOptions,
        runtime_workers: Option<usize>,
        upload_bytes: u64,
        download_bytes: u64,
        retries: usize,
        elapsed: Duration,
        latencies: &[u128],
    ) -> Self {
        let total_requests = options.streams.saturating_mul(options.requests);
        let completed_requests = latencies.len();
        let errors = total_requests.saturating_sub(completed_requests);
        let seconds = elapsed.as_secs_f64().max(f64::EPSILON);
        Self {
            protocol: protocol.to_string(),
            mode: mode.to_string(),
            streams: options.streams,
            runtime_workers,
            requests_per_stream: options.requests,
            payload_bytes: options.payload_size,
            total_requests,
            completed_requests,
            upload_bytes,
            download_bytes,
            retries,
            errors,
            error_rate: if total_requests == 0 {
                0.0
            } else {
                errors as f64 / total_requests as f64
            },
            elapsed_ms: elapsed.as_millis(),
            requests_per_second: completed_requests as f64 / seconds,
            roundtrip_mbps: ((upload_bytes + download_bytes) as f64 * 8.0) / seconds / 1_000_000.0,
            latency: latency_report(latencies),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LatencyReport {
    min_us: u128,
    p50_us: u128,
    p95_us: u128,
    p99_us: u128,
    max_us: u128,
}

#[derive(Debug)]
struct ClientStats {
    latencies: Vec<u128>,
    retries: usize,
}

#[derive(Clone, Debug)]
struct BenchSuiteOptions {
    bench: BenchOptions,
    commands: Vec<String>,
    repeats: usize,
    label: String,
    out: Option<PathBuf>,
}

#[derive(Debug)]
struct BenchCompareOptions {
    baseline: PathBuf,
    candidate: PathBuf,
    out: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct ExternalBenchSuiteOptions {
    bench: BenchOptions,
    commands: Vec<String>,
    repeats: usize,
    label: String,
    out: Option<PathBuf>,
    cores: HashMap<String, SocketAddr>,
    certs: HashMap<String, CertificateDer<'static>>,
    server_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BenchSuiteReport {
    schema: String,
    label: String,
    core: String,
    generated_at_unix: u64,
    streams: usize,
    requests_per_stream: usize,
    payload_bytes: usize,
    repeats: usize,
    runs: Vec<BenchSuiteRun>,
    summaries: Vec<BenchSummary>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BenchSuiteRun {
    command: String,
    repeat: usize,
    report: BenchReport,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BenchSummary {
    command: String,
    protocol: String,
    mode: String,
    repeats: usize,
    total_requests: usize,
    completed_requests_min: usize,
    errors_total: usize,
    retries_total: usize,
    requests_per_second_avg: f64,
    roundtrip_mbps_avg: f64,
    roundtrip_mbps_min: f64,
    roundtrip_mbps_max: f64,
    p95_us_avg: f64,
    p99_us_avg: f64,
}

#[derive(Debug, Serialize)]
struct BenchComparisonReport {
    schema: String,
    baseline_label: String,
    candidate_label: String,
    rows: Vec<BenchComparisonRow>,
}

#[derive(Debug, Serialize)]
struct BenchComparisonRow {
    command: String,
    baseline_roundtrip_mbps: f64,
    candidate_roundtrip_mbps: f64,
    throughput_change_percent: Option<f64>,
    baseline_p99_us: f64,
    candidate_p99_us: f64,
    p99_change_percent: Option<f64>,
    baseline_errors_total: usize,
    candidate_errors_total: usize,
    baseline_retries_total: usize,
    candidate_retries_total: usize,
}

pub fn run_bench(args: impl Iterator<Item = String>) -> Result<(), String> {
    let mut args = args;
    match args.next().as_deref() {
        Some("suite") => {
            let options = parse_bench_suite_options(args)?;
            let report = run_bench_suite(&options).map_err(|error| error.to_string())?;
            let json = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
            if let Some(path) = options.out.as_ref() {
                write_text_file(path, &json).map_err(|error| error.to_string())?;
            }
            println!("{json}");
            Ok(())
        }
        Some("compare") => {
            let options = parse_bench_compare_options(args)?;
            let report = compare_bench_suites(&options).map_err(|error| error.to_string())?;
            let json = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
            if let Some(path) = options.out.as_ref() {
                write_text_file(path, &json).map_err(|error| error.to_string())?;
            }
            println!("{json}");
            Ok(())
        }
        Some("external-suite") => {
            let options = parse_external_bench_suite_options(args)?;
            let report = run_external_bench_suite(&options).map_err(|error| error.to_string())?;
            let json = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
            if let Some(path) = options.out.as_ref() {
                write_text_file(path, &json).map_err(|error| error.to_string())?;
            }
            println!("{json}");
            Ok(())
        }
        Some(command) if canonical_bench_command(command).is_some() => {
            let command = canonical_bench_command(command).expect("known bench command");
            let options = parse_bench_options(args)?;
            let report = run_named_bench(command, &options).map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Some("--help") | Some("help") | None => {
            print_bench_usage();
            Ok(())
        }
        Some(command) => Err(format!("unknown bench command {command}")),
    }
}

fn parse_bench_options(args: impl Iterator<Item = String>) -> Result<BenchOptions, String> {
    let mut options = BenchOptions::default();
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--streams" => {
                options.streams = parse_next_usize(&mut args, "--streams")?;
            }
            "--requests" => {
                options.requests = parse_next_usize(&mut args, "--requests")?;
            }
            "--payload" => {
                options.payload_size = parse_next_usize(&mut args, "--payload")?;
            }
            "--help" | "help" => {
                print_bench_usage();
            }
            other => return Err(format!("unknown bench option {other}")),
        }
    }
    validate_bench_options(&options)?;
    Ok(options)
}

fn parse_next_usize(
    args: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<usize, String> {
    let value = args
        .next()
        .ok_or_else(|| format!("{option} requires a positive integer"))?;
    value
        .parse::<usize>()
        .map_err(|_| format!("{option} requires a positive integer"))
}

fn validate_bench_options(options: &BenchOptions) -> Result<(), String> {
    if options.streams == 0 || options.streams > MAX_STREAMS {
        return Err(format!("--streams must be between 1 and {MAX_STREAMS}"));
    }
    if options.requests == 0 {
        return Err("--requests must be greater than 0".to_string());
    }
    if options.payload_size == 0 || options.payload_size > MAX_PAYLOAD_SIZE {
        return Err(format!(
            "--payload must be between 1 and {MAX_PAYLOAD_SIZE}"
        ));
    }
    Ok(())
}

fn parse_bench_suite_options(
    args: impl Iterator<Item = String>,
) -> Result<BenchSuiteOptions, String> {
    let mut bench = BenchOptions::default();
    let mut repeats = 1usize;
    let mut commands = DEFAULT_SUITE_COMMANDS
        .iter()
        .map(|command| command.to_string())
        .collect::<Vec<_>>();
    let mut label = "keli-core-rs".to_string();
    let mut out = None;
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--streams" => bench.streams = parse_next_usize(&mut args, "--streams")?,
            "--requests" => bench.requests = parse_next_usize(&mut args, "--requests")?,
            "--payload" => bench.payload_size = parse_next_usize(&mut args, "--payload")?,
            "--repeats" => repeats = parse_next_usize(&mut args, "--repeats")?,
            "--commands" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--commands requires a comma-separated list".to_string())?;
                commands = value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|value| {
                        canonical_bench_command(value)
                            .ok_or_else(|| format!("unknown bench command {value}"))
                            .map(str::to_string)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if commands.is_empty() {
                    return Err("--commands must contain at least one command".to_string());
                }
            }
            "--label" => {
                label = args
                    .next()
                    .ok_or_else(|| "--label requires a value".to_string())?;
                if label.trim().is_empty() {
                    return Err("--label cannot be empty".to_string());
                }
            }
            "--out" => {
                out = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| "--out requires a file path".to_string())?,
                ));
            }
            "--help" | "help" => print_bench_usage(),
            other => return Err(format!("unknown bench suite option {other}")),
        }
    }
    validate_bench_options(&bench)?;
    if repeats == 0 || repeats > 100 {
        return Err("--repeats must be between 1 and 100".to_string());
    }
    Ok(BenchSuiteOptions {
        bench,
        commands,
        repeats,
        label,
        out,
    })
}

fn parse_bench_compare_options(
    args: impl Iterator<Item = String>,
) -> Result<BenchCompareOptions, String> {
    let mut baseline = None;
    let mut candidate = None;
    let mut out = None;
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--baseline" => {
                baseline =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        "--baseline requires a suite json path".to_string()
                    })?));
            }
            "--candidate" => {
                candidate =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        "--candidate requires a suite json path".to_string()
                    })?));
            }
            "--out" => {
                out = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| "--out requires a file path".to_string())?,
                ));
            }
            "--help" | "help" => print_bench_usage(),
            other => return Err(format!("unknown bench compare option {other}")),
        }
    }
    Ok(BenchCompareOptions {
        baseline: baseline.ok_or_else(|| "--baseline is required".to_string())?,
        candidate: candidate.ok_or_else(|| "--candidate is required".to_string())?,
        out,
    })
}

fn parse_external_bench_suite_options(
    args: impl Iterator<Item = String>,
) -> Result<ExternalBenchSuiteOptions, String> {
    let mut bench = BenchOptions::default();
    let mut repeats = 1usize;
    let mut commands = vec!["vless-tcp-stream".to_string()];
    let mut label = "external-core".to_string();
    let mut out = None;
    let mut cores = HashMap::<String, SocketAddr>::new();
    let mut certs = HashMap::<String, CertificateDer<'static>>::new();
    let mut default_cert = None;
    let mut server_name = "localhost".to_string();
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--streams" => bench.streams = parse_next_usize(&mut args, "--streams")?,
            "--requests" => bench.requests = parse_next_usize(&mut args, "--requests")?,
            "--payload" => bench.payload_size = parse_next_usize(&mut args, "--payload")?,
            "--repeats" => repeats = parse_next_usize(&mut args, "--repeats")?,
            "--commands" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--commands requires a comma-separated list".to_string())?;
                commands = value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|value| {
                        canonical_bench_command(value)
                            .ok_or_else(|| format!("unknown bench command {value}"))
                            .and_then(|command| match command {
                                "http-connect-stream"
                                | "shadowsocks-tcp-stream"
                                | "socks-tcp-stream"
                                | "trojan-tcp-stream"
                                | "hy2-tcp"
                                | "hy2-tcp-stream"
                                | "hy2-udp"
                                | "tuic-tcp"
                                | "tuic-tcp-stream"
                                | "tuic-udp"
                                | "vless-tcp"
                                | "vless-tcp-stream"
                                | "vmess-tcp-stream" => Ok(command.to_string()),
                                _ => Err(format!(
                                    "external-suite does not support {value}; use TCP stream or QUIC commands backed by one external inbound"
                                )),
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if commands.is_empty() {
                    return Err("--commands must contain at least one command".to_string());
                }
            }
            "--vless-core" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--vless-core requires host:port".to_string())?;
                let addr = value
                    .parse::<SocketAddr>()
                    .map_err(|_| "--vless-core requires a socket address".to_string())?;
                cores.insert("vless-tcp".to_string(), addr);
                cores.insert("vless-tcp-stream".to_string(), addr);
            }
            "--core" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--core requires command=host:port".to_string())?;
                let (command, addr) = parse_external_core_mapping(&value)?;
                cores.insert(command, addr);
            }
            "--cert" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--cert requires path or command=path".to_string())?;
                if let Some((command, path)) = value.split_once('=') {
                    let command = canonical_bench_command(command.trim()).ok_or_else(|| {
                        format!("unknown external bench command {}", command.trim())
                    })?;
                    if !is_external_quic_command(command) {
                        return Err(format!(
                            "--cert is only used by external QUIC commands, got {command}"
                        ));
                    }
                    certs.insert(
                        command.to_string(),
                        load_bench_certificate(Path::new(path.trim()))?,
                    );
                } else {
                    default_cert = Some(load_bench_certificate(Path::new(value.trim()))?);
                }
            }
            "--server-name" => {
                server_name = args
                    .next()
                    .ok_or_else(|| "--server-name requires a value".to_string())?;
                if server_name.trim().is_empty() {
                    return Err("--server-name cannot be empty".to_string());
                }
            }
            "--label" => {
                label = args
                    .next()
                    .ok_or_else(|| "--label requires a value".to_string())?;
                if label.trim().is_empty() {
                    return Err("--label cannot be empty".to_string());
                }
            }
            "--out" => {
                out = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| "--out requires a file path".to_string())?,
                ));
            }
            "--help" | "help" => print_bench_usage(),
            other => return Err(format!("unknown bench external-suite option {other}")),
        }
    }
    validate_bench_options(&bench)?;
    if repeats == 0 || repeats > 100 {
        return Err("--repeats must be between 1 and 100".to_string());
    }
    for command in &commands {
        if !cores.contains_key(command) {
            return Err(format!("missing --core {command}=host:port"));
        }
        if is_external_quic_command(command) && !certs.contains_key(command) {
            let cert = default_cert
                .as_ref()
                .ok_or_else(|| format!("missing --cert for external QUIC command {command}"))?
                .clone();
            certs.insert(command.clone(), cert);
        }
    }
    Ok(ExternalBenchSuiteOptions {
        bench,
        commands,
        repeats,
        label,
        out,
        cores,
        certs,
        server_name,
    })
}

fn parse_external_core_mapping(value: &str) -> Result<(String, SocketAddr), String> {
    let (command, addr) = value
        .split_once('=')
        .ok_or_else(|| "--core requires command=host:port".to_string())?;
    let command = canonical_bench_command(command.trim())
        .ok_or_else(|| format!("unknown external bench command {}", command.trim()))?;
    let command = match command {
        "http-connect-stream"
        | "hy2-tcp"
        | "hy2-tcp-stream"
        | "hy2-udp"
        | "shadowsocks-tcp-stream"
        | "socks-tcp-stream"
        | "trojan-tcp-stream"
        | "tuic-tcp"
        | "tuic-tcp-stream"
        | "tuic-udp"
        | "vless-tcp"
        | "vless-tcp-stream"
        | "vmess-tcp-stream" => command.to_string(),
        _ => {
            return Err(format!(
                "external-suite does not support {command}; use TCP stream or QUIC commands backed by one external inbound"
            ));
        }
    };
    let addr = addr
        .trim()
        .parse::<SocketAddr>()
        .map_err(|_| "--core requires command=host:port".to_string())?;
    Ok((command, addr))
}

fn is_external_quic_command(command: &str) -> bool {
    matches!(
        command,
        "hy2-tcp" | "hy2-tcp-stream" | "hy2-udp" | "tuic-tcp" | "tuic-tcp-stream" | "tuic-udp"
    )
}

fn load_bench_certificate(path: &Path) -> Result<CertificateDer<'static>, String> {
    let data = fs::read(path)
        .map_err(|error| format!("failed to read cert {}: {error}", path.display()))?;
    let mut reader = std::io::BufReader::new(data.as_slice());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to parse PEM cert {}: {error}", path.display()))?;
    if let Some(cert) = certs.into_iter().next() {
        return Ok(cert);
    }
    if data.is_empty() {
        return Err(format!("cert {} is empty", path.display()));
    }
    Ok(CertificateDer::from(data))
}

fn bench_quic_runtime_workers() -> usize {
    thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .clamp(2, 16)
}

fn print_bench_usage() {
    println!(
        "bench commands:\n  bench direct-tcp-stream [--streams N] [--requests N] [--payload BYTES]\n  bench direct-tcp-proxy-stream [--streams N] [--requests N] [--payload BYTES]\n  bench http-connect-stream [--streams N] [--requests N] [--payload BYTES]\n  bench shadowsocks-tcp-stream [--streams N] [--requests N] [--payload BYTES]\n  bench socks-tcp-stream [--streams N] [--requests N] [--payload BYTES]\n  bench trojan-tcp-stream [--streams N] [--requests N] [--payload BYTES]\n  bench vless-tcp [--streams N] [--requests N] [--payload BYTES]\n  bench vless-tcp-stream [--streams N] [--requests N] [--payload BYTES]\n  bench vmess-tcp-stream [--streams N] [--requests N] [--payload BYTES]\n  bench hy2-tcp [--streams N] [--requests N] [--payload BYTES]\n  bench hy2-tcp-stream [--streams N] [--requests N] [--payload BYTES]\n  bench hy2-udp [--streams N] [--requests N] [--payload BYTES]\n  bench tuic-tcp [--streams N] [--requests N] [--payload BYTES]\n  bench tuic-tcp-stream [--streams N] [--requests N] [--payload BYTES]\n  bench tuic-udp [--streams N] [--requests N] [--payload BYTES]\n  bench suite [--commands a,b] [--streams N] [--requests N] [--payload BYTES] [--repeats N] [--label NAME] [--out FILE]\n  bench external-suite --core command=HOST:PORT [--core other=HOST:PORT] [--cert CERT.pem] [--cert command=CERT.pem] [--server-name NAME] [--commands a,b] [--streams N] [--requests N] [--payload BYTES] [--repeats N] [--label NAME] [--out FILE]\n  bench compare --baseline FILE --candidate FILE [--out FILE]"
    );
}

fn canonical_bench_command(command: &str) -> Option<&'static str> {
    match command {
        "direct-tcp-stream" | "direct-stream" | "tcp-stream" => Some("direct-tcp-stream"),
        "direct-tcp-proxy-stream" | "direct-proxy-stream" | "tcp-proxy-stream" => {
            Some("direct-tcp-proxy-stream")
        }
        "http-connect-stream" | "http-tcp-stream" | "http-stream" => Some("http-connect-stream"),
        "shadowsocks-tcp-stream" | "ss-tcp-stream" | "ss-stream" => Some("shadowsocks-tcp-stream"),
        "socks-tcp-stream" | "socks5-tcp-stream" | "socks-stream" => Some("socks-tcp-stream"),
        "trojan-tcp-stream" | "trojan-stream" => Some("trojan-tcp-stream"),
        "vless-tcp" => Some("vless-tcp"),
        "vless-tcp-stream" | "vless-stream" => Some("vless-tcp-stream"),
        "vmess-tcp-stream" | "vmess-stream" => Some("vmess-tcp-stream"),
        "hy2-tcp" | "hysteria2-tcp" => Some("hy2-tcp"),
        "hy2-tcp-stream" | "hysteria2-tcp-stream" | "hy2-stream" => Some("hy2-tcp-stream"),
        "hy2-udp" | "hysteria2-udp" => Some("hy2-udp"),
        "tuic-tcp" => Some("tuic-tcp"),
        "tuic-tcp-stream" | "tuic-stream" => Some("tuic-tcp-stream"),
        "tuic-udp" => Some("tuic-udp"),
        _ => None,
    }
}

fn run_named_bench(command: &str, options: &BenchOptions) -> io::Result<BenchReport> {
    match canonical_bench_command(command) {
        Some("direct-tcp-stream") => run_direct_tcp_stream_bench(options),
        Some("direct-tcp-proxy-stream") => run_direct_tcp_proxy_stream_bench(options),
        Some("http-connect-stream") => run_http_connect_stream_bench(options),
        Some("shadowsocks-tcp-stream") => run_shadowsocks_tcp_stream_bench(options),
        Some("socks-tcp-stream") => run_socks_tcp_stream_bench(options),
        Some("trojan-tcp-stream") => run_trojan_tcp_stream_bench(options),
        Some("vless-tcp") => run_vless_tcp_bench(options),
        Some("vless-tcp-stream") => run_vless_tcp_stream_bench(options),
        Some("vmess-tcp-stream") => run_vmess_tcp_stream_bench(options),
        Some("hy2-tcp") => run_hy2_tcp_bench(options),
        Some("hy2-tcp-stream") => run_hy2_tcp_stream_bench(options),
        Some("hy2-udp") => run_hy2_udp_bench(options),
        Some("tuic-tcp") => run_tuic_tcp_bench(options),
        Some("tuic-tcp-stream") => run_tuic_tcp_stream_bench(options),
        Some("tuic-udp") => run_tuic_udp_bench(options),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown bench command {command}"),
        )),
    }
}

fn run_bench_suite(options: &BenchSuiteOptions) -> io::Result<BenchSuiteReport> {
    let mut runs = Vec::new();
    for command in &options.commands {
        for repeat in 1..=options.repeats {
            let report = run_named_bench(command, &options.bench)?;
            runs.push(BenchSuiteRun {
                command: command.clone(),
                repeat,
                report,
            });
            settle_bench_resources();
        }
    }
    let summaries = summarize_bench_runs(&runs);
    Ok(BenchSuiteReport {
        schema: "keli-core-bench-suite-v1".to_string(),
        label: options.label.clone(),
        core: "keli-core-rs".to_string(),
        generated_at_unix: now_unix_secs(),
        streams: options.bench.streams,
        requests_per_stream: options.bench.requests,
        payload_bytes: options.bench.payload_size,
        repeats: options.repeats,
        runs,
        summaries,
    })
}

fn run_external_bench_suite(options: &ExternalBenchSuiteOptions) -> io::Result<BenchSuiteReport> {
    let mut runs = Vec::new();
    for command in &options.commands {
        for repeat in 1..=options.repeats {
            let core_addr = *options.cores.get(command).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("missing external core addr for {command}"),
                )
            })?;
            let report = run_external_named_bench(command, options, core_addr)?;
            runs.push(BenchSuiteRun {
                command: command.clone(),
                repeat,
                report,
            });
            settle_bench_resources();
        }
    }
    let summaries = summarize_bench_runs(&runs);
    Ok(BenchSuiteReport {
        schema: "keli-core-bench-suite-v1".to_string(),
        label: options.label.clone(),
        core: "external".to_string(),
        generated_at_unix: now_unix_secs(),
        streams: options.bench.streams,
        requests_per_stream: options.bench.requests,
        payload_bytes: options.bench.payload_size,
        repeats: options.repeats,
        runs,
        summaries,
    })
}

fn settle_bench_resources() {
    thread::sleep(Duration::from_millis(500));
}

fn run_external_named_bench(
    command: &str,
    suite_options: &ExternalBenchSuiteOptions,
    core_addr: SocketAddr,
) -> io::Result<BenchReport> {
    let options = &suite_options.bench;
    match canonical_bench_command(command) {
        Some("hy2-tcp") => run_external_hy2_tcp_bench(
            options,
            core_addr,
            external_cert_for(command, suite_options)?,
            &suite_options.server_name,
        ),
        Some("hy2-tcp-stream") => run_external_hy2_tcp_stream_bench(
            options,
            core_addr,
            external_cert_for(command, suite_options)?,
            &suite_options.server_name,
        ),
        Some("hy2-udp") => run_external_hy2_udp_bench(
            options,
            core_addr,
            external_cert_for(command, suite_options)?,
            &suite_options.server_name,
        ),
        Some("http-connect-stream") => run_external_stream_bench(
            options,
            core_addr,
            "http-connect",
            "connection-per-stream",
            run_http_connect_stream_client,
        ),
        Some("shadowsocks-tcp-stream") => run_external_stream_bench(
            options,
            core_addr,
            "shadowsocks-tcp",
            "connection-per-stream",
            run_shadowsocks_tcp_stream_client,
        ),
        Some("socks-tcp-stream") => run_external_stream_bench(
            options,
            core_addr,
            "socks-tcp",
            "connection-per-stream",
            run_socks_tcp_stream_client,
        ),
        Some("trojan-tcp-stream") => run_external_stream_bench(
            options,
            core_addr,
            "trojan-tcp",
            "connection-per-stream",
            run_trojan_tcp_stream_client,
        ),
        Some("tuic-tcp") => run_external_tuic_tcp_bench(
            options,
            core_addr,
            external_cert_for(command, suite_options)?,
            &suite_options.server_name,
        ),
        Some("tuic-tcp-stream") => run_external_tuic_tcp_stream_bench(
            options,
            core_addr,
            external_cert_for(command, suite_options)?,
            &suite_options.server_name,
        ),
        Some("tuic-udp") => run_external_tuic_udp_bench(
            options,
            core_addr,
            external_cert_for(command, suite_options)?,
            &suite_options.server_name,
        ),
        Some("vless-tcp") => run_external_vless_tcp_bench(options, core_addr),
        Some("vless-tcp-stream") => run_external_vless_tcp_stream_bench(options, core_addr),
        Some("vmess-tcp-stream") => run_external_stream_bench(
            options,
            core_addr,
            "vmess-tcp",
            "connection-per-stream",
            run_vmess_tcp_stream_client,
        ),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("external bench command {command} is not supported yet"),
        )),
    }
}

fn external_cert_for(
    command: &str,
    options: &ExternalBenchSuiteOptions,
) -> io::Result<CertificateDer<'static>> {
    options.certs.get(command).cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing external cert for {command}"),
        )
    })
}

fn run_external_stream_bench(
    options: &BenchOptions,
    core_addr: SocketAddr,
    protocol: &'static str,
    mode: &'static str,
    client: fn(SocketAddr, SocketAddr, usize, &BenchOptions) -> io::Result<ClientStats>,
) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        workers.push(thread::spawn(move || {
            client(core_addr, echo_addr, stream_id, &options)
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "bench worker panicked"))??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(echo_addr);
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        protocol,
        mode,
        options,
        None,
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

fn run_external_hy2_tcp_bench(
    options: &BenchOptions,
    core_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    server_name: &str,
) -> io::Result<BenchReport> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(bench_quic_runtime_workers())
        .enable_all()
        .build()?
        .block_on(run_external_hy2_tcp_bench_async(
            options,
            core_addr,
            cert_der,
            server_name,
        ))
}

fn run_external_hy2_tcp_stream_bench(
    options: &BenchOptions,
    core_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    server_name: &str,
) -> io::Result<BenchReport> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(bench_quic_runtime_workers())
        .enable_all()
        .build()?
        .block_on(run_external_hy2_tcp_stream_bench_async(
            options,
            core_addr,
            cert_der,
            server_name,
        ))
}

fn run_external_hy2_udp_bench(
    options: &BenchOptions,
    core_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    server_name: &str,
) -> io::Result<BenchReport> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(bench_quic_runtime_workers())
        .enable_all()
        .build()?
        .block_on(run_external_hy2_udp_bench_async(
            options,
            core_addr,
            cert_der,
            server_name,
        ))
}

fn run_external_tuic_tcp_bench(
    options: &BenchOptions,
    core_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    server_name: &str,
) -> io::Result<BenchReport> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(bench_quic_runtime_workers())
        .enable_all()
        .build()?
        .block_on(run_external_tuic_tcp_bench_async(
            options,
            core_addr,
            cert_der,
            server_name,
        ))
}

fn run_external_tuic_tcp_stream_bench(
    options: &BenchOptions,
    core_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    server_name: &str,
) -> io::Result<BenchReport> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(bench_quic_runtime_workers())
        .enable_all()
        .build()?
        .block_on(run_external_tuic_tcp_stream_bench_async(
            options,
            core_addr,
            cert_der,
            server_name,
        ))
}

fn run_external_tuic_udp_bench(
    options: &BenchOptions,
    core_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    server_name: &str,
) -> io::Result<BenchReport> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(bench_quic_runtime_workers())
        .enable_all()
        .build()?
        .block_on(run_external_tuic_udp_bench_async(
            options,
            core_addr,
            cert_der,
            server_name,
        ))
}

fn run_direct_tcp_stream_bench(options: &BenchOptions) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        workers.push(thread::spawn(move || {
            let mut stream = TcpStream::connect(echo_addr)?;
            run_plain_stream_echo_client(&mut stream, "direct-tcp", stream_id, &options)
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "bench worker panicked"))??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(echo_addr);
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "direct-tcp",
        "direct-echo-stream",
        options,
        None,
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

fn run_direct_tcp_proxy_stream_bench(options: &BenchOptions) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;
    let proxy_stop = Arc::new(AtomicBool::new(false));
    let (proxy_addr, proxy_thread) = start_direct_tcp_proxy(echo_addr, proxy_stop.clone())?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        workers.push(thread::spawn(move || {
            let mut stream = TcpStream::connect(proxy_addr)?;
            run_plain_stream_echo_client(&mut stream, "direct-tcp-proxy", stream_id, &options)
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "bench worker panicked"))??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    proxy_stop.store(true, Ordering::SeqCst);
    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(proxy_addr);
    let _ = TcpStream::connect(echo_addr);
    join_server(proxy_thread)?;
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "direct-tcp-proxy",
        "raw-proxy-stream",
        options,
        None,
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

fn run_http_connect_stream_bench(options: &BenchOptions) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;
    let core_stop = Arc::new(AtomicBool::new(false));
    let (core_addr, core_thread) = start_http_proxy_server(core_stop.clone())?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        workers.push(thread::spawn(move || {
            run_http_connect_stream_client(core_addr, echo_addr, stream_id, &options)
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "bench worker panicked"))??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    core_stop.store(true, Ordering::SeqCst);
    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(core_addr);
    let _ = TcpStream::connect(echo_addr);
    join_server(core_thread)?;
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "http-connect",
        "connection-per-stream",
        options,
        None,
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

fn run_shadowsocks_tcp_stream_bench(options: &BenchOptions) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;
    let core_stop = Arc::new(AtomicBool::new(false));
    let (core_addr, core_thread) = start_shadowsocks_server(core_stop.clone())?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        workers.push(thread::spawn(move || {
            run_shadowsocks_tcp_stream_client(core_addr, echo_addr, stream_id, &options)
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "bench worker panicked"))??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    core_stop.store(true, Ordering::SeqCst);
    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(core_addr);
    let _ = TcpStream::connect(echo_addr);
    join_server(core_thread)?;
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "shadowsocks-tcp",
        "connection-per-stream",
        options,
        None,
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

fn run_socks_tcp_stream_bench(options: &BenchOptions) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;
    let core_stop = Arc::new(AtomicBool::new(false));
    let (core_addr, core_thread) = start_socks_server(core_stop.clone())?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        workers.push(thread::spawn(move || {
            run_socks_tcp_stream_client(core_addr, echo_addr, stream_id, &options)
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "bench worker panicked"))??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    core_stop.store(true, Ordering::SeqCst);
    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(core_addr);
    let _ = TcpStream::connect(echo_addr);
    join_server(core_thread)?;
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "socks-tcp",
        "connection-per-stream",
        options,
        None,
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

fn run_trojan_tcp_stream_bench(options: &BenchOptions) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;
    let core_stop = Arc::new(AtomicBool::new(false));
    let (core_addr, core_thread) = start_trojan_server(core_stop.clone())?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        workers.push(thread::spawn(move || {
            run_trojan_tcp_stream_client(core_addr, echo_addr, stream_id, &options)
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "bench worker panicked"))??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    core_stop.store(true, Ordering::SeqCst);
    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(core_addr);
    let _ = TcpStream::connect(echo_addr);
    join_server(core_thread)?;
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "trojan-tcp",
        "connection-per-stream",
        options,
        None,
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

fn summarize_bench_runs(runs: &[BenchSuiteRun]) -> Vec<BenchSummary> {
    let mut commands = Vec::<String>::new();
    for run in runs {
        if !commands.contains(&run.command) {
            commands.push(run.command.clone());
        }
    }
    commands
        .into_iter()
        .filter_map(|command| {
            let reports = runs
                .iter()
                .filter(|run| run.command == command)
                .map(|run| &run.report)
                .collect::<Vec<_>>();
            summarize_reports(&command, &reports)
        })
        .collect()
}

fn summarize_reports(command: &str, reports: &[&BenchReport]) -> Option<BenchSummary> {
    let first = reports.first()?;
    let repeats = reports.len();
    let completed_requests_min = reports
        .iter()
        .map(|report| report.completed_requests)
        .min()
        .unwrap_or(0);
    Some(BenchSummary {
        command: command.to_string(),
        protocol: first.protocol.clone(),
        mode: first.mode.clone(),
        repeats,
        total_requests: reports
            .iter()
            .map(|report| report.total_requests)
            .max()
            .unwrap_or(0),
        completed_requests_min,
        errors_total: reports.iter().map(|report| report.errors).sum(),
        retries_total: reports.iter().map(|report| report.retries).sum(),
        requests_per_second_avg: avg_f64(reports.iter().map(|report| report.requests_per_second)),
        roundtrip_mbps_avg: avg_f64(reports.iter().map(|report| report.roundtrip_mbps)),
        roundtrip_mbps_min: reports
            .iter()
            .map(|report| report.roundtrip_mbps)
            .fold(f64::INFINITY, f64::min),
        roundtrip_mbps_max: reports
            .iter()
            .map(|report| report.roundtrip_mbps)
            .fold(0.0, f64::max),
        p95_us_avg: avg_f64(reports.iter().map(|report| report.latency.p95_us as f64)),
        p99_us_avg: avg_f64(reports.iter().map(|report| report.latency.p99_us as f64)),
    })
}

fn compare_bench_suites(options: &BenchCompareOptions) -> io::Result<BenchComparisonReport> {
    let baseline = read_bench_suite(&options.baseline)?;
    let candidate = read_bench_suite(&options.candidate)?;
    let mut rows = Vec::new();
    for baseline_summary in &baseline.summaries {
        if let Some(candidate_summary) = candidate
            .summaries
            .iter()
            .find(|summary| summary.command == baseline_summary.command)
        {
            rows.push(BenchComparisonRow {
                command: baseline_summary.command.clone(),
                baseline_roundtrip_mbps: baseline_summary.roundtrip_mbps_avg,
                candidate_roundtrip_mbps: candidate_summary.roundtrip_mbps_avg,
                throughput_change_percent: percent_change(
                    baseline_summary.roundtrip_mbps_avg,
                    candidate_summary.roundtrip_mbps_avg,
                ),
                baseline_p99_us: baseline_summary.p99_us_avg,
                candidate_p99_us: candidate_summary.p99_us_avg,
                p99_change_percent: percent_change(
                    baseline_summary.p99_us_avg,
                    candidate_summary.p99_us_avg,
                ),
                baseline_errors_total: baseline_summary.errors_total,
                candidate_errors_total: candidate_summary.errors_total,
                baseline_retries_total: baseline_summary.retries_total,
                candidate_retries_total: candidate_summary.retries_total,
            });
        }
    }
    Ok(BenchComparisonReport {
        schema: "keli-core-bench-comparison-v1".to_string(),
        baseline_label: baseline.label,
        candidate_label: candidate.label,
        rows,
    })
}

fn read_bench_suite(path: &Path) -> io::Result<BenchSuiteReport> {
    let contents = fs::read_to_string(path)?;
    serde_json::from_str(&contents).map_err(io_other)
}

fn write_text_file(path: &Path, contents: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)
}

fn avg_f64(values: impl Iterator<Item = f64>) -> f64 {
    let mut count = 0usize;
    let mut total = 0.0;
    for value in values {
        count += 1;
        total += value;
    }
    if count == 0 {
        0.0
    } else {
        total / count as f64
    }
}

fn percent_change(baseline: f64, candidate: f64) -> Option<f64> {
    (baseline > 0.0).then(|| ((candidate - baseline) / baseline) * 100.0)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn run_vless_tcp_bench(options: &BenchOptions) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;
    let core_stop = Arc::new(AtomicBool::new(false));
    let (core_addr, core_thread) = start_vless_server(echo_addr, core_stop.clone())?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        workers.push(thread::spawn(move || {
            run_vless_tcp_client(core_addr, echo_addr, stream_id, &options)
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "bench worker panicked"))??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    core_stop.store(true, Ordering::SeqCst);
    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(core_addr);
    let _ = TcpStream::connect(echo_addr);
    join_server(core_thread)?;
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "vless-tcp",
        "connection-per-request",
        options,
        None,
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

fn run_external_vless_tcp_bench(
    options: &BenchOptions,
    core_addr: SocketAddr,
) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        workers.push(thread::spawn(move || {
            run_vless_tcp_client(core_addr, echo_addr, stream_id, &options)
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "bench worker panicked"))??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(echo_addr);
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "vless-tcp",
        "connection-per-request",
        options,
        None,
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

fn run_vmess_tcp_stream_bench(options: &BenchOptions) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;
    let core_stop = Arc::new(AtomicBool::new(false));
    let (core_addr, core_thread) = start_vmess_server(core_stop.clone())?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        workers.push(thread::spawn(move || {
            run_vmess_tcp_stream_client(core_addr, echo_addr, stream_id, &options)
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "bench worker panicked"))??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    core_stop.store(true, Ordering::SeqCst);
    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(core_addr);
    let _ = TcpStream::connect(echo_addr);
    join_server(core_thread)?;
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "vmess-tcp",
        "connection-per-stream",
        options,
        None,
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

fn run_hy2_tcp_bench(options: &BenchOptions) -> io::Result<BenchReport> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(bench_quic_runtime_workers())
        .enable_all()
        .build()?
        .block_on(run_hy2_tcp_bench_async(options))
}

fn run_hy2_tcp_stream_bench(options: &BenchOptions) -> io::Result<BenchReport> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(bench_quic_runtime_workers())
        .enable_all()
        .build()?
        .block_on(run_hy2_tcp_stream_bench_async(options))
}

fn run_hy2_udp_bench(options: &BenchOptions) -> io::Result<BenchReport> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(bench_quic_runtime_workers())
        .enable_all()
        .build()?
        .block_on(run_hy2_udp_bench_async(options))
}

fn run_tuic_tcp_bench(options: &BenchOptions) -> io::Result<BenchReport> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(bench_quic_runtime_workers())
        .enable_all()
        .build()?
        .block_on(run_tuic_tcp_bench_async(options))
}

fn run_tuic_tcp_stream_bench(options: &BenchOptions) -> io::Result<BenchReport> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(bench_quic_runtime_workers())
        .enable_all()
        .build()?
        .block_on(run_tuic_tcp_stream_bench_async(options))
}

fn run_tuic_udp_bench(options: &BenchOptions) -> io::Result<BenchReport> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(bench_quic_runtime_workers())
        .enable_all()
        .build()?
        .block_on(run_tuic_udp_bench_async(options))
}

async fn collect_quic_workers(
    workers: Vec<tokio::task::JoinHandle<io::Result<ClientStats>>>,
    label: &str,
) -> io::Result<(Vec<u128>, usize)> {
    let mut latencies = Vec::new();
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker.await.map_err(|_| {
            io::Error::new(io::ErrorKind::Other, format!("{label} worker panicked"))
        })??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    Ok((latencies, retries))
}

fn start_udp_echo_task(
    echo_stop: Arc<AtomicBool>,
) -> io::Result<(
    Arc<tokio::net::UdpSocket>,
    SocketAddr,
    tokio::task::JoinHandle<io::Result<()>>,
)> {
    let echo = Arc::new(bind_bench_udp_echo_socket()?);
    let echo_addr = echo.local_addr()?;
    let echo_task = {
        let echo = echo.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 65_535];
            while !echo_stop.load(Ordering::SeqCst) {
                match tokio::time::timeout(Duration::from_millis(20), echo.recv_from(&mut buffer))
                    .await
                {
                    Ok(Ok((read, peer))) => {
                        echo.send_to(&buffer[..read], peer).await?;
                    }
                    Ok(Err(error)) => return Err(error),
                    Err(_) => {}
                }
            }
            Ok::<(), io::Error>(())
        })
    };
    Ok((echo, echo_addr, echo_task))
}

async fn run_external_hy2_tcp_bench_async(
    options: &BenchOptions,
    core_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    server_name: &str,
) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;
    let client_endpoint = hy2_client_endpoint(cert_der)?;
    let connection = client_endpoint
        .connect(core_addr, server_name)
        .map_err(io_other)?
        .await
        .map_err(io_other)?;
    authenticate_hy2(&connection).await?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        let connection = connection.clone();
        workers.push(tokio::spawn(async move {
            run_hy2_tcp_client(connection, echo_addr, stream_id, &options).await
        }));
    }

    let (mut latencies, retries) = collect_quic_workers(workers, "external hy2 tcp").await?;
    let elapsed = started.elapsed();

    connection.close(0u32.into(), b"bench done");
    client_endpoint.wait_idle().await;
    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(echo_addr);
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "hy2-tcp",
        "external-single-quic-connection",
        options,
        Some(bench_quic_runtime_workers()),
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

async fn run_external_hy2_tcp_stream_bench_async(
    options: &BenchOptions,
    core_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    server_name: &str,
) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;
    let client_endpoint = hy2_client_endpoint(cert_der)?;
    let connection = client_endpoint
        .connect(core_addr, server_name)
        .map_err(io_other)?
        .await
        .map_err(io_other)?;
    authenticate_hy2(&connection).await?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        let connection = connection.clone();
        workers.push(tokio::spawn(async move {
            run_hy2_tcp_stream_client(connection, echo_addr, stream_id, &options).await
        }));
    }

    let (mut latencies, retries) = collect_quic_workers(workers, "external hy2 stream").await?;
    let elapsed = started.elapsed();

    connection.close(0u32.into(), b"bench done");
    client_endpoint.wait_idle().await;
    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(echo_addr);
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "hy2-tcp",
        "external-hy2-tcp-stream-per-worker",
        options,
        Some(bench_quic_runtime_workers()),
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

async fn run_external_hy2_udp_bench_async(
    options: &BenchOptions,
    core_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    server_name: &str,
) -> io::Result<BenchReport> {
    validate_udp_bench_payload(options)?;
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo, echo_addr, echo_task) = start_udp_echo_task(echo_stop.clone())?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        let cert_der = cert_der.clone();
        let server_name = server_name.to_string();
        workers.push(tokio::spawn(async move {
            run_hy2_udp_client(
                core_addr,
                cert_der,
                server_name,
                echo_addr,
                stream_id,
                &options,
            )
            .await
        }));
    }

    let (mut latencies, retries) = collect_quic_workers(workers, "external hy2 udp").await?;
    let elapsed = started.elapsed();

    echo_stop.store(true, Ordering::SeqCst);
    drop(echo);
    echo_task
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "hy2 udp echo task panicked"))??;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "hy2-udp",
        "external-hy2-udp-datagram-connection-per-worker",
        options,
        Some(bench_quic_runtime_workers()),
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

async fn run_external_tuic_tcp_bench_async(
    options: &BenchOptions,
    core_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    server_name: &str,
) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;
    let client_endpoint = hy2_client_endpoint(cert_der)?;
    let connection = client_endpoint
        .connect(core_addr, server_name)
        .map_err(io_other)?
        .await
        .map_err(io_other)?;
    authenticate_tuic(&connection).await?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        let connection = connection.clone();
        workers.push(tokio::spawn(async move {
            run_tuic_tcp_client(connection, echo_addr, stream_id, &options).await
        }));
    }

    let (mut latencies, retries) = collect_quic_workers(workers, "external tuic tcp").await?;
    let elapsed = started.elapsed();

    connection.close(0u32.into(), b"bench done");
    client_endpoint.wait_idle().await;
    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(echo_addr);
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "tuic-tcp",
        "external-single-quic-connection",
        options,
        Some(bench_quic_runtime_workers()),
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

async fn run_external_tuic_tcp_stream_bench_async(
    options: &BenchOptions,
    core_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    server_name: &str,
) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;
    let client_endpoint = hy2_client_endpoint(cert_der)?;
    let connection = client_endpoint
        .connect(core_addr, server_name)
        .map_err(io_other)?
        .await
        .map_err(io_other)?;
    authenticate_tuic(&connection).await?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        let connection = connection.clone();
        workers.push(tokio::spawn(async move {
            run_tuic_tcp_stream_client(connection, echo_addr, stream_id, &options).await
        }));
    }

    let (mut latencies, retries) = collect_quic_workers(workers, "external tuic stream").await?;
    let elapsed = started.elapsed();

    connection.close(0u32.into(), b"bench done");
    client_endpoint.wait_idle().await;
    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(echo_addr);
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "tuic-tcp",
        "external-tuic-tcp-stream-per-worker",
        options,
        Some(bench_quic_runtime_workers()),
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

async fn run_external_tuic_udp_bench_async(
    options: &BenchOptions,
    core_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    server_name: &str,
) -> io::Result<BenchReport> {
    validate_udp_bench_payload(options)?;
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo, echo_addr, echo_task) = start_udp_echo_task(echo_stop.clone())?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        let cert_der = cert_der.clone();
        let server_name = server_name.to_string();
        workers.push(tokio::spawn(async move {
            run_tuic_udp_client(
                core_addr,
                cert_der,
                server_name,
                echo_addr,
                stream_id,
                &options,
            )
            .await
        }));
    }

    let (mut latencies, retries) = collect_quic_workers(workers, "external tuic udp").await?;
    let elapsed = started.elapsed();

    echo_stop.store(true, Ordering::SeqCst);
    drop(echo);
    echo_task
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "tuic udp echo task panicked"))??;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "tuic-udp",
        "external-tuic-udp-datagram-connection-per-worker",
        options,
        Some(bench_quic_runtime_workers()),
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

async fn run_hy2_tcp_bench_async(options: &BenchOptions) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;
    let cert = BenchCert::new("hy2-bench")?;
    let server = Hysteria2Server::new(Hysteria2ServerConfig {
        node_tag: "bench|hy2|tcp".to_string(),
        listen: "127.0.0.1:0".parse().expect("valid listen addr"),
        users: vec![hy2_user()],
        routes: Vec::new(),
        cert_file: cert.cert_path.to_string_lossy().to_string(),
        key_file: cert.key_path.to_string_lossy().to_string(),
        server_name: "localhost".to_string(),
        alpn: vec!["h3".to_string()],
        reject_unknown_sni: false,
        connect_timeout: Duration::from_secs(3),
        up_mbps: 0,
        down_mbps: 0,
        ignore_client_bandwidth: false,
        congestion_control: String::new(),
        obfs: None,
    });
    let endpoint = server.bind()?;
    let server_addr = endpoint.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let server_task = tokio::spawn(server.run(endpoint, stop.clone()));
    let client_endpoint = hy2_client_endpoint(cert.cert_der.clone())?;
    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .map_err(io_other)?
        .await
        .map_err(io_other)?;
    authenticate_hy2(&connection).await?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        let connection = connection.clone();
        workers.push(tokio::spawn(async move {
            run_hy2_tcp_client(connection, echo_addr, stream_id, &options).await
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "hy2 bench worker panicked"))??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    connection.close(0u32.into(), b"bench done");
    client_endpoint.wait_idle().await;
    stop.store(true, Ordering::SeqCst);
    server_task
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "hy2 bench server task panicked"))?;
    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(echo_addr);
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "hy2-tcp",
        "single-quic-connection",
        options,
        Some(bench_quic_runtime_workers()),
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

async fn run_hy2_tcp_stream_bench_async(options: &BenchOptions) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;
    let cert = BenchCert::new("hy2-stream-bench")?;
    let server = Hysteria2Server::new(Hysteria2ServerConfig {
        node_tag: "bench|hy2|tcp-stream".to_string(),
        listen: "127.0.0.1:0".parse().expect("valid listen addr"),
        users: vec![hy2_user()],
        routes: Vec::new(),
        cert_file: cert.cert_path.to_string_lossy().to_string(),
        key_file: cert.key_path.to_string_lossy().to_string(),
        server_name: "localhost".to_string(),
        alpn: vec!["h3".to_string()],
        reject_unknown_sni: false,
        connect_timeout: Duration::from_secs(3),
        up_mbps: 0,
        down_mbps: 0,
        ignore_client_bandwidth: false,
        congestion_control: String::new(),
        obfs: None,
    });
    let endpoint = server.bind()?;
    let server_addr = endpoint.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let server_task = tokio::spawn(server.run(endpoint, stop.clone()));
    let client_endpoint = hy2_client_endpoint(cert.cert_der.clone())?;
    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .map_err(io_other)?
        .await
        .map_err(io_other)?;
    authenticate_hy2(&connection).await?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        let connection = connection.clone();
        workers.push(tokio::spawn(async move {
            run_hy2_tcp_stream_client(connection, echo_addr, stream_id, &options).await
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker.await.map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "hy2 stream bench worker panicked")
        })??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    connection.close(0u32.into(), b"bench done");
    client_endpoint.wait_idle().await;
    stop.store(true, Ordering::SeqCst);
    server_task
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "hy2 bench server task panicked"))?;
    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(echo_addr);
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "hy2-tcp",
        "hy2-tcp-stream-per-worker",
        options,
        Some(bench_quic_runtime_workers()),
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

async fn run_hy2_udp_bench_async(options: &BenchOptions) -> io::Result<BenchReport> {
    validate_udp_bench_payload(options)?;
    let echo_stop = Arc::new(AtomicBool::new(false));
    let echo = Arc::new(bind_bench_udp_echo_socket()?);
    let echo_addr = echo.local_addr()?;
    let echo_task = {
        let echo = echo.clone();
        let echo_stop = echo_stop.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 65_535];
            while !echo_stop.load(Ordering::SeqCst) {
                match tokio::time::timeout(Duration::from_millis(20), echo.recv_from(&mut buffer))
                    .await
                {
                    Ok(Ok((read, peer))) => {
                        echo.send_to(&buffer[..read], peer).await?;
                    }
                    Ok(Err(error)) => return Err(error),
                    Err(_) => {}
                }
            }
            Ok::<(), io::Error>(())
        })
    };

    let cert = BenchCert::new("hy2-udp-bench")?;
    let server = Hysteria2Server::new(Hysteria2ServerConfig {
        node_tag: "bench|hy2|udp".to_string(),
        listen: "127.0.0.1:0".parse().expect("valid listen addr"),
        users: vec![hy2_user()],
        routes: Vec::new(),
        cert_file: cert.cert_path.to_string_lossy().to_string(),
        key_file: cert.key_path.to_string_lossy().to_string(),
        server_name: "localhost".to_string(),
        alpn: vec!["h3".to_string()],
        reject_unknown_sni: false,
        connect_timeout: Duration::from_secs(3),
        up_mbps: 0,
        down_mbps: 0,
        ignore_client_bandwidth: false,
        congestion_control: String::new(),
        obfs: None,
    });
    let endpoint = server.bind()?;
    let server_addr = endpoint.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let server_task = tokio::spawn(server.run(endpoint, stop.clone()));

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        let cert_der = cert.cert_der.clone();
        let server_name = "localhost".to_string();
        workers.push(tokio::spawn(async move {
            run_hy2_udp_client(
                server_addr,
                cert_der,
                server_name,
                echo_addr,
                stream_id,
                &options,
            )
            .await
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "hy2 udp worker panicked"))??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    stop.store(true, Ordering::SeqCst);
    server_task
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "hy2 udp server task panicked"))?;
    echo_stop.store(true, Ordering::SeqCst);
    echo_task
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "hy2 udp echo task panicked"))??;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "hy2-udp",
        "hy2-udp-datagram-connection-per-worker",
        options,
        Some(bench_quic_runtime_workers()),
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

async fn run_tuic_tcp_bench_async(options: &BenchOptions) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;
    let cert = BenchCert::new("tuic-tcp-bench")?;
    let server = TuicServer::new(TuicServerConfig {
        node_tag: "bench|tuic|tcp".to_string(),
        listen: "127.0.0.1:0".parse().expect("valid listen addr"),
        users: vec![tuic_user()],
        routes: Vec::new(),
        cert_file: cert.cert_path.to_string_lossy().to_string(),
        key_file: cert.key_path.to_string_lossy().to_string(),
        server_name: "localhost".to_string(),
        alpn: vec!["h3".to_string()],
        reject_unknown_sni: false,
        congestion_control: String::new(),
        connect_timeout: Duration::from_secs(3),
    });
    let endpoint = server.bind()?;
    let server_addr = endpoint.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let server_task = tokio::spawn(server.run(endpoint, stop.clone()));
    let client_endpoint = hy2_client_endpoint(cert.cert_der.clone())?;
    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .map_err(io_other)?
        .await
        .map_err(io_other)?;
    authenticate_tuic(&connection).await?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        let connection = connection.clone();
        workers.push(tokio::spawn(async move {
            run_tuic_tcp_client(connection, echo_addr, stream_id, &options).await
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "tuic tcp worker panicked"))??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    connection.close(0u32.into(), b"bench done");
    client_endpoint.wait_idle().await;
    stop.store(true, Ordering::SeqCst);
    server_task
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "tuic tcp server task panicked"))?;
    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(echo_addr);
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "tuic-tcp",
        "single-quic-connection",
        options,
        Some(bench_quic_runtime_workers()),
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

async fn run_tuic_tcp_stream_bench_async(options: &BenchOptions) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;
    let cert = BenchCert::new("tuic-tcp-stream-bench")?;
    let server = TuicServer::new(TuicServerConfig {
        node_tag: "bench|tuic|tcp-stream".to_string(),
        listen: "127.0.0.1:0".parse().expect("valid listen addr"),
        users: vec![tuic_user()],
        routes: Vec::new(),
        cert_file: cert.cert_path.to_string_lossy().to_string(),
        key_file: cert.key_path.to_string_lossy().to_string(),
        server_name: "localhost".to_string(),
        alpn: vec!["h3".to_string()],
        reject_unknown_sni: false,
        congestion_control: String::new(),
        connect_timeout: Duration::from_secs(3),
    });
    let endpoint = server.bind()?;
    let server_addr = endpoint.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let server_task = tokio::spawn(server.run(endpoint, stop.clone()));
    let client_endpoint = hy2_client_endpoint(cert.cert_der.clone())?;
    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .map_err(io_other)?
        .await
        .map_err(io_other)?;
    authenticate_tuic(&connection).await?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        let connection = connection.clone();
        workers.push(tokio::spawn(async move {
            run_tuic_tcp_stream_client(connection, echo_addr, stream_id, &options).await
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker.await.map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "tuic stream bench worker panicked")
        })??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    connection.close(0u32.into(), b"bench done");
    client_endpoint.wait_idle().await;
    stop.store(true, Ordering::SeqCst);
    server_task
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "tuic bench server task panicked"))?;
    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(echo_addr);
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "tuic-tcp",
        "tuic-tcp-stream-per-worker",
        options,
        Some(bench_quic_runtime_workers()),
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

async fn run_tuic_udp_bench_async(options: &BenchOptions) -> io::Result<BenchReport> {
    validate_udp_bench_payload(options)?;
    let echo_stop = Arc::new(AtomicBool::new(false));
    let echo = Arc::new(bind_bench_udp_echo_socket()?);
    let echo_addr = echo.local_addr()?;
    let echo_task = {
        let echo = echo.clone();
        let echo_stop = echo_stop.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 65_535];
            while !echo_stop.load(Ordering::SeqCst) {
                match tokio::time::timeout(Duration::from_millis(20), echo.recv_from(&mut buffer))
                    .await
                {
                    Ok(Ok((read, peer))) => {
                        echo.send_to(&buffer[..read], peer).await?;
                    }
                    Ok(Err(error)) => return Err(error),
                    Err(_) => {}
                }
            }
            Ok::<(), io::Error>(())
        })
    };

    let cert = BenchCert::new("tuic-udp-bench")?;
    let server = TuicServer::new(TuicServerConfig {
        node_tag: "bench|tuic|udp".to_string(),
        listen: "127.0.0.1:0".parse().expect("valid listen addr"),
        users: vec![tuic_user()],
        routes: Vec::new(),
        cert_file: cert.cert_path.to_string_lossy().to_string(),
        key_file: cert.key_path.to_string_lossy().to_string(),
        server_name: "localhost".to_string(),
        alpn: vec!["h3".to_string()],
        reject_unknown_sni: false,
        congestion_control: String::new(),
        connect_timeout: Duration::from_secs(3),
    });
    let endpoint = server.bind()?;
    let server_addr = endpoint.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let server_task = tokio::spawn(server.run(endpoint, stop.clone()));

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        let cert_der = cert.cert_der.clone();
        let server_name = "localhost".to_string();
        workers.push(tokio::spawn(async move {
            run_tuic_udp_client(
                server_addr,
                cert_der,
                server_name,
                echo_addr,
                stream_id,
                &options,
            )
            .await
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "tuic udp worker panicked"))??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    stop.store(true, Ordering::SeqCst);
    server_task
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "tuic udp server task panicked"))?;
    echo_stop.store(true, Ordering::SeqCst);
    echo_task
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "tuic udp echo task panicked"))??;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "tuic-udp",
        "tuic-udp-datagram-connection-per-worker",
        options,
        Some(bench_quic_runtime_workers()),
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

fn run_vless_tcp_stream_bench(options: &BenchOptions) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;
    let core_stop = Arc::new(AtomicBool::new(false));
    let (core_addr, core_thread) = start_vless_server(echo_addr, core_stop.clone())?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        workers.push(thread::spawn(move || {
            run_vless_tcp_stream_client(core_addr, echo_addr, stream_id, &options)
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "bench worker panicked"))??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    core_stop.store(true, Ordering::SeqCst);
    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(core_addr);
    let _ = TcpStream::connect(echo_addr);
    join_server(core_thread)?;
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "vless-tcp",
        "connection-per-stream",
        options,
        None,
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

fn run_external_vless_tcp_stream_bench(
    options: &BenchOptions,
    core_addr: SocketAddr,
) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let (echo_addr, echo_thread) = start_echo_server(echo_stop.clone())?;

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.streams);
    for stream_id in 0..options.streams {
        let options = options.clone();
        workers.push(thread::spawn(move || {
            run_vless_tcp_stream_client(core_addr, echo_addr, stream_id, &options)
        }));
    }

    let mut latencies = Vec::with_capacity(options.streams.saturating_mul(options.requests));
    let mut retries = 0usize;
    for worker in workers {
        let mut stats = worker
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "bench worker panicked"))??;
        retries = retries.saturating_add(stats.retries);
        latencies.append(&mut stats.latencies);
    }
    let elapsed = started.elapsed();

    echo_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(echo_addr);
    join_server(echo_thread)?;

    latencies.sort_unstable();
    let total_requests = options.streams.saturating_mul(options.requests);
    let upload_bytes = (total_requests as u64).saturating_mul(options.payload_size as u64);
    let download_bytes = upload_bytes;
    Ok(BenchReport::completed(
        "vless-tcp",
        "connection-per-stream",
        options,
        None,
        upload_bytes,
        download_bytes,
        retries,
        elapsed,
        &latencies,
    ))
}

fn start_echo_server(
    stop: Arc<AtomicBool>,
) -> io::Result<(SocketAddr, thread::JoinHandle<io::Result<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let handle = thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_nodelay(true);
                    thread::spawn(move || {
                        let mut buffer = vec![0u8; 64 * 1024];
                        loop {
                            match stream.read(&mut buffer) {
                                Ok(0) => break,
                                Ok(read) => {
                                    if stream.write_all(&buffer[..read]).is_err() {
                                        break;
                                    }
                                }
                                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                                Err(_) => break,
                            }
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    });
    Ok((addr, handle))
}

fn start_direct_tcp_proxy(
    target: SocketAddr,
    stop: Arc<AtomicBool>,
) -> io::Result<(SocketAddr, thread::JoinHandle<io::Result<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let handle = thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((client, _)) => {
                    let _ = client.set_nonblocking(false);
                    let _ = client.set_nodelay(true);
                    thread::spawn(move || {
                        let remote = match TcpStream::connect(target) {
                            Ok(remote) => remote,
                            Err(error) => {
                                eprintln!("bench direct proxy connect error: {error}");
                                return;
                            }
                        };
                        let _ = remote.set_nonblocking(false);
                        let _ = remote.set_nodelay(true);
                        if let Err(error) = relay_tcp_fast_unlimited(client, remote) {
                            if !is_expected_bench_disconnect(&error) {
                                eprintln!("bench direct proxy relay error: {error}");
                            }
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    });
    Ok((addr, handle))
}

fn start_http_proxy_server(
    stop: Arc<AtomicBool>,
) -> io::Result<(SocketAddr, thread::JoinHandle<io::Result<()>>)> {
    let server = HttpProxyServer::new(HttpProxyServerConfig {
        node_tag: "bench|http|connect".to_string(),
        listen: "127.0.0.1:0".parse().expect("valid listen addr"),
        users: vec![bench_user()],
        routes: Vec::new(),
        connect_timeout: Duration::from_secs(3),
    });
    let listener = server.bind()?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let handle = thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_nodelay(true);
                    let server = server.clone();
                    thread::spawn(move || {
                        if let Err(error) = server.handle_tcp_client(stream) {
                            if !is_expected_bench_disconnect(&error) {
                                eprintln!("bench http server connection error: {error}");
                            }
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    });
    Ok((addr, handle))
}

fn start_shadowsocks_server(
    stop: Arc<AtomicBool>,
) -> io::Result<(SocketAddr, thread::JoinHandle<io::Result<()>>)> {
    let server = ShadowsocksServer::new(ShadowsocksServerConfig {
        node_tag: "bench|shadowsocks|tcp".to_string(),
        listen: "127.0.0.1:0".parse().expect("valid listen addr"),
        method: "aes-128-gcm".to_string(),
        users: vec![bench_user()],
        routes: Vec::new(),
        connect_timeout: Duration::from_secs(3),
    });
    let listener = server.bind()?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let handle = thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_nodelay(true);
                    let server = server.clone();
                    thread::spawn(move || {
                        if let Err(error) = server.handle_tcp_client(stream) {
                            if !is_expected_bench_disconnect(&error) {
                                eprintln!("bench shadowsocks server connection error: {error}");
                            }
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    });
    Ok((addr, handle))
}

fn start_socks_server(
    stop: Arc<AtomicBool>,
) -> io::Result<(SocketAddr, thread::JoinHandle<io::Result<()>>)> {
    let server = Socks5Server::new(Socks5ServerConfig {
        node_tag: "bench|socks|tcp".to_string(),
        listen: "127.0.0.1:0".parse().expect("valid listen addr"),
        users: vec![bench_user()],
        routes: Vec::new(),
        connect_timeout: Duration::from_secs(3),
    });
    let listener = server.bind()?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let handle = thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_nodelay(true);
                    let server = server.clone();
                    thread::spawn(move || {
                        if let Err(error) = server.handle_tcp_client(stream) {
                            if !is_expected_bench_disconnect(&error) {
                                eprintln!("bench socks server connection error: {error}");
                            }
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    });
    Ok((addr, handle))
}

fn start_trojan_server(
    stop: Arc<AtomicBool>,
) -> io::Result<(SocketAddr, thread::JoinHandle<io::Result<()>>)> {
    let server = TrojanServer::new(TrojanServerConfig {
        node_tag: "bench|trojan|tcp".to_string(),
        listen: "127.0.0.1:0".parse().expect("valid listen addr"),
        users: vec![bench_user()],
        routes: Vec::new(),
        connect_timeout: Duration::from_secs(3),
    });
    let listener = server.bind()?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let handle = thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_nodelay(true);
                    let server = server.clone();
                    thread::spawn(move || {
                        if let Err(error) = server.handle_tcp_client(stream) {
                            if !is_expected_bench_disconnect(&error) {
                                eprintln!("bench trojan server connection error: {error}");
                            }
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    });
    Ok((addr, handle))
}

fn start_vmess_server(
    stop: Arc<AtomicBool>,
) -> io::Result<(SocketAddr, thread::JoinHandle<io::Result<()>>)> {
    let server = VmessServer::new(VmessServerConfig {
        node_tag: "bench|vmess|tcp".to_string(),
        listen: "127.0.0.1:0".parse().expect("valid listen addr"),
        users: vec![bench_user()],
        routes: Vec::new(),
        connect_timeout: Duration::from_secs(3),
    });
    let listener = server.bind()?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let handle = thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_nodelay(true);
                    let server = server.clone();
                    thread::spawn(move || {
                        if let Err(error) = server.handle_tcp_client(stream) {
                            if !is_expected_bench_disconnect(&error) {
                                eprintln!("bench vmess server connection error: {error}");
                            }
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    });
    Ok((addr, handle))
}

fn start_vless_server(
    echo_addr: SocketAddr,
    stop: Arc<AtomicBool>,
) -> io::Result<(SocketAddr, thread::JoinHandle<io::Result<()>>)> {
    let server = VlessServer::new(VlessServerConfig {
        node_tag: "bench|vless|tcp".to_string(),
        listen: "127.0.0.1:0".parse().expect("valid listen addr"),
        users: vec![bench_user()],
        routes: Vec::new(),
        flow: String::new(),
        connect_timeout: Duration::from_secs(3),
    });
    let listener = server.bind()?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let handle = thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener)?;
                while !stop.load(Ordering::SeqCst) {
                    match tokio::time::timeout(Duration::from_millis(20), listener.accept()).await {
                        Ok(Ok((stream, _))) => {
                            let _ = stream.set_nodelay(true);
                            let server = server.clone();
                            tokio::spawn(async move {
                                if let Err(error) = server.handle_tcp_client_async(stream).await {
                                    if !is_expected_bench_disconnect(&error) {
                                        eprintln!("bench vless server connection error: {error}");
                                    }
                                }
                            });
                        }
                        Ok(Err(error)) => return Err(error),
                        Err(_) => {}
                    }
                }
                let _ = echo_addr;
                Ok(())
            })
    });
    Ok((addr, handle))
}

fn is_expected_bench_disconnect(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
    )
}

fn run_http_connect_stream_client(
    core_addr: SocketAddr,
    echo_addr: SocketAddr,
    stream_id: usize,
    options: &BenchOptions,
) -> io::Result<ClientStats> {
    let payload = bench_payload(stream_id, options.payload_size);
    let mut response = vec![0u8; payload.len()];
    let mut latencies = Vec::with_capacity(options.requests);
    let mut stream = TcpStream::connect(core_addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    write_http_connect(&mut stream, echo_addr)?;

    for request_index in 0..options.requests {
        let started = Instant::now();
        stream.write_all(&payload).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "http stream {stream_id} request {} write failed: {error}",
                    request_index + 1
                ),
            )
        })?;
        stream.read_exact(&mut response).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "http stream {stream_id} request {} read failed: {error}",
                    request_index + 1
                ),
            )
        })?;
        if response != payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http connect bench echo payload mismatch",
            ));
        }
        latencies.push(started.elapsed().as_micros());
    }

    Ok(ClientStats {
        latencies,
        retries: 0,
    })
}

fn run_shadowsocks_tcp_stream_client(
    core_addr: SocketAddr,
    echo_addr: SocketAddr,
    stream_id: usize,
    options: &BenchOptions,
) -> io::Result<ClientStats> {
    let target = socket_addr_target(echo_addr);
    let mut stream = connect_shadowsocks_tcp_outbound(
        &shadowsocks_outbound(core_addr),
        &target,
        Duration::from_secs(10),
    )?;
    run_plain_stream_echo_client(&mut stream, "shadowsocks", stream_id, options)
}

fn run_socks_tcp_stream_client(
    core_addr: SocketAddr,
    echo_addr: SocketAddr,
    stream_id: usize,
    options: &BenchOptions,
) -> io::Result<ClientStats> {
    let payload = bench_payload(stream_id, options.payload_size);
    let mut response = vec![0u8; payload.len()];
    let mut latencies = Vec::with_capacity(options.requests);
    let mut stream = TcpStream::connect(core_addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    write_socks5_connect(&mut stream, echo_addr)?;

    for request_index in 0..options.requests {
        let started = Instant::now();
        stream.write_all(&payload).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "socks stream {stream_id} request {} write failed: {error}",
                    request_index + 1
                ),
            )
        })?;
        stream.read_exact(&mut response).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "socks stream {stream_id} request {} read failed: {error}",
                    request_index + 1
                ),
            )
        })?;
        if response != payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "socks bench echo payload mismatch",
            ));
        }
        latencies.push(started.elapsed().as_micros());
    }

    Ok(ClientStats {
        latencies,
        retries: 0,
    })
}

fn run_vmess_tcp_stream_client(
    core_addr: SocketAddr,
    echo_addr: SocketAddr,
    stream_id: usize,
    options: &BenchOptions,
) -> io::Result<ClientStats> {
    let target = socket_addr_target(echo_addr);
    let mut stream =
        connect_vmess_tcp_outbound(&vmess_outbound(core_addr), &target, Duration::from_secs(10))?;
    run_plain_stream_echo_client(&mut stream, "vmess", stream_id, options)
}

fn run_trojan_tcp_stream_client(
    core_addr: SocketAddr,
    echo_addr: SocketAddr,
    stream_id: usize,
    options: &BenchOptions,
) -> io::Result<ClientStats> {
    let payload = bench_payload(stream_id, options.payload_size);
    let mut response = vec![0u8; payload.len()];
    let mut latencies = Vec::with_capacity(options.requests);
    let mut stream = TcpStream::connect(core_addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(&trojan_tcp_request(echo_addr))?;

    for request_index in 0..options.requests {
        let started = Instant::now();
        stream.write_all(&payload).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "trojan stream {stream_id} request {} write failed: {error}",
                    request_index + 1
                ),
            )
        })?;
        stream.read_exact(&mut response).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "trojan stream {stream_id} request {} read failed: {error}",
                    request_index + 1
                ),
            )
        })?;
        if response != payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trojan bench echo payload mismatch",
            ));
        }
        latencies.push(started.elapsed().as_micros());
    }

    Ok(ClientStats {
        latencies,
        retries: 0,
    })
}

fn run_plain_stream_echo_client(
    stream: &mut TcpStream,
    label: &str,
    stream_id: usize,
    options: &BenchOptions,
) -> io::Result<ClientStats> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let payload = bench_payload(stream_id, options.payload_size);
    let mut response = vec![0u8; payload.len()];
    let mut latencies = Vec::with_capacity(options.requests);

    for request_index in 0..options.requests {
        let started = Instant::now();
        stream.write_all(&payload).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "{label} stream {stream_id} request {} write failed: {error}",
                    request_index + 1
                ),
            )
        })?;
        stream.read_exact(&mut response).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "{label} stream {stream_id} request {} read failed: {error}",
                    request_index + 1
                ),
            )
        })?;
        if response != payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{label} bench echo payload mismatch"),
            ));
        }
        latencies.push(started.elapsed().as_micros());
    }

    Ok(ClientStats {
        latencies,
        retries: 0,
    })
}

fn run_vless_tcp_client(
    core_addr: SocketAddr,
    echo_addr: SocketAddr,
    stream_id: usize,
    options: &BenchOptions,
) -> io::Result<ClientStats> {
    let payload = bench_payload(stream_id, options.payload_size);
    let mut latencies = Vec::with_capacity(options.requests);
    let mut retries = 0usize;
    for request_index in 0..options.requests {
        let mut attempts = 0usize;
        loop {
            match run_one_vless_tcp_request(core_addr, echo_addr, &payload) {
                Ok(latency) => {
                    latencies.push(latency);
                    break;
                }
                Err(error)
                    if attempts < MAX_REQUEST_RETRIES && is_retryable_bench_error(&error) =>
                {
                    attempts = attempts.saturating_add(1);
                    retries = retries.saturating_add(1);
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => {
                    return Err(io::Error::new(
                        error.kind(),
                        format!(
                            "stream {stream_id} request {} failed: {error}",
                            request_index + 1
                        ),
                    ));
                }
            }
        }
    }
    Ok(ClientStats { latencies, retries })
}

fn run_one_vless_tcp_request(
    core_addr: SocketAddr,
    echo_addr: SocketAddr,
    payload: &[u8],
) -> io::Result<u128> {
    let started = Instant::now();
    let mut stream = TcpStream::connect(core_addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(&vless_tcp_request(echo_addr))?;
    stream.write_all(payload)?;
    read_vless_response_header(&mut stream)?;
    let mut response = vec![0u8; payload.len()];
    stream.read_exact(&mut response)?;
    if response != payload {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bench echo payload mismatch",
        ));
    }
    Ok(started.elapsed().as_micros())
}

fn run_vless_tcp_stream_client(
    core_addr: SocketAddr,
    echo_addr: SocketAddr,
    stream_id: usize,
    options: &BenchOptions,
) -> io::Result<ClientStats> {
    let payload = bench_payload(stream_id, options.payload_size);
    let mut response = vec![0u8; payload.len()];
    let mut latencies = Vec::with_capacity(options.requests);
    let mut stream = TcpStream::connect(core_addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(&vless_tcp_request(echo_addr))?;
    let mut response_header_read = false;

    for request_index in 0..options.requests {
        let started = Instant::now();
        stream.write_all(&payload).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "stream {stream_id} request {} write failed: {error}",
                    request_index + 1
                ),
            )
        })?;
        if !response_header_read {
            read_vless_response_header(&mut stream)?;
            response_header_read = true;
        }
        stream.read_exact(&mut response).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "stream {stream_id} request {} read failed: {error}",
                    request_index + 1
                ),
            )
        })?;
        if response != payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bench echo payload mismatch",
            ));
        }
        latencies.push(started.elapsed().as_micros());
    }

    Ok(ClientStats {
        latencies,
        retries: 0,
    })
}

fn is_retryable_bench_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

fn read_vless_response_header(stream: &mut TcpStream) -> io::Result<()> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header)?;
    if header[0] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid vless bench response version",
        ));
    }
    if header[1] > 0 {
        let mut addon = vec![0u8; usize::from(header[1])];
        stream.read_exact(&mut addon)?;
    }
    Ok(())
}

fn write_http_connect(stream: &mut TcpStream, target: SocketAddr) -> io::Result<()> {
    let auth = BASE64_STANDARD.encode(format!("{BENCH_USER_UUID}:{BENCH_USER_UUID}"));
    let authority = format_socket_addr(&target);
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;
    let mut response = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte)?;
        response.push(byte[0]);
        if response.len() > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http connect bench response headers are too large",
            ));
        }
    }
    let response = String::from_utf8_lossy(&response);
    if !response.starts_with("HTTP/1.1 200 ") && !response.starts_with("HTTP/1.0 200 ") {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "http connect bench failed: {}",
                response.lines().next().unwrap_or("")
            ),
        ));
    }
    Ok(())
}

fn write_socks5_connect(stream: &mut TcpStream, target: SocketAddr) -> io::Result<()> {
    stream.write_all(&[0x05, 0x01, 0x02])?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method)?;
    if method != [0x05, 0x02] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks bench auth method rejected",
        ));
    }

    let username = BENCH_USER_UUID.as_bytes();
    let password = BENCH_USER_UUID.as_bytes();
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socks bench credential is too long",
        ));
    }
    let mut auth = Vec::with_capacity(3 + username.len() + password.len());
    auth.push(0x01);
    auth.push(username.len() as u8);
    auth.extend_from_slice(username);
    auth.push(password.len() as u8);
    auth.extend_from_slice(password);
    stream.write_all(&auth)?;
    let mut auth_status = [0u8; 2];
    stream.read_exact(&mut auth_status)?;
    if auth_status != [0x01, 0x00] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks bench password auth rejected",
        ));
    }

    let mut request = Vec::with_capacity(32);
    request.extend_from_slice(&[0x05, 0x01, 0x00]);
    request.extend_from_slice(&socks_target_bytes(target));
    stream.write_all(&request)?;
    read_socks5_response(stream)
}

fn read_socks5_response(stream: &mut TcpStream) -> io::Result<()> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != 0x05 || header[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("socks bench connect failed with status {}", header[1]),
        ));
    }
    match header[3] {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr)?;
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr)?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            let mut addr = vec![0u8; usize::from(len[0])];
            stream.read_exact(&mut addr)?;
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "socks bench response has unsupported address type",
            ));
        }
    }
    let mut port = [0u8; 2];
    stream.read_exact(&mut port)?;
    Ok(())
}

fn trojan_tcp_request(target: SocketAddr) -> Vec<u8> {
    let mut request = Vec::with_capacity(64);
    request.extend_from_slice(trojan_password_hash(BENCH_USER_UUID).as_bytes());
    request.extend_from_slice(b"\r\n");
    request.push(0x01);
    request.extend_from_slice(&socks_target_bytes(target));
    request.extend_from_slice(b"\r\n");
    request
}

fn socks_target_bytes(target: SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    match target {
        SocketAddr::V4(addr) => {
            bytes.push(0x01);
            bytes.extend_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            bytes.push(0x04);
            bytes.extend_from_slice(&addr.ip().octets());
        }
    }
    bytes.extend_from_slice(&target.port().to_be_bytes());
    bytes
}

fn socket_addr_target(addr: SocketAddr) -> SocksTarget {
    SocksTarget {
        host: addr.ip().to_string(),
        port: addr.port(),
    }
}

fn shadowsocks_outbound(server: SocketAddr) -> OutboundConfig {
    OutboundConfig {
        tag: "bench-ss-out".to_string(),
        protocol: "shadowsocks".to_string(),
        method: Some("aes-128-gcm".to_string()),
        alter_id: None,
        address: Some(server.ip().to_string()),
        port: Some(server.port()),
        username: None,
        password: Some(BENCH_USER_UUID.to_string()),
        tls: None,
        transport: None,
    }
}

fn vmess_outbound(server: SocketAddr) -> OutboundConfig {
    OutboundConfig {
        tag: "bench-vmess-out".to_string(),
        protocol: "vmess".to_string(),
        method: Some("aes-128-gcm".to_string()),
        alter_id: None,
        address: Some(server.ip().to_string()),
        port: Some(server.port()),
        username: Some(BENCH_USER_UUID.to_string()),
        password: None,
        tls: None,
        transport: None,
    }
}

fn vless_tcp_request(target: SocketAddr) -> Vec<u8> {
    let mut request = Vec::with_capacity(24);
    request.push(0x00);
    request.extend_from_slice(&BENCH_USER_BYTES);
    request.push(0x00);
    request.push(0x01);
    request.extend_from_slice(&target.port().to_be_bytes());
    match target {
        SocketAddr::V4(addr) => {
            request.push(0x01);
            request.extend_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            request.push(0x03);
            request.extend_from_slice(&addr.ip().octets());
        }
    }
    request
}

fn bench_payload(stream_id: usize, size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| ((index.wrapping_add(stream_id)) % 251) as u8)
        .collect()
}

fn bench_user() -> CoreUser {
    CoreUser {
        id: 1,
        uuid: BENCH_USER_UUID.to_string(),
        password: None,
        email: None,
        speed_limit: 0,
        device_limit: 0,
    }
}

fn hy2_user() -> CoreUser {
    CoreUser {
        id: 1,
        uuid: HY2_PASSWORD.to_string(),
        password: None,
        email: None,
        speed_limit: 0,
        device_limit: 0,
    }
}

fn tuic_user() -> CoreUser {
    CoreUser {
        id: 1,
        uuid: BENCH_USER_UUID.to_string(),
        password: Some(TUIC_PASSWORD.to_string()),
        email: None,
        speed_limit: 0,
        device_limit: 0,
    }
}

async fn run_hy2_tcp_client(
    connection: quinn::Connection,
    echo_addr: SocketAddr,
    stream_id: usize,
    options: &BenchOptions,
) -> io::Result<ClientStats> {
    let payload = bench_payload(stream_id, options.payload_size);
    let mut latencies = Vec::with_capacity(options.requests);
    let mut retries = 0usize;
    for request_index in 0..options.requests {
        let mut attempts = 0usize;
        loop {
            match run_one_hy2_tcp_request(&connection, echo_addr, &payload).await {
                Ok(latency) => {
                    latencies.push(latency);
                    break;
                }
                Err(error)
                    if attempts < MAX_REQUEST_RETRIES && is_retryable_bench_error(&error) =>
                {
                    attempts = attempts.saturating_add(1);
                    retries = retries.saturating_add(1);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(error) => {
                    return Err(io::Error::new(
                        error.kind(),
                        format!(
                            "hy2 stream {stream_id} request {} failed: {error}",
                            request_index + 1
                        ),
                    ));
                }
            }
        }
    }

    Ok(ClientStats { latencies, retries })
}

async fn run_one_hy2_tcp_request(
    connection: &quinn::Connection,
    echo_addr: SocketAddr,
    payload: &[u8],
) -> io::Result<u128> {
    let started = Instant::now();
    let mut response = vec![0u8; payload.len()];
    let (mut send, mut recv) = connection.open_bi().await.map_err(io_other)?;
    send.write_all(&hy2_tcp_request(echo_addr))
        .await
        .map_err(io_other)?;
    read_hy2_tcp_response_header(&mut recv).await?;
    send.write_all(payload).await.map_err(io_other)?;
    send.finish().map_err(io_other)?;
    recv.read_exact(&mut response).await.map_err(|error| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("stream finished before echo response: {error}"),
        )
    })?;
    if response != payload {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hy2 bench echo payload mismatch",
        ));
    }
    Ok(started.elapsed().as_micros())
}

async fn run_hy2_tcp_stream_client(
    connection: quinn::Connection,
    echo_addr: SocketAddr,
    stream_id: usize,
    options: &BenchOptions,
) -> io::Result<ClientStats> {
    let payload = bench_payload(stream_id, options.payload_size);
    let mut response = vec![0u8; payload.len()];
    let mut latencies = Vec::with_capacity(options.requests);
    let (mut send, mut recv) = connection.open_bi().await.map_err(io_other)?;
    send.write_all(&hy2_tcp_request(echo_addr))
        .await
        .map_err(io_other)?;
    read_hy2_tcp_response_header(&mut recv).await?;

    for request_index in 0..options.requests {
        let started = Instant::now();
        send.write_all(&payload).await.map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "hy2 stream {stream_id} request {} write failed: {error}",
                    request_index + 1
                ),
            )
        })?;
        recv.read_exact(&mut response).await.map_err(|error| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "hy2 stream {stream_id} request {} read failed: {error}",
                    request_index + 1
                ),
            )
        })?;
        if response != payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "hy2 stream bench echo payload mismatch",
            ));
        }
        latencies.push(started.elapsed().as_micros());
    }

    send.finish().map_err(io_other)?;
    Ok(ClientStats {
        latencies,
        retries: 0,
    })
}

async fn run_hy2_udp_client(
    server_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    server_name: String,
    echo_addr: SocketAddr,
    stream_id: usize,
    options: &BenchOptions,
) -> io::Result<ClientStats> {
    let client_endpoint = hy2_client_endpoint(cert_der)?;
    let connection = client_endpoint
        .connect(server_addr, &server_name)
        .map_err(io_other)?
        .await
        .map_err(io_other)?;
    authenticate_hy2(&connection).await?;
    let payload = bench_payload(stream_id, options.payload_size);
    let session_id = stream_id.saturating_add(1) as u32;
    let mut latencies = Vec::with_capacity(options.requests);
    let mut retries = 0usize;

    for request_index in 0..options.requests {
        let mut attempts = 0usize;
        loop {
            let packet_id = (((request_index + attempts) % usize::from(u16::MAX)) + 1) as u16;
            let started = Instant::now();
            send_hy2_udp_datagrams(&connection, session_id, packet_id, echo_addr, &payload).await?;
            let response = tokio::time::timeout(
                UDP_RESPONSE_TIMEOUT,
                read_hy2_udp_response_payload(&connection, session_id),
            )
            .await;
            let response = match response {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => return Err(io_other(error)),
                Err(_) if attempts < MAX_REQUEST_RETRIES => {
                    attempts = attempts.saturating_add(1);
                    retries = retries.saturating_add(1);
                    continue;
                }
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "hy2 udp stream {stream_id} request {} response timeout after {} retries",
                            request_index + 1,
                            attempts
                        ),
                    ));
                }
            };
            if response != payload {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "hy2 udp bench echo payload mismatch",
                ));
            }
            latencies.push(started.elapsed().as_micros());
            break;
        }
    }

    connection.close(0u32.into(), b"bench done");
    client_endpoint.wait_idle().await;
    Ok(ClientStats { latencies, retries })
}

async fn run_tuic_tcp_client(
    connection: quinn::Connection,
    echo_addr: SocketAddr,
    stream_id: usize,
    options: &BenchOptions,
) -> io::Result<ClientStats> {
    let payload = bench_payload(stream_id, options.payload_size);
    let mut latencies = Vec::with_capacity(options.requests);
    let mut retries = 0usize;
    for request_index in 0..options.requests {
        let mut attempts = 0usize;
        loop {
            match run_one_tuic_tcp_request(&connection, echo_addr, &payload).await {
                Ok(latency) => {
                    latencies.push(latency);
                    break;
                }
                Err(error)
                    if attempts < MAX_REQUEST_RETRIES && is_retryable_bench_error(&error) =>
                {
                    attempts = attempts.saturating_add(1);
                    retries = retries.saturating_add(1);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(error) => {
                    return Err(io::Error::new(
                        error.kind(),
                        format!(
                            "tuic stream {stream_id} request {} failed: {error}",
                            request_index + 1
                        ),
                    ));
                }
            }
        }
    }

    Ok(ClientStats { latencies, retries })
}

async fn run_one_tuic_tcp_request(
    connection: &quinn::Connection,
    echo_addr: SocketAddr,
    payload: &[u8],
) -> io::Result<u128> {
    let started = Instant::now();
    let mut response = vec![0u8; payload.len()];
    let (mut send, mut recv) = connection.open_bi().await.map_err(io_other)?;
    send.write_all(&tuic_connect_command(echo_addr))
        .await
        .map_err(io_other)?;
    send.write_all(payload).await.map_err(io_other)?;
    send.finish().map_err(io_other)?;
    recv.read_exact(&mut response).await.map_err(|error| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("tuic stream finished before echo response: {error}"),
        )
    })?;
    if response != payload {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tuic bench echo payload mismatch",
        ));
    }
    Ok(started.elapsed().as_micros())
}

async fn run_tuic_tcp_stream_client(
    connection: quinn::Connection,
    echo_addr: SocketAddr,
    stream_id: usize,
    options: &BenchOptions,
) -> io::Result<ClientStats> {
    let payload = bench_payload(stream_id, options.payload_size);
    let mut response = vec![0u8; payload.len()];
    let mut latencies = Vec::with_capacity(options.requests);
    let (mut send, mut recv) = connection.open_bi().await.map_err(io_other)?;
    send.write_all(&tuic_connect_command(echo_addr))
        .await
        .map_err(io_other)?;

    for request_index in 0..options.requests {
        let started = Instant::now();
        send.write_all(&payload).await.map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "tuic stream {stream_id} request {} write failed: {error}",
                    request_index + 1
                ),
            )
        })?;
        recv.read_exact(&mut response).await.map_err(|error| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "tuic stream {stream_id} request {} read failed: {error}",
                    request_index + 1
                ),
            )
        })?;
        if response != payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tuic stream bench echo payload mismatch",
            ));
        }
        latencies.push(started.elapsed().as_micros());
    }

    send.finish().map_err(io_other)?;
    Ok(ClientStats {
        latencies,
        retries: 0,
    })
}

async fn run_tuic_udp_client(
    server_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    server_name: String,
    echo_addr: SocketAddr,
    stream_id: usize,
    options: &BenchOptions,
) -> io::Result<ClientStats> {
    let client_endpoint = hy2_client_endpoint(cert_der)?;
    let connection = client_endpoint
        .connect(server_addr, &server_name)
        .map_err(io_other)?
        .await
        .map_err(io_other)?;
    authenticate_tuic(&connection).await?;
    let payload = bench_payload(stream_id, options.payload_size);
    let assoc_id = stream_id.saturating_add(1) as u16;
    let mut latencies = Vec::with_capacity(options.requests);
    let mut retries = 0usize;

    for request_index in 0..options.requests {
        let mut attempts = 0usize;
        loop {
            let packet_id = (((request_index + attempts) % usize::from(u16::MAX)) + 1) as u16;
            let started = Instant::now();
            send_tuic_udp_datagrams(&connection, assoc_id, packet_id, Some(echo_addr), &payload)
                .await?;
            let response = tokio::time::timeout(
                UDP_RESPONSE_TIMEOUT,
                read_tuic_udp_response_payload(&connection, assoc_id),
            )
            .await;
            let response = match response {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => return Err(io_other(error)),
                Err(_) if attempts < MAX_REQUEST_RETRIES => {
                    attempts = attempts.saturating_add(1);
                    retries = retries.saturating_add(1);
                    continue;
                }
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "tuic udp stream {stream_id} request {} response timeout after {} retries",
                            request_index + 1,
                            attempts
                        ),
                    ));
                }
            };
            if response != payload {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tuic udp bench echo payload mismatch",
                ));
            }
            latencies.push(started.elapsed().as_micros());
            break;
        }
    }

    connection.close(0u32.into(), b"bench done");
    client_endpoint.wait_idle().await;
    Ok(ClientStats { latencies, retries })
}

async fn authenticate_tuic(connection: &quinn::Connection) -> io::Result<()> {
    let mut auth = connection.open_uni().await.map_err(io_other)?;
    auth.write_all(&tuic_auth_command(connection)?)
        .await
        .map_err(io_other)?;
    auth.finish().map_err(io_other)
}

fn tuic_auth_command(connection: &quinn::Connection) -> io::Result<Vec<u8>> {
    let mut token = [0u8; 32];
    connection
        .export_keying_material(&mut token, &BENCH_USER_BYTES, TUIC_PASSWORD.as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::Other, format!("{error:?}")))?;
    let mut command = vec![TUIC_VERSION, TUIC_COMMAND_AUTHENTICATE];
    command.extend_from_slice(&BENCH_USER_BYTES);
    command.extend_from_slice(&token);
    Ok(command)
}

fn tuic_connect_command(target: SocketAddr) -> Vec<u8> {
    let mut command = vec![TUIC_VERSION, TUIC_COMMAND_CONNECT];
    command.extend_from_slice(&tuic_address(Some(target)));
    command
}

fn tuic_udp_packet_fragment(
    assoc_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    target: Option<SocketAddr>,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tuic udp packet payload is too large",
        ));
    }
    let address = tuic_address(target);
    let mut output = Vec::with_capacity(10 + address.len() + payload.len());
    output.push(TUIC_VERSION);
    output.push(TUIC_COMMAND_PACKET);
    output.extend_from_slice(&assoc_id.to_be_bytes());
    output.extend_from_slice(&packet_id.to_be_bytes());
    output.push(fragment_total);
    output.push(fragment_id);
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(&address);
    output.extend_from_slice(payload);
    Ok(output)
}

async fn send_tuic_udp_datagrams(
    connection: &quinn::Connection,
    assoc_id: u16,
    packet_id: u16,
    target: Option<SocketAddr>,
    payload: &[u8],
) -> io::Result<()> {
    let Some(max_size) = connection.max_datagram_size() else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tuic udp datagram size is unavailable",
        ));
    };
    let header_len = tuic_udp_packet_fragment(assoc_id, packet_id, 1, 0, target, &[])?.len();
    let max_payload = max_size.saturating_sub(header_len);
    if max_payload == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tuic udp datagram overhead exceeds max datagram size",
        ));
    }
    let fragment_count = payload.len().saturating_add(max_payload - 1) / max_payload;
    if fragment_count == 0 || fragment_count > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tuic udp payload requires too many fragments",
        ));
    }
    let fragment_count = fragment_count as u8;
    for (fragment_id, chunk) in payload.chunks(max_payload).enumerate() {
        let datagram = tuic_udp_packet_fragment(
            assoc_id,
            packet_id,
            fragment_count,
            fragment_id as u8,
            target,
            chunk,
        )?;
        connection
            .send_datagram_wait(Bytes::from(datagram))
            .await
            .map_err(io_other)?;
    }
    Ok(())
}

fn tuic_address(target: Option<SocketAddr>) -> Vec<u8> {
    let Some(target) = target else {
        return vec![TUIC_ATYP_NONE];
    };
    let mut output = Vec::new();
    match target {
        SocketAddr::V4(addr) => {
            output.push(TUIC_ATYP_IPV4);
            output.extend_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            output.push(TUIC_ATYP_IPV6);
            output.extend_from_slice(&addr.ip().octets());
        }
    }
    output.extend_from_slice(&target.port().to_be_bytes());
    output
}

#[derive(Debug, PartialEq, Eq)]
struct TuicUdpPacket {
    assoc_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    payload: Vec<u8>,
}

fn parse_tuic_udp_packet(input: &[u8]) -> io::Result<TuicUdpPacket> {
    if input.len() < 10 || input[0] != TUIC_VERSION || input[1] != TUIC_COMMAND_PACKET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tuic udp packet header",
        ));
    }
    let assoc_id = u16::from_be_bytes([input[2], input[3]]);
    let packet_id = u16::from_be_bytes([input[4], input[5]]);
    let fragment_total = input[6];
    let fragment_id = input[7];
    if fragment_total == 0 || fragment_id >= fragment_total {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tuic udp fragment index",
        ));
    }
    let payload_len = u16::from_be_bytes([input[8], input[9]]) as usize;
    let mut offset = 10usize;
    skip_tuic_address(input, &mut offset)?;
    if input.len().saturating_sub(offset) != payload_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tuic udp payload length mismatch",
        ));
    }
    Ok(TuicUdpPacket {
        assoc_id,
        packet_id,
        fragment_total,
        fragment_id,
        payload: input[offset..].to_vec(),
    })
}

async fn read_tuic_udp_response_payload(
    connection: &quinn::Connection,
    assoc_id: u16,
) -> io::Result<Vec<u8>> {
    let mut fragments: HashMap<u16, Vec<Option<Vec<u8>>>> = HashMap::new();
    loop {
        let datagram = connection.read_datagram().await.map_err(io_other)?;
        let packet = parse_tuic_udp_packet(&datagram)?;
        if packet.assoc_id != assoc_id {
            continue;
        }
        if packet.fragment_total == 1 {
            return Ok(packet.payload);
        }
        let parts = fragments
            .entry(packet.packet_id)
            .or_insert_with(|| vec![None; packet.fragment_total as usize]);
        if parts.len() != packet.fragment_total as usize {
            fragments.remove(&packet.packet_id);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mismatched tuic udp response fragment count",
            ));
        }
        parts[packet.fragment_id as usize] = Some(packet.payload);
        if parts.iter().all(Option::is_some) {
            let parts = fragments
                .remove(&packet.packet_id)
                .expect("fragment set exists");
            let mut payload = Vec::new();
            for part in parts {
                payload.extend_from_slice(&part.expect("all fragments present"));
            }
            return Ok(payload);
        }
    }
}

fn skip_tuic_address(input: &[u8], offset: &mut usize) -> io::Result<()> {
    let Some(atyp) = input.get(*offset).copied() else {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "missing tuic address type",
        ));
    };
    *offset += 1;
    match atyp {
        TUIC_ATYP_NONE => Ok(()),
        TUIC_ATYP_IPV4 => {
            *offset = (*offset).saturating_add(4);
            skip_tuic_port(input, offset)
        }
        TUIC_ATYP_IPV6 => {
            *offset = (*offset).saturating_add(16);
            skip_tuic_port(input, offset)
        }
        TUIC_ATYP_DOMAIN => {
            let Some(length) = input.get(*offset).copied() else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing tuic domain length",
                ));
            };
            *offset += 1 + usize::from(length);
            skip_tuic_port(input, offset)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported tuic address type",
        )),
    }
}

fn skip_tuic_port(input: &[u8], offset: &mut usize) -> io::Result<()> {
    if input.len().saturating_sub(*offset) < 2 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated tuic port",
        ));
    }
    *offset += 2;
    if *offset > input.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated tuic address",
        ));
    }
    Ok(())
}

fn bind_bench_udp_echo_socket() -> io::Result<tokio::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_recv_buffer_size(UDP_ECHO_SOCKET_BUFFER_SIZE)?;
    socket.set_send_buffer_size(UDP_ECHO_SOCKET_BUFFER_SIZE)?;
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("valid bench udp addr");
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(socket.into())
}

fn validate_udp_bench_payload(options: &BenchOptions) -> io::Result<()> {
    if options.payload_size <= MAX_UDP_PAYLOAD_SIZE {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "udp bench payload {} exceeds max UDP payload {}; use 65507 or lower",
            options.payload_size, MAX_UDP_PAYLOAD_SIZE
        ),
    ))
}

fn hy2_client_endpoint(cert_der: CertificateDer<'static>) -> io::Result<quinn::Endpoint> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).map_err(io_other)?;
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto).map_err(io_other)?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport
        .datagram_receive_buffer_size(Some(1024 * 1024))
        .datagram_send_buffer_size(1024 * 1024);
    client_config.transport_config(Arc::new(transport));
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("valid client addr"))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

async fn authenticate_hy2(connection: &quinn::Connection) -> io::Result<()> {
    let quic = h3_quinn::Connection::new(connection.clone());
    let (mut h3_connection, mut send_request) = h3::client::new(quic).await.map_err(io_other)?;
    let (authenticated, stop_driver) = tokio::sync::oneshot::channel::<()>();
    let driver = tokio::spawn(async move {
        tokio::select! {
            _ = poll_fn(|cx| h3_connection.poll_close(cx)) => {}
            _ = stop_driver => {
                std::mem::forget(h3_connection);
            }
        }
    });
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://hysteria/auth")
        .header("Hysteria-Auth", HY2_PASSWORD)
        .header("Hysteria-CC-RX", "0")
        .body(())
        .map_err(io_other)?;
    let mut stream = send_request.send_request(request).await.map_err(io_other)?;
    stream.finish().await.map_err(io_other)?;
    let response = stream.recv_response().await.map_err(io_other)?;
    if response.status().as_u16() != 233 {
        driver.abort();
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("hy2 auth failed with status {}", response.status()),
        ));
    }
    std::mem::forget(send_request);
    let _ = authenticated.send(());
    driver
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "hy2 h3 driver panicked"))?;
    Ok(())
}

fn hy2_tcp_request(target: SocketAddr) -> Vec<u8> {
    let address = format_socket_addr(&target);
    let mut request = encode_hy2_varint(HY2_TCP_REQUEST_ID).expect("request id");
    request.extend_from_slice(&encode_hy2_varint(address.len() as u64).expect("address length"));
    request.extend_from_slice(address.as_bytes());
    request.extend_from_slice(&encode_hy2_varint(0).expect("padding length"));
    request
}

struct Hy2UdpBenchDatagram {
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    data: Vec<u8>,
}

fn hy2_udp_datagram_fragment(
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    target: SocketAddr,
    data: &[u8],
) -> io::Result<Vec<u8>> {
    let address = format_socket_addr(&target);
    let mut output = Vec::with_capacity(8 + address.len() + data.len() + 8);
    output.extend_from_slice(&session_id.to_be_bytes());
    output.extend_from_slice(&packet_id.to_be_bytes());
    output.push(fragment_id);
    output.push(fragment_count);
    output.extend_from_slice(&encode_hy2_varint(address.len() as u64)?);
    output.extend_from_slice(address.as_bytes());
    output.extend_from_slice(data);
    Ok(output)
}

async fn send_hy2_udp_datagrams(
    connection: &quinn::Connection,
    session_id: u32,
    packet_id: u16,
    target: SocketAddr,
    payload: &[u8],
) -> io::Result<()> {
    let Some(max_size) = connection.max_datagram_size() else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "hy2 udp datagram size is unavailable",
        ));
    };
    let header_len = hy2_udp_datagram_fragment(session_id, packet_id, 0, 1, target, &[])?.len();
    let max_payload = max_size.saturating_sub(header_len);
    if max_payload == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hy2 udp datagram overhead exceeds max datagram size",
        ));
    }
    let fragment_count = payload.len().saturating_add(max_payload - 1) / max_payload;
    if fragment_count == 0 || fragment_count > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hy2 udp payload requires too many fragments",
        ));
    }
    let fragment_count = fragment_count as u8;
    for (fragment_id, chunk) in payload.chunks(max_payload).enumerate() {
        let datagram = hy2_udp_datagram_fragment(
            session_id,
            packet_id,
            fragment_id as u8,
            fragment_count,
            target,
            chunk,
        )?;
        connection
            .send_datagram_wait(Bytes::from(datagram))
            .await
            .map_err(io_other)?;
    }
    Ok(())
}

fn parse_hy2_udp_datagram(input: &[u8]) -> io::Result<Hy2UdpBenchDatagram> {
    if input.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hy2 udp datagram is too short",
        ));
    }
    let session_id = u32::from_be_bytes(input[0..4].try_into().expect("fixed slice"));
    let packet_id = u16::from_be_bytes(input[4..6].try_into().expect("fixed slice"));
    let fragment_id = input[6];
    let fragment_count = input[7];
    if fragment_count == 0 || fragment_id >= fragment_count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid hy2 udp fragment index",
        ));
    }
    let mut offset = 8usize;
    let address_len = read_hy2_varint_from(input, &mut offset)?;
    let address_len = usize::try_from(address_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "hy2 udp address length overflows usize",
        )
    })?;
    if address_len == 0 || input.len().saturating_sub(offset) < address_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hy2 udp datagram address is invalid",
        ));
    }
    offset += address_len;
    Ok(Hy2UdpBenchDatagram {
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        data: input[offset..].to_vec(),
    })
}

async fn read_hy2_udp_response_payload(
    connection: &quinn::Connection,
    session_id: u32,
) -> io::Result<Vec<u8>> {
    let mut fragments: HashMap<u16, Vec<Option<Vec<u8>>>> = HashMap::new();
    loop {
        let datagram = connection.read_datagram().await.map_err(io_other)?;
        let packet = parse_hy2_udp_datagram(&datagram)?;
        if packet.session_id != session_id {
            continue;
        }
        if packet.fragment_count == 1 {
            return Ok(packet.data);
        }
        let parts = fragments
            .entry(packet.packet_id)
            .or_insert_with(|| vec![None; packet.fragment_count as usize]);
        if parts.len() != packet.fragment_count as usize {
            fragments.remove(&packet.packet_id);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mismatched hy2 udp response fragment count",
            ));
        }
        parts[packet.fragment_id as usize] = Some(packet.data);
        if parts.iter().all(Option::is_some) {
            let parts = fragments
                .remove(&packet.packet_id)
                .expect("fragment set exists");
            let mut payload = Vec::new();
            for part in parts {
                payload.extend_from_slice(&part.expect("all fragments present"));
            }
            return Ok(payload);
        }
    }
}

async fn read_hy2_tcp_response_header(recv: &mut quinn::RecvStream) -> io::Result<()> {
    let mut status = [0u8; 1];
    recv.read_exact(&mut status).await.map_err(io_other)?;
    if status[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "hy2 tcp request failed",
        ));
    }
    let message_len = read_hy2_varint(recv).await?;
    if message_len > 0 {
        let mut message = vec![0u8; message_len as usize];
        recv.read_exact(&mut message).await.map_err(io_other)?;
    }
    let padding_len = read_hy2_varint(recv).await?;
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len as usize];
        recv.read_exact(&mut padding).await.map_err(io_other)?;
    }
    Ok(())
}

fn encode_hy2_varint(value: u64) -> io::Result<Vec<u8>> {
    if value < (1 << 6) {
        return Ok(vec![value as u8]);
    }
    if value < (1 << 14) {
        let encoded = ((value as u16) | 0x4000).to_be_bytes();
        return Ok(encoded.to_vec());
    }
    if value < (1 << 30) {
        let encoded = ((value as u32) | 0x8000_0000).to_be_bytes();
        return Ok(encoded.to_vec());
    }
    if value < (1 << 62) {
        let encoded = (value | 0xc000_0000_0000_0000).to_be_bytes();
        return Ok(encoded.to_vec());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "hy2 varint is too large",
    ))
}

async fn read_hy2_varint(recv: &mut quinn::RecvStream) -> io::Result<u64> {
    let first = recv.read_u8().await.map_err(io_other)?;
    let tag = first >> 6;
    let mut value = u64::from(first & 0x3f);
    let extra = match tag {
        0 => 0,
        1 => 1,
        2 => 3,
        3 => 7,
        _ => unreachable!(),
    };
    for _ in 0..extra {
        value = (value << 8) | u64::from(recv.read_u8().await.map_err(io_other)?);
    }
    Ok(value)
}

fn read_hy2_varint_from(input: &[u8], offset: &mut usize) -> io::Result<u64> {
    let Some(first) = input.get(*offset).copied() else {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated hy2 varint",
        ));
    };
    *offset += 1;
    let tag = first >> 6;
    let mut value = u64::from(first & 0x3f);
    let extra = match tag {
        0 => 0,
        1 => 1,
        2 => 3,
        3 => 7,
        _ => unreachable!(),
    };
    if input.len().saturating_sub(*offset) < extra {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated hy2 varint",
        ));
    }
    for _ in 0..extra {
        value = (value << 8) | u64::from(input[*offset]);
        *offset += 1;
    }
    Ok(value)
}

fn format_socket_addr(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(addr) => addr.to_string(),
        SocketAddr::V6(addr) => format!("[{}]:{}", addr.ip(), addr.port()),
    }
}

struct BenchCert {
    cert_path: PathBuf,
    key_path: PathBuf,
    cert_der: CertificateDer<'static>,
}

impl BenchCert {
    fn new(label: &str) -> io::Result<Self> {
        let cert =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).map_err(io_other)?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io_other)?
            .as_nanos();
        let dir = std::env::temp_dir();
        let cert_path = dir.join(format!("keli-core-rs-bench-{label}-{nanos}.crt"));
        let key_path = dir.join(format!("keli-core-rs-bench-{label}-{nanos}.key"));
        fs::write(&cert_path, cert.cert.pem())?;
        fs::write(&key_path, cert.key_pair.serialize_pem())?;
        Ok(Self {
            cert_path,
            key_path,
            cert_der: cert.cert.der().clone(),
        })
    }
}

impl Drop for BenchCert {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.cert_path);
        let _ = fs::remove_file(&self.key_path);
    }
}

fn io_other(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error.to_string())
}

fn latency_report(values: &[u128]) -> LatencyReport {
    LatencyReport {
        min_us: *values.first().unwrap_or(&0),
        p50_us: percentile(values, 50),
        p95_us: percentile(values, 95),
        p99_us: percentile(values, 99),
        max_us: *values.last().unwrap_or(&0),
    }
}

fn percentile(values: &[u128], percentile: usize) -> u128 {
    if values.is_empty() {
        return 0;
    }
    let rank = values.len().saturating_mul(percentile).saturating_add(99) / 100;
    values[rank.saturating_sub(1).min(values.len() - 1)]
}

fn join_server(handle: thread::JoinHandle<io::Result<()>>) -> io::Result<()> {
    handle
        .join()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "bench server panicked"))?
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_bench_command, parse_bench_options, parse_bench_suite_options,
        parse_external_bench_suite_options, percent_change, run_direct_tcp_proxy_stream_bench,
        run_direct_tcp_stream_bench, run_external_vless_tcp_stream_bench,
        run_http_connect_stream_bench, run_hy2_udp_bench, run_shadowsocks_tcp_stream_bench,
        run_socks_tcp_stream_bench, run_trojan_tcp_stream_bench, run_tuic_tcp_bench,
        run_tuic_tcp_stream_bench, run_tuic_udp_bench, run_vless_tcp_bench,
        run_vless_tcp_stream_bench, run_vmess_tcp_stream_bench, summarize_bench_runs,
        validate_udp_bench_payload, BenchCert, BenchOptions, BenchReport, BenchSuiteRun,
        LatencyReport,
    };
    use std::net::{SocketAddr, TcpStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn parses_bench_options() {
        let options = parse_bench_options(
            ["--streams", "2", "--requests", "3", "--payload", "4"]
                .into_iter()
                .map(str::to_string),
        )
        .expect("options");

        assert_eq!(options.streams, 2);
        assert_eq!(options.requests, 3);
        assert_eq!(options.payload_size, 4);
    }

    #[test]
    fn udp_bench_rejects_payload_above_udp_datagram_limit() {
        let options = BenchOptions {
            streams: 1,
            requests: 1,
            payload_size: 65_508,
        };

        let error = validate_udp_bench_payload(&options).expect_err("payload rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn parses_bench_suite_options() {
        let options = parse_bench_suite_options(
            [
                "--commands",
                "hysteria2-tcp,vless-stream",
                "--streams",
                "2",
                "--requests",
                "3",
                "--payload",
                "4",
                "--repeats",
                "5",
                "--label",
                "rust-candidate",
                "--out",
                "runtime/bench/rust.json",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .expect("suite options");

        assert_eq!(options.commands, vec!["hy2-tcp", "vless-tcp-stream"]);
        assert_eq!(options.bench.streams, 2);
        assert_eq!(options.bench.requests, 3);
        assert_eq!(options.bench.payload_size, 4);
        assert_eq!(options.repeats, 5);
        assert_eq!(options.label, "rust-candidate");
        assert_eq!(options.out, Some(PathBuf::from("runtime/bench/rust.json")));
    }

    #[test]
    fn parses_external_bench_suite_options() {
        let options = parse_external_bench_suite_options(
            [
                "--vless-core",
                "127.0.0.1:12345",
                "--commands",
                "socks-stream,vless-tcp,vless-stream",
                "--core",
                "socks-stream=127.0.0.1:12344",
                "--streams",
                "2",
                "--requests",
                "3",
                "--payload",
                "4",
                "--repeats",
                "2",
                "--label",
                "go-xray",
                "--out",
                "runtime/bench/go-suite.json",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .expect("external suite options");

        assert_eq!(
            options.commands,
            vec!["socks-tcp-stream", "vless-tcp", "vless-tcp-stream"]
        );
        assert_eq!(options.bench.streams, 2);
        assert_eq!(options.bench.requests, 3);
        assert_eq!(options.bench.payload_size, 4);
        assert_eq!(options.repeats, 2);
        assert_eq!(options.label, "go-xray");
        assert_eq!(
            options.cores.get("socks-tcp-stream"),
            Some(&"127.0.0.1:12344".parse().unwrap())
        );
        assert_eq!(
            options.cores.get("vless-tcp"),
            Some(&"127.0.0.1:12345".parse().unwrap())
        );
        assert_eq!(
            options.cores.get("vless-tcp-stream"),
            Some(&"127.0.0.1:12345".parse().unwrap())
        );
        assert_eq!(
            options.out,
            Some(PathBuf::from("runtime/bench/go-suite.json"))
        );
    }

    #[test]
    fn rejects_unsupported_external_bench_command() {
        let error = parse_external_bench_suite_options(
            [
                "--core",
                "direct-stream=127.0.0.1:12345",
                "--commands",
                "direct-stream",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .expect_err("unsupported command");
        assert!(error.contains("external-suite does not support"));
    }

    #[test]
    fn parses_external_quic_bench_suite_options() {
        let cert = BenchCert::new("external-quic-parse").expect("cert");
        let cert_path = cert.cert_path.to_string_lossy().to_string();
        let options = parse_external_bench_suite_options(
            [
                "--commands",
                "hy2-stream,tuic-udp",
                "--core",
                "hy2-stream=127.0.0.1:29200",
                "--core",
                "tuic-udp=127.0.0.1:29201",
                "--cert",
                cert_path.as_str(),
                "--server-name",
                "localhost",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .expect("external quic suite options");

        assert_eq!(options.commands, vec!["hy2-tcp-stream", "tuic-udp"]);
        assert!(options.certs.contains_key("hy2-tcp-stream"));
        assert!(options.certs.contains_key("tuic-udp"));
        assert_eq!(options.server_name, "localhost");
    }

    #[test]
    fn rejects_external_quic_command_without_cert() {
        let error = parse_external_bench_suite_options(
            [
                "--commands",
                "hy2-stream",
                "--core",
                "hy2-stream=127.0.0.1:29200",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .expect_err("missing cert");
        assert!(error.contains("missing --cert for external QUIC command hy2-tcp-stream"));
    }

    #[test]
    fn rejects_external_command_without_core_mapping() {
        let error = parse_external_bench_suite_options(
            ["--commands", "socks-stream"]
                .into_iter()
                .map(str::to_string),
        )
        .expect_err("missing core");
        assert!(error.contains("missing --core socks-tcp-stream"));
    }

    #[test]
    fn canonicalizes_bench_command_aliases() {
        assert_eq!(
            canonical_bench_command("direct-stream"),
            Some("direct-tcp-stream")
        );
        assert_eq!(
            canonical_bench_command("direct-proxy-stream"),
            Some("direct-tcp-proxy-stream")
        );
        assert_eq!(canonical_bench_command("hysteria2-tcp"), Some("hy2-tcp"));
        assert_eq!(
            canonical_bench_command("hysteria2-tcp-stream"),
            Some("hy2-tcp-stream")
        );
        assert_eq!(
            canonical_bench_command("vless-stream"),
            Some("vless-tcp-stream")
        );
        assert_eq!(
            canonical_bench_command("tuic-stream"),
            Some("tuic-tcp-stream")
        );
        assert_eq!(
            canonical_bench_command("socks5-tcp-stream"),
            Some("socks-tcp-stream")
        );
        assert_eq!(
            canonical_bench_command("trojan-stream"),
            Some("trojan-tcp-stream")
        );
        assert_eq!(
            canonical_bench_command("http-stream"),
            Some("http-connect-stream")
        );
        assert_eq!(
            canonical_bench_command("ss-stream"),
            Some("shadowsocks-tcp-stream")
        );
        assert_eq!(
            canonical_bench_command("vmess-stream"),
            Some("vmess-tcp-stream")
        );
        assert_eq!(canonical_bench_command("unknown"), None);
    }

    #[test]
    fn rejects_invalid_bench_suite_options() {
        let error = parse_bench_suite_options(
            ["--commands", "hy2-tcp,unknown"]
                .into_iter()
                .map(str::to_string),
        )
        .expect_err("invalid command");
        assert!(error.contains("unknown bench command unknown"));

        let error = parse_bench_suite_options(["--repeats", "0"].into_iter().map(str::to_string))
            .expect_err("invalid repeats");
        assert!(error.contains("--repeats must be between 1 and 100"));
    }

    #[test]
    fn summarizes_bench_suite_runs() {
        let runs = vec![
            BenchSuiteRun {
                command: "hy2-tcp".to_string(),
                repeat: 1,
                report: synthetic_report("hy2-tcp", 10.0, 100, 0, 1),
            },
            BenchSuiteRun {
                command: "hy2-tcp".to_string(),
                repeat: 2,
                report: synthetic_report("hy2-tcp", 20.0, 300, 1, 2),
            },
            BenchSuiteRun {
                command: "tuic-udp".to_string(),
                repeat: 1,
                report: synthetic_report("tuic-udp", 5.0, 200, 0, 0),
            },
        ];

        let summaries = summarize_bench_runs(&runs);
        assert_eq!(summaries.len(), 2);

        let hy2 = summaries
            .iter()
            .find(|summary| summary.command == "hy2-tcp")
            .expect("hy2 summary");
        assert_eq!(hy2.repeats, 2);
        assert_eq!(hy2.completed_requests_min, 9);
        assert_eq!(hy2.errors_total, 1);
        assert_eq!(hy2.retries_total, 3);
        assert!((hy2.roundtrip_mbps_avg - 15.0).abs() < f64::EPSILON);
        assert!((hy2.p99_us_avg - 200.0).abs() < f64::EPSILON);
    }

    #[test]
    fn computes_percent_change_for_comparison() {
        assert_eq!(percent_change(0.0, 10.0), None);
        assert_eq!(percent_change(100.0, 125.0), Some(25.0));
        assert_eq!(percent_change(100.0, 80.0), Some(-20.0));
    }

    #[test]
    fn runs_direct_tcp_stream_bench_smoke() {
        let report = run_direct_tcp_stream_bench(&BenchOptions {
            streams: 1,
            requests: 3,
            payload_size: 16,
        })
        .expect("bench");

        assert_eq!(report.protocol, "direct-tcp");
        assert_eq!(report.mode, "direct-echo-stream");
        assert_eq!(report.total_requests, 3);
        assert_eq!(report.completed_requests, 3);
        assert_eq!(report.errors, 0);
        assert_eq!(report.error_rate, 0.0);
        assert_eq!(report.runtime_workers, None);
        assert!(report.download_bytes > 0);
    }

    #[test]
    fn runs_direct_tcp_proxy_stream_bench_smoke() {
        let report = run_direct_tcp_proxy_stream_bench(&BenchOptions {
            streams: 1,
            requests: 3,
            payload_size: 16,
        })
        .expect("bench");

        assert_eq!(report.protocol, "direct-tcp-proxy");
        assert_eq!(report.mode, "raw-proxy-stream");
        assert_eq!(report.total_requests, 3);
        assert_eq!(report.completed_requests, 3);
        assert_eq!(report.errors, 0);
        assert_eq!(report.error_rate, 0.0);
        assert_eq!(report.runtime_workers, None);
        assert!(report.download_bytes > 0);
    }

    #[test]
    fn runs_vless_tcp_bench_smoke() {
        let report = run_vless_tcp_bench(&BenchOptions {
            streams: 1,
            requests: 3,
            payload_size: 16,
        })
        .expect("bench");

        assert_eq!(report.protocol, "vless-tcp");
        assert_eq!(report.mode, "connection-per-request");
        assert_eq!(report.total_requests, 3);
        assert_eq!(report.completed_requests, 3);
        assert_eq!(report.errors, 0);
        assert_eq!(report.error_rate, 0.0);
        assert_eq!(report.runtime_workers, None);
        assert!(report.download_bytes > 0);
    }

    #[test]
    fn runs_socks_tcp_stream_bench_smoke() {
        let report = run_socks_tcp_stream_bench(&BenchOptions {
            streams: 1,
            requests: 3,
            payload_size: 16,
        })
        .expect("bench");

        assert_eq!(report.protocol, "socks-tcp");
        assert_eq!(report.mode, "connection-per-stream");
        assert_eq!(report.total_requests, 3);
        assert_eq!(report.completed_requests, 3);
        assert_eq!(report.errors, 0);
        assert_eq!(report.error_rate, 0.0);
        assert_eq!(report.runtime_workers, None);
        assert!(report.download_bytes > 0);
    }

    #[test]
    fn runs_http_connect_stream_bench_smoke() {
        let report = run_http_connect_stream_bench(&BenchOptions {
            streams: 1,
            requests: 3,
            payload_size: 16,
        })
        .expect("bench");

        assert_eq!(report.protocol, "http-connect");
        assert_eq!(report.mode, "connection-per-stream");
        assert_eq!(report.total_requests, 3);
        assert_eq!(report.completed_requests, 3);
        assert_eq!(report.errors, 0);
        assert_eq!(report.error_rate, 0.0);
        assert_eq!(report.runtime_workers, None);
        assert!(report.download_bytes > 0);
    }

    #[test]
    fn runs_shadowsocks_tcp_stream_bench_smoke() {
        let report = run_shadowsocks_tcp_stream_bench(&BenchOptions {
            streams: 1,
            requests: 3,
            payload_size: 16,
        })
        .expect("bench");

        assert_eq!(report.protocol, "shadowsocks-tcp");
        assert_eq!(report.mode, "connection-per-stream");
        assert_eq!(report.total_requests, 3);
        assert_eq!(report.completed_requests, 3);
        assert_eq!(report.errors, 0);
        assert_eq!(report.error_rate, 0.0);
        assert_eq!(report.runtime_workers, None);
        assert!(report.download_bytes > 0);
    }

    #[test]
    fn runs_trojan_tcp_stream_bench_smoke() {
        let report = run_trojan_tcp_stream_bench(&BenchOptions {
            streams: 1,
            requests: 3,
            payload_size: 16,
        })
        .expect("bench");

        assert_eq!(report.protocol, "trojan-tcp");
        assert_eq!(report.mode, "connection-per-stream");
        assert_eq!(report.total_requests, 3);
        assert_eq!(report.completed_requests, 3);
        assert_eq!(report.errors, 0);
        assert_eq!(report.error_rate, 0.0);
        assert_eq!(report.runtime_workers, None);
        assert!(report.download_bytes > 0);
    }

    #[test]
    fn runs_vless_tcp_stream_bench_smoke() {
        let report = run_vless_tcp_stream_bench(&BenchOptions {
            streams: 1,
            requests: 3,
            payload_size: 16,
        })
        .expect("bench");

        assert_eq!(report.protocol, "vless-tcp");
        assert_eq!(report.mode, "connection-per-stream");
        assert_eq!(report.total_requests, 3);
        assert_eq!(report.completed_requests, 3);
        assert_eq!(report.errors, 0);
        assert_eq!(report.error_rate, 0.0);
        assert_eq!(report.runtime_workers, None);
        assert!(report.download_bytes > 0);
    }

    #[test]
    fn runs_vmess_tcp_stream_bench_smoke() {
        let report = run_vmess_tcp_stream_bench(&BenchOptions {
            streams: 1,
            requests: 3,
            payload_size: 16,
        })
        .expect("bench");

        assert_eq!(report.protocol, "vmess-tcp");
        assert_eq!(report.mode, "connection-per-stream");
        assert_eq!(report.total_requests, 3);
        assert_eq!(report.completed_requests, 3);
        assert_eq!(report.errors, 0);
        assert_eq!(report.error_rate, 0.0);
        assert_eq!(report.runtime_workers, None);
        assert!(report.download_bytes > 0);
    }

    #[test]
    fn runs_external_vless_tcp_stream_bench_smoke() {
        let core_stop = Arc::new(AtomicBool::new(false));
        let discard_addr: SocketAddr = "127.0.0.1:9".parse().expect("discard addr");
        let (core_addr, core_thread) =
            super::start_vless_server(discard_addr, core_stop.clone()).expect("core");

        let result = run_external_vless_tcp_stream_bench(
            &BenchOptions {
                streams: 1,
                requests: 3,
                payload_size: 16,
            },
            core_addr,
        );

        core_stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(core_addr);
        super::join_server(core_thread).expect("core stopped");

        let report = result.expect("bench");
        assert_eq!(report.protocol, "vless-tcp");
        assert_eq!(report.mode, "connection-per-stream");
        assert_eq!(report.total_requests, 3);
        assert_eq!(report.completed_requests, 3);
        assert_eq!(report.errors, 0);
        assert_eq!(report.error_rate, 0.0);
        assert_eq!(report.runtime_workers, None);
        assert!(report.download_bytes > 0);
    }

    #[test]
    fn runs_hy2_tcp_bench_smoke() {
        let _network_guard = crate::test_support::network_test_lock();
        let report = super::run_hy2_tcp_bench(&BenchOptions {
            streams: 1,
            requests: 2,
            payload_size: 16,
        })
        .expect("bench");

        assert_eq!(report.protocol, "hy2-tcp");
        assert_eq!(report.mode, "single-quic-connection");
        assert_eq!(report.total_requests, 2);
        assert_eq!(report.completed_requests, 2);
        assert_eq!(report.errors, 0);
        assert_eq!(report.error_rate, 0.0);
        assert!(report.runtime_workers.unwrap_or_default() >= 2);
        assert!(report.download_bytes > 0);
    }

    #[test]
    fn runs_hy2_tcp_stream_bench_smoke() {
        let _network_guard = crate::test_support::network_test_lock();
        let report = super::run_hy2_tcp_stream_bench(&BenchOptions {
            streams: 1,
            requests: 3,
            payload_size: 16,
        })
        .expect("bench");

        assert_eq!(report.protocol, "hy2-tcp");
        assert_eq!(report.mode, "hy2-tcp-stream-per-worker");
        assert_eq!(report.total_requests, 3);
        assert_eq!(report.completed_requests, 3);
        assert_eq!(report.errors, 0);
        assert_eq!(report.error_rate, 0.0);
        assert!(report.runtime_workers.unwrap_or_default() >= 2);
        assert!(report.download_bytes > 0);
    }

    #[test]
    fn runs_hy2_udp_bench_smoke() {
        let _network_guard = crate::test_support::network_test_lock();
        let report = run_hy2_udp_bench(&BenchOptions {
            streams: 1,
            requests: 2,
            payload_size: 16,
        })
        .expect("bench");

        assert_eq!(report.protocol, "hy2-udp");
        assert_eq!(report.mode, "hy2-udp-datagram-connection-per-worker");
        assert_eq!(report.total_requests, 2);
        assert_eq!(report.completed_requests, 2);
        assert_eq!(report.errors, 0);
        assert_eq!(report.error_rate, 0.0);
        assert!(report.runtime_workers.unwrap_or_default() >= 2);
        assert!(report.download_bytes > 0);
    }

    #[test]
    fn runs_tuic_tcp_bench_smoke() {
        let _network_guard = crate::test_support::network_test_lock();
        let report = run_tuic_tcp_bench(&BenchOptions {
            streams: 1,
            requests: 2,
            payload_size: 16,
        })
        .expect("bench");

        assert_eq!(report.protocol, "tuic-tcp");
        assert_eq!(report.mode, "single-quic-connection");
        assert_eq!(report.total_requests, 2);
        assert_eq!(report.completed_requests, 2);
        assert_eq!(report.errors, 0);
        assert_eq!(report.error_rate, 0.0);
        assert!(report.runtime_workers.unwrap_or_default() >= 2);
        assert!(report.download_bytes > 0);
    }

    #[test]
    fn runs_tuic_tcp_stream_bench_smoke() {
        let _network_guard = crate::test_support::network_test_lock();
        let report = run_tuic_tcp_stream_bench(&BenchOptions {
            streams: 1,
            requests: 3,
            payload_size: 16,
        })
        .expect("bench");

        assert_eq!(report.protocol, "tuic-tcp");
        assert_eq!(report.mode, "tuic-tcp-stream-per-worker");
        assert_eq!(report.total_requests, 3);
        assert_eq!(report.completed_requests, 3);
        assert_eq!(report.errors, 0);
        assert_eq!(report.error_rate, 0.0);
        assert!(report.runtime_workers.unwrap_or_default() >= 2);
        assert!(report.download_bytes > 0);
    }

    #[test]
    fn runs_tuic_udp_bench_smoke() {
        let _network_guard = crate::test_support::network_test_lock();
        let report = run_tuic_udp_bench(&BenchOptions {
            streams: 1,
            requests: 2,
            payload_size: 16,
        })
        .expect("bench");

        assert_eq!(report.protocol, "tuic-udp");
        assert_eq!(report.mode, "tuic-udp-datagram-connection-per-worker");
        assert_eq!(report.total_requests, 2);
        assert_eq!(report.completed_requests, 2);
        assert_eq!(report.errors, 0);
        assert_eq!(report.error_rate, 0.0);
        assert!(report.runtime_workers.unwrap_or_default() >= 2);
        assert!(report.download_bytes > 0);
    }

    fn synthetic_report(
        protocol: &str,
        roundtrip_mbps: f64,
        p99_us: u128,
        errors: usize,
        retries: usize,
    ) -> BenchReport {
        BenchReport {
            protocol: protocol.to_string(),
            mode: "synthetic".to_string(),
            streams: 1,
            runtime_workers: Some(2),
            requests_per_stream: 10,
            payload_bytes: 16,
            total_requests: 10,
            completed_requests: 10usize.saturating_sub(errors),
            upload_bytes: 160,
            download_bytes: 160,
            retries,
            errors,
            error_rate: errors as f64 / 10.0,
            elapsed_ms: 10,
            requests_per_second: 1000.0,
            roundtrip_mbps,
            latency: LatencyReport {
                min_us: 10,
                p50_us: 20,
                p95_us: p99_us.saturating_sub(1),
                p99_us,
                max_us: p99_us,
            },
        }
    }
}
