use std::fs;
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use serde::Serialize;
use tokio::io::AsyncReadExt;

use crate::hysteria2::{Hysteria2Server, Hysteria2ServerConfig};
use crate::tuic::{TuicServer, TuicServerConfig};
use crate::user::CoreUser;
use crate::vless::{VlessServer, VlessServerConfig};

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
const MAX_REQUEST_RETRIES: usize = 3;

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

#[derive(Debug, Serialize)]
struct BenchReport {
    protocol: &'static str,
    mode: &'static str,
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
            protocol,
            mode,
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

#[derive(Debug, Serialize)]
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

pub fn run_bench(args: impl Iterator<Item = String>) -> Result<(), String> {
    let mut args = args;
    match args.next().as_deref() {
        Some("vless-tcp") => {
            let options = parse_bench_options(args)?;
            let report = run_vless_tcp_bench(&options).map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Some("vless-tcp-stream") | Some("vless-stream") => {
            let options = parse_bench_options(args)?;
            let report = run_vless_tcp_stream_bench(&options).map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Some("hy2-tcp") | Some("hysteria2-tcp") => {
            let options = parse_bench_options(args)?;
            let report = run_hy2_tcp_bench(&options).map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Some("hy2-tcp-stream") | Some("hysteria2-tcp-stream") | Some("hy2-stream") => {
            let options = parse_bench_options(args)?;
            let report = run_hy2_tcp_stream_bench(&options).map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Some("hy2-udp") | Some("hysteria2-udp") => {
            let options = parse_bench_options(args)?;
            let report = run_hy2_udp_bench(&options).map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Some("tuic-tcp") => {
            let options = parse_bench_options(args)?;
            let report = run_tuic_tcp_bench(&options).map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Some("tuic-udp") => {
            let options = parse_bench_options(args)?;
            let report = run_tuic_udp_bench(&options).map_err(|error| error.to_string())?;
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

fn bench_quic_runtime_workers() -> usize {
    thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .clamp(2, 16)
}

fn print_bench_usage() {
    println!(
        "bench commands:\n  bench vless-tcp [--streams N] [--requests N] [--payload BYTES]\n  bench vless-tcp-stream [--streams N] [--requests N] [--payload BYTES]\n  bench hy2-tcp [--streams N] [--requests N] [--payload BYTES]\n  bench hy2-tcp-stream [--streams N] [--requests N] [--payload BYTES]\n  bench hy2-udp [--streams N] [--requests N] [--payload BYTES]\n  bench tuic-tcp [--streams N] [--requests N] [--payload BYTES]\n  bench tuic-udp [--streams N] [--requests N] [--payload BYTES]"
    );
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

fn run_tuic_udp_bench(options: &BenchOptions) -> io::Result<BenchReport> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(bench_quic_runtime_workers())
        .enable_all()
        .build()?
        .block_on(run_tuic_udp_bench_async(options))
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
    let echo_stop = Arc::new(AtomicBool::new(false));
    let echo = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
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
        workers.push(tokio::spawn(async move {
            run_hy2_udp_client(server_addr, cert_der, echo_addr, stream_id, &options).await
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

async fn run_tuic_udp_bench_async(options: &BenchOptions) -> io::Result<BenchReport> {
    let echo_stop = Arc::new(AtomicBool::new(false));
    let echo = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
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
        workers.push(tokio::spawn(async move {
            run_tuic_udp_client(server_addr, cert_der, echo_addr, stream_id, &options).await
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
    read_vless_response_header(&mut stream)?;
    stream.write_all(payload)?;
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
    read_vless_response_header(&mut stream)?;

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
    echo_addr: SocketAddr,
    stream_id: usize,
    options: &BenchOptions,
) -> io::Result<ClientStats> {
    let client_endpoint = hy2_client_endpoint(cert_der)?;
    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .map_err(io_other)?
        .await
        .map_err(io_other)?;
    authenticate_hy2(&connection).await?;
    let payload = bench_payload(stream_id, options.payload_size);
    let session_id = stream_id.saturating_add(1) as u32;
    let mut latencies = Vec::with_capacity(options.requests);

    for request_index in 0..options.requests {
        let packet_id = ((request_index % usize::from(u16::MAX)) + 1) as u16;
        let started = Instant::now();
        let datagram = hy2_udp_datagram(session_id, packet_id, echo_addr, &payload)?;
        connection
            .send_datagram_wait(Bytes::from(datagram))
            .await
            .map_err(io_other)?;
        let response = tokio::time::timeout(Duration::from_secs(10), connection.read_datagram())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "hy2 udp response timeout"))?
            .map_err(io_other)?;
        let response = parse_hy2_udp_datagram(&response)?;
        if response.session_id != session_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "hy2 udp response id mismatch",
            ));
        }
        if response.data != payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "hy2 udp bench echo payload mismatch",
            ));
        }
        latencies.push(started.elapsed().as_micros());
    }

    connection.close(0u32.into(), b"bench done");
    client_endpoint.wait_idle().await;
    Ok(ClientStats {
        latencies,
        retries: 0,
    })
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

async fn run_tuic_udp_client(
    server_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    echo_addr: SocketAddr,
    stream_id: usize,
    options: &BenchOptions,
) -> io::Result<ClientStats> {
    let client_endpoint = hy2_client_endpoint(cert_der)?;
    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .map_err(io_other)?
        .await
        .map_err(io_other)?;
    authenticate_tuic(&connection).await?;
    let payload = bench_payload(stream_id, options.payload_size);
    let assoc_id = stream_id.saturating_add(1) as u16;
    let mut latencies = Vec::with_capacity(options.requests);

    for request_index in 0..options.requests {
        let packet_id = ((request_index % usize::from(u16::MAX)) + 1) as u16;
        let started = Instant::now();
        let datagram = tuic_udp_packet(assoc_id, packet_id, Some(echo_addr), &payload)?;
        connection
            .send_datagram_wait(Bytes::from(datagram))
            .await
            .map_err(io_other)?;
        let response = tokio::time::timeout(Duration::from_secs(10), connection.read_datagram())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tuic udp response timeout"))?
            .map_err(io_other)?;
        let response = parse_tuic_udp_packet(&response)?;
        if response.assoc_id != assoc_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tuic udp response association id mismatch",
            ));
        }
        if response.payload != payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tuic udp bench echo payload mismatch",
            ));
        }
        latencies.push(started.elapsed().as_micros());
    }

    connection.close(0u32.into(), b"bench done");
    client_endpoint.wait_idle().await;
    Ok(ClientStats {
        latencies,
        retries: 0,
    })
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

fn tuic_udp_packet(
    assoc_id: u16,
    packet_id: u16,
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
    output.push(1);
    output.push(0);
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(&address);
    output.extend_from_slice(payload);
    Ok(output)
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
    let fragment_total = input[6];
    let fragment_id = input[7];
    if fragment_total != 1 || fragment_id != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tuic bench does not support fragmented udp responses",
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
        payload: input[offset..].to_vec(),
    })
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
    data: Vec<u8>,
}

fn hy2_udp_datagram(
    session_id: u32,
    packet_id: u16,
    target: SocketAddr,
    data: &[u8],
) -> io::Result<Vec<u8>> {
    let address = format_socket_addr(&target);
    let mut output = Vec::with_capacity(8 + address.len() + data.len() + 8);
    output.extend_from_slice(&session_id.to_be_bytes());
    output.extend_from_slice(&packet_id.to_be_bytes());
    output.push(0);
    output.push(1);
    output.extend_from_slice(&encode_hy2_varint(address.len() as u64)?);
    output.extend_from_slice(address.as_bytes());
    output.extend_from_slice(data);
    Ok(output)
}

fn parse_hy2_udp_datagram(input: &[u8]) -> io::Result<Hy2UdpBenchDatagram> {
    if input.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hy2 udp datagram is too short",
        ));
    }
    let session_id = u32::from_be_bytes(input[0..4].try_into().expect("fixed slice"));
    let _packet_id = u16::from_be_bytes(input[4..6].try_into().expect("fixed slice"));
    if input[6] != 0 || input[7] != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hy2 udp bench expects unfragmented datagram",
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
        data: input[offset..].to_vec(),
    })
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
        parse_bench_options, run_hy2_udp_bench, run_tuic_tcp_bench, run_tuic_udp_bench,
        run_vless_tcp_bench, run_vless_tcp_stream_bench, BenchOptions,
    };

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
}
