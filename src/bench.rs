use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::user::CoreUser;
use crate::vless::{VlessServer, VlessServerConfig};

const BENCH_USER_UUID: &str = "11111111-1111-1111-1111-111111111111";
const BENCH_USER_BYTES: [u8; 16] = [0x11; 16];
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
    requests_per_stream: usize,
    payload_bytes: usize,
    total_requests: usize,
    upload_bytes: u64,
    download_bytes: u64,
    retries: usize,
    elapsed_ms: u128,
    requests_per_second: f64,
    roundtrip_mbps: f64,
    latency: LatencyReport,
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

fn print_bench_usage() {
    println!("bench commands:\n  bench vless-tcp [--streams N] [--requests N] [--payload BYTES]");
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
    let seconds = elapsed.as_secs_f64().max(f64::EPSILON);
    Ok(BenchReport {
        protocol: "vless-tcp",
        mode: "connection-per-request",
        streams: options.streams,
        requests_per_stream: options.requests,
        payload_bytes: options.payload_size,
        total_requests,
        upload_bytes,
        download_bytes,
        retries,
        elapsed_ms: elapsed.as_millis(),
        requests_per_second: total_requests as f64 / seconds,
        roundtrip_mbps: ((upload_bytes + download_bytes) as f64 * 8.0) / seconds / 1_000_000.0,
        latency: latency_report(&latencies),
    })
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
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let server = server.clone();
                    thread::spawn(move || {
                        if let Err(error) = server.handle_tcp_client(stream) {
                            eprintln!("bench vless server connection error: {error}");
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error),
            }
        }
        let _ = echo_addr;
        Ok(())
    });
    Ok((addr, handle))
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
    use super::{parse_bench_options, run_vless_tcp_bench, BenchOptions};

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
        assert!(report.download_bytes > 0);
    }
}
