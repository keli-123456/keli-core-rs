use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use crate::config::{DnsConfig, DnsServerConfig};
use crate::routing::route_targets_match;

static DNS_CONFIG: OnceLock<RwLock<DnsConfig>> = OnceLock::new();
static DNS_QUERY_ID: AtomicU16 = AtomicU16::new(1);
static DNS_NEGATIVE_CACHE: OnceLock<Mutex<HashMap<DnsCacheKey, DnsNegativeCacheEntry>>> =
    OnceLock::new();
const DNS_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(15);
const DNS_NEGATIVE_CACHE_MAX_ENTRIES: usize = 4096;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DnsCacheKey {
    host: String,
    port: u16,
}

#[derive(Clone, Debug)]
struct DnsNegativeCacheEntry {
    expires_at: Instant,
    kind: io::ErrorKind,
    message: String,
}

pub fn configure(config: DnsConfig) {
    let lock = DNS_CONFIG.get_or_init(|| RwLock::new(DnsConfig::default()));
    *lock.write().expect("dns config lock poisoned") = config;
    clear_negative_cache();
}

pub fn connect_tcp(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let addrs = resolve_socket_addrs(host, port, timeout)?;
    let mut last_error = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => {
                tune_tcp_stream(&stream);
                return Ok(stream);
            }
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

pub async fn connect_tcp_tokio(
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<tokio::net::TcpStream> {
    let addrs = resolve_socket_addrs_tokio(host, port, timeout).await?;
    let mut last_error = None;
    for addr in addrs {
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                tune_tokio_tcp_stream(&stream);
                return Ok(stream);
            }
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => {
                last_error = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "target connect timed out",
                ));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "target did not resolve to any socket address",
        )
    }))
}

fn tune_tcp_stream(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let _ = socket2::SockRef::from(stream).set_tcp_quickack(true);
    }
}

fn tune_tokio_tcp_stream(stream: &tokio::net::TcpStream) {
    let _ = stream.set_nodelay(true);
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let _ = stream.set_quickack(true);
    }
}

pub fn resolve_socket_addr(host: &str, port: u16, timeout: Duration) -> io::Result<SocketAddr> {
    resolve_socket_addrs(host, port, timeout)?
        .into_iter()
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "target did not resolve to any socket address",
            )
        })
}

pub async fn resolve_socket_addr_tokio(
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<SocketAddr> {
    resolve_socket_addrs_tokio(host, port, timeout)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "target did not resolve to any socket address",
            )
        })
}

pub async fn resolve_socket_addrs_tokio(
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<Vec<SocketAddr>> {
    if let Some(addr) = literal_socket_addr(host, port) {
        return Ok(vec![addr]);
    }

    let host = host.to_string();
    tokio::task::spawn_blocking(move || resolve_socket_addrs(&host, port, timeout))
        .await
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("dns resolve task failed: {error}"),
            )
        })?
}

pub fn resolve_socket_addrs(
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<Vec<SocketAddr>> {
    if let Some(addr) = literal_socket_addr(host, port) {
        return Ok(vec![addr]);
    }

    let host = host.trim().trim_matches(['[', ']']);
    let cache_key = DnsCacheKey {
        host: host.to_ascii_lowercase(),
        port,
    };
    if let Some(error) = cached_negative_error(&cache_key) {
        return Err(error);
    }
    let config = current_config();
    let result = if config.servers.is_empty() {
        system_resolve(host, port)
    } else {
        let servers = select_servers(&config, host);
        let query_types = query_types(&config.query_strategy);
        let mut last_error = None;
        let mut resolved = None;
        'outer: for server in servers {
            for qtype in &query_types {
                match query_dns_server(&server, host, *qtype, timeout) {
                    Ok(ips) if !ips.is_empty() => {
                        resolved = Some(
                            ips.into_iter()
                                .map(|ip| SocketAddr::new(ip, port))
                                .collect::<Vec<_>>(),
                        );
                        break 'outer;
                    }
                    Ok(_) => {}
                    Err(error) => last_error = Some(error),
                }
            }
        }

        resolved.map(Ok).unwrap_or_else(|| {
            Err(last_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "configured dns servers returned no target address",
                )
            }))
        })
    };

    match result {
        Ok(addrs) => {
            remove_negative_cache_entry(&cache_key);
            Ok(addrs)
        }
        Err(error) => {
            record_negative_cache(&cache_key, &error);
            Err(error)
        }
    }
}

fn clear_negative_cache() {
    if let Some(cache) = DNS_NEGATIVE_CACHE.get() {
        cache.lock().expect("dns negative cache poisoned").clear();
    }
}

fn negative_cache() -> &'static Mutex<HashMap<DnsCacheKey, DnsNegativeCacheEntry>> {
    DNS_NEGATIVE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cached_negative_error(key: &DnsCacheKey) -> Option<io::Error> {
    let now = Instant::now();
    let mut cache = negative_cache()
        .lock()
        .expect("dns negative cache poisoned");
    let Some(entry) = cache.get(key) else {
        return None;
    };
    if now >= entry.expires_at {
        cache.remove(key);
        return None;
    }
    Some(io::Error::new(entry.kind, entry.message.clone()))
}

fn record_negative_cache(key: &DnsCacheKey, error: &io::Error) {
    let mut cache = negative_cache()
        .lock()
        .expect("dns negative cache poisoned");
    if cache.len() >= DNS_NEGATIVE_CACHE_MAX_ENTRIES {
        let now = Instant::now();
        cache.retain(|_, entry| entry.expires_at > now);
        if cache.len() >= DNS_NEGATIVE_CACHE_MAX_ENTRIES {
            if let Some(first) = cache.keys().next().cloned() {
                cache.remove(&first);
            }
        }
    }
    cache.insert(
        key.clone(),
        DnsNegativeCacheEntry {
            expires_at: Instant::now() + DNS_NEGATIVE_CACHE_TTL,
            kind: error.kind(),
            message: error.to_string(),
        },
    );
}

fn remove_negative_cache_entry(key: &DnsCacheKey) {
    if let Some(cache) = DNS_NEGATIVE_CACHE.get() {
        cache
            .lock()
            .expect("dns negative cache poisoned")
            .remove(key);
    }
}

fn current_config() -> DnsConfig {
    DNS_CONFIG
        .get_or_init(|| RwLock::new(DnsConfig::default()))
        .read()
        .expect("dns config lock poisoned")
        .clone()
}

fn select_servers(config: &DnsConfig, host: &str) -> Vec<DnsServerConfig> {
    let matched = config
        .servers
        .iter()
        .filter(|server| {
            !server.domains.is_empty() && route_targets_match(&server.domains, host, 0, "")
        })
        .cloned()
        .collect::<Vec<_>>();
    if !matched.is_empty() {
        return matched;
    }
    config
        .servers
        .iter()
        .filter(|server| server.domains.is_empty())
        .cloned()
        .collect()
}

fn query_types(strategy: &str) -> Vec<u16> {
    match strategy.trim().to_ascii_lowercase().as_str() {
        "useipv6" | "ipv6" => vec![28],
        "asis" | "useip" | "useipv4v6" => vec![1, 28],
        _ => vec![1],
    }
}

fn query_dns_server(
    server: &DnsServerConfig,
    host: &str,
    qtype: u16,
    timeout: Duration,
) -> io::Result<Vec<IpAddr>> {
    let query_id = DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed);
    let query = encode_query(query_id, host, qtype)?;
    let response = match dns_server_endpoint(&server.address)? {
        DnsServerEndpoint::Udp(server_addr) => query_udp_dns(server_addr, &query, timeout)?,
        DnsServerEndpoint::Tcp(server_addr) => query_tcp_dns(server_addr, &query, timeout)?,
    };
    parse_response(&response, query_id, qtype)
}

enum DnsServerEndpoint {
    Udp(SocketAddr),
    Tcp(SocketAddr),
}

fn dns_server_endpoint(address: &str) -> io::Result<DnsServerEndpoint> {
    let address = address.trim();
    if let Some(rest) = address.strip_prefix("tcp://") {
        return Ok(DnsServerEndpoint::Tcp(dns_server_addr(rest)?));
    }
    if let Some(rest) = address.strip_prefix("udp://") {
        return Ok(DnsServerEndpoint::Udp(dns_server_addr(rest)?));
    }
    if address.contains("://") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only udp and tcp dns server addresses are supported",
        ));
    }
    Ok(DnsServerEndpoint::Udp(dns_server_addr(address)?))
}

fn dns_server_addr(address: &str) -> io::Result<SocketAddr> {
    let address = address.trim();
    if let Ok(addr) = address.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let host = address.trim_matches(['[', ']']);
    (host, 53).to_socket_addrs()?.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "dns server did not resolve to any socket address",
        )
    })
}

fn query_udp_dns(server_addr: SocketAddr, query: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
    let bind_addr = match server_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    socket.send_to(query, server_addr)?;

    let mut response = vec![0u8; 4096];
    let (read, _) = socket.recv_from(&mut response)?;
    response.truncate(read);
    Ok(response)
}

fn query_tcp_dns(server_addr: SocketAddr, query: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&server_addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let len = u16::try_from(query.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "dns tcp query is too large"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(query)?;

    let mut len = [0u8; 2];
    stream.read_exact(&mut len)?;
    let response_len = u16::from_be_bytes(len) as usize;
    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response)?;
    Ok(response)
}

fn system_resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    (host, port).to_socket_addrs().map(|addrs| addrs.collect())
}

fn literal_socket_addr(host: &str, port: u16) -> Option<SocketAddr> {
    host.trim()
        .trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, port))
}

fn encode_query(query_id: u16, host: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(512);
    output.extend_from_slice(&query_id.to_be_bytes());
    output.extend_from_slice(&0x0100u16.to_be_bytes());
    output.extend_from_slice(&1u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dns query host label is invalid",
            ));
        }
        output.push(label.len() as u8);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    output.extend_from_slice(&qtype.to_be_bytes());
    output.extend_from_slice(&1u16.to_be_bytes());
    Ok(output)
}

fn parse_response(input: &[u8], query_id: u16, qtype: u16) -> io::Result<Vec<IpAddr>> {
    if input.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "dns response is too short",
        ));
    }
    if u16::from_be_bytes([input[0], input[1]]) != query_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dns response id mismatch",
        ));
    }
    let flags = u16::from_be_bytes([input[2], input[3]]);
    if flags & 0x8000 == 0 || flags & 0x000f != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dns response indicates failure",
        ));
    }
    let question_count = u16::from_be_bytes([input[4], input[5]]) as usize;
    let answer_count = u16::from_be_bytes([input[6], input[7]]) as usize;
    let mut offset = 12;
    for _ in 0..question_count {
        read_name(input, &mut offset)?;
        if input.len().saturating_sub(offset) < 4 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated dns question",
            ));
        }
        offset += 4;
    }

    let mut ips = Vec::new();
    for _ in 0..answer_count {
        read_name(input, &mut offset)?;
        if input.len().saturating_sub(offset) < 10 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated dns answer",
            ));
        }
        let answer_type = u16::from_be_bytes([input[offset], input[offset + 1]]);
        let class = u16::from_be_bytes([input[offset + 2], input[offset + 3]]);
        let data_len = u16::from_be_bytes([input[offset + 8], input[offset + 9]]) as usize;
        offset += 10;
        if input.len().saturating_sub(offset) < data_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated dns answer data",
            ));
        }
        if class == 1 && answer_type == qtype {
            match (answer_type, data_len) {
                (1, 4) => {
                    ips.push(IpAddr::V4(Ipv4Addr::new(
                        input[offset],
                        input[offset + 1],
                        input[offset + 2],
                        input[offset + 3],
                    )));
                }
                (28, 16) => {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&input[offset..offset + 16]);
                    ips.push(IpAddr::V6(Ipv6Addr::from(bytes)));
                }
                _ => {}
            }
        }
        offset += data_len;
    }
    Ok(ips)
}

fn read_name(input: &[u8], offset: &mut usize) -> io::Result<()> {
    let mut cursor = *offset;
    let mut jumped = false;
    for _ in 0..128 {
        let Some(&len) = input.get(cursor) else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated dns name",
            ));
        };
        if len & 0xc0 == 0xc0 {
            if input.get(cursor + 1).is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated dns name pointer",
                ));
            }
            if !jumped {
                *offset = cursor + 2;
            }
            let pointer = (((len & 0x3f) as usize) << 8) | input[cursor + 1] as usize;
            cursor = pointer;
            jumped = true;
            continue;
        }
        if len == 0 {
            if !jumped {
                *offset = cursor + 1;
            }
            return Ok(());
        }
        cursor += 1 + usize::from(len);
        if cursor > input.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated dns label",
            ));
        }
        if !jumped {
            *offset = cursor;
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "dns name compression loop",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn parses_dns_a_response() {
        let query = encode_query(7, "example.com", 1).expect("query");
        let mut response = Vec::new();
        response.extend_from_slice(&7u16.to_be_bytes());
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&[203, 0, 113, 9]);

        let ips = parse_response(&response, 7, 1).expect("response");
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]);
    }

    #[test]
    fn resolves_with_configured_dns_server() {
        let dns = UdpSocket::bind("127.0.0.1:0").expect("dns bind");
        dns.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("dns timeout");
        let dns_addr = dns.local_addr().expect("dns addr");
        let server = thread::spawn(move || {
            let mut packet = [0u8; 512];
            let (read, peer) = dns.recv_from(&mut packet).expect("dns recv");
            assert!(read > 12);
            let query_id = u16::from_be_bytes([packet[0], packet[1]]);
            let mut response = Vec::new();
            response.extend_from_slice(&query_id.to_be_bytes());
            response.extend_from_slice(&0x8180u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&packet[12..read]);
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&30u32.to_be_bytes());
            response.extend_from_slice(&4u16.to_be_bytes());
            response.extend_from_slice(&[198, 51, 100, 8]);
            dns.send_to(&response, peer).expect("dns response");
        });

        configure(DnsConfig {
            servers: vec![DnsServerConfig {
                address: dns_addr.to_string(),
                domains: vec!["domain:example.com".to_string()],
            }],
            query_strategy: "UseIPv4".to_string(),
        });
        let addrs =
            resolve_socket_addrs("api.example.com", 443, Duration::from_secs(2)).expect("resolve");
        assert_eq!(addrs, vec!["198.51.100.8:443".parse().unwrap()]);
        server.join().expect("server");
        configure(DnsConfig::default());
    }

    #[test]
    fn resolves_with_configured_tcp_dns_server() {
        let dns = TcpListener::bind("127.0.0.1:0").expect("dns bind");
        let dns_addr = dns.local_addr().expect("dns addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = dns.accept().expect("dns accept");
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).expect("dns query len");
            let mut packet = vec![0u8; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut packet).expect("dns query");
            let query_id = u16::from_be_bytes([packet[0], packet[1]]);
            let mut response = Vec::new();
            response.extend_from_slice(&query_id.to_be_bytes());
            response.extend_from_slice(&0x8180u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&packet[12..]);
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&30u32.to_be_bytes());
            response.extend_from_slice(&4u16.to_be_bytes());
            response.extend_from_slice(&[203, 0, 113, 12]);
            let response_len = u16::try_from(response.len()).expect("response len");
            stream
                .write_all(&response_len.to_be_bytes())
                .expect("write response len");
            stream.write_all(&response).expect("write response");
        });

        configure(DnsConfig {
            servers: vec![DnsServerConfig {
                address: format!("tcp://{dns_addr}"),
                domains: vec!["domain:example.net".to_string()],
            }],
            query_strategy: "UseIPv4".to_string(),
        });
        let addrs =
            resolve_socket_addrs("api.example.net", 443, Duration::from_secs(2)).expect("resolve");
        assert_eq!(addrs, vec!["203.0.113.12:443".parse().unwrap()]);
        server.join().expect("server");
        configure(DnsConfig::default());
    }

    #[tokio::test]
    async fn async_resolves_literal_ips_without_dns_lookup() {
        configure(DnsConfig {
            servers: vec![DnsServerConfig {
                address: "udp://192.0.2.1:53".to_string(),
                domains: Vec::new(),
            }],
            query_strategy: "UseIPv4".to_string(),
        });

        let ipv4 = resolve_socket_addrs_tokio("127.0.0.1", 443, Duration::from_millis(1))
            .await
            .expect("ipv4 literal");
        assert_eq!(ipv4, vec!["127.0.0.1:443".parse().unwrap()]);

        let ipv6 = resolve_socket_addrs_tokio("[::1]", 443, Duration::from_millis(1))
            .await
            .expect("ipv6 literal");
        assert_eq!(ipv6, vec!["[::1]:443".parse().unwrap()]);

        configure(DnsConfig::default());
    }

    #[test]
    fn negative_dns_cache_reuses_recent_failures_and_clears_on_configure() {
        let key = DnsCacheKey {
            host: "missing.example.test".to_string(),
            port: 443,
        };
        record_negative_cache(
            &key,
            &io::Error::new(io::ErrorKind::AddrNotAvailable, "no answer"),
        );

        let cached = cached_negative_error(&key).expect("cached error");
        assert_eq!(cached.kind(), io::ErrorKind::AddrNotAvailable);
        assert_eq!(cached.to_string(), "no answer");

        configure(DnsConfig::default());
        assert!(cached_negative_error(&key).is_none());
    }
}
