use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};

use crate::config::OutboundConfig;
use crate::socks5::SocksTarget;

const MAX_UDP_CONNECTION_RESET_RETRIES: usize = 8;

pub fn connect_tcp_outbound(
    outbound: &OutboundConfig,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    match outbound.protocol.trim().to_ascii_lowercase().as_str() {
        "freedom" => connect_direct(&freedom_target(outbound, target), timeout),
        "socks" | "socks5" => connect_socks5(outbound, target, timeout),
        "http" => connect_http(outbound, target, timeout),
        "shadowsocks" => {
            crate::shadowsocks::connect_shadowsocks_tcp_outbound(outbound, target, timeout)
        }
        "trojan" => crate::trojan::connect_trojan_tcp_outbound(outbound, target, timeout),
        "vless" => crate::vless::connect_vless_tcp_outbound(outbound, target, timeout),
        "vmess" => crate::vmess::connect_vmess_tcp_outbound(outbound, target, timeout),
        protocol => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("outbound protocol {protocol} is not implemented"),
        )),
    }
}

pub fn outbound_udp_target(
    outbound: &OutboundConfig,
    target: &SocksTarget,
) -> io::Result<SocksTarget> {
    match outbound.protocol.trim().to_ascii_lowercase().as_str() {
        "freedom" => Ok(freedom_target(outbound, target)),
        protocol => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("outbound protocol {protocol} does not support udp in keli-core-rs yet"),
        )),
    }
}

pub fn send_udp_outbound(
    outbound: &OutboundConfig,
    target: &SocksTarget,
    payload: &[u8],
    timeout: Duration,
) -> io::Result<(SocketAddr, Vec<u8>)> {
    match outbound.protocol.trim().to_ascii_lowercase().as_str() {
        "freedom" => send_direct_udp(&freedom_target(outbound, target), payload, timeout),
        "socks" | "socks5" => send_socks5_udp(outbound, target, payload, timeout),
        "shadowsocks" => {
            crate::shadowsocks::send_shadowsocks_udp_outbound(outbound, target, payload, timeout)
        }
        "vmess" => crate::vmess::send_vmess_udp_outbound(outbound, target, payload, timeout),
        protocol => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("outbound protocol {protocol} does not support udp in keli-core-rs yet"),
        )),
    }
}

pub async fn send_udp_outbound_tokio(
    outbound: &OutboundConfig,
    target: &SocksTarget,
    payload: &[u8],
    timeout: Duration,
) -> io::Result<(SocketAddr, Vec<u8>)> {
    let outbound = outbound.clone();
    let target = target.clone();
    let payload = payload.to_vec();
    tokio::task::spawn_blocking(move || send_udp_outbound(&outbound, &target, &payload, timeout))
        .await
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("outbound udp task failed: {error}"),
            )
        })?
}

pub async fn connect_tcp_outbound_tokio(
    outbound: &OutboundConfig,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<tokio::net::TcpStream> {
    let outbound = outbound.clone();
    let target = target.clone();
    let stream =
        tokio::task::spawn_blocking(move || connect_tcp_outbound(&outbound, &target, timeout))
            .await
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("outbound task failed: {error}"),
                )
            })??;
    stream.set_nonblocking(true)?;
    tokio::net::TcpStream::from_std(stream)
}

fn send_direct_udp(
    target: &SocksTarget,
    payload: &[u8],
    timeout: Duration,
) -> io::Result<(SocketAddr, Vec<u8>)> {
    let remote_addr = resolve_socket_addr(target, timeout)?;
    let udp = UdpSocket::bind(udp_bind_addr_for_remote(remote_addr))?;
    udp.set_read_timeout(Some(timeout))?;
    udp.set_write_timeout(Some(timeout))?;
    udp.send_to(payload, remote_addr)?;
    let mut response = vec![0u8; 65_535];
    let (read, source) = recv_udp_response(&udp, &mut response)?;
    response.truncate(read);
    Ok((source, response))
}

fn freedom_target(outbound: &OutboundConfig, target: &SocksTarget) -> SocksTarget {
    SocksTarget {
        host: outbound
            .address
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&target.host)
            .to_string(),
        port: outbound.port.unwrap_or(target.port),
    }
}

fn connect_direct(target: &SocksTarget, timeout: Duration) -> io::Result<TcpStream> {
    let addrs = crate::dns::resolve_socket_addrs(&target.host, target.port, timeout)?;
    let mut last_error = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
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

fn connect_proxy(outbound: &OutboundConfig, timeout: Duration) -> io::Result<TcpStream> {
    let target = SocksTarget {
        host: outbound
            .address
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "outbound address is required")
            })?
            .to_string(),
        port: outbound.port.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "outbound port is required")
        })?,
    };
    let stream = connect_direct(&target, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

fn connect_socks5(
    outbound: &OutboundConfig,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let mut stream = connect_proxy(outbound, timeout)?;
    let auth = outbound
        .username
        .as_deref()
        .or(outbound.password.as_deref());
    let methods = if auth.is_some() {
        [0x05, 0x02, 0x00, 0x02].as_slice()
    } else {
        [0x05, 0x01, 0x00].as_slice()
    };
    stream.write_all(methods)?;

    let mut response = [0u8; 2];
    stream.read_exact(&mut response)?;
    if response[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid socks5 outbound version",
        ));
    }
    match response[1] {
        0x00 => {}
        0x02 => authenticate_socks5(&mut stream, outbound)?,
        0xff => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socks5 outbound rejected authentication methods",
            ));
        }
        method => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported socks5 outbound auth method {method}"),
            ));
        }
    }

    let mut request = vec![0x05, 0x01, 0x00];
    write_socks5_address(&mut request, &target.host)?;
    request.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&request)?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid socks5 outbound connect response",
        ));
    }
    if head[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("socks5 outbound connect failed with reply {}", head[1]),
        ));
    }
    drain_socks5_bound_address(&mut stream, head[3])?;
    Ok(stream)
}

fn send_socks5_udp(
    outbound: &OutboundConfig,
    target: &SocksTarget,
    payload: &[u8],
    timeout: Duration,
) -> io::Result<(SocketAddr, Vec<u8>)> {
    let mut control = connect_proxy(outbound, timeout)?;
    negotiate_socks5(&mut control, outbound)?;

    let mut request = vec![0x05, 0x03, 0x00];
    write_socks5_address(&mut request, "0.0.0.0")?;
    request.extend_from_slice(&0u16.to_be_bytes());
    control.write_all(&request)?;

    let relay = read_socks5_reply_target(&mut control)?;
    let relay = relay_socket_addr(outbound, relay, timeout)?;
    let udp = UdpSocket::bind(udp_bind_addr_for_remote(relay))?;
    udp.set_read_timeout(Some(timeout))?;
    udp.set_write_timeout(Some(timeout))?;

    let request = encode_socks5_udp_packet(target, payload)?;
    udp.send_to(&request, relay)?;
    let mut response = vec![0u8; 65_535];
    let (read, _) = recv_udp_response(&udp, &mut response)?;
    let (source, payload) = parse_socks5_udp_packet(&response[..read])?;
    let source = resolve_socket_addr(&source, timeout)?;
    Ok((source, payload))
}

pub(crate) fn recv_udp_response(
    udp: &UdpSocket,
    response: &mut [u8],
) -> io::Result<(usize, SocketAddr)> {
    let mut resets = 0usize;
    loop {
        match udp.recv_from(response) {
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {
                resets += 1;
                if resets > MAX_UDP_CONNECTION_RESET_RETRIES {
                    return Err(error);
                }
            }
            result => return result,
        }
    }
}

fn negotiate_socks5(stream: &mut TcpStream, outbound: &OutboundConfig) -> io::Result<()> {
    let auth = outbound
        .username
        .as_deref()
        .or(outbound.password.as_deref());
    let methods = if auth.is_some() {
        [0x05, 0x02, 0x00, 0x02].as_slice()
    } else {
        [0x05, 0x01, 0x00].as_slice()
    };
    stream.write_all(methods)?;

    let mut response = [0u8; 2];
    stream.read_exact(&mut response)?;
    if response[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid socks5 outbound version",
        ));
    }
    match response[1] {
        0x00 => Ok(()),
        0x02 => authenticate_socks5(stream, outbound),
        0xff => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks5 outbound rejected authentication methods",
        )),
        method => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported socks5 outbound auth method {method}"),
        )),
    }
}

fn authenticate_socks5(stream: &mut TcpStream, outbound: &OutboundConfig) -> io::Result<()> {
    let username = outbound.username.as_deref().unwrap_or_default().as_bytes();
    let password = outbound.password.as_deref().unwrap_or_default().as_bytes();
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socks5 outbound credentials are too long",
        ));
    }
    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.push(0x01);
    request.push(username.len() as u8);
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream.write_all(&request)?;

    let mut response = [0u8; 2];
    stream.read_exact(&mut response)?;
    if response != [0x01, 0x00] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks5 outbound authentication failed",
        ));
    }
    Ok(())
}

fn write_socks5_address(output: &mut Vec<u8>, host: &str) -> io::Result<()> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        output.push(0x01);
        output.extend_from_slice(&ip.octets());
        return Ok(());
    }
    if let Ok(ip) = host.parse::<Ipv6Addr>() {
        output.push(0x04);
        output.extend_from_slice(&ip.octets());
        return Ok(());
    }
    let host = host.trim().trim_matches(['[', ']']);
    if host.is_empty() || host.len() > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socks5 outbound target host is invalid",
        ));
    }
    output.push(0x03);
    output.push(host.len() as u8);
    output.extend_from_slice(host.as_bytes());
    Ok(())
}

fn drain_socks5_bound_address(stream: &mut TcpStream, atyp: u8) -> io::Result<()> {
    match atyp {
        0x01 => {
            let mut bytes = [0u8; 4 + 2];
            stream.read_exact(&mut bytes)
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            let mut bytes = vec![0u8; usize::from(len[0]) + 2];
            stream.read_exact(&mut bytes)
        }
        0x04 => {
            let mut bytes = [0u8; 16 + 2];
            stream.read_exact(&mut bytes)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid socks5 outbound bound address type",
        )),
    }
}

fn read_socks5_reply_target(stream: &mut TcpStream) -> io::Result<SocksTarget> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid socks5 outbound response version",
        ));
    }
    if head[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("socks5 outbound request failed with reply {}", head[1]),
        ));
    }
    read_socks5_target_body(stream, head[3])
}

fn read_socks5_target_body(stream: &mut TcpStream, atyp: u8) -> io::Result<SocksTarget> {
    let host = match atyp {
        0x01 => {
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes)?;
            Ipv4Addr::from(bytes).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            let mut bytes = vec![0u8; usize::from(len[0])];
            stream.read_exact(&mut bytes)?;
            String::from_utf8(bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid socks5 domain"))?
        }
        0x04 => {
            let mut bytes = [0u8; 16];
            stream.read_exact(&mut bytes)?;
            Ipv6Addr::from(bytes).to_string()
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid socks5 outbound address type",
            ));
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port)?;
    Ok(SocksTarget {
        host,
        port: u16::from_be_bytes(port),
    })
}

fn encode_socks5_udp_packet(target: &SocksTarget, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(10 + payload.len());
    output.extend_from_slice(&[0, 0, 0]);
    write_socks5_address(&mut output, &target.host)?;
    output.extend_from_slice(&target.port.to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

fn parse_socks5_udp_packet(input: &[u8]) -> io::Result<(SocksTarget, Vec<u8>)> {
    if input.len() < 4 || input[0] != 0 || input[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid socks5 udp response header",
        ));
    }
    if input[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fragmented socks5 udp responses are not supported",
        ));
    }
    let mut cursor = io::Cursor::new(&input[4..]);
    let source = read_socks5_target_body_from_read(&mut cursor, input[3])?;
    let offset = 4 + usize::try_from(cursor.position()).unwrap_or(usize::MAX);
    if offset > input.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated socks5 udp response",
        ));
    }
    Ok((source, input[offset..].to_vec()))
}

fn read_socks5_target_body_from_read<R: Read>(reader: &mut R, atyp: u8) -> io::Result<SocksTarget> {
    let host = match atyp {
        0x01 => {
            let mut bytes = [0u8; 4];
            reader.read_exact(&mut bytes)?;
            Ipv4Addr::from(bytes).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len)?;
            let mut bytes = vec![0u8; usize::from(len[0])];
            reader.read_exact(&mut bytes)?;
            String::from_utf8(bytes).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid socks5 udp domain")
            })?
        }
        0x04 => {
            let mut bytes = [0u8; 16];
            reader.read_exact(&mut bytes)?;
            Ipv6Addr::from(bytes).to_string()
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid socks5 udp address type",
            ));
        }
    };
    let mut port = [0u8; 2];
    reader.read_exact(&mut port)?;
    Ok(SocksTarget {
        host,
        port: u16::from_be_bytes(port),
    })
}

fn relay_socket_addr(
    outbound: &OutboundConfig,
    relay: SocksTarget,
    timeout: Duration,
) -> io::Result<SocketAddr> {
    let host = relay
        .host
        .parse::<IpAddr>()
        .ok()
        .filter(|ip| !ip.is_unspecified())
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| outbound.address.clone().unwrap_or(relay.host));
    resolve_socket_addr(
        &SocksTarget {
            host,
            port: relay.port,
        },
        timeout,
    )
}

fn resolve_socket_addr(target: &SocksTarget, timeout: Duration) -> io::Result<SocketAddr> {
    crate::dns::resolve_socket_addr(&target.host, target.port, timeout)
}

fn udp_bind_addr_for_remote(remote: SocketAddr) -> SocketAddr {
    match remote {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn connect_http(
    outbound: &OutboundConfig,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let mut stream = connect_proxy(outbound, timeout)?;
    let authority = target_authority(&target.host, target.port);
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if outbound.username.is_some() || outbound.password.is_some() {
        let credentials = format!(
            "{}:{}",
            outbound.username.as_deref().unwrap_or_default(),
            outbound.password.as_deref().unwrap_or_default()
        );
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&BASE64_STANDARD.encode(credentials));
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes())?;

    let response = read_http_connect_response(&mut stream)?;
    if !response.starts_with("HTTP/1.0 200") && !response.starts_with("HTTP/1.1 200") {
        let status = response
            .lines()
            .next()
            .unwrap_or("invalid http outbound response");
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("http outbound connect failed: {status}"),
        ));
    }
    Ok(stream)
}

fn read_http_connect_response(stream: &mut TcpStream) -> io::Result<String> {
    let mut buffer = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while buffer.len() < 8192 {
        stream.read_exact(&mut byte)?;
        buffer.push(byte[0]);
        if buffer.ends_with(b"\r\n\r\n") {
            return String::from_utf8(buffer).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "http outbound response is not utf-8",
                )
            });
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "http outbound response headers are too large",
    ))
}

fn target_authority(host: &str, port: u16) -> String {
    let host = host.trim().trim_matches(['[', ']']);
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};
    use std::thread;
    use std::time::Duration;

    use crate::config::OutboundConfig;
    use crate::outbound::{connect_tcp_outbound, send_udp_outbound};
    use crate::socks5::SocksTarget;

    #[test]
    fn connects_through_socks5_outbound_with_password_auth() {
        let proxy = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = proxy.accept().expect("accept proxy");
            let mut hello = [0u8; 4];
            stream.read_exact(&mut hello).expect("hello");
            assert_eq!(hello, [0x05, 0x02, 0x00, 0x02]);
            stream.write_all(&[0x05, 0x02]).expect("method");
            let mut auth = [0u8; 12];
            stream.read_exact(&mut auth).expect("auth");
            assert_eq!(
                &auth,
                &[0x01, 0x04, b'u', b's', b'e', b'r', 0x05, b'p', b'a', b's', b's', b'1']
            );
            stream.write_all(&[0x01, 0x00]).expect("auth ok");
            let mut request = [0u8; 18];
            stream.read_exact(&mut request).expect("connect");
            assert_eq!(&request[..5], &[0x05, 0x01, 0x00, 0x03, 11]);
            assert_eq!(&request[5..16], b"example.com");
            assert_eq!(u16::from_be_bytes([request[16], request[17]]), 443);
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .expect("connect ok");
            stream.write_all(b"pong").expect("payload");
        });

        let outbound = OutboundConfig {
            tag: "socks-out".to_string(),
            protocol: "socks".to_string(),
            method: None,
            alter_id: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: Some("user".to_string()),
            password: Some("pass1".to_string()),
            tls: None,
            transport: None,
        };
        let target = SocksTarget {
            host: "example.com".to_string(),
            port: 443,
        };
        let mut stream =
            connect_tcp_outbound(&outbound, &target, Duration::from_secs(2)).expect("connect");
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).expect("payload");
        assert_eq!(&payload, b"pong");
        server.join().expect("server");
    }

    #[test]
    fn connects_through_http_outbound_with_basic_auth() {
        let proxy = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = proxy.accept().expect("accept proxy");
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).expect("request");
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).expect("request utf8");
            assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
            assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\npong")
                .expect("response");
        });

        let outbound = OutboundConfig {
            tag: "http-out".to_string(),
            protocol: "http".to_string(),
            method: None,
            alter_id: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            tls: None,
            transport: None,
        };
        let target = SocksTarget {
            host: "example.com".to_string(),
            port: 443,
        };
        let mut stream =
            connect_tcp_outbound(&outbound, &target, Duration::from_secs(2)).expect("connect");
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).expect("payload");
        assert_eq!(&payload, b"pong");
        server.join().expect("server");
    }

    #[test]
    fn sends_udp_through_socks5_outbound() {
        let relay = UdpSocket::bind("127.0.0.1:0").expect("bind relay");
        relay
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("relay timeout");
        let relay_addr = relay.local_addr().expect("relay addr");
        let proxy = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let server = thread::spawn(move || {
            let (mut control, _) = proxy.accept().expect("accept proxy");
            let mut hello = [0u8; 3];
            control.read_exact(&mut hello).expect("hello");
            assert_eq!(hello, [0x05, 0x01, 0x00]);
            control.write_all(&[0x05, 0x00]).expect("method");
            let mut associate = [0u8; 10];
            control.read_exact(&mut associate).expect("associate");
            assert_eq!(associate, [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            let mut response = vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1];
            response.extend_from_slice(&relay_addr.port().to_be_bytes());
            control.write_all(&response).expect("associate ok");

            let mut packet = [0u8; 512];
            let (read, client_addr) = relay.recv_from(&mut packet).expect("relay recv");
            assert_eq!(&packet[..5], &[0, 0, 0, 0x03, 11]);
            assert_eq!(&packet[5..16], b"example.com");
            assert_eq!(u16::from_be_bytes([packet[16], packet[17]]), 443);
            assert_eq!(&packet[18..read], b"ping");

            let mut udp_response = vec![0, 0, 0, 0x01, 127, 0, 0, 1];
            udp_response.extend_from_slice(&443u16.to_be_bytes());
            udp_response.extend_from_slice(b"pong");
            relay
                .send_to(&udp_response, client_addr)
                .expect("relay response");
        });

        let outbound = OutboundConfig {
            tag: "socks-out".to_string(),
            protocol: "socks".to_string(),
            method: None,
            alter_id: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: None,
            password: None,
            tls: None,
            transport: None,
        };
        let target = SocksTarget {
            host: "example.com".to_string(),
            port: 443,
        };
        let (source, payload) =
            send_udp_outbound(&outbound, &target, b"ping", Duration::from_secs(2))
                .expect("udp outbound");

        assert_eq!(source.ip().to_string(), "127.0.0.1");
        assert_eq!(source.port(), 443);
        assert_eq!(payload, b"pong");
        server.join().expect("server");
    }
}
