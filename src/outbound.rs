use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};

use crate::config::OutboundConfig;
use crate::socks5::SocksTarget;

pub fn connect_tcp_outbound(
    outbound: &OutboundConfig,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    match outbound.protocol.trim().to_ascii_lowercase().as_str() {
        "freedom" => connect_direct(&freedom_target(outbound, target), timeout),
        "socks" | "socks5" => connect_socks5(outbound, target, timeout),
        "http" => connect_http(outbound, target, timeout),
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
    let addrs = (target.host.as_str(), target.port).to_socket_addrs()?;
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
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    use crate::config::OutboundConfig;
    use crate::outbound::connect_tcp_outbound;
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
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: Some("user".to_string()),
            password: Some("pass1".to_string()),
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
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
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
}
