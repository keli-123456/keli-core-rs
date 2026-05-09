use std::io::{self, Read, Write};
use std::net::TcpStream;

use crate::tls::TlsConnection;

const MAX_HTTP_HEADER: usize = 16 * 1024;

pub fn accept_httpupgrade(
    mut stream: TcpStream,
    expected_path: Option<&str>,
    expected_host: Option<&str>,
) -> io::Result<TcpStream> {
    let request = read_http_upgrade(&mut stream)?;
    let (path, host) = parse_httpupgrade_request(&request)?;
    validate_path(path, expected_path)?;
    validate_host(host, expected_host)?;

    stream.write_all(httpupgrade_response().as_bytes())?;
    Ok(stream)
}

pub fn accept_httpupgrade_tls(
    mut stream: TlsConnection,
    expected_path: Option<&str>,
    expected_host: Option<&str>,
) -> io::Result<TlsConnection> {
    let request = read_http_upgrade(&mut stream)?;
    let (path, host) = parse_httpupgrade_request(&request)?;
    validate_path(path, expected_path)?;
    validate_host(host, expected_host)?;

    stream.write_plain_all_wait(httpupgrade_response().as_bytes())?;
    Ok(stream)
}

pub fn connect_httpupgrade_client<S: Read + Write>(
    mut stream: S,
    path: Option<&str>,
    host: &str,
) -> io::Result<S> {
    let path = path
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("/");
    let host = host.trim();
    if host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "httpupgrade outbound host is required",
        ));
    }
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let response = read_http_upgrade(&mut stream)?;
    validate_httpupgrade_response(&response)?;
    Ok(stream)
}

fn read_http_upgrade<R: Read>(stream: &mut R) -> io::Result<String> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while bytes.len() < MAX_HTTP_HEADER {
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid http header"));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "httpupgrade header too large",
    ))
}

fn parse_httpupgrade_request(request: &str) -> io::Result<(&str, Option<&str>)> {
    let mut lines = request.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default();
    let path = request_parts.next().unwrap_or_default();
    let version = request_parts.next().unwrap_or_default();
    if !method.eq_ignore_ascii_case("GET")
        || path.is_empty()
        || !version.eq_ignore_ascii_case("HTTP/1.1")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid httpupgrade request line",
        ));
    }

    let mut upgrade = false;
    let mut connection_upgrade = false;
    let mut host = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("upgrade") && value.eq_ignore_ascii_case("websocket") {
            upgrade = true;
        } else if name.eq_ignore_ascii_case("connection")
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
        {
            connection_upgrade = true;
        } else if name.eq_ignore_ascii_case("host") {
            host = Some(value);
        }
    }

    if !upgrade || !connection_upgrade {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing httpupgrade headers",
        ));
    }
    Ok((path, host))
}

fn validate_path(path: &str, expected_path: Option<&str>) -> io::Result<()> {
    if let Some(expected) = expected_path
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let request_path = path.split('?').next().unwrap_or(path);
        if request_path != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "httpupgrade path does not match inbound transport path",
            ));
        }
    }
    Ok(())
}

fn validate_host(host: Option<&str>, expected_host: Option<&str>) -> io::Result<()> {
    let Some(expected) = expected_host
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    let Some(actual) = host else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "httpupgrade host is required",
        ));
    };
    if http_host_matches(actual, expected) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "httpupgrade host does not match inbound transport host",
    ))
}

fn validate_httpupgrade_response(response: &str) -> io::Result<()> {
    let mut lines = response.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if !status.contains(" 101 ") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "httpupgrade outbound upgrade failed",
        ));
    }
    let mut upgrade = false;
    let mut connection_upgrade = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("upgrade") && value.eq_ignore_ascii_case("websocket") {
            upgrade = true;
        } else if name.eq_ignore_ascii_case("connection")
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
        {
            connection_upgrade = true;
        }
    }
    if upgrade && connection_upgrade {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "httpupgrade outbound upgrade response is invalid",
    ))
}

fn http_host_matches(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected)
        || actual
            .rsplit_once(':')
            .map(|(host, _)| host.eq_ignore_ascii_case(expected))
            .unwrap_or(false)
}

fn httpupgrade_response() -> &'static str {
    "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
}

#[cfg(test)]
mod tests {
    use super::{parse_httpupgrade_request, validate_host, validate_path};

    #[test]
    fn parses_httpupgrade_request() {
        let request = "GET /edge?ed=2560 HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let (path, host) = parse_httpupgrade_request(request).expect("request");

        assert_eq!(path, "/edge?ed=2560");
        assert_eq!(host, Some("example.test"));
    }

    #[test]
    fn validates_httpupgrade_path_without_early_data_query() {
        validate_path("/edge?ed=2560", Some("/edge")).expect("path");
        assert!(validate_path("/other", Some("/edge")).is_err());
    }

    #[test]
    fn validates_httpupgrade_host_with_optional_port() {
        validate_host(Some("example.test:443"), Some("example.test")).expect("host");
        assert!(validate_host(Some("other.test"), Some("example.test")).is_err());
    }
}
