use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::Engine;
use sha1::{Digest, Sha1};

use crate::limits::BandwidthLimiter;
use crate::tls::TlsConnection;

const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HTTP_HEADER: usize = 16 * 1024;
const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;

pub struct WebSocketReader {
    reader: TcpStream,
    control_writer: Arc<Mutex<TcpStream>>,
    buffer: Vec<u8>,
}

pub struct WebSocketWriter {
    writer: Arc<Mutex<TcpStream>>,
}

pub struct WebSocketTlsStream {
    stream: TlsConnection,
    input: Vec<u8>,
    buffer: Vec<u8>,
}

pub struct WebSocketClientStream<S> {
    stream: S,
    buffer: Vec<u8>,
}

pub fn connect_websocket_client<S: Read + Write>(
    mut stream: S,
    path: Option<&str>,
    host: &str,
) -> io::Result<WebSocketClientStream<S>> {
    let path = path
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("/");
    let host = host.trim();
    if host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "websocket outbound host is required",
        ));
    }
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let response = read_http_upgrade(&mut stream)?;
    validate_client_upgrade_response(&response, key)?;
    Ok(WebSocketClientStream {
        stream,
        buffer: Vec::new(),
    })
}

pub fn accept_websocket(
    stream: TcpStream,
    expected_path: Option<&str>,
) -> io::Result<(WebSocketReader, WebSocketWriter)> {
    let (reader, writer, _) = accept_websocket_with_client_ip(stream, expected_path)?;
    Ok((reader, writer))
}

pub fn accept_websocket_with_client_ip(
    mut stream: TcpStream,
    expected_path: Option<&str>,
) -> io::Result<(WebSocketReader, WebSocketWriter, Option<IpAddr>)> {
    let request = read_http_upgrade(&mut stream)?;
    let (path, key) = parse_upgrade_request(&request)?;
    validate_path(path, expected_path)?;
    let forwarded_ip = forwarded_client_ip(&request);
    let (early_protocol, early_data) = websocket_early_data(&request);

    let accept = websocket_accept_key(key);
    let protocol_header = early_protocol
        .map(|protocol| format!("Sec-WebSocket-Protocol: {protocol}\r\n"))
        .unwrap_or_default();
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n{protocol_header}\r\n"
    );
    stream.write_all(response.as_bytes())?;

    let control_writer = Arc::new(Mutex::new(stream.try_clone()?));
    Ok((
        WebSocketReader {
            reader: stream,
            control_writer: control_writer.clone(),
            buffer: early_data,
        },
        WebSocketWriter {
            writer: control_writer,
        },
        forwarded_ip,
    ))
}

pub fn accept_websocket_tls(
    stream: TlsConnection,
    expected_path: Option<&str>,
) -> io::Result<WebSocketTlsStream> {
    let (stream, _) = accept_websocket_tls_with_client_ip(stream, expected_path)?;
    Ok(stream)
}

pub fn accept_websocket_tls_with_client_ip(
    mut stream: TlsConnection,
    expected_path: Option<&str>,
) -> io::Result<(WebSocketTlsStream, Option<IpAddr>)> {
    let request = read_http_upgrade(&mut stream)?;
    let (path, key) = parse_upgrade_request(&request)?;
    validate_path(path, expected_path)?;
    let forwarded_ip = forwarded_client_ip(&request);
    let (early_protocol, early_data) = websocket_early_data(&request);

    let accept = websocket_accept_key(key);
    let protocol_header = early_protocol
        .map(|protocol| format!("Sec-WebSocket-Protocol: {protocol}\r\n"))
        .unwrap_or_default();
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n{protocol_header}\r\n"
    );
    stream.write_plain_all_wait(response.as_bytes())?;

    Ok((
        WebSocketTlsStream {
            stream,
            input: Vec::new(),
            buffer: early_data,
        },
        forwarded_ip,
    ))
}

pub fn relay_websocket_tls_stream(
    mut client: WebSocketTlsStream,
    mut remote: TcpStream,
    limiter: Option<Arc<BandwidthLimiter>>,
) -> io::Result<(u64, u64)> {
    client.set_nonblocking(true)?;
    remote.set_nonblocking(true)?;

    let mut upload = 0u64;
    let mut download = 0u64;
    let mut upload_done = false;
    let mut download_done = false;
    let mut client_buffer = [0u8; 16 * 1024];
    let mut remote_buffer = [0u8; 16 * 1024];
    let mut idle_rounds = 0u8;

    while !upload_done || !download_done {
        let mut progressed = false;

        if !upload_done {
            match client.read(&mut client_buffer) {
                Ok(0) => {
                    upload_done = true;
                    download_done = true;
                    shutdown_websocket_tls_pair(&mut client, &remote);
                    progressed = true;
                }
                Ok(read) => {
                    if let Some(limiter) = limiter.as_deref() {
                        if !limiter.wait_for(read) {
                            upload_done = true;
                            download_done = true;
                            shutdown_websocket_tls_pair(&mut client, &remote);
                            continue;
                        }
                    }
                    write_all_wait(&mut remote, &client_buffer[..read])?;
                    upload = upload.saturating_add(read as u64);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    upload_done = true;
                    download_done = true;
                    shutdown_websocket_tls_pair(&mut client, &remote);
                    progressed = true;
                }
            }
        }

        if !download_done {
            match remote.read(&mut remote_buffer) {
                Ok(0) => {
                    download_done = true;
                    upload_done = true;
                    shutdown_websocket_tls_pair(&mut client, &remote);
                    progressed = true;
                }
                Ok(read) => {
                    client.write_binary_wait(&remote_buffer[..read])?;
                    download = download.saturating_add(read as u64);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    download_done = true;
                    upload_done = true;
                    shutdown_websocket_tls_pair(&mut client, &remote);
                    progressed = true;
                }
            }
        }

        if !progressed {
            let timeout = websocket_tls_relay_idle_timeout(&mut idle_rounds);
            client.wait_readable_with_remote(&remote, !upload_done, !download_done, timeout)?;
        } else {
            idle_rounds = 0;
        }
    }

    Ok((upload, download))
}

fn shutdown_websocket_tls_pair(client: &mut WebSocketTlsStream, remote: &TcpStream) {
    let _ = client.shutdown();
    let _ = remote.shutdown(Shutdown::Both);
}

impl WebSocketReader {
    pub(crate) fn shutdown(&self) -> io::Result<()> {
        self.reader.shutdown(Shutdown::Both)
    }

    pub(crate) fn peer_closed_nonblocking(&self) -> io::Result<bool> {
        self.reader.set_nonblocking(true)?;
        let mut byte = [0u8; 1];
        let result = match self.reader.peek(&mut byte) {
            Ok(0) => Ok(true),
            Ok(_) => Ok(false),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error),
        };
        let restore = self.reader.set_nonblocking(false);
        match (result, restore) {
            (Ok(closed), Ok(())) => Ok(closed),
            (Err(error), _) => Err(error),
            (_, Err(error)) => Err(error),
        }
    }
}

impl WebSocketWriter {
    pub(crate) fn shutdown(&self) -> io::Result<()> {
        self.writer
            .lock()
            .expect("websocket writer lock poisoned")
            .shutdown(Shutdown::Both)
    }
}

impl Read for WebSocketReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.buffer.is_empty() {
            match read_frame(&mut self.reader)? {
                WebSocketFrame::Data(data) => self.buffer = data,
                WebSocketFrame::Ping(data) => {
                    write_frame(&self.control_writer, OPCODE_PONG, &data)?;
                }
                WebSocketFrame::Pong | WebSocketFrame::Close => return Ok(0),
            }
        }

        let len = output.len().min(self.buffer.len());
        output[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);
        Ok(len)
    }
}

impl Write for WebSocketWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        write_frame(&self.writer, OPCODE_BINARY, input)?;
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer
            .lock()
            .expect("websocket writer lock poisoned")
            .flush()
    }
}

impl WebSocketTlsStream {
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.stream.set_nonblocking(nonblocking)
    }

    fn write_binary_wait(&mut self, payload: &[u8]) -> io::Result<()> {
        self.stream
            .write_plain_all_wait(&frame_bytes(OPCODE_BINARY, payload))
    }

    pub(crate) fn shutdown(&self) -> io::Result<()> {
        self.stream.shutdown(Shutdown::Both)
    }

    pub(crate) fn peer_closed_nonblocking(&self) -> io::Result<bool> {
        self.stream.set_nonblocking(true)?;
        let result = self.stream.peer_closed();
        let restore = self.stream.set_nonblocking(false);
        match (result, restore) {
            (Ok(closed), Ok(())) => Ok(closed),
            (Err(error), _) => Err(error),
            (_, Err(error)) => Err(error),
        }
    }

    fn wait_readable_with_remote(
        &self,
        remote: &TcpStream,
        wait_client: bool,
        wait_remote: bool,
        timeout: Duration,
    ) -> io::Result<()> {
        if wait_client && !self.buffer.is_empty() {
            return Ok(());
        }
        self.stream
            .wait_raw_readable_with(remote, wait_client, wait_remote, timeout)
    }
}

pub(crate) fn websocket_tls_relay_idle_timeout(idle_rounds: &mut u8) -> Duration {
    const BACKOFF_MS: [u64; 5] = [25, 50, 100, 250, 1000];
    let idx = usize::from((*idle_rounds).min((BACKOFF_MS.len() - 1) as u8));
    *idle_rounds = idle_rounds
        .saturating_add(1)
        .min((BACKOFF_MS.len() - 1) as u8);
    Duration::from_millis(BACKOFF_MS[idx])
}

impl Read for WebSocketTlsStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.buffer.is_empty() {
            if let Some(frame) = parse_buffered_frame(&mut self.input)? {
                match frame {
                    WebSocketFrame::Data(data) => self.buffer = data,
                    WebSocketFrame::Ping(data) => self
                        .stream
                        .write_plain_all_wait(&frame_bytes(OPCODE_PONG, &data))?,
                    WebSocketFrame::Pong => {}
                    WebSocketFrame::Close => return Ok(0),
                }
                continue;
            }

            let mut input = [0u8; 8 * 1024];
            match self.stream.read(&mut input) {
                Ok(0) => return Ok(0),
                Ok(read) => self.input.extend_from_slice(&input[..read]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Err(error),
                Err(error) => return Err(error),
            }
        }

        let len = output.len().min(self.buffer.len());
        output[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);
        Ok(len)
    }
}

impl Write for WebSocketTlsStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        self.write_binary_wait(input)?;
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl<S> WebSocketClientStream<S> {
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

impl<S: Read + Write> Read for WebSocketClientStream<S> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.buffer.is_empty() {
            match read_server_frame(&mut self.stream)? {
                WebSocketFrame::Data(data) => self.buffer = data,
                WebSocketFrame::Ping(data) => {
                    self.stream
                        .write_all(&client_frame_bytes(OPCODE_PONG, &data))?;
                    self.stream.flush()?;
                }
                WebSocketFrame::Pong => {}
                WebSocketFrame::Close => return Ok(0),
            }
        }

        let len = output.len().min(self.buffer.len());
        output[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);
        Ok(len)
    }
}

impl<S: Write> Write for WebSocketClientStream<S> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        self.stream
            .write_all(&client_frame_bytes(OPCODE_BINARY, input))?;
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

enum WebSocketFrame {
    Data(Vec<u8>),
    Ping(Vec<u8>),
    Pong,
    Close,
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
        "websocket upgrade header too large",
    ))
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
                "websocket path does not match inbound transport path",
            ));
        }
    }
    Ok(())
}

fn forwarded_client_ip(request: &str) -> Option<IpAddr> {
    header_value(request, "x-forwarded-for")
        .and_then(first_forwarded_for_ip)
        .or_else(|| header_value(request, "cf-connecting-ip").and_then(parse_header_ip))
        .or_else(|| header_value(request, "true-client-ip").and_then(parse_header_ip))
        .or_else(|| header_value(request, "x-real-ip").and_then(parse_header_ip))
}

fn websocket_early_data(request: &str) -> (Option<String>, Vec<u8>) {
    let Some(protocol) = header_value(request, "sec-websocket-protocol") else {
        return (None, Vec::new());
    };
    let protocol = protocol.trim();
    if protocol.is_empty() {
        return (None, Vec::new());
    }
    let encoded = protocol
        .replace('+', "-")
        .replace('/', "_")
        .replace('=', "");
    match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded.as_bytes()) {
        Ok(data) if !data.is_empty() => (Some(protocol.to_string()), data),
        _ => (None, Vec::new()),
    }
}

fn first_forwarded_for_ip(value: &str) -> Option<IpAddr> {
    value.split(',').find_map(parse_header_ip)
}

fn header_value<'a>(request: &'a str, header_name: &str) -> Option<&'a str> {
    request.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case(header_name) {
            Some(value.trim())
        } else {
            None
        }
    })
}

fn parse_header_ip(value: &str) -> Option<IpAddr> {
    value.trim().trim_matches('"').parse().ok()
}

fn parse_upgrade_request(request: &str) -> io::Result<(&str, &str)> {
    let mut lines = request.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default();
    let path = request_parts.next().unwrap_or_default();
    if !method.eq_ignore_ascii_case("GET") || path.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid websocket request line",
        ));
    }

    let mut upgrade = false;
    let mut connection_upgrade = false;
    let mut key = None;
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
        } else if name.eq_ignore_ascii_case("sec-websocket-key") {
            key = Some(value);
        }
    }

    match (upgrade, connection_upgrade, key) {
        (true, true, Some(key)) => Ok((path, key)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing websocket upgrade headers",
        )),
    }
}

fn validate_client_upgrade_response(response: &str, key: &str) -> io::Result<()> {
    let mut lines = response.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if !status.contains(" 101 ") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket outbound upgrade failed",
        ));
    }
    let expected_accept = websocket_accept_key(key);
    let mut upgrade = false;
    let mut connection_upgrade = false;
    let mut accept_matches = false;
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
        } else if name.eq_ignore_ascii_case("sec-websocket-accept") && value == expected_accept {
            accept_matches = true;
        }
    }
    if upgrade && connection_upgrade && accept_matches {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "websocket outbound upgrade response is invalid",
    ))
}

fn websocket_accept_key(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WEBSOCKET_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

fn read_server_frame<R: Read>(reader: &mut R) -> io::Result<WebSocketFrame> {
    let mut header = [0u8; 2];
    reader.read_exact(&mut header)?;
    let fin = header[0] & 0x80 != 0;
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    if masked {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server websocket frame must not be masked",
        ));
    }

    let mut len = u64::from(header[1] & 0x7f);
    if len == 126 {
        let mut extended = [0u8; 2];
        reader.read_exact(&mut extended)?;
        len = u64::from(u16::from_be_bytes(extended));
    } else if len == 127 {
        let mut extended = [0u8; 8];
        reader.read_exact(&mut extended)?;
        len = u64::from_be_bytes(extended);
    }
    if len > MAX_HTTP_HEADER as u64 * 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket frame too large",
        ));
    }

    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload)?;

    match opcode {
        OPCODE_BINARY | OPCODE_CONTINUATION if fin => Ok(WebSocketFrame::Data(payload)),
        OPCODE_PING => Ok(WebSocketFrame::Ping(payload)),
        OPCODE_PONG => Ok(WebSocketFrame::Pong),
        OPCODE_CLOSE => Ok(WebSocketFrame::Close),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported websocket frame",
        )),
    }
}

fn read_frame(reader: &mut TcpStream) -> io::Result<WebSocketFrame> {
    let mut header = [0u8; 2];
    reader.read_exact(&mut header)?;
    let fin = header[0] & 0x80 != 0;
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    if !masked {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client websocket frame must be masked",
        ));
    }

    let mut len = u64::from(header[1] & 0x7f);
    if len == 126 {
        let mut extended = [0u8; 2];
        reader.read_exact(&mut extended)?;
        len = u64::from(u16::from_be_bytes(extended));
    } else if len == 127 {
        let mut extended = [0u8; 8];
        reader.read_exact(&mut extended)?;
        len = u64::from_be_bytes(extended);
    }
    if len > MAX_HTTP_HEADER as u64 * 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket frame too large",
        ));
    }

    let mut mask = [0u8; 4];
    reader.read_exact(&mut mask)?;
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload)?;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }

    match opcode {
        OPCODE_BINARY | OPCODE_CONTINUATION if fin => Ok(WebSocketFrame::Data(payload)),
        OPCODE_PING => Ok(WebSocketFrame::Ping(payload)),
        OPCODE_PONG => Ok(WebSocketFrame::Pong),
        OPCODE_CLOSE => Ok(WebSocketFrame::Close),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported websocket frame",
        )),
    }
}

fn parse_buffered_frame(buffer: &mut Vec<u8>) -> io::Result<Option<WebSocketFrame>> {
    if buffer.len() < 2 {
        return Ok(None);
    }
    let fin = buffer[0] & 0x80 != 0;
    let opcode = buffer[0] & 0x0f;
    let masked = buffer[1] & 0x80 != 0;
    if !masked {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client websocket frame must be masked",
        ));
    }

    let mut offset = 2usize;
    let mut len = u64::from(buffer[1] & 0x7f);
    if len == 126 {
        if buffer.len() < offset + 2 {
            return Ok(None);
        }
        len = u64::from(u16::from_be_bytes([buffer[offset], buffer[offset + 1]]));
        offset += 2;
    } else if len == 127 {
        if buffer.len() < offset + 8 {
            return Ok(None);
        }
        len = u64::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
            buffer[offset + 4],
            buffer[offset + 5],
            buffer[offset + 6],
            buffer[offset + 7],
        ]);
        offset += 8;
    }
    if len > MAX_HTTP_HEADER as u64 * 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket frame too large",
        ));
    }
    if buffer.len() < offset + 4 + len as usize {
        return Ok(None);
    }

    let mask = [
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ];
    offset += 4;
    let mut payload = buffer[offset..offset + len as usize].to_vec();
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    buffer.drain(..offset + len as usize);

    match opcode {
        OPCODE_BINARY | OPCODE_CONTINUATION if fin => Ok(Some(WebSocketFrame::Data(payload))),
        OPCODE_PING => Ok(Some(WebSocketFrame::Ping(payload))),
        OPCODE_PONG => Ok(Some(WebSocketFrame::Pong)),
        OPCODE_CLOSE => Ok(Some(WebSocketFrame::Close)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported websocket frame",
        )),
    }
}

fn write_frame(writer: &Arc<Mutex<TcpStream>>, opcode: u8, payload: &[u8]) -> io::Result<()> {
    let mut stream = writer.lock().expect("websocket writer lock poisoned");
    stream.write_all(&frame_bytes(opcode, payload))?;
    stream.flush()
}

fn frame_bytes(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut header = vec![0x80 | opcode];
    if payload.len() < 126 {
        header.push(payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        header.push(126);
        header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        header.push(127);
        header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    header.extend_from_slice(payload);
    header
}

fn client_frame_bytes(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mask = [1u8, 2, 3, 4];
    let mut frame = vec![0x80 | opcode];
    if payload.len() < 126 {
        frame.push(0x80 | payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    for (index, byte) in payload.iter().enumerate() {
        frame.push(*byte ^ mask[index % 4]);
    }
    frame
}

fn write_all_wait(writer: &mut TcpStream, mut input: &[u8]) -> io::Result<()> {
    while !input.is_empty() {
        match writer.write(input) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "socket write returned zero",
                ));
            }
            Ok(written) => input = &input[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    use crate::websocket::{
        accept_websocket, accept_websocket_with_client_ip, websocket_accept_key,
    };

    fn masked_frame(payload: &[u8]) -> Vec<u8> {
        let mask = [1u8, 2, 3, 4];
        let mut frame = vec![0x82, 0x80 | payload.len() as u8];
        frame.extend_from_slice(&mask);
        for (index, byte) in payload.iter().enumerate() {
            frame.push(*byte ^ mask[index % 4]);
        }
        frame
    }

    fn read_http_response(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut byte = [0u8; 1];
        while !bytes.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).expect("response byte");
            bytes.push(byte[0]);
        }
        String::from_utf8(bytes).expect("response utf8")
    }

    #[test]
    fn computes_accept_key() {
        assert_eq!(
            websocket_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn accepts_upgrade_and_reads_binary_frames() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let (mut reader, mut writer) = accept_websocket(stream, Some("/ws")).expect("upgrade");
            let mut payload = [0u8; 4];
            reader.read_exact(&mut payload).expect("payload");
            assert_eq!(&payload, b"ping");
            writer.write_all(b"pong").expect("write");
        });

        let mut client = TcpStream::connect(addr).expect("client");
        client
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            )
            .expect("request");
        let response = read_http_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        client.write_all(&masked_frame(b"ping")).expect("frame");

        let mut header = [0u8; 2];
        client.read_exact(&mut header).expect("frame header");
        assert_eq!(header, [0x82, 0x04]);
        let mut body = [0u8; 4];
        client.read_exact(&mut body).expect("frame body");
        assert_eq!(&body, b"pong");
        server.join().expect("server");
    }

    #[test]
    fn accepts_sec_websocket_protocol_early_data_like_xray() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let (mut reader, _) = accept_websocket(stream, Some("/ws")).expect("upgrade");
            let mut payload = [0u8; 4];
            reader.read_exact(&mut payload).expect("early payload");
            assert_eq!(&payload, b"ping");
        });

        let mut client = TcpStream::connect(addr).expect("client");
        client
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: cGluZw\r\n\r\n",
            )
            .expect("request");
        let response = read_http_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        assert!(response.contains("Sec-WebSocket-Protocol: cGluZw"));
        drop(client);
        server.join().expect("server");
    }

    #[test]
    fn accepts_upgrade_and_uses_forwarded_for_client_ip() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let (_, _, forwarded_ip) =
                accept_websocket_with_client_ip(stream, Some("/ws")).expect("upgrade");
            assert_eq!(forwarded_ip, Some("198.51.100.8".parse().unwrap()));
        });

        let mut client = TcpStream::connect(addr).expect("client");
        client
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nX-Forwarded-For: 198.51.100.8, 203.0.113.9\r\n\r\n",
            )
            .expect("request");
        let response = read_http_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        server.join().expect("server");
    }

    #[test]
    fn websocket_tls_relay_idle_timeout_uses_poll_scale_backoff() {
        let mut idle_rounds = 0u8;
        assert_eq!(
            super::websocket_tls_relay_idle_timeout(&mut idle_rounds),
            Duration::from_millis(25)
        );
        assert_eq!(
            super::websocket_tls_relay_idle_timeout(&mut idle_rounds),
            Duration::from_millis(50)
        );
        assert_eq!(
            super::websocket_tls_relay_idle_timeout(&mut idle_rounds),
            Duration::from_millis(100)
        );
        assert_eq!(
            super::websocket_tls_relay_idle_timeout(&mut idle_rounds),
            Duration::from_millis(250)
        );
        assert_eq!(
            super::websocket_tls_relay_idle_timeout(&mut idle_rounds),
            Duration::from_secs(1)
        );
        assert_eq!(
            super::websocket_tls_relay_idle_timeout(&mut idle_rounds),
            Duration::from_secs(1)
        );
    }
}
