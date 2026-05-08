use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use base64::Engine;
use sha1::{Digest, Sha1};

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

pub fn accept_websocket(
    mut stream: TcpStream,
    expected_path: Option<&str>,
) -> io::Result<(WebSocketReader, WebSocketWriter)> {
    let request = read_http_upgrade(&mut stream)?;
    let (path, key) = parse_upgrade_request(&request)?;
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

    let accept = websocket_accept_key(key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream.write_all(response.as_bytes())?;

    let control_writer = Arc::new(Mutex::new(stream.try_clone()?));
    Ok((
        WebSocketReader {
            reader: stream,
            control_writer: control_writer.clone(),
            buffer: Vec::new(),
        },
        WebSocketWriter {
            writer: control_writer,
        },
    ))
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

enum WebSocketFrame {
    Data(Vec<u8>),
    Ping(Vec<u8>),
    Pong,
    Close,
}

fn read_http_upgrade(stream: &mut TcpStream) -> io::Result<String> {
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

fn websocket_accept_key(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WEBSOCKET_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
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

fn write_frame(writer: &Arc<Mutex<TcpStream>>, opcode: u8, payload: &[u8]) -> io::Result<()> {
    let mut stream = writer.lock().expect("websocket writer lock poisoned");
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
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use crate::websocket::{accept_websocket, websocket_accept_key};

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
}
