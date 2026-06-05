use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::limits::BandwidthLimiter;
use crate::stream::RelayActivityDeadline;
use crate::tls::{RawTcpStreamAccess, TlsConnection};

const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HTTP_HEADER: usize = 16 * 1024;
const ASYNC_WEBSOCKET_RELAY_BUFFER_SIZE: usize = 6 * 1024;
const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;

pub struct WebSocketReader {
    reader: TcpStream,
    control_writer: Arc<Mutex<TcpStream>>,
    input: Vec<u8>,
    buffer: Vec<u8>,
    assembler: WebSocketMessageAssembler,
}

pub struct WebSocketWriter {
    writer: Arc<Mutex<TcpStream>>,
}

pub struct WebSocketTlsStream {
    stream: TlsConnection,
    input: Vec<u8>,
    buffer: Vec<u8>,
    assembler: WebSocketMessageAssembler,
}

pub(crate) struct AsyncWebSocketStream<S> {
    stream: S,
    input: Vec<u8>,
    buffer: Vec<u8>,
    assembler: WebSocketMessageAssembler,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct WebSocketRelayStats {
    pub upload: u64,
    pub download: u64,
    pub first_byte_ms: Option<u128>,
    pub finish_reason: &'static str,
    pub finish_detail: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WebSocketRelayTimeouts {
    pub connection_idle: Duration,
    pub uplink_only: Duration,
    pub downlink_only: Duration,
}

impl Default for WebSocketRelayTimeouts {
    fn default() -> Self {
        Self {
            connection_idle: Duration::from_secs(120),
            uplink_only: Duration::from_secs(2),
            downlink_only: Duration::from_secs(4),
        }
    }
}

pub struct WebSocketClientStream<S> {
    stream: S,
    input: Vec<u8>,
    buffer: Vec<u8>,
    assembler: WebSocketMessageAssembler,
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
        input: Vec::new(),
        buffer: Vec::new(),
        assembler: WebSocketMessageAssembler::default(),
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
            input: Vec::new(),
            buffer: early_data,
            assembler: WebSocketMessageAssembler::default(),
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
            assembler: WebSocketMessageAssembler::default(),
        },
        forwarded_ip,
    ))
}

pub(crate) async fn accept_websocket_async_with_client_ip<S>(
    mut stream: S,
    expected_path: Option<&str>,
) -> io::Result<(AsyncWebSocketStream<S>, Option<IpAddr>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_http_upgrade_async(&mut stream).await?;
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
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    Ok((
        AsyncWebSocketStream {
            stream,
            input: Vec::new(),
            buffer: early_data,
            assembler: WebSocketMessageAssembler::default(),
        },
        forwarded_ip,
    ))
}

pub fn relay_websocket_tls_stream(
    client: WebSocketTlsStream,
    remote: TcpStream,
    limiter: Option<Arc<BandwidthLimiter>>,
) -> io::Result<(u64, u64)> {
    let stats = relay_websocket_tls_stream_stats(
        client,
        remote,
        limiter,
        WebSocketRelayTimeouts::default(),
        None,
    )?;
    Ok((stats.upload, stats.download))
}

pub(crate) fn relay_websocket_tls_stream_stats(
    mut client: WebSocketTlsStream,
    mut remote: TcpStream,
    limiter: Option<Arc<BandwidthLimiter>>,
    timeouts: WebSocketRelayTimeouts,
    mut upload_observer: Option<&mut dyn FnMut(&[u8])>,
) -> io::Result<WebSocketRelayStats> {
    client.set_nonblocking(true)?;
    remote.set_nonblocking(true)?;

    let started = Instant::now();
    let mut stats = WebSocketRelayStats::default();
    stats.finish_reason = "completed";
    let mut upload_done = false;
    let mut download_done = false;
    let mut client_buffer = [0u8; ASYNC_WEBSOCKET_RELAY_BUFFER_SIZE];
    let mut remote_buffer = [0u8; ASYNC_WEBSOCKET_RELAY_BUFFER_SIZE];
    let mut idle_rounds = 0u8;
    let mut activity_deadline = RelayActivityDeadline::new();

    while !upload_done || !download_done {
        let mut progressed = false;

        let idle_limit = websocket_relay_idle_limit(&timeouts, upload_done, download_done);
        let idle_elapsed = activity_deadline.elapsed(upload_done, download_done);
        if idle_elapsed >= idle_limit {
            stats.finish_reason = websocket_relay_timeout_reason(upload_done, download_done);
            upload_done = true;
            download_done = true;
            shutdown_websocket_tls_pair(&mut client, &remote);
            continue;
        }

        if !upload_done {
            match client.read(&mut client_buffer) {
                Ok(0) => {
                    upload_done = true;
                    remember_websocket_finish_reason(&mut stats, "client_eof");
                    let _ = remote.shutdown(Shutdown::Write);
                    progressed = true;
                }
                Ok(read) => {
                    if let Some(observer) = upload_observer.as_deref_mut() {
                        observer(&client_buffer[..read]);
                    }
                    if let Some(limiter) = limiter.as_deref() {
                        if !limiter.wait_for(read) {
                            upload_done = true;
                            download_done = true;
                            stats.finish_reason = "bandwidth_limiter_closed";
                            shutdown_websocket_tls_pair(&mut client, &remote);
                            continue;
                        }
                    }
                    write_all_wait(&mut remote, &client_buffer[..read])?;
                    stats.upload = stats.upload.saturating_add(read as u64);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    upload_done = true;
                    download_done = true;
                    remember_websocket_finish_reason(&mut stats, "client_read_error");
                    stats.finish_detail = Some(websocket_finish_detail("client_read", &error));
                    shutdown_websocket_tls_pair(&mut client, &remote);
                    progressed = true;
                }
            }
        }

        if !download_done {
            match remote.read(&mut remote_buffer) {
                Ok(0) => {
                    download_done = true;
                    remember_websocket_finish_reason(&mut stats, "remote_eof");
                    progressed = true;
                }
                Ok(read) => {
                    if stats.first_byte_ms.is_none() {
                        stats.first_byte_ms = Some(started.elapsed().as_millis());
                    }
                    client.write_binary_wait(&remote_buffer[..read])?;
                    stats.download = stats.download.saturating_add(read as u64);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    download_done = true;
                    upload_done = true;
                    remember_websocket_finish_reason(&mut stats, "remote_read_error");
                    stats.finish_detail = Some(websocket_finish_detail("remote_read", &error));
                    shutdown_websocket_tls_pair(&mut client, &remote);
                    progressed = true;
                }
            }
        }

        if !progressed {
            let idle_limit = websocket_relay_idle_limit(&timeouts, upload_done, download_done);
            let idle_elapsed = activity_deadline.elapsed(upload_done, download_done);
            if idle_elapsed >= idle_limit {
                stats.finish_reason = websocket_relay_timeout_reason(upload_done, download_done);
                upload_done = true;
                download_done = true;
                shutdown_websocket_tls_pair(&mut client, &remote);
                continue;
            }
            let timeout = websocket_tls_relay_idle_timeout(&mut idle_rounds);
            client.wait_readable_with_remote(
                &remote,
                !upload_done,
                !download_done,
                timeout.min(idle_limit.saturating_sub(idle_elapsed)),
            )?;
        } else {
            idle_rounds = 0;
            activity_deadline.note_progress(upload_done, download_done);
        }
    }

    Ok(stats)
}

pub(crate) async fn relay_websocket_async_stream_stats<S>(
    mut client: AsyncWebSocketStream<S>,
    mut remote: tokio::net::TcpStream,
    limiter: Option<Arc<BandwidthLimiter>>,
    timeouts: WebSocketRelayTimeouts,
) -> io::Result<WebSocketRelayStats>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    let mut stats = WebSocketRelayStats {
        finish_reason: "completed",
        ..WebSocketRelayStats::default()
    };
    let mut upload_done = false;
    let mut download_done = false;
    let mut client_buffer = [0u8; 16 * 1024];
    let mut remote_buffer = [0u8; 16 * 1024];
    let mut activity_deadline = RelayActivityDeadline::new();

    while !upload_done || !download_done {
        if limiter
            .as_deref()
            .map(BandwidthLimiter::is_revoked)
            .unwrap_or(false)
        {
            stats.finish_reason = "bandwidth_limiter_closed";
            let _ = client.shutdown().await;
            let _ = remote.shutdown().await;
            break;
        }

        let idle_limit = websocket_relay_idle_limit(&timeouts, upload_done, download_done);
        let idle_elapsed = activity_deadline.elapsed(upload_done, download_done);
        if idle_elapsed >= idle_limit {
            stats.finish_reason = websocket_relay_timeout_reason(upload_done, download_done);
            let _ = client.shutdown().await;
            let _ = remote.shutdown().await;
            break;
        }
        let idle_left = idle_limit.saturating_sub(idle_elapsed);

        tokio::select! {
            result = client.read_data(&mut client_buffer), if !upload_done => {
                match result {
                    Ok(0) => {
                        upload_done = true;
                        remember_websocket_finish_reason(&mut stats, "client_eof");
                        let _ = remote.shutdown().await;
                    }
                    Ok(read) => {
                        if let Some(limiter) = limiter.as_deref() {
                            if !limiter.wait_for_async(read).await {
                                upload_done = true;
                                download_done = true;
                                stats.finish_reason = "bandwidth_limiter_closed";
                                let _ = client.shutdown().await;
                                let _ = remote.shutdown().await;
                                continue;
                            }
                        }
                        remote.write_all(&client_buffer[..read]).await?;
                        stats.upload = stats.upload.saturating_add(read as u64);
                    }
                    Err(error) => {
                        upload_done = true;
                        download_done = true;
                        remember_websocket_finish_reason(&mut stats, "client_read_error");
                        stats.finish_detail = Some(websocket_finish_detail("client_read", &error));
                        let _ = client.shutdown().await;
                        let _ = remote.shutdown().await;
                    }
                }
                activity_deadline.note_progress(upload_done, download_done);
            }
            result = remote.read(&mut remote_buffer), if !download_done => {
                match result {
                    Ok(0) => {
                        download_done = true;
                        remember_websocket_finish_reason(&mut stats, "remote_eof");
                    }
                    Ok(read) => {
                        if stats.first_byte_ms.is_none() {
                            stats.first_byte_ms = Some(started.elapsed().as_millis());
                        }
                        client.write_binary_all(&remote_buffer[..read]).await?;
                        stats.download = stats.download.saturating_add(read as u64);
                    }
                    Err(error) => {
                        download_done = true;
                        upload_done = true;
                        remember_websocket_finish_reason(&mut stats, "remote_read_error");
                        stats.finish_detail = Some(websocket_finish_detail("remote_read", &error));
                        let _ = client.shutdown().await;
                        let _ = remote.shutdown().await;
                    }
                }
                activity_deadline.note_progress(upload_done, download_done);
            }
            _ = tokio::time::sleep(idle_left) => {
                stats.finish_reason = websocket_relay_timeout_reason(upload_done, download_done);
                let _ = client.shutdown().await;
                let _ = remote.shutdown().await;
                break;
            }
        }
    }

    Ok(stats)
}

fn remember_websocket_finish_reason(stats: &mut WebSocketRelayStats, reason: &'static str) {
    if stats.finish_reason == "completed" {
        stats.finish_reason = reason;
    }
}

fn websocket_finish_detail(context: &str, error: &io::Error) -> String {
    format!("{context}:{:?}:{}", error.kind(), error)
}

fn shutdown_websocket_tls_pair(client: &mut WebSocketTlsStream, remote: &TcpStream) {
    let _ = client.shutdown();
    let _ = remote.shutdown(Shutdown::Both);
}

impl WebSocketReader {
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.reader.set_read_timeout(timeout)
    }

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.reader.set_nonblocking(nonblocking)
    }

    pub(crate) fn shutdown(&self) -> io::Result<()> {
        self.reader.shutdown(Shutdown::Both)
    }

    pub(crate) fn wait_readable_with_remote(
        &self,
        remote: &TcpStream,
        wait_client: bool,
        wait_remote: bool,
        timeout: Duration,
    ) -> io::Result<()> {
        if wait_client && !self.buffer.is_empty() {
            return Ok(());
        }
        self.reader
            .wait_readable_with(remote, wait_client, wait_remote, timeout)
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
        let mut stream = self.writer.lock().expect("websocket writer lock poisoned");
        let close_result = stream
            .write_all(&frame_bytes(OPCODE_CLOSE, &[]))
            .and_then(|_| stream.flush());
        let shutdown_result = stream.shutdown(Shutdown::Both);
        close_result.or(shutdown_result)
    }
}

impl Read for WebSocketReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.buffer.is_empty() {
            if let Some(frame) = parse_buffered_frame(&mut self.input, &mut self.assembler)? {
                match frame {
                    WebSocketFrame::Data(data) => self.buffer = data,
                    WebSocketFrame::Ping(data) => {
                        write_frame(&self.control_writer, OPCODE_PONG, &data)?;
                    }
                    WebSocketFrame::Pong => {}
                    WebSocketFrame::Close => return Ok(0),
                }
                continue;
            }

            let mut input = [0u8; 8 * 1024];
            match self.reader.read(&mut input) {
                Ok(0) => return Ok(0),
                Ok(read) => self.input.extend_from_slice(&input[..read]),
                Err(error) => return Err(error),
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
    pub(crate) fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_io_timeout(timeout)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.stream.set_nonblocking(nonblocking)
    }

    fn write_binary_wait(&mut self, payload: &[u8]) -> io::Result<()> {
        let (header, header_len) = server_frame_header(OPCODE_BINARY, payload.len());
        self.stream
            .write_plain_chunks_all_wait(&[&header[..header_len], payload])
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

    pub(crate) fn wait_readable_with_udp(
        &self,
        udp_v4: Option<&UdpSocket>,
        udp_v6: Option<&UdpSocket>,
        timeout: Duration,
    ) -> io::Result<()> {
        if !self.buffer.is_empty() {
            return Ok(());
        }
        self.stream
            .wait_raw_readable_with_udp(udp_v4, udp_v6, true, timeout)
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

pub(crate) fn websocket_relay_idle_limit(
    timeouts: &WebSocketRelayTimeouts,
    upload_done: bool,
    download_done: bool,
) -> Duration {
    if upload_done && !download_done {
        timeouts.downlink_only
    } else if download_done && !upload_done {
        timeouts.uplink_only
    } else {
        timeouts.connection_idle
    }
}

pub(crate) fn websocket_relay_timeout_reason(
    upload_done: bool,
    download_done: bool,
) -> &'static str {
    if upload_done && !download_done {
        "downlink_only_timeout"
    } else if !upload_done && download_done {
        "uplink_only_timeout"
    } else {
        "connection_idle_timeout"
    }
}

impl Read for WebSocketTlsStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.buffer.is_empty() {
            if let Some(frame) = parse_buffered_frame(&mut self.input, &mut self.assembler)? {
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

impl<S> AsyncWebSocketStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) async fn read_data(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.buffer.is_empty() {
            if let Some(frame) = parse_buffered_frame(&mut self.input, &mut self.assembler)? {
                match frame {
                    WebSocketFrame::Data(data) => self.buffer = data,
                    WebSocketFrame::Ping(data) => {
                        self.stream
                            .write_all(&frame_bytes(OPCODE_PONG, &data))
                            .await?;
                        self.stream.flush().await?;
                    }
                    WebSocketFrame::Pong => {}
                    WebSocketFrame::Close => return Ok(0),
                }
                continue;
            }

            let mut input = [0u8; 8 * 1024];
            match self.stream.read(&mut input).await {
                Ok(0) => return Ok(0),
                Ok(read) => self.input.extend_from_slice(&input[..read]),
                Err(error) => return Err(error),
            }
        }

        let len = output.len().min(self.buffer.len());
        output[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);
        Ok(len)
    }

    pub(crate) async fn write_binary_all(&mut self, payload: &[u8]) -> io::Result<()> {
        let (header, header_len) = server_frame_header(OPCODE_BINARY, payload.len());
        self.stream.write_all(&header[..header_len]).await?;
        self.stream.write_all(payload).await?;
        self.stream.flush().await
    }

    pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
        let close_result = async {
            self.stream
                .write_all(&frame_bytes(OPCODE_CLOSE, &[]))
                .await?;
            self.stream.flush().await
        }
        .await;
        let shutdown_result = self.stream.shutdown().await;
        close_result.or(shutdown_result)
    }
}

impl<S: Read + Write> Read for WebSocketClientStream<S> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.buffer.is_empty() {
            if let Some(frame) =
                parse_buffered_frame_with_mask(&mut self.input, &mut self.assembler, false)?
            {
                match frame {
                    WebSocketFrame::Data(data) => self.buffer = data,
                    WebSocketFrame::Ping(data) => {
                        self.stream
                            .write_all(&client_frame_bytes(OPCODE_PONG, &data))?;
                        self.stream.flush()?;
                    }
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

struct RawWebSocketFrame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

#[derive(Default)]
struct WebSocketMessageAssembler {
    fragmented: bool,
}

impl WebSocketMessageAssembler {
    fn accept(&mut self, frame: RawWebSocketFrame) -> io::Result<Option<WebSocketFrame>> {
        match frame.opcode {
            OPCODE_TEXT | OPCODE_BINARY => {
                if self.fragmented {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "websocket data frame started before previous fragmented message ended",
                    ));
                }
                if frame.fin {
                    Ok(Some(WebSocketFrame::Data(frame.payload)))
                } else {
                    self.fragmented = true;
                    Ok(Some(WebSocketFrame::Data(frame.payload)))
                }
            }
            OPCODE_CONTINUATION => {
                if !self.fragmented {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "websocket continuation frame without fragmented message",
                    ));
                }
                if frame.fin {
                    self.fragmented = false;
                }
                Ok(Some(WebSocketFrame::Data(frame.payload)))
            }
            OPCODE_PING => {
                validate_control_frame(&frame)?;
                Ok(Some(WebSocketFrame::Ping(frame.payload)))
            }
            OPCODE_PONG => {
                validate_control_frame(&frame)?;
                Ok(Some(WebSocketFrame::Pong))
            }
            OPCODE_CLOSE => {
                validate_control_frame(&frame)?;
                self.fragmented = false;
                Ok(Some(WebSocketFrame::Close))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported websocket frame",
            )),
        }
    }
}

fn validate_control_frame(frame: &RawWebSocketFrame) -> io::Result<()> {
    if !frame.fin {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket control frame must not be fragmented",
        ));
    }
    if frame.payload.len() > 125 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket control frame too large",
        ));
    }
    Ok(())
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

async fn read_http_upgrade_async<S>(stream: &mut S) -> io::Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while bytes.len() < MAX_HTTP_HEADER {
        stream.read_exact(&mut byte).await?;
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
        .map(normalize_websocket_path)
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

fn normalize_websocket_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
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

fn parse_buffered_frame(
    buffer: &mut Vec<u8>,
    assembler: &mut WebSocketMessageAssembler,
) -> io::Result<Option<WebSocketFrame>> {
    parse_buffered_frame_with_mask(buffer, assembler, true)
}

fn parse_buffered_frame_with_mask(
    buffer: &mut Vec<u8>,
    assembler: &mut WebSocketMessageAssembler,
    expect_masked: bool,
) -> io::Result<Option<WebSocketFrame>> {
    while let Some(raw) = parse_buffered_raw_frame(buffer, expect_masked)? {
        if let Some(frame) = assembler.accept(raw)? {
            return Ok(Some(frame));
        }
    }
    Ok(None)
}

fn parse_buffered_raw_frame(
    buffer: &mut Vec<u8>,
    expect_masked: bool,
) -> io::Result<Option<RawWebSocketFrame>> {
    if buffer.len() < 2 {
        return Ok(None);
    }
    let fin = buffer[0] & 0x80 != 0;
    let opcode = buffer[0] & 0x0f;
    let masked = buffer[1] & 0x80 != 0;
    if expect_masked && !masked {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client websocket frame must be masked",
        ));
    }
    if !expect_masked && masked {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server websocket frame must not be masked",
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
    let mask_len = if masked { 4 } else { 0 };
    if buffer.len() < offset + mask_len + len as usize {
        return Ok(None);
    }

    let mask = if masked {
        let mask = [
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ];
        offset += 4;
        Some(mask)
    } else {
        None
    };
    let mut payload = buffer[offset..offset + len as usize].to_vec();
    if let Some(mask) = mask {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    buffer.drain(..offset + len as usize);

    Ok(Some(RawWebSocketFrame {
        fin,
        opcode,
        payload,
    }))
}

fn write_frame(writer: &Arc<Mutex<TcpStream>>, opcode: u8, payload: &[u8]) -> io::Result<()> {
    let mut stream = writer.lock().expect("websocket writer lock poisoned");
    let (header, header_len) = server_frame_header(opcode, payload.len());
    stream.write_all(&header[..header_len])?;
    stream.write_all(payload)?;
    stream.flush()
}

fn server_frame_header(opcode: u8, payload_len: usize) -> ([u8; 10], usize) {
    let mut header = [0u8; 10];
    header[0] = 0x80 | opcode;
    if payload_len < 126 {
        header[1] = payload_len as u8;
        (header, 2)
    } else if payload_len <= u16::MAX as usize {
        header[1] = 126;
        header[2..4].copy_from_slice(&(payload_len as u16).to_be_bytes());
        (header, 4)
    } else {
        header[1] = 127;
        header[2..10].copy_from_slice(&(payload_len as u64).to_be_bytes());
        (header, 10)
    }
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
    use std::time::{Duration, Instant};

    use crate::websocket::{
        accept_websocket, accept_websocket_with_client_ip, connect_websocket_client,
        websocket_accept_key,
    };

    #[test]
    fn server_frame_header_matches_allocated_frame_encoding() {
        for payload_len in [
            0usize,
            1,
            125,
            126,
            u16::MAX as usize,
            u16::MAX as usize + 1,
        ] {
            let payload = vec![0x5a; payload_len];
            let frame = super::frame_bytes(super::OPCODE_BINARY, &payload);
            let (header, header_len) =
                super::server_frame_header(super::OPCODE_BINARY, payload.len());

            assert_eq!(&frame[..header_len], &header[..header_len]);
            assert_eq!(&frame[header_len..], payload);
        }
    }

    fn masked_frame_with(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mask = [1u8, 2, 3, 4];
        let mut frame = vec![
            (if fin { 0x80 } else { 0x00 }) | opcode,
            0x80 | payload.len() as u8,
        ];
        frame.extend_from_slice(&mask);
        for (index, byte) in payload.iter().enumerate() {
            frame.push(*byte ^ mask[index % 4]);
        }
        frame
    }

    fn masked_frame(payload: &[u8]) -> Vec<u8> {
        masked_frame_with(true, 0x2, payload)
    }

    fn server_frame_with(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![
            (if fin { 0x80 } else { 0x00 }) | opcode,
            payload.len() as u8,
        ];
        frame.extend_from_slice(payload);
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
    fn accepts_upgrade_path_without_leading_slash_like_go() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            accept_websocket(stream, Some("ws")).expect("upgrade");
        });

        let mut client = TcpStream::connect(addr).expect("client");
        client
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            )
            .expect("request");
        let response = read_http_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        server.join().expect("server");
    }

    #[test]
    fn accepts_fragmented_binary_message_like_gorilla() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let (mut reader, _) = accept_websocket(stream, Some("/ws")).expect("upgrade");
            let mut payload = [0u8; 4];
            reader.read_exact(&mut payload).expect("fragmented payload");
            assert_eq!(&payload, b"ping");
        });

        let mut client = TcpStream::connect(addr).expect("client");
        client
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            )
            .expect("request");
        let response = read_http_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        client
            .write_all(&masked_frame_with(false, 0x2, b"pi"))
            .expect("first fragment");
        client
            .write_all(&masked_frame_with(true, 0x0, b"ng"))
            .expect("last fragment");
        server.join().expect("server");
    }

    #[test]
    fn streams_fragmented_binary_before_final_fragment_like_gorilla() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let (mut reader, _) = accept_websocket(stream, Some("/ws")).expect("upgrade");
            reader
                .set_read_timeout(Some(Duration::from_millis(200)))
                .expect("read timeout");
            let mut first = [0u8; 2];
            reader
                .read_exact(&mut first)
                .expect("first fragment before final continuation");
            assert_eq!(&first, b"pi");
        });

        let mut client = TcpStream::connect(addr).expect("client");
        client
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            )
            .expect("request");
        let response = read_http_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        client
            .write_all(&masked_frame_with(false, 0x2, b"pi"))
            .expect("first fragment");
        thread::sleep(Duration::from_millis(350));
        let _ = client.write_all(&masked_frame_with(true, 0x0, b"ng"));
        server.join().expect("server");
    }

    #[test]
    fn accepts_text_message_payload_like_gorilla() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let (mut reader, _) = accept_websocket(stream, Some("/ws")).expect("upgrade");
            let mut payload = [0u8; 4];
            reader.read_exact(&mut payload).expect("text frame payload");
            assert_eq!(&payload, b"ping");
        });

        let mut client = TcpStream::connect(addr).expect("client");
        client
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            )
            .expect("request");
        let response = read_http_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        client
            .write_all(&masked_frame_with(true, 0x1, b"ping"))
            .expect("text frame");
        server.join().expect("server");
    }

    #[test]
    fn server_reader_ignores_pong_control_frames_like_gorilla() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let (mut reader, _) = accept_websocket(stream, Some("/ws")).expect("upgrade");
            let mut payload = [0u8; 4];
            reader
                .read_exact(&mut payload)
                .expect("payload after pong control frame");
            assert_eq!(&payload, b"ping");
        });

        let mut client = TcpStream::connect(addr).expect("client");
        client
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            )
            .expect("request");
        let response = read_http_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        client
            .write_all(&masked_frame_with(true, 0xA, b"keepalive"))
            .expect("pong frame");
        client
            .write_all(&masked_frame(b"ping"))
            .expect("data frame");
        server.join().expect("server");
    }

    #[test]
    fn plain_reader_waits_for_client_or_remote_readiness_without_spin_polling() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let remote_listener = TcpListener::bind("127.0.0.1:0").expect("remote bind");
        let remote_addr = remote_listener.local_addr().expect("remote addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let (reader, _) = accept_websocket(stream, Some("/ws")).expect("upgrade");
            let remote_client = TcpStream::connect(remote_addr).expect("remote client");
            let (remote, _) = remote_listener.accept().expect("remote accept");
            let delayed = thread::spawn(move || {
                thread::sleep(Duration::from_millis(120));
                (&remote_client)
                    .write_all(b"wake")
                    .expect("wake remote readable");
            });

            reader.set_nonblocking(true).expect("reader nonblocking");
            let started = Instant::now();
            reader
                .wait_readable_with_remote(&remote, true, true, Duration::from_secs(1))
                .expect("wait readable");
            let elapsed = started.elapsed();
            if cfg!(unix) {
                assert!(elapsed >= Duration::from_millis(80));
                assert!(elapsed < Duration::from_millis(800));
            } else {
                assert!(elapsed < Duration::from_millis(200));
            }
            delayed.join().expect("delayed writer");
        });

        let mut client = TcpStream::connect(addr).expect("client");
        client
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            )
            .expect("request");
        let response = read_http_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        server.join().expect("server");
    }

    #[test]
    fn client_reads_fragmented_server_binary_message_like_gorilla() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let request = read_http_response(&mut stream);
            assert!(request.contains("GET /ws HTTP/1.1"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                )
                .expect("response");
            stream
                .write_all(&server_frame_with(false, 0x2, b"po"))
                .expect("first fragment");
            stream
                .write_all(&server_frame_with(true, 0x0, b"ng"))
                .expect("last fragment");
        });

        let client = TcpStream::connect(addr).expect("client");
        let mut ws =
            connect_websocket_client(client, Some("/ws"), "example.test").expect("upgrade");
        let mut payload = [0u8; 4];
        ws.read_exact(&mut payload).expect("fragmented payload");
        assert_eq!(&payload, b"pong");
        server.join().expect("server");
    }

    #[test]
    fn client_nonblocking_read_preserves_partial_server_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let request = read_http_response(&mut stream);
            assert!(request.contains("GET /ws HTTP/1.1"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                )
                .expect("response");
            let frame = server_frame_with(true, 0x2, b"pong");
            stream.write_all(&frame[..2]).expect("frame header");
            stream.flush().expect("flush header");
            thread::sleep(Duration::from_millis(100));
            stream.write_all(&frame[2..]).expect("frame body");
            stream.flush().expect("flush body");
        });

        let client = TcpStream::connect(addr).expect("client");
        let mut ws =
            connect_websocket_client(client, Some("/ws"), "example.test").expect("upgrade");
        ws.get_mut().set_nonblocking(true).expect("nonblocking");
        let mut payload = [0u8; 4];
        let mut read = 0usize;
        let deadline = Instant::now() + Duration::from_secs(1);
        while read < payload.len() && Instant::now() < deadline {
            match ws.read(&mut payload[read..]) {
                Ok(0) => break,
                Ok(n) => read += n,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("read websocket frame: {error}"),
            }
        }

        assert_eq!(read, payload.len());
        assert_eq!(&payload, b"pong");
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

    #[test]
    fn websocket_relay_idle_limit_matches_go_after_one_side_finishes() {
        let timeouts = super::WebSocketRelayTimeouts {
            connection_idle: Duration::from_secs(120),
            uplink_only: Duration::from_secs(2),
            downlink_only: Duration::from_secs(4),
        };

        assert_eq!(
            super::websocket_relay_idle_limit(&timeouts, false, false),
            Duration::from_secs(120)
        );
        assert_eq!(
            super::websocket_relay_idle_limit(&timeouts, true, false),
            Duration::from_secs(4)
        );
        assert_eq!(
            super::websocket_relay_idle_limit(&timeouts, false, true),
            Duration::from_secs(2)
        );
    }
}
