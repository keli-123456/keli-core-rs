use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::net::Ipv6Addr;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use bytes::Bytes;
use h2::RecvStream;
use http::{HeaderMap, Request, Response, StatusCode};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio_rustls::{TlsAcceptor as TokioTlsAcceptor, TlsConnector};

use crate::config::OutboundTlsConfig;
use crate::socks5::SocksTarget;
use crate::stream::spawn_background_io;
use crate::tls::server_config_from_files;

const DEFAULT_SERVICE_NAME: &str = "GunService";
const MAX_GRPC_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrpcTlsConfig {
    pub cert_file: String,
    pub key_file: String,
    pub server_name: String,
    pub alpn: Vec<String>,
    pub reject_unknown_sni: bool,
}

pub type GrpcStreamHandler = Arc<dyn Fn(GrpcHunkReader, GrpcHunkWriter) + Send + Sync + 'static>;

pub struct GrpcHunkReader {
    rx: mpsc::Receiver<Vec<u8>>,
    buffer: Vec<u8>,
}

#[derive(Clone)]
pub struct GrpcHunkWriter {
    tx: UnboundedSender<Vec<u8>>,
}

pub(crate) struct GrpcClientStream {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: UnboundedSender<Vec<u8>>,
    buffer: Vec<u8>,
    nonblocking: bool,
}

pub async fn run_grpc_listener(
    listener: TcpListener,
    stop: Arc<std::sync::atomic::AtomicBool>,
    service_name: String,
    tls: Option<GrpcTlsConfig>,
    handler: GrpcStreamHandler,
) -> io::Result<()> {
    let tls_acceptor = tls.map(tokio_tls_acceptor).transpose()?;
    let path = Arc::new(grpc_tun_path(&service_name));

    loop {
        if stop.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }

        tokio::select! {
            result = listener.accept() => {
                let Ok((stream, _)) = result else {
                    if stop.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    continue;
                };
                let path = path.clone();
                let handler = handler.clone();
                let tls_acceptor = tls_acceptor.clone();
                tokio::spawn(async move {
                    let result = if let Some(acceptor) = tls_acceptor {
                        match acceptor.accept(stream).await {
                            Ok(stream) => serve_h2_connection(stream, path, handler).await,
                            Err(error) => Err(io_other(error)),
                        }
                    } else {
                        serve_h2_connection(stream, path, handler).await
                    };
                    let _ = result;
                });
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }

    Ok(())
}

pub(crate) fn connect_grpc_client(
    server: &SocksTarget,
    timeout: Duration,
    tls: Option<&OutboundTlsConfig>,
    service_name: Option<&str>,
    host: &str,
) -> io::Result<GrpcClientStream> {
    let (ready_tx, ready_rx) = mpsc::channel();
    let (input_tx, input_rx) = mpsc::channel();
    let (output_tx, output_rx) = unbounded_channel();
    let server = server.clone();
    let tls = tls.cloned();
    let service_name = service_name.unwrap_or(DEFAULT_SERVICE_NAME).to_string();
    let host = host.trim().trim_matches(['[', ']']).to_string();

    spawn_background_io(async move {
        let result = run_grpc_client(
            server,
            timeout,
            tls,
            service_name,
            host,
            input_tx,
            output_rx,
            ready_tx.clone(),
        )
        .await;
        if let Err(error) = result {
            let _ = ready_tx.send(Err(error));
        }
    })?;

    match ready_rx.recv_timeout(timeout) {
        Ok(Ok(())) => Ok(GrpcClientStream::new(input_rx, output_tx)),
        Ok(Err(error)) => Err(error),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "grpc outbound handshake timed out",
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "grpc outbound worker exited before handshake",
        )),
    }
}

async fn run_grpc_client(
    server: SocksTarget,
    timeout: Duration,
    tls: Option<OutboundTlsConfig>,
    service_name: String,
    host: String,
    input_tx: mpsc::Sender<Vec<u8>>,
    output_rx: UnboundedReceiver<Vec<u8>>,
    ready_tx: mpsc::Sender<io::Result<()>>,
) -> io::Result<()> {
    let tcp = crate::dns::connect_tcp_tokio(&server.host, server.port, timeout).await?;
    tcp.set_nodelay(true)?;
    let request_host = first_non_empty(host.trim(), server.host.trim()).to_string();

    if let Some(tls_config) = tls {
        let server_name = grpc_tls_server_name(&tls_config, &server)?;
        let connector = TlsConnector::from(grpc_tls_client_config(&tls_config));
        let stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "grpc tls handshake timed out"))?
            .map_err(io_other)?;
        run_grpc_client_stream(
            stream,
            true,
            request_host,
            service_name,
            input_tx,
            output_rx,
            ready_tx,
        )
        .await
    } else {
        run_grpc_client_stream(
            tcp,
            false,
            request_host,
            service_name,
            input_tx,
            output_rx,
            ready_tx,
        )
        .await
    }
}

async fn run_grpc_client_stream<S>(
    stream: S,
    tls: bool,
    host: String,
    service_name: String,
    input_tx: mpsc::Sender<Vec<u8>>,
    output_rx: UnboundedReceiver<Vec<u8>>,
    ready_tx: mpsc::Sender<io::Result<()>>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut client, connection) = h2::client::handshake(stream).await.map_err(io_other)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let path = grpc_tun_path(&service_name);
    let uri = grpc_request_uri(tls, &host, &path);
    let request = Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .map_err(io_other)?;
    let (response, mut send) = client.send_request(request, false).map_err(io_other)?;
    let response = response.await.map_err(io_other)?;
    if response.status() != StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("grpc outbound server returned {}", response.status()),
        ));
    }
    let response_task = read_grpc_hunks(response.into_body(), input_tx);
    let request_task = write_grpc_client_hunks(&mut send, output_rx);
    let _ = ready_tx.send(Ok(()));
    let (response_result, request_result) = tokio::join!(response_task, request_task);
    response_result?;
    request_result
}

async fn write_grpc_client_hunks(
    send: &mut h2::SendStream<Bytes>,
    mut rx: UnboundedReceiver<Vec<u8>>,
) -> io::Result<()> {
    while let Some(payload) = rx.recv().await {
        send_grpc_data(send, Bytes::from(encode_grpc_hunk(&payload)), false).await?;
    }
    send_grpc_data(send, Bytes::new(), true).await
}

fn grpc_tls_client_config(tls: &OutboundTlsConfig) -> Arc<ClientConfig> {
    let mut config = if tls.allow_insecure {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    let mut alpn = tls.alpn.clone();
    if alpn.is_empty() {
        alpn.push("h2".to_string());
    } else if !alpn.iter().any(|value| value == "h2") {
        alpn.insert(0, "h2".to_string());
    }
    config.alpn_protocols = alpn.iter().map(|value| value.as_bytes().to_vec()).collect();
    Arc::new(config)
}

fn grpc_tls_server_name(
    tls: &OutboundTlsConfig,
    server: &SocksTarget,
) -> io::Result<ServerName<'static>> {
    let value = tls.server_name.trim().trim_matches(['[', ']']).to_string();
    let value = if value.is_empty() {
        server.host.trim().trim_matches(['[', ']']).to_string()
    } else {
        value
    };
    ServerName::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "grpc tls server_name is invalid",
        )
    })
}

fn grpc_request_uri(tls: bool, host: &str, path: &str) -> String {
    let scheme = if tls { "https" } else { "http" };
    let authority = grpc_authority(host);
    format!("{scheme}://{authority}{path}")
}

fn grpc_authority(host: &str) -> String {
    let host = host.trim().trim_matches(['[', ']']);
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn tokio_tls_acceptor(config: GrpcTlsConfig) -> io::Result<TokioTlsAcceptor> {
    let mut alpn = config.alpn;
    if alpn.is_empty() {
        alpn.push("h2".to_string());
    } else if !alpn.iter().any(|value| value == "h2") {
        alpn.insert(0, "h2".to_string());
    }
    let config = server_config_from_files(
        config.cert_file,
        config.key_file,
        &alpn,
        &config.server_name,
        config.reject_unknown_sni,
    )?;
    Ok(TokioTlsAcceptor::from(Arc::new(config)))
}

async fn serve_h2_connection<S>(
    stream: S,
    expected_path: Arc<String>,
    handler: GrpcStreamHandler,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = h2::server::handshake(stream).await.map_err(io_other)?;
    while let Some(request) = connection.accept().await {
        let (request, respond) = request.map_err(io_other)?;
        let path = expected_path.clone();
        let handler = handler.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_grpc_request(request, respond, path, handler).await {
                eprintln!("grpc request failed: {error}");
            }
        });
    }
    Ok(())
}

async fn handle_grpc_request(
    request: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    expected_path: Arc<String>,
    handler: GrpcStreamHandler,
) -> io::Result<()> {
    if request.method() != http::Method::POST || request.uri().path() != expected_path.as_str() {
        let response = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())
            .map_err(io_other)?;
        respond.send_response(response, true).map_err(io_other)?;
        return Ok(());
    }

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .body(())
        .map_err(io_other)?;
    let mut send = respond.send_response(response, false).map_err(io_other)?;
    let (input_tx, input_rx) = mpsc::channel();
    let (output_tx, output_rx) = unbounded_channel();
    let reader = GrpcHunkReader::new(input_rx);
    let writer = GrpcHunkWriter::new(output_tx);
    let handler_task = tokio::task::spawn_blocking(move || handler(reader, writer));

    let request_task = read_grpc_hunks(request.into_body(), input_tx);
    let response_task = write_grpc_hunks(&mut send, output_rx);
    let (request_result, response_result) = tokio::join!(request_task, response_task);
    let _ = handler_task.await;
    request_result?;
    response_result
}

async fn read_grpc_hunks(mut stream: RecvStream, tx: mpsc::Sender<Vec<u8>>) -> io::Result<()> {
    let mut buffer = Vec::new();
    while let Some(chunk) = stream.data().await {
        let chunk = chunk.map_err(io_other)?;
        let len = chunk.len();
        buffer.extend_from_slice(&chunk);
        let _ = stream.flow_control().release_capacity(len);
        while let Some(message) = take_grpc_message(&mut buffer)? {
            let data = decode_hunk_message(&message)?;
            if tx.send(data).is_err() {
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn write_grpc_hunks(
    send: &mut h2::SendStream<Bytes>,
    mut rx: UnboundedReceiver<Vec<u8>>,
) -> io::Result<()> {
    while let Some(payload) = rx.recv().await {
        send_grpc_data(send, Bytes::from(encode_grpc_hunk(&payload)), false).await?;
    }
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", "0".parse().map_err(io_other)?);
    send.send_trailers(trailers).map_err(io_other)
}

pub(crate) async fn send_grpc_data(
    send: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
    end_stream: bool,
) -> io::Result<()> {
    if data.is_empty() {
        return send.send_data(data, end_stream).map_err(io_other);
    }

    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let capacity = loop {
            match poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(capacity)) if capacity > 0 => break capacity,
                Some(Ok(_)) => continue,
                Some(Err(error)) => return Err(io_other(error)),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "grpc stream closed before data capacity was assigned",
                    ));
                }
            }
        };
        let chunk_len = capacity.min(data.len());
        let chunk = data.split_to(chunk_len);
        let chunk_ends_stream = end_stream && data.is_empty();
        send.send_data(chunk, chunk_ends_stream).map_err(io_other)?;
    }

    Ok(())
}

pub(crate) fn take_grpc_message(buffer: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
    if buffer.len() < 5 {
        return Ok(None);
    }
    if buffer[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "compressed grpc hunk messages are not supported",
        ));
    }
    let len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
    if len > MAX_GRPC_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "grpc hunk message is too large",
        ));
    }
    if buffer.len() < 5 + len {
        return Ok(None);
    }
    let message = buffer[5..5 + len].to_vec();
    buffer.drain(..5 + len);
    Ok(Some(message))
}

pub fn encode_grpc_hunk(payload: &[u8]) -> Vec<u8> {
    let message = encode_hunk_message(payload);
    let mut output = Vec::with_capacity(5 + message.len());
    output.push(0);
    output.extend_from_slice(&(message.len() as u32).to_be_bytes());
    output.extend_from_slice(&message);
    output
}

fn encode_hunk_message(payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(1 + varint_len(payload.len() as u64) + payload.len());
    output.push(0x0a);
    encode_varint(payload.len() as u64, &mut output);
    output.extend_from_slice(payload);
    output
}

pub(crate) fn decode_hunk_message(message: &[u8]) -> io::Result<Vec<u8>> {
    let mut cursor = 0usize;
    let mut data = None;
    while cursor < message.len() {
        let key = decode_varint(message, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (1, 2) => {
                let len = decode_varint(message, &mut cursor)? as usize;
                if cursor + len > message.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated grpc hunk data",
                    ));
                }
                data = Some(message[cursor..cursor + len].to_vec());
                cursor += len;
            }
            (_, 0) => {
                let _ = decode_varint(message, &mut cursor)?;
            }
            (_, 2) => {
                let len = decode_varint(message, &mut cursor)? as usize;
                if cursor + len > message.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated grpc hunk field",
                    ));
                }
                cursor += len;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported grpc hunk wire type",
                ));
            }
        }
    }
    Ok(data.unwrap_or_default())
}

fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn decode_varint(input: &[u8], cursor: &mut usize) -> io::Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    while *cursor < input.len() && shift < 64 {
        let byte = input[*cursor];
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid grpc hunk varint",
    ))
}

fn varint_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        len += 1;
        value >>= 7;
    }
    len
}

fn grpc_tun_path(service_name: &str) -> String {
    let service_name = service_name.trim();
    if service_name.is_empty() {
        return format!("/{DEFAULT_SERVICE_NAME}/Tun");
    }
    if !service_name.starts_with('/') {
        return format!("/{service_name}/Tun");
    }

    let trimmed = service_name.trim_start_matches('/');
    let Some((prefix, ending)) = trimmed.rsplit_once('/') else {
        return format!("/{}/Tun", trimmed.trim_matches('/'));
    };
    let tun = ending.split('|').next().unwrap_or("Tun").trim();
    format!(
        "/{}/{}",
        prefix.trim_matches('/'),
        first_non_empty(tun, "Tun")
    )
}

fn first_non_empty<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.trim().is_empty() {
        fallback
    } else {
        value
    }
}

impl GrpcHunkReader {
    fn new(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            buffer: Vec::new(),
        }
    }
}

impl Read for GrpcHunkReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.buffer.is_empty() {
            match self.rx.recv() {
                Ok(data) => self.buffer = data,
                Err(_) => return Ok(0),
            }
        }
        let len = output.len().min(self.buffer.len());
        output[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);
        Ok(len)
    }
}

impl GrpcClientStream {
    fn new(rx: mpsc::Receiver<Vec<u8>>, tx: UnboundedSender<Vec<u8>>) -> Self {
        Self {
            rx,
            tx,
            buffer: Vec::new(),
            nonblocking: false,
        }
    }

    pub(crate) fn set_nonblocking(&mut self, nonblocking: bool) {
        self.nonblocking = nonblocking;
    }
}

impl Read for GrpcClientStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.buffer.is_empty() {
            if self.nonblocking {
                match self.rx.try_recv() {
                    Ok(data) => self.buffer = data,
                    Err(mpsc::TryRecvError::Empty) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "grpc stream has no data available",
                        ));
                    }
                    Err(mpsc::TryRecvError::Disconnected) => return Ok(0),
                }
            } else {
                match self.rx.recv() {
                    Ok(data) => self.buffer = data,
                    Err(_) => return Ok(0),
                }
            }
        }
        let len = output.len().min(self.buffer.len());
        output[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);
        Ok(len)
    }
}

impl Write for GrpcClientStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        self.tx
            .send(input.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "grpc stream closed"))?;
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl GrpcHunkWriter {
    fn new(tx: UnboundedSender<Vec<u8>>) -> Self {
        Self { tx }
    }
}

impl Write for GrpcHunkWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        self.tx
            .send(input.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "grpc stream closed"))?;
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

fn io_other(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{decode_hunk_message, encode_grpc_hunk, grpc_tun_path, take_grpc_message};

    #[test]
    fn encodes_and_decodes_grpc_hunk_messages() {
        let mut encoded = encode_grpc_hunk(b"hello");
        let message = take_grpc_message(&mut encoded)
            .expect("frame")
            .expect("message");

        assert_eq!(decode_hunk_message(&message).expect("hunk"), b"hello");
        assert!(encoded.is_empty());
    }

    #[test]
    fn resolves_xray_grpc_tun_path() {
        assert_eq!(grpc_tun_path("GunService"), "/GunService/Tun");
        assert_eq!(grpc_tun_path("/my/sample/path1|path2"), "/my/sample/path1");
        assert_eq!(grpc_tun_path(""), "/GunService/Tun");
    }
}
