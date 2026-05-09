use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use h2::RecvStream;
use http::{Request, Response, StatusCode};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio_rustls::{TlsAcceptor as TokioTlsAcceptor, TlsConnector};

use crate::config::OutboundTlsConfig;
use crate::socks5::SocksTarget;
use crate::tls::server_config_from_files;

const DEFAULT_H2_PATH: &str = "/";
const DEFAULT_H2_METHOD: &str = "PUT";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Http2TlsConfig {
    pub cert_file: String,
    pub key_file: String,
    pub server_name: String,
    pub alpn: Vec<String>,
    pub reject_unknown_sni: bool,
}

pub type Http2StreamHandler = Arc<dyn Fn(Http2BodyReader, Http2BodyWriter) + Send + Sync + 'static>;

pub struct Http2BodyReader {
    rx: mpsc::Receiver<Vec<u8>>,
    buffer: Vec<u8>,
}

#[derive(Clone)]
pub struct Http2BodyWriter {
    tx: UnboundedSender<Vec<u8>>,
}

pub(crate) struct Http2ClientStream {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: UnboundedSender<Vec<u8>>,
    buffer: Vec<u8>,
    nonblocking: bool,
}

pub async fn run_http2_listener(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    path: String,
    method: String,
    tls: Option<Http2TlsConfig>,
    handler: Http2StreamHandler,
) -> io::Result<()> {
    let tls_acceptor = tls.map(tokio_tls_acceptor).transpose()?;
    let path = Arc::new(normalize_path(&path));
    let method = Arc::new(http2_method(&method)?);

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        tokio::select! {
            result = listener.accept() => {
                let Ok((stream, _)) = result else {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    continue;
                };
                let path = path.clone();
                let method = method.clone();
                let handler = handler.clone();
                let tls_acceptor = tls_acceptor.clone();
                tokio::spawn(async move {
                    let result = if let Some(acceptor) = tls_acceptor {
                        match acceptor.accept(stream).await {
                            Ok(stream) => serve_h2_connection(stream, path, method, handler).await,
                            Err(error) => Err(io_other(error)),
                        }
                    } else {
                        serve_h2_connection(stream, path, method, handler).await
                    };
                    let _ = result;
                });
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }

    Ok(())
}

pub(crate) fn connect_http2_client(
    server: &SocksTarget,
    timeout: Duration,
    tls: Option<&OutboundTlsConfig>,
    path: Option<&str>,
    host: &str,
    method: Option<&str>,
    headers: Option<&BTreeMap<String, String>>,
) -> io::Result<Http2ClientStream> {
    let (ready_tx, ready_rx) = mpsc::channel();
    let (input_tx, input_rx) = mpsc::channel();
    let (output_tx, output_rx) = unbounded_channel();
    let server = server.clone();
    let tls = tls.cloned();
    let path = normalize_path(path.unwrap_or(DEFAULT_H2_PATH));
    let host = host.trim().trim_matches(['[', ']']).to_string();
    let method = method.unwrap_or(DEFAULT_H2_METHOD).trim().to_string();
    let headers: Vec<(String, String)> = headers
        .map(|headers| {
            headers
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default();

    thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = ready_tx.send(Err(io_other(error)));
                return;
            }
        };
        let result = runtime.block_on(run_http2_client(
            server,
            timeout,
            tls,
            path,
            host,
            method,
            headers,
            input_tx,
            output_rx,
            ready_tx.clone(),
        ));
        if let Err(error) = result {
            let _ = ready_tx.send(Err(error));
        }
    });

    match ready_rx.recv_timeout(timeout) {
        Ok(Ok(())) => Ok(Http2ClientStream::new(input_rx, output_tx)),
        Ok(Err(error)) => Err(error),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "h2 outbound handshake timed out",
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "h2 outbound worker exited before handshake",
        )),
    }
}

pub(crate) fn local_bridge_for_http2(
    mut http2: Http2ClientStream,
) -> io::Result<std::net::TcpStream> {
    let local_listener = std::net::TcpListener::bind(std::net::SocketAddr::from((
        std::net::Ipv4Addr::LOCALHOST,
        0,
    )))?;
    let local_addr = local_listener.local_addr()?;
    let local_client = std::net::TcpStream::connect(local_addr)?;
    let (local_plain, _) = local_listener.accept()?;
    http2.set_nonblocking(true);

    thread::spawn(move || {
        let _ = relay_plain_to_http2(local_plain, http2);
    });

    Ok(local_client)
}

async fn run_http2_client(
    server: SocksTarget,
    timeout: Duration,
    tls: Option<OutboundTlsConfig>,
    path: String,
    host: String,
    method: String,
    headers: Vec<(String, String)>,
    input_tx: mpsc::Sender<Vec<u8>>,
    output_rx: UnboundedReceiver<Vec<u8>>,
    ready_tx: mpsc::Sender<io::Result<()>>,
) -> io::Result<()> {
    let tcp = crate::dns::connect_tcp_tokio(&server.host, server.port, timeout).await?;
    tcp.set_nodelay(true)?;
    let request_host = first_non_empty(host.trim(), server.host.trim()).to_string();

    if let Some(tls_config) = tls {
        let server_name = http2_tls_server_name(&tls_config, &server)?;
        let connector = TlsConnector::from(http2_tls_client_config(&tls_config));
        let stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "h2 tls handshake timed out"))?
            .map_err(io_other)?;
        run_http2_client_stream(
            stream,
            true,
            request_host,
            path,
            method,
            headers,
            input_tx,
            output_rx,
            ready_tx,
        )
        .await
    } else {
        run_http2_client_stream(
            tcp,
            false,
            request_host,
            path,
            method,
            headers,
            input_tx,
            output_rx,
            ready_tx,
        )
        .await
    }
}

async fn run_http2_client_stream<S>(
    stream: S,
    tls: bool,
    host: String,
    path: String,
    method: String,
    headers: Vec<(String, String)>,
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

    let uri = http2_request_uri(tls, &host, &path);
    let mut request = Request::builder().method(http2_method(&method)?).uri(uri);
    for (name, value) in headers {
        request = request.header(name.as_str(), value.as_str());
    }
    let request = request.body(()).map_err(io_other)?;
    let (response, mut send) = client.send_request(request, false).map_err(io_other)?;
    let response = response.await.map_err(io_other)?;
    if response.status() != StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("h2 outbound server returned {}", response.status()),
        ));
    }
    let response_task = read_h2_data(response.into_body(), input_tx);
    let request_task = write_h2_data(&mut send, output_rx);
    let _ = ready_tx.send(Ok(()));
    let (response_result, request_result) = tokio::join!(response_task, request_task);
    response_result?;
    request_result
}

async fn serve_h2_connection<S>(
    stream: S,
    expected_path: Arc<String>,
    expected_method: Arc<http::Method>,
    handler: Http2StreamHandler,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = h2::server::handshake(stream).await.map_err(io_other)?;
    while let Some(request) = connection.accept().await {
        let (request, respond) = request.map_err(io_other)?;
        let path = expected_path.clone();
        let method = expected_method.clone();
        let handler = handler.clone();
        tokio::spawn(async move {
            let _ = handle_h2_request(request, respond, path, method, handler).await;
        });
    }
    Ok(())
}

async fn handle_h2_request(
    request: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    expected_path: Arc<String>,
    expected_method: Arc<http::Method>,
    handler: Http2StreamHandler,
) -> io::Result<()> {
    if request.method() != expected_method.as_ref()
        || request.uri().path() != expected_path.as_str()
    {
        let response = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())
            .map_err(io_other)?;
        respond.send_response(response, true).map_err(io_other)?;
        return Ok(());
    }

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .map_err(io_other)?;
    let mut send = respond.send_response(response, false).map_err(io_other)?;
    let (input_tx, input_rx) = mpsc::channel();
    let (output_tx, output_rx) = unbounded_channel();
    let reader = Http2BodyReader::new(input_rx);
    let writer = Http2BodyWriter::new(output_tx);
    let handler_task = tokio::task::spawn_blocking(move || handler(reader, writer));

    let request_task = read_h2_data(request.into_body(), input_tx);
    let response_task = write_h2_data(&mut send, output_rx);
    let (request_result, response_result) = tokio::join!(request_task, response_task);
    let _ = handler_task.await;
    request_result?;
    response_result
}

async fn read_h2_data(mut stream: RecvStream, tx: mpsc::Sender<Vec<u8>>) -> io::Result<()> {
    while let Some(chunk) = stream.data().await {
        let chunk = chunk.map_err(io_other)?;
        let len = chunk.len();
        if len > 0 && tx.send(chunk.to_vec()).is_err() {
            return Ok(());
        }
        let _ = stream.flow_control().release_capacity(len);
    }
    Ok(())
}

async fn write_h2_data(
    send: &mut h2::SendStream<Bytes>,
    mut rx: UnboundedReceiver<Vec<u8>>,
) -> io::Result<()> {
    while let Some(payload) = rx.recv().await {
        if !payload.is_empty() {
            send.send_data(Bytes::from(payload), false)
                .map_err(io_other)?;
        }
    }
    send.send_data(Bytes::new(), true).map_err(io_other)
}

fn relay_plain_to_http2(
    mut plain: std::net::TcpStream,
    mut http2: Http2ClientStream,
) -> io::Result<()> {
    plain.set_nonblocking(true)?;

    let mut upload_done = false;
    let mut download_done = false;
    let mut upload_buffer = [0u8; 16 * 1024];
    let mut download_buffer = [0u8; 16 * 1024];

    while !upload_done || !download_done {
        let mut progressed = false;

        if !upload_done {
            match plain.read(&mut upload_buffer) {
                Ok(0) => {
                    upload_done = true;
                    let _ = http2.flush();
                    progressed = true;
                }
                Ok(read) => {
                    write_all_wait(&mut http2, &upload_buffer[..read])?;
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    upload_done = true;
                    let _ = http2.flush();
                    progressed = true;
                }
            }
        }

        if !download_done {
            match http2.read(&mut download_buffer) {
                Ok(0) => {
                    download_done = true;
                    let _ = plain.shutdown(std::net::Shutdown::Write);
                    progressed = true;
                }
                Ok(read) => {
                    write_all_wait(&mut plain, &download_buffer[..read])?;
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    download_done = true;
                    let _ = plain.shutdown(std::net::Shutdown::Write);
                    progressed = true;
                }
            }
        }

        if !progressed {
            thread::sleep(Duration::from_millis(1));
        }
    }

    let _ = plain.shutdown(std::net::Shutdown::Both);
    Ok(())
}

fn http2_tls_client_config(tls: &OutboundTlsConfig) -> Arc<ClientConfig> {
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

fn http2_tls_server_name(
    tls: &OutboundTlsConfig,
    server: &SocksTarget,
) -> io::Result<ServerName<'static>> {
    let value = tls.server_name.trim().trim_matches(['[', ']']).to_string();
    let value = if value.is_empty() {
        server.host.trim().trim_matches(['[', ']']).to_string()
    } else {
        value
    };
    ServerName::try_from(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "h2 tls server_name is invalid"))
}

fn tokio_tls_acceptor(config: Http2TlsConfig) -> io::Result<TokioTlsAcceptor> {
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

fn http2_request_uri(tls: bool, host: &str, path: &str) -> String {
    let scheme = if tls { "https" } else { "http" };
    let authority = http2_authority(host);
    format!("{scheme}://{authority}{path}")
}

fn http2_authority(host: &str) -> String {
    let host = host.trim().trim_matches(['[', ']']);
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn http2_method(value: &str) -> io::Result<http::Method> {
    let value = first_non_empty(value.trim(), DEFAULT_H2_METHOD);
    http::Method::from_bytes(value.as_bytes()).map_err(io_other)
}

fn normalize_path(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return DEFAULT_H2_PATH.to_string();
    }
    if value.starts_with('/') {
        value.to_string()
    } else {
        format!("/{value}")
    }
}

fn first_non_empty<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.trim().is_empty() {
        fallback
    } else {
        value
    }
}

fn write_all_wait<W: Write>(writer: &mut W, mut input: &[u8]) -> io::Result<()> {
    while !input.is_empty() {
        match writer.write(input) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "writer returned zero",
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

impl Http2BodyReader {
    fn new(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            buffer: Vec::new(),
        }
    }
}

impl Read for Http2BodyReader {
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

impl Http2BodyWriter {
    fn new(tx: UnboundedSender<Vec<u8>>) -> Self {
        Self { tx }
    }
}

impl Write for Http2BodyWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        self.tx
            .send(input.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "h2 stream closed"))?;
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Http2ClientStream {
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

impl Read for Http2ClientStream {
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
                            "h2 stream has no data available",
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

impl Write for Http2ClientStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        self.tx
            .send(input.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "h2 stream closed"))?;
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
    use std::io::{Read, Write};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::net::TcpListener;

    use crate::http2::{connect_http2_client, run_http2_listener, Http2StreamHandler};
    use crate::socks5::SocksTarget;

    #[test]
    fn http2_client_relays_bidirectional_body() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind h2");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr");
        let _guard = runtime.enter();
        let listener = TcpListener::from_std(listener).expect("tokio listener");
        drop(_guard);
        let stop = Arc::new(AtomicBool::new(false));
        let handler: Http2StreamHandler = Arc::new(|mut reader, mut writer| {
            let mut payload = [0u8; 4];
            reader.read_exact(&mut payload).expect("read h2 body");
            assert_eq!(&payload, b"ping");
            writer.write_all(b"pong").expect("write h2 body");
        });
        let stop_clone = stop.clone();
        std::thread::spawn(move || {
            runtime
                .block_on(run_http2_listener(
                    listener,
                    stop_clone,
                    "/h2".to_string(),
                    "PUT".to_string(),
                    None,
                    handler,
                ))
                .expect("h2 listener");
        });

        let target = SocksTarget {
            host: addr.ip().to_string(),
            port: addr.port(),
        };
        let mut stream = connect_http2_client(
            &target,
            Duration::from_secs(2),
            None,
            Some("/h2"),
            "example.test",
            Some("PUT"),
            None,
        )
        .expect("connect h2");
        stream.write_all(b"ping").expect("write");
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).expect("read");
        assert_eq!(&response, b"pong");
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
