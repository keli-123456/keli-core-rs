use std::collections::HashSet;
use std::fmt;
use std::io::{self, Cursor as IoCursor, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::stream::relay_tcp_streams_limited;

const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_RECORD_CHANGE_CIPHER_SPEC: u8 = 0x14;
const TLS_RECORD_ALERT: u8 = 0x15;
const TLS_RECORD_APPLICATION_DATA: u8 = 0x17;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_KEY_SHARE: u16 = 0x0033;
const GROUP_X25519: u16 = 0x001d;
const MAX_TLS_RECORD_LEN: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealityAuthConfig {
    pub private_key: [u8; 32],
    pub server_names: HashSet<String>,
    pub short_ids: HashSet<[u8; 8]>,
    pub max_time_diff: Option<Duration>,
    pub now: SystemTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealityClientAuth {
    pub server_name: String,
    pub client_version: [u8; 3],
    pub client_time: SystemTime,
    pub short_id: [u8; 8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealityGatewayConfig {
    pub auth: RealityAuthConfig,
    pub dest: String,
    pub connect_timeout: Duration,
}

#[derive(Debug)]
pub enum RealityGatewayResult {
    Authenticated(RealityAuthenticatedStream),
    Fallback {
        reason: RealityAuthError,
        upload: u64,
        download: u64,
    },
}

#[derive(Debug)]
pub struct RealityAuthenticatedStream {
    pub auth: RealityClientAuth,
    pub stream: PrefixedTcpStream,
    pub dest: TcpStream,
}

#[derive(Debug)]
pub struct PrefixedTcpStream {
    prefix: IoCursor<Vec<u8>>,
    socket: TcpStream,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RealityAuthError {
    InvalidClientHello(String),
    ServerNameMismatch(String),
    MissingX25519KeyShare,
    InvalidPrivateKey,
    AuthenticationFailed,
    TimeDiffExceeded,
    ShortIdMismatch([u8; 8]),
}

impl fmt::Display for RealityAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RealityAuthError::InvalidClientHello(message) => {
                write!(formatter, "invalid reality client hello: {message}")
            }
            RealityAuthError::ServerNameMismatch(name) => {
                write!(formatter, "reality server name mismatch: {name}")
            }
            RealityAuthError::MissingX25519KeyShare => {
                formatter.write_str("reality client hello missing x25519 key share")
            }
            RealityAuthError::InvalidPrivateKey => {
                formatter.write_str("reality private key is invalid")
            }
            RealityAuthError::AuthenticationFailed => {
                formatter.write_str("reality authentication failed")
            }
            RealityAuthError::TimeDiffExceeded => {
                formatter.write_str("reality client time exceeds max_time_diff")
            }
            RealityAuthError::ShortIdMismatch(short_id) => {
                write!(
                    formatter,
                    "reality short_id mismatch: {}",
                    short_id_hex(short_id)
                )
            }
        }
    }
}

impl std::error::Error for RealityAuthError {}

pub fn handle_reality_preface(
    mut client: TcpStream,
    config: &RealityGatewayConfig,
) -> io::Result<RealityGatewayResult> {
    let first_record = read_first_tls_record(&mut client)?;
    let mut dest = connect_dest(&config.dest, config.connect_timeout)?;
    dest.write_all(&first_record)?;
    match authenticate_reality_client_hello(&first_record, &config.auth) {
        Ok(auth) => Ok(RealityGatewayResult::Authenticated(
            RealityAuthenticatedStream {
                auth,
                stream: PrefixedTcpStream::new(client, first_record),
                dest,
            },
        )),
        Err(reason) => {
            let (upload, download) = fallback_to_dest(client, first_record, dest)?;
            Ok(RealityGatewayResult::Fallback {
                reason,
                upload,
                download,
            })
        }
    }
}

pub fn authenticate_reality_client_hello(
    raw_record: &[u8],
    config: &RealityAuthConfig,
) -> Result<RealityClientAuth, RealityAuthError> {
    let hello = parse_client_hello(raw_record)?;
    if !config.server_names.is_empty() && !config.server_names.contains(&hello.server_name) {
        return Err(RealityAuthError::ServerNameMismatch(hello.server_name));
    }
    let Some(peer_public) = hello.x25519_key_share else {
        return Err(RealityAuthError::MissingX25519KeyShare);
    };

    let secret = StaticSecret::from(config.private_key);
    let auth_key = secret.diffie_hellman(&PublicKey::from(peer_public));
    if auth_key.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(RealityAuthError::InvalidPrivateKey);
    }
    let mut derived = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&hello.random[..20]), auth_key.as_bytes())
        .expand(b"REALITY", &mut derived)
        .map_err(|_| RealityAuthError::AuthenticationFailed)?;

    let aead =
        Aes256Gcm::new_from_slice(&derived).map_err(|_| RealityAuthError::AuthenticationFailed)?;
    let mut associated_data = raw_record.to_vec();
    associated_data[hello.session_id_offset..hello.session_id_offset + 32].fill(0);
    let plaintext = aead
        .decrypt(
            Nonce::from_slice(&hello.random[20..32]),
            aes_gcm::aead::Payload {
                msg: &hello.session_id,
                aad: &associated_data,
            },
        )
        .map_err(|_| RealityAuthError::AuthenticationFailed)?;
    if plaintext.len() < 16 {
        return Err(RealityAuthError::AuthenticationFailed);
    }

    let client_time = UNIX_EPOCH
        + Duration::from_secs(u64::from(u32::from_be_bytes([
            plaintext[4],
            plaintext[5],
            plaintext[6],
            plaintext[7],
        ])));
    if let Some(max) = config.max_time_diff {
        let diff = config
            .now
            .duration_since(client_time)
            .unwrap_or_else(|_| client_time.duration_since(config.now).unwrap_or_default());
        if diff > max {
            return Err(RealityAuthError::TimeDiffExceeded);
        }
    }

    let mut client_version = [0u8; 3];
    client_version.copy_from_slice(&plaintext[..3]);
    let mut short_id = [0u8; 8];
    short_id.copy_from_slice(&plaintext[8..16]);
    if !config.short_ids.is_empty() && !config.short_ids.contains(&short_id) {
        return Err(RealityAuthError::ShortIdMismatch(short_id));
    }

    Ok(RealityClientAuth {
        server_name: hello.server_name,
        client_version,
        client_time,
        short_id,
    })
}

pub fn decode_reality_private_key(value: &str) -> Result<[u8; 32], RealityAuthError> {
    let value = value.trim();
    if value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        let bytes = decode_hex(value).map_err(RealityAuthError::InvalidClientHello)?;
        return bytes
            .try_into()
            .map_err(|_| RealityAuthError::InvalidPrivateKey);
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(value))
        .map_err(|_| RealityAuthError::InvalidPrivateKey)?;
    bytes
        .try_into()
        .map_err(|_| RealityAuthError::InvalidPrivateKey)
}

pub fn decode_short_id(value: &str) -> Result<[u8; 8], RealityAuthError> {
    let value = value.trim();
    if value.len() > 16 || value.len() % 2 != 0 {
        return Err(RealityAuthError::InvalidClientHello(
            "short_id must be 0 to 8 bytes of hex".to_string(),
        ));
    }
    let bytes = decode_hex(value).map_err(RealityAuthError::InvalidClientHello)?;
    let mut short_id = [0u8; 8];
    short_id[..bytes.len()].copy_from_slice(&bytes);
    Ok(short_id)
}

impl PrefixedTcpStream {
    pub fn new(socket: TcpStream, prefix: Vec<u8>) -> Self {
        Self {
            prefix: IoCursor::new(prefix),
            socket,
        }
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.socket.set_nonblocking(nonblocking)
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.socket.shutdown(how)
    }

    pub fn into_inner(self) -> TcpStream {
        self.socket
    }
}

impl RealityAuthenticatedStream {
    pub fn read_dest_tls_records(
        &mut self,
        max_records: usize,
        timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        if max_records == 0 {
            return Ok(Vec::new());
        }
        self.dest.set_read_timeout(Some(timeout))?;
        let result = read_tls_records(&mut self.dest, max_records);
        let restore_result = self.dest.set_read_timeout(None);
        match (result, restore_result) {
            (Ok(records), Ok(())) => Ok(records),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }
}

impl Read for PrefixedTcpStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if (self.prefix.position() as usize) < self.prefix.get_ref().len() {
            return self.prefix.read(output);
        }
        self.socket.read(output)
    }
}

impl Write for PrefixedTcpStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.socket.write(input)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

fn read_first_tls_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    read_tls_record(stream).map(|record| record.unwrap_or_default())
}

fn read_tls_records(stream: &mut TcpStream, max_records: usize) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    for _ in 0..max_records {
        match read_tls_record(stream) {
            Ok(Some(record)) => output.extend_from_slice(&record),
            Ok(None) => break,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(output)
}

fn read_tls_record(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 5];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    if !matches!(
        header[0],
        TLS_RECORD_CHANGE_CIPHER_SPEC
            | TLS_RECORD_ALERT
            | TLS_RECORD_HANDSHAKE
            | TLS_RECORD_APPLICATION_DATA
    ) {
        return Ok(Some(header.to_vec()));
    }
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if record_len > MAX_TLS_RECORD_LEN {
        return Ok(Some(header.to_vec()));
    }
    let mut record = Vec::with_capacity(5 + record_len);
    record.extend_from_slice(&header);
    record.resize(5 + record_len, 0);
    stream.read_exact(&mut record[5..])?;
    Ok(Some(record))
}

fn fallback_to_dest(
    client: TcpStream,
    first_record: Vec<u8>,
    remote: TcpStream,
) -> io::Result<(u64, u64)> {
    let initial_upload = first_record.len() as u64;
    let (upload, download) = relay_tcp_streams_limited(client, remote, None)?;
    Ok((initial_upload.saturating_add(upload), download))
}

fn connect_dest(dest: &str, timeout: Duration) -> io::Result<TcpStream> {
    let addrs = dest.to_socket_addrs()?;
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
            "reality dest did not resolve to any socket address",
        )
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedClientHello {
    random: [u8; 32],
    session_id: [u8; 32],
    session_id_offset: usize,
    server_name: String,
    x25519_key_share: Option<[u8; 32]>,
}

fn parse_client_hello(input: &[u8]) -> Result<ParsedClientHello, RealityAuthError> {
    if input.len() < 5 {
        return Err(invalid("record is too short"));
    }
    if input[0] != TLS_RECORD_HANDSHAKE {
        return Err(invalid("record is not a handshake"));
    }
    let record_len = read_u16(input, 3)? as usize;
    if input.len() < 5 + record_len {
        return Err(invalid("record body is truncated"));
    }
    let body = &input[5..5 + record_len];
    if body.len() < 4 || body[0] != TLS_HANDSHAKE_CLIENT_HELLO {
        return Err(invalid("handshake is not client hello"));
    }
    let handshake_len = read_u24(body, 1)? as usize;
    if body.len() < 4 + handshake_len {
        return Err(invalid("client hello body is truncated"));
    }
    let hello = &body[4..4 + handshake_len];
    let mut cursor = Cursor::new(hello);
    let _legacy_version = cursor.read_u16()?;
    let random = cursor.read_array::<32>()?;
    let session_id_len = cursor.read_u8()? as usize;
    if session_id_len != 32 {
        return Err(invalid("reality requires a 32-byte session id"));
    }
    let session_id_offset = 5 + 4 + cursor.position();
    let session_id = cursor.read_array::<32>()?;
    let cipher_len = cursor.read_u16()? as usize;
    cursor.skip(cipher_len)?;
    let compression_len = cursor.read_u8()? as usize;
    cursor.skip(compression_len)?;
    let extensions_len = cursor.read_u16()? as usize;
    let extensions = cursor.read_slice(extensions_len)?;

    let mut server_name = String::new();
    let mut x25519_key_share = None;
    let mut extensions = Cursor::new(extensions);
    while extensions.remaining() > 0 {
        let ext_type = extensions.read_u16()?;
        let ext_len = extensions.read_u16()? as usize;
        let ext = extensions.read_slice(ext_len)?;
        match ext_type {
            EXT_SERVER_NAME => {
                server_name = parse_sni_extension(ext)?;
            }
            EXT_KEY_SHARE => {
                x25519_key_share = parse_key_share_extension(ext)?;
            }
            _ => {}
        }
    }

    Ok(ParsedClientHello {
        random,
        session_id,
        session_id_offset,
        server_name,
        x25519_key_share,
    })
}

fn parse_sni_extension(input: &[u8]) -> Result<String, RealityAuthError> {
    let mut cursor = Cursor::new(input);
    let list_len = cursor.read_u16()? as usize;
    let list = cursor.read_slice(list_len)?;
    let mut list = Cursor::new(list);
    while list.remaining() > 0 {
        let name_type = list.read_u8()?;
        let len = list.read_u16()? as usize;
        let value = list.read_slice(len)?;
        if name_type == 0 {
            return String::from_utf8(value.to_vec())
                .map_err(|_| invalid("sni is not valid utf-8"));
        }
    }
    Ok(String::new())
}

fn parse_key_share_extension(input: &[u8]) -> Result<Option<[u8; 32]>, RealityAuthError> {
    let mut cursor = Cursor::new(input);
    let client_shares_len = cursor.read_u16()? as usize;
    let shares = cursor.read_slice(client_shares_len)?;
    let mut shares = Cursor::new(shares);
    while shares.remaining() > 0 {
        let group = shares.read_u16()?;
        let len = shares.read_u16()? as usize;
        let value = shares.read_slice(len)?;
        if group == GROUP_X25519 && value.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(value);
            return Ok(Some(key));
        }
    }
    Ok(None)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    if value.len() % 2 != 0 {
        return Err("hex string must have an even length".to_string());
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        output.push(
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| "hex string contains invalid characters".to_string())?,
        );
    }
    Ok(output)
}

fn invalid(message: impl Into<String>) -> RealityAuthError {
    RealityAuthError::InvalidClientHello(message.into())
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, RealityAuthError> {
    if offset + 2 > input.len() {
        return Err(invalid("u16 field is truncated"));
    }
    Ok(u16::from_be_bytes([input[offset], input[offset + 1]]))
}

fn read_u24(input: &[u8], offset: usize) -> Result<u32, RealityAuthError> {
    if offset + 3 > input.len() {
        return Err(invalid("u24 field is truncated"));
    }
    Ok((u32::from(input[offset]) << 16)
        | (u32::from(input[offset + 1]) << 8)
        | u32::from(input[offset + 2]))
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.offset)
    }

    fn read_u8(&mut self) -> Result<u8, RealityAuthError> {
        if self.offset >= self.input.len() {
            return Err(invalid("u8 field is truncated"));
        }
        let value = self.input[self.offset];
        self.offset += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, RealityAuthError> {
        let value = read_u16(self.input, self.offset)?;
        self.offset += 2;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], RealityAuthError> {
        let bytes = self.read_slice(N)?;
        let mut output = [0u8; N];
        output.copy_from_slice(bytes);
        Ok(output)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], RealityAuthError> {
        if self.offset + len > self.input.len() {
            return Err(invalid("field is truncated"));
        }
        let slice = &self.input[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice)
    }

    fn skip(&mut self, len: usize) -> Result<(), RealityAuthError> {
        let _ = self.read_slice(len)?;
        Ok(())
    }
}

fn short_id_hex(value: &[u8; 8]) -> String {
    let mut output = String::with_capacity(16);
    for byte in value {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0f));
    }
    output
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => unreachable!("hex nibble is always below 16"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, UNIX_EPOCH};

    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::reality::{
        authenticate_reality_client_hello, decode_reality_private_key, decode_short_id,
        handle_reality_preface, RealityAuthConfig, RealityAuthError, RealityGatewayConfig,
        RealityGatewayResult,
    };

    #[test]
    fn decodes_short_ids_like_xray() {
        assert_eq!(decode_short_id("").expect("empty"), [0u8; 8]);
        assert_eq!(
            decode_short_id("6ba85179e30d4fc2").expect("short id"),
            [0x6b, 0xa8, 0x51, 0x79, 0xe3, 0x0d, 0x4f, 0xc2]
        );
        assert_eq!(
            decode_short_id("b1").expect("short id"),
            [0xb1, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn authenticates_reality_client_hello() {
        let server_secret = StaticSecret::from([7u8; 32]);
        let client_secret = StaticSecret::from([9u8; 32]);
        let short_id = [0x6b, 0xa8, 0x51, 0x79, 0xe3, 0x0d, 0x4f, 0xc2];
        let now = UNIX_EPOCH + Duration::from_secs(1_777_650_625);
        let record = build_reality_client_hello(
            &client_secret,
            &PublicKey::from(&server_secret),
            "www.example.test",
            [1, 8, 23],
            1_777_650_625,
            short_id,
        );
        let config = RealityAuthConfig {
            private_key: server_secret.to_bytes(),
            server_names: HashSet::from(["www.example.test".to_string()]),
            short_ids: HashSet::from([short_id]),
            max_time_diff: Some(Duration::from_secs(30)),
            now,
        };

        let auth = authenticate_reality_client_hello(&record, &config).expect("auth");

        assert_eq!(auth.server_name, "www.example.test");
        assert_eq!(auth.client_version, [1, 8, 23]);
        assert_eq!(auth.short_id, short_id);
    }

    #[test]
    fn rejects_reality_short_id_mismatch() {
        let server_secret = StaticSecret::from([7u8; 32]);
        let client_secret = StaticSecret::from([9u8; 32]);
        let record = build_reality_client_hello(
            &client_secret,
            &PublicKey::from(&server_secret),
            "www.example.test",
            [1, 8, 23],
            1_777_650_625,
            [0xb1, 0, 0, 0, 0, 0, 0, 0],
        );
        let config = RealityAuthConfig {
            private_key: server_secret.to_bytes(),
            server_names: HashSet::from(["www.example.test".to_string()]),
            short_ids: HashSet::from([[0x6b, 0xa8, 0x51, 0x79, 0xe3, 0x0d, 0x4f, 0xc2]]),
            max_time_diff: None,
            now: UNIX_EPOCH + Duration::from_secs(1_777_650_625),
        };

        let error = authenticate_reality_client_hello(&record, &config).expect_err("reject");

        assert!(matches!(error, RealityAuthError::ShortIdMismatch(_)));
    }

    #[test]
    fn rejects_reality_tampered_session_id() {
        let server_secret = StaticSecret::from([7u8; 32]);
        let client_secret = StaticSecret::from([9u8; 32]);
        let short_id = [0x6b, 0xa8, 0x51, 0x79, 0xe3, 0x0d, 0x4f, 0xc2];
        let mut record = build_reality_client_hello(
            &client_secret,
            &PublicKey::from(&server_secret),
            "www.example.test",
            [1, 8, 23],
            1_777_650_625,
            short_id,
        );
        record[44] ^= 0x55;
        let config = RealityAuthConfig {
            private_key: server_secret.to_bytes(),
            server_names: HashSet::from(["www.example.test".to_string()]),
            short_ids: HashSet::from([short_id]),
            max_time_diff: None,
            now: UNIX_EPOCH + Duration::from_secs(1_777_650_625),
        };

        let error = authenticate_reality_client_hello(&record, &config).expect_err("reject");

        assert!(matches!(error, RealityAuthError::AuthenticationFailed));
    }

    #[test]
    fn decodes_urlsafe_private_key() {
        let key = decode_reality_private_key("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc")
            .expect("private key");

        assert_eq!(key, [7u8; 32]);
    }

    #[test]
    fn gateway_returns_authenticated_prefixed_stream() {
        let target = TcpListener::bind("127.0.0.1:0").expect("bind target");
        let target_addr = target.local_addr().expect("target addr");
        let (target_tx, target_rx) = mpsc::channel();
        let target_records = [
            tls_record(TLS_RECORD_HANDSHAKE, b"server-hello"),
            tls_record(TLS_RECORD_APPLICATION_DATA, b"encrypted-extensions"),
        ]
        .concat();
        let target_records_for_server = target_records.clone();
        let target_thread = thread::spawn(move || {
            let (mut stream, _) = target.accept().expect("accept target");
            let mut header = [0u8; 5];
            stream.read_exact(&mut header).expect("read target header");
            let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut captured = header.to_vec();
            captured.resize(5 + body_len, 0);
            stream
                .read_exact(&mut captured[5..])
                .expect("read target body");
            target_tx.send(captured).expect("send target capture");
            stream
                .write_all(&target_records)
                .expect("write target records");
        });

        let server_secret = StaticSecret::from([7u8; 32]);
        let client_secret = StaticSecret::from([9u8; 32]);
        let short_id = [0x6b, 0xa8, 0x51, 0x79, 0xe3, 0x0d, 0x4f, 0xc2];
        let record = build_reality_client_hello(
            &client_secret,
            &PublicKey::from(&server_secret),
            "www.example.test",
            [1, 8, 23],
            1_777_650_625,
            short_id,
        );
        let record_for_server = record.clone();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind reality");
        let addr = listener.local_addr().expect("reality addr");
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept reality");
            let config = gateway_config(server_secret, short_id, target_addr.to_string());
            let result = handle_reality_preface(stream, &config).expect("reality preface");
            let RealityGatewayResult::Authenticated(mut authenticated) = result else {
                panic!("expected authenticated reality stream");
            };
            assert_eq!(authenticated.auth.server_name, "www.example.test");

            let mut replayed = vec![0u8; record_for_server.len()];
            authenticated
                .stream
                .read_exact(&mut replayed)
                .expect("read replayed record");
            assert_eq!(replayed, record_for_server);

            let mut after = [0u8; 5];
            authenticated
                .stream
                .read_exact(&mut after)
                .expect("read after bytes");
            assert_eq!(&after, b"after");

            let dest_records = authenticated
                .read_dest_tls_records(2, Duration::from_secs(3))
                .expect("read dest records");
            assert_eq!(dest_records, target_records_for_server);
        });

        let mut client = TcpStream::connect(addr).expect("connect reality");
        client.write_all(&record).expect("write record");
        client.write_all(b"after").expect("write after bytes");
        client.shutdown(Shutdown::Write).expect("shutdown client");

        server_thread.join().expect("server thread");
        target_thread.join().expect("target thread");
        assert_eq!(target_rx.recv().expect("target capture"), record);
    }

    #[test]
    fn gateway_falls_back_to_dest_for_invalid_reality_auth() {
        let fallback = TcpListener::bind("127.0.0.1:0").expect("bind fallback");
        let fallback_addr = fallback.local_addr().expect("fallback addr");
        let (captured_tx, captured_rx) = mpsc::channel();
        let fallback_thread = thread::spawn(move || {
            let (mut stream, _) = fallback.accept().expect("accept fallback");
            let mut captured = Vec::new();
            stream.read_to_end(&mut captured).expect("read fallback");
            captured_tx.send(captured).expect("send captured");
            stream.write_all(b"fallback-ok").expect("write fallback");
        });

        let server_secret = StaticSecret::from([7u8; 32]);
        let client_secret = StaticSecret::from([9u8; 32]);
        let valid_short_id = [0x6b, 0xa8, 0x51, 0x79, 0xe3, 0x0d, 0x4f, 0xc2];
        let wrong_short_id = [0xb1, 0, 0, 0, 0, 0, 0, 0];
        let record = build_reality_client_hello(
            &client_secret,
            &PublicKey::from(&server_secret),
            "www.example.test",
            [1, 8, 23],
            1_777_650_625,
            wrong_short_id,
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind reality");
        let addr = listener.local_addr().expect("reality addr");
        let record_len = record.len();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept reality");
            let config = gateway_config(server_secret, valid_short_id, fallback_addr.to_string());
            let result = handle_reality_preface(stream, &config).expect("reality preface");
            let RealityGatewayResult::Fallback {
                reason,
                upload,
                download,
            } = result
            else {
                panic!("expected reality fallback");
            };
            assert!(matches!(reason, RealityAuthError::ShortIdMismatch(_)));
            assert_eq!(upload, (record_len + 5) as u64);
            assert_eq!(download, b"fallback-ok".len() as u64);
        });

        let mut client = TcpStream::connect(addr).expect("connect reality");
        client.write_all(&record).expect("write record");
        client.write_all(b"plain").expect("write payload");
        client.shutdown(Shutdown::Write).expect("shutdown write");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("read response");
        assert_eq!(response, b"fallback-ok");

        server_thread.join().expect("server thread");
        fallback_thread.join().expect("fallback thread");
        let captured = captured_rx.recv().expect("captured fallback");
        let mut expected = record;
        expected.extend_from_slice(b"plain");
        assert_eq!(captured, expected);
    }

    fn gateway_config(
        server_secret: StaticSecret,
        short_id: [u8; 8],
        dest: String,
    ) -> RealityGatewayConfig {
        RealityGatewayConfig {
            auth: RealityAuthConfig {
                private_key: server_secret.to_bytes(),
                server_names: HashSet::from(["www.example.test".to_string()]),
                short_ids: HashSet::from([short_id]),
                max_time_diff: Some(Duration::from_secs(30)),
                now: UNIX_EPOCH + Duration::from_secs(1_777_650_625),
            },
            dest,
            connect_timeout: Duration::from_secs(3),
        }
    }

    fn build_reality_client_hello(
        client_secret: &StaticSecret,
        server_public: &PublicKey,
        server_name: &str,
        version: [u8; 3],
        unix_time: u32,
        short_id: [u8; 8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes());
        let mut random = [0x22u8; 32];
        random[..20].copy_from_slice(&[0x31; 20]);
        random[20..].copy_from_slice(&[0x42; 12]);
        body.extend_from_slice(&random);
        body.push(32);
        let session_id_offset = body.len();
        body.extend_from_slice(&[0u8; 32]);
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.extend_from_slice(&0x1302u16.to_be_bytes());
        body.push(1);
        body.push(0);

        let sni_ext = sni_extension(server_name);
        let key_share_ext = key_share_extension(&PublicKey::from(client_secret));
        let mut extensions = Vec::new();
        extension(&mut extensions, EXT_SERVER_NAME, &sni_ext);
        extension(&mut extensions, EXT_KEY_SHARE, &key_share_ext);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(TLS_HANDSHAKE_CLIENT_HELLO);
        push_u24(&mut handshake, body.len() as u32);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(TLS_RECORD_HANDSHAKE);
        record.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        let shared = client_secret.diffie_hellman(server_public);
        let mut derived = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&random[..20]), shared.as_bytes())
            .expand(b"REALITY", &mut derived)
            .expect("hkdf");
        let mut plain = [0u8; 16];
        plain[..3].copy_from_slice(&version);
        plain[4..8].copy_from_slice(&unix_time.to_be_bytes());
        plain[8..16].copy_from_slice(&short_id);
        let aead = Aes256Gcm::new_from_slice(&derived).expect("aead");
        let encrypted = aead
            .encrypt(
                Nonce::from_slice(&random[20..32]),
                aes_gcm::aead::Payload {
                    msg: &plain,
                    aad: &record,
                },
            )
            .expect("encrypt");
        let absolute_session_id_offset = 5 + 4 + session_id_offset;
        record[absolute_session_id_offset..absolute_session_id_offset + 32]
            .copy_from_slice(&encrypted);
        record
    }

    const TLS_RECORD_HANDSHAKE: u8 = 0x16;
    const TLS_RECORD_APPLICATION_DATA: u8 = 0x17;
    const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
    const TLS_VERSION_1_2: u16 = 0x0303;
    const EXT_SERVER_NAME: u16 = 0x0000;
    const EXT_KEY_SHARE: u16 = 0x0033;
    const GROUP_X25519: u16 = 0x001d;

    fn sni_extension(server_name: &str) -> Vec<u8> {
        let mut name = Vec::new();
        name.push(0);
        name.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        name.extend_from_slice(server_name.as_bytes());
        let mut output = Vec::new();
        output.extend_from_slice(&(name.len() as u16).to_be_bytes());
        output.extend_from_slice(&name);
        output
    }

    fn key_share_extension(public_key: &PublicKey) -> Vec<u8> {
        let mut share = Vec::new();
        share.extend_from_slice(&GROUP_X25519.to_be_bytes());
        share.extend_from_slice(&32u16.to_be_bytes());
        share.extend_from_slice(public_key.as_bytes());
        let mut output = Vec::new();
        output.extend_from_slice(&(share.len() as u16).to_be_bytes());
        output.extend_from_slice(&share);
        output
    }

    fn extension(output: &mut Vec<u8>, ext_type: u16, value: &[u8]) {
        output.extend_from_slice(&ext_type.to_be_bytes());
        output.extend_from_slice(&(value.len() as u16).to_be_bytes());
        output.extend_from_slice(value);
    }

    fn tls_record(record_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        record.push(record_type);
        record.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes());
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    fn push_u24(output: &mut Vec<u8>, value: u32) {
        output.push((value >> 16) as u8);
        output.push((value >> 8) as u8);
        output.push(value as u8);
    }
}
