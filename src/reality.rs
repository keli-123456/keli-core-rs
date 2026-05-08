use std::collections::HashSet;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_KEY_SHARE: u16 = 0x0033;
const GROUP_X25519: u16 = 0x001d;

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
    use std::time::{Duration, UNIX_EPOCH};

    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::reality::{
        authenticate_reality_client_hello, decode_reality_private_key, decode_short_id,
        RealityAuthConfig, RealityAuthError,
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

    fn push_u24(output: &mut Vec<u8>, value: u32) {
        output.push((value >> 16) as u8);
        output.push((value >> 8) as u8);
        output.push(value as u8);
    }
}
