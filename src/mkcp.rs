use std::io;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce as AesNonce};
use sha2::{Digest, Sha256};

const FNV_OFFSET: u32 = 0x811c9dc5;
const FNV_PRIME: u32 = 0x01000193;

pub const DATA_SEGMENT_OVERHEAD: usize = 18;
pub const SIMPLE_AUTH_OVERHEAD: usize = 6;
pub const AES_GCM_AUTH_OVERHEAD: usize = 28;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MkcpCommand {
    Ack = 0,
    Data = 1,
    Terminate = 2,
    Ping = 3,
}

impl MkcpCommand {
    fn from_byte(value: u8) -> Self {
        match value {
            0 => Self::Ack,
            1 => Self::Data,
            2 => Self::Terminate,
            3 => Self::Ping,
            _ => Self::Ping,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MkcpSegment {
    Data(MkcpDataSegment),
    Ack(MkcpAckSegment),
    Command(MkcpCommandSegment),
}

impl MkcpSegment {
    pub fn conversation(&self) -> u16 {
        match self {
            Self::Data(segment) => segment.conv,
            Self::Ack(segment) => segment.conv,
            Self::Command(segment) => segment.conv,
        }
    }

    pub fn command(&self) -> MkcpCommand {
        match self {
            Self::Data(_) => MkcpCommand::Data,
            Self::Ack(_) => MkcpCommand::Ack,
            Self::Command(segment) => segment.command,
        }
    }

    pub fn serialized_len(&self) -> usize {
        match self {
            Self::Data(segment) => DATA_SEGMENT_OVERHEAD + segment.payload.len(),
            Self::Ack(segment) => 17 + segment.numbers.len() * 4,
            Self::Command(_) => 16,
        }
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        match self {
            Self::Data(segment) => segment.serialize(output),
            Self::Ack(segment) => segment.serialize(output),
            Self::Command(segment) => segment.serialize(output),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MkcpDataSegment {
    pub conv: u16,
    pub option: u8,
    pub timestamp: u32,
    pub number: u32,
    pub sending_next: u32,
    pub payload: Vec<u8>,
}

impl MkcpDataSegment {
    fn serialize(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.conv.to_be_bytes());
        output.push(MkcpCommand::Data as u8);
        output.push(self.option);
        output.extend_from_slice(&self.timestamp.to_be_bytes());
        output.extend_from_slice(&self.number.to_be_bytes());
        output.extend_from_slice(&self.sending_next.to_be_bytes());
        output.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        output.extend_from_slice(&self.payload);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MkcpAckSegment {
    pub conv: u16,
    pub option: u8,
    pub receiving_window: u32,
    pub receiving_next: u32,
    pub timestamp: u32,
    pub numbers: Vec<u32>,
}

impl MkcpAckSegment {
    fn serialize(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.conv.to_be_bytes());
        output.push(MkcpCommand::Ack as u8);
        output.push(self.option);
        output.extend_from_slice(&self.receiving_window.to_be_bytes());
        output.extend_from_slice(&self.receiving_next.to_be_bytes());
        output.extend_from_slice(&self.timestamp.to_be_bytes());
        output.push(self.numbers.len() as u8);
        for number in &self.numbers {
            output.extend_from_slice(&number.to_be_bytes());
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MkcpCommandSegment {
    pub conv: u16,
    pub command: MkcpCommand,
    pub option: u8,
    pub sending_next: u32,
    pub receiving_next: u32,
    pub peer_rto: u32,
}

impl MkcpCommandSegment {
    fn serialize(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.conv.to_be_bytes());
        output.push(self.command as u8);
        output.push(self.option);
        output.extend_from_slice(&self.sending_next.to_be_bytes());
        output.extend_from_slice(&self.receiving_next.to_be_bytes());
        output.extend_from_slice(&self.peer_rto.to_be_bytes());
    }
}

pub fn read_mkcp_segments(mut input: &[u8]) -> Vec<MkcpSegment> {
    let mut output = Vec::new();
    while let Some((segment, rest)) = read_mkcp_segment(input) {
        output.push(segment);
        input = rest;
    }
    output
}

pub fn read_mkcp_segment(input: &[u8]) -> Option<(MkcpSegment, &[u8])> {
    if input.len() < 4 {
        return None;
    }
    let conv = u16::from_be_bytes([input[0], input[1]]);
    let command = MkcpCommand::from_byte(input[2]);
    let option = input[3];
    let input = &input[4..];
    match command {
        MkcpCommand::Data => read_data_segment(conv, option, input),
        MkcpCommand::Ack => read_ack_segment(conv, option, input),
        MkcpCommand::Terminate | MkcpCommand::Ping => {
            read_command_segment(conv, command, option, input)
        }
    }
}

fn read_data_segment(conv: u16, option: u8, input: &[u8]) -> Option<(MkcpSegment, &[u8])> {
    if input.len() < 14 {
        return None;
    }
    let timestamp = u32::from_be_bytes(input[0..4].try_into().ok()?);
    let number = u32::from_be_bytes(input[4..8].try_into().ok()?);
    let sending_next = u32::from_be_bytes(input[8..12].try_into().ok()?);
    let payload_len = u16::from_be_bytes(input[12..14].try_into().ok()?) as usize;
    let input = &input[14..];
    if input.len() < payload_len {
        return None;
    }
    let payload = input[..payload_len].to_vec();
    Some((
        MkcpSegment::Data(MkcpDataSegment {
            conv,
            option,
            timestamp,
            number,
            sending_next,
            payload,
        }),
        &input[payload_len..],
    ))
}

fn read_ack_segment(conv: u16, option: u8, input: &[u8]) -> Option<(MkcpSegment, &[u8])> {
    if input.len() < 13 {
        return None;
    }
    let receiving_window = u32::from_be_bytes(input[0..4].try_into().ok()?);
    let receiving_next = u32::from_be_bytes(input[4..8].try_into().ok()?);
    let timestamp = u32::from_be_bytes(input[8..12].try_into().ok()?);
    let count = input[12] as usize;
    let input = &input[13..];
    if input.len() < count * 4 {
        return None;
    }
    let mut numbers = Vec::with_capacity(count);
    for chunk in input[..count * 4].chunks_exact(4) {
        numbers.push(u32::from_be_bytes(chunk.try_into().ok()?));
    }
    Some((
        MkcpSegment::Ack(MkcpAckSegment {
            conv,
            option,
            receiving_window,
            receiving_next,
            timestamp,
            numbers,
        }),
        &input[count * 4..],
    ))
}

fn read_command_segment(
    conv: u16,
    command: MkcpCommand,
    option: u8,
    input: &[u8],
) -> Option<(MkcpSegment, &[u8])> {
    if input.len() < 12 {
        return None;
    }
    Some((
        MkcpSegment::Command(MkcpCommandSegment {
            conv,
            command,
            option,
            sending_next: u32::from_be_bytes(input[0..4].try_into().ok()?),
            receiving_next: u32::from_be_bytes(input[4..8].try_into().ok()?),
            peer_rto: u32::from_be_bytes(input[8..12].try_into().ok()?),
        }),
        &input[12..],
    ))
}

pub fn seal_simple_auth(plain: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(plain.len() + SIMPLE_AUTH_OVERHEAD + 3);
    output.extend_from_slice(&[0, 0, 0, 0]);
    output.extend_from_slice(&(plain.len() as u16).to_be_bytes());
    output.extend_from_slice(plain);
    let hash = fnv1a32(&output[4..]);
    output[..4].copy_from_slice(&hash.to_be_bytes());

    let original_len = output.len();
    let padding = (4 - original_len % 4) % 4;
    output.resize(original_len + padding, 0);
    xor_forward(&mut output);
    output.truncate(original_len);
    output
}

pub fn open_simple_auth(ciphertext: &[u8]) -> io::Result<Vec<u8>> {
    if ciphertext.len() < SIMPLE_AUTH_OVERHEAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mkcp packet auth is too short",
        ));
    }
    let mut output = ciphertext.to_vec();
    let original_len = output.len();
    let padding = (4 - original_len % 4) % 4;
    output.resize(original_len + padding, 0);
    xor_backward(&mut output);
    output.truncate(original_len);

    let expected_hash =
        u32::from_be_bytes(output[..4].try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "mkcp auth hash is missing")
        })?);
    let actual_hash = fnv1a32(&output[4..]);
    if expected_hash != actual_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid mkcp auth hash",
        ));
    }
    let payload_len =
        u16::from_be_bytes(output[4..6].try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "mkcp auth length is missing")
        })?) as usize;
    if output.len() - SIMPLE_AUTH_OVERHEAD != payload_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid mkcp auth length",
        ));
    }
    Ok(output[SIMPLE_AUTH_OVERHEAD..].to_vec())
}

pub fn seal_aes_gcm_seed_auth(seed: &str, plain: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = mkcp_seed_cipher(seed)?;
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
    let mut output = Vec::with_capacity(plain.len() + AES_GCM_AUTH_OVERHEAD);
    output.extend_from_slice(&nonce);
    let encrypted = cipher
        .encrypt(AesNonce::from_slice(&nonce), plain)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mkcp aes-gcm seal failed"))?;
    output.extend_from_slice(&encrypted);
    Ok(output)
}

pub fn open_aes_gcm_seed_auth(seed: &str, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
    if ciphertext.len() <= AES_GCM_AUTH_OVERHEAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mkcp aes-gcm packet is too short",
        ));
    }
    let cipher = mkcp_seed_cipher(seed)?;
    let (nonce, encrypted) = ciphertext.split_at(12);
    cipher
        .decrypt(AesNonce::from_slice(nonce), encrypted)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid mkcp aes-gcm auth"))
}

fn mkcp_seed_cipher(seed: &str) -> io::Result<Aes128Gcm> {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let digest = hasher.finalize();
    Aes128Gcm::new_from_slice(&digest[..16])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))
}

fn fnv1a32(input: &[u8]) -> u32 {
    let mut hash = FNV_OFFSET;
    for byte in input {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn xor_forward(input: &mut [u8]) {
    for index in 4..input.len() {
        input[index] ^= input[index - 4];
    }
}

fn xor_backward(input: &mut [u8]) {
    for index in (4..input.len()).rev() {
        input[index] ^= input[index - 4];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_and_reads_data_segments() {
        let segment = MkcpSegment::Data(MkcpDataSegment {
            conv: 7,
            option: 1,
            timestamp: 100,
            number: 2,
            sending_next: 1,
            payload: b"hello".to_vec(),
        });
        let mut encoded = Vec::new();
        segment.serialize(&mut encoded);

        assert_eq!(encoded.len(), DATA_SEGMENT_OVERHEAD + 5);
        assert_eq!(read_mkcp_segment(&encoded).expect("segment").0, segment);
    }

    #[test]
    fn serializes_and_reads_ack_segments() {
        let segment = MkcpSegment::Ack(MkcpAckSegment {
            conv: 9,
            option: 0,
            receiving_window: 64,
            receiving_next: 3,
            timestamp: 1024,
            numbers: vec![1, 2, 4],
        });
        let mut encoded = Vec::new();
        segment.serialize(&mut encoded);

        assert_eq!(encoded.len(), 17 + 3 * 4);
        assert_eq!(read_mkcp_segment(&encoded).expect("segment").0, segment);
    }

    #[test]
    fn serializes_and_reads_command_segments() {
        let segment = MkcpSegment::Command(MkcpCommandSegment {
            conv: 11,
            command: MkcpCommand::Ping,
            option: 0,
            sending_next: 7,
            receiving_next: 8,
            peer_rto: 125,
        });
        let mut encoded = Vec::new();
        segment.serialize(&mut encoded);

        assert_eq!(encoded.len(), 16);
        assert_eq!(read_mkcp_segment(&encoded).expect("segment").0, segment);
    }

    #[test]
    fn simple_auth_round_trips_segments() {
        let segment = MkcpSegment::Data(MkcpDataSegment {
            conv: 7,
            option: 0,
            timestamp: 100,
            number: 2,
            sending_next: 1,
            payload: b"hello".to_vec(),
        });
        let mut encoded = Vec::new();
        segment.serialize(&mut encoded);

        let sealed = seal_simple_auth(&encoded);
        assert_ne!(sealed, encoded);
        let opened = open_simple_auth(&sealed).expect("open");
        assert_eq!(opened, encoded);
        assert_eq!(read_mkcp_segments(&opened), vec![segment]);
    }

    #[test]
    fn simple_auth_rejects_tampered_packets() {
        let mut sealed = seal_simple_auth(b"hello");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(open_simple_auth(&sealed).is_err());
    }

    #[test]
    fn aes_gcm_seed_auth_round_trips_segments() {
        let segment = MkcpSegment::Command(MkcpCommandSegment {
            conv: 11,
            command: MkcpCommand::Ping,
            option: 0,
            sending_next: 7,
            receiving_next: 8,
            peer_rto: 125,
        });
        let mut encoded = Vec::new();
        segment.serialize(&mut encoded);

        let sealed = seal_aes_gcm_seed_auth("seed-value", &encoded).expect("seal");
        assert_eq!(sealed.len(), encoded.len() + AES_GCM_AUTH_OVERHEAD);
        assert_eq!(
            open_aes_gcm_seed_auth("seed-value", &sealed).expect("open"),
            encoded
        );
        assert!(open_aes_gcm_seed_auth("other-seed", &sealed).is_err());
    }
}
