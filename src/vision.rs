use std::collections::VecDeque;
use std::io::{self, Read, Write};

const COMMAND_PADDING_CONTINUE: u8 = 0x00;
const COMMAND_PADDING_END: u8 = 0x01;
const COMMAND_PADDING_DIRECT: u8 = 0x02;
const MAX_PADDING: usize = 255;
const LONG_PADDING_THRESHOLD: usize = 900;
const LONG_PADDING_JITTER: usize = 500;
const LONG_PADDING_BASE: usize = 900;
const DEFAULT_PACKET_FILTER_COUNT: i32 = 8;
const TLS_HANDSHAKE: u8 = 0x16;
const TLS_APPLICATION_DATA: u8 = 0x17;
const TLS_MAJOR: u8 = 0x03;
const TLS_MINOR_12: u8 = 0x03;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const TLS13_SUPPORTED_VERSIONS_EXTENSION: &[u8] = &[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

#[derive(Clone, Debug)]
pub struct VisionState {
    user_id: [u8; 16],
    checked_prefix: bool,
    saw_vision_prefix: bool,
    plain: bool,
    remaining_command: i32,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: u8,
}

impl VisionState {
    pub fn new(user_id: [u8; 16]) -> Self {
        Self {
            user_id,
            checked_prefix: false,
            saw_vision_prefix: false,
            plain: false,
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: COMMAND_PADDING_CONTINUE,
        }
    }
}

pub struct VisionReader<R> {
    reader: R,
    decoder: VisionDecoder,
}

pub struct VisionWriter<W> {
    writer: W,
    encoder: VisionEncoder,
}

pub struct VisionDecoder {
    state: VisionState,
    input: VecDeque<u8>,
    output: VecDeque<u8>,
}

pub struct VisionEncoder {
    user_id: Option<[u8; 16]>,
    padding_active: bool,
    direct_copy: bool,
    is_tls: bool,
    is_tls12_or_above: bool,
    remaining_server_hello: i32,
    packets_to_filter: i32,
}

impl<R> VisionReader<R> {
    pub fn new(reader: R, user_id: [u8; 16]) -> Self {
        Self {
            reader,
            decoder: VisionDecoder::new(user_id),
        }
    }
}

impl<W> VisionWriter<W> {
    pub fn new(writer: W, user_id: [u8; 16]) -> Self {
        Self {
            writer,
            encoder: VisionEncoder::new(user_id),
        }
    }
}

impl VisionDecoder {
    pub fn new(user_id: [u8; 16]) -> Self {
        Self {
            state: VisionState::new(user_id),
            input: VecDeque::new(),
            output: VecDeque::new(),
        }
    }

    pub fn push(&mut self, input: &[u8]) {
        self.input.extend(input.iter().copied());
    }

    pub fn finish(&mut self) {
        if !self.input.is_empty() {
            self.output.extend(self.input.drain(..));
        }
    }

    pub fn read_decoded(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.process_buffer()?;
        Ok(drain_output(&mut self.output, output).unwrap_or(0))
    }

    pub fn prefix_checked(&self) -> bool {
        self.state.checked_prefix
    }

    pub fn saw_vision_prefix(&self) -> bool {
        self.state.saw_vision_prefix
    }

    pub fn is_direct_copy(&self) -> bool {
        self.state.current_command == COMMAND_PADDING_DIRECT && self.state.plain
    }
}

impl VisionEncoder {
    pub fn new(user_id: [u8; 16]) -> Self {
        Self {
            user_id: Some(user_id),
            padding_active: true,
            direct_copy: false,
            is_tls: false,
            is_tls12_or_above: false,
            remaining_server_hello: -1,
            packets_to_filter: DEFAULT_PACKET_FILTER_COUNT,
        }
    }

    pub fn encode(&mut self, input: &[u8]) -> Vec<u8> {
        if !self.padding_active || input.is_empty() {
            return input.to_vec();
        }

        let split_at = input.len().min(u16::MAX as usize);
        let payload = &input[..split_at];
        self.filter_tls(payload);
        let complete_application_data = is_complete_tls_application_data_records(payload);
        let (command, keep_padding, long_padding, switch_to_direct) =
            self.next_command(complete_application_data);
        let padding = self.padding_len(payload.len(), long_padding);
        let mut frame = Vec::with_capacity(16 + 5 + input.len() + padding);
        if let Some(user_id) = self.user_id.take() {
            frame.extend_from_slice(&user_id);
        }
        frame.push(command);
        frame.extend_from_slice(&(split_at as u16).to_be_bytes());
        frame.extend_from_slice(&(padding as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        append_random_padding(&mut frame, padding);
        self.padding_active = keep_padding;
        self.direct_copy = switch_to_direct;
        if split_at < input.len() {
            frame.extend_from_slice(&input[split_at..]);
        }
        frame
    }

    pub fn finish_padding(&mut self) -> Option<Vec<u8>> {
        if !self.padding_active {
            return None;
        }
        let mut frame = Vec::with_capacity(16 + 5);
        if let Some(user_id) = self.user_id.take() {
            frame.extend_from_slice(&user_id);
        }
        frame.push(COMMAND_PADDING_END);
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        self.padding_active = false;
        Some(frame)
    }

    pub fn is_direct_copy(&self) -> bool {
        self.direct_copy
    }

    fn next_command(&self, complete_application_data: bool) -> (u8, bool, bool, bool) {
        let long_padding = self.is_tls;
        if self.is_tls && complete_application_data {
            return (COMMAND_PADDING_DIRECT, false, true, true);
        }
        if !self.is_tls12_or_above && self.packets_to_filter <= 1 {
            return (COMMAND_PADDING_END, false, long_padding, false);
        }
        (COMMAND_PADDING_CONTINUE, true, long_padding, false)
    }

    fn padding_len(&self, content_len: usize, long_padding: bool) -> usize {
        let padding = if content_len < LONG_PADDING_THRESHOLD && long_padding {
            random_padding_below(LONG_PADDING_JITTER)
                .saturating_add(LONG_PADDING_BASE)
                .saturating_sub(content_len)
        } else {
            random_padding_below(MAX_PADDING + 1)
        };
        padding.min(u16::MAX as usize - content_len)
    }

    fn filter_tls(&mut self, input: &[u8]) {
        if self.packets_to_filter > 0 {
            self.packets_to_filter -= 1;
        }
        if input.len() >= 6 {
            if starts_with_tls_server_hello(input) {
                self.remaining_server_hello = tls_record_len(input)
                    .map(|len| len as i32 + 5)
                    .unwrap_or(-1);
                self.is_tls12_or_above = true;
                self.is_tls = true;
            } else if starts_with_tls_client_hello(input) {
                self.is_tls = true;
            }
        }

        if self.remaining_server_hello > 0 {
            let scan_len = self.remaining_server_hello.min(input.len() as i32) as usize;
            self.remaining_server_hello -= input.len() as i32;
            if input.get(..scan_len).is_some_and(|data| {
                data.windows(TLS13_SUPPORTED_VERSIONS_EXTENSION.len())
                    .any(|w| w == TLS13_SUPPORTED_VERSIONS_EXTENSION)
            }) {
                self.packets_to_filter = 0;
            } else if self.remaining_server_hello <= 0 {
                self.packets_to_filter = 0;
            }
        }
    }
}

impl<R: Read> Read for VisionReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }

        loop {
            if let Some(read) = drain_output(&mut self.decoder.output, output) {
                return Ok(read);
            }

            self.decoder.process_buffer()?;
            if let Some(read) = drain_output(&mut self.decoder.output, output) {
                return Ok(read);
            }

            let mut buffer = [0u8; 8 * 1024];
            match self.reader.read(&mut buffer) {
                Ok(0) => {
                    if !self.decoder.input.is_empty() {
                        self.decoder.finish();
                        continue;
                    }
                    return Ok(0);
                }
                Ok(read) => self.decoder.push(&buffer[..read]),
                Err(error) => return Err(error),
            }
        }
    }
}

impl VisionDecoder {
    fn process_buffer(&mut self) -> io::Result<()> {
        if self.state.plain {
            self.output.extend(self.input.drain(..));
            return Ok(());
        }

        if !self.state.checked_prefix {
            if self.input.len() < 21 {
                return Ok(());
            }
            let has_prefix = self.input.iter().take(16).copied().eq(self.state.user_id);
            self.state.checked_prefix = true;
            if has_prefix {
                self.state.saw_vision_prefix = true;
                self.input.drain(..16);
                self.state.remaining_command = 5;
            } else {
                self.state.plain = true;
                self.output.extend(self.input.drain(..));
                return Ok(());
            }
        }

        while !self.input.is_empty() && !self.state.plain {
            if self.state.remaining_command > 0 {
                let Some(data) = self.input.pop_front() else {
                    return Ok(());
                };
                match self.state.remaining_command {
                    5 => self.state.current_command = data,
                    4 => self.state.remaining_content = i32::from(data) << 8,
                    3 => self.state.remaining_content |= i32::from(data),
                    2 => self.state.remaining_padding = i32::from(data) << 8,
                    1 => self.state.remaining_padding |= i32::from(data),
                    _ => {}
                }
                self.state.remaining_command -= 1;
            } else if self.state.remaining_content > 0 {
                let len = (self.state.remaining_content as usize).min(self.input.len());
                self.output.extend(self.input.drain(..len));
                self.state.remaining_content -= len as i32;
            } else if self.state.remaining_padding > 0 {
                let len = (self.state.remaining_padding as usize).min(self.input.len());
                self.input.drain(..len);
                self.state.remaining_padding -= len as i32;
            }

            if self.state.remaining_command <= 0
                && self.state.remaining_content <= 0
                && self.state.remaining_padding <= 0
            {
                match self.state.current_command {
                    COMMAND_PADDING_CONTINUE => self.state.remaining_command = 5,
                    COMMAND_PADDING_END | COMMAND_PADDING_DIRECT => {
                        self.state.remaining_command = -1;
                        self.state.remaining_content = -1;
                        self.state.remaining_padding = -1;
                        self.state.plain = true;
                        self.output.extend(self.input.drain(..));
                    }
                    command => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unknown vision padding command {command}"),
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

impl<W: Write> Write for VisionWriter<W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let frame = self.encoder.encode(input);
        self.writer.write_all(&frame)?;
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

fn drain_output(output: &mut VecDeque<u8>, target: &mut [u8]) -> Option<usize> {
    if output.is_empty() {
        return None;
    }
    let len = target.len().min(output.len());
    for slot in &mut target[..len] {
        *slot = output.pop_front().expect("output length checked");
    }
    Some(len)
}

fn random_padding_below(limit: usize) -> usize {
    if limit <= 1 {
        return 0;
    }
    let mut bytes = [0u8; 2];
    if getrandom::getrandom(&mut bytes).is_ok() {
        usize::from(u16::from_be_bytes(bytes)) % limit
    } else {
        0
    }
}

fn append_random_padding(frame: &mut Vec<u8>, len: usize) {
    if len == 0 {
        return;
    }
    let start = frame.len();
    frame.resize(start + len, 0);
    let _ = getrandom::getrandom(&mut frame[start..]);
}

fn starts_with_tls_client_hello(input: &[u8]) -> bool {
    input.len() >= 6
        && input[0] == TLS_HANDSHAKE
        && input[1] == TLS_MAJOR
        && input[5] == TLS_HANDSHAKE_CLIENT_HELLO
}

fn starts_with_tls_server_hello(input: &[u8]) -> bool {
    input.len() >= 6
        && input[0] == TLS_HANDSHAKE
        && input[1] == TLS_MAJOR
        && input[2] == TLS_MINOR_12
        && input[5] == TLS_HANDSHAKE_SERVER_HELLO
}

fn is_complete_tls_application_data_records(input: &[u8]) -> bool {
    let mut offset = 0usize;
    let mut saw_record = false;
    while offset + 5 <= input.len() {
        let record_type = input[offset];
        if record_type != TLS_APPLICATION_DATA
            || input[offset + 1] != TLS_MAJOR
            || input[offset + 2] != TLS_MINOR_12
        {
            return false;
        }
        saw_record = true;
        let record_len = (usize::from(input[offset + 3]) << 8) | usize::from(input[offset + 4]);
        let next = offset.saturating_add(5).saturating_add(record_len);
        if next > input.len() {
            return false;
        }
        offset = next;
    }
    saw_record && offset == input.len()
}

fn tls_record_len(input: &[u8]) -> Option<usize> {
    if input.len() < 5 {
        return None;
    }
    Some((usize::from(input[3]) << 8) | usize::from(input[4]))
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use crate::vision::{VisionEncoder, VisionReader, VisionWriter};

    #[test]
    fn vision_writer_and_reader_round_trip() {
        let user_id = [0x11; 16];
        let mut encoded = Vec::new();
        VisionWriter::new(&mut encoded, user_id)
            .write_all(b"hello")
            .expect("vision write");

        let mut decoded = Vec::new();
        VisionReader::new(Cursor::new(encoded), user_id)
            .read_to_end(&mut decoded)
            .expect("vision read");

        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn vision_reader_accepts_plain_payload_without_prefix() {
        let mut decoded = Vec::new();
        VisionReader::new(Cursor::new(b"plain payload".to_vec()), [0x11; 16])
            .read_to_end(&mut decoded)
            .expect("vision read");

        assert_eq!(decoded, b"plain payload");
    }

    #[test]
    fn vision_reader_handles_split_prefix_and_blocks() {
        let user_id = [0x11; 16];
        let mut input = Vec::new();
        input.extend_from_slice(&user_id);
        input.extend_from_slice(&[0x00, 0x00, 0x02, 0x00, 0x01]);
        input.extend_from_slice(b"he");
        input.push(0xff);
        input.extend_from_slice(&[0x01, 0x00, 0x03, 0x00, 0x00]);
        input.extend_from_slice(b"llo");

        let mut decoded = Vec::new();
        VisionReader::new(SlowReader::new(input, 3), user_id)
            .read_to_end(&mut decoded)
            .expect("vision read");

        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn vision_encoder_keeps_tls_server_hello_padding_until_application_data() {
        let user_id = [0x11; 16];
        let mut encoder = VisionEncoder::new(user_id);
        let mut server_hello = vec![0x16, 0x03, 0x03, 0x00, 0x20, 0x02];
        server_hello.extend_from_slice(&[0u8; 12]);
        server_hello.extend_from_slice(super::TLS13_SUPPORTED_VERSIONS_EXTENSION);
        server_hello.resize(37, 0);

        let first = encoder.encode(&server_hello);
        assert_eq!(&first[..16], &user_id);
        assert_eq!(first[16], super::COMMAND_PADDING_CONTINUE);

        let app_data = [0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb];
        let second = encoder.encode(&app_data);
        assert_eq!(second[0], super::COMMAND_PADDING_DIRECT);
        assert!(encoder.is_direct_copy());

        let mut decoded = Vec::new();
        let mut framed = first;
        framed.extend_from_slice(&second);
        VisionReader::new(Cursor::new(framed), user_id)
            .read_to_end(&mut decoded)
            .expect("vision read");

        let mut expected = server_hello;
        expected.extend_from_slice(&app_data);
        assert_eq!(decoded, expected);
    }

    #[test]
    fn vision_encoder_keeps_padding_for_coalesced_server_hello_and_application_data() {
        let user_id = [0x11; 16];
        let mut encoder = VisionEncoder::new(user_id);
        let mut server_hello = vec![0x16, 0x03, 0x03, 0x00, 0x20, 0x02];
        server_hello.extend_from_slice(&[0u8; 12]);
        server_hello.extend_from_slice(super::TLS13_SUPPORTED_VERSIONS_EXTENSION);
        server_hello.resize(37, 0);
        let app_data = [0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb];
        let mut coalesced = server_hello.clone();
        coalesced.extend_from_slice(&app_data);

        let encoded = encoder.encode(&coalesced);
        assert_eq!(&encoded[..16], &user_id);
        assert_eq!(encoded[16], super::COMMAND_PADDING_CONTINUE);
        assert!(!encoder.is_direct_copy());

        let mut decoded = Vec::new();
        VisionReader::new(Cursor::new(encoded), user_id)
            .read_to_end(&mut decoded)
            .expect("vision read");

        assert_eq!(decoded, coalesced);
    }

    struct SlowReader {
        input: Cursor<Vec<u8>>,
        chunk: usize,
    }

    impl SlowReader {
        fn new(input: Vec<u8>, chunk: usize) -> Self {
            Self {
                input: Cursor::new(input),
                chunk,
            }
        }
    }

    impl Read for SlowReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let len = output.len().min(self.chunk);
            self.input.read(&mut output[..len])
        }
    }
}
