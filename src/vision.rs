use std::collections::VecDeque;
use std::io::{self, Read, Write};

const COMMAND_PADDING_CONTINUE: u8 = 0x00;
const COMMAND_PADDING_END: u8 = 0x01;
const COMMAND_PADDING_DIRECT: u8 = 0x02;
const MAX_PADDING: usize = 255;

#[derive(Clone, Debug)]
pub struct VisionState {
    user_id: [u8; 16],
    checked_prefix: bool,
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
}

impl VisionEncoder {
    pub fn new(user_id: [u8; 16]) -> Self {
        Self {
            user_id: Some(user_id),
            padding_active: true,
        }
    }

    pub fn encode(&mut self, input: &[u8]) -> Vec<u8> {
        if !self.padding_active || input.is_empty() {
            return input.to_vec();
        }

        let split_at = input.len().min(u16::MAX as usize);
        let mut frame = Vec::with_capacity(16 + 5 + input.len() + MAX_PADDING);
        if let Some(user_id) = self.user_id.take() {
            frame.extend_from_slice(&user_id);
        }
        let padding = random_padding_len();
        frame.push(COMMAND_PADDING_END);
        frame.extend_from_slice(&(split_at as u16).to_be_bytes());
        frame.extend_from_slice(&(padding as u16).to_be_bytes());
        frame.extend_from_slice(&input[..split_at]);
        append_random_padding(&mut frame, padding);
        self.padding_active = false;
        if split_at < input.len() {
            frame.extend_from_slice(&input[split_at..]);
        }
        frame
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

fn random_padding_len() -> usize {
    let mut byte = [0u8; 1];
    if getrandom::getrandom(&mut byte).is_ok() {
        usize::from(byte[0])
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

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use crate::vision::{VisionReader, VisionWriter};

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
