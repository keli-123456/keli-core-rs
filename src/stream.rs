use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::thread;

pub fn relay_tcp_streams(client: TcpStream, remote: TcpStream) -> io::Result<(u64, u64)> {
    let mut client_read = client.try_clone()?;
    let mut client_write = client;
    let mut remote_read = remote.try_clone()?;
    let mut remote_write = remote;

    let upload_thread = thread::spawn(move || {
        let bytes = copy_count_best_effort(&mut client_read, &mut remote_write);
        let _ = remote_write.shutdown(Shutdown::Write);
        bytes
    });
    let download = copy_count_best_effort(&mut remote_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
    let upload = upload_thread
        .join()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "upload relay thread panicked"))?;

    Ok((upload, download))
}

pub fn copy_count_best_effort<R, W>(reader: &mut R, writer: &mut W) -> u64
where
    R: Read,
    W: Write,
{
    let mut total = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => break,
        };
        if writer.write_all(&buffer[..read]).is_err() {
            break;
        }
        total = total.saturating_add(read as u64);
    }
    total
}
