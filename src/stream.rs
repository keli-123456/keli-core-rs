use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::thread;

use tokio::io::AsyncWriteExt;

use crate::limits::BandwidthLimiter;

pub fn relay_tcp_streams(client: TcpStream, remote: TcpStream) -> io::Result<(u64, u64)> {
    relay_tcp_streams_limited(client, remote, None)
}

pub fn relay_tcp_streams_limited(
    client: TcpStream,
    remote: TcpStream,
    limiter: Option<Arc<BandwidthLimiter>>,
) -> io::Result<(u64, u64)> {
    if limiter.is_none() {
        return relay_tcp_streams_async(client, remote);
    }

    let mut client_read = client.try_clone()?;
    let mut client_write = client;
    let mut remote_read = remote.try_clone()?;
    let mut remote_write = remote;

    let upload_limiter = limiter.clone();
    let upload_thread = thread::spawn(move || {
        let bytes = copy_count_best_effort_limited(
            &mut client_read,
            &mut remote_write,
            upload_limiter.as_deref(),
        );
        let _ = remote_write.shutdown(Shutdown::Write);
        bytes
    });
    let download =
        copy_count_best_effort_limited(&mut remote_read, &mut client_write, limiter.as_deref());
    let _ = client_write.shutdown(Shutdown::Write);
    let upload = upload_thread
        .join()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "upload relay thread panicked"))?;

    Ok((upload, download))
}

fn relay_tcp_streams_async(client: TcpStream, remote: TcpStream) -> io::Result<(u64, u64)> {
    client.set_nonblocking(true)?;
    remote.set_nonblocking(true)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    runtime.block_on(async move {
        let mut client = tokio::net::TcpStream::from_std(client)?;
        let mut remote = tokio::net::TcpStream::from_std(remote)?;
        let transferred = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
        let _ = client.shutdown().await;
        let _ = remote.shutdown().await;
        transferred
    })
}

pub fn copy_count_best_effort<R, W>(reader: &mut R, writer: &mut W) -> u64
where
    R: Read,
    W: Write,
{
    copy_count_best_effort_limited(reader, writer, None)
}

pub fn copy_count_best_effort_limited<R, W>(
    reader: &mut R,
    writer: &mut W,
    limiter: Option<&BandwidthLimiter>,
) -> u64
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
        if let Some(limiter) = limiter {
            limiter.wait_for(read);
        }
        if writer.write_all(&buffer[..read]).is_err() {
            break;
        }
        total = total.saturating_add(read as u64);
    }
    total
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::limits::BandwidthLimiter;
    use crate::stream::copy_count_best_effort_limited;

    #[test]
    fn limited_copy_still_counts_transferred_bytes() {
        let input = b"hello".to_vec();
        let limiter = BandwidthLimiter::new(1024 * 1024 * 1024);
        let mut reader = Cursor::new(input);
        let mut output = Vec::new();

        let copied = copy_count_best_effort_limited(&mut reader, &mut output, Some(&limiter));

        assert_eq!(copied, 5);
        assert_eq!(output, b"hello");
    }
}
