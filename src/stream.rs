use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, OnceLock};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::limits::BandwidthLimiter;

static TCP_RELAY_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

pub fn relay_tcp_streams(client: TcpStream, remote: TcpStream) -> io::Result<(u64, u64)> {
    relay_tcp_streams_limited(client, remote, None)
}

pub fn relay_tcp_streams_limited(
    client: TcpStream,
    remote: TcpStream,
    limiter: Option<Arc<BandwidthLimiter>>,
) -> io::Result<(u64, u64)> {
    relay_tcp_streams_async(client, remote, limiter)
}

fn relay_tcp_streams_async(
    client: TcpStream,
    remote: TcpStream,
    limiter: Option<Arc<BandwidthLimiter>>,
) -> io::Result<(u64, u64)> {
    client.set_nonblocking(true)?;
    remote.set_nonblocking(true)?;
    tcp_relay_runtime()?.block_on(async move {
        let client = tokio::net::TcpStream::from_std(client)?;
        let remote = tokio::net::TcpStream::from_std(remote)?;
        let (mut client_read, mut client_write) = client.into_split();
        let (mut remote_read, mut remote_write) = remote.into_split();
        let upload_limiter = limiter.clone();
        let upload = copy_count_best_effort_limited_async(
            &mut client_read,
            &mut remote_write,
            upload_limiter.as_deref(),
        );
        let download = copy_count_best_effort_limited_async(
            &mut remote_read,
            &mut client_write,
            limiter.as_deref(),
        );
        let (upload, download) = tokio::join!(upload, download);
        Ok((upload, download))
    })
}

fn tcp_relay_runtime() -> io::Result<&'static tokio::runtime::Runtime> {
    if let Some(runtime) = TCP_RELAY_RUNTIME.get() {
        return Ok(runtime);
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(tcp_relay_worker_threads())
        .thread_name("keli-core-tcp-relay")
        .enable_io()
        .enable_time()
        .build()?;
    match TCP_RELAY_RUNTIME.set(runtime) {
        Ok(()) => Ok(TCP_RELAY_RUNTIME
            .get()
            .expect("tcp relay runtime initialized")),
        Err(_) => Ok(TCP_RELAY_RUNTIME
            .get()
            .expect("tcp relay runtime initialized by another thread")),
    }
}

fn tcp_relay_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .clamp(2, 16)
}

async fn copy_count_best_effort_limited_async<R, W>(
    reader: &mut R,
    writer: &mut W,
    limiter: Option<&BandwidthLimiter>,
) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => break,
        };
        if let Some(limiter) = limiter {
            limiter.wait_for_async(read).await;
        }
        if writer.write_all(&buffer[..read]).await.is_err() {
            break;
        }
        total = total.saturating_add(read as u64);
    }
    let _ = writer.shutdown().await;
    total
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
