use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::limits::BandwidthLimiter;

static TCP_RELAY_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static NATIVE_RELAY_POOL: OnceLock<NativeRelayPool> = OnceLock::new();

pub type BlockingRelayHandle<T> = tokio::task::JoinHandle<T>;
type NativeRelayJob = Box<dyn FnOnce() + Send + 'static>;

pub struct NativeRelayHandle<T> {
    receiver: mpsc::Receiver<thread::Result<T>>,
}

impl<T> std::fmt::Debug for NativeRelayHandle<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeRelayHandle")
            .finish_non_exhaustive()
    }
}

struct NativeRelayPool {
    queue: Mutex<VecDeque<NativeRelayJob>>,
    ready: Condvar,
    worker_count: AtomicUsize,
    idle_count: AtomicUsize,
    pending_count: AtomicUsize,
    max_workers: usize,
}

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

pub fn spawn_blocking_relay<F, T>(task: F) -> io::Result<BlockingRelayHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    Ok(tcp_relay_runtime()?.spawn_blocking(task))
}

pub fn spawn_background_io<F>(future: F) -> io::Result<tokio::task::JoinHandle<F::Output>>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    Ok(tcp_relay_runtime()?.spawn(future))
}

pub fn join_blocking_relay<T>(
    handle: BlockingRelayHandle<T>,
    panic_message: &'static str,
) -> io::Result<T> {
    tcp_relay_runtime()?
        .block_on(handle)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, panic_message))
}

pub fn spawn_native_blocking_relay<F, T>(task: F) -> io::Result<NativeRelayHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    let job = Box::new(move || {
        let _ = sender.send(std::panic::catch_unwind(std::panic::AssertUnwindSafe(task)));
    });
    native_relay_pool().submit(job)?;
    Ok(NativeRelayHandle { receiver })
}

pub fn join_native_blocking_relay<T>(
    handle: NativeRelayHandle<T>,
    panic_message: &'static str,
) -> io::Result<T> {
    match handle.receiver.recv() {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err(io::Error::new(io::ErrorKind::Other, panic_message)),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "native relay task exited without result",
        )),
    }
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
        .max_blocking_threads(tcp_relay_blocking_threads())
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

fn tcp_relay_blocking_threads() -> usize {
    std::thread::available_parallelism()
        .map(|threads| usize::from(threads).saturating_mul(64))
        .unwrap_or(128)
        .clamp(64, 512)
}

impl NativeRelayPool {
    fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
            worker_count: AtomicUsize::new(0),
            idle_count: AtomicUsize::new(0),
            pending_count: AtomicUsize::new(0),
            max_workers: native_relay_worker_threads(),
        }
    }

    fn submit(&'static self, job: NativeRelayJob) -> io::Result<()> {
        if !self.ensure_worker_available() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to spawn native relay worker",
            ));
        }

        self.pending_count.fetch_add(1, Ordering::Relaxed);
        {
            let mut queue = self.queue.lock().expect("native relay queue lock poisoned");
            queue.push_back(job);
        }
        self.ready.notify_one();
        self.spawn_extra_worker_if_needed();
        Ok(())
    }

    fn ensure_worker_available(&'static self) -> bool {
        if self.worker_count.load(Ordering::Acquire) > 0 {
            return true;
        }
        self.spawn_worker()
    }

    fn spawn_extra_worker_if_needed(&'static self) {
        let pending = self.pending_count.load(Ordering::Relaxed);
        let idle = self.idle_count.load(Ordering::Relaxed);
        if pending > idle {
            let _ = self.spawn_worker();
        }
    }

    fn spawn_worker(&'static self) -> bool {
        loop {
            let current = self.worker_count.load(Ordering::Acquire);
            if current >= self.max_workers {
                return current > 0;
            }
            if self
                .worker_count
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            let pool = self;
            let spawned = thread::Builder::new()
                .name("keli-core-native-relay".to_string())
                .stack_size(native_relay_stack_size())
                .spawn(move || pool.run_worker());
            if spawned.is_ok() {
                return true;
            }
            self.worker_count.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
    }

    fn run_worker(&'static self) {
        loop {
            let Some(job) = self.wait_for_job() else {
                self.worker_count.fetch_sub(1, Ordering::AcqRel);
                break;
            };
            self.pending_count.fetch_sub(1, Ordering::Relaxed);
            job();
        }
    }

    fn wait_for_job(&'static self) -> Option<NativeRelayJob> {
        let mut queue = self.queue.lock().expect("native relay queue lock poisoned");
        loop {
            if let Some(job) = queue.pop_front() {
                return Some(job);
            }

            self.idle_count.fetch_add(1, Ordering::Relaxed);
            let (next_queue, wait_result) = self
                .ready
                .wait_timeout(queue, native_relay_idle_timeout())
                .expect("native relay queue lock poisoned");
            self.idle_count.fetch_sub(1, Ordering::Relaxed);
            queue = next_queue;

            if wait_result.timed_out()
                && queue.is_empty()
                && self.pending_count.load(Ordering::Acquire) == 0
            {
                return None;
            }
        }
    }
}

fn native_relay_pool() -> &'static NativeRelayPool {
    NATIVE_RELAY_POOL.get_or_init(NativeRelayPool::new)
}

fn native_relay_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(|threads| usize::from(threads).saturating_mul(128))
        .unwrap_or(256)
        .clamp(256, 4096)
}

fn native_relay_stack_size() -> usize {
    512 * 1024
}

fn native_relay_idle_timeout() -> Duration {
    Duration::from_secs(30)
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
        if limiter.map(BandwidthLimiter::is_revoked).unwrap_or(false) {
            break;
        }
        let read = match limiter {
            Some(limiter) => {
                tokio::select! {
                    read = reader.read(&mut buffer) => match read {
                        Ok(0) => break,
                        Ok(read) => read,
                        Err(_) => break,
                    },
                    _ = wait_for_limiter_revoke(limiter) => break,
                }
            }
            None => match reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(read) => read,
                Err(_) => break,
            },
        };
        if let Some(limiter) = limiter {
            if !limiter.wait_for_async(read).await {
                break;
            }
        }
        if writer.write_all(&buffer[..read]).await.is_err() {
            break;
        }
        total = total.saturating_add(read as u64);
    }
    let _ = writer.shutdown().await;
    total
}

async fn wait_for_limiter_revoke(limiter: &BandwidthLimiter) {
    while !limiter.is_revoked() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
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
            if !limiter.wait_for(read) {
                break;
            }
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
    use std::io::{Cursor, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use crate::limits::{BandwidthLimiter, UserBandwidthLimiters};
    use crate::stream::{
        copy_count_best_effort_limited, join_native_blocking_relay, relay_tcp_streams_limited,
        spawn_native_blocking_relay,
    };
    use crate::user::CoreUser;

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

    #[test]
    fn revoked_limiter_stops_limited_copy_before_forwarding_bytes() {
        let input = b"blocked".to_vec();
        let limiter = BandwidthLimiter::unlimited();
        limiter.revoke();
        let mut reader = Cursor::new(input);
        let mut output = Vec::new();

        let copied = copy_count_best_effort_limited(&mut reader, &mut output, Some(&limiter));

        assert_eq!(copied, 0);
        assert!(output.is_empty());
    }

    #[test]
    fn async_tcp_relay_exits_when_user_limiter_is_revoked_while_idle() {
        let client_listener = TcpListener::bind("127.0.0.1:0").expect("client bind");
        let remote_listener = TcpListener::bind("127.0.0.1:0").expect("remote bind");
        let client_addr = client_listener.local_addr().expect("client addr");
        let remote_addr = remote_listener.local_addr().expect("remote addr");
        let client_peer = thread::spawn(move || TcpStream::connect(client_addr).expect("client"));
        let remote_peer = thread::spawn(move || TcpStream::connect(remote_addr).expect("remote"));
        let (client, _) = client_listener.accept().expect("client accept");
        let (remote, _) = remote_listener.accept().expect("remote accept");
        let mut client_peer = client_peer.join().expect("client thread");
        let mut remote_peer = remote_peer.join().expect("remote thread");
        let limiters = UserBandwidthLimiters::default();
        let user = CoreUser {
            id: 1,
            uuid: "user-a".to_string(),
            password: None,
            email: None,
            speed_limit: 0,
            device_limit: 0,
        };
        let limiter = limiters.limiter_for(Some(&user)).expect("limiter");
        let (done_tx, done_rx) = mpsc::channel();
        let relay = thread::spawn(move || {
            let result = relay_tcp_streams_limited(client, remote, Some(limiter));
            done_tx.send(result).expect("send relay result");
        });

        thread::sleep(Duration::from_millis(100));
        limiters.revoke_users(std::slice::from_ref(&user.uuid));

        let result = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("relay should exit after revoke")
            .expect("relay result");
        assert_eq!(result, (0, 0));
        let _ = client_peer.write_all(b"x");
        let mut byte = [0u8; 1];
        client_peer
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("client timeout");
        assert!(matches!(client_peer.read(&mut byte), Ok(0) | Err(_)));
        remote_peer
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("remote timeout");
        assert!(matches!(remote_peer.read(&mut byte), Ok(0) | Err(_)));
        relay.join().expect("relay thread");
    }

    #[test]
    fn native_relay_pool_returns_task_result() {
        let handle = spawn_native_blocking_relay(|| 42).expect("spawn native relay");
        let value = join_native_blocking_relay(handle, "native relay panicked").expect("join");
        assert_eq!(value, 42);
    }

    #[test]
    fn native_relay_pool_reports_panics() {
        let handle =
            spawn_native_blocking_relay(|| panic!("expected panic")).expect("spawn native relay");
        let error = join_native_blocking_relay::<()>(handle, "native relay panicked")
            .expect_err("panic should be reported");
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn native_relay_pool_handles_bursts() {
        let handles = (0..64)
            .map(|index| spawn_native_blocking_relay(move || index).expect("spawn native relay"))
            .collect::<Vec<_>>();

        let mut values = handles
            .into_iter()
            .map(|handle| {
                join_native_blocking_relay(handle, "native relay panicked").expect("join")
            })
            .collect::<Vec<_>>();
        values.sort_unstable();

        assert_eq!(values, (0..64).collect::<Vec<_>>());
    }
}
