use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::limits::BandwidthLimiter;
use crate::quic_resources::{available_parallelism_count, memory_limit_mib, open_file_soft_limit};

static TCP_RELAY_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static NATIVE_RELAY_POOL: OnceLock<NativeRelayPool> = OnceLock::new();
static NATIVE_RELAY_ACTIVE: OnceLock<Mutex<BTreeMap<&'static str, usize>>> = OnceLock::new();
static ASYNC_RELAY_ACTIVE: OnceLock<Mutex<BTreeMap<&'static str, usize>>> = OnceLock::new();
static DETACHED_BLOCKING_RELAY_ACTIVE: OnceLock<Mutex<BTreeMap<&'static str, usize>>> =
    OnceLock::new();
// Keep per-direction relay buffers modest; thousands of active TCP relays otherwise amplify RSS.
const RELAY_COPY_BUFFER_SIZE: usize = 16 * 1024;
const TCP_RELAY_BLOCKING_THREADS_MIN: usize = 16;
const TCP_RELAY_BLOCKING_THREADS_MAX: usize = 128;
const TCP_RELAY_BLOCKING_THREADS_PER_CPU: usize = 16;
const TCP_RELAY_BLOCKING_THREAD_MEMORY_MIB: usize = 4;
const NATIVE_RELAY_WORKERS_MIN: usize = 16;
const NATIVE_RELAY_WORKERS_MAX: usize = 512;
const NATIVE_RELAY_WORKERS_PER_CPU: usize = 64;
const NATIVE_RELAY_WORKER_MEMORY_MIB: usize = 4;
const NATIVE_RELAY_RESERVED_FDS: usize = 1024;
const NATIVE_RELAY_FDS_PER_WORKER: usize = 4;
const WINDOWS_NATIVE_RELAY_STACK_KIB: usize = 2048;
const UNIX_NATIVE_RELAY_STACK_KIB: usize = 256;
const MIN_NATIVE_RELAY_STACK_KIB: usize = 128;
const MAX_NATIVE_RELAY_STACK_KIB: usize = 8192;
const NATIVE_RELAY_STACK_ENV: &str = "KELI_CORE_NATIVE_RELAY_STACK_KIB";
const UNIX_NATIVE_RELAY_STACK_BUDGET_MIB: usize = 64;
const UNIX_NATIVE_RELAY_STACK_MEMORY_BUDGET_DIVISOR: usize = 8;
const WINDOWS_DETACHED_BLOCKING_RELAY_STACK_KIB: usize = 2048;
// VLESS/Trojan WS+TLS relay frames can nest TLS/WebSocket buffers deeply enough to
// overflow 128 KiB stacks under real Linux traffic. Keep Linux at 256 KiB until
// these relays move to the async runtime instead of detached OS threads.
const UNIX_DETACHED_BLOCKING_RELAY_STACK_KIB: usize = 256;
const MIN_DETACHED_BLOCKING_RELAY_STACK_KIB: usize = 64;
const MAX_DETACHED_BLOCKING_RELAY_STACK_KIB: usize = 8192;
const DETACHED_BLOCKING_RELAY_STACK_ENV: &str = "KELI_CORE_DETACHED_RELAY_STACK_KIB";

pub type BlockingRelayHandle<T> = tokio::task::JoinHandle<T>;
type NativeRelayTask = Box<dyn FnOnce() + Send + 'static>;

struct NativeRelayJob {
    label: &'static str,
    enqueued_at: Instant,
    task: NativeRelayTask,
}

#[derive(Debug)]
pub(crate) struct RelayActivityDeadline {
    idle_since: Instant,
    one_side_finished_since: Option<Instant>,
}

impl RelayActivityDeadline {
    pub(crate) fn new() -> Self {
        Self {
            idle_since: Instant::now(),
            one_side_finished_since: None,
        }
    }

    pub(crate) fn elapsed(&mut self, upload_done: bool, download_done: bool) -> Duration {
        if upload_done ^ download_done {
            self.one_side_finished_since
                .get_or_insert_with(Instant::now)
                .elapsed()
        } else {
            self.idle_since.elapsed()
        }
    }

    pub(crate) fn note_progress(&mut self, upload_done: bool, download_done: bool) {
        if upload_done ^ download_done {
            self.one_side_finished_since
                .get_or_insert_with(Instant::now);
        } else {
            self.idle_since = Instant::now();
            self.one_side_finished_since = None;
        }
    }
}

pub struct NativeRelayHandle<T> {
    receiver: mpsc::Receiver<thread::Result<T>>,
}

pub struct DetachedBlockingRelayHandle<T> {
    receiver: mpsc::Receiver<thread::Result<T>>,
}

impl<T> std::fmt::Debug for NativeRelayHandle<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeRelayHandle")
            .finish_non_exhaustive()
    }
}

impl<T> std::fmt::Debug for DetachedBlockingRelayHandle<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DetachedBlockingRelayHandle")
            .finish_non_exhaustive()
    }
}

struct NativeRelayPool {
    queue: Mutex<NativeRelayQueueState>,
    ready: Condvar,
    worker_count: AtomicUsize,
    idle_count: AtomicUsize,
    pending_count: AtomicUsize,
    max_workers: AtomicUsize,
    label_soft_limit: AtomicUsize,
    dynamic_limits: AtomicBool,
}

struct NativeRelayActiveLabelGuard {
    pool: &'static NativeRelayPool,
    label: &'static str,
}

impl Drop for NativeRelayActiveLabelGuard {
    fn drop(&mut self) {
        self.pool.finish_job_label(self.label);
    }
}

#[derive(Default)]
struct NativeRelayQueueState {
    jobs: VecDeque<NativeRelayJob>,
    active_by_label: BTreeMap<&'static str, usize>,
    queue_wait_ms_by_label: BTreeMap<&'static str, u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RelaySchedulerMetricsSnapshot {
    pub active_native: BTreeMap<String, usize>,
    pub active_async: BTreeMap<String, usize>,
    pub active_detached_blocking: BTreeMap<String, usize>,
    pub native_worker_count: usize,
    pub native_idle_count: usize,
    pub native_pending_count: usize,
    pub native_label_soft_limit: usize,
    pub native_pending_by_label: BTreeMap<String, usize>,
    pub native_queue_wait_ms_by_label: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NativeRelayPoolSnapshot {
    worker_count: usize,
    idle_count: usize,
    pending_count: usize,
    label_soft_limit: usize,
    pending_by_label: BTreeMap<String, usize>,
    queue_wait_ms_by_label: BTreeMap<String, u64>,
}

pub fn relay_tcp_streams(client: TcpStream, remote: TcpStream) -> io::Result<(u64, u64)> {
    relay_tcp_fast_unlimited(client, remote)
}

pub fn relay_tcp_fast_unlimited(client: TcpStream, remote: TcpStream) -> io::Result<(u64, u64)> {
    relay_tcp_streams_unlimited_native(client, remote, false)
}

pub fn relay_tcp_fast_unlimited_close_on_eof(
    client: TcpStream,
    remote: TcpStream,
) -> io::Result<(u64, u64)> {
    relay_tcp_streams_unlimited_native(client, remote, true)
}

pub fn spawn_tcp_relay_background<F>(
    client: TcpStream,
    remote: TcpStream,
    limiter: Option<Arc<BandwidthLimiter>>,
    close_peer_on_eof: bool,
    on_finish: F,
) -> io::Result<tokio::task::JoinHandle<()>>
where
    F: FnOnce(u64, u64) + Send + 'static,
{
    let upload_client_shutdown = client.try_clone()?;
    let upload_remote_shutdown = remote.try_clone()?;
    let download_client_shutdown = client.try_clone()?;
    let download_remote_shutdown = remote.try_clone()?;

    client.set_nonblocking(true)?;
    remote.set_nonblocking(true)?;

    spawn_background_io(async move {
        let (upload, download) = match (
            tokio::net::TcpStream::from_std(client),
            tokio::net::TcpStream::from_std(remote),
        ) {
            (Ok(client), Ok(remote)) => {
                let (mut client_read, mut client_write) = client.into_split();
                let (mut remote_read, mut remote_write) = remote.into_split();
                if let Some(limiter) = limiter {
                    let upload = copy_count_best_effort_limited_async(
                        &mut client_read,
                        &mut remote_write,
                        Some(limiter.as_ref()),
                    );
                    let download = copy_count_best_effort_limited_async(
                        &mut remote_read,
                        &mut client_write,
                        Some(limiter.as_ref()),
                    );
                    tokio::join!(upload, download)
                } else {
                    let upload = relay_copy_unlimited_async(
                        &mut client_read,
                        &mut remote_write,
                        upload_client_shutdown,
                        upload_remote_shutdown,
                        close_peer_on_eof,
                    );
                    let download = relay_copy_unlimited_async(
                        &mut remote_read,
                        &mut client_write,
                        download_client_shutdown,
                        download_remote_shutdown,
                        close_peer_on_eof,
                    );
                    tokio::join!(upload, download)
                }
            }
            (client_result, remote_result) => {
                if let Ok(client) = client_result {
                    let _ = client
                        .into_std()
                        .map(|stream| stream.shutdown(Shutdown::Both));
                }
                if let Ok(remote) = remote_result {
                    let _ = remote
                        .into_std()
                        .map(|stream| stream.shutdown(Shutdown::Both));
                }
                (0, 0)
            }
        };
        on_finish(upload, download);
    })
}

pub fn relay_tcp_limited(
    client: TcpStream,
    remote: TcpStream,
    limiter: Arc<BandwidthLimiter>,
) -> io::Result<(u64, u64)> {
    relay_tcp_streams_limited(client, remote, Some(limiter))
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

pub fn spawn_detached_blocking_relay<F, T>(name: &'static str, task: F) -> io::Result<()>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let _ = spawn_detached_blocking_relay_with_handle(name, task)?;
    Ok(())
}

pub fn spawn_detached_blocking_relay_with_handle<F, T>(
    name: &'static str,
    task: F,
) -> io::Result<DetachedBlockingRelayHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name(name.to_string())
        .stack_size(detached_blocking_relay_stack_size())
        .spawn(move || {
            let _metrics = DetachedBlockingRelayMetricsGuard::new(name);
            let _ = sender.send(std::panic::catch_unwind(std::panic::AssertUnwindSafe(task)));
        })?;
    Ok(DetachedBlockingRelayHandle { receiver })
}

pub(crate) struct DetachedBlockingRelayMetricsGuard {
    name: &'static str,
}

impl DetachedBlockingRelayMetricsGuard {
    pub(crate) fn new(name: &'static str) -> Self {
        {
            let mut active = detached_blocking_relay_metrics()
                .lock()
                .expect("detached blocking relay metrics poisoned");
            let count = active.entry(name).or_default();
            *count = count.saturating_add(1);
        }
        Self { name }
    }
}

impl Drop for DetachedBlockingRelayMetricsGuard {
    fn drop(&mut self) {
        let mut active = detached_blocking_relay_metrics()
            .lock()
            .expect("detached blocking relay metrics poisoned");
        let Some(count) = active.get_mut(self.name) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            active.remove(self.name);
        }
    }
}

pub(crate) fn detached_blocking_relay_metrics_snapshot() -> BTreeMap<String, usize> {
    detached_blocking_relay_metrics()
        .lock()
        .expect("detached blocking relay metrics poisoned")
        .iter()
        .map(|(name, count)| ((*name).to_string(), *count))
        .collect()
}

fn detached_blocking_relay_metrics() -> &'static Mutex<BTreeMap<&'static str, usize>> {
    DETACHED_BLOCKING_RELAY_ACTIVE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(crate) struct NativeRelayMetricsGuard {
    name: &'static str,
}

impl NativeRelayMetricsGuard {
    pub(crate) fn new(name: &'static str) -> Self {
        {
            let mut active = native_relay_metrics()
                .lock()
                .expect("native relay metrics poisoned");
            let count = active.entry(name).or_default();
            *count = count.saturating_add(1);
        }
        Self { name }
    }
}

impl Drop for NativeRelayMetricsGuard {
    fn drop(&mut self) {
        let mut active = native_relay_metrics()
            .lock()
            .expect("native relay metrics poisoned");
        let Some(count) = active.get_mut(self.name) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            active.remove(self.name);
        }
    }
}

pub(crate) fn native_relay_metrics_snapshot() -> BTreeMap<String, usize> {
    native_relay_metrics()
        .lock()
        .expect("native relay metrics poisoned")
        .iter()
        .map(|(name, count)| ((*name).to_string(), *count))
        .collect()
}

fn native_relay_metrics() -> &'static Mutex<BTreeMap<&'static str, usize>> {
    NATIVE_RELAY_ACTIVE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(crate) struct AsyncRelayMetricsGuard {
    name: &'static str,
}

impl AsyncRelayMetricsGuard {
    pub(crate) fn new(name: &'static str) -> Self {
        {
            let mut active = async_relay_metrics()
                .lock()
                .expect("async relay metrics poisoned");
            let count = active.entry(name).or_default();
            *count = count.saturating_add(1);
        }
        Self { name }
    }
}

impl Drop for AsyncRelayMetricsGuard {
    fn drop(&mut self) {
        let mut active = async_relay_metrics()
            .lock()
            .expect("async relay metrics poisoned");
        let Some(count) = active.get_mut(self.name) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            active.remove(self.name);
        }
    }
}

fn async_relay_metrics_snapshot() -> BTreeMap<String, usize> {
    async_relay_metrics()
        .lock()
        .expect("async relay metrics poisoned")
        .iter()
        .map(|(name, count)| ((*name).to_string(), *count))
        .collect()
}

fn async_relay_metrics() -> &'static Mutex<BTreeMap<&'static str, usize>> {
    ASYNC_RELAY_ACTIVE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub fn spawn_background_io<F>(future: F) -> io::Result<tokio::task::JoinHandle<F::Output>>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    Ok(tcp_relay_runtime()?.spawn(future))
}

pub fn spawn_async_relay<F>(
    name: &'static str,
    future: F,
) -> io::Result<tokio::task::JoinHandle<F::Output>>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let task = async move {
        let _metrics = AsyncRelayMetricsGuard::new(name);
        future.await
    };
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => Ok(handle.spawn(task)),
        Err(_) => spawn_background_io(task),
    }
}

pub(crate) fn relay_scheduler_metrics_snapshot() -> RelaySchedulerMetricsSnapshot {
    let native = native_relay_pool().snapshot();
    RelaySchedulerMetricsSnapshot {
        active_native: native_relay_metrics_snapshot(),
        active_async: async_relay_metrics_snapshot(),
        active_detached_blocking: detached_blocking_relay_metrics_snapshot(),
        native_worker_count: native.worker_count,
        native_idle_count: native.idle_count,
        native_pending_count: native.pending_count,
        native_label_soft_limit: native.label_soft_limit,
        native_pending_by_label: native.pending_by_label,
        native_queue_wait_ms_by_label: native.queue_wait_ms_by_label,
    }
}

pub(crate) fn format_relay_scheduler_metrics(snapshot: RelaySchedulerMetricsSnapshot) -> String {
    let mut fields = Vec::new();
    for (name, count) in snapshot.active_native {
        fields.push(format!("relay_active_native.{name}={count}"));
    }
    for (name, count) in snapshot.active_async {
        fields.push(format!("relay_active_async.{name}={count}"));
    }
    for (name, count) in snapshot.active_detached_blocking {
        fields.push(format!("relay_active_blocking.{name}={count}"));
    }
    fields.push(format!(
        "native_relay_workers={}",
        snapshot.native_worker_count
    ));
    fields.push(format!("native_relay_idle={}", snapshot.native_idle_count));
    fields.push(format!(
        "native_relay_pending={}",
        snapshot.native_pending_count
    ));
    fields.push(format!(
        "native_relay_label_soft_limit={}",
        snapshot.native_label_soft_limit
    ));
    for (name, count) in snapshot.native_pending_by_label {
        fields.push(format!("native_relay_pending.{name}={count}"));
    }
    for (name, wait_ms) in snapshot.native_queue_wait_ms_by_label {
        fields.push(format!("native_relay_queue_wait_ms.{name}={wait_ms}"));
    }
    fields.join(" ")
}

pub fn join_blocking_relay<T>(
    handle: BlockingRelayHandle<T>,
    panic_message: &'static str,
) -> io::Result<T> {
    tcp_relay_runtime()?
        .block_on(handle)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, panic_message))
}

pub fn join_async_relay<T>(
    handle: tokio::task::JoinHandle<T>,
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
    spawn_named_native_blocking_relay("keli-core-native-relay", task)
}

pub fn spawn_named_native_blocking_relay<F, T>(
    name: &'static str,
    task: F,
) -> io::Result<NativeRelayHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    let job = Box::new(move || {
        let _metrics = NativeRelayMetricsGuard::new(name);
        let _ = sender.send(std::panic::catch_unwind(std::panic::AssertUnwindSafe(task)));
    });
    native_relay_pool().submit_named(name, job)?;
    Ok(NativeRelayHandle { receiver })
}

pub fn spawn_detached_native_relay<F, T>(name: &'static str, task: F) -> io::Result<()>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let _ = spawn_named_native_blocking_relay(name, task)?;
    Ok(())
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

pub fn join_detached_blocking_relay<T>(
    handle: DetachedBlockingRelayHandle<T>,
    panic_message: &'static str,
) -> io::Result<T> {
    match handle.receiver.recv() {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err(io::Error::new(io::ErrorKind::Other, panic_message)),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "detached blocking relay task exited without result",
        )),
    }
}

fn relay_tcp_streams_async(
    client: TcpStream,
    remote: TcpStream,
    limiter: Option<Arc<BandwidthLimiter>>,
) -> io::Result<(u64, u64)> {
    if limiter.is_none() {
        return relay_tcp_streams_unlimited_native(client, remote, false);
    }
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

fn relay_tcp_streams_unlimited_native(
    client: TcpStream,
    remote: TcpStream,
    close_peer_on_eof: bool,
) -> io::Result<(u64, u64)> {
    relay_tcp_streams_unlimited_tokio(client, remote, close_peer_on_eof)
}

fn shutdown_tcp_pair(client: Option<&TcpStream>, remote: Option<&TcpStream>) {
    if let Some(client) = client {
        let _ = client.shutdown(Shutdown::Both);
    }
    if let Some(remote) = remote {
        let _ = remote.shutdown(Shutdown::Both);
    }
}

fn relay_tcp_streams_unlimited_tokio(
    client: TcpStream,
    remote: TcpStream,
    close_peer_on_eof: bool,
) -> io::Result<(u64, u64)> {
    let upload_client_shutdown = client.try_clone()?;
    let upload_remote_shutdown = remote.try_clone()?;
    let download_client_shutdown = client.try_clone()?;
    let download_remote_shutdown = remote.try_clone()?;

    client.set_nonblocking(true)?;
    remote.set_nonblocking(true)?;

    tcp_relay_runtime()?.block_on(async move {
        let client = tokio::net::TcpStream::from_std(client)?;
        let remote = tokio::net::TcpStream::from_std(remote)?;
        let (mut client_read, mut client_write) = client.into_split();
        let (mut remote_read, mut remote_write) = remote.into_split();

        let upload = relay_copy_unlimited_async(
            &mut client_read,
            &mut remote_write,
            upload_client_shutdown,
            upload_remote_shutdown,
            close_peer_on_eof,
        );
        let download = relay_copy_unlimited_async(
            &mut remote_read,
            &mut client_write,
            download_client_shutdown,
            download_remote_shutdown,
            close_peer_on_eof,
        );
        let (upload, download) = tokio::join!(upload, download);
        Ok((upload, download))
    })
}

async fn relay_copy_unlimited_async<R, W>(
    reader: &mut R,
    writer: &mut W,
    client_shutdown: TcpStream,
    remote_shutdown: TcpStream,
    close_peer_on_eof: bool,
) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    let mut buffer = [0u8; RELAY_COPY_BUFFER_SIZE];
    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => break,
        };
        if writer.write_all(&buffer[..read]).await.is_err() {
            break;
        }
        total = total.saturating_add(read as u64);
    }

    if close_peer_on_eof {
        shutdown_tcp_pair(Some(&client_shutdown), Some(&remote_shutdown));
    } else {
        let _ = writer.shutdown().await;
    }
    total
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
    available_parallelism_count().clamp(2, 16)
}

fn tcp_relay_blocking_threads() -> usize {
    tcp_relay_blocking_threads_from_resources(available_parallelism_count(), memory_limit_mib())
}

fn detached_blocking_relay_stack_size() -> usize {
    detached_blocking_relay_stack_size_from_env(
        std::env::var(DETACHED_BLOCKING_RELAY_STACK_ENV).ok(),
        detached_blocking_relay_default_stack_kib(cfg!(windows)),
    )
}

fn detached_blocking_relay_default_stack_kib(is_windows: bool) -> usize {
    if is_windows {
        WINDOWS_DETACHED_BLOCKING_RELAY_STACK_KIB
    } else {
        UNIX_DETACHED_BLOCKING_RELAY_STACK_KIB
    }
}

fn detached_blocking_relay_stack_size_from_env(value: Option<String>, default_kib: usize) -> usize {
    let stack_kib = value
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(default_kib)
        .clamp(
            MIN_DETACHED_BLOCKING_RELAY_STACK_KIB,
            MAX_DETACHED_BLOCKING_RELAY_STACK_KIB,
        );
    stack_kib * 1024
}

impl NativeRelayPool {
    fn new() -> Self {
        let max_workers = native_relay_worker_threads();
        Self::with_limits(
            max_workers,
            native_relay_label_soft_limit(max_workers),
            true,
        )
    }

    #[cfg(test)]
    fn with_max_workers(max_workers: usize) -> Self {
        Self::with_limits(
            max_workers,
            native_relay_label_soft_limit(max_workers),
            false,
        )
    }

    fn with_limits(max_workers: usize, label_soft_limit: usize, dynamic_limits: bool) -> Self {
        let max_workers = max_workers.max(1);
        Self {
            queue: Mutex::new(NativeRelayQueueState::default()),
            ready: Condvar::new(),
            worker_count: AtomicUsize::new(0),
            idle_count: AtomicUsize::new(0),
            pending_count: AtomicUsize::new(0),
            max_workers: AtomicUsize::new(max_workers),
            label_soft_limit: AtomicUsize::new(label_soft_limit.clamp(1, max_workers)),
            dynamic_limits: AtomicBool::new(dynamic_limits),
        }
    }

    #[cfg(test)]
    fn with_max_workers_for_test(max_workers: usize) -> &'static Self {
        Box::leak(Box::new(Self::with_max_workers(max_workers)))
    }

    #[cfg(test)]
    fn with_limits_for_test(max_workers: usize, label_soft_limit: usize) -> &'static Self {
        Box::leak(Box::new(Self::with_limits(
            max_workers,
            label_soft_limit,
            false,
        )))
    }

    #[cfg(test)]
    fn submit(&'static self, task: NativeRelayTask) -> io::Result<()> {
        self.submit_named("keli-core-native-relay", task)
    }

    fn submit_named(&'static self, label: &'static str, task: NativeRelayTask) -> io::Result<()> {
        self.refresh_limits();
        if !self.ensure_worker_available() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to spawn native relay worker",
            ));
        }

        self.pending_count.fetch_add(1, Ordering::Relaxed);
        {
            let mut queue = self.queue.lock().expect("native relay queue lock poisoned");
            queue.jobs.push_back(NativeRelayJob {
                label,
                enqueued_at: Instant::now(),
                task,
            });
        }
        self.ready.notify_one();
        self.spawn_extra_worker_if_needed();
        Ok(())
    }

    fn refresh_limits(&self) {
        if !self.dynamic_limits.load(Ordering::Relaxed) {
            return;
        }
        let max_workers = native_relay_worker_threads();
        self.max_workers.store(max_workers, Ordering::Release);
        self.label_soft_limit.store(
            native_relay_label_soft_limit(max_workers),
            Ordering::Release,
        );
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
        let deficit = pending.saturating_sub(idle);
        if deficit == 0 {
            return;
        }
        let workers = self.worker_count.load(Ordering::Acquire);
        let capacity = self
            .max_workers
            .load(Ordering::Acquire)
            .saturating_sub(workers);
        for _ in 0..deficit.min(capacity).min(8) {
            let _ = self.spawn_worker();
        }
    }

    fn spawn_worker(&'static self) -> bool {
        loop {
            let current = self.worker_count.load(Ordering::Acquire);
            if current >= self.max_workers.load(Ordering::Acquire) {
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
            let label = job.label;
            let _active_label = NativeRelayActiveLabelGuard { pool: self, label };
            (job.task)();
        }
    }

    fn wait_for_job(&'static self) -> Option<NativeRelayJob> {
        let mut queue = self.queue.lock().expect("native relay queue lock poisoned");
        loop {
            if let Some(index) = self.next_runnable_job_index(&queue) {
                let job = queue
                    .jobs
                    .remove(index)
                    .expect("native relay runnable job disappeared");
                let wait_ms = job
                    .enqueued_at
                    .elapsed()
                    .as_millis()
                    .min(u128::from(u64::MAX)) as u64;
                let previous = queue.queue_wait_ms_by_label.entry(job.label).or_default();
                *previous = (*previous).max(wait_ms);
                let active = queue.active_by_label.entry(job.label).or_default();
                *active = active.saturating_add(1);
                maybe_log_native_relay_queue_wait(job.label, wait_ms);
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
                && queue.jobs.is_empty()
                && self.pending_count.load(Ordering::Acquire) == 0
            {
                return None;
            }
        }
    }

    fn next_runnable_job_index(&self, queue: &NativeRelayQueueState) -> Option<usize> {
        let label_soft_limit = self.label_soft_limit.load(Ordering::Acquire).max(1);
        queue.jobs.iter().position(|job| {
            queue.active_by_label.get(job.label).copied().unwrap_or(0) < label_soft_limit
        })
    }

    fn finish_job_label(&self, label: &'static str) {
        let mut queue = self.queue.lock().expect("native relay queue lock poisoned");
        if let Some(count) = queue.active_by_label.get_mut(label) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                queue.active_by_label.remove(label);
            }
        }
        drop(queue);
        self.ready.notify_all();
    }

    fn snapshot(&self) -> NativeRelayPoolSnapshot {
        let queue = self.queue.lock().expect("native relay queue lock poisoned");
        let mut pending_by_label = BTreeMap::<String, usize>::new();
        for job in &queue.jobs {
            let count = pending_by_label.entry(job.label.to_string()).or_default();
            *count = count.saturating_add(1);
        }
        NativeRelayPoolSnapshot {
            worker_count: self.worker_count.load(Ordering::Acquire),
            idle_count: self.idle_count.load(Ordering::Acquire),
            pending_count: self.pending_count.load(Ordering::Acquire),
            label_soft_limit: self.label_soft_limit.load(Ordering::Acquire),
            pending_by_label,
            queue_wait_ms_by_label: queue
                .queue_wait_ms_by_label
                .iter()
                .map(|(label, wait_ms)| ((*label).to_string(), *wait_ms))
                .collect(),
        }
    }
}

fn native_relay_pool() -> &'static NativeRelayPool {
    NATIVE_RELAY_POOL.get_or_init(NativeRelayPool::new)
}

fn native_relay_worker_threads() -> usize {
    if let Ok(value) = std::env::var("KELI_CORE_NATIVE_RELAY_WORKERS") {
        if let Ok(parsed) = value.trim().parse::<usize>() {
            return parsed.clamp(16, 1024);
        }
    }
    native_relay_worker_threads_from_resources(
        available_parallelism_count(),
        memory_limit_mib(),
        open_file_soft_limit(),
    )
}

fn native_relay_label_soft_limit(max_workers: usize) -> usize {
    if let Ok(value) = std::env::var("KELI_CORE_NATIVE_RELAY_LABEL_WORKERS") {
        if let Ok(parsed) = value.trim().parse::<usize>() {
            return parsed.clamp(1, max_workers.max(1));
        }
    }
    native_relay_label_soft_limit_from_max_workers(max_workers)
}

fn native_relay_label_soft_limit_from_max_workers(max_workers: usize) -> usize {
    let max_workers = max_workers.max(1);
    ((max_workers / 2).max(32)).min(max_workers)
}

fn tcp_relay_blocking_threads_from_resources(
    cpu_count: usize,
    memory_limit_mib: Option<usize>,
) -> usize {
    let cpu_target = cpu_count
        .max(1)
        .saturating_mul(TCP_RELAY_BLOCKING_THREADS_PER_CPU);
    let memory_target = memory_limit_mib
        .map(|mib| mib / TCP_RELAY_BLOCKING_THREAD_MEMORY_MIB)
        .filter(|target| *target > 0)
        .unwrap_or(TCP_RELAY_BLOCKING_THREADS_MAX);
    cpu_target
        .min(memory_target)
        .min(TCP_RELAY_BLOCKING_THREADS_MAX)
        .max(TCP_RELAY_BLOCKING_THREADS_MIN)
}

fn native_relay_worker_threads_from_resources(
    cpu_count: usize,
    memory_limit_mib: Option<usize>,
    fd_limit: Option<usize>,
) -> usize {
    let cpu_target = cpu_count
        .max(1)
        .saturating_mul(NATIVE_RELAY_WORKERS_PER_CPU);
    let memory_target = memory_limit_mib
        .map(|mib| mib / NATIVE_RELAY_WORKER_MEMORY_MIB)
        .filter(|target| *target > 0)
        .unwrap_or(NATIVE_RELAY_WORKERS_MAX);
    let fd_target = fd_limit
        .map(|limit| limit.saturating_sub(NATIVE_RELAY_RESERVED_FDS) / NATIVE_RELAY_FDS_PER_WORKER)
        .filter(|target| *target > 0)
        .unwrap_or(NATIVE_RELAY_WORKERS_MAX);
    cpu_target
        .min(memory_target)
        .min(fd_target)
        .min(NATIVE_RELAY_WORKERS_MAX)
        .max(NATIVE_RELAY_WORKERS_MIN)
}

fn native_relay_stack_size() -> usize {
    let default = native_relay_default_stack_kib_from_resources(
        available_parallelism_count(),
        memory_limit_mib(),
        open_file_soft_limit(),
        cfg!(windows),
    );
    native_relay_stack_size_from_env(std::env::var(NATIVE_RELAY_STACK_ENV).ok(), default)
}

fn native_relay_default_stack_kib_from_resources(
    cpu_count: usize,
    memory_limit_mib: Option<usize>,
    fd_limit: Option<usize>,
    is_windows: bool,
) -> usize {
    if is_windows {
        return WINDOWS_NATIVE_RELAY_STACK_KIB;
    }
    let workers = native_relay_worker_threads_from_resources(cpu_count, memory_limit_mib, fd_limit);
    unix_native_relay_stack_kib_for_workers(workers, memory_limit_mib)
}

fn unix_native_relay_stack_kib_for_workers(
    worker_count: usize,
    memory_limit_mib: Option<usize>,
) -> usize {
    let memory_budget_mib = memory_limit_mib
        .map(|mib| {
            (mib / UNIX_NATIVE_RELAY_STACK_MEMORY_BUDGET_DIVISOR)
                .clamp(1, UNIX_NATIVE_RELAY_STACK_BUDGET_MIB)
        })
        .unwrap_or(UNIX_NATIVE_RELAY_STACK_BUDGET_MIB);
    let stack_kib = memory_budget_mib
        .saturating_mul(1024)
        .checked_div(worker_count.max(1))
        .unwrap_or(UNIX_NATIVE_RELAY_STACK_KIB);
    stack_kib.clamp(MIN_NATIVE_RELAY_STACK_KIB, MAX_NATIVE_RELAY_STACK_KIB)
}

fn native_relay_stack_size_from_env(value: Option<String>, default_kib: usize) -> usize {
    let stack_kib = value
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(default_kib)
        .clamp(MIN_NATIVE_RELAY_STACK_KIB, MAX_NATIVE_RELAY_STACK_KIB);
    stack_kib * 1024
}

fn native_relay_idle_timeout() -> Duration {
    Duration::from_secs(10)
}

fn native_relay_queue_wait_warn_ms() -> u64 {
    std::env::var("KELI_CORE_NATIVE_RELAY_QUEUE_WARN_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(250)
}

fn maybe_log_native_relay_queue_wait(label: &'static str, wait_ms: u64) {
    let threshold = native_relay_queue_wait_warn_ms();
    if wait_ms < threshold {
        return;
    }
    const LOG_INTERVAL: Duration = Duration::from_secs(60);
    static LAST_LOG: OnceLock<Mutex<BTreeMap<&'static str, Instant>>> = OnceLock::new();
    let last_log = LAST_LOG.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut last_log = last_log
        .lock()
        .expect("native relay queue wait log lock poisoned");
    let now = Instant::now();
    if last_log
        .get(label)
        .map(|last| last.elapsed() < LOG_INTERVAL)
        .unwrap_or(false)
    {
        return;
    }
    last_log.insert(label, now);
    crate::logging::emit_legacy_line(&format!(
        "WARN  core   native relay queue wait label={label} wait_ms={wait_ms} threshold_ms={threshold}"
    ));
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
    let mut buffer = [0u8; RELAY_COPY_BUFFER_SIZE];
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
    limiter.wait_revoked().await;
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
    let mut buffer = [0u8; RELAY_COPY_BUFFER_SIZE];
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
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use crate::limits::{BandwidthLimiter, UserBandwidthLimiters};
    #[cfg(unix)]
    use crate::stream::relay_tcp_fast_unlimited_close_on_eof;
    use crate::stream::{
        copy_count_best_effort_limited, join_native_blocking_relay, relay_tcp_fast_unlimited,
        relay_tcp_streams_limited, spawn_native_blocking_relay,
    };
    use crate::user::CoreUser;

    #[test]
    fn relay_thread_counts_scale_with_machine_resources() {
        assert_eq!(super::RELAY_COPY_BUFFER_SIZE, 16 * 1024);

        assert_eq!(
            super::tcp_relay_blocking_threads_from_resources(1, None),
            16
        );
        assert_eq!(
            super::tcp_relay_blocking_threads_from_resources(16, Some(64_000)),
            128
        );
        assert_eq!(
            super::tcp_relay_blocking_threads_from_resources(16, Some(128)),
            32
        );

        assert_eq!(
            super::native_relay_worker_threads_from_resources(4, Some(4096), Some(100_000)),
            256
        );
        assert_eq!(
            super::native_relay_worker_threads_from_resources(32, Some(4096), Some(100_000)),
            512
        );
        assert_eq!(
            super::native_relay_worker_threads_from_resources(32, Some(512), Some(4096)),
            128
        );
        assert_eq!(
            super::native_relay_worker_threads_from_resources(4, Some(64), Some(100_000)),
            16
        );
    }

    #[test]
    fn detached_blocking_relay_stack_size_is_small_and_configurable() {
        assert_eq!(super::UNIX_NATIVE_RELAY_STACK_KIB, 256);
        assert_eq!(
            super::native_relay_default_stack_kib_from_resources(
                4,
                Some(4096),
                Some(100_000),
                false
            ),
            256
        );
        assert_eq!(
            super::native_relay_default_stack_kib_from_resources(
                32,
                Some(4096),
                Some(100_000),
                false
            ),
            128
        );
        assert_eq!(
            super::native_relay_default_stack_kib_from_resources(1, None, Some(100_000), false),
            1024
        );
        assert_eq!(
            super::native_relay_default_stack_kib_from_resources(4, Some(64), Some(100_000), false),
            512
        );
        assert_eq!(
            super::native_relay_default_stack_kib_from_resources(
                4,
                Some(4096),
                Some(100_000),
                true
            ),
            2048
        );
        assert_eq!(
            super::native_relay_stack_size_from_env(None, 256),
            256 * 1024
        );
        assert_eq!(
            super::native_relay_stack_size_from_env(Some("64".to_string()), 256),
            128 * 1024
        );
        assert_eq!(
            super::native_relay_stack_size_from_env(Some("16384".to_string()), 256),
            8192 * 1024
        );
        assert_eq!(super::detached_blocking_relay_default_stack_kib(false), 256);
        assert_eq!(super::detached_blocking_relay_default_stack_kib(true), 2048);
        assert_eq!(
            super::detached_blocking_relay_stack_size_from_env(None, 256),
            256 * 1024
        );
        assert_eq!(
            super::detached_blocking_relay_stack_size_from_env(Some("32".to_string()), 256),
            64 * 1024
        );
        assert_eq!(
            super::detached_blocking_relay_stack_size_from_env(Some("512".to_string()), 256),
            512 * 1024
        );
        assert_eq!(
            super::detached_blocking_relay_stack_size_from_env(Some("99999".to_string()), 256),
            8192 * 1024
        );
    }

    #[test]
    fn detached_blocking_relay_metrics_track_active_tasks_by_name() {
        let _guard = super::DetachedBlockingRelayMetricsGuard::new("keli-core-test-relay");
        assert_eq!(
            super::detached_blocking_relay_metrics_snapshot().get("keli-core-test-relay"),
            Some(&1)
        );
        {
            let _second = super::DetachedBlockingRelayMetricsGuard::new("keli-core-test-relay");
            assert_eq!(
                super::detached_blocking_relay_metrics_snapshot().get("keli-core-test-relay"),
                Some(&2)
            );
        }
        assert_eq!(
            super::detached_blocking_relay_metrics_snapshot().get("keli-core-test-relay"),
            Some(&1)
        );
    }

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
    fn unlimited_tcp_relay_preserves_half_close_response() {
        let client_listener = TcpListener::bind("127.0.0.1:0").expect("client bind");
        let remote_listener = TcpListener::bind("127.0.0.1:0").expect("remote bind");
        let client_addr = client_listener.local_addr().expect("client addr");
        let remote_addr = remote_listener.local_addr().expect("remote addr");
        let client_peer = thread::spawn(move || TcpStream::connect(client_addr).expect("client"));
        let remote_peer = thread::spawn(move || {
            let mut stream = TcpStream::connect(remote_addr).expect("remote");
            let mut captured = Vec::new();
            stream.read_to_end(&mut captured).expect("remote read");
            assert_eq!(captured, b"request");
            stream.write_all(b"response").expect("remote write");
        });
        let (client, _) = client_listener.accept().expect("client accept");
        let (remote, _) = remote_listener.accept().expect("remote accept");
        let mut client_peer = client_peer.join().expect("client thread");
        let relay = thread::spawn(move || relay_tcp_fast_unlimited(client, remote));

        client_peer.write_all(b"request").expect("client write");
        client_peer
            .shutdown(Shutdown::Write)
            .expect("client half close");
        let mut response = Vec::new();
        client_peer.read_to_end(&mut response).expect("client read");
        assert_eq!(response, b"response");

        let (upload, download) = relay
            .join()
            .expect("relay thread")
            .expect("relay should finish");
        assert_eq!(upload, b"request".len() as u64);
        assert_eq!(download, b"response".len() as u64);
        remote_peer.join().expect("remote thread");
    }

    #[cfg(unix)]
    #[test]
    fn unlimited_tcp_relay_closes_both_sides_when_client_disconnects() {
        let client_listener = TcpListener::bind("127.0.0.1:0").expect("client bind");
        let remote_listener = TcpListener::bind("127.0.0.1:0").expect("remote bind");
        let client_addr = client_listener.local_addr().expect("client addr");
        let remote_addr = remote_listener.local_addr().expect("remote addr");
        let client_peer = thread::spawn(move || TcpStream::connect(client_addr).expect("client"));
        let remote_peer = thread::spawn(move || TcpStream::connect(remote_addr).expect("remote"));
        let (client, _) = client_listener.accept().expect("client accept");
        let (remote, _) = remote_listener.accept().expect("remote accept");
        let client_peer = client_peer.join().expect("client thread");
        let mut remote_peer = remote_peer.join().expect("remote thread");
        let (done_tx, done_rx) = mpsc::channel();

        let relay = thread::spawn(move || {
            let result = relay_tcp_fast_unlimited_close_on_eof(client, remote);
            done_tx.send(result).expect("send relay result");
        });

        client_peer
            .shutdown(Shutdown::Both)
            .expect("client disconnect");
        let result = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("relay should exit after client disconnect")
            .expect("relay result");
        assert_eq!(result, (0, 0));
        remote_peer
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("remote timeout");
        let mut byte = [0u8; 1];
        assert!(matches!(remote_peer.read(&mut byte), Ok(0) | Err(_)));
        relay.join().expect("relay thread");
    }

    #[cfg(unix)]
    #[test]
    fn unlimited_tcp_relay_close_on_eof_exits_when_client_half_closes() {
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
        let (done_tx, done_rx) = mpsc::channel();

        let relay = thread::spawn(move || {
            let result = relay_tcp_fast_unlimited_close_on_eof(client, remote);
            done_tx.send(result).expect("send relay result");
        });

        client_peer
            .shutdown(Shutdown::Write)
            .expect("client half close");
        let result = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("relay should exit after client half close")
            .expect("relay result");
        assert_eq!(result, (0, 0));

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

    #[test]
    fn native_relay_metrics_track_active_tasks_by_name() {
        let (release_tx, release_rx) = mpsc::channel();
        let handle = super::spawn_named_native_blocking_relay("test-native-relay", move || {
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
            7
        })
        .expect("spawn named native relay");

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let snapshot = super::relay_scheduler_metrics_snapshot();
            if snapshot.active_native.get("test-native-relay") == Some(&1) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "named native relay metric was not observed"
            );
            thread::sleep(Duration::from_millis(10));
        }

        release_tx.send(()).expect("release native relay");
        assert_eq!(
            super::join_native_blocking_relay(handle, "native relay panicked")
                .expect("join native relay"),
            7
        );

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let snapshot = super::relay_scheduler_metrics_snapshot();
            if snapshot.active_native.get("test-native-relay").is_none() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "named native relay metric did not clear"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn native_relay_pool_snapshot_reports_pending_and_workers() {
        let pool = super::NativeRelayPool::with_max_workers_for_test(1);
        let (release_tx, release_rx) = mpsc::channel();
        let (started_tx, started_rx) = mpsc::channel();

        pool.submit(Box::new(move || {
            started_tx.send(()).expect("send started");
            let _ = release_rx.recv();
        }))
        .expect("submit first native relay job");
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first job started");

        pool.submit(Box::new(|| {}))
            .expect("submit queued native relay job");

        let snapshot = pool.snapshot();
        assert_eq!(snapshot.worker_count, 1);
        assert!(snapshot.pending_count >= 1);

        release_tx.send(()).expect("release first job");
        let deadline = Instant::now() + Duration::from_secs(2);
        while pool.snapshot().pending_count > 0 {
            if Instant::now() >= deadline {
                panic!("queued native relay job did not drain");
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn native_relay_pool_schedules_unsaturated_labels_ahead_of_saturated_label_queue() {
        let pool = super::NativeRelayPool::with_limits_for_test(4, 2);
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release = std::sync::Arc::new(std::sync::Mutex::new(release_rx));
        let (started_tx, started_rx) = mpsc::channel();

        for index in 0..2 {
            let release = release.clone();
            let started_tx = started_tx.clone();
            pool.submit_named(
                "label-a",
                Box::new(move || {
                    started_tx
                        .send(format!("a{index}"))
                        .expect("send label-a start");
                    let _ = release
                        .lock()
                        .expect("release lock")
                        .recv_timeout(Duration::from_secs(2));
                }),
            )
            .expect("submit blocking label-a job");
        }

        assert!(started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first label-a start")
            .starts_with('a'));
        assert!(started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("second label-a start")
            .starts_with('a'));

        pool.submit_named("label-a", Box::new(|| {}))
            .expect("submit queued saturated label-a job");
        pool.submit_named(
            "label-b",
            Box::new(move || {
                started_tx
                    .send("b".to_string())
                    .expect("send label-b start");
            }),
        )
        .expect("submit label-b job");

        assert_eq!(
            started_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("label-b should start while label-a is saturated"),
            "b"
        );
        assert!(
            pool.snapshot()
                .pending_by_label
                .get("label-a")
                .copied()
                .unwrap_or(0)
                >= 1
        );

        release_tx.send(()).expect("release first label-a");
        release_tx.send(()).expect("release second label-a");
        let deadline = Instant::now() + Duration::from_secs(2);
        while pool.snapshot().pending_count > 0 {
            if Instant::now() >= deadline {
                panic!("saturated label-a queue did not drain");
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn native_relay_pool_records_per_label_pending_and_queue_wait() {
        let pool = super::NativeRelayPool::with_limits_for_test(1, 1);
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (started_tx, started_rx) = mpsc::channel();
        let first_started_tx = started_tx.clone();

        pool.submit_named(
            "label-wait",
            Box::new(move || {
                first_started_tx.send("first").expect("send first start");
                let _ = release_rx.recv_timeout(Duration::from_secs(2));
            }),
        )
        .expect("submit first job");
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first job started");

        pool.submit_named(
            "label-wait",
            Box::new(move || {
                started_tx.send("second").expect("send second start");
            }),
        )
        .expect("submit queued job");
        assert_eq!(
            pool.snapshot()
                .pending_by_label
                .get("label-wait")
                .copied()
                .unwrap_or(0),
            1
        );

        thread::sleep(Duration::from_millis(20));
        release_tx.send(()).expect("release first job");
        assert_eq!(
            started_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("second job started"),
            "second"
        );
        let snapshot = pool.snapshot();
        assert!(
            snapshot
                .queue_wait_ms_by_label
                .get("label-wait")
                .copied()
                .unwrap_or(0)
                >= 10,
            "queue wait should be recorded by label: {snapshot:?}"
        );
    }

    #[test]
    fn async_relay_metrics_guard_tracks_active_task() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("test runtime");
        runtime.block_on(async {
            let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
            let handle = super::spawn_async_relay("test-async-relay", async move {
                let _ = release_rx.await;
            })
            .expect("spawn async relay");

            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let snapshot = super::relay_scheduler_metrics_snapshot();
                if snapshot.active_async.get("test-async-relay") == Some(&1) {
                    break;
                }
                if Instant::now() >= deadline {
                    panic!("async relay metric did not become active");
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }

            release_tx.send(()).expect("release async relay");
            handle.await.expect("async relay task");
            let snapshot = super::relay_scheduler_metrics_snapshot();
            assert_eq!(snapshot.active_async.get("test-async-relay"), None);
        });
    }

    #[test]
    fn async_relay_metrics_allow_protocol_named_tasks() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("test runtime");
        runtime.block_on(async {
            let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
            let handle = super::spawn_async_relay("keli-core-vless-relay", async move {
                let _ = release_rx.await;
            })
            .expect("spawn async relay");

            let deadline = Instant::now() + Duration::from_secs(2);
            while super::relay_scheduler_metrics_snapshot()
                .active_async
                .get("keli-core-vless-relay")
                != Some(&1)
            {
                if Instant::now() >= deadline {
                    panic!("vless async relay metric did not become active");
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }

            release_tx.send(()).expect("release async relay");
            handle.await.expect("join async relay");
        });
    }

    #[test]
    fn detached_blocking_relay_handle_returns_task_result() {
        let handle =
            super::spawn_detached_blocking_relay_with_handle("test-detached-blocking-relay", || 42)
                .expect("spawn detached blocking relay");
        let value = super::join_detached_blocking_relay(handle, "detached blocking relay panicked")
            .expect("join detached blocking relay");
        assert_eq!(value, 42);
    }

    #[test]
    fn relay_scheduler_snapshot_formats_low_cardinality_fields() {
        let mut snapshot = super::RelaySchedulerMetricsSnapshot::default();
        snapshot
            .active_native
            .insert("keli-core-vless-vision-relay".to_string(), 1);
        snapshot
            .active_async
            .insert("keli-core-vless-relay".to_string(), 2);
        snapshot
            .active_detached_blocking
            .insert("keli-core-mieru-session".to_string(), 1);
        snapshot.native_worker_count = 4;
        snapshot.native_pending_count = 3;

        let formatted = super::format_relay_scheduler_metrics(snapshot);
        assert!(formatted.contains("relay_active_native.keli-core-vless-vision-relay=1"));
        assert!(formatted.contains("relay_active_async.keli-core-vless-relay=2"));
        assert!(formatted.contains("relay_active_blocking.keli-core-mieru-session=1"));
        assert!(formatted.contains("native_relay_workers=4"));
        assert!(formatted.contains("native_relay_pending=3"));
    }
}
