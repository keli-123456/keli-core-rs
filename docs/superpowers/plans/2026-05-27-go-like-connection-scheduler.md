# Go-like Connection Scheduler Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the Rust core scheduler toward the old Go node's elastic per-connection model without turning every connection into a heavyweight Rust OS thread.

**Architecture:** Keep the current service and protocol boundaries, but add explicit connection and relay scheduler accounting. Existing async-capable paths run as async tasks; sync-only protocol paths remain in blocking fallback with metrics so they cannot be confused with normal async relay capacity.

**Tech Stack:** Rust, Tokio, std TCP streams, existing `keli-core-rs` protocol modules, existing `kelinode-rs` embedded-core packaging.

---

## File Structure

- Modify `src/service.rs`: extend `ConnectionWorkerGroup` into a connection scheduler with separate async and blocking counters, snapshots, and tests. Keep existing call sites stable by preserving `spawn`, `spawn_async`, and `join_timeout`.
- Modify `src/stream.rs`: add relay scheduler snapshots for async relay, detached blocking relay, and native fallback. Keep current public functions stable while routing metrics through small guards.
- Modify `src/mieru.rs`: move long-lived MIERU session work out of the shared native relay pool into the detached blocking compatibility fallback and keep native relay for short upload/download split jobs until a later protocol-specific async rewrite.
- Modify `src/trojan.rs` and `src/vless.rs`: remove remaining native relay usage from TLS/WS paths that already have async equivalents; ensure fallback paths are named and visible.
- Modify `Cargo.toml` and `Cargo.lock`: bump `keli-core-rs` after behavioral changes.
- Modify `../kelinode-rs/Cargo.toml` and `../kelinode-rs/Cargo.lock`: bump node and embedded-core versions after core changes.

## Task 1: Add Connection Scheduler Accounting

**Files:**
- Modify: `src/service.rs`

- [ ] **Step 1: Write failing tests for async and blocking accounting**

Add the following test in `src/service.rs` near the existing `connection_worker_group_*` tests:

```rust
#[test]
fn connection_worker_group_reports_async_and_blocking_activity() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
        .enable_time()
        .build()
        .expect("test runtime");
    runtime.block_on(async {
        let group = super::ConnectionWorkerGroup::new();
        let (blocking_release_tx, blocking_release_rx) = mpsc::channel();
        assert!(group.spawn(move || {
            let _ = blocking_release_rx.recv();
        }));

        let async_release = Arc::new(AtomicBool::new(false));
        let async_release_for_task = async_release.clone();
        assert!(group.spawn_async(async move {
            while !async_release_for_task.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }));

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let snapshot = group.snapshot();
            if snapshot.active_blocking == 1 && snapshot.active_async == 1 {
                assert_eq!(snapshot.active_total, 2);
                break;
            }
            if Instant::now() >= deadline {
                panic!("connection scheduler did not report active async and blocking workers");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        blocking_release_tx.send(()).expect("release blocking worker");
        async_release.store(true, Ordering::SeqCst);
        assert!(group.join_timeout(Duration::from_secs(2)));
        let snapshot = group.snapshot();
        assert_eq!(snapshot.active_total, 0);
        assert_eq!(snapshot.active_blocking, 0);
        assert_eq!(snapshot.active_async, 0);
    });
}
```

- [ ] **Step 2: Run the focused failing test**

Run:

```powershell
cargo test -p keli-core-rs connection_worker_group_reports_async_and_blocking_activity
```

Expected: FAIL because `ConnectionWorkerGroup::snapshot` and the snapshot fields do not exist.

- [ ] **Step 3: Implement connection scheduler counters**

In `src/service.rs`, replace the current `ConnectionWorkerGroupState` with:

```rust
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ConnectionWorkerGroupSnapshot {
    active_total: usize,
    active_blocking: usize,
    active_async: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionWorkerKind {
    Blocking,
    Async,
}

#[derive(Debug, Default)]
struct ConnectionWorkerCounts {
    active_blocking: usize,
    active_async: usize,
}

#[derive(Debug)]
struct ConnectionWorkerGroupState {
    counts: Mutex<ConnectionWorkerCounts>,
    finished: Condvar,
}
```

Change `ConnectionWorkerGroupState::acquire`, `release`, and `wait_until_idle_timeout` to:

```rust
fn acquire(&self, kind: ConnectionWorkerKind) -> bool {
    let mut counts = self.counts.lock().expect("worker group lock poisoned");
    match kind {
        ConnectionWorkerKind::Blocking => counts.active_blocking += 1,
        ConnectionWorkerKind::Async => counts.active_async += 1,
    }
    true
}

fn release(&self, kind: ConnectionWorkerKind) {
    let mut counts = self.counts.lock().expect("worker group lock poisoned");
    match kind {
        ConnectionWorkerKind::Blocking => {
            counts.active_blocking = counts.active_blocking.saturating_sub(1);
        }
        ConnectionWorkerKind::Async => {
            counts.active_async = counts.active_async.saturating_sub(1);
        }
    }
    if counts.active_blocking == 0 && counts.active_async == 0 {
        self.finished.notify_all();
    }
}

fn snapshot(&self) -> ConnectionWorkerGroupSnapshot {
    let counts = self.counts.lock().expect("worker group lock poisoned");
    ConnectionWorkerGroupSnapshot {
        active_total: counts.active_blocking + counts.active_async,
        active_blocking: counts.active_blocking,
        active_async: counts.active_async,
    }
}

fn wait_until_idle_timeout(&self, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut counts = self.counts.lock().expect("worker group lock poisoned");
    while counts.active_blocking + counts.active_async > 0 {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining = deadline.saturating_duration_since(now);
        let (next_counts, wait_result) = self
            .finished
            .wait_timeout(counts, remaining)
            .expect("worker group lock poisoned");
        counts = next_counts;
        if wait_result.timed_out() && counts.active_blocking + counts.active_async > 0 {
            return false;
        }
    }
    true
}
```

Update `ConnectionWorkerGroup::new`, `spawn`, `spawn_async`, and `ConnectionWorkerAsyncGuard` so blocking tasks call `acquire/release(ConnectionWorkerKind::Blocking)` and async tasks call `acquire/release(ConnectionWorkerKind::Async)`. Add:

```rust
fn snapshot(&self) -> ConnectionWorkerGroupSnapshot {
    self.state.snapshot()
}
```

- [ ] **Step 4: Verify focused tests pass**

Run:

```powershell
cargo test -p keli-core-rs connection_worker_group
```

Expected: all `connection_worker_group_*` tests PASS.

- [ ] **Step 5: Commit Task 1**

Run:

```powershell
git add src/service.rs
git commit -m "Track async and blocking connection tasks"
```

## Task 2: Add Relay Scheduler Accounting

**Files:**
- Modify: `src/stream.rs`

- [ ] **Step 1: Write failing relay scheduler tests**

Add the following tests in `src/stream.rs` near `native_relay_pool_handles_bursts`:

```rust
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
```

- [ ] **Step 2: Run focused failing tests**

Run:

```powershell
cargo test -p keli-core-rs native_relay_pool_snapshot_reports_pending_and_workers
cargo test -p keli-core-rs async_relay_metrics_guard_tracks_active_task
```

Expected: FAIL because `with_max_workers_for_test`, `snapshot`, `spawn_async_relay`, and `relay_scheduler_metrics_snapshot` do not exist.

- [ ] **Step 3: Implement relay scheduler metrics**

In `src/stream.rs`, add:

```rust
static ASYNC_RELAY_ACTIVE: OnceLock<Mutex<BTreeMap<&'static str, usize>>> = OnceLock::new();

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RelaySchedulerMetricsSnapshot {
    pub active_async: BTreeMap<String, usize>,
    pub active_detached_blocking: BTreeMap<String, usize>,
    pub native_worker_count: usize,
    pub native_idle_count: usize,
    pub native_pending_count: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NativeRelayPoolSnapshot {
    worker_count: usize,
    idle_count: usize,
    pending_count: usize,
}
```

Add `AsyncRelayMetricsGuard` equivalent to the existing `DetachedBlockingRelayMetricsGuard`, and implement:

```rust
pub fn spawn_async_relay<F>(name: &'static str, future: F) -> io::Result<tokio::task::JoinHandle<F::Output>>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    spawn_background_io(async move {
        let _metrics = AsyncRelayMetricsGuard::new(name);
        future.await
    })
}

pub(crate) fn relay_scheduler_metrics_snapshot() -> RelaySchedulerMetricsSnapshot {
    let native = native_relay_pool().snapshot();
    RelaySchedulerMetricsSnapshot {
        active_async: async_relay_metrics_snapshot(),
        active_detached_blocking: detached_blocking_relay_metrics_snapshot(),
        native_worker_count: native.worker_count,
        native_idle_count: native.idle_count,
        native_pending_count: native.pending_count,
    }
}
```

Add `NativeRelayPool::with_max_workers_for_test(max_workers: usize)` under `#[cfg(test)]`, refactor `new()` to call a private `with_max_workers(max_workers: usize)`, and add:

```rust
fn snapshot(&self) -> NativeRelayPoolSnapshot {
    NativeRelayPoolSnapshot {
        worker_count: self.worker_count.load(Ordering::Acquire),
        idle_count: self.idle_count.load(Ordering::Acquire),
        pending_count: self.pending_count.load(Ordering::Acquire),
    }
}
```

- [ ] **Step 4: Verify relay scheduler tests pass**

Run:

```powershell
cargo test -p keli-core-rs native_relay_pool_snapshot_reports_pending_and_workers
cargo test -p keli-core-rs async_relay_metrics_guard_tracks_active_task
```

Expected: PASS.

- [ ] **Step 5: Commit Task 2**

Run:

```powershell
git add src/stream.rs
git commit -m "Add relay scheduler accounting"
```

## Task 3: Move MIERU Sessions Out of Shared Native Relay Pool

**Files:**
- Modify: `src/mieru.rs`
- Modify: `src/stream.rs`

- [ ] **Step 1: Write a failing MIERU scheduler test**

Add this test near the MIERU relay tests in `src/mieru.rs`:

```rust
#[test]
fn mieru_session_worker_uses_detached_blocking_fallback_metric() {
    let snapshot = crate::stream::relay_scheduler_metrics_snapshot();
    assert_eq!(
        snapshot
            .active_detached_blocking
            .get("keli-core-mieru-session"),
        None
    );

    let _guard = crate::stream::DetachedBlockingRelayMetricsGuard::new("keli-core-mieru-session");
    let snapshot = crate::stream::relay_scheduler_metrics_snapshot();
    assert_eq!(
        snapshot
            .active_detached_blocking
            .get("keli-core-mieru-session"),
        Some(&1)
    );
}
```

- [ ] **Step 2: Run focused failing test**

Run:

```powershell
cargo test -p keli-core-rs mieru_session_worker_uses_detached_blocking_fallback_metric
```

Expected: FAIL if `relay_scheduler_metrics_snapshot` is not visible enough or detached metrics are not exposed through the unified snapshot.

- [ ] **Step 3: Replace long-lived MIERU session spawn**

In `spawn_mieru_session`, change the `workers` parameter from:

```rust
workers: &mut Vec<NativeRelayHandle<()>>,
```

to:

```rust
workers: &mut Vec<DetachedBlockingRelayHandle<()>>,
```

Then replace:

```rust
workers.push(spawn_native_blocking_relay(move || {
    let result = handle_mieru_session(initial, rx, writer.clone(), user, client_ip, runtime)
        .map_err(|error| (error.kind(), error.to_string()));
    if result.is_err() {
        close_mieru_underlay(&writer);
    }
    let _ = done_tx.send((session_id, result));
})?);
```

with:

```rust
workers.push(spawn_detached_blocking_relay_with_handle(
    "keli-core-mieru-session",
    move || {
        let result = handle_mieru_session(initial, rx, writer.clone(), user, client_ip, runtime)
            .map_err(|error| (error.kind(), error.to_string()));
        if result.is_err() {
            close_mieru_underlay(&writer);
        }
        let _ = done_tx.send((session_id, result));
    },
)?);
```

Update the `use crate::stream::{...}` list in `src/mieru.rs` to import `DetachedBlockingRelayHandle`, `join_detached_blocking_relay`, and `spawn_detached_blocking_relay_with_handle`. Keep the final session join loop, but call `join_detached_blocking_relay` instead of `join_native_blocking_relay`.

- [ ] **Step 4: Verify MIERU tests**

Run:

```powershell
cargo test -p keli-core-rs mieru
```

Expected: PASS.

- [ ] **Step 5: Commit Task 3**

Run:

```powershell
git add src/mieru.rs src/stream.rs
git commit -m "Move MIERU sessions to blocking fallback"
```

## Task 4: Route Async Relay Spawns Through Relay Scheduler

**Files:**
- Modify: `src/stream.rs`
- Modify: `src/vless.rs`
- Modify: `src/trojan.rs`

- [ ] **Step 1: Write failing tests for async relay metrics in VLESS/Trojan helpers**

In `src/stream.rs`, add a test that spawns two async relay tasks with protocol names:

```rust
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
```

- [ ] **Step 2: Run focused test**

Run:

```powershell
cargo test -p keli-core-rs async_relay_metrics_allow_protocol_named_tasks
```

Expected: PASS after Task 2.

- [ ] **Step 3: Replace generic async background spawns with named relay spawns**

In VLESS/Trojan async relay paths, replace relay-specific `spawn_background_io(...)` calls with:

```rust
spawn_async_relay("keli-core-vless-relay", async move {
    /* existing relay future */
})?
```

and:

```rust
spawn_async_relay("keli-core-trojan-relay", async move {
    /* existing relay future */
})?
```

Do not convert sync-only TLS Vision or sync websocket readers in this task. They remain blocking fallback with visible metrics.

- [ ] **Step 4: Verify VLESS and Trojan tests**

Run:

```powershell
cargo test -p keli-core-rs vless trojan
```

Expected: PASS.

- [ ] **Step 5: Commit Task 4**

Run:

```powershell
git add src/stream.rs src/vless.rs src/trojan.rs
git commit -m "Name async relay scheduler tasks"
```

## Task 5: Add Scheduler Snapshot Logging Hook

**Files:**
- Modify: `src/service.rs`
- Modify: `src/stream.rs`

- [ ] **Step 1: Write focused snapshot formatting tests**

In `src/service.rs`, add:

```rust
#[test]
fn connection_worker_snapshot_formats_low_cardinality_fields() {
    let snapshot = super::ConnectionWorkerGroupSnapshot {
        active_total: 3,
        active_blocking: 1,
        active_async: 2,
    };
    assert_eq!(
        super::format_connection_worker_snapshot(snapshot),
        "connection_active_total=3 connection_active_blocking=1 connection_active_async=2"
    );
}
```

In `src/stream.rs`, add:

```rust
#[test]
fn relay_scheduler_snapshot_formats_low_cardinality_fields() {
    let mut snapshot = super::RelaySchedulerMetricsSnapshot::default();
    snapshot.active_async.insert("keli-core-vless-relay".to_string(), 2);
    snapshot
        .active_detached_blocking
        .insert("keli-core-mieru-session".to_string(), 1);
    snapshot.native_worker_count = 4;
    snapshot.native_pending_count = 3;

    let formatted = super::format_relay_scheduler_metrics(snapshot);
    assert!(formatted.contains("relay_active_async.keli-core-vless-relay=2"));
    assert!(formatted.contains("relay_active_blocking.keli-core-mieru-session=1"));
    assert!(formatted.contains("native_relay_workers=4"));
    assert!(formatted.contains("native_relay_pending=3"));
}
```

- [ ] **Step 2: Run focused failing tests**

Run:

```powershell
cargo test -p keli-core-rs snapshot_formats_low_cardinality_fields
```

Expected: FAIL because formatting helpers do not exist.

- [ ] **Step 3: Implement formatting helpers**

Add private helpers:

```rust
fn format_connection_worker_snapshot(snapshot: ConnectionWorkerGroupSnapshot) -> String {
    format!(
        "connection_active_total={} connection_active_blocking={} connection_active_async={}",
        snapshot.active_total, snapshot.active_blocking, snapshot.active_async
    )
}
```

and:

```rust
pub(crate) fn format_relay_scheduler_metrics(snapshot: RelaySchedulerMetricsSnapshot) -> String {
    let mut fields = Vec::new();
    for (name, count) in snapshot.active_async {
        fields.push(format!("relay_active_async.{name}={count}"));
    }
    for (name, count) in snapshot.active_detached_blocking {
        fields.push(format!("relay_active_blocking.{name}={count}"));
    }
    fields.push(format!("native_relay_workers={}", snapshot.native_worker_count));
    fields.push(format!("native_relay_idle={}", snapshot.native_idle_count));
    fields.push(format!("native_relay_pending={}", snapshot.native_pending_count));
    fields.join(" ")
}
```

Use these helpers only in rate-limited status/pressure logs. Do not add per-connection noisy logs.

- [ ] **Step 4: Verify formatting tests pass**

Run:

```powershell
cargo test -p keli-core-rs snapshot_formats_low_cardinality_fields
```

Expected: PASS.

- [ ] **Step 5: Commit Task 5**

Run:

```powershell
git add src/service.rs src/stream.rs
git commit -m "Format scheduler pressure snapshots"
```

## Task 6: Full Core Verification and Version Bump

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`

- [ ] **Step 1: Run formatting**

Run:

```powershell
cargo fmt --check
```

Expected: PASS.

- [ ] **Step 2: Run core tests**

Run:

```powershell
cargo test --lib
```

Expected: PASS.

- [ ] **Step 3: Bump core version**

In `Cargo.toml`, bump the package version by one patch version. Then run:

```powershell
cargo check --lib
```

Expected: PASS and `Cargo.lock` updates to the same core version.

- [ ] **Step 4: Commit Task 6**

Run:

```powershell
git add Cargo.toml Cargo.lock
git commit -m "Bump core for Go-like scheduler"
```

## Task 7: Bump Node Embedded Core and Verify

**Files:**
- Modify: `../kelinode-rs/Cargo.toml`
- Modify: `../kelinode-rs/Cargo.lock`

- [ ] **Step 1: Update embedded core version**

In `../kelinode-rs/Cargo.toml`, update the package patch version by one and update the embedded `keli-core-rs` dependency version or lock entry to match the new core version.

- [ ] **Step 2: Run node formatting**

Run:

```powershell
cargo fmt --check
```

from `../kelinode-rs`.

Expected: PASS.

- [ ] **Step 3: Run node tests**

Run:

```powershell
cargo test --features embedded-core
```

from `../kelinode-rs`.

Expected: PASS.

- [ ] **Step 4: Commit Task 7**

Run:

```powershell
git add Cargo.toml Cargo.lock
git commit -m "Bump node for Go-like scheduler"
```

## Task 8: Deploy and Validate on Nodes

**Files:**
- Create: `../remote_deploy_go_like_scheduler.sh`

- [ ] **Step 1: Build release binary**

Run from `../kelinode-rs`:

```powershell
cargo build --release --features embedded-core
```

Expected: PASS and a release `kelinode-rs` binary exists.

- [ ] **Step 2: Deploy to test-node when available**

Use the existing SSH key and deployment pattern. Record:

- `node_role=test-node`
- `node_ip=45.32.122.113`
- node version
- core version
- memory RSS
- native relay pending count

- [ ] **Step 3: Deploy to problem-node**

Use the existing SSH key and deployment pattern. Record:

- `node_role=problem-node`
- `node_ip=2.56.116.39`
- node version
- core version
- memory RSS
- native relay pending count
- detached blocking MIERU session count
- active async relay count

- [ ] **Step 4: Client and log validation**

Validate at least:

- Trojan WS through Cloudflare domain `123.dnscloudcloud.top`
- VLESS TCP/WS node
- MIERU node
- HY2 node
- AnyTLS node

For each result, record:

- test node IP
- protocol
- transport
- target address
- connect time
- first byte time
- relay duration
- error kind
- upload bytes
- download bytes
- whether transfer remains stable after connect timeout duration

- [ ] **Step 5: Push commits**

Run:

```powershell
git push
```

from `keli-core-rs` and `kelinode-rs` after local and remote validation passes.

## Self-Review

- Spec coverage: accept, connection scheduler, relay scheduler, blocking fallback, observability, version bump, node validation, and rollback are covered by tasks.
- Placeholder scan: clear.
- Type consistency: `ConnectionWorkerGroupSnapshot`, `RelaySchedulerMetricsSnapshot`, `spawn_async_relay`, and `relay_scheduler_metrics_snapshot` are introduced before later tasks use them.
- Scope check: panel fields and subscription output remain out of scope, matching the design.
