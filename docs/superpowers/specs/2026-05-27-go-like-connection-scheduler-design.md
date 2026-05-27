# Go-like connection scheduler design

## Context

The legacy Go node does not use a small fixed relay worker pool. Its dispatcher starts per-connection work with `go d.routedDispatch(...)`, while Go's runtime multiplexes many goroutines over `GOMAXPROCS` OS threads. The practical behavior is elastic: active connections can grow with demand, and scheduler capacity is not a protocol-level bottleneck.

The Rust rewrite currently has two layers that can diverge from that behavior:

- `ConnectionWorkerGroup` tracks per-connection work, but some paths still use dedicated OS threads for connection handlers.
- `NativeRelayPool` runs relay jobs through a bounded worker pool. The previous low cap caused MIERU, VLESS, and Trojan traffic to stall when long-lived relay jobs occupied all workers.

The immediate cap increase restored capacity, but it is still a fixed-pool model. The next step is to move the scheduler design closer to the Go behavior while keeping Rust memory usage under control.

## Goals

- Accept TCP connections quickly and move protocol work out of the accept loop.
- Run per-connection work as elastic async tasks where the protocol path supports it.
- Move long-lived relay traffic away from a small native worker pool.
- Keep blocking work isolated to explicit blocking boundaries.
- Preserve Docker and binary node deployment behavior.
- Preserve hot reload semantics: new connections use the new config while existing connections drain normally unless the listener is stopped.
- Add enough metrics and logs to distinguish connection-task pressure from blocking-pool pressure.
- Validate Trojan WS, VLESS TCP/WS, MIERU, HY2, AnyTLS, and Shadowsocks after each scheduler phase.

## Non-goals

- Do not reimplement the Go runtime.
- Do not create one Rust OS thread per connection as the default model.
- Do not change protocol wire behavior while changing scheduling.
- Do not change panel configuration fields or subscription output as part of this scheduler work.
- Do not introduce hard-coded node IP addresses.

## Proposed architecture

### 1. Accept layer

TCP listeners should only accept sockets, apply minimal socket setup, and submit the connection into the connection scheduler. The accept loop must not block on protocol handshake or long relay work.

The current `spawn_tcp_accept_loop` shape can remain, but its submission path should prefer async connection tasks when the handler can be represented as an async future.

### 2. Connection scheduler

Introduce a `ConnectionScheduler` abstraction that replaces direct use of `ConnectionWorkerGroup` at listener call sites.

Responsibilities:

- Track active connection tasks for graceful shutdown.
- Spawn async connection tasks with `tokio::spawn`.
- Keep a fallback `spawn_blocking_connection` path for protocol code that is still synchronous.
- Report active async tasks, active blocking tasks, spawn failures, and shutdown wait timeouts.

The first implementation should be intentionally small. It can wrap the existing `ConnectionWorkerGroup` counters and add separate async/blocking counters rather than creating a large new runtime subsystem.

### 3. Relay scheduler

Introduce a `RelayScheduler` abstraction for long-lived bidirectional copy work.

Preferred behavior:

- Async streams use `tokio::io::copy_bidirectional` or existing counted async copy helpers.
- Split upload/download relay tasks are spawned as async tasks when both sides support async I/O.
- Synchronous stream pairs use the existing native relay path only as a compatibility fallback.

The native fallback should stay bounded, but it should stop being the primary path for protocols that already operate inside async runtimes.

### 4. Blocking boundary

Keep blocking operations explicit:

- Synchronous DNS resolution.
- Synchronous socket connect paths that cannot be converted in the same phase.
- Compatibility TLS or WebSocket paths that still expose blocking readers/writers.

These use a separate blocking pool with observable queue depth and active worker count. Blocking-pool saturation should be logged as a pressure signal, not silently converted into protocol timeout behavior.

## Data flow

1. Listener accepts a socket.
2. Listener submits the socket to `ConnectionScheduler`.
3. Connection task performs protocol handshake and routing.
4. When relay starts, protocol code asks `RelayScheduler` for the best available relay mode.
5. Async-capable relay uses async tasks and counted async copy.
6. Blocking-only relay uses native fallback.
7. Shutdown stops listeners first, then waits for connection and relay tasks to drain with existing timeout behavior.

## Resource policy

The scheduler should behave like Go in connection elasticity, but not pretend Rust OS threads are goroutines.

- Async connection and relay tasks are allowed to scale with active connections.
- Blocking fallback workers remain capped by CPU, memory, and FD limits.
- The cap is a protection for truly blocking code, not a normal relay throughput limiter.
- Idle blocking workers should retire.
- Memory optimization must come from smaller stacks, async relay paths, bounded logs, buffer reuse, and cleanup of finished task state.

## Observability

Add or preserve low-cardinality counters/log fields:

- `connection_active_async`
- `connection_active_blocking`
- `relay_active_async`
- `relay_active_blocking`
- `blocking_queue_pending`
- `blocking_worker_count`
- `scheduler_spawn_error`
- `scheduler_shutdown_timeout`

Per-connection finish logs should continue to include protocol, transport, target, duration, byte counts, first-byte timing, and finish reason. High-frequency success logs should remain rate-limited or summarized where possible.

## Compatibility

- Existing public APIs stay unchanged.
- Existing node configs stay unchanged.
- Existing Docker and binary modes continue to call the same core service entry points.
- Environment overrides such as worker counts remain as emergency controls.
- Existing synchronous protocol paths keep a native fallback until converted.

## Implementation phases

### Phase 1: scheduler abstraction

- Add `ConnectionScheduler` and `RelayScheduler` wrappers.
- Route listener submission and native relay submission through those wrappers without changing protocol behavior.
- Add unit tests for accounting, shutdown drain, panic cleanup, and fallback submission.

### Phase 2: async relay migration

- Convert VLESS and Trojan TCP/WS relay paths that already have async stream sides.
- Convert MIERU relay path or its bridge into async tasks where feasible.
- Keep native fallback for sync-only paths.
- Add focused relay tests proving long-lived relay does not occupy connection workers.

### Phase 3: pressure visibility and tuning

- Add metrics/log fields for active async/blocking tasks and pending blocking work.
- Tune fallback caps after measuring problem-node behavior.
- Confirm that high concurrency no longer manifests as protocol timeout caused by scheduler saturation.

### Phase 4: deployment validation

- Bump versions.
- Build and deploy to test-node first when practical.
- Deploy to problem-node after local tests pass.
- Validate with client traffic and logs for Trojan WS, VLESS, MIERU, HY2, AnyTLS, and Shadowsocks.

## Verification plan

Local checks:

- `cargo fmt --check`
- `cargo test --lib`
- `cargo test --features embedded-core` in `kelinode-rs` after version bump

Targeted tests:

- Burst connection tests exceed the previous fixed worker cap.
- Long-lived relay tests prove new connections still start.
- Native fallback tests prove sync-only paths still work.
- Shutdown tests prove async and blocking tasks drain or time out cleanly.

Problem-node checks:

- Confirm node and core versions after deployment.
- Confirm no fixed 64-worker saturation pattern.
- Inspect memory, FD, CPU, and restart count.
- Verify MIERU/VLESS/Trojan with client traffic and protocol finish logs.

## Rollback

Rollback remains simple per phase:

- Keep native fallback code until async relay migration is proven.
- Guard risky paths behind internal scheduler selection functions, not panel fields.
- If a converted protocol regresses, route that protocol back to native fallback while retaining accounting and observability.
- Reinstall the previous node binary on problem-node if client traffic regresses.

## Self-review

- No placeholder requirements remain.
- The design keeps panel and subscription behavior out of scope.
- The design distinguishes async elasticity from unbounded OS-thread creation.
- The design preserves fallback paths and rollback options.
- Verification covers local tests, node deployment, and client-visible protocol behavior.
