# Real Client Interop And Soak

This document is the production-readiness entry point for native Keli core validation. Passing unit tests and local loopback benchmarks is not enough to mark a protocol production-ready.

## Priority Matrix

Run interop in this order:

1. Hysteria2 TCP relay.
2. Hysteria2 UDP relay.
3. VLESS TCP TLS Vision, or Trojan TCP TLS if that is the larger live protocol for the target site.
4. The same TCP protocol with WebSocket, HTTPUpgrade, and gRPC when those transports are used by live nodes.
5. TUIC TCP and UDP.

## Required Checks

Each protocol/configuration must record:

- Core commit SHA and binary version.
- `kelinode-rs` commit SHA and config renderer version.
- Panel node id, protocol, transport, TLS/REALITY/obfs settings, and user count.
- Client app and version.
- Connect success and first-byte latency.
- 30 minute smoke run result.
- 6 hour soak result before any live migration.
- Upload/download traffic deltas compared with client-side bytes.
- User delete behavior: new connections fail immediately, existing accepted connections may drain naturally.
- Speed limit result.
- Device limit result, including same-IP multi-session behavior.
- Error count, reconnect count, and p95/p99 latency.

## Core Startup

Generate the native config through `kelinode-rs`, then run the core directly while testing:

```bash
cargo run --release -- check-config ./config.json
cargo run --release -- run-config ./config.json --control 127.0.0.1:18080
```

Use the control socket to verify runtime state without restarting listeners:

```json
{"type":"status"}
{"type":"drain_traffic","minimum_bytes":1}
```

## User Delta Checks

For small user changes, use `apply_user_delta` through `kelinode-rs` or the control socket. A normal incremental delta must include `base_revision` and `revision`. If the core returns a revision mismatch, `kelinode-rs` must fall back to a full snapshot.

Expected semantics:

- Added user: new authentication succeeds without listener restart.
- Updated user: credential, speed limit, and device limit are visible to new sessions.
- Deleted user: new authentication fails immediately.
- Existing accepted connection after delete: may continue until normal close and must report tail traffic with the captured `user_id`.
- Full snapshot: may reset the core revision after mismatch.

## Local Benchmarks

Loopback benchmarks are useful for regression detection, not production certification:

```bash
cargo run --release -- bench hy2-tcp --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench hy2-tcp-stream --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench hy2-udp --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench vless-tcp-stream --streams 16 --requests 5000 --payload 1024
```

Record the JSON output and compare `runtime_workers` where present, `completed_requests`, `errors`, `error_rate`, `roundtrip_mbps`, p95/p99 latency, and `retries` across commits on the same host.

## Soak Pass Criteria

A soak pass requires:

- No listener crash.
- No process restart outside the planned test.
- No unbounded memory growth.
- No traffic drain loss after report/requeue cycles.
- Deleted users cannot create new sessions.
- Valid users are not falsely rejected.
- p99 latency does not degrade progressively during the run.
- Error bursts are attributable to client/network conditions and recover without manual core restart.

Keep the protocol marked as `Partial` in `docs/PARITY.md` until the real-client matrix and soak notes are attached to the release candidate.
