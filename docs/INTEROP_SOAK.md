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
- User delete behavior: new connections fail immediately; existing accepted connections stop at the next limiter or relay checkpoint and must report tail traffic with the captured `user_id`.
- Speed limit result.
- Device limit result, including same-IP multi-session behavior.
- Error count, reconnect count, and p95/p99 latency.

Copy `docs/interop_runs/TEMPLATE.md` for every real-client run. Keep the protocol marked as
`Partial` until the completed run record is attached to the release candidate.

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
- Existing accepted connection after delete: main TCP relay paths close registered sockets, and HY2/TUIC authenticated QUIC connections close through limiter revocation. Other protocol wrappers must at least stop forwarding at the next shared bandwidth limiter or relay checkpoint.
- Deleted user tail traffic: must report with the captured `user_id` even after the user leaves the active table.
- Full snapshot: may reset the core revision after mismatch.
- Missing current revision plus an incremental `base_revision`: must be rejected so the agent can request a full snapshot.
- Empty delta: can advance revision when `revision` is present.

## Local Benchmarks

Loopback benchmarks are useful for regression detection, not production certification:

```bash
cargo run --release -- bench hy2-tcp --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench hy2-tcp-stream --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench hy2-udp --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench tuic-tcp --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench tuic-udp --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench vless-tcp-stream --streams 16 --requests 5000 --payload 1024
```

Record the JSON output and compare `runtime_workers` where present, `completed_requests`, `errors`, `error_rate`, `roundtrip_mbps`, p95/p99 latency, and `retries` across commits on the same host.

Small local smoke sample from a Windows loopback release build on `v0.1.24` after the active
TCP connection registry, QUIC revoke watcher, and VLESS/VMess/AnyTLS tail-traffic coverage:

| Command | Completed | Errors | Retries | Runtime workers | p99 latency | Roundtrip Mbps |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `hy2-tcp --streams 2 --requests 20 --payload 256` | 40 / 40 | 0 | 0 | 8 | 10612 us | 2.77 |
| `hy2-tcp-stream --streams 2 --requests 20 --payload 256` | 40 / 40 | 0 | 0 | 8 | 1285 us | 33.32 |
| `hy2-udp --streams 2 --requests 20 --payload 256` | 40 / 40 | 0 | 0 | 8 | 823 us | 1.77 |
| `tuic-tcp --streams 2 --requests 20 --payload 256` | 40 / 40 | 0 | 0 | 8 | 11106 us | 2.83 |
| `tuic-udp --streams 2 --requests 20 --payload 256` | 40 / 40 | 0 | 0 | 8 | 666 us | 1.90 |

## Soak Pass Criteria

A soak pass requires:

- No listener crash.
- No process restart outside the planned test.
- No unbounded memory growth.
- No traffic drain loss after report/requeue cycles.
- Deleted users cannot create new sessions.
- Existing deleted-user connections stop forwarding on the next limiter or relay checkpoint.
- Valid users are not falsely rejected.
- p99 latency does not degrade progressively during the run.
- Error bursts are attributable to client/network conditions and recover without manual core restart.

Keep the protocol marked as `Partial` in `docs/PARITY.md` until the real-client matrix and soak notes are attached to the release candidate.

## Local Real-Client Matrix

For repeatable protocol smoke testing with a real client, run the local sing-box matrix. It
starts temporary loopback `keli-core-rs` listeners, a local HTTP echo server, a local UDP echo
server, and one sing-box client config per case:

```bash
cargo build --release
cargo run --example interop_matrix -- --sing-box /path/to/sing-box
```

On the Windows development workspace used for Keli, the bundled client path is usually:

```powershell
cargo run --example interop_matrix -- --sing-box ..\tools\sing-box\sing-box-1.12.22-windows-amd64\sing-box.exe
```

Useful filters:

```bash
cargo run --example interop_matrix -- --sing-box /path/to/sing-box --only vless
cargo run --example interop_matrix -- --sing-box /path/to/sing-box --only hy2 --keep
```

The matrix currently verifies TCP forwarding through sing-box for SOCKS, HTTP proxy,
Shadowsocks, VLESS, VMess, Trojan, AnyTLS, Hysteria2, and TUIC combinations, plus UDP relay
through Shadowsocks, Hysteria2, and TUIC. It intentionally skips Naive because the native core
treats it as a sidecar, skips Mieru until an official client is installed in the test
environment, and skips VLESS REALITY until there is a deterministic local REALITY destination
fixture.

Latest local Windows loopback sample:

```text
interop matrix summary: 33 passed, 0 failed
SKIP mieru: no official mieru client is bundled with this matrix
SKIP naive: native core intentionally treats Naive as a sidecar
SKIP vless-reality: requires a deterministic REALITY destination fixture
```

The same matrix is available from GitHub Actions as the manual `Native Interop Matrix`
workflow. Use the optional `case_filter` input to run one protocol family before a focused
gray release, or leave it empty to run all supported sing-box cases.
