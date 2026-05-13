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
cargo run --release -- bench tuic-tcp-stream --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench tuic-udp --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench vless-tcp-stream --streams 16 --requests 5000 --payload 1024
```

For repeatable Rust-vs-baseline comparisons, collect a suite report instead of copying
one-off command output:

```bash
cargo run --release -- bench suite --streams 16 --requests 5000 --payload 1024 --repeats 3 --label rust-native --out runtime/bench/rust-suite.json
cargo run --release -- bench suite --commands hy2-tcp,hy2-tcp-stream,hy2-udp --streams 16 --requests 5000 --payload 1024 --repeats 3 --label rust-hy2 --out runtime/bench/rust-hy2-suite.json
cargo run --release -- bench external-suite --vless-core 127.0.0.1:19080 --commands vless-tcp-stream --streams 16 --requests 5000 --payload 1024 --repeats 3 --label go-xray-vless --out runtime/bench/go-suite.json
cargo run --release -- bench compare --baseline runtime/bench/go-suite.json --candidate runtime/bench/rust-suite.json --out runtime/bench/go-vs-rust.json
```

The Go/Xray VLESS baseline can be collected by running the old core with a VLESS TCP inbound
using benchmark user UUID `11111111-1111-1111-1111-111111111111` and normal direct/freedom
outbound routing. `external-suite` starts the local echo target itself and sends that target
inside the VLESS request. HY2/TUIC external Go baselines still need dedicated harness support.
All baselines must be produced on the same host with the same release/debug mode, stream count,
request count, payload size, repeat count, and report schema (`keli-core-bench-suite-v1`).
Until every target protocol has a baseline in this schema, treat `bench compare` as a focused
VLESS/Rust-regression tool rather than proof that Rust has already beaten the whole production
Go stack.

Recent Windows loopback release baseline for VLESS stream mode (`16` streams, `5000` requests
per stream, `1024` byte payload, `3` repeats):

| Baseline | Roundtrip Mbps avg | p99 avg | Errors | Retries |
| --- | ---: | ---: | ---: | ---: |
| Go/Xray VLESS | 1090.87 | 612 us | 0 | 0 |
| Rust VLESS, 4MiB async traffic flush | 824.28 | 622 us | 0 | 0 |

This keeps Rust VLESS stable under the benchmark but still below the Go/Xray throughput baseline,
so keep using this suite to gate future VLESS relay optimizations.

Recent Windows loopback release baseline for QUIC stream/datagram paths with the same `16 x 5000 x
1024` shape and `3` repeats:

| Command | Roundtrip Mbps avg | p99 avg | Errors | Retries |
| --- | ---: | ---: | ---: | ---: |
| `hy2-tcp-stream` | 529.76 | 911 us | 0 | 0 |
| `hy2-udp` | 584.69 | 764 us | 0 | 0 |
| `tuic-tcp-stream` | 495.25 | 951 us | 0 | 0 |
| `tuic-udp` | 558.66 | 787 us | 0 | 0 |

Use `tuic-tcp-stream` for steady-state TUIC relay benchmarking on Windows. The older `tuic-tcp`
command intentionally opens one proxied TCP connection per request, which can exhaust local
ephemeral ports under very high loopback request counts before it measures core throughput.

Large-payload stream smoke (`16` streams, `1000` requests per stream, `65536` byte payload,
single repeat) shows the current data-plane split more clearly:

| Command | Roundtrip Mbps | p99 | Errors | Retries |
| --- | ---: | ---: | ---: | ---: |
| `vless-tcp-stream` | 19194.43 | 1561 us | 0 | 0 |
| `hy2-tcp-stream` | 2141.52 | 32021 us | 0 | 0 |
| `tuic-tcp-stream` | 2674.95 | 33059 us | 0 | 0 |

Treat these as local loopback throughput indicators, not internet p99 latency promises. They show
that the next large performance target is the QUIC stream relay path, while VLESS TCP relay already
has enough headroom for 10Gbps-class local relay smoke.

Record the JSON output and compare `runtime_workers` where present, `completed_requests`, `errors`, `error_rate`, `roundtrip_mbps`, p95/p99 latency, and `retries` across commits on the same host.

Small local smoke sample from a Windows loopback release build on `v0.1.32` after the active
TCP connection registry, QUIC revoke watcher, VLESS REALITY interop fixture, and VLESS/VMess/AnyTLS
tail-traffic coverage:

| Command | Completed | Errors | Retries | Runtime workers | p99 latency | Roundtrip Mbps |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `hy2-tcp --streams 2 --requests 20 --payload 256` | 40 / 40 | 0 | 0 | 8 | 11180 us | 2.81 |
| `hy2-tcp-stream --streams 2 --requests 20 --payload 256` | 40 / 40 | 0 | 0 | 8 | 1801 us | 38.92 |
| `hy2-udp --streams 2 --requests 20 --payload 256` | 40 / 40 | 0 | 0 | 8 | 682 us | 1.90 |
| `tuic-tcp --streams 2 --requests 20 --payload 256` | 40 / 40 | 0 | 0 | 8 | 11480 us | 2.57 |
| `tuic-udp --streams 2 --requests 20 --payload 256` | 40 / 40 | 0 | 0 | 8 | 938 us | 1.84 |

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

For repeatable protocol smoke testing with a real client, run the local client matrix. It
starts temporary loopback `keli-core-rs` listeners, a local HTTP echo server, a local UDP echo
server, and one client config per case:

```bash
cargo build --release
cargo run --example interop_matrix -- --sing-box /path/to/sing-box
cargo run --example interop_matrix -- --client mihomo --mihomo /path/to/mihomo
cargo run --example interop_matrix -- --client both --sing-box /path/to/sing-box --mihomo /path/to/mihomo
```

On the Windows development workspace used for Keli, the bundled client paths are usually:

```powershell
cargo run --example interop_matrix -- --sing-box ..\tools\sing-box\sing-box-1.12.22-windows-amd64\sing-box.exe
cargo run --example interop_matrix -- --client mihomo --mihomo ..\tools\mihomo\mihomo-windows-amd64-v1.19.24\mihomo-windows-amd64.exe
```

Useful filters:

```bash
cargo run --example interop_matrix -- --sing-box /path/to/sing-box --only vless
cargo run --example interop_matrix -- --client mihomo --mihomo /path/to/mihomo --only vless-reality
cargo run --example interop_matrix -- --client both --sing-box /path/to/sing-box --mihomo /path/to/mihomo --only hy2 --keep
```

The sing-box client verifies TCP forwarding for SOCKS, HTTP proxy, Shadowsocks, VLESS, VLESS
REALITY Vision, VMess, Trojan, AnyTLS, Hysteria2, and TUIC combinations, plus UDP relay through
Shadowsocks, Hysteria2, and TUIC.

The mihomo client currently verifies SOCKS, HTTP proxy, Shadowsocks TCP/UDP, VLESS TCP/TLS/Vision,
VLESS REALITY Vision, VLESS WS/gRPC, VMess TCP/TLS/WS/gRPC, Trojan TLS/WS/gRPC, Hysteria2 TCP/UDP,
Hysteria2 Salamander, and TUIC TCP/UDP. It skips cases without a reliable mihomo proxy equivalent
in this matrix, such as HTTPUpgrade, Trojan plain TCP, AnyTLS, Mieru, and Naive.

Both clients use a deterministic local TLS destination fixture for REALITY.

Latest local Windows loopback sample:

```text
interop matrix summary: 34 passed, 0 skipped, 0 failed
SKIP mieru: no official mieru client is bundled with this matrix
SKIP naive: native core intentionally treats Naive as a sidecar
```

Latest local Windows loopback sample for mihomo v1.19.24:

```text
interop matrix summary: 24 passed, 10 skipped, 0 failed
SKIP mieru: no official mieru client is bundled with this matrix
SKIP naive: native core intentionally treats Naive as a sidecar
```

The same matrix is available from GitHub Actions as the manual `Native Interop Matrix`
workflow. Use the optional `case_filter` input to run one protocol family before a focused
gray release, or leave it empty to run all supported sing-box cases. Mihomo coverage is currently
a local matrix until the CI image has a pinned mihomo binary.
