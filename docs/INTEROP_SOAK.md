# Real Client Interop And Soak

This document is the production-readiness entry point for native Keli core validation. Passing unit tests and local loopback benchmarks is not enough to mark a protocol production-ready.

## Priority Matrix

Run interop in this order:

1. Hysteria2 TCP relay.
2. Hysteria2 UDP relay.
3. VLESS TCP TLS Vision, or Trojan TCP TLS if that is the larger live protocol for the target site.
4. The same TCP protocol with WebSocket, HTTPUpgrade, and gRPC when those transports are used by live nodes.
5. TUIC TCP and UDP.
6. Naive HTTP/2 CONNECT over TLS, after the primary live protocols above are stable.
7. Naive HTTP/3 CONNECT over QUIC, before enabling Naive on any high-latency or mobile-heavy site.

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
cargo run --release -- bench direct-tcp-stream --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench direct-tcp-proxy-stream --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench naive-tcp-stream --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench hy2-tcp --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench hy2-tcp-stream --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench hy2-udp --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench tuic-tcp --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench tuic-tcp-stream --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench tuic-udp --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench vless-tcp-stream --streams 16 --requests 5000 --payload 1024
```

Naive has local H2/TLS and H3/QUIC CONNECT data-path tests plus the `naive-tcp-stream` loopback
benchmark. Use the official NaiveProxy client for interop and soak before enabling it for live
traffic. Keep Naive marked `Partial` until H2/TLS behavior, H3/QUIC behavior, padding,
delete-user behavior, traffic accounting, auth/backoff behavior, and long-running reconnect
behavior are recorded.

Official NaiveProxy Linux soak helper:

```bash
# Default runs both native Naive cases: naive-h2-tls and naive-h3-quic.
bash scripts/naive_official_soak_linux.sh --rounds 1800 --interval-ms 1000

# Focused runs when narrowing a failure.
bash scripts/naive_official_soak_linux.sh --case naive-h2-tls --rounds 1800 --interval-ms 1000
bash scripts/naive_official_soak_linux.sh --case naive-h3-quic --rounds 1800 --interval-ms 1000
bash scripts/naive_official_soak_linux.sh --case naive-h3-quic --rounds 600 --restart-every-rounds 50 --netem "delay 80ms 20ms loss 1%"
```

The helper installs a short-lived local CA certificate for the official client and removes it on
exit. On Windows, the official client still requires the test certificate to be trusted by the OS;
without that trust the `quic://` probe can close before returning HTTP response headers.
The generated `runtime/interop-matrix/interop-summary.json` includes per-case probe telemetry:
round count, probe count, retry attempts, planned client restarts, and p50/p95/p99/max probe
latency. Treat a rising retry count or p99 over a long H3/weak-network run as a signal to inspect
the kept core/client logs before enabling Naive on real users. The matrix starts official
NaiveProxy with `--log=` so its client-side TLS/QUIC/HTTP errors are captured in the process
stdout/stderr logs and redacted before they are copied into failure summaries. Use
`--naive-net-log` on the matrix or `--net-log` on the Linux helper for deeper Chromium NetLog
artifacts when H3/QUIC still fails before normal client logs are emitted.

Local Windows loopback baseline after the bounded `Bytes` H2 bridge change:

| Command | Throughput | Requests | Errors | Retries | p50 | p95 | p99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `naive-tcp-stream --streams 16 --requests 1000 --payload 1024` | 649 Mbps | 16000 | 0 | 0 | 271 us | 570 us | 980 us |
| `naive-tcp-stream --streams 16 --requests 1000 --payload 4096` | 1.89 Gbps | 16000 | 0 | 0 | 328 us | 903 us | 1.68 ms |
| `naive-tcp-stream --streams 16 --requests 1000 --payload 65536` | 7.08 Gbps | 16000 | 0 | 0 | 1.87 ms | 4.08 ms | 5.86 ms |

For repeatable Rust-vs-baseline comparisons, collect a suite report instead of copying
one-off command output:

```bash
cargo run --release -- bench suite --streams 16 --requests 5000 --payload 1024 --repeats 3 --label rust-native --out runtime/bench/rust-suite.json
cargo run --release -- bench suite --commands hy2-tcp,hy2-tcp-stream,hy2-udp --streams 16 --requests 5000 --payload 1024 --repeats 3 --label rust-hy2 --out runtime/bench/rust-hy2-suite.json
cargo run --release -- bench external-suite \
  --commands socks-tcp-stream,http-connect-stream,shadowsocks-tcp-stream,trojan-tcp-stream,vless-tcp-stream,vmess-tcp-stream \
  --core socks-tcp-stream=127.0.0.1:29100 \
  --core http-connect-stream=127.0.0.1:29101 \
  --core shadowsocks-tcp-stream=127.0.0.1:29102 \
  --core trojan-tcp-stream=127.0.0.1:29103 \
  --core vless-tcp-stream=127.0.0.1:29104 \
  --core vmess-tcp-stream=127.0.0.1:29105 \
  --streams 16 --requests 5000 --payload 1024 --repeats 3 --label go-xray-tcp --out runtime/bench/go-suite.json
cargo run --release -- bench external-suite \
  --commands hy2-stream,hy2-udp,tuic-stream,tuic-udp \
  --core hy2-stream=127.0.0.1:29300 \
  --core hy2-udp=127.0.0.1:29300 \
  --core tuic-stream=127.0.0.1:29301 \
  --core tuic-udp=127.0.0.1:29301 \
  --cert ./bench.crt \
  --server-name localhost \
  --streams 16 --requests 5000 --payload 1024 --repeats 3 --label external-quic --out runtime/bench/external-quic.json
cargo run --release -- bench compare --baseline runtime/bench/go-suite.json --candidate runtime/bench/rust-suite.json --out runtime/bench/go-vs-rust.json
```

`external-suite` starts the local echo target itself and sends that target through the external
core. It accepts one `--core command=HOST:PORT` mapping per command. The older `--vless-core`
flag remains as a compatibility shortcut for `vless-tcp` and `vless-tcp-stream` only. External
HY2/TUIC commands also require a trusted certificate with `--cert CERT.pem`; use
`--cert command=CERT.pem` when each external inbound has a different certificate and
`--server-name` when the certificate SAN is not `localhost`. All baselines must be produced on
the same host with the same release/debug mode, stream count, request count, payload size, repeat
count, and report schema (`keli-core-bench-suite-v1`).

For Go/Xray TCP baselines, start the old core with one loopback inbound per protocol and use
benchmark credential `11111111-1111-1111-1111-111111111111`. The latest Linux matrix used:

- SOCKS on `127.0.0.1:29100`, username/password set to the benchmark credential.
- HTTP CONNECT on `127.0.0.1:29101`, basic auth set to the benchmark credential.
- Shadowsocks on `127.0.0.1:29102`, `aes-128-gcm`, password set to the benchmark credential.
- Trojan on `127.0.0.1:29103`, password set to the benchmark credential.
- VLESS on `127.0.0.1:29104`, UUID set to the benchmark credential.
- VMess on `127.0.0.1:29105`, UUID set to the benchmark credential, `alterId: 0`.

VMess interop note: Go/Xray waits for the first request body before sending the VMess response
header. The Rust outbound bridge must therefore start upload before reading the response header.
Reading the response header immediately after the request header can deadlock against Go/Xray.

The current old Go/Xray fork in this workspace does not expose HY2/TUIC inbounds: the Xray module
contains no `hysteria`/`tuic` protocol implementation, and test configs fail before startup. A
fair HY2/TUIC Go baseline therefore needs a production Go `v2node`/`kelinode` binary or another
old Go sidecar that actually supports these protocols. Once such a binary is started on loopback,
the external QUIC command above can collect the report with the same Rust client and echo target.

HY2/TUIC external harness smoke on the Linux host was verified by starting a temporary Rust
`keli-core-rs` external core on `127.0.0.1:29300` and `127.0.0.1:29301`, then running
`hy2-stream`, `hy2-udp`, `tuic-stream`, and `tuic-udp` through `external-suite`. The smoke used
`2` streams, `5` requests, `256` byte payloads, and all four commands completed `10 / 10` requests
with `0` errors and `0` retries.

Recent Windows loopback release baseline for VLESS stream mode (`16` streams, `5000` requests
per stream, `1024` byte payload, `3` repeats):

| Baseline | Roundtrip Mbps avg | p99 avg | Errors | Retries |
| --- | ---: | ---: | ---: | ---: |
| Go/Xray VLESS | 1090.87 | 612 us | 0 | 0 |
| Rust VLESS, 4MiB async traffic flush | 824.28 | 622 us | 0 | 0 |

Keep the Windows row as a local regression marker only; do not use it to judge Linux production
capacity.

Latest Linux same-host TCP stream matrix on the 4 vCPU Debian 12 test host (`64` streams, `5000`
requests per stream, single repeat). Rust native and Go/Xray used the same Rust benchmark client,
same local echo target, same credentials, same host, and release builds. Every row completed
`320000 / 320000` requests with `0` errors and `0` retries.

| Protocol | Payload | Rust Mbps | Go/Xray Mbps | Rust p95 | Go/Xray p95 | Rust p99 | Go/Xray p99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SOCKS | 1024 | 908.11 | 595.80 | 1746 us | 4124 us | 3486 us | 7729 us |
| SOCKS | 4096 | 3363.09 | 2339.80 | 2242 us | 4468 us | 4786 us | 8674 us |
| SOCKS | 65536 | 12944.64 | 11143.37 | 9609 us | 13616 us | 14748 us | 22613 us |
| HTTP CONNECT | 1024 | 846.99 | 655.23 | 2217 us | 3824 us | 4485 us | 8029 us |
| HTTP CONNECT | 4096 | 3392.09 | 2314.53 | 2179 us | 4707 us | 4690 us | 9522 us |
| HTTP CONNECT | 65536 | 13214.25 | 10820.07 | 9051 us | 13895 us | 15509 us | 22077 us |
| Shadowsocks | 1024 | 355.48 | 256.36 | 5036 us | 9194 us | 13002 us | 14972 us |
| Shadowsocks | 4096 | 1255.35 | 873.66 | 5653 us | 10934 us | 10335 us | 19212 us |
| Shadowsocks | 65536 | 1466.63 | 1456.43 | 49691 us | 51712 us | 54784 us | 55797 us |
| Trojan | 1024 | 817.27 | 400.56 | 2186 us | 6711 us | 6608 us | 12717 us |
| Trojan | 4096 | 2902.33 | 1793.39 | 2391 us | 5437 us | 4621 us | 10167 us |
| Trojan | 65536 | 14010.70 | 9429.10 | 9037 us | 16248 us | 14852 us | 24865 us |
| VLESS | 1024 | 785.34 | 503.98 | 2249 us | 5193 us | 9510 us | 10183 us |
| VLESS | 4096 | 3196.70 | 1917.81 | 2533 us | 5147 us | 5441 us | 9938 us |
| VLESS | 65536 | 12517.96 | 7834.71 | 13429 us | 19409 us | 21833 us | 28638 us |
| VMess | 1024 | 280.02 | 243.86 | 6461 us | 9806 us | 12729 us | 16362 us |
| VMess | 4096 | 1070.08 | 988.42 | 6134 us | 8962 us | 9988 us | 14382 us |
| VMess | 65536 | 3970.82 | 3334.78 | 39739 us | 40419 us | 109034 us | 66918 us |

On this Linux host, Rust native is above the Go/Xray baseline for the measured TCP stream protocols
and payload sizes. The shared stream relay buffer is now `64 KiB`, which helps large-payload relay
without regressing 1 KiB rows. VMess remains the most sensitive path because authenticated length
and body framing add fixed work per chunk; the current bridge defers VMess response-header reads
until upload starts to avoid Go/Xray interop deadlock, and uses larger relay/chunk buffers for
better 64 KiB throughput. A native blocking relay prototype, VMess cipher reuse prototype, and
smaller VMess chunk-size prototypes were rejected because they reduced same-host throughput.

Recent Linux loopback release baseline for QUIC UDP datagram paths after HY2/TUIC UDP reply
fragmentation and the benchmark echo socket buffer fix. UDP benchmarks reject payloads above
`65507` bytes because a single IPv4 UDP payload cannot legally carry `65536` bytes; large datagram
payloads are useful as fragmentation stress tests, not as the default production PPS shape.

| Command | Shape | Roundtrip Mbps | p95 | p99 | Errors | Retries |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `hy2-udp` | `64 x 5000 x 1024` | 534.37 | 2564 us | 3249 us | 0 | 26 |
| `hy2-udp` | `64 x 5000 x 4096` | 1484.03 | 2820 us | 3496 us | 0 | 108 |
| `hy2-udp` | `64 x 100 x 32768` | 321.67 | 4339 us | 30205 us | 0 | 131 |
| `tuic-udp` | `64 x 5000 x 1024` | 490.75 | 2872 us | 3585 us | 0 | 22 |
| `tuic-udp` | `64 x 5000 x 4096` | 1450.43 | 2705 us | 3500 us | 0 | 123 |
| `tuic-udp` | `64 x 100 x 16384` | 264.38 | 3581 us | 13827 us | 0 | 113 |

The 4 KiB rows verify that HY2/TUIC can now move payloads larger than one QUIC datagram MTU through
the local benchmark without errors. Very large 32 KiB+ datagram stress runs are retry-heavy because
QUIC datagrams remain unreliable; treat those rows as boundary checks and keep the primary HY2/TUIC
UDP regression target at 1 KiB and 4 KiB.

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
cargo run --example interop_matrix -- --client naive --naive /path/to/naive --only naive
cargo run --example interop_matrix -- --client both --sing-box /path/to/sing-box --mihomo /path/to/mihomo
```

On the Windows development workspace used for Keli, the bundled client paths are usually:

```powershell
cargo run --example interop_matrix -- --sing-box ..\tools\sing-box\sing-box-1.12.22-windows-amd64\sing-box.exe
cargo run --example interop_matrix -- --client mihomo --mihomo ..\tools\mihomo\mihomo-windows-amd64-v1.19.24\mihomo-windows-amd64.exe
cargo run --example interop_matrix -- --client naive --naive C:\path\to\naive.exe --only naive
```

Useful filters:

```bash
cargo run --example interop_matrix -- --sing-box /path/to/sing-box --only vless
cargo run --example interop_matrix -- --client mihomo --mihomo /path/to/mihomo --only vless-reality
cargo run --example interop_matrix -- --client naive --naive /path/to/naive --only naive-h2-tls --keep
cargo run --example interop_matrix -- --client naive --naive /path/to/naive --only naive-h2-tls --tls-cert /path/to/trusted.crt --tls-key /path/to/trusted.key --naive-server-name naive.example.test --keep
cargo run --example interop_matrix -- --client both --sing-box /path/to/sing-box --mihomo /path/to/mihomo --only hy2 --keep
```

Short soak / repeated probe runs:

```bash
cargo run --example interop_matrix -- --client naive --naive /path/to/naive --only naive-h2-tls --probe-rounds 120 --probe-interval-ms 1000 --keep
cargo run --example interop_matrix -- --client naive --naive /path/to/naive --only naive-h2-tls --probe-rounds 120 --probe-interval-ms 1000 --naive-restart-every-rounds 30 --keep
cargo run --example interop_matrix -- --sing-box /path/to/sing-box --only hy2 --probe-rounds 120 --probe-interval-ms 1000 --keep
```

Linux official NaiveProxy soak helper:

```bash
# 30 minute smoke, one probe per second.
bash scripts/naive_official_soak_linux.sh --rounds 1800 --interval-ms 1000

# Reconnect soak: restart the official NaiveProxy client every 5 minutes.
bash scripts/naive_official_soak_linux.sh --rounds 1800 --interval-ms 1000 --restart-every-rounds 300

# Weak-network loopback soak. This applies tc netem to lo and removes it on exit.
bash scripts/naive_official_soak_linux.sh --rounds 1800 --interval-ms 1000 --restart-every-rounds 300 --netem "delay 80ms 20ms loss 1%"
```

The Linux helper downloads the pinned official NaiveProxy release when `--naive` is omitted,
generates a one-day local test certificate, installs it into the system trust store, runs the
interop matrix, and removes the certificate on exit. When `--netem` is set, it also installs and
removes the selected `tc netem` qdisc. Use it only on a disposable test host because `tc` on `lo`
affects other loopback traffic while the soak is running.

The sing-box client verifies TCP forwarding for SOCKS, HTTP proxy, Shadowsocks, VLESS, VLESS
REALITY Vision, VMess, Trojan, AnyTLS, Hysteria2, and TUIC combinations, plus UDP relay through
Shadowsocks, Hysteria2, and TUIC.

The mihomo client currently verifies SOCKS, HTTP proxy, Shadowsocks TCP/UDP, VLESS TCP/TLS/Vision,
VLESS REALITY Vision, VLESS WS/gRPC, VMess TCP/TLS/WS/gRPC, Trojan TLS/WS/gRPC, Hysteria2 TCP/UDP,
Hysteria2 Salamander, and TUIC TCP/UDP. It skips cases without a reliable mihomo proxy equivalent
in this matrix, such as HTTPUpgrade, Trojan plain TCP, AnyTLS, Mieru, and Naive.

The NaiveProxy client verifies the native `naive-h2-tls` case with a generated
`listen=socks://127.0.0.1:<port>` and `proxy=https://user:pass@localhost:<port>`
configuration. Because the matrix uses a temporary self-signed localhost certificate by default,
official NaiveProxy runs may require the generated certificate to be trusted by the host OS or a
trusted local test certificate to be wired in before recording the result as production interop.
Use `--tls-cert`, `--tls-key`, and `--naive-server-name` for that path. When the Naive server name
is not localhost, the matrix passes a NaiveProxy host-resolver rule so the official client still
connects to the loopback core listener.

Latest official NaiveProxy Windows x64 interop/short-soak sample:

```text
client: naiveproxy-v148.0.7778.96-5-win-x64
case: naive-h2-tls
command: cargo run --release --example interop_matrix -- --core target\release\keli-core-rs.exe --client naive --naive tools\naiveproxy\naiveproxy-v148.0.7778.96-5-win-x64\naive.exe --only naive --tls-cert runtime\interop-certs\naive-local.crt --tls-key runtime\interop-certs\naive-local.key --probe-rounds 120 --probe-interval-ms 500 --keep
result: 120 / 120 probe rounds passed, 1 passed, 0 skipped, 0 failed
duration: 62347 ms
certificate handling: localhost test certificate was temporarily trusted in the CurrentUser Root store and removed after the run
artifact summary: runtime/interop-matrix/interop-summary.json
```

Latest official NaiveProxy reconnect sample:

```text
client: naiveproxy-v148.0.7778.96-5-win-x64
case: naive-h2-tls
command: cargo run --release --example interop_matrix -- --core target\release\keli-core-rs.exe --client naive --naive tools\naiveproxy\naiveproxy-v148.0.7778.96-5-win-x64\naive.exe --only naive --tls-cert runtime\interop-certs\naive-local.crt --tls-key runtime\interop-certs\naive-local.key --probe-rounds 30 --probe-interval-ms 200 --naive-restart-every-rounds 10 --keep
result: 30 / 30 probe rounds passed, with official NaiveProxy restarted before rounds 11 and 21
summary: 1 passed, 0 skipped, 0 failed
certificate handling: localhost test certificate was temporarily trusted in the CurrentUser Root store and removed after the run
```

Both clients use a deterministic local TLS destination fixture for REALITY.

Latest local Windows loopback sample:

```text
interop matrix summary: 34 passed, 0 skipped, 0 failed
SKIP mieru: no official mieru client is bundled with this matrix
SKIP naive official-client: pass --client naive --naive <naive> --only naive
```

Latest local Windows loopback sample for mihomo v1.19.24:

```text
interop matrix summary: 24 passed, 10 skipped, 0 failed
SKIP mieru: no official mieru client is bundled with this matrix
SKIP naive official-client: pass --client naive --naive <naive> --only naive
```

The same matrix is available from GitHub Actions as the manual `Native Interop Matrix`
workflow. Use the optional `case_filter` input to run one protocol family before a focused
gray release, or leave it empty to run all supported sing-box cases. Enable `include_naive` to
download the pinned official NaiveProxy Linux client, install a temporary trusted local certificate,
and run both `naive-h2-tls` and `naive-h3-quic` by default. Set `case_filter` to one exact case name
when you only want H2 or H3. Increase `probe_rounds` and set `probe_interval_ms` for a short CI soak
before a gray release. For reconnect and weak-network Naive coverage, set
`naive_restart_every_rounds` and optionally `naive_netem`, for example `delay 80ms 20ms loss 1%`.
The NaiveProxy job timeout is intentionally longer than the default so a 30 minute or 6 hour soak
can run from the manual workflow. Mihomo coverage is currently a local matrix until the CI image has
a pinned mihomo binary.
