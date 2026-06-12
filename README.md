# Keli Core RS

`keli-core-rs` is the experimental Rust data-plane core track for Keli.

The legacy production baseline is the Go node stack:

```text
keliboard -> kelinode -> keli-core
```

This repository is for the long-term Rust core path:

```text
keliboard -> kelinode-rs -> keli-core-rs
```

The current goal is to make `kelinode-rs -> keli-core-rs` the native Keli data-plane path while keeping old Go behavior as the comparison and rollback baseline.

## Current Scope

Implemented in this first skeleton:

- Core config model for inbound, outbound, routing, TLS, sniffing, users, and stats.
- Protocol validation rules so unsupported protocol shapes are rejected instead of reported as fake running listeners.
- Go-compatible user traffic keys using `<node-tag>|<user-uuid>`.
- Traffic registry with minimum-threshold draining.
- Runtime planning with deterministic config fingerprints.
- Apply/noop reload decisions wired to real listener startup.
- User-only config changes hot-update active listener user tables without rebinding ports.
- Transport-neutral control commands for apply config, drain traffic, status, and stop.
- SOCKS5 TCP CONNECT inbound with username/password authentication.
- Per-user SOCKS5 TCP upload/download accounting.
- HTTP proxy inbound with Basic authentication.
- HTTP CONNECT tunneling and plain HTTP request forwarding.
- Basic route matching with block decisions for implemented proxy inbounds.
- Per-user device_limit enforcement for SOCKS5 and HTTP proxy connections.
- Per-user speed_limit enforcement for SOCKS5 and HTTP proxy traffic.
- Shadowsocks AEAD TCP and UDP inbound for aes-128-gcm, aes-256-gcm, and chacha20-ietf-poly1305.
- VLESS TCP and UDP inbound for non-TLS, non-transport TCP/UDP commands.
- Trojan TCP inbound for non-TLS TCP CONNECT and UDP ASSOCIATE.
- AnyTLS TCP frame inbound with password authentication, TCP stream forwarding, UDP-over-TCP relay, and padding-scheme update negotiation.
- Concurrent per-listener connection worker threads with stop-time joining.
- Local JSON-line TCP control socket for apply config, process status, traffic drain, and stop commands.
- CLI with `version`, `health`, `check-config`, and `run-config`.
- SOCKS5 UDP ASSOCIATE with UDP packet framing, relay lifetime bound to the TCP control connection, and per-user traffic accounting.
- VMess AEAD TCP/UDP inbound with TCP, TLS, WebSocket, TLS WebSocket, authenticated length, and replay protection.
- VLESS Vision flow for TLS and TCP relay paths.
- Trojan TLS, WebSocket, and TLS WebSocket TCP/UDP data paths.
- VLESS / VMess / Trojan HTTP/2 and gRPC transport listeners/outbounds, including H2 outbound request headers for XHTTP stream-one interop.
- Hysteria2 QUIC TCP and UDP data paths, including salamander obfs validation.
- TUIC QUIC TCP and UDP data paths, including cubic/bbr/new_reno congestion selection.
- VLESS REALITY config validation, client ClientHello authentication, fallback routing, dest ServerHello validation, dest handshake capture, temporary certificate generation, REALITY certificate signature embedding, rustls TLS accept, and VLESS/Vision handoff.
- Mieru stream-underlay session demux so multiple TCP sessions can share one encrypted underlay connection.
- Naive HTTP/2 CONNECT over TLS with Basic authentication, optional Naive padding frames, TCP forwarding, per-user traffic accounting, speed/device limits, and ApplyUserDelta user-table updates.
- Local sing-box and mihomo real-client interop matrix coverage for VLESS REALITY Vision and other primary protocol paths, plus a NaiveProxy official-client entry for the native Naive H2/TLS path.

Not implemented yet:

- REALITY ML-DSA-65 certificate signing.
- Naive H3/QUIC transport and long production NaiveProxy soak coverage.
- DoH/DoT DNS execution, cache policy, and custom outbounds beyond freedom/SOCKS/HTTP/Shadowsocks/Trojan TCP+TLS+WS+HTTPUpgrade+H2+gRPC/VLESS TCP+TLS+WS+HTTPUpgrade+H2+gRPC+Vision TCP TLS/VMess TCP+TLS+WS+HTTPUpgrade+H2+gRPC+UDP-over-stream+legacy alterId auth/XHTTP stream-one rendered as H2.
- Realtime integration.
- Broader release platform matrix and performance profiles.

The code-level protocol and runtime parity gate is tracked in `docs/PARITY.md`.

## Relationship To Existing Projects

`kelinode`

- Current production node agent.
- Pulls node config and users from `keliboard`.
- Embeds and drives `keli-core`.

`keli-core`

- Current production protocol core.
- Fork of Xray-core.
- Handles the real data plane today.

`kelinode-rs`

- Rust rewrite of the node agent.
- Drives `keli-core-rs` as the native data-plane core for server-side node execution.

`keli-core-rs`

- Rust native protocol core.
- Should only claim a protocol after it has real data-path tests and clear validation for unsupported shapes.

## Protocol Strategy

Early core-planned protocols:

- SOCKS
- HTTP
- Shadowsocks
- VLESS
- VMess
- Trojan
- Hysteria2
- TUIC
- AnyTLS
- Mieru TCP
- Naive H2/TLS

Protocols that are not listed as core-planned above must stay rejected until they have strict
validation, native listeners, traffic accounting, user delta behavior, and real-client interop
coverage.

## Build

Run:

```bash
cargo fmt --check
cargo test
cargo run -- health
cargo run -- check-config ./core.json
cargo run -- run-config ./core.json
cargo run -- run-config ./core.json --control 127.0.0.1:18080
cargo run -- bench direct-tcp-stream --streams 8 --requests 1000 --payload 1024
cargo run -- bench direct-tcp-proxy-stream --streams 8 --requests 1000 --payload 1024
cargo run -- bench naive-tcp-stream --streams 8 --requests 1000 --payload 1024
cargo run -- bench vless-tcp --streams 8 --requests 1000 --payload 1024
cargo run -- bench vless-tcp-stream --streams 8 --requests 1000 --payload 1024
cargo run -- bench hy2-tcp --streams 8 --requests 1000 --payload 1024
cargo run -- bench hy2-tcp-stream --streams 8 --requests 1000 --payload 1024
cargo run -- bench hy2-udp --streams 8 --requests 1000 --payload 1024
cargo run -- bench tuic-tcp --streams 8 --requests 1000 --payload 1024
cargo run -- bench tuic-tcp-stream --streams 8 --requests 1000 --payload 1024
cargo run -- bench tuic-udp --streams 8 --requests 1000 --payload 1024
cargo run -- bench suite --streams 8 --requests 1000 --payload 1024 --repeats 3 --out runtime/bench/rust-suite.json
cargo run -- bench external-suite --vless-core 127.0.0.1:19080 --commands vless-tcp-stream --streams 8 --requests 1000 --payload 1024 --repeats 3 --label go-xray --out runtime/bench/go-suite.json
cargo run -- bench external-suite --commands hy2-stream,hy2-udp,tuic-stream,tuic-udp --core hy2-stream=127.0.0.1:29300 --core hy2-udp=127.0.0.1:29300 --core tuic-stream=127.0.0.1:29301 --core tuic-udp=127.0.0.1:29301 --cert ./bench.crt --server-name localhost --streams 8 --requests 1000 --payload 1024 --label external-quic --out runtime/bench/external-quic.json
cargo run -- bench compare --baseline runtime/bench/go-suite.json --candidate runtime/bench/rust-suite.json
```

## Local Benchmarks

The benchmark command starts local loopback echo and core listeners, drives real protocol
traffic through the core, and prints JSON metrics. `direct-tcp-stream` measures the local
echo ceiling without a proxy hop. `direct-tcp-proxy-stream` measures raw TCP proxy relay
without protocol parsing, which is the baseline for TCP stream fixed overhead. The current
`vless-tcp` benchmark is
connection-per-request so it measures VLESS TCP setup plus one echo payload per request.
The `vless-tcp-stream` benchmark opens one VLESS TCP connection per stream and sends
all request payloads through that connection, so it isolates the steady-state relay path.
The `naive-tcp-stream` benchmark opens one Naive H2 CONNECT tunnel over TLS per worker and
sends all request payloads through that tunnel, isolating native Naive H2/TLS relay overhead.
The Naive H2 body bridge uses bounded `Bytes` channels so slow clients apply backpressure instead
of growing unbounded relay memory.
The `hy2-tcp` benchmark authenticates once and opens TCP request streams over a single
QUIC connection, so the stream count represents HY2 multiplexed concurrency.
The `hy2-tcp-stream` benchmark opens one HY2 TCP stream per worker and sends all request
payloads through that stream, isolating steady-state relay inside an established HY2 stream:
`tuic-tcp` follows the same connection-per-request shape as a proxy opening many short TCP
sessions, while `tuic-tcp-stream` keeps one CONNECT stream per worker and measures steady-state
TUIC relay without exhausting local ephemeral ports on Windows.

```bash
cargo run --release -- bench direct-tcp-stream --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench direct-tcp-proxy-stream --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench naive-tcp-stream --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench vless-tcp --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench vless-tcp-stream --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench hy2-tcp --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench hy2-tcp-stream --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench hy2-udp --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench tuic-tcp --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench tuic-tcp-stream --streams 16 --requests 5000 --payload 1024
cargo run --release -- bench tuic-udp --streams 16 --requests 5000 --payload 1024
```

Use `bench suite` when collecting comparable protocol results:

```bash
cargo run --release -- bench suite --streams 16 --requests 5000 --payload 1024 --repeats 3 --label rust-native --out runtime/bench/rust-suite.json
cargo run --release -- bench suite --commands hy2-tcp,hy2-tcp-stream,hy2-udp --streams 16 --requests 5000 --payload 1024 --repeats 3 --label rust-hy2 --out runtime/bench/rust-hy2-suite.json
```

To collect an old Go/Xray VLESS baseline, start the Go core with a VLESS TCP inbound
using benchmark user UUID `11111111-1111-1111-1111-111111111111` and a `freedom`
outbound, then run:

```bash
cargo run --release -- bench external-suite --vless-core 127.0.0.1:19080 --commands vless-tcp-stream --streams 16 --requests 5000 --payload 1024 --repeats 3 --label go-xray-vless --out runtime/bench/go-suite.json
```

`external-suite` starts its own local echo target and sends the target address through
the external core, so the external Go core should not need a special outbound beyond
normal direct/freedom routing. For TCP protocols, provide one `--core command=HOST:PORT`
mapping per external inbound. For HY2/TUIC, also provide the server certificate with
`--cert CERT.pem` or `--cert command=CERT.pem`; use `--server-name` when the certificate
SAN is not `localhost`.

The old Go/Xray fork in this workspace does not currently expose HY2/TUIC inbounds, so
there is no honest Go/Xray HY2/TUIC baseline from that binary. If a production Go
`v2node`/`kelinode` binary with HY2/TUIC support is available, start its HY2 and TUIC
inbounds on loopback and collect the baseline with the external QUIC command above.

Use `bench compare` only with reports generated from the same host, release mode,
stream count, request count, payload size, and repeat count:

```bash
cargo run --release -- bench compare --baseline runtime/bench/go-suite.json --candidate runtime/bench/rust-suite.json --out runtime/bench/go-vs-rust.json
```

For release gating, keep the same comparison rules and add explicit failure thresholds:

```bash
cargo run --release -- bench compare \
  --baseline runtime/bench/go-suite.json \
  --candidate runtime/bench/rust-suite.json \
  --out runtime/bench/go-vs-rust.json \
  --max-throughput-drop-percent 10 \
  --max-p99-increase-percent 30 \
  --fail-on-errors \
  --require-all-baseline-commands
```

The threshold flags are opt-in. Without them, `bench compare` remains report-only.

The baseline file must use the same `keli-core-bench-suite-v1` schema. Do not claim a
Go-vs-Rust performance win from single-run output copied from a different host, debug
build, payload size, stream count, request count, or schema.

Use the same host, release build, payload, stream count, and request count when comparing
against Xray or another core. The JSON includes `runtime_workers` when applicable, `completed_requests`,
`errors`, `error_rate`, `retries`, throughput, and latency percentiles. The `retries`
field records retryable local socket EOF/reset noise seen while establishing benchmark
requests; treat non-zero retries or errors as environment noise until reproduced on a
second run.

Real-client interop and soak runs are tracked separately from local loopback benchmarks in
`docs/INTEROP_SOAK.md`. Do not mark a protocol production-ready from these loopback
benchmarks alone.

## Release Artifacts

Tag pushes such as `v0.1.0` and manual release workflow runs package the Linux x86_64 binary as:

```text
keli-core-rs-<version>-linux-x86_64.tar.gz
keli-core-rs-<version>-linux-x86_64.tar.gz.sha256
keli-core-rs-<version>-linux-x86_64.manifest.json
```

`kelinode-rs` can run that binary directly when `kernel.type: keli-core-rs` is selected. Put `keli-core-rs` in `PATH`, or set `kernel.core_command` in the node config to the absolute installed binary path.

## Compatibility Rules

Any future implementation must preserve:

- Docker direct node deployments.
- Binary machine-bound deployments.
- Single-site single-node deployments.
- Multi-site multi-node deployments.
- Existing `keliboard` node API contracts.
- Existing traffic report keys and per-user accounting behavior.

Do not mark this core production-ready until protocol data paths have interop tests against real clients.
