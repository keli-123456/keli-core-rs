# Keli Core RS

`keli-core-rs` is the experimental Rust data-plane core track for Keli.

Production should keep using the current Go node stack:

```text
keliboard -> kelinode -> keli-core
```

This repository is for the long-term Rust core path:

```text
keliboard -> kelinode-rs -> keli-core-rs
```

The first goal is not to replace Xray immediately. The first goal is to define a small, testable core boundary that `kelinode-rs` can eventually drive without guessing behavior.

## Current Scope

Implemented in this first skeleton:

- Core config model for inbound, outbound, routing, TLS, sniffing, users, and stats.
- Protocol placement rules so external sidecar protocols such as Naive are not faked inside the core.
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
- VLESS / VMess / Trojan gRPC transport listeners.
- Hysteria2 QUIC TCP and UDP data paths, including salamander obfs validation.
- TUIC QUIC TCP and UDP data paths, including cubic/bbr/new_reno congestion selection.
- VLESS REALITY config validation, client ClientHello authentication, fallback routing, dest ServerHello validation, dest handshake capture, temporary certificate generation, REALITY certificate signature embedding, rustls TLS accept, and VLESS/Vision handoff.
- Mieru stream-underlay session demux so multiple TCP sessions can share one encrypted underlay connection.

Not implemented yet:

- Real-client interop verification for the VLESS REALITY TLS 1.3 server path.
- REALITY ML-DSA-65 certificate signing.
- DoH/DoT DNS execution, cache policy, and custom outbounds beyond freedom/SOCKS/HTTP/Shadowsocks/Trojan TCP+TLS/VLESS plain TCP.
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

- Experimental Rust rewrite of the node agent.
- Should eventually choose between `keli-core`, `keli-core-rs`, and sidecars per protocol.

`keli-core-rs`

- Experimental Rust rewrite path for the protocol core.
- Should only claim a protocol after it has real data-path tests.

`keli-edge`

- Sidecar supervisor/runtime for protocols that should not be forced into Xray-style core plans, such as Naive.

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

External sidecar protocols:

- Naive

Sidecar protocols are rejected by `keli-core-rs` config validation. They should be handled by `kelinode-rs` through `keli-edge`.

## Build

Run:

```bash
cargo fmt --check
cargo test
cargo run -- health
cargo run -- check-config ./core.json
cargo run -- run-config ./core.json
cargo run -- run-config ./core.json --control 127.0.0.1:18080
```

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
