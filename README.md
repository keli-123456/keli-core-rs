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
- Protocol placement rules so external sidecar protocols such as Naive and Mieru are not faked inside the core.
- Go-compatible user traffic keys using `<node-tag>|<user-uuid>`.
- Traffic registry with minimum-threshold draining.
- Runtime planning with deterministic config fingerprints.
- Apply/noop reload decisions.
- Transport-neutral control commands for apply config, drain traffic, status, and stop.
- Tiny CLI with `version` and `health`.

Not implemented yet:

- Real socket listeners.
- Real protocol handshakes.
- Encryption/decryption data paths.
- DNS/routing execution.
- Realtime integration.
- Hot user patching.
- Production packaging.

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

- Sidecar supervisor/runtime for protocols that should not be forced into Xray-style core plans, such as Mieru and Naive.

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

External sidecar protocols:

- Naive
- Mieru

Sidecar protocols are rejected by `keli-core-rs` config validation. They should be handled by `kelinode-rs` through `keli-edge`.

## Build

This machine does not currently have Rust installed. On a Linux build machine:

```bash
cargo fmt --check
cargo test
cargo run -- health
```

## Compatibility Rules

Any future implementation must preserve:

- Docker direct node deployments.
- Binary machine-bound deployments.
- Single-site single-node deployments.
- Multi-site multi-node deployments.
- Existing `keliboard` node API contracts.
- Existing traffic report keys and per-user accounting behavior.

Do not mark this core production-ready until protocol data paths have interop tests against real clients.
