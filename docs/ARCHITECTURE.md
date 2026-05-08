# Architecture

`keli-core-rs` has three boundaries.

## Config Boundary

The config boundary accepts a normalized core config from `kelinode-rs`.

It should not know how to call `keliboard` directly. Panel contracts belong in `kelinode-rs`; core contracts belong here.

## Runtime Boundary

The runtime boundary turns a validated config into an active data plane.

The current implementation only tracks fingerprints and reload decisions. Future stages will attach real listeners and protocol workers behind the same boundary.

## Control Boundary

The control boundary accepts transport-neutral commands:

- Apply config.
- Drain traffic.
- Read status.
- Stop.

`ApplyConfig` now starts the real `CoreService` for implemented protocols. This lets `kelinode-rs` later use an in-process adapter, a Unix socket, or another local transport without changing the core model.

The binary also exposes a minimal process boundary:

- `check-config <path>` validates a JSON `CoreConfig` and prints its fingerprint.
- `run-config <path>` applies a JSON `CoreConfig`, prints the apply response, and keeps the core service alive.
- `run-config <path> --control <addr>` also opens a local JSON-line TCP control socket for `status`, `drain_traffic`, and `stop`.

## Protocol Placement

Protocols are split by responsibility:

```text
Core-planned:      VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, SOCKS, HTTP
External sidecar:  Naive, Mieru
```

External sidecar protocols must be handled by `keli-edge`. The Rust core should not silently accept them and produce a fake running state.

## First Production Gate

The first useful production gate is not "all protocols complete".

The first useful gate is:

```text
SOCKS or HTTP inbound
  + real listener
  + user auth
  + per-user traffic counters
  + config reload
  + kelinode-rs drain/report integration
```

Current status:

```text
SOCKS5 TCP CONNECT
  + real listener
  + username/password authentication
  + UDP ASSOCIATE relay
  + per-user traffic counters
  + runtime config wiring
  - kelinode-rs drain/report integration

HTTP proxy
  + Basic authentication
  + CONNECT tunneling
  + plain HTTP request forwarding
  + block route enforcement
  + per-user traffic counters
  + runtime config wiring
  + process-level control socket for status and traffic drain
  - keep-alive reuse
  - kelinode-rs drain/report integration
```

Implemented listeners accept connections concurrently and join connection workers during shutdown so traffic accounting has a clean stop boundary.

The route matcher currently supports exact hosts, `*.suffix` rules, `.suffix` rules, wildcard `*`, Xray-style `domain:`, `full:`, and `keyword:` domain rules, numeric `ip:` exact/CIDR rules, `port:` exact/range rules, `network:tcp|udp` rules, and block decisions. Custom outbound routing is intentionally reported as unsupported until an outbound data path exists.

VLESS REALITY is still treated as an experimental path. The core validates REALITY config, authenticates the client ClientHello, falls back invalid clients to the configured target, mirrors the first ClientHello to the target, validates/captures the target ServerHello, generates a temporary Ed25519 certificate, embeds the REALITY certificate signature, completes the rustls server handshake over the prefixed ClientHello stream, and hands the decrypted stream to VLESS/Vision. It is not production-ready until the path has real-client interop coverage against the clients Keli expects to support.

The code-level parity gate is maintained in `docs/PARITY.md`. Anything not marked as a real code path there must remain rejected or sidecar-only.

Once that path is real, the same runtime/control boundary can be expanded protocol by protocol.
