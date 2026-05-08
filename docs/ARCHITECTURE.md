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
  + per-user traffic counters
  + runtime config wiring
  - kelinode-rs drain/report integration

HTTP proxy
  + Basic authentication
  + CONNECT tunneling
  + plain HTTP request forwarding
  + per-user traffic counters
  + runtime config wiring
  - keep-alive reuse
  - kelinode-rs drain/report integration
```

Once that path is real, the same runtime/control boundary can be expanded protocol by protocol.
