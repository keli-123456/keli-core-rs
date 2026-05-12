# Architecture

`keli-core-rs` has three boundaries.

## Config Boundary

The config boundary accepts a normalized core config from `kelinode-rs`.

It should not know how to call `keliboard` directly. Panel contracts belong in `kelinode-rs`; core contracts belong here.

## Runtime Boundary

The runtime boundary turns a validated config into an active data plane.

The runtime tracks config fingerprints, starts real listeners for implemented protocols, and can apply user-only updates to active listener user tables without rebinding ports.

## Control Boundary

The control boundary accepts transport-neutral commands:

- Apply config.
- Apply user delta.
- Drain traffic.
- Read status.
- Read metrics.
- Stop.

`ApplyConfig` starts the real `CoreService` for implemented protocols. If only inbound users change, it returns `updated` and patches the existing listeners in place; otherwise it reloads the service. This lets `kelinode-rs` later use an in-process adapter, a Unix socket, or another local transport without changing the core model.

`ApplyUserDelta` is the native small-change path. It applies added, updated, deleted, or full-snapshot users to one inbound without rebinding the listener. The core tracks an optional revision per inbound: non-full deltas with a known `base_revision` must match the current revision, while a full snapshot may reset the revision after a mismatch. Deleting a user immediately rejects new authentication for that user. Accepted TCP connections on SOCKS, HTTP CONNECT/plain HTTP, VLESS, VMess, Trojan, Shadowsocks, and AnyTLS main relay paths are registered by user and actively shut down on delete/full-snapshot removal; common async TCP relays that hold the shared user bandwidth limiter also exit when revocation is observed even while idle, HY2/TUIC QUIC accept/datagram/TCP relay loops watch limiter revocation, TLS/Vision/WebSocket/Shadowsocks relays apply revocation on both upload and download checkpoints, deleted/full-snapshot removals clear active device-session counters to avoid stale idle sessions after re-add, and already captured `user_id` values remain available for tail traffic accounting.

The control boundary also exposes `metrics`, a JSON snapshot intended for the agent or a future exporter. The current low-cardinality counters cover native user delta attempts, successes/errors, incremental versus full snapshot applies, revision mismatch/current-missing fallback signals, duration histogram buckets, and per-inbound active user counts. It deliberately does not use `user_uuid` as a metric dimension.

Production control sockets must either listen on a loopback address or set `KELI_CORE_CONTROL_TOKEN`. The TCP JSON-line transport remains useful for development and agent sidecars, but the core rejects non-loopback listeners without a token so `stop`, `apply_config`, `apply_user_delta`, `drain_traffic`, and `requeue_traffic` are not accidentally exposed.

The binary also exposes a minimal process boundary:

- `check-config <path>` validates a JSON `CoreConfig` and prints its fingerprint.
- `run-config <path>` applies a JSON `CoreConfig`, prints the apply response, and keeps the core service alive.
- `run-config <path> --control <addr>` also opens a local JSON-line TCP control socket for `apply_config`, `apply_user_delta`, `status`, `metrics`, `drain_traffic`, and `stop`.

## Protocol Placement

Protocols are split by responsibility:

```text
Core-planned:      VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, Mieru TCP, SOCKS, HTTP
External sidecar:  Naive
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

The route matcher currently supports exact hosts, `*.suffix` rules, `.suffix` rules, wildcard `*`, Xray-style `domain:`, `full:`, `keyword:`, `regexp:`, `geosite:`, numeric `ip:` exact/CIDR rules, `geoip:`, `port:` exact/range rules, `network:` rules, `protocol:` labels, block decisions, and custom outbound tags. Freedom outbounds can either keep direct egress or rewrite the target with `address`/`port`. SOCKS5 and HTTP outbounds establish TCP proxy tunnels with optional username/password, SOCKS5 outbounds proxy UDP routes through UDP ASSOCIATE, and VMess outbounds proxy UDP routes over VMess UDP command streams. VLESS, VMess, and Trojan custom outbounds can carry TCP routes over TCP/TLS, WebSocket, HTTPUpgrade, HTTP/2, gRPC, and old-QUIC transports with `none`/`aes-128-gcm`/`chacha20-poly1305` QUIC packet security when packet header obfuscation is disabled. VMess `alter_id` enables the legacy MD5/AES-CFB header-auth path for compatibility with old alterId servers while keeping the selected VMess body security. HTTP UDP remains rejected because HTTP CONNECT does not provide an equivalent UDP data path here. Built-in `geoip:private`/`geosite:private` and a few common site groups are available, `geoip`/`ip` rules lazily resolve domain targets when needed, and additional text rules can be supplied through `KELI_CORE_GEOIP_DIR` and `KELI_CORE_GEOSITE_DIR`.

Native DNS config is process-wide for the active core instance. It supports UDP DNS servers, `tcp://` DNS servers, domain-scoped server selection using the same route target syntax, and direct TCP/UDP target resolution through that resolver. It deliberately rejects encrypted URL-style DNS transports such as DoH/DoT until those transports have concrete code paths.

VLESS REALITY is still treated as an experimental path. The core validates REALITY config, authenticates the client ClientHello, falls back invalid clients to the configured target, mirrors the first ClientHello to the target, validates/captures the target ServerHello, generates a temporary Ed25519 certificate, embeds the REALITY certificate signature, completes the rustls server handshake over the prefixed ClientHello stream, and hands the decrypted stream to VLESS/Vision. It is not production-ready until the path has real-client interop coverage against the clients Keli expects to support.

The code-level parity gate is maintained in `docs/PARITY.md`. Anything not marked as a real code path there must remain rejected or sidecar-only.

Once that path is real, the same runtime/control boundary can be expanded protocol by protocol.
