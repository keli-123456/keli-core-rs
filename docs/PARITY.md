# Native Core Parity

This document is the code-level gate for the experimental Rust native core.

Do not move real panel traffic onto `keli-core-rs` just because a protocol appears in the schema. A protocol is usable only when all three layers are true:

1. Config validation accepts only the implemented feature set.
2. Runtime has a real listener and data path.
3. Real clients have passed interop tests for the exact panel configuration.

The current production path remains:

```text
keliboard -> kelinode -> keli-core
```

The experimental path is:

```text
keliboard -> kelinode-rs -> keli-core-rs
```

## Status Meanings

| Status | Meaning |
| --- | --- |
| Code path | Validation, listener startup, auth, forwarding, and traffic accounting exist in Rust. |
| Partial | Some real code exists, but common panel options or real-client coverage are still missing. |
| Rejected | The Rust core intentionally rejects this so it cannot look supported by accident. |
| Sidecar | The feature belongs to an external runtime rather than `keli-core-rs`. |

## Protocol Matrix

| Protocol | Keli panel/native render | `keli-core-rs` runtime | Implemented code-level scope | Missing before production |
| --- | --- | --- | --- | --- |
| SOCKS | Rendered by `kelinode-rs` | Code path | TCP CONNECT, UDP ASSOCIATE, username/password auth, per-user traffic, speed/device limits | Real workload soak |
| HTTP proxy | Rendered by `kelinode-rs` | Code path | Basic auth, HTTP CONNECT, plain HTTP forwarding, block routes, per-user traffic, speed/device limits | Keep-alive reuse, real workload soak |
| Shadowsocks | Rendered by `kelinode-rs` for supported AEAD ciphers | Partial | TCP and UDP AEAD for `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, per-user traffic, TCP speed/device limits, UDP traffic accounting, UDP client-source device limits | 2022 ciphers, HTTP obfs, real-client interop |
| VLESS | Rendered by `kelinode-rs` | Partial | TCP, UDP command, WS, HTTPUpgrade, gRPC, TLS, VLESS Vision over TCP TLS, block routes, per-user traffic, speed/device limits | XUDP/Mux, real-client matrix |
| VLESS REALITY | Rendered by `kelinode-rs` | Partial | Config validation, ClientHello auth, fallback routing, destination ServerHello validation/capture, temporary certificate generation, REALITY cert signature embedding, rustls accept, VLESS/Vision handoff | Real-client TLS 1.3 interop, ML-DSA-65 |
| VMess | Rendered by `kelinode-rs` | Partial | AEAD TCP and UDP command, TLS, WS, TLS WS, HTTPUpgrade, gRPC, authenticated length, replay protection, per-user traffic, speed/device limits | Legacy alterId variants, real-client matrix |
| Trojan | Rendered by `kelinode-rs` | Partial | TCP, UDP ASSOCIATE over stream, TLS, WS, TLS WS, HTTPUpgrade, gRPC, per-user traffic, speed/device limits | Real-client UDP/TLS/WS matrix |
| AnyTLS | Rendered by `kelinode-rs` | Partial | TCP frame inbound, password authentication, TCP stream forwarding, UDP-over-TCP, padding-scheme update negotiation, per-user traffic, speed/device limits | Real-client matrix |
| Hysteria2 | Rendered by `kelinode-rs` | Partial | QUIC listener, password auth, TCP relay, UDP relay, salamander obfs, bandwidth options, per-user traffic, speed/device limits | Real-client matrix and production soak |
| TUIC | Rendered by `kelinode-rs` when 0-RTT is absent | Partial | QUIC listener, UUID/token auth, TCP relay, UDP relay, cubic/bbr/new_reno congestion selection, per-user traffic, speed/device limits | zero-RTT, real-client matrix |
| Naive | Sidecar plan only | Sidecar | Explicitly rejected by native core validation | Concrete Caddy forward_proxy deployment integration |
| Mieru | Sidecar plan only | Sidecar | Explicitly rejected by native core validation | Operator-provided `mita` runtime, traffic/status integration |

## Transport Matrix

| Transport | Protocols | Rust core status | Notes |
| --- | --- | --- | --- |
| TCP | SOCKS, HTTP, Shadowsocks, VLESS, VMess, Trojan, AnyTLS | Code path/partial by protocol | Shadowsocks also supports UDP on the same port. |
| TLS over TCP | VLESS, VMess, Trojan | Code path/partial by protocol | Certificate file based TLS exists. |
| WS | VLESS, VMess, Trojan | Code path | Path and Host settings are accepted. |
| TLS WS | VLESS, VMess, Trojan | Code path | Real-client matrix still required. |
| HTTPUpgrade | VLESS, VMess, Trojan | Code path | Path and Host settings are accepted. |
| gRPC | VLESS, VMess, Trojan | Code path | `TunMulti` is rejected. |
| REALITY | VLESS only | Partial | TCP only. ML-DSA-65 is rejected. |
| QUIC/Hysteria2 | Hysteria2 | Partial | TCP and UDP relay paths exist. |
| QUIC/TUIC | TUIC | Partial | TCP and UDP relay paths exist. |
| KCP/QUIC/XHTTP/H2 | Xray production path only | Rejected | Do not render into `keli-core-rs` until native data paths exist. |

## Runtime Capability Matrix

| Capability | Status | Notes |
| --- | --- | --- |
| Config schema and validation | Code path | Unsupported protocols and options should fail early. |
| Listener apply/noop/update fingerprinting | Code path | Runtime planning is deterministic; user-only changes patch active listeners without rebinding ports. |
| Local control socket | Code path | Apply config, status, stop, and traffic drain commands exist. |
| Per-user traffic accounting | Code path | Uses Go-compatible `<node-tag>|<user-uuid>` keys. |
| Per-user device limit | Code path | Enforced by shared session tracker for native listeners; concurrent sessions from the same client IP count as one device. |
| Per-user speed limit | Code path | Enforced by shared bandwidth limiter for native listeners. |
| Direct outbound | Code path | Built-in direct egress plus freedom route outbounds. |
| Block routing | Code path | Exact/wildcard/suffix, `domain:`/`full:`/`keyword:`, `regexp:`, `geosite:`, numeric IP/CIDR, `geoip:`, port/range, `network:`, and `protocol:` matching. |
| Custom outbound routing | Partial | Freedom outbounds render and execute, including optional `address`/`port` redirects. SOCKS5 and HTTP outbounds render and execute for TCP routes, including username/password. SOCKS5 outbounds also execute UDP routes through UDP ASSOCIATE; HTTP UDP remains rejected. |
| DNS execution | Partial | Native core accepts DNS server config, selects servers by domain route rules, and resolves direct TCP/UDP targets through UDP or `tcp://` DNS with `UseIPv4` default. DoH/DoT and cache policy are not implemented yet. |
| Hot user patching | Code path | `ApplyConfig` returns `updated` for user-only changes and replaces protocol user tables in-place. |
| Realtime integration | Rejected | Belongs first in `kelinode-rs` runtime control. |
| Production packaging | Rejected | Release profile exists, but artifacts/signing/install flow are not complete. |

## Code-Complete Before Interop Gate

Before real-client interop starts, each target protocol must have:

- A strict validator that rejects unsupported panel options.
- A listener/data path test that proves auth and forwarding.
- A traffic drain test using the production traffic key format.
- A negative test for every panel option that is intentionally not implemented.
- A renderer test in `kelinode-rs` proving the panel field maps into the native core schema.

The first interop batch should be:

1. VLESS TCP TLS Vision.
2. VLESS TCP REALITY Vision.
3. VMess TCP TLS and WS TLS.
4. Trojan TCP TLS and WS TLS.
5. Hysteria2 TCP/UDP.
6. TUIC TCP/UDP.
