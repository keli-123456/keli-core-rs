# Xray Dispatcher Policy Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move keli-core-rs closer to the stable Go/Xray path for routing, sniffing, connection policy, and route outbound compatibility.

**Architecture:** Add a small central dispatcher/policy layer in keli-core-rs and migrate high-risk route decisions through it without rewriting every protocol. Keep protocol parsers unchanged, but centralize route decision, outbound connection, and sniff label behavior. Update kelinode-rs rendering so generated native core configs carry Xray-like policy defaults and parse common Xray route outbound shapes.

**Tech Stack:** Rust 1.74, keli-core-rs, kelinode-rs, serde JSON config, cargo tests.

---

### Task 1: Policy Defaults

**Files:**
- Modify: `keli-core-rs/src/config.rs`
- Modify: `keli-core-rs/src/service.rs`
- Modify: `keli-core-rs/src/lib.rs`
- Modify: `kelinode-rs/src/core.rs`

- [x] Add `PolicyConfig` to `CoreConfig` with defaults matching old Go/Xray: handshake 4s, connection idle 120s, uplink only 2s, downlink only 4s, buffer size 128 KiB, sniff cache 200ms.
- [x] Add tests that deserialize missing policy as defaults and reject zero/oversized values only where they would break runtime semantics.
- [x] Render the policy from kelinode-rs so native generated configs are explicit and inspectable.

### Task 2: Central Dispatcher Methods

**Files:**
- Create: `keli-core-rs/src/dispatcher.rs`
- Modify: `keli-core-rs/src/lib.rs`
- Modify: selected protocol files that currently call `RouteMatcher::decide_target` directly.

- [x] Add `RouteDispatcher` owning `RouteMatcher`, `PolicyConfig`, and `SniffingConfig`.
- [x] Add sync/async helpers for TCP connect and UDP send that return the same errors protocols already expect.
- [x] Migrate VLESS, AnyTLS, HY2, TUIC, Socks, HTTP, Trojan, VMess, Shadowsocks, Mieru, and Naive route decisions to call the dispatcher.

### Task 3: Bounded Sniffing

**Files:**
- Modify: `keli-core-rs/src/dispatcher.rs`
- Modify: route-call sites with existing initial payloads first.

- [x] Implement Xray-style bounded sniff labels: only `dest_override` protocols are appended, and sniffing disabled means the dispatcher uses only the base network label.
- [x] Keep the cache window at 200ms in policy and use it as the public semantic even where a protocol already has initial payload available.
- [x] Add tests for HTTP/TLS/QUIC labels, disabled sniffing, and filtered `dest_override`.

### Task 4: Route Outbound Compatibility

**Files:**
- Modify: `kelinode-rs/src/core.rs`
- Modify: `keli-core-rs/src/config.rs` only when the normalized outbound shape needs a new field.

- [x] Accept common Go/Xray route outbound shapes for supported native protocols, including `settings.servers`, `settings.vnext`, `streamSettings.sockopt`, `mux`, and no-op official keys that should not block config rendering.
- [x] Keep unsupported protocol implementations rejected with a clear error, instead of silently pretending they work.
- [x] Add renderer tests for ignored official no-op keys and blackhole-style route conversion where applicable.

### Task 5: Verification and Release

**Files:**
- Modify: `keli-core-rs/Cargo.toml`
- Modify: `kelinode-rs/Cargo.toml`

- [x] Run focused cargo tests for dispatcher, config, and renderer.
- [x] Run full cargo tests in both touched repos where feasible.
- [x] Bump versions, commit, push.
- [ ] Deploy new build to problem-node only after local verification and keep test-node evidence separate if it becomes reachable.
