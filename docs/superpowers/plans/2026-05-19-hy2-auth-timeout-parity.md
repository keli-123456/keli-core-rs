# HY2 Auth Timeout Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent slow HY2 handshakes or authentication timeouts from being treated as invalid-auth abuse while keeping real bad credentials rate-limited.

**Architecture:** Keep the Rust native HY2 listener and auth path. Align the visible behavior with the stable Go/Xray path by making the Rust-only auth backoff apply only to explicit bad credentials, not to network latency or incomplete handshakes. Widen the default auth timeout conservatively so high-latency clients get a fair auth window.

**Tech Stack:** Rust, `tokio`, `quinn`, `h3`, `keli-core-rs` HY2 runtime, existing benchmark and external probe harness.

---

### Task 1: Add HY2 Auth Backoff Policy Tests

**Files:**
- Modify: `src/hysteria2.rs`

- [ ] **Step 1: Add tests for timeout vs invalid-auth policy**

Add tests near the existing `hysteria2_invalid_auth_backoff_*` tests:

```rust
#[test]
fn hysteria2_auth_backoff_policy_ignores_timeouts() {
    assert!(should_record_hysteria2_auth_backoff(&io::Error::new(
        io::ErrorKind::PermissionDenied,
        "invalid hysteria2 authentication",
    )));
    assert!(!should_record_hysteria2_auth_backoff(&io::Error::new(
        io::ErrorKind::TimedOut,
        "hysteria2 handshake timed out",
    )));
    assert!(!should_record_hysteria2_auth_backoff(&io::Error::new(
        io::ErrorKind::TimedOut,
        "hysteria2 authentication timed out",
    )));
}

#[test]
fn hysteria2_auth_timeout_default_is_not_rust_only_three_second_gate() {
    assert_eq!(DEFAULT_HY2_AUTH_TIMEOUT_SECS, 10);
}
```

- [ ] **Step 2: Run the new tests and verify they fail before implementation**

Run:

```powershell
cargo test --locked hysteria2_auth_backoff_policy_ignores_timeouts hysteria2_auth_timeout_default_is_not_rust_only_three_second_gate -- --test-threads=1
```

Expected: fail because the policy helper does not exist and the default timeout is still 3 seconds.

### Task 2: Implement HY2 Auth Backoff Parity

**Files:**
- Modify: `src/hysteria2.rs`

- [ ] **Step 1: Add the policy helper**

Add this helper near `is_hysteria2_invalid_auth_error`:

```rust
fn should_record_hysteria2_auth_backoff(error: &io::Error) -> bool {
    is_hysteria2_invalid_auth_error(error)
}
```

- [ ] **Step 2: Apply the helper in the auth error path**

In `handle_incoming`, keep `record_invalid` for explicit invalid credentials only:

```rust
if should_record_hysteria2_auth_backoff(&error) {
    self.auth_backoff.record_invalid(client_ip);
    connection.close(0u32.into(), b"invalid auth");
} else {
    connection.close(0u32.into(), b"auth failed");
}
```

- [ ] **Step 3: Stop penalizing timeout paths**

In the QUIC handshake timeout and HTTP/3 authentication timeout branches, remove the `record_invalid(client_ip)` calls. Keep the timeout error and connection close behavior.

- [ ] **Step 4: Widen the default auth timeout**

Change:

```rust
const DEFAULT_HY2_AUTH_TIMEOUT_SECS: u64 = 3;
```

to:

```rust
const DEFAULT_HY2_AUTH_TIMEOUT_SECS: u64 = 10;
```

### Task 3: Verify Locally

**Files:**
- No code edits unless verification exposes a regression.

- [ ] **Step 1: Run focused HY2 tests**

Run:

```powershell
cargo test --locked hysteria2_auth_backoff -- --test-threads=1
```

Expected: pass.

- [ ] **Step 2: Run full core tests**

Run:

```powershell
cargo test --locked --all-targets -- --test-threads=1
```

Expected: all tests pass.

- [ ] **Step 3: Run formatting check**

Run:

```powershell
cargo fmt --all -- --check
```

Expected: pass.

### Task 4: Release, Deploy, And Validate

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify in `kelinode-rs`: `Cargo.toml`, `Cargo.lock`

- [ ] **Step 1: Bump `keli-core-rs` version**

Bump `keli-core-rs` from `0.1.44` to `0.1.45`.

- [ ] **Step 2: Update `kelinode-rs` dependency lock and version**

Update the sibling `keli-core-rs` dependency, then bump `kelinode-rs` from `0.1.121` to `0.1.122`.

- [ ] **Step 3: Build Linux release binary**

Build `kelinode-rs` with embedded core for Linux musl on `test-node` or another Linux build host.

- [ ] **Step 4: Deploy to `test-node` first**

Deploy to `test-node` (`45.32.122.113`), restart, and record:

- version
- process status
- HY2 auth probe result
- HY2 TCP stream probe result if available
- `hysteria2 authentication timed out`
- `hysteria2 invalid-auth`
- `quic limit reached`

- [ ] **Step 5: Deploy to `problem-node` after test-node is acceptable**

Deploy to `problem-node` (`2.56.116.39`), restart, and record the same fields separately.

- [ ] **Step 6: Commit and push**

Commit and push `keli-core-rs 0.1.45` and `kelinode-rs 0.1.122`.
