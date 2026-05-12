# Native Core Interop Run Template

Do not mark a protocol production-ready until this record is completed for the exact panel
configuration and client family used in production.

## Scope

- Date:
- Operator:
- Site / region:
- Panel node id:
- Protocol:
- Transport / security / obfs:
- Core commit:
- Core version:
- `kelinode-rs` commit:
- `kelinode-rs` version:
- Native config source:
- Client app and version:
- Client OS:
- User count loaded:
- Runtime duration:

## Preflight

- `check-config` passed:
- Core started without listener errors:
- `Metrics` control command reachable:
- `Status` reports expected listener address:
- `native_core_gray_health.mode` before test:
- Active user count matches expected:
- No control token present in status, metrics, logs, or config:

## User Delta

- Added user auth succeeds without listener restart:
- Updated credential succeeds:
- Updated old credential fails:
- Updated speed limit reflected:
- Updated device limit reflected:
- Deleted user new auth fails immediately:
- Existing deleted-user connection closes or stops forwarding:
- Deleted-user tail traffic reports with captured `user_id`:
- Revision mismatch fallback repaired by full snapshot:
- No full rebuild during normal incremental delta:

## Traffic Accounting

- Client upload bytes:
- Client download bytes:
- Panel/core upload delta:
- Panel/core download delta:
- Difference:
- Pending spool used:
- Requeue used:
- Retry success cleared pending:
- Online IPs deduplicated:

## Performance

- Connect success rate:
- First byte latency:
- p50 latency:
- p95 latency:
- p99 latency:
- Reconnect count:
- Error count:
- CPU average:
- CPU peak:
- Memory start:
- Memory peak:
- Throughput average:
- Throughput peak:

## Soak Result

- 30 minute smoke pass:
- 6 hour soak pass:
- Process restart count:
- Listener crash count:
- Unbounded memory growth observed:
- Protocol errors isolated to this protocol:
- Other inbound impacted:
- Rollback triggered:
- Final `native_core_gray_health.mode`:
- Final warning / reasons:

## Decision

- Result: pending / pass / fail
- Safe for next gray step:
- Required fixes before next run:
- Notes:
