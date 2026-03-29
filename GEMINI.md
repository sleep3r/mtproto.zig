# MTProto Proxy (Zig) — Engineering Notes

A production-grade Telegram MTProto proxy implemented in Zig, featuring TLS-fronted obfuscated connections. Runs on a Linux VPS, cross-compiled from Mac.

## Project Overview

High-performance MTProto proxy that mimics TLS 1.3 handshakes (domain fronting) to relay Telegram traffic. Compatible with `telemt` (Rust) config format.

### Current Status
- **Mac Telegram Desktop**: Fully working, MB-scale traffic, images loading.
- **iPhone Telegram**: Fully functional. `FAST_MODE` implemented, tested natively, and recommended by default to eliminate S2C encryption overhead.
- **Stability**: Service previously degraded to 99% CPU within 2 days. Root cause (logging mutexes) found and fixed. Tests prove zero memory leaks.
- **Test Coverage**: 31/31 tests passing, including fully simulated Black-Box E2E tests for DPI active-probing defense and FakeTLS validation workflows. Target: weeks of stable operation.

---

## Tech Stack
- **Language**: Zig 0.15
- **Networking**: `std.net` for TCP, `std.posix` for `poll()`-based I/O
- **Cryptography**: `std.crypto` for SHA256, HMAC, AES-256-CTR
- **Build System**: Zig Build System (`build.zig`)
- **Deployment**: `systemd` service on Linux VPS (Vultr), cross-compiled from macOS

---

## Architecture

```text
src/
├── main.zig              # Entry point, banner, public IP detection, custom logger
├── config.zig            # TOML config parser
├── proxy/
│   └── proxy.zig         # Core: accept loop, client handler, relay, DRS
├── protocol/
│   ├── tls.zig           # FakeTLS 1.3: ClientHello validation, ServerHello builder
│   ├── obfuscation.zig   # MTProto handshake parsing, key derivation, nonce generation
│   └── constants.zig     # DC addresses, protocol tags, TLS constants
└── crypto/
    └── crypto.zig        # AES-256-CTR, SHA-256, HMAC wrappers
```

### Connection Flow
**Client → TCP → Proxy (port 443)**
1. Client sends TLS 1.3 `ClientHello` (with HMAC-SHA256 auth in SNI digest).
2. Proxy validates HMAC, sends `ServerHello`.
3. Client sends `CCS` + 64-byte MTProto obfuscation handshake (in TLS `AppData`).
4. Proxy derives AES-CTR keys, connects to Telegram DC.
5. Proxy sends 64-byte nonce to DC.
6. **Bidirectional relay**: Client ↔ Proxy ↔ DC
   - **C2S**: TLS unwrap → AES-CTR decrypt(client) → AES-CTR encrypt(DC) → DC
   - **S2C**: DC → AES-CTR decrypt(DC) → AES-CTR encrypt(client) → TLS wrap → Client

### Threading Model
- One thread per connection (spawned from accept loop).
- **128KB stack per thread**: Not the default 8-16MB. This prevents OOM when handling thousands of iOS pool connections.
- Non-blocking sockets + `poll()` in relay loop.
- No global mutable state — `ProxyState` passed by reference.

---

## Building and Running

### Prerequisites
- Zig 0.15.0+
- SSH access to VPS for deployment

### Key Commands
```bash
zig build                                              # Debug build (native)
zig build -Doptimize=ReleaseFast                       # Release build (native)
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux # Cross-compile for Linux
zig build test                                         # Run unit tests
make deploy                                            # Cross-compile + stop + scp + start
```

### Deployment
`make deploy` performs the following steps:
1. Cross-compile for Linux.
2. `systemctl stop mtproto-proxy`.
3. `scp` binary to VPS.
4. `systemctl start mtproto-proxy`.

> [!IMPORTANT]
> You must stop the service before using `scp` because the systemd unit has `ReadOnlyPaths=/opt/mtproto-proxy`, which prevents overwriting the binary while it is running.

### Configuration (`config.toml`)
```toml
[server]
port = 443

[censorship]
tls_domain = "wb.ru"
mask = true

[access.users]
alexander = "0b513f6e83524354984a8835939fa9af"
```

### Systemd Unit (`deploy/mtproto-proxy.service`)
Key performance and security settings:
- `LimitNOFILE=65535`: Enough file descriptors for thousands of concurrent connections.
- `TasksMax=65535`: Enough threads for the one-thread-per-connection model.
- `ReadOnlyPaths=/opt/mtproto-proxy`: Security hardening.

---

## Critical Zig Gotchas

### 1. `log_level = .debug` Causes 99% CPU in `ReleaseFast`
**THIS WAS THE #1 STABILITY KILLER.**

```zig
// BAD — forces ALL log.debug calls to execute even in ReleaseFast
pub const std_options = std.Options{
    .log_level = .debug,
};
```

Zig's default logger (`std.log.defaultLog`) acquires a global `stderr_mutex` (`std.Thread.Mutex.Recursive` in `std.Progress`) for **EVERY** log message. It uses a small 64-byte buffer, causing multiple `flush`/`write` syscalls per message while holding the lock.

**The Cascade:**
1. Hundreds of connections spawn threads (iOS pool warmers + Mac probes).
2. Each thread logs debug messages.
3. All threads contend on the single `stderr_mutex`.
4. Mutex contention stalls connection processing → connections time out → more error logs → more contention.
5. CPU hits 99%, and `CLOSE-WAIT` sockets accumulate.

**Evidence from `/proc` analysis:**
- 337 threads in `futex_wait_queue` (blocked on `stderr_mutex`).
- 39 threads in `do_poll` (normal relay).
- 1 thread in running state consume 99% CPU.

**Fix:** Remove the `log_level` override. `ReleaseFast` default is `.info`, which compiles out all `log.debug` calls at comptime (zero overhead via dead code elimination).

### 2. Custom Lock-Free Logger
Replaced `std.log.defaultLog` with a custom `lockFreeLog` that:
- Formats into a stack buffer.
- Uses a single atomic `write()` syscall to `stderr`.
- **No mutex**: Eliminates all contention.
- Lines may interleave under extreme concurrency, which is acceptable for performance.

```zig
pub const std_options = std.Options{
    .logFn = lockFreeLog,
};
```

### 3. GPA Mutex Deadlock
`std.heap.GeneralPurposeAllocator` has an internal mutex. Under high thread contention, this caused deadlocks.
**Fix:** Switched to `std.heap.page_allocator`, which has no internal locking.

### 4. Log Level Strategy
Only 4 `log.info` messages survive in the hot path:
1. `"Listening on 0.0.0.0:{port}"` — startup
2. `"TLS auth OK: user={name}"` — successful authentication
3. `"Relaying traffic"` — relay start
4. `"Relay: max lifetime reached"` — operational event

Everything else is `log.debug` (compiled out in `ReleaseFast`):
- MTProto handshake details, Client cipher diagnostics, DC connection attempts, Pipelined data info, Relay end reasons, Idle pool closures, and all error details in the relay loop.

### 5. Zig stdlib Internals (Reference)
- `std/log.zig:122`: Comptime log level check.
- `std/log.zig:154`: `lockStderrWriter` acquires mutex.
- `std/Progress.zig:1560`: `var stderr_mutex = std.Thread.Mutex.Recursive.init`.
- `std/os/linux.zig`: `TCP.KEEPIDLE=4`, `TCP.KEEPINTVL=5`, `TCP.KEEPCNT=6`.
- Note: Zig's `posix.SOL` doesn't have `.TCP`, so TCP socket options use raw `sol_tcp: i32 = 6`.

---

## iOS vs Desktop Telegram Differences

### Connection Pooling (iOS)
iOS Telegram aggressively pre-warms TCP connection pools, opening 2-5+ idle sockets that sit empty until needed. A short timeout kills these, causing iOS to mark the proxy as unstable.

**Fix (Two-stage timeout):**
- **Stage 1 (Idle Phase)**: `poll()` with a 5-minute timeout. Sleeping threads consume zero CPU.
- **Stage 2 (Active Phase)**: `SO_RCVTIMEO` 10s once data starts arriving.

### Fragmented MTProto Handshake (iOS)
Desktop sends the 64-byte MTProto handshake in a single TLS `AppData` record. iOS may split it across multiple records or interleave `CCS` records.

**Fix:** Assembly loop that reads TLS records until 64 bytes of handshake are collected. Extra bytes are treated as pipelined data.

### Handshake Timeout (iOS)
A tight 10s `SO_RCVTIMEO` was previously armed too early. iOS may delay the MTProto handshake after `ServerHello`.

**Fix:** Use a generous 60s timeout during the handshake phase. The 10s timeout is only applied after the full 64-byte handshake is assembled.

### TLS Record Sizing (S2C)
`DynamicRecordSizer` previously ramped record sizes from 1369 to 16384 bytes. Desktop handles this, but it may cause issues on iOS.

**Fix:** Frozen at 1369 bytes (MSS-sized) for iOS compatibility. Ramp will be re-enabled after further testing.

---

## Stability Fixes Applied

### Socket Configuration
All relay sockets use these settings:
1. **TCP Keepalive**:
   - `SO_KEEPALIVE` enabled.
   - `TCP_KEEPIDLE = 60s`, `TCP_KEEPINTVL = 10s`, `TCP_KEEPCNT = 3`.
   - Result: Dead peer detection within ~90 seconds.
2. **`SO_SNDTIMEO = 30s`**: Prevents `writeAll` from hanging indefinitely.
3. **Max Connection Lifetime = 30 minutes**: Hard cap checked via `std.time.milliTimestamp()`.
4. **Non-blocking sockets**: Used with `poll()` for bidirectional flow.

### Relay Loop Robustness
- **`POLLHUP` drain-before-close**: Drain readable data before closing on disconnect.
- **Progress-aware spin detection**: `RelayProgress` enum tracks none/partial/forwarded progress.
- **Improved `writeAll`**: Handles `WouldBlock` with `POLLOUT` and a spin counter (32 max).
- **Overload protection**: Max 8192 concurrent connections.

---

## Chronological Bug Fixes
1. `buildServerHello` fixed against Telegram client source.
2. `GPA` mutex deadlock → `page_allocator`.
3. Pipelined data loss handled.
4. Partial write bugs → `writeAll`.
5. `POLLHUP` drain-before-close.
6. CPU busy-loop → `RelayProgress` spin detection.
7. iOS pool connections killed → two-stage timeout.
8. 99% CPU from logging → removed `log_level = .debug`, custom lock-free logger.
9. TCP keepalive implemented.
10. `SO_SNDTIMEO` added.
11. Max connection lifetime (30-minute cap).
12. Fragmented handshake assembly.
13. Handshake timeout adjusted (60s).
14. DRS frozen at 1369 bytes for compatibility.
15. TLS Alert logging added.

---

## Future Work

### Local E2E Testing Topology
Implemented a 100% loopback test capability:
- **DPI Masking**: Mock Google server spins up, proxy directs failed validations cleanly to it.
- **Handshakes**: Emulated MTProto drop & relay parsing flows, securely tested via internal `datacenter_override`.

### Re-enabling DRS
Once iPhone connectivity is stable, test with the `DRS` ramp enabled (shifting to 16384-byte records after a threshold).

---

## Development Conventions
- **Memory Management**: Pass `Allocator` to functions; use `defer` for cleanup.
- **Error Handling**: Use Zig error unions (`!T`) with `try`/`catch`.
- **Testing**: Comprehensive E2E Integration tests + unit tests in `test` blocks at the bottom of `.zig` files. Includes fake localhost TCP servers directly communicating via background loopback sockets.
- **Logging**: Only `log.info` for essential events; `log.debug` for diagnostics.
- **No global mutable state**: Always pass `ProxyState` by reference.

---

## Useful Diagnostics

### Service & Process Monitoring
```bash
# Check service status
ssh root@45.77.223.232 'systemctl status mtproto-proxy --no-pager'

# Check active connections
ssh root@45.77.223.232 'ss -tnp | grep mtproto'

# Check process stats (CPU, threads, memory)
ssh root@45.77.223.232 'ps -o pid,pcpu,pmem,nlwp,rss,vsz,args -p $(pgrep -f mtproto-proxy)'
```

### Log Analysis
```bash
# Check recent logs
ssh root@45.77.223.232 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager'

# Filter by IP (Mac)
ssh root@45.77.223.232 'journalctl -u mtproto-proxy --no-pager | grep 81.17.27.66'

# Filter by IP (iPhone)
ssh root@45.77.223.232 'journalctl -u mtproto-proxy --no-pager | grep 109.252.90.134'
```

### Low-level Debugging
```bash
# Check for CLOSE-WAIT sockets
ssh root@45.77.223.232 'ss -tnp state close-wait | grep mtproto'

# Check thread states in Linux /proc
ssh root@45.77.223.232 'cat /proc/$(pgrep -f mtproto-proxy)/status | grep -E "Threads|State"'
```