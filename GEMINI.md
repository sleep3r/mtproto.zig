# MTProto Proxy (Zig) — Engineering Notes

A production-grade Telegram MTProto proxy implemented in Zig, featuring TLS-fronted obfuscated connections. Runs on a Linux VPS, cross-compiled from Mac.

## Project Overview

High-performance MTProto proxy that mimics TLS 1.3 handshakes (domain fronting) to relay Telegram traffic. Compatible with `telemt` (Rust) config format.

### Current Status
- **Mac Telegram Desktop**: Fully working, MB-scale traffic, images loading.
- **iPhone Telegram**: Functional via IPv6; media reliability improved after MiddleProxy routing fixes.
- **Ubuntu Telegram Desktop**: Connect path stabilized after reconnect regressions (including post-restart "connecting" hangs).
- **Stability**: Service previously degraded to 99% CPU within 2 days. Root cause (logging mutexes) found and fixed.
- **Test Coverage**: 34/34 tests passing, including fully simulated Black-Box E2E tests for DPI active-probing defense and FakeTLS validation workflows.
- **Promotion Tag**: Supported. Sends `proxy_ans_tag` (RPC `0xaeaf0c42`) after DC handshake for sponsored channel registration.
- **ТСПУ Evasion**: Seven-layer DPI bypass implemented and active (see section below).

---

## Tech Stack
- **Language**: Zig 0.15
- **Networking**: `std.net` for TCP, `std.posix` for `poll()`-based I/O
- **Cryptography**: `std.crypto` for SHA256, HMAC, AES-256-CTR
- **Build System**: Zig Build System (`build.zig`)
- **Deployment**: `systemd` service on Linux VPS, cross-compiled from macOS

---

## Architecture

```text
src/
├── main.zig              # Entry point, banner, public IP detection, custom logger
├── bench.zig             # Performance microbench + multithreaded soak runner
├── config.zig            # TOML config parser
├── proxy/
│   └── proxy.zig         # Core: accept loop, client handler, relay, DRS, Split-TLS desync
├── protocol/
│   ├── tls.zig           # FakeTLS 1.3: ClientHello validation, Nginx template ServerHello
│   ├── obfuscation.zig   # MTProto handshake parsing, key derivation, nonce generation
│   ├── middleproxy.zig   # Telegram MiddleProxy transport (RPC_PROXY_REQ/ANS over AES-CBC)
│   └── constants.zig     # DC addresses, protocol tags, TLS constants
├── crypto/
│   └── crypto.zig        # AES-256-CTR, SHA-256, HMAC wrappers
deploy/
├── install.sh            # One-line VPS bootstrap (Zig + build + systemd + TCPMSS + IPv6)
├── update.sh             # In-place server updater from GitHub Release artifacts
├── ipv6-hop.sh           # IPv6 address rotation (Cloudflare API)
├── mtproto-proxy.service # systemd unit file
├── update_dns.sh         # Cloudflare DNS A-record updater
├── capture_template.py   # Capture real Nginx ServerHello for template verification
├── setup_masking.sh      # Local Nginx for zero-RTT DPI masking
└── setup_nfqws.sh        # zapret nfqws OS-level TCP desync
```

### Connection Flow
**Client → TCP → Proxy (port 443)**
1. Client sends TLS 1.3 `ClientHello` (with HMAC-SHA256 auth in SNI digest).
2. Proxy validates HMAC, sends `ServerHello`.
3. Client sends `CCS` + 64-byte MTProto obfuscation handshake (in TLS `AppData`).
4. Proxy derives AES-CTR keys, connects to Telegram DC.
5. In direct mode (`use_middle_proxy = false`), proxy sends 64-byte obfuscated nonce to regular DCs.
6. If `use_middle_proxy = true` (or `dc=203`), proxy performs MiddleProxy handshake (`RPC_NONCE`, `RPC_HANDSHAKE`) and relays user frames via `RPC_PROXY_REQ/ANS`.
7. Promotion tag is carried in ME path as `ad_tag` TL block inside `RPC_PROXY_REQ` and in direct path via promo RPC (`0xaeaf0c42` + 16-byte tag).
8. **Bidirectional relay**: Client ↔ Proxy ↔ DC
   - **C2S**: TLS unwrap → AES-CTR decrypt(client) → AES-CTR encrypt(DC) → DC
   - **S2C (classic DC)**: DC → AES-CTR decrypt(DC) → AES-CTR encrypt(client) → TLS wrap → Client
   - **S2C (DC203)**: DC AES-CBC frame → decapsulate `RPC_PROXY_ANS`/`RPC_SIMPLE_ACK` → TLS wrap → Client

### Threading Model
- One thread per connection (spawned from accept loop).
- **256KB stack per thread**: Prevents OOM when handling thousands of iOS pool connections.
- Non-blocking sockets + `poll()` in relay loop.
- No global mutable state — `ProxyState` passed by reference.
- Proxy binds on `[::]` (IPv6 wildcard) — automatically accepts both IPv4 and IPv6 connections.

---

## Building and Running

### Prerequisites
- Zig 0.15.0+
- SSH access to VPS for deployment

### Key Commands
```bash
make build                                             # Debug build (native)
make release                                           # Release build (native)
make release_linux                                     # Cross-compile for Linux
make test                                              # Run unit tests
make bench                                             # ReleaseFast encapsulation microbench
make soak                                              # ReleaseFast 30s multithreaded soak stress
make deploy                                            # Cross-compile + stop + scp + start
make update-server SERVER=<ip> [VERSION=vX.Y.Z]       # Update VPS from GitHub Release
```

### Release Workflow (GitHub)

- Release automation is handled by `release-please` in `.github/workflows/release-please.yml`.
- It updates/opens one release PR, not one release per commit.
- A real GitHub release is created only when the release PR is merged.
- Bump policy follows Conventional Commits:
  - `fix:` -> patch
  - `feat:` -> minor
  - `BREAKING CHANGE:` / `!` -> major
- To keep required checks compatible with release PRs, repository secret `RELEASE_PLEASE_TOKEN` must be set (PAT with `Contents`, `Pull requests`, `Issues` read/write for this repo).

> [!NOTE]
> On macOS 26 (Tahoe), `zig build` is broken due to Zig 0.15.2's linker not supporting the new TBD format.
> The Makefile works around this by using `zig build-exe`/`zig test` with `--sysroot` pointing to the macOS 15 SDK from Command Line Tools.

### Deployment
`make deploy` performs the following steps:
1. Cross-compile for Linux.
2. `systemctl stop mtproto-proxy`.
3. `scp` binary and deploy scripts to VPS.
4. If `$(CONFIG)` exists locally, upload it as `/opt/mtproto-proxy/config.toml`.
5. `systemctl start mtproto-proxy`.

> [!IMPORTANT]
> You must stop the service before using `scp` because the systemd unit has `ReadOnlyPaths=/opt/mtproto-proxy`, which prevents overwriting the binary while it is running.

### Server Update Path (Recommended for Operators)

For routine production upgrades, users should update from GitHub Releases instead of rebuilding on the VPS.

#### Local orchestrated update
```bash
make update-server SERVER=<SERVER_IP>
make update-server SERVER=<SERVER_IP> VERSION=v0.1.0
```

This runs `deploy/update.sh` remotely over SSH.

#### Direct update on the VPS
```bash
curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/update.sh | sudo bash
curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/update.sh | sudo bash -s -- v0.1.0
```

#### Update safety guarantees
- Detects server architecture (`x86_64`/`aarch64`) and downloads matching release artifact.
- Stops `mtproto-proxy`, installs new binary, updates deploy helper scripts and service unit.
- Preserves runtime state (`/opt/mtproto-proxy/config.toml`, `/opt/mtproto-proxy/env.sh`).
- Creates timestamped backup of current binary before replacement.
- Automatically rolls back to previous binary if restart fails.

#### Operator rollback
If needed, restore the backup binary printed by `update.sh` and restart:
```bash
sudo cp /opt/mtproto-proxy/mtproto-proxy.backup.<timestamp> /opt/mtproto-proxy/mtproto-proxy
sudo systemctl restart mtproto-proxy
```

### Configuration (`config.toml.example`)
Users can copy `config.toml.example` to `config.toml`. The structure natively supports the new anti-DPI routing fields:
```toml
[server]
port = 443
tag = "1234567890abcdef1234567890abcdef"   # Optional: promotion tag from @MTProxybot

[censorship]
tls_domain = "wb.ru"
mask = true
mask_port = 8443                           # Zero-RTT override
desync = true                              # TCP desync: split ServerHello (1-byte + rest)
drs = false                                # Dynamic Record Sizing: ramp 1369→16384 bytes
fast_mode = true

[access.users]
alexander = "00112233445566778899aabbccddeeff"
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

## Telegram Client Behavior Matrix (WIP)

We currently keep this section strict: no behavior claims without either (a) reproducible captures/logs, or (b) direct links to client source code with an explicit version/tag/commit.

### iOS (Telegram iOS)
- **Field evidence (our captures/logs)**: iOS pre-warms multiple idle sockets, can fragment the 64-byte obfuscation handshake across TLS records, and may delay first payload after `ServerHello`.
- **Version-pinned source snapshot**: `TelegramMessenger/Telegram-iOS` tag `build-26855` (target commit `b16d9acdffa9b3f88db68e26b77a3713e87a92e3`).
- In this source snapshot, TCP connect timeout is `12s` in `submodules/MtProtoKit/Sources/MTTcpConnection.m:980`.
- Response watchdog is based on `MTMinTcpResponseTimeout = 12.0` (`submodules/MtProtoKit/Sources/MTTcpConnection.m:576`) plus payload-dependent term (`submodules/MtProtoKit/Sources/MTTcpConnection.m:1339`), and is reset on partial reads (`submodules/MtProtoKit/Sources/MTTcpConnection.m:1398`).
- Transport-level connection watchdog is `20s` in `submodules/MtProtoKit/Sources/MTTcpTransport.m:312`.
- Reconnect backoff in `submodules/MtProtoKit/Sources/MTTcpConnectionBehaviour.m:66` is stepped (`1s` for early retries, then `4s`, then `8s`).

**Proxy-side handling used for iOS compatibility:**
- Two-stage timeout model: `poll()` idle phase (5 min), then active `SO_RCVTIMEO=10s` after payload starts.
- Handshake assembly loop collects full 64 bytes before switching relay into normal mode.
- Handshake-stage receive timeout widened to 60s before tightening to normal relay timeout.
- TLS S2C record size currently pinned to 1369 bytes (MSS-sized) until broader cross-client validation is completed.

### Android (Telegram Android)
- **Version-pinned source snapshot**: `DrKLO/Telegram` tag `release-11.4.2-5469` (commit `fb2e545101f41303f1e2712de2e7611a9335f1c3`).
- Socket setup in `TMessagesProj/jni/tgnet/ConnectionSocket.cpp:571` enables `TCP_NODELAY` (`TMessagesProj/jni/tgnet/ConnectionSocket.cpp:574`), switches socket to `O_NONBLOCK` (`TMessagesProj/jni/tgnet/ConnectionSocket.cpp:587`), and uses `connect(..., EINPROGRESS)` with edge-triggered epoll (`EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLERR|EPOLLET`, `TMessagesProj/jni/tgnet/ConnectionSocket.cpp:596`).
- Timeout handling is internal logical timeout (`setTimeout`/`checkTimeout`) in `TMessagesProj/jni/tgnet/ConnectionSocket.cpp:1066` and `TMessagesProj/jni/tgnet/ConnectionSocket.cpp:1076`.
- Per-connection-type timeout profile is explicitly assigned in `TMessagesProj/jni/tgnet/Connection.cpp:368` and after first useful data in `TMessagesProj/jni/tgnet/Connection.cpp:131`.
- Connection type split is explicit (`ConnectionTypeGeneric/Download/Upload/Push/Temp/Proxy`) in `TMessagesProj/jni/tgnet/Defines.h:68`, with multiple parallel slots (`PROXY_CONNECTIONS_COUNT=4`, `DOWNLOAD_CONNECTIONS_COUNT=2`, `UPLOAD_CONNECTIONS_COUNT=4`) in `TMessagesProj/jni/tgnet/Defines.h:26`.
- Datacenter keeps separate connection objects/arrays per type in `TMessagesProj/jni/tgnet/Datacenter.h:88` and lazily creates/connects them in `TMessagesProj/jni/tgnet/Datacenter.cpp:835` and `TMessagesProj/jni/tgnet/Datacenter.cpp:1311`.

### Windows (Telegram Desktop)
- **Version-pinned source snapshot**: `telegramdesktop/tdesktop` tag `v6.7.2` (commit `085c4ba65d1f8aa13abf0fd7fc8489f094552542`).
- MTProto layer prepares multiple "test connections" across endpoint/protocol variants in `Telegram/SourceFiles/mtproto/session_private.cpp:1010` and `Telegram/SourceFiles/mtproto/session_private.cpp:1065`, then selects by priority from `appendTestConnection` (`Telegram/SourceFiles/mtproto/session_private.cpp:192`, priority formula at `Telegram/SourceFiles/mtproto/session_private.cpp:199`).
- Connection wait timeout starts from `kMinConnectedTimeout = 1000ms` (`Telegram/SourceFiles/mtproto/session_private.cpp:34`), scheduled via `_waitForConnectedTimer.callOnce(_waitForConnected)` (`Telegram/SourceFiles/mtproto/session_private.cpp:1111`), and grows up to max in `waitConnectedFailed` (`Telegram/SourceFiles/mtproto/session_private.cpp:1236`).
- Transport full-connect timeout in TCP path is `8s` (`Telegram/SourceFiles/mtproto/connection_tcp.cpp:21`, `Telegram/SourceFiles/mtproto/connection_tcp.cpp:581`), and HTTP path is `8s` (`Telegram/SourceFiles/mtproto/connection_http.cpp:18`, `Telegram/SourceFiles/mtproto/connection_http.cpp:242`).
- Resolving wrapper uses per-IP timeout `kOneConnectionTimeout = 4000` (`Telegram/SourceFiles/mtproto/connection_resolving.cpp:16`) and multiplies by number of resolved IPs in `Telegram/SourceFiles/mtproto/connection_resolving.cpp:187`.
- After first success, Desktop may wait `kWaitForBetterTimeout = 2000ms` for a better candidate (`Telegram/SourceFiles/mtproto/session_private.cpp:33`, `Telegram/SourceFiles/mtproto/session_private.cpp:2336`).

### Ubuntu/Linux (Telegram Desktop)
- Source-backed connection behavior currently maps to the same `tdesktop` MTProto files referenced in the Windows section above (`Telegram/SourceFiles/mtproto/*`, tag `v6.7.2`).
- In reviewed files, we did not find OS-specific branching for the listed connect/retry timeout logic.
- TODO: add package/channel-specific validation (Snap/DEB/Flatpak build differences) with explicit tested build IDs.

### macOS (Telegram Desktop)
- Source-backed baseline is currently the same `tdesktop` MTProto layer (`v6.7.2`) used for the Windows/Ubuntu notes above.
- TODO: add version-pinned macOS binary/build validation and capture-backed deltas (if any).

### Placeholder: Other clients (WebK/WebZ/TDLib-based)
- TODO: Add entries only after source/capture-backed verification with explicit version.

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

### MiddleProxy Auto-Refresh
- Proxy caches DC203 MiddleProxy endpoint and shared secret inside `ProxyState`.
- On startup and then every 24 hours, it fetches:
  - `https://core.telegram.org/getProxyConfig` (parse `proxy_for 203 ...`)
  - `https://core.telegram.org/getProxySecret`
- Runtime updates are protected by `std.Thread.RwLock` and applied per new connection.
- If fetching fails, bundled defaults remain active.

### MiddleProxy Endpoint Rotation (DC4/DC203)
- The proxy now parses and stores multiple `proxy_for` candidates for unstable paths (`dc=4`, `dc=203`).
- Candidate lists are deduplicated by `ip:port` before use.
- Connection logic rotates through candidates per connection before giving up.
- For non-media paths, direct-DC fallback remains enabled on timeout to avoid multi-minute connect hangs.
- For media paths (`dc_idx < 0` and legacy `dc=203`), fallback to direct is disabled by design; only MiddleProxy is used.

### MiddleProxy C2S Frame Safety
- `encapsulateSingleMessageC2S` previously built RPC payload in a fixed 64KiB stack buffer.
- Under large client packets, this could overflow the local buffer and crash with `SIGSEGV`.
- Fixed by writing RPC payload directly into `out_buf` with precomputed frame size and explicit bounds checks (`error.OutBufOverflow`).
- Added regression test for payloads larger than 64KiB.

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
16. **Hairpin routing fix**: AmneziaVPN (Docker/WireGuard) on the same server blocked iOS VPN clients from reaching port 443 due to Docker's `FORWARD policy DROP`. Fixed with `iptables -I DOCKER-USER -s 172.29.172.0/24 -p tcp --dport 443 -j ACCEPT`.
17. **Promotion tag**: Added `tag` config field and `proxy_ans_tag` RPC (`0xaeaf0c42`) sent to DC after handshake. Supports abridged, intermediate, and secure framing.
18. **Nginx template ServerHello**: Replaced hand-crafted `buildServerHello` with comptime Nginx/OpenSSL template. Fixed extension ordering (supported_versions before key_share), fixed AppData size (2878 bytes), deterministic PRNG body.
19. **Split-TLS desync**: Added 1-byte TCP split on ServerHello send to break ТСПУ passive signature matching. Gated by `desync` config flag.
20. **MiddleProxy DC203 parity fix**: Added complete `middleproxy.zig` path, fixed `RPC_PROXY_REQ` serialization, CBC frame handling, key derivation inputs, and `RPC_HANDSHAKE_ANS` validation.
21. **MiddleProxy metadata updater**: Added periodic refresh of DC203 proxy endpoint and shared secret from Telegram core endpoints.
22. **Telemt promo parity**: Added `[general].use_middle_proxy` support for regular DC1..5 and `[general].ad_tag` alias; ME path now injects ad tag into `RPC_PROXY_REQ` when configured.
23. **Deploy config parity**: `make deploy` now uploads runtime `config.toml` (via `CONFIG`) to `/opt/mtproto-proxy/config.toml` to avoid stale server config after binary-only deploys.
24. **Production log normalization**: reverted temporary relay diagnostics (`DIAG C2S/S2C`, `Relay ended`, common reset/EOF errors) back to debug level to reduce log I/O noise and keep warning/error logs actionable under high mobile churn.
25. **MiddleProxy C2S overflow fix**: removed fixed 64KiB stack RPC buffer in `encapsulateSingleMessageC2S`, switched to direct write into output buffer with explicit bounds checks.
26. **Bench/Soak tooling**: added built-in `bench` and multithreaded `soak` runners (`src/bench.zig`, `zig build bench`, `zig build soak`, `make bench`, `make soak`) for repeatable local performance and stability validation.
27. **ClientHello fragmentation fix**: hardened `readExact` to assemble full TLS records across multiple TCP segments; eliminated `Short read on ClientHello body (got 1443, expected ...)` drops seen on Linux/Windows/Android.
28. **MiddleProxy candidate rotation**: parse and cache multiple `proxy_for` endpoints for `dc=4` and `dc=203`, deduplicate by `ip:port`, and retry across candidates per connection.
29. **Reconnect stability tuning**: reverted an experimental short desktop first-byte timeout that caused Ubuntu regressions; kept long two-stage timeout semantics and moved resilience to upstream retry logic.
30. **Media/non-media routing split**: retain fast direct fallback for non-media timeouts while keeping media paths on MiddleProxy transport to preserve media load behavior.
31. **Soak Gate in CI**: added `bench` job to `.github/workflows/ci.yml` that runs microbenchmarks and soak stress tests after unit tests pass. Tiered durations: 10s on PRs, 60s on main. Results uploaded as artifacts for perf drift tracking.
32. **DRS re-enabled**: restored Dynamic Record Sizing ramp logic (1369→16384 bytes after 8 records or 128KB), gated by `drs = true` config flag in `[censorship]`. Default off for backward compatibility.

---

## Future Work

### Event-Loop Migration (Scalability Track)

Current architecture is intentionally thread-per-connection because it made protocol correctness and debugging simpler during the stabilization phase (FakeTLS, MTProto handshake assembly, MiddleProxy parity, iOS edge cases).

Next major scalability milestone is migrating relay I/O from per-connection threads to a reactor model (`epoll` on Linux / `kqueue` on BSD/macOS):

1. Extract explicit per-connection state machines (handshake, C2S/S2C relay, timeout lifecycle) independent of thread-local control flow.
2. Introduce acceptor + worker loops (N workers ~= CPU cores) with non-blocking sockets and centralized readiness polling.
3. Preserve existing safety behavior: partial read/write handling, backpressure (`POLLOUT`/write readiness), idle/active timeout split, lifetime cap, and replay cache checks.
4. Validate parity with existing test suite, then add event-loop-specific stress tests (10k+ idle connections, mixed burst traffic).

Expected outcome: significantly lower per-connection memory overhead and higher concurrency on small VPS tiers (especially 1 vCPU / 1 GB RAM), without changing protocol semantics.

Note: buffer downsizing is intentionally deferred until after event-loop migration to avoid coupling two risk-heavy changes in one phase.

### ~~Local E2E Testing Topology~~ ✅
Implemented a 100% loopback test capability:
- **DPI Masking**: Mock Google server spins up, proxy directs failed validations cleanly to it.
- **Handshakes**: Emulated MTProto drop & relay parsing flows, securely tested via internal `datacenter_override`.

### ~~Re-enabling DRS~~ ✅
Restored DRS ramp logic gated by `drs = true` in `[censorship]` config. Default off. When enabled, TLS S2C records start at 1369 bytes (MSS-sized) and ramp to 16384 after 8 records or 128KB — mimicking Chrome/Firefox initial TLS behavior.

### ~~Soak Gate in CI~~ ✅
Implemented in `.github/workflows/ci.yml` — `bench` job runs after tests, with 10s soak on PRs / 60s on main. Results published as CI artifacts. Remaining future work:
- keep host-specific throughput baselines and fail on statistically significant regressions

### Advanced Anti-DPI Research
Based on continuous updates from DPI developers (e.g., VAS Experts/EcoSnat), bypass development remains a cat-and-mouse game. Notably, they actively maintain a detailed public changelog tracking new blocking capabilities: [VAS Experts DPI Changelog](https://wiki.vasexperts.ru/doku.php?id=dpi:changelog:versions:beta).

Recent shifts (like DPI version 14.2) show active targeting of FakeTLS, explicit MTProto fingerprinting, and blacklisting of specific hosting subnetworks (e.g., Hetzner). Even clean VLESS (sing-box) can be blocked based on the destination IP or SNI mismatch ("pessimization" logic).
Ideas for future countermeasures to explore:
- **Rigorous SNI Selection**: Tuning SNI domains to perfectly match the traffic profile of the destination IP, as generic/mismatched domains combined with QUIC are now actively penalized.
- **Podkop-style "Garbage Injection"**: Injecting junk data into streams to disrupt the "fuzzy logic" state machines of modern DPIs.
- **Alternative Exotic Transports**:
  - TCP over VK Voice Calls (exploiting permitted domestic WebRTC/STUN traffic).
  - TCP over Emails (SMTP tunnels, e.g., `x011/smtp-tunnel-proxy`).
  - TCP over DNS (e.g., `yarrick/iodine`).
  - TCP over ICMP / Max.
  - Mesh Networks.

---

## ТСПУ / DPI Evasion (Russian ISP Blocking)

### Anatomy of the Block
Российский ТСПУ работает в **два этапа**:
1. **Пассивный анализ**: видит FakeTLS ClientHello с SNI `wb.ru` к неизвестному VPS → SNI-IP mismatch → IP ставится в очередь на проверку.
2. **Активные пробы («Ревизор»)**: через 5-10 минут сканер РКН подключается к серверу и:
   - Шлёт обычный ClientHello с `SNI=wb.ru` (SNI Probe)
   - **Replay Attack**: побитово повторяет перехваченный у клиента ClientHello. HMAC сходится → прокси отвечает ServerHello → прокси идентифицирован → бан.
3. IP улетает в BGP-blackhole за ~20 минут. Клиенты получают 0 пакетов.

### Solution 1: Anti-Replay Cache (код в `proxy.zig`)

`ReplayCache` хранит 4096 последних виденных `client_digest` (32 байта каждый) в кольцевом буфере. Легитимные клиенты Telegram **никогда** не повторяют digest. При повторе — это Ревизор.

```zig
// В handleConnectionInner, после HMAC-валидации:
if (state.replay_cache.checkAndInsert(&v.digest)) {
    log.info("Replay attack detected (ТСПУ Revisor) — masking to {s}", ...);
    maskConnection(state, client_stream, ...); // → реальный wb.ru:443
    return;
}
```

Сканер получает настоящий сертификат Wildberries и заносит IP в whitelist.

### Solution 2: TCPMSS Clamping (iptables на сервере)

```bash
iptables -t mangle -A OUTPUT -p tcp --sport 443 --tcp-flags SYN,ACK SYN,ACK -j TCPMSS --set-mss 88
```

В SYN-ACK сервер объявляет MSS=88 байт. iOS дробит ~517-байтный ClientHello на 6 мелких TCP-пакетов. Пассивный ТСПУ не в состоянии собрать сигнатуру FakeTLS из разрозненных сегментов (reassembly engine экономит CPU на 100Gbps+ линках).

Правило сохранено в `/etc/iptables/rules.v4`.

### Solution 3: IPv6 Address Hopping (`deploy/ipv6-hop.sh`)

AVPS получает бесплатную подсеть `/64` (18 квинтиллионов адресов). ТСПУ не банит `/64` целиком. Скрипт `ipv6-hop.sh`:
1. Генерирует случайный IPv6 из `/64`
2. Вешает его на интерфейс (`ip -6 addr add`)
3. Обновляет Cloudflare AAAA-запись через API (TTL=60s)
4. Cron-job раз в 5 минут: если `>10 Handshake timeout/мин` → автоматический hop

Прокси слушает на `[::]` — ротация без рестарта. Клиент при следующем DNS lookup получает новый IPv6.

```bash
# Ручная ротация:
/opt/mtproto-proxy/ipv6-hop.sh

# Статус:
/opt/mtproto-proxy/ipv6-hop.sh --check

# Credentials (Cloudflare API):
# CF_TOKEN и CF_ZONE хранятся в /opt/mtproto-proxy/env.sh
```

### Solution 4: Nginx Template ServerHello (код в `tls.zig`)

Старый `buildServerHello` собирал TLS 1.3 ServerHello вручную с рядом fingerprint-проблем:
- **Extension ordering**: `key_share` шёл до `supported_versions`, а OpenSSL/Nginx ставит `supported_versions` первым. DPI сравнивает порядок расширений.
- **Random AppData size**: Случайный размер `1024 + (random % 3072)` — у реального Nginx размер фиксирован (зависит от сертификата).
- **AppData content**: Нули вместо реалистичного зашифрованного контента.

**Исправление**: Comptime-шаблон `buildNginxTemplate()` генерирует побайтово идентичный ответ Nginx/OpenSSL:
- Правильный порядок расширений: `supported_versions` (0x002b) → `key_share` (0x0033)
- Фиксированный AppData = 2878 байт (реальный Let's Encrypt ECDSA cert chain)
- Детерминированное псевдослучайное тело AppData через SplitMix64 PRNG (comptime)
- Runtime-патчинг только 3 полей: HMAC random (32B), session_id (32B), x25519 key (32B)
- `@setEvalBranchQuota(100_000)` для 2878-байтового comptime цикла

```
Template layout (3016 bytes total):
  [0..127]     ServerHello record (5 hdr + 122 body)
  [127..133]   ChangeCipherSpec record (5 hdr + 1 body)
  [133..3016]  ApplicationData record (5 hdr + 2878 body)

Mutable field offsets:
  tmpl_random_offset     = 11   (32 bytes — HMAC)
  tmpl_session_id_offset = 44   (32 bytes — echo from client)
  tmpl_x25519_key_offset = 95   (32 bytes — random x25519)
```

Утилита `deploy/capture_template.py` позволяет захватить реальный ServerHello с живого сервера для верификации/обновления шаблона при смене версии OpenSSL/Nginx.

### Solution 5: Split-TLS Desync (код в `proxy.zig`)

Серверный аналог zapret split — разбивает ServerHello на два TCP-сегмента:
1. **Первый сегмент**: 1 байт (`0x16` — TLS record type)
2. **Пауза 3ms** (`std.Thread.sleep`) — форсирует границу сегмента
3. **Второй сегмент**: остальные ~3015 байт

Пассивный ТСПУ классифицирует TCP payload по первым байтам. Одиночный `0x16` не даёт DPI достаточно данных для сигнатуры FakeTLS. К моменту прихода второго сегмента DPI уже не ассоциирует его с TLS handshake.

```zig
// proxy.zig ~line 388:
if (state.config.desync and server_hello.len > 1) {
    setsockopt(TCP_NODELAY, enable);
    writeAll(client_stream, server_hello[0..1]);    // 1 byte
    std.Thread.sleep(3 * std.time.ns_per_ms);       // 3ms
    writeAll(client_stream, server_hello[1..]);      // rest
}
```

Безопасно с thread-per-connection: sleep блокирует только текущий поток, accept loop продолжает работать. Управляется конфигом: `desync = true` в `[censorship]` (включён по умолчанию).

### Solution 6: nfqws OS-Level Desync (`deploy/setup_nfqws.sh`)

Для максимальной защиты — OS-level TCP desync через zapret `nfqws`:
- **Fake packets**: отправляет поддельный TLS ServerHello с TTL, который истекает до DPI, но после ISP-роутера. DPI видит «валидный TLS» и пропускает соединение.
- **MD5sig fooling**: fake-пакеты имеют невалидную TCP MD5 подпись — ядро Linux на стороне клиента их дропает, но DPI не проверяет md5sig.
- **Split at byte 1**: дублирует Split-TLS из proxy.zig на уровне ядра (belt and suspenders).

```bash
# Установка:
sudo bash deploy/setup_nfqws.sh

# С кастомным TTL (по traceroute до ISP):
sudo bash deploy/setup_nfqws.sh --ttl 4

# Удаление:
sudo bash deploy/setup_nfqws.sh --remove
```

### Solution 7: Local Nginx Masking (`deploy/setup_masking.sh`)

Timing side-channel: при маскировке bad clients проксирование на удалённый `wb.ru:443` добавляет 30-60ms RTT. DPI может сравнить RTT «нашего wb.ru» с реальным и обнаружить аномалию.

Решение: локальный Nginx на `127.0.0.1:8443` с self-signed (или Let's Encrypt) сертификатом. RTT маскировки < 1ms — неотличимо от реального сервера.

```bash
sudo bash deploy/setup_masking.sh wb.ru
```

### Конфигурация для работы с ТСПУ
```toml
[censorship]
tls_domain = "wb.ru"   # ВАЖНО: должен совпадать с hex-суффиксом в ee-секрете
mask = true             # Прозрачный проброс на реальный wb.ru для неизвестных клиентов
```

### Хронология блокировок
- **IP сжигается**: ~10 мин после первого FakeTLS соединения (пассивный детект)
- **BGP-blackhole**: ~20 мин (0 пакетов до сервера)
- **IPv6 не блокируется**: /64-подсети не трогают — слишком большой риск collateral damage

---

## Co-located AmneziaVPN / WireGuard

When the proxy and AmneziaVPN run on the same server, iOS VPN clients cannot reach `host:443` by default.

**Root cause**: iOS routes ALL traffic through the VPN tunnel (unlike macOS, which bypasses the tunnel for the VPN server's own IP). Packets exit the WireGuard tunnel inside Docker network `amn0` (`172.29.172.0/24`). Docker's default `FORWARD policy DROP` silently discards these packets before they reach the proxy on `eth0:443`.

**Symptoms**: iPhone shows "checking..." / "Updating..." when VPN is active. Mac works fine. Existing connections survive VPN activation (sockets already established outside the tunnel).

**Diagnosis**: `tcpdump -n -i any dst port 443` shows zero packets from the VPN subnet. `iptables -L FORWARD` shows `policy DROP`.

**Fix**:
```bash
# Allow WireGuard client IPs (default AmneziaWG is 10.8.1.x)
iptables -I DOCKER-USER -s 10.8.1.0/24 -p tcp --dport 443 -j ACCEPT

# Allow Docker network IPs (if proxy runs from another container)
iptables -I DOCKER-USER -s 172.29.172.0/24 -p tcp --dport 443 -j ACCEPT

netfilter-persistent save
```

### Commercial / Premium VPNs Filtering
If connecting to the proxy while behind a **Commercial/Premium VPN**, the VPN provider's firewall often drops MTProto traffic by design:
- **DPI**: They perform Deep Packet Inspection and drop FakeTLS connections that do not act identically to standard browsers.
- **IP Blocking**: They silently block TCP routing to Telegram Datacenter IPs.
- **Symptoms**: Proxy sits in "Updating..." state indefinitely. The proxy instance receives 0 packets from the VPN exit node.
- **Solution**: Use self-hosted VPNs (like the co-located AmneziaWG above) which do not perform traffic filtering or DPI on outbound connections.

---

## Development Conventions
- **Memory Management**: Pass `Allocator` to functions; use `defer` for cleanup.
- **Error Handling**: Use Zig error unions (`!T`) with `try`/`catch`.
- **Testing**: Comprehensive E2E Integration tests + unit tests in `test` blocks at the bottom of `.zig` files. Includes fake localhost TCP servers directly communicating via background loopback sockets.
- **Logging**: Only `log.info` for essential events; `log.debug` for diagnostics.
- **No global mutable state**: Always pass `ProxyState` by reference.

### Repository Workflow Rule
- For every substantial code task, update both `README.md` (sometimes referred to as `REDMI`) and `GEMINI.md` before finalizing, so user-facing docs and engineering notes stay in sync.
- Agent-facing instruction: treat README/REDMI + GEMINI updates as part of done criteria for feature/fix work, not as optional cleanup.

---

## Useful Diagnostics

### Service & Process Monitoring
```bash
# Check service status
ssh root@154.59.111.234 'systemctl status mtproto-proxy --no-pager'

# Check active connections (IPv4 + IPv6)
ssh root@154.59.111.234 'ss -tnp | grep mtproto'

# Check process stats (CPU, threads, memory)
ssh root@154.59.111.234 'ps -o pid,pcpu,pmem,nlwp,rss,vsz,args -p $(pgrep -f mtproto-proxy)'
```

### Log Analysis
```bash
# Check recent logs
ssh root@154.59.111.234 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager'

# Check for Replay attacks detected (ТСПУ Revisor)
ssh root@154.59.111.234 'journalctl -u mtproto-proxy --no-pager | grep "Replay attack"'

# Check IPv6 hopping log
ssh root@154.59.111.234 'cat /var/log/mtproto-ipv6-hop.log | tail -20'

# Check current active IPv6
ssh root@154.59.111.234 'cat /tmp/mtproto-ipv6-current'

# Check short-read diagnostics (fragmented ClientHello / partial reads)
ssh root@154.59.111.234 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager | grep "DIAG: readExact"'

# Check MiddleProxy route instability for media/non-media
ssh root@154.59.111.234 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager | grep -E "MiddleProxy connect|DC4 MiddleProxy timeout|DC203 MiddleProxy timeout"'
```

### IPv6 Hopping
```bash
# Manual hop to new IPv6 address
ssh root@154.59.111.234 '/opt/mtproto-proxy/ipv6-hop.sh'

# Check hop status
ssh root@154.59.111.234 '/opt/mtproto-proxy/ipv6-hop.sh --check'

# Check cron job
ssh root@154.59.111.234 'cat /etc/cron.d/mtproto-ipv6'
```

### Low-level Debugging
```bash
# Check for CLOSE-WAIT sockets
ssh root@154.59.111.234 'ss -tnp state close-wait | grep mtproto'

# Check thread states in Linux /proc
ssh root@154.59.111.234 'cat /proc/$(pgrep -f mtproto-proxy)/status | grep -E "Threads|State"'

# Verify TCPMSS clamping rule
ssh root@154.59.111.234 'iptables -t mangle -L OUTPUT -n -v | grep TCPMSS'
```

---

## Server Migration Guide

If the current VPS is permanently blocked or blacklisted, migrating to a new VPS requires these steps to maintain seamless connectivity for clients:

1. **Deploy to New VPS**: 
   Use the `install.sh` script to set up Zig, clone the proxy, compile it, and enable DPI bypass metrics (TCPMSS).
   *The `--auto` mode for IPv6 hopping requires Cloudflare API credentials.*
   ```bash
   cat deploy/install.sh | ssh root@<NEW_VPS_IP> "export CF_TOKEN='...'; export CF_ZONE='...'; bash"
   ```

2. **Migrate Configuration**:
   It is crucial to keep the `[access.users]` secrets identical so the client connection strings (`tg://proxy?server=...&secret=...`) remain valid.
   Copy `/opt/mtproto-proxy/config.toml` from the old server to the new one, and then restart the proxy.
   ```bash
   systemctl restart mtproto-proxy
   ```

3. **Update DNS Records**:
   To ensure transparent failover without changing the immutable client link:
   - Update the **A record** (`proxy.sleep3r.ru`) to point to the new `<NEW_VPS_IP>` using the Cloudflare Dashboard or API.
   - Run `/opt/mtproto-proxy/ipv6-hop.sh` on the new server to force an immediate **AAAA record** overwrite to the new server's IPv6 pool.

4. **Verify**:
   Check `systemctl status mtproto-proxy` and verify that the Cloudflare DNS now resolves to the new IP addresses. Telegram clients will automatically pick up the new IPs from the existing proxy link.
