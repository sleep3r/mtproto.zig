# Architecture

A production MTProto proxy in Zig with FakeTLS fronting, active anti-replay, and Linux-first
deployment. This document is the in-repo architecture reference; the public stability contract is in
[COMPATIBILITY.md](COMPATIBILITY.md), and the forward-looking plan is in [ROADMAP_1.0.md](ROADMAP_1.0.md).

## Build artifacts

`build.zig` produces two binaries:

| Binary | Source | Install path | Purpose |
|--------|--------|--------------|---------|
| `mtproto-proxy` | `src/main.zig` | `/opt/mtproto-proxy/mtproto-proxy` | The proxy server (data plane) |
| `mtbuddy` | `src/ctl/main.zig` | `/usr/local/bin/mtbuddy` | Installer & control panel (TUI) |

- **Toolchain**: pinned via `build.zig.zon` (`minimum_zig_version`) and `.zig-version`. The codebase
  rides churn-prone `std` APIs, so the compiler is part of the contract.
- **Data-plane safety**: the proxy is built **ReleaseSafe by default** in release builds
  (`-Ddataplane_safety`, default on) — it parses untrusted network input, so bounds/overflow/null
  checks stay on. `mtbuddy`/`bench` keep the requested mode. The proxy is also a **PIE** (ASLR); full
  RELRO is Zig's default.
- Cross-compile for production: `make build` (or
  `zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux -Dcpu=x86_64_v3+aes`).

## Runtime model

- **Epoll event-loop core** (`src/proxy/proxy.zig`, `EventLoop.run`): each worker runs one Linux
  `epoll` loop and handles all its socket I/O with no thread-per-connection — handling is
  state-machine driven.
- **Multi-core via SO_REUSEPORT workers** (`[server].workers`, default `1`): `1` = the classic single
  loop (unchanged); `>1` (or `0`=auto=one-per-CPU) spawns N workers, each on its own thread with its
  **own SO_REUSEPORT listener + epoll**. The kernel load-balances incoming connections across workers,
  spreading the relay/crypto load across cores. Worker 0 runs on the main thread and owns the signalfd;
  workers 1..N−1 observe `ProxyState.shutting_down` (atomic) to drain together on shutdown. Total
  active connections stay bounded by the **global saturation cap** (`active_connections` vs
  `max_connections`), so per-worker pools are not divided.
- **Connection slots** are pre-allocated per worker and reused; per-connection heavy buffers are
  allocated on-demand, not embedded in idle slots.
- **Shared state** (`ProxyState`): global counters are `std.atomic.Value` (so `/metrics` aggregates
  across workers for free); the **replay cache**, the **middle-proxy snapshot**, and the **flood guard
  + subnet rate limiter** are all guarded by a real cross-thread mutex (`std.Io.Mutex`, since Zig 0.16
  has no `std.Thread.Mutex`), correct under N workers (all touched only on the handshake/accept/routing
  path, not the per-byte relay). The flood/subnet guards are **shared (global)**, so an IP/subnet
  spread across SO_REUSEPORT shards is still limited globally rather than ~N×threshold.
- **Liveness across workers**: each worker writes its own slot in a shared `worker_heartbeats` array;
  `/healthz` and the systemd watchdog require **every** active worker to be fresh, so a wedged
  non-owner shard is surfaced (not masked by worker 0 staying alive). The per-worker connection pool is
  sized `max_connections / workers` so total slot memory stays ~constant regardless of worker count.
- **SIGHUP config reload is refused when `workers>1`** (logs a message): a live reload swaps and frees
  shared config strings (e.g. `tls_domain`) that the other worker threads read on the hot path, so a
  restart is required to apply config changes under multi-worker. Single-worker hot-reload is unchanged.
- **Background threads**: a middle-proxy metadata updater and the metrics server run as detached
  threads reading atomics/snapshots; they are spawned once (not per worker) and never touch the
  per-byte relay path.

> Runtime validation note: the multi-worker path builds and cross-compiles and was adversarially
> concurrency-reviewed, but it is **opt-in** and should be validated under real load on a Linux host
> (throughput scaling, even distribution, graceful shutdown) before being made the default.

## Core connection flow

1. Accept client socket (non-blocking); reserve handshake budget at **first byte** (slow-loris guard).
2. Parse the TLS ClientHello record header/body incrementally.
3. Validate the TLS-auth HMAC (`tls.validateTlsHandshake`) and SNI against `tls_domain`.
4. Build/send the fake `ServerHello` — a comptime nginx/OpenSSL template whose per-connection fields
   (server-random=HMAC, echoed session_id, fresh x25519 key, randomized cert AppData) and the
   **client-echoed cipher suite** are patched in. Optional split/desync behavior follows.
5. Read the 64-byte MTProto obfuscation handshake.
6. Resolve route: direct DC or MiddleProxy (RPC relay), media-aware (`dc_idx < 0` / DC203).
7. Enter relay mode (C2S/S2C transform pipeline).

Non-validating / probe traffic is **masked**: the buffered bytes are forwarded to the configured mask
target (real `tls_domain:443` by default) so an active prober sees only a real backend.

## Relay pipeline

**C2S**: TLS unwrap → client AES-CTR decrypt → transport encapsulation (direct: AES-CTR re-encrypt for
the DC; MiddleProxy: `RPC_PROXY_REQ` framing + AES-CBC layer). **S2C**: transport
decapsulation/decrypt → client AES-CTR encrypt (unless fast-mode) → TLS application-record wrapping.
AES-CTR runs **8-wide** on the block-aligned bulk (`src/crypto/crypto.zig`).

## MiddleProxy (media / ad-tag relay)

Event-loop-integrated non-blocking handshake; periodic endpoint/secret metadata refresh; per-DC
routing with a direct fallback. Quick-acks (`RPC_SIMPLE_ACK`) are relayed per-transport (the 4-byte
confirm is byte-reversed for abridged, verbatim for intermediate/secure).

## Anti-replay & flood

- Handshake digest validated within a timestamp-skew window; the replay-cache key is the canonical
  pre-XOR HMAC.
- Per-IP handshake flood guard + per-/24 subnet rate limiter (both off by default; opt-in).

## Observability (metrics server, localhost by default)

- `/metrics` — Prometheus text: connections, drops, per-reason close counters
  (`mtproto_connection_close_reason_total{reason}` — the evasion/block signal), bytes, middleproxy.
- `/healthz` — liveness (event loop ticked within 5s).
- `/readyz` — readiness (serving and not draining; **not** gated on middleproxy).
- **systemd**: `Type=notify` (READY=1 after bind) + `WatchdogSec` (WATCHDOG=1 each loop iteration) via
  a native dependency-free sd_notify (`src/proxy/sd_notify.zig`).

## mtbuddy (installer & control panel)

Source: `src/ctl/`. Interactive TUI (raw terminal, arrow-key nav, EN/RU i18n).

| Module | Purpose |
|--------|---------|
| `main.zig` | CLI dispatch + interactive menu |
| `install.zig` / `update.zig` / `uninstall.zig` | Install / signed self-update / clean removal |
| `tunnel.zig` | AmneziaWG tunnel + SO_MARK policy routing |
| `dashboard.zig` | FastAPI dashboard installer (pinned+verified `uv` + pinned deps) |
| `masking.zig` / `nfqws.zig` / `recovery.zig` | Masking backend / zapret desync (latest release tag) / recovery |
| `release.zig` / `links.zig` / `i18n.zig` | Unit/asset generation / tg:// link builder / localization |

Third-party install artifacts: `uv` is version-pinned and verified against its published `.sha256`,
and the dashboard's Python deps are exact-version pinned. `zapret`/`nfqws` is treated differently — it
is the **DPI-bypass engine and must stay current with DPI changes**, so it is *not* frozen: the
installer clones the **latest release tag** (resolved via `git ls-remote`, with an offline fallback)
and verifies the clone landed on the commit that tag advertised. This is a deliberate
freshness-over-pinning trade-off for the evasion engine — it is **not** a signed-tag or in-repo-checksum
supply-chain pin (it is built and run root-side, so operators should be aware). Stronger options
(hardcoded `uv` SHA, `--require-hashes` Python lockfile, signed-release verification) are tracked in
ROADMAP_1.0.md.

## Deployment layout (server)

```
/opt/mtproto-proxy/
├── mtproto-proxy          # proxy binary (ReleaseSafe, PIE)
├── config.toml            # runtime configuration
├── env.sh                 # optional env vars (TAG, etc.)
└── monitor/               # dashboard assets (optional)
/usr/local/bin/mtbuddy
/etc/systemd/system/mtproto-proxy.service   # Type=notify, hardened (seccomp/RestrictAddressFamilies/…)
```

## Platform scope

- **Linux-only runtime target** (epoll, `std.os.linux`). macOS is supported for development /
  cross-compile / `zig build test`, not for production runtime.

## Design principles

- Keep the hot path non-blocking and allocation-light.
- Favor explicit state transitions over hidden control flow.
- Keep handshake-path security checks strict and cheap.
- Avoid stale parallel implementations of the same protocol path.
- Secure-by-default config; opt-in for anything that weakens evasion or adds attack surface.
