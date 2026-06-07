# Architecture

A production MTProto proxy in Zig with FakeTLS fronting, active anti-replay, and Linux-first
deployment. This document is the in-repo architecture reference; the public stability contract is in
[COMPATIBILITY.md](COMPATIBILITY.md).

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

## FakeTLS fronting & domain selection

The FakeTLS ServerHello is a fixed three-record shape — `ServerHello` (one x25519
key_share, a client-echoed cipher) + `ChangeCipherSpec` + one `ApplicationData`
"certificate" record — validated by the Telegram client only for framing + the HMAC
in `server-random`. Two hard constraints follow:

1. **`tls_domain` is immutable once links are distributed.** The `ee` secret embeds
   the domain as hex, so a tg:// link is a function of `(secret, tls_domain)`.
   Changing `tls_domain` on a live deployment invalidates **every** user's link.
   Treat it as frozen the moment a link is shared. (See `config.zig` /
   [COMPATIBILITY.md](COMPATIBILITY.md).)

2. **We can only mimic a domain whose genuine TLS 1.3 is single-round x25519.** Our
   FakeTLS emits exactly one ServerHello with an **x25519** key_share and cannot
   replicate a `HelloRetryRequest` or a non-x25519 group. So a *good* fronting
   domain negotiates **x25519 in one round** for a modern (Chrome-shaped, MLKEM-
   offering) ClientHello — the client offers key_shares for both MLKEM and x25519,
   and such a server simply picks x25519, which is exactly what we emit. Big RU
   sites like `rutube.ru`, `ozon.ru`, `vk.com`, `yandex.ru`, `dzen.ru` do this.

   Some domains do **not**: e.g. `wb.ru` and `mail.ru` prefer `secp521r1` and send a
   `HelloRetryRequest` (they even fail an x25519-only hello). For such a domain a
   genuine handshake is `ClientHello → HRR → ClientHello#2 → ServerHello(secp521r1)`
   while ours is a single `ServerHello(x25519)` — a **passive ServerHello mismatch we
   cannot fix without changing `tls_domain`**, which constraint (1) forbids. The
   installer therefore probes the chosen domain and **warns** if it is a poor mimicry
   target, so the choice is made well *before* the link is locked. There is no
   runtime fix for an already-distributed link pointed at a poor domain — it is an
   accepted residual.

**Masking / active probes** are independent of the link: non-validating (no-secret)
traffic is transparently relayed to the mask target. Field-verified behavior
(against a live tunnel-mode deployment):

- Fronting the **real** domain (`mask_port=443` → `tls_domain:443`) makes a prober
  see the genuine site + a CA-chained cert — **verified working** for a single-round
  domain (probing the proxy fronting `rutube.ru` returned its real GlobalSign cert).
  This requires the proxy to resolve the domain — see the DNS note below.
- It only works for domains whose TLS 1.3 is **single-round x25519**. Our relay
  carries a single ClientHello↔ServerHello exchange, **not** a `HelloRetryRequest`
  multi-round. Fronting an HRR domain (e.g. `wb.ru`) yields an *incomplete* handshake
  (no certificate) — worse than a complete one. This is the same reason such domains
  are poor fronting targets (see `tls_domain` above).
- A local **self-signed nginx** (`mask_port=8443`) serves a self-signed cert — an
  active-probe tell — but completes a handshake. So when a deployment is locked to an
  HRR domain (the link is immutable), local nginx is the **least-bad** fallback (a
  complete self-signed handshake beats an incomplete real-domain one).

> DNS note: real-domain fronting needs hostname resolution. Zig's std resolver throws
> `ResolvConfParseFailed` on a `/etc/resolv.conf` with no trailing newline (common on
> SolusVM/VPS images), which silently disables all hostname masking; `getAddressList`
> falls back to `getent` (NSS) to tolerate that.

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
- **systemd**: mtbuddy installs `Type=simple` (robust on bare-metal **and** in containers).
  A native dependency-free sd_notify (`src/proxy/sd_notify.zig`) implementing READY=1 +
  WATCHDOG=1 is present but dormant — `Type=notify`/`WatchdogSec` is gated off until
  container detection lands, because containerized systemd often drops the notify datagram
  and would restart-loop a healthy proxy under `Restart=always`.

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
(hardcoded `uv` SHA, `--require-hashes` Python lockfile, signed-release verification) are tracked as
internal follow-ups.

## Deployment layout (server)

```
/opt/mtproto-proxy/
├── mtproto-proxy          # proxy binary (ReleaseSafe, PIE)
├── config.toml            # runtime configuration
├── env.sh                 # optional env vars (TAG, etc.)
└── monitor/               # dashboard assets (optional)
/usr/local/bin/mtbuddy
/etc/systemd/system/mtproto-proxy.service   # Type=simple, hardened (seccomp/RestrictAddressFamilies/…)
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
