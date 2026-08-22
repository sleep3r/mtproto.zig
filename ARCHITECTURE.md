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

The FakeTLS ServerHello is a fixed three-record shape — `ServerHello` (one key_share:
an X25519MLKEM768 `0x11ec` share when the client offered one, else a classical x25519
share, plus a client-echoed cipher) + `ChangeCipherSpec` + one `ApplicationData`
"certificate" record — validated by the Telegram client only for framing + the HMAC
in `server-random`. Two hard constraints follow:

1. **`tls_domain` is immutable once links are distributed.** The `ee` secret embeds
   the domain as hex, so a tg:// link is a function of `(secret, tls_domain)`.
   Changing `tls_domain` on a live deployment invalidates **every** user's link.
   Treat it as frozen the moment a link is shared. (See `config.zig` /
   [COMPATIBILITY.md](COMPATIBILITY.md).)

2. **We can only mimic a domain whose genuine TLS 1.3 is single-round, and since June
   2026 it must support X25519MLKEM768.** Our FakeTLS emits exactly one ServerHello,
   with either an X25519MLKEM768 (`0x11ec`) key_share (when the client offered it) or a
   classical x25519 key_share — never an HRR, never a group the client didn't offer.
   Two things make a domain a *good* target:

   - **Single round, no HRR.** For a modern (Chrome-shaped, MLKEM-offering) ClientHello
     the domain must answer in one ServerHello. `wb.ru` / `mail.ru` prefer `secp521r1`
     and send a `HelloRetryRequest` (genuine handshake:
     `ClientHello → HRR → ClientHello#2 → ServerHello(secp521r1)`) while ours is a
     single record — an unfixable **passive ServerHello mismatch**.
   - **Post-quantum capable.** Since the night of 4→5 June 2026 the TSPU flags a domain
     that negotiates *only* classical x25519 (declining X25519MLKEM768): iOS clients —
     and everyone on their NAT egress IP — fronting such a domain get blocked. The
     signal is a property of the **domain** (the censor probes the SNI out-of-band), so
     our 0x11ec echo can't buy it back; the domain itself must negotiate
     X25519MLKEM768. A PQ-capable domain that does so in one round is exactly what our
     FakeTLS mimics via the 0x11ec echo, so it satisfies both requirements at once. See
     [THREAT_MODEL.md](THREAT_MODEL.md) "Post-quantum key_share".

   The installer probes the chosen domain (`src/ctl/fronting_domain.zig`, offering
   `X25519MLKEM768:X25519`) and **warns** if it does only classical x25519 or an HRR,
   so the choice is made well *before* the link is locked. There is no runtime fix for
   an already-distributed link pointed at a poor domain — it is an accepted residual,
   and the `tls_domain` immutability in (1) means an existing deploy on a now-marked
   domain cannot migrate without invalidating every link.

**Masking / active probes** are independent of the link: non-validating (no-secret)
traffic is transparently relayed to the mask target. Field-verified behavior
(against a live tunnel-mode deployment):

- Fronting the **real** domain (`mask_port=443` → `tls_domain:443`) makes a prober
  see the genuine site + a CA-chained cert — **verified working** for a single-round
  domain (probing the proxy fronting `rutube.ru` returned its real GlobalSign cert;
  note that domain-selection guidance has since tightened to require X25519MLKEM768 —
  see constraint 2 — so re-probe any candidate for PQ support before committing).
  This requires the proxy to resolve the domain — see the DNS note below.
- It only works for domains whose TLS 1.3 is **single-round** (x25519 or the PQ
  hybrid). Our relay
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

## WEB proxy relay (Telegram Desktop 7.1+)

Telegram Desktop 7.1 added a fourth proxy type, `WEB` (serialized type code `4`). It is an ordinary
MTProxy whose **carrier is a browser**: the client opens no MTProto socket. A hidden native WebView
loads `https://<domain>/?bridge=<capability>` and the page we serve shuttles multiplexed frames over
a same-origin WebSocket. We implement the server half.

```text
Telegram Desktop → hidden WebView → https://relay.example.com/
  → [TLS terminator: local nginx via the masking path, or a CDN]
  → mtproto-web-relay  (mtproto-proxy web-relay)
  → mtproto-proxy      (direct-obfuscated, PROXY-protocol prefixed)
  → Telegram
```

**Process model.** The relay is a mode of the *same* binary
(`mtproto-proxy web-relay <config.toml>`, unit `mtproto-web-relay.service`), because `mtbuddy update`
swaps exactly one proxy artifact — a separate binary would reach nobody until the already-installed
mtbuddy learned to fetch it. It is a *separate process* because a fault in it must not abort the data
plane, which is built ReleaseSafe. It has its own single-threaded, level-triggered epoll loop in
`src/web/relay.zig`, with the same discipline as `EventLoop` in `src/proxy/proxy.zig` (`data.fd`
tagging, interest recomputed only on change, `close()` deferred to the top of the next iteration).

**Protocol** (`src/web/frame.zig`, byte-exact with tdesktop's `web_proxy_frame.cpp`):

```text
type:u8 | stream_id:u24 | length:u32 | payload      (big-endian)
```

`HELLO(0x10)` from the client, `WELCOME(0x11)` back — alone in its own carrier message, because the
client requires exactly one WELCOME frame in the first message it parses. Then `OPEN`/`DATA`/`CLOSE`/
`WINDOW` per stream, `PING`/`PONG` on stream 0 for liveness. Each stream starts with an implicit
4 MiB window in each direction; we replenish the client's credit only once its bytes have actually
left for the backend, so a stalled backend throttles the client instead of growing our memory.

**The bridge capability** (`src/web/capability.zig`) is
`base64url(HMAC-SHA256(key = secret_bytes, "tdesktop-web-proxy-bridge-v1\n" + host))`, computed by the
client and never carrying the secret itself. Two consequences we lean on: the relay can recompute it
per configured user and so knows *which* user is connecting without touching the MTProto stream; and a
visitor who cannot present a capability derived from a real secret never sees the bridge page — they
get the same cover page every other path returns, so an active prober without a user secret cannot
distinguish this host from a plain website.

**Why `dd` and not `ee`.** The relay is a raw byte pipe; it adds no TLS-emulation record, so the
client reports an `ee` FakeTLS secret as `Status::Unsupported` for a WEB proxy. WEB links therefore
carry the *same* 16-byte user secret encoded as `dd…`. That means the data plane must accept the
direct-obfuscated transport from the relay while `fake_tls_only` keeps rejecting it for everyone else.

**The trust gate** (`src/proxy/trusted_peers.zig`, `proxy.zig:readTlsHeader`). Trust is decided once,
at `accept()`, from the address the kernel reported, and stored in `slot.trusted_peer`. It must never
be recomputed from `peer_addr`, which the PROXY-protocol path overwrites with a client-supplied
address — gating on that would let anyone on the internet claim `127.0.0.1` and unlock a
fingerprintable `dd` responder. Loopback is trusted while `[web].enabled`; other relay hosts are named
in `[web].relay_sources`. Trusted peers are also exempt from the per-IP flood guard, the per-/24
limiter and the 4-second `dd` decision timer, because every relayed user shares one source address and
one flaky client would otherwise block them all. The relay prefixes each backend connection with a
PROXY v2 header carrying the real browser address, so per-IP accounting and the address Telegram sees
stay honest.

**Topologies.** `mtbuddy setup web --mode mask` (default) serves the relay through the proxy's own
masking backend: a second nginx vhost on `mask_port`, selected by SNI, holding a Let's Encrypt
certificate for the relay domain. Unknown-SNI probes keep hitting the masking vhost, which stays the
default server for that listener. `--mode behind` skips nginx entirely and expects a CDN or another
host to terminate TLS.

**The client's address across the mask hop.** Masking is a raw byte pipe, so the terminator behind it
observes `127.0.0.1` and every relayed user would reach Telegram as a loopback client —
`slot.peer_addr` is what `middle_proxy_handshake.zig` puts in `RPC_PROXY_REQ.remote_ip_port`. So the
relay vhost carries a *second* listener, `127.0.0.1:8444 ssl proxy_protocol`, named by
`[web].mask_backend`: when a masked connection's SNI equals `[web].domain` the proxy fronts it there
and prefixes it with a PROXY v2 header built from the address `accept()` reported
(`proxy_protocol.buildV2`). nginx passes that on as `X-Forwarded-For $proxy_protocol_addr`, the relay
reads the right-most entry, and it lands back in `peer_addr` on the backend connection. Every other
SNI keeps using the plain masking port with no header, so probe behaviour is unchanged.

**Cost.** One WEB client occupies one masked connection plus one connection per logical MTProto
stream against `[server].max_connections` — budget roughly 3–5× a direct client.

**Testing.** The frame codec, the capability derivation (against tdesktop's own normative vectors),
the WebSocket and HTTP parsers and the PROXY-header emission are unit-tested in `zig build test`. The
bridge page is the one piece that runs in the user's browser, so `zig build web-bridge`
(`test/web-bridge/`) drives it with a scripted stand-in for the client: it asserts the
`tproxy-android-init` ordering, that WELCOME arrives alone in the first binary message, that a
post-adoption carrier loss does *not* reconnect, that a pre-adoption retry replays HELLO, and that
the loopback-iframe path rejects a foreign origin. Against a live deployment, `test/web-e2e/live_check.py`
is the real end-to-end: it drives the whole chain from the outside (cover/bridge pages, capability
gate, HELLO→WELCOME, then a genuine `req_pq_multi → res_pq` through relay → proxy → Telegram) and can
hold a session idle longer than every timeout in the chain to prove the keepalive design.

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
| `tunnel.zig` | Tunnel-egress orchestration (SO_MARK policy routing) |
| `tunnel_wg.zig` | WG/AmneziaWG kernel-tunnel backend + tunnel-pool failover script |
| `tunnel_singbox.zig` | Share-link sing-box TUN egress (vless/vmess/trojan/ss); dispatches `wireguard://` to `tunnel_wg.zig` |
| `sharelink.zig` | VPN share-link parsing + `wireguard://` → WG `.conf` transform (std-only) |
| `ipv6hop.zig` | IPv6 `/64` address rotation + Cloudflare DNS update |
| `config_cmd.zig` / `fronting_domain.zig` | `config` get/set editor / domain-fronting x25519 helper |
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
