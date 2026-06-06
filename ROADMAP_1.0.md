# mtproto.zig → 1.0.0 — Implementation Plan ("best Telegram proxy in the world")

> Status: planning document for the first major release. Derived from a multi-agent forward-looking
> audit (web research on 2023–2026 censor/DPI techniques + competitor proxies + a deep 1.0-lens code
> audit, 11 domains, each adversarially verified — 182 recommendations) cross-checked against
> first-hand code grounding. This is the **why/what/how**, prioritized, with concrete file:line
> touchpoints, effort, risk, dependencies, and acceptance criteria. It supersedes ad-hoc TODOs.
>
> A prior security pass (PR #301) already fixed ~96 issues (secure-by-default `fake_tls_only`,
> dashboard auth, supply-chain SHA pins, handshake-budget-at-first-byte, config 0640, etc.). This
> plan is **forward-looking**: what separates "a working proxy" from "the best one in the world."

---

## 0. Thesis — what "best in the world" means here

A Telegram MTProto proxy wins on five axes. We are strong on footprint/UX and have a credible
evasion base, but have hard gaps on the axes that decide survival at scale:

| Axis | Today | 1.0 target |
|---|---|---|
| **Evasion authenticity** | one **static** nginx-template ServerHello; cipher hardcoded `0x1301`; x25519-only key_share; fixed 2878-byte cert record; `setup-masking` wizard defaults to **local self-signed nginx** | ServerHello that **matches the fronted domain** (echo client params → probe real domain → optional REALITY-style reflection); probes always hit a **real** backend; per-region evasion **profiles** + rotation |
| **Scale (per host)** | **single epoll thread**, 1 core, default 512 conns; scalar AES (~1 GB/s) | **SO_REUSEPORT worker model** (N cores), 8-wide AES, load-gated throughput; tens of cores × 60k conns |
| **Scale (fleet / "масштабирование обхода")** | single-box; hardcoded one-host DNS helper; ipv6-hop is demo-grade | **fleet identity** (one link, N nodes), provider-agnostic **DNS-fronting** rotation, **block-detection → auto-rotate** loop, aggregated fleet metrics |
| **Measured undetectability** | **none** — no JA4S/DPI test, no block-rate signal | **DPI-validation in CI** (JA4S/record-geometry vs real domain) + **evasion/block telemetry** + (post-1.0) geo block-rate monitoring |
| **Test rigor & safety** | 189 unit, **14 e2e** (byte-count only), **no fuzzing**, prod builds **ReleaseFast** (safety OFF on attacker-facing parsers) | bidirectional **integrity** e2e, **coverage-guided fuzzing**, **load gate**, client-compat matrix, **ReleaseSafe data plane** |

The single most important strategic truth from the research: **a censor that fetches the genuine
`tls_domain` and compares it to what the proxy emits sees an instant mismatch** (cipher / key_share
group / cert-record size), and **the default `setup-masking` flow serves a self-signed cert for a
domain the operator doesn't own** — both decisive active-probe distinguishers. Fixing the
ServerHello↔domain authenticity story is the moat.

### The 2026 threat reality (from research; sources in Appendix C)

> Provenance note: the **TSPU** specifics below (the `2026-04-01` `TELEGRAM_TLS` signature, <48h proxy
> lifetime, TCP-stream MITM) are **community- and vendor-reported** (tgvpn.io, teleproxy, HRW) and
> corroborated client-side by Telegram-Android PR #1949 — treat them as credible field reports, not
> peer-reviewed measurements. The **GFW** and **Xue'24** claims below *are* from peer-reviewed
> sources (USENIX). Plan against both, but weight them accordingly.

- **Russia TSPU** reportedly moved from blocklists to AI protocol-fingerprinting. Around **2026-04-01**
  it is reported to have shipped a `TELEGRAM_TLS` JA3/JA4 signature — but that signature is on the
  **client ClientHello** (fixed client-side by Telegram-Android PR #1949), **not** our ServerHello.
  Public-proxy lifetime is reported to have fallen to **<48h**; TSPU is also reported to do active
  TCP-stream MITM/injection and to block Cloudflare ECH.
- **GFW** runs a passive fully-encrypted-traffic classifier (first-packet popcount/entropy) — it
  **exempts TLS-looking flows**, so it threatens our opt-in `dd` transport, not FakeTLS.
- **USENIX'24 (Xue et al.)** detects obfuscated proxies by **encapsulated-TLS-handshake / burst-shape
  similarity** at ISP scale; random padding alone is insufficient.
- **Iran** uses a protocol whitelist + SNI inspection + TLS fingerprinting.
- **The gold standard** (Xray **REALITY**, mtg/teleproxy "doppelganger") makes the served TLS
  identity *genuinely that of a real site* (relay/mimic), and treats **real-world block-rate** as the
  only true evasion metric.

---

## 1. Prioritization & the 1.0 release gate

**Tiers**: **P0** = 1.0 blocker (must) · **P1** = 1.0 should-have · **P2** = nice-for-1.0 · **P3** =
post-1.0 moat/moonshot. Each item carries Impact (C/H/M/L) × Effort (S/M/L/XL), deps, risk, and
acceptance criteria.

**1.0 ships only when** (the release gate, automated where possible):
1. **Safety**: data plane builds **ReleaseSafe**; core wire parsers have **fuzz targets** green; no
   known parser panic on the corpus.
2. **Scale**: **multi-core workers** land *with* shared-state correctness; **load gate** green with
   published per-worker throughput/latency/RSS numbers.
3. **Evasion**: ServerHello **negotiates from the ClientHello** (cipher + key_share group); default
   masking forwards to a **real** backend (no self-signed-for-unowned-domain default);
   **DPI-validation CI** asserts JA4S + record-geometry match a reference, and proves the
   masking/zero-RTT path is **byte-identical** to the backend in both directions.
4. **Correctness**: **bidirectional integrity** e2e (not byte counts) + **MiddleProxy golden vectors**
   + **client-compat matrix** green in CI; DC203 media + abridged quick-ack bugs fixed.
5. **Trust**: stable surfaces frozen (**ARCHITECTURE.md + COMPATIBILITY.md**), **toolchain pinned**,
   signing hardened (offline/SLSA), all **third-party install artifacts pinned & verified**, systemd
   units at an exemplary `systemd-analyze security` score.

---

## 2. Workstreams

Nine workstreams. Within each, items are ordered by priority then leverage. IDs match the audit for
traceability.

### WS1 — Multi-core scale-out (the per-host scale moat) · CRITICAL

> Verified low-risk: `ProxyState` global counters are **already `std.atomic.Value`**; `ConnectionPool`,
> `flood_guard`, `subnet_limiter` are already per-EventLoop; `ReplayCache` is a flat `[8192]Entry`
> table. SO_REUSEPORT 4-tuple hashing pins a flow to one worker for life → per-worker state needs no
> cross-worker locking on the byte path.

- **[P0·C·L] `reuseport-workers` — SO_REUSEPORT worker threads, each its own epoll.**
  *What*: `[server].workers` (0=auto=nproc, clamp to cores; 1 = today). Each worker opens its **own**
  listener with `SO_REUSEPORT` (the listen path at `proxy.zig:989-1013` currently sets only
  `SO_REUSEADDR`; std `address.listen` doesn't expose REUSEPORT → manual socket), builds its own
  `EventLoop` (epoll_fd, pool, shared_read_buf, mp scratch), runs the **existing loop unchanged**, and
  `sched_setaffinity`-pins to a core. Shared `ProxyState` (atomics, config, middleproxy snapshot) is
  read by all. Aggregate per-worker counters for `/metrics`; broadcast graceful shutdown + join.
  *Deps*: **must land together with `shared-state-multicore`** (they are one change). *Risk*: largest
  change in the tree; `RLIMIT_NOFILE` is process-wide so the per-worker conn cap + `requiredFdsForConnections`
  math must split the shared fd budget; REUSEPORT does **not** rebalance existing (long-lived) Telegram
  connections → imbalance can persist (see `reuseport-imbalance-observability`). Keep the worker set
  fixed for process lifetime. *Acceptance*: load gate shows ~linear scaling to N cores; zero byte
  corruption; graceful shutdown drains all workers.
- **[P0·H·M] `shared-state-multicore` — replay cache / flood guard / subnet limiter correct under N
  workers.** *What*: make `replay_cache` (`proxy.zig:705`, currently an **unlocked** table — security
  regression risk) shared in `ProxyState` behind **64-way striped locks** keyed by hash, *or* keep
  per-worker but scale thresholds by 1/N and document the weaker guarantee. The guards touch only the
  **handshake** path, not the per-byte relay, so contention is bounded. *Risk*: per-worker subnet/flood
  enforce only 1/N because REUSEPORT scatters one IP across workers → consider **eBPF SO_REUSEPORT
  client-IP steering** (`ebpf-reuseport-ip-steering`, P1) to keep per-IP defenses coherent. *Acceptance*:
  a handshake replayed onto any worker is still caught; flood/subnet limits hold globally.
- **[P0·H·M] `aes-ctr-wide` — 8-wide AES-CTR on the relay hot path.** *What*: rewrite
  `AesCtr.apply()` (`crypto/crypto.zig:47-71`, currently one block/loop with a serial counter the
  compiler can't widen) to drive `AesEncryptCtx.xorWide(optimal_parallel_blocks=8)` for the
  block-aligned bulk while preserving the partial-block keystream carry (`buffer`/`buffer_pos`) for the
  unaligned head/tail. *Why*: every relayed byte passes AES twice; realistic **~3–5×** per-core gain
  (AES-256/14-round), compounding the multi-core win — highest leverage-per-effort item. *Risk*: CTR
  continuity across arbitrary-length `apply()` calls; **mandatory cross-boundary byte-equivalence test**.
- **[P0·H·L] `load-throughput-relay-ci` / `load-bench-ci` — real load gate.** *What*: a Linux load
  harness (extend `test/e2e/run.py` or new `src/loadgen`) driving K concurrent real FakeTLS (+dd)
  connections with verifiable payload, reporting **conns/sec** (separate from steady-state MB/s — each
  handshake is CPU-heavy and AES-wide does NOT help it), sustained MB/s/direction, p50/p99 relay
  latency, peak RSS at 10k/50k/100k, **per worker count**. CI fails on relative regression; big-N tier
  runs nightly. Replaces the socket-less `bench.zig:299` "soak". *Why*: can't claim best-in-world,
  size the pool, or guard `reuseport-workers`/`aes-ctr-wide` without measuring real I/O.
- **[P1·H·S] `shard-hotpath-counters`** per-worker sharded traffic counters (avoid contended global
  atomics on the per-byte path). **[P1·M·S] `cgroup-aware-worker-count`** derive workers/affinity from
  the cgroup CPU set. **[P1·M·M] `reuseport-imbalance-observability`** + **`ebpf-reuseport-ip-steering`**.
  **[P1·M·S] `slot-memory-trim`** move rare-path buffers off `ConnectionSlot` to raise the conn cap.
- **[P2·L·M] `splice-cover-path`** zero-copy `splice()` on the untouched masking/zero-RTT cover path.
  **[P2·M·S] `cpu-locality-tuning`**, **`edge-triggered-relay`**.
- **[P3·M·XL] `iouring-backend`** evaluate an io_uring relay backend (multishot recv + registered
  buffers). **[P3·L·XL] `middleproxy-conn-mux`** multiplex client streams over a persistent MP pool.

### WS2 — Evasion authenticity (the protocol moat) · CRITICAL

> The ServerHello must look like the **specific domain** it claims to be, to whoever looks. Present as
> a **ladder** from cheap+local to full+expensive; ship the bottom rungs for 1.0.

- **[P0·H·M] `serverhello-echo-client-params` / `faketls-echo-cipher` — negotiate from the
  ClientHello (rung 1, no network).** *What*: in `buildServerHelloWithTemplate` (`tls.zig:145`) stop
  emitting the comptime-fixed cipher `0x1301` (cipher bytes at template **offset 76-77**, not 89-90)
  and x25519-only key_share (`tls.zig:303-321`). Parse the client's cipher list + `key_share`/
  `supported_groups` (extend the existing `extractSni` walk; add `extractFirstCipher` + key_share
  group), then: pick a **client-offered** cipher with a realistic server preference; set the
  ServerHello **key_share group to one the client actually offered** — if it offered
  **X25519MLKEM768 (`0x11ec`)**, emit a `0x11ec` key_share with a correctly-sized **1088-byte**
  ML-KEM-768 body of random bytes (safe — FakeTLS clients never decapsulate, only check framing+HMAC).
  *Why*: fixes the **single most reliable passive distinguisher** (x25519/AES-128 anachronism vs a 2025
  client offering MLKEM) **and** an RFC 8446 §4.2.8 latent bug (a server key_share group the client
  didn't offer is invalid). Telegram clients ignore the cipher (`tls.zig:127-135`) → pure evasion
  upside, no compat risk. Captures ~70% of the probe-based benefit with **zero network dependency**.
  *Risk*: more ClientHello parsing surface → **fuzz it**; varying cipher/group shifts field offsets so
  `buildServerHelloWithTemplate` must locate the random/session/x25519 fields **dynamically** (not the
  fixed 11/44/95). Cert **record size** still won't match the real domain without rung 2.
- **[P0·H·S] `mask-real-backend-default` — never serve self-signed for an unowned domain (fix the
  wizard).** *What*: the bare config default is already safe (`mask_port=443` → `effectiveMaskTarget=
  tls_domain`, `config.zig:267`). The unsafe path is **`mtbuddy setup-masking`** which sets
  `mask_port=8443` + a **self-signed local nginx** (`masking.zig:120-128,219`). Refuse to enable local
  masking with a self-signed cert unless the operator **owns** the domain (certbot succeeded); else
  keep forwarding probes to the **real** `tls_domain:443`. Hard startup warning + metric when
  `maskTargetIsLocal()` and cert is self-signed. Also: a local nginx serving `<h1>It works!</h1>`
  (`masking.zig:134`) is a content tell even with a real cert — forward to the genuine host.
  *Why*: an active prober with the right SNI but bad HMAC is forwarded to the mask target
  (`proxy.zig:2519-2531`); self-signed-for-unowned-domain = instant unmask. *Residual*: the auth path
  emits a local ServerHello in ~0ms vs the masked path's backend RTT — a **response-timing** side
  channel (track in `response-timing-parity`, P1).
- **[P0·H·S] `mss-clienthello-frag-tuning` — promote MSS fragmentation to a first-class, tested
  evasion primitive.** *What*: the installer already forces ClientHello fragmentation via an **MSS=88**
  clamp on the SYN-ACK (`install.zig:585-600`) — the same trick teleproxy uses. But 88 is itself
  anomalous (real ≈1380). **Retune** MSS so the JA4-relevant extensions (ALPN/sig_algs/key_share)
  still land in segments 2+ without the clamp being a giveaway; pair with inbound nfqws desync so the
  split survives **stateful** reassembly; **assert in CI** that a captured ClientHello arrives in ≥2
  segments with the signatured extensions split; expose a metric. *Why*: this is the deployed,
  cheapest counter to the **April-2026 single-packet ClientHello JA4** extractor (the proxy can't
  change the client's hello, but it can fragment it). *Risk*: too-small MSS hurts upload throughput +
  is its own fingerprint — pick empirically.
- **[P1·H·M] `probe-real-template` / `serverhello-template-diversity` — derive the template from the
  real domain (rung 2).** *What*: at startup + periodically (reuse the middleproxy-refresh thread
  pattern) open a TLS 1.3 connection to `tls_domain:443` **using the actual Telegram client's
  ClientHello shape** (critical — RFC 8446: the elicited cipher/group must be one the *client* offers,
  not a generic Chrome hello), capture the genuine ServerHello, and build the template from the
  **observed** cipher, key_share group, extension order, and **encrypted cert-record size** — replacing
  the fixed `2878` (`tls.zig:226`). Keep the per-connection **random body** (don't cache the body
  verbatim — that re-introduces the byte-identical tell fixed in PR #301). Ship a **library** of
  harvested real-domain templates + an install-time `mtbuddy` capture tool. *Note*: only a raw
  ClientHello + record-header parse is needed (no full TLS client) → effort ~M/L. *Risk*: backend
  rotation → re-sample on JA4S drift + shipped fallback.
- **[P1·H·L] `evasion-profiles` — composable per-region profiles (the structural prerequisite for
  scaling evasion).** *What*: an `[[evasion_profile]]` bundling `{tls_domain, ServerHello template id,
  nfqws desync strategy, DRS params, mask target}`, multiple profiles, a selection key (region/ASN/
  listen-port), and **SIGHUP hot-swap** (the reload path already re-resolves mask/tls_domain,
  `proxy.zig:2054-2099`). Ship curated profiles for **RU-TSPU / IR / CN**. *Why*: today there is
  exactly one of everything; optimal evasion differs by censor and over time. Foundation for A/B,
  fallback, and fleet rotation. *Deps*: builds on the template library + the `Transport` interface
  (WS8).
- **[P1·H·L] `traffic-shape-modeling`** sample (don't hardcode) the DRS ramp and cert-record size from
  the probed domain; jitter inter-record timing on the ServerHello/CCS/AppData burst (reuse
  `desync_wait`); de-fingerprint the shared magic constants **1369** (`drs.zig:10`) and **2878**
  (`tls.zig:226`). Threat = **Xue'24 burst-shape** (not GFW popcount — that exempts TLS).
  **[P1·M·M] `desync-autodiscovery`** blockcheck-style automatic desync-strategy discovery.
  **[P1·H·M] `response-timing-parity`** kill the auth-vs-mask time-to-first-server-byte side channel.
  **[P1·H·M] `block-detection-feedback`** closed-loop: on a block signal (WS6 telemetry) auto-rotate
  profile/domain/strategy.
- **[P2·M·S] `cipher-extension-variation`**, **`sni-ip-plausibility-check`** (refuse to advertise links
  when the SNI's hosting is implausible for the server IP — `google.com` on a random VPS is anomalous),
  **`newsessionticket-posthandshake-realism`**, **`flow-shape-padding`**.
- **[P3·XL] `reality-reflect` / `reality-handshake-relay`, `ech-and-custom-client-moonshot`,
  `shadowtls-utls-moonshot`, `internal-desync-engine` (in-process raw-socket/eBPF desync, drop the
  external nfqws dep).** *Note on REALITY*: full per-connection live relay is **largely infeasible for
  the stock Telegram client** (it has no client-side REALITY logic and requires HMAC-in-ServerHello.random),
  and active diff-probers can't reach the success path anyway (no secret → always masked to the real
  backend). The real, achievable win is **template harvest+replay** (rung 2) + **echo client params**
  (rung 1). Keep reflection as a **gated, opt-in** mode and a research track, not a 1.0 blocker.

### WS3 — Measured undetectability (turn the marketing claim into a CI signal) · CRITICAL

- **[P0·C·M] `dpi-validation-ci` / `dpi-ja4s-validation` / `ja3s-ja4s-ci` — DPI-detectability gate.**
  *What*: a CI job that drives a **valid authenticated** FakeTLS ClientHello (unauth probes get
  masked, so they never reach the FakeTLS responder), captures the ServerHello, and asserts: JA4S
  **and** the fields JA4S misses (**key_share group**, ServerHello record length, encrypted **cert-flight
  record count/sizes**, extension order, CCS placement) match a **pinned offline golden vector** of the
  real `tls_domain`; that two connections differ where a real server differs (random/keyshare/cert
  ciphertext) and match where it's constant (cipher/extensions); that the ServerHello contains **no
  GREASE** (servers must not); and that the ClientHello is actually MSS-fragmented. *Why*: this test
  will (correctly) **fail first** and force rung-1/rung-2 evasion — that exposure is the point. No
  competitor ships this. *Risk*: ja4 tooling is an external dep; pin an offline golden to avoid egress
  flakiness.
- **[P0·H·M] `dpi-mask-probe-byteidentity` — masking is byte-identical to the backend in BOTH
  directions.** *What*: upgrade the mask scenarios (`run.py:927/951`, currently
  `received.startswith(payload)` C2S-only) to assert the prober's exact C2S bytes reach the backend AND
  the exact S2C bytes reach the client, with **no proxy-injected byte, no premature RST, no timing
  tell** a real backend wouldn't emit — vs a real nginx capture, including a recorded GFW/TSPU probe
  sequence. *Why*: masking exists so a prober sees *only* a real backend; one injected/dropped byte
  unmasks the node and is invisible today.
- **[P3·H·L] `geo-reachability-monitoring` — real-world block-rate (the only true evasion metric).**
  Out-of-band reachability loop attempting full FakeTLS handshakes to **canary** endpoints from RU/IR/CN-
  adjacent vantage points (OONI integration / opt-in community telemetry), per-region success/block
  rate over time, dashboard + alerting. Lab JA4S equality is necessary-not-sufficient; measured
  block-rate is ground truth. Use **throwaway** canary domains so probing doesn't burn production fronts.

### WS4 — Test rigor (unit + e2e + fuzz + load + integrity) · CRITICAL

- **[P0·C·M] `e2e-bidirectional-integrity` — cryptographic data-integrity both directions.** *What*:
  port the client obf/AES-CTR keystream (+ ee FakeTLS framing) into `test/e2e/run.py`; the fake DC
  **decrypts** C2S and asserts byte-match to the client plaintext; the DC sends a known pattern S2C
  and the client decrypts the proxy output and asserts byte-exactness. Cover intermediate/abridged/
  secure tags + a >256KB payload (exercise DRS). Replace the `tunnel_bytes > 0` asserts. *Why*: the
  proxy's core job; today a corruption in AES-CTR/DRS/MP framing passes CI. *Helper*:
  `src/e2e_obf_handshake_gen.zig` already encodes the layout.
- **[P0·C·M] `test-eventloop-chunk-boundary-harness` — deterministic fragmentation harness.** *What*:
  a Zig-native harness driving the per-connection state machine over a **mock fd**, feeding adversarial
  TCP segmentation (1-byte-at-a-time, TLS records split across reads, obf handshake split mid-key,
  interleaved C2S/S2C, WouldBlock storms, EOF mid-frame, short writes) and asserting byte-exact
  reassembly + no panic for **every** split offset. *Why*: the single-threaded relay's hardest bugs
  are framing/reassembly under arbitrary segmentation — which byte-counting socket e2e **and**
  single-buffer fuzzing both miss. Needs a thin reader-interface seam (some relay code reads fds
  directly).
- **[P0·C·M] `fuzz-targets-core` — coverage-guided fuzzing of wire parsers.** *What*: real
  `std.testing.fuzz` targets for the variable-length parsers (priority): **`tls.extractSni`** +
  **`tls.validateTlsHandshake`** (`tls.zig:374,42`), **`middle_proxy_frames.tryReadFrame`**
  (needs an in-memory buffer shim — it reads an fd), **`socks5.parse*`** / **`http_connect.parseResponse`**,
  **`config` TOML parser**. (`obfuscation.fromHandshake` is fixed-length crypto-derivation → lowest
  ROI.) `testOne` asserts no panic/OOB + invariants (`consumed ≤ len`). Replace the fixed-seed PRNG
  loops. *Risk*: Zig 0.16 `--fuzz` is young (open self-hosted backend crash) → make an **AFL++** kit
  the actual gate, run against a **ReleaseSafe** build, keep a checked-in corpus + regression seeds;
  native `--fuzz` interactive-only. **OSS-Fuzz is not viable** (no Zig integration) — post-1.0
  aspirational at best.
- **[P0·C·M] `mp-golden-vectors` — MiddleProxy known-answer vectors + full encrypted media e2e.**
  *What*: generate vectors from **`alexbers/mtprotoproxy`** for `getAesKeyAndIv` (IPv4/IPv6/v4-mapped),
  full `RPC_PROXY_REQ` encapsulation (incl. ad_tag + QuickAck for abridged/intermediate/secure), and
  `RPC_PROXY_ANS`/`RPC_SIMPLE_ACK`/`RPC_CLOSE_EXT` decapsulation; commit as Zig tests against
  `middleproxy.zig`. Extend `run.py` with a **FakeMiddleProxy** that completes the real nonce+handshake,
  derives the same CBC keys, and round-trips encrypted RPC frames. *Why*: the media/MP path is the
  least-tested, highest-blast-radius code (today e2e answers the plain nonce then drops). **Include
  per-transport quick-ack S2C vectors** — they would have caught the abridged byte-order bug (WS7).
- **[P0·H·M] `e2e-client-compat-matrix` / `client-compat-e2e-matrix` — real-client compatibility.**
  *What*: a corpus of **real captured ClientHellos** (tdesktop/Android/iOS/TDLib/Web, incl. GREASE and
  the post-PR#1949 ECH ext `0xfe0d` + 32-byte key share), HMAC-patched, replayed through the proxy;
  assert handshake completes + ServerHello emitted; add abridged/secure + IPv6 client cases; replay the
  documented quirks from `.agent/skills/client-behavior/SKILL.md` (fragmented inner handshake across
  records w/ delays, prewarmed idle first-byte, parallel racing w/ cancellation). *Why*: this is the
  **direct compatibility proof for the live threat** — the proxy must keep accepting clients as their
  ClientHello evolves (verify it's extension-agnostic: validates HMAC-over-bytes + session_id, ignores
  specific exts). Arguably **critical**, not just high.
- **[P1·H·M] `soak-leak-gate`** (RSS growth + fd baseline over churn/idle), **`e2e-middleproxy-success`**
  (drive successful MP media to completion), **`e2e-flood-ratelimit-concurrency`** (behavioral),
  **`e2e-releasesafe-sanitizer-leak`** (run e2e+load against ReleaseSafe under leak/UB detection),
  **`dpi-flow-shape-stats`**. **[P1·M·S] `binary-size-startup-rss-gate`** (regression-gate the marketed
  177KB / <10ms / <1MB numbers). **[P1·M·M] `coverage-measure-and-release-gate`** (kcov + bind suites).
- **[P2·M·M] `e2e-graceful-shutdown-and-tunnel-failover`, `real-client-conformance-e2e`,
  `differential-conformance-oracle`** (validate parsers vs a reference impl).
  **[P2·M·L] `mutation-testing-suite-efficacy`** (prove the suite catches bugs).
- **CI must actually gate on these**: e2e is Linux-only and currently runs but several suites aren't
  PR-blocking — make integrity + golden-vectors + DPI-validation + load PR or merge gates.

### WS5 — Security & supply chain (a tool nation-states attack) · CRITICAL

- **[P0·C·M] `safety-on-wire-parsers` — ReleaseSafe data plane.** *What*: ship `mtproto-proxy` built
  **ReleaseSafe** (keep `mtbuddy` ReleaseFast). `@setRuntimeSafety(true)` does **not** propagate into
  callees (most parse logic is in `extractSni`/frame decoders) so the per-scope route is a leaky
  stopgap — build the whole data-plane binary ReleaseSafe. Also note the data plane runs on
  `std.heap.page_allocator` (no allocator safety). Publish the RSS/size/throughput delta; offer a
  "hardened" artifact. *Why*: today one off-by-one in the FakeTLS/obf/MP parser is exploitable UB on
  the most-exposed process; ReleaseSafe turns it into a safe panic. Pairs with fuzzing.
- **[P0·C·M] `verify-thirdparty-install-supplychain` — pin & verify ALL third-party install
  artifacts.** *What*: three install paths execute **unverified code as root**: (1)
  `dashboard.zig:104-120` downloads **`uv`** with no checksum → apply the per-arch pinned-SHA pattern
  already used for the Zig tarball; (2) `dashboard.zig:177-184` runs `uv pip install fastapi …`
  **unpinned** → a checked-in **hash-pinned `requirements.txt`** via `uv pip install --require-hashes`;
  (3) `nfqws.zig:144` does `git clone --depth 1 …/zapret.git` at **HEAD** then builds+runs as root with
  NET_ADMIN → pin a reviewed commit SHA (ideally vendor/ship a prebuilt+signed nfqws). *Why*: these are
  worse than the signing key — they require compromising only an *upstream*, not the maintainer.
- **[P0·C·M] `harden-signing-slsa` — offline signing + SLSA provenance + revocation.** *What*: stop
  using an **unencrypted minisign secret as a hot CI secret** (`release-please.yml`). Either Sigstore
  keyless (signature + in-toto provenance to Rekor) or keep minisign on a dedicated **offline/hardware**
  signer; add `actions/attest-build-provenance` (GA) to release + docker workflows; document a pubkey
  **rotation/revocation** channel (the pinned key in `build.zig:6` has none). *Correction*: there is
  **no auto-update** — `update.zig` is manual/root/interactive and already verifies sig+sha256 against
  the embedded key; keep minisign as the user-facing verify path and **layer** provenance on top.
- **[P0·H·S] `systemd-seccomp-hardening` — exemplary `systemd-analyze security` score.** *What*: add
  to all four identical unit templates (`deploy/…`, `release.zig:236-249`, `tunnel.zig:578-586`,
  dashboard) `SystemCallFilter=@system-service ~@privileged ~@resources …`,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` (SO_MARK is setsockopt, not netlink; nfqueue lives
  in the separate nfqws process), `MemoryDenyWriteExecute=yes`, `RestrictNamespaces`, `LockPersonality`,
  `ProtectProc=invisible`, `ProcSubset=pid`, `PrivateDevices`, `UMask=0077`, etc. CI/installer asserts a
  target score. *Why*: caps any parser-RCE blast radius to a tiny syscall set. Validate across
  direct/tunnel/socks/http egress before shipping.
- **[P0·H·M] `fuzz-pipeline`** (the continuous side of `fuzz-targets-core`) — time-boxed CI fuzz vs the
  ReleaseSafe build + checked-in corpus; crashes → permanent regression tests.
- **[P1·H·M] `container-nonroot-distroless`** static **musl** binary, distroless/scratch,
  `USER 65532`, drop caps, read-only, no-new-privileges + seccomp profile, **cosign-signed image +
  syft SBOM**. *Corrections*: do **not** blanket-drop `curl` (socks5/http egress shells to it,
  `http_fetch.zig:149`) or ca-certs (std.http HTTPS fetch needs them; distroless/static bundles them);
  the entrypoint secret-gen uses `od/tr/head` absent in distroless → move secret-gen **into the
  binary**. Effort realistically **M**.
- **[P1·H·M] `in-process-sandbox-privdrop`** self-contained **seccomp-bpf + Landlock** + privilege drop
  *inside* the proxy (parity for Docker-run-as-root / manual runs that get no systemd hardening).
  **[P1·M·S] `binary-exploit-mitigations`** PIE/ASLR, stack protector, full RELRO (verify in CI).
  **[P1·M·S] `secrets-in-memory`** mlock key material out of swap/core dumps, wipe on exit.
  **[P1·M·S] `ci-egress-harden-runner`** Harden-Runner egress control on the signing job.
  **[P1·M·M] `reproducible-build-verify`** CI-verified bit-for-bit reproducible build + SBOM + invite an
  independent rebuilder. **[P1·M·S] `dep-cadence-scorecard`** Dependabot/Renovate + OpenSSF Scorecard +
  scheduled base-image rebuild. **[P1·M·S] `threat-model-supplychain`** add supply-chain/RCE adversaries
  + key-compromise runbook to THREAT_MODEL.
- **[P3·H·XL] `binary-transparency-moonshot`** binary transparency + independent rebuilder network.

### WS6 — Reliability & observability (run a fleet, see a block) · HIGH

- **[P0·C·M] `evasion-block-telemetry` + [P0·H·S] `close-reason-counter` — the core circumvention
  signal.** *What*: replace the **free-text `reason` string** passed to `closeSlot` at **72 sites**
  (`proxy.zig:1496-2548`, only logged today) with a bounded `CloseReason` enum + an atomic array →
  `mtproto_connections_closed_total{reason="tls_validation_failed|sni_mismatch|replay_detected|
  handshake_budget|flood_guard|upstream_rst|client_rst|handshake_timeout|…"}`. This single change
  delivers the whole RED "errors" dimension **and** subsumes most evasion counters (the reject/replay/
  sni reasons **are** the block signals). Add a rolling **handshake-success-rate** gauge + an advisory
  `mtproto_block_suspected` (success-rate collapse / early-RST spike vs trailing baseline). *Why*: the
  product exists to evade, yet nothing tells an operator a censor started blocking. Feeds
  `block-detection-feedback` (WS2) and `ipv6hop-productize` (WS9).
- **[P0·H·M] `metrics-red-histograms-perdc`** zero-alloc fixed-bucket histograms
  (`mtproto_handshake_duration_seconds`, `…upstream_connect_duration_seconds`) + per-DC labels
  (`{dc}` is already per-slot, bounded 1-5+203). (Defer OpenMetrics exemplars to post-1.0.)
- **[P0·H·M] `dashboard-scrape-metrics`** replace the dashboard's `journalctl`-regex stats
  (`server.py:313-385`, brittle/lossy) with an HTTP scrape of `/metrics`; enable `[metrics]` on
  localhost by default. **[P0·H·S] `health-readiness-endpoints`** `/healthz` (loop ticked within N s
  via a main-loop heartbeat) + `/readyz` (listen bound AND not draining — **do NOT** gate on
  middleproxy: it runs on bundled defaults and may never refresh on a censored host).
  **[P0·H·S] `systemd-notify-watchdog`** `Type=notify` + `sd_notify(READY=1)` after bind + `WATCHDOG=1`
  from the loop + `WatchdogSec=30` (mind the **blocking DNS `getAddressList`** in SIGHUP mask reload,
  `proxy.zig:2138` — the one place the loop can stall seconds).
- **[P0·C·M] `sighup-reload-users` — hot user/secret rotation (zero-downtime).** *What*:
  `reloadConfigFromDisk` currently checks `next.users.count()` but **never applies users**
  (`proxy.zig:1991`). Rebuild `user_secrets`/`user_metrics`/`direct_users`, preserving counters for
  surviving names. **Hazard (must handle)**: each `ConnectionSlot` caches a raw `*UserMetrics` +
  counter-field pointers for its whole lifetime (`proxy.zig:443,3510-3564`), and the detached metrics
  thread iterates `user_metrics` concurrently (`monitoring.zig:251`) → freeing the old slice is a
  **use-after-free + cross-thread race**. Correct design: keep removed/renamed metric structs alive
  until their connections drain (generation list / refcount, freed in `deinit`) + guard the swap
  (atomic pointer + deferred free). Effort **L**.
- **[P1·H·M] `upstream-circuit-breaker`** shared DC-endpoint health table / breaker.
  **[P1·H·M] `egress-tunnel-health-metrics`** tunnel/socks5/http liveness.
  **[P1·M·S] `middleproxy-staleness-metric`**, **`config-check-mode`** (`mtproto-proxy --check`),
  **`crash-telemetry-coredump-hygiene`**, **`log-rate-limit-hot-warnings`**.
  **[P1·M·M] `structured-json-logging`**, **`alerting-hooks`**.
  **[P1·H·L] `zero-downtime-upgrade`** SO_REUSEPORT listener handoff (pairs with WS1).
- **[P3] `synthetic-probe-canary`** (proxies as sensors), **`fleet-control-plane`** (WS9).

### WS7 — Protocol correctness, MiddleProxy, media, IPv6 · HIGH

- **[P1·H·S] `dc203-direct-fallback-fix`** — media silently fails on MP handshake failure (no working
  direct fallback for DC203). Verify against `proxy.zig:724-729` media routing + the MP fallback path;
  fix + cover with `mp-golden-vectors` + an e2e media scenario. *(Correctness bug surfaced by audit.)*
- **[P1·M·S] `mp-quickack-abridged-reversal`** — fix abridged quick-ack (`RPC_SIMPLE_ACK`) byte order
  in MP S2C (`middleproxy.zig:240-263,449`). The per-transport quick-ack golden vectors (WS4) are the
  regression guard. **[P1·L·S] `mp-conn-id-validate-s2c`** validate `conn_id` on `RPC_PROXY_ANS`/
  `RPC_SIMPLE_ACK`. **[P1·H·M] `mp-encap-fuzz`** coverage-guided + differential fuzz for
  `encapsulateC2S`/`decapsulateS2C`.
- **[P1·M·M] `ipv6-dc-egress`** implement IPv6 DC egress (`tg_datacenters_v6`) + a `prefer_ip` policy /
  happy-eyeballs, for v6-capable/-only hosts. **[P1·M·S] `quickack-s2c-verify`**.
- **[P1·H·L] `mp-handshake-budget`** shrink/parallelize the per-connection MP RPC handshake to fit
  client timeout budgets at scale. **[P2·M·S] `getproxyconfig-cache-and-default`** persist last-good
  getProxyConfig/secret + honor the `default` DC directive + promo lines.
  **[P2·L·S] `dd-decision-timeout-tune`** re-tune the 4s dd decision vs measured client behavior.
- **[P3·H·XL] `mp-mux-pool`** multiplex clients over a per-DC MP connection pool via `conn_id` (+
  `RPC_PING/PONG` keepalive + dead-conn reaping).

### WS8 — Architecture for a 1.0 "piece of art" · HIGH

- **[P0·C·L] `transport-strategy-interface` — the extensibility seam (prerequisite for evasion
  profiles).** *What*: a `Transport`/`EvasionStrategy` abstraction in `src/proxy/transport/` with an
  explicit contract (`sniff(first_bytes)->?match`, `buildClientResponse`, `wrapC2S`, `unwrapS2C`,
  per-transport state). Prefer a **comptime registry + tagged-union dispatch** (zero-cost on the
  single-thread hot path) over runtime fn-pointers — the win is an **explicit documented contract**,
  not indirection. Replace the `ClientTransport` enum (`proxy.zig:183`) + the hardcoded branches in
  `readTlsHeader` (`2399-2440`) and the relay trio (`2962-3129`) and the implicit `slot: anytype` seam
  (`relay_steps.zig:14-19`). *Sequencing (high destabilization risk on a working proxy)*: introduce the
  seam and **port the two existing transports behind it first** (behavior-preserving, e2e-covered)
  **before** adding any new strategy.
- **[P0·H·M] `config-schema-validate`** replace the 246-line if-else over 44 keys gated by 10
  `in_*_section` booleans (`config.zig:401-637`, mixed failure modes — hard error at 453 vs silent
  port→443 at 494) with a **comptime field-descriptor table** + a single `validate()` (aggregated,
  line-numbered diagnostics) + a `mtproto-proxy --check-config` dry-run. Snapshot-test parse output vs
  deployed configs; preserve telemt-compat aliases.
- **[P0·H·S] `stability-policy-architecture-md`** promote `.agent/skills/architecture/SKILL.md` to an
  in-repo **ARCHITECTURE.md** (module map, hot-path dataflow, multi-core model, transport interface) +
  **COMPATIBILITY.md** enumerating exactly which surfaces SemVer covers for 1.0 (config keys, tg:// ee/dd
  link format, `/metrics` names, CLI flags, mtbuddy behaviors) and what "breaking" means. *1.0 literally
  means these are stable.*
- **[P0·H·S] `pin-zig-toolchain`** add `build.zig.zon` (name/version + **`minimum_zig_version`**) +
  `.zig-version`; today nothing pins the compiler except `Dockerfile ARG ZIG_VERSION` while the code
  rides **unstable std APIs** (`std.Io.Threaded.global_single_threaded`, the `CompatRwLock` shim exists
  *because* of std churn). A reproducible 1.0 must guarantee its compiler.
- **[P1·H·L] `split-connectionslot-pathstate`** collapse `ConnectionSlot`'s mutually-exclusive state
  into a tagged-union `PathState`. **[P1·M·M] `explicit-error-sets`** named error sets at wire/parser/
  relay boundaries; audit the many silent error swallows. **[P1·M·M] `centralize-connection-fsm`**.
  **[P1·M·S] `config-version-migration`** (`config_version` + migration), **`auto-test-aggregation`**
  (auto-discover unit-test targets), **`architectural-fitness-tests`** (no upward imports).
  **[P2·M·M] `comptime-feature-flags`**, **`inject-allocators`**.
- *Decompose `proxy.zig` (~3700 lines)* incrementally **behind** the transport seam + tests as
  guardrails (accept/relay/timers/state-machine/mp-glue) — high payoff, but **do not destabilize the
  working proxy pre-1.0**; sequence after the seam + e2e integrity land.

### WS9 — Fleet platform ("масштабирование обхода") · HIGH

> Turn one box into a scalable circumvention platform. Since MTProto has **no Outline-style dynamic
> key**, the only client-transparent rotation channel is **DNS** + a **shared link identity**.

- **[P0·C·M] `fleet-identity`** first-class "fleet member" provisioning: `mtbuddy fleet init` mints one
  shared `{secret, tls_domain, public-fqdn}` manifest; `mtbuddy fleet join <manifest>` provisions a
  node so **N backends emit one identical `tg://` link**. *Refinement*: the building blocks largely
  exist (`install.zig` `--secret`/`--domain`/`--config`; `links.zig` `--server`/`--domain`); the real
  missing pieces are a **`--public-ip` install flag**, the init/join manifest ergonomics, and docs →
  reframe as "productize + document," effort **S/M**. The shared `ee` link requires a shared domain
  (the secret embeds tls_domain hex).
- **[P0·C·M] `dns-fronting`** generalize the Cloudflare-only, hardcoded `updateDnsA`
  (`ipv6hop.zig:261-338`, name hardcoded `proxy.sleep3r.ru`) into `mtbuddy dns` with pluggable
  providers (Cloudflare token, generic RFC2136/`nsupdate`, webhook/exec hook), **health-checked
  round-robin A/AAAA**, and `--drain <ip>` to atomically pull a blocked node from DNS. The link's
  `server=` points at the fleet FQDN → rotation is invisible to clients. Recommend low TTL; provider-
  agnostic because Cloudflare itself is throttled in RU/IR.
- **[P1·H·M] `ipv6hop-productize`** turn ipv6-hop from demo-grade into a real installed daemon: remove
  personal hardcodes (`ipv6hop.zig:61-63,267`: sleep3r.ru, a specific /64, eth0), auto-detect the v6
  interface, replace the foreground `while(true)` + journalctl-grep with a systemd service+timer the
  installer actually installs (today `install.zig:612` just prints "configure manually"), and **feed it
  real ban signals from `/metrics`** (the new evasion/close-reason counters) instead of log scraping;
  wire to `mtbuddy dns`. *(Needs a routed /64 — `should` rather than hard `must` for universality.)*
- **[P1·H·M] `bluegreen-domain`** blue/green `tls_domain` rotation primitive using the existing SIGHUP
  hot-reload. **[P1·H·S] `fleet-metrics`** fleet-labeled metrics + Prometheus federation + a fleet
  Grafana board. **[P1·H·L] `admin-api`** a tiny **token-auth** control API embedded in the proxy for
  orchestration (users/secrets/profile/drain) — *verifier flagged as over-reach; keep minimal and
  optional*. **[P1·H·M] `reuseport-template-unit`** systemd template unit + SO_REUSEPORT as the
  cheapest multi-instance-per-box scale path (interim before in-process workers).
  **[P1·H·S] `declarative-config-push`** validated declarative config/user push + secret-rotation
  runbook. **[P1·M·M] `distro-portability`** apt/dnf/apk installer.
- **[P1·H·L] `iac-modules`** official Terraform module + Ansible role + cloud-init wrapping
  `bootstrap.sh`. **[P1·M·S] `lb-readiness-signal`**, **`identity-drift-metric`**.
  **[P2·M·M] `canary-rollout`** staged fleet rollout w/ reachability gate + auto-rollback.
  **[P2·M·S] `lightweight-monitor`** agentless metrics-only mode (drop the per-box Python dashboard at
  fleet scale). **[P2·M·S] `ip-blocklist-allowlist`** (FireHOL-style pre-handshake drop),
  **`per-user-quotas-analytics`** (per-user accounting, quotas, secret TTL/rotation),
  **`runtime-user-hot-reload`**, **`burnable-public-link-defense`** (per-user short-TTL secrets vs
  link-harvesting), **`region-attribution-lite`** (embedded IP→ASN/country for per-region block signals).
- **[P3] `blocked-rotate-loop`** (fleet coordinator: closed-loop blocked-detection → automated
  rotation/drain), **`client-subscription`** (operator-run rotating link dispenser — MTProto's
  dynamic-key analog), **`fleet-control-plane`**, **`anycast-bgp-path`** (zero-TTL-lag rotation).

---

## 3. Phased roadmap (sequencing respects dependencies)

> Each phase is independently shippable; phases overlap where deps allow. Every phase lands with its
> tests/gates so `main` is always releasable.

**Phase 1 — Foundation: safety + correctness + measurement (unblocks trust in everything else)**
`safety-on-wire-parsers` → `fuzz-targets-core`/`fuzz-pipeline` · `e2e-bidirectional-integrity` +
`test-eventloop-chunk-boundary-harness` · `mp-golden-vectors` (+ DC203 + abridged-quickack fixes) ·
`close-reason-counter` + `evasion-block-telemetry` · `pin-zig-toolchain` · `config-schema-validate` +
`--check-config` · `stability-policy-architecture-md`. *Outcome: a hardened, observable, well-tested
single-core proxy with a frozen public contract.*

**Phase 2 — Scale per host**
`transport-strategy-interface` (port existing transports behind it) → `reuseport-workers` +
`shared-state-multicore` (land together) · `aes-ctr-wide` · `load-throughput-relay-ci` ·
`systemd-notify-watchdog` + `health-readiness-endpoints` + `metrics-red-histograms-perdc` +
`dashboard-scrape-metrics` · `sighup-reload-users`. *Outcome: N-core, load-gated, hot-reloadable proxy.*

**Phase 3 — Evasion authenticity + measured undetectability (the moat)**
`serverhello-echo-client-params` + `mask-real-backend-default` (wizard fix) + `mss-clienthello-frag-tuning`
→ `dpi-validation-ci` + `dpi-mask-probe-byteidentity` · `probe-real-template`/template library ·
`evasion-profiles` (on the transport seam) + `traffic-shape-modeling` + `response-timing-parity` ·
`e2e-client-compat-matrix`. *Outcome: ServerHello matches the fronted domain, probes hit a real
backend, undetectability is CI-gated, per-region profiles exist.*

**Phase 4 — Fleet platform (scale the circumvention)**
`fleet-identity` + `dns-fronting` → `ipv6hop-productize` + `bluegreen-domain` + `block-detection-feedback`
· `fleet-metrics` + federation + Grafana board · `reuseport-template-unit` + `declarative-config-push`
· `iac-modules`. *Outcome: deploy N nodes behind one link, rotate ahead of blocks (manual → signal-driven).*

**Phase 5 — Harden the 1.0 release & polish**
`harden-signing-slsa` + `verify-thirdparty-install-supplychain` + `systemd-seccomp-hardening` +
`container-nonroot-distroless` + `in-process-sandbox-privdrop` + `reproducible-build-verify` ·
architecture polish (`split-connectionslot-pathstate`, decompose `proxy.zig`) · `binary-size-startup-rss-gate`
· coverage gate · finalize THREAT_MODEL + COMPATIBILITY. **→ tag 1.0.0.**

**Post-1.0 moonshots** (the "art" ceiling): `reality-reflect`/`reality-handshake-relay` (gated),
`geo-reachability-monitoring`, `internal-desync-engine` (drop external nfqws), `iouring-backend`,
`mp-mux-pool`, `ech-and-custom-client` transport, `anycast-bgp-path`, `client-subscription` dispenser,
`binary-transparency`.

---

## 4. Top-10 highest-leverage items (if you do nothing else first)

1. **`serverhello-echo-client-params`** (P0·H·M) — kill the #1 passive distinguisher, cheap, no network.
2. **`mask-real-backend-default`** (P0·H·S) — stop the default that burns servers under active probing.
3. **`reuseport-workers` + `shared-state-multicore`** (P0·C·L) — 1 core → N cores.
4. **`aes-ctr-wide`** (P0·H·M) — 3–5× relay throughput, localized change.
5. **`dpi-validation-ci`** (P0·C·M) — turn "undetectable" into a regression-gated fact.
6. **`e2e-bidirectional-integrity` + `mp-golden-vectors`** (P0·C·M) — close the largest correctness blind spots.
7. **`safety-on-wire-parsers` + `fuzz-targets-core`** (P0·C·M) — stop shipping safety-off attacker-facing parsers.
8. **`close-reason-counter` + `evasion-block-telemetry`** (P0·H·S/M) — *see* a censor start blocking.
9. **`fleet-identity` + `dns-fronting`** (P0·C·M) — N nodes, one link, client-transparent rotation.
10. **`mss-clienthello-frag-tuning`** (P0·H·S) — the deployed counter to the April-2026 ClientHello signature.

---

## Appendix A — Full prioritized backlog (all 182 recommendations, deduped by theme)

The complete machine-readable backlog (every recommendation with what/why/effort/risk/evidence and the
verifier verdict) is preserved from the audit run. To regenerate or query it:
`workflow result wf_b8b6e05f-6ea` (24 agents, 11 domains × investigate+refine). Items above carry their
original IDs (e.g. `reuseport-workers`, `serverhello-echo-client-params`) for 1:1 traceability. Convergent
themes (independently raised by ≥3 agents → highest confidence): REALITY-style ServerHello authenticity,
SO_REUSEPORT multi-core, DPI-validation-in-CI, coverage-guided fuzzing, ReleaseSafe data plane,
bidirectional integrity e2e, evasion/block telemetry, evasion-profile registry, fleet identity + DNS rotation.

## Appendix B — Surfaced correctness bugs (verify + fix during Phase 1)
- **DC203 media direct-fallback** non-functional → non-Premium media silently fails when the MP handshake
  fails (`audit-protocol-correctness`; anchor `proxy.zig:724-729`).
- **Abridged quick-ack (`RPC_SIMPLE_ACK`) byte order** in MP S2C (`middleproxy.zig:240-263,449`).
- **SIGHUP user reload** is a no-op (`proxy.zig:1991`) — and the naive fix is a use-after-free (see WS6).
- **Many silent error swallows** at wire/parser boundaries (audit `explicit-error-sets`).

## Appendix C — Key research sources (full list in the audit run)
- TSPU AI/JA4 + 2026 blocking: tgvpn.io 2026 analysis; DrKLO/Telegram **PR #1949**; HRW "Disrupted,
  Throttled, and Blocked" (2025); zona.media RU censorship 2026; net4people #417 (ECH block).
- GFW fully-encrypted classifier: **gfw.report / USENIX'23**; Geneva.
- Obfuscated-proxy detection at scale: **USENIX'24 Xue et al.**; censoredplanet.
- Evasion gold standard: **XTLS/REALITY**; **9seconds/mtg** + teleproxy "doppelganger"; uTLS;
  FoxIO **JA4/JA4S**, Salesforce **JARM**.
- Scale references: official **MTProxy `--slaves`** (60k conns/core); Cloudflare "sad state of socket
  balancing" (SO_REUSEPORT); sing-box adapter/registry model.
- Supply chain / trust: SLSA build provenance; `actions/attest-build-provenance`; Sigstore/cosign; OSS-Fuzz
  (note: no Zig support — aspirational).

---
*This plan is intentionally opinionated about sequencing and risk: ship safety + correctness +
measurement first (so every later change is trustworthy and observable), then scale per host, then the
evasion moat, then the fleet platform, then harden and freeze for 1.0. The single thing that most makes
this "the best in the world" is the combination no competitor ships: an authentic, domain-matched
FakeTLS identity **proven undetectable in CI** and **measured in the field**, on a **multi-core**,
**fuzzed**, **ReleaseSafe** core, operated as a **rotating fleet** behind one link.*

---

## Implementation status — one-pass execution (2026-06)

This section tracks a focused execution pass that closed **everything realistically shippable in a
single pass without standing up new external systems** (no external monitoring stack, no fleet control
plane, no live-DPI lab). Branch: `feature/roadmap-1.0`. Every ✅ item builds clean
(`zig build test` + `x86_64-linux+aes` + `aarch64-linux`) and is committed (no Claude co-author).

### ✅ Done this pass (16+ commits)

> WS1 multi-core (`reuseport-workers` + `shared-state-multicore`) was added in a follow-up after a
> map-the-mechanics workflow + an adversarial concurrency-review workflow (which found and fixed 2 real
> races/accounting bugs before commit). See row 16 below.

| # | Item (roadmap ID) | What shipped | Commit |
|---|---|---|---|
| 1 | `pin-zig-toolchain` (WS8) | `build.zig.zon` (`minimum_zig_version=0.16.0`) + `.zig-version` | `6babb76` |
| 2 | `config-check-mode` (WS6/8) | `mtproto-proxy --check-config [path]` → exit 0/1 (nginx -t style) | `6babb76` |
| 3 | `serverhello-echo-client-params` (WS2) | ServerHello echoes the client's non-GREASE TLS1.3 cipher (kills the constant-`0x1301` passive tell) + `extractFirstTls13Cipher` + tests | `b981457` |
| 4 | `mask-real-backend-default` (WS2) | `mtbuddy setup-masking` no longer self-signs for an unowned domain — fronts the real `tls_domain:443` instead | `dc6f162` |
| 5 | `aes-ctr-wide` (WS1) | 8-wide AES-CTR on the relay hot path + cross-boundary byte-equivalence test (incl. counter wrap) | `b7a8b35` |
| 6 | `close-reason-counter` + `evasion-block-telemetry` (WS6) | bounded `CloseReason` + `mtproto_connection_close_reason_total{reason}` (the block signal) + classifier test | `b1a92d1` |
| 7 | `health-readiness-endpoints` (WS6) | `/healthz` + `/readyz` on the metrics server (loop heartbeat + drain flag; not gated on middleproxy) | `6e5af77` |
| 8 | `systemd-notify-watchdog` (WS6) | native dependency-free sd_notify; `Type=notify` + `WatchdogSec=30` on all proxy units + encoding test | `a474509`, `7ea731f` |
| 9 | `systemd-seccomp-hardening` (WS5) | proxy unit: `SystemCallFilter=@system-service`, `RestrictAddressFamilies`, `MemoryDenyWriteExecute`, `ProtectKernel*`, `ProtectProc`, … (3 unit copies); tunnel unit gets the device/netlink-safe subset | `a474509`, `7ea731f` |
| 10 | `verify-thirdparty-install-supplychain` (WS5) | `uv` pinned 0.11.19 + `.sha256` verify; Python deps pinned exact. **zapret is deliberately NOT frozen** — it's the DPI-bypass engine, so it clones the *latest release tag* (resolved at install, offline fallback) instead of raw HEAD, staying current with DPI evolution | `47da6f7`, `f6f97b1` |
| 11 | `mp-quickack-abridged-reversal` (WS7) | **confirmed bug fixed** vs reference: byte-reverse the abridged `RPC_SIMPLE_ACK` confirm; `relaySimpleAck` + golden test | `c91ac94` |
| 12 | `safety-on-wire-parsers` (WS5) | proxy data plane built **ReleaseSafe** by default (`-Ddataplane_safety`, default on); mtbuddy/bench unchanged | `5090f60` |
| 13 | `binary-exploit-mitigations` (WS5) | proxy built **PIE** (ASLR; verified `e_type=DYN`); full RELRO already default | `6fa730c` |
| 14 | `fuzz-targets-core` (WS4) | `std.testing.fuzz` (Smith) targets for TLS/socks5/http_connect parsers — deterministic in CI, coverage-guided under `--fuzz` | `7b64de6` |
| 15 | `stability-policy-architecture-md` (WS8) | `ARCHITECTURE.md` + `COMPATIBILITY.md` (SemVer-covered surfaces) + this checklist | `1fffb51` |
| 16 | `reuseport-workers` + `shared-state-multicore` (WS1) | **opt-in** `[server].workers` SO_REUSEPORT thread-per-worker model (default 1 = unchanged); replay cache + middle-proxy snapshot mutex-guarded (real `std.Io.Mutex`); SIGHUP reload refused under >1 worker; worker fd accounting; map + adversarial-review workflows (fixed a `tls_domain` use-after-free race + fd-accounting before commit) | `972f72f` (+ review fixes) |
| 17 | WS2 evasion (safe subset) | hermetic **DPI-validation structural test** (the local gate: cipher tracks ClientHello, no-GREASE, key_share group, record geometry, differ-where-random/constant-where-structural) + **configurable TCPMSS** (`--tcpmss <n>`, default 88). Runtime-rewriting rungs (probe/reality/transport/traffic, MLKEM key_share) deferred — need a DPI harness + Linux + real client to validate | `58b8d0b` |
| 18 | WS2 evasion (field-validated finding) | live testing (real RU client + server probes) showed the real Telegram client is modern-Chrome-shaped (offers X25519MLKEM768) and that **`tls_domain` selection — not ServerHello complexity — is the lever**: `wb.ru`/`mail.ru` do HelloRetryRequest→secp521r1 (our 3-record FakeTLS can't match → passive mismatch), while `rutube.ru`/`ozon.ru`/`vk.com`/`yandex.ru` do single-round x25519 (which our existing FakeTLS already matches, so no MLKEM resize needed). **But `tls_domain` is immutable once links ship** (the `ee` secret embeds it), so the realistic levers are: ClientHello telemetry (shipped), an **install-time domain-suitability probe/warning** (shipped), real-domain active-probe masking (`mask_port=443`), and documenting the immutable-link constraint (ARCHITECTURE/COMPATIBILITY/config) | `73fcd8b` |
| 19 | DNS resolver getent fallback (field bug) | live debugging found the proxy could resolve IP literals but **no hostnames** on the deployment: Zig's std resolver throws `ResolvConfParseFailed` on a `resolv.conf` with no trailing newline (SolusVM/VPS images), silently disabling all hostname masking. `getAddressList` now falls back to `getent` (NSS). With it, real-domain active-probe masking is **verified working** (fronting `rutube.ru` returns its genuine GlobalSign cert externally); the masking relay itself was never broken — earlier "hang" reports were a loopback test artifact (tunnel SO_MARK routing breaks loopback). Fronting an **HRR** domain like `wb.ru` yields an incomplete handshake, so a link locked to such a domain keeps local self-signed nginx as the least-bad mask | `03e53ea` |

### ⏸️ Investigated but deliberately NOT changed (with reason)

- **`dc203-direct-fallback-fix` (WS7)** — *investigated, real-but-narrow, not changed.* The MP direct
  fallback IS wired (`mpHandshakeFallbackToDirect` → `fallbackToDirect`) and populated for the common
  media path (`dc_idx<0` → `dc_abs` 1–5 → a real direct DC, which works). For the literal `dc_abs==203`
  case, `getDcAddressV4(203)` returns a *MiddleProxy* IP, so a direct-obfuscated fallback there can't
  work — but there is no genuine "direct DC203" endpoint, so the correct failure semantics need a live
  media repro. Not changed speculatively (high-blast-radius media router, not locally testable).

- **`e2e-bidirectional-integrity` (WS4)** — *deferred, not safely closeable this pass.* Requires
  decrypting the relayed stream in `test/e2e/run.py`, but Python's stdlib has **no AES** (CI may lack a
  crypto dependency) and the proxy is **Linux-only**, so no run.py change can be validated locally —
  modifying an un-runnable harness blind risks red CI. The Zig-side relay integrity is instead covered
  deterministically and locally-verified by the new **AES-CTR cross-boundary equivalence test** (#5)
  and the **quick-ack golden vector** (#11). The Python harness work (incl. the plaintext
  `dpi-mask-probe-byteidentity` mask-path check) needs a Linux e2e env — tracked under WS4.

### ❌ Not attempted this pass — needs new systems / scale / live validation (per the brief)

Explicitly out of scope for a single no-new-systems pass; these remain the headline roadmap work:
- **WS1 multi-core**: `reuseport-workers` + `shared-state-multicore` are now **done** (row 16) — but
  still need **real-load validation on Linux** (throughput scaling, even distribution, graceful
  shutdown) before `workers>1` becomes a default. The companion `load-throughput-relay-ci` gate (WS4)
  is the missing piece to validate it automatically.
- **WS2 evasion (deeper rungs)** — the *safe subset is done* (row 17): a hermetic **DPI-validation
  structural test** (cipher-tracks-ClientHello, no-GREASE, key_share group, record geometry,
  differ-where-random/constant-where-structural — the local gate that makes future evasion changes
  safe to iterate) and a **configurable TCPMSS** clamp. **Deferred** (can't be validated blind — they
  change the moat and need a JA4S/record-geometry harness + a Linux host + a real Telegram client to
  prove they *improve* detectability and don't break compat): `probe-real-template` / `reality-reflect`
  (runtime outbound TLS scout / post-1.0 moonshot), `evasion-profiles` + `transport-strategy-interface`
  (large hot-path refactor), `traffic-shape-modeling`, and the `key_share` MLKEM echo (resizes the
  ServerHello → needs the dynamic-template rewrite + real-client validation; the new structural test
  now guards that attempt).
- **WS3 measured undetectability**: `dpi-validation-ci` (external JA4S/tshark tooling) and
  `geo-reachability-monitoring` (external vantage points).
- **WS4**: `load-throughput-relay-ci`, `mp-golden-vectors` (full FakeMiddleProxy + reference oracle),
  `client-compat-e2e-matrix`.
- **WS5 (stronger follow-ups)**: hardcoded in-repo per-arch `uv` SHA (Dockerfile-style),
  `--require-hashes` Python lockfile, offline/SLSA signing, distroless image.
- **WS6**: RED histograms + per-DC labels, `sighup-reload-users` (the safe fix needs the
  use-after-free-avoiding refcount design), `dashboard-scrape-metrics`.
- **WS9 fleet platform**: `fleet-identity`, `dns-fronting`, `ipv6hop-productize`, etc.

### ⚠️ Needs validation before relying on (un-testable locally)

- **systemd `Type=notify` + watchdog** (#8) and the **seccomp/RestrictAddressFamilies** hardening (#9)
  follow the spec and the sd_notify address encoding is unit-tested, but the systemd handshake and the
  egress-mode interaction (direct/tunnel/socks5/http) can only be confirmed on a **real systemd host**
  / the installer-e2e CI job. Conservative choices were made (`@system-service` keeps `setrlimit`;
  `AF_NETLINK` kept for glibc `getaddrinfo`; tunnel unit omits the syscall/family filters). Run
  `systemd-analyze security mtproto-proxy.service` + the installer-e2e before tightening further.
- **PIE / ReleaseSafe** (#12, #13) change the release artifact; the marketed footprint/throughput
  numbers were measured at ReleaseFast — re-measure RSS/size/throughput on the release build.
