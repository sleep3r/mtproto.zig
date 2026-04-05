---
name: MTProto Proxy Architecture
description: Core architecture, DPI evasion techniques, client behavior matrix, and networking rules for the Zig MTProto proxy.
---

# MTProto Proxy Architecture & Core Concepts

A production-grade Telegram MTProto proxy implemented in Zig, featuring TLS-fronted obfuscated connections. Runs on a Linux VPS, cross-compiled from Mac.

## Tech Stack
- **Language**: Zig 0.15.2
- **Networking**: `std.net` for TCP, `std.posix` for `poll()`-based I/O
- **Cryptography**: `std.crypto` for SHA256, HMAC, AES-256-CTR
- **Build System**: Zig Build System (`build.zig`)
- **Deployment**: `systemd` service on Linux VPS, cross-compiled from macOS

## Architecture

```text
src/
├── main.zig              # Entry point, banner, public IP detection, custom logger
├── bench.zig             # Performance microbench + multithreaded soak runner
├── config.zig            # TOML config parser
├── proxy/
│   └── proxy.zig         # Core: accept loop, client handler, relay, DRS, Split-TLS desync
├── protocol/             # Handshake & header definitions
│   ├── constants.zig     # Handshake magics, DC addresses, buffer sizes
│   ├── middleproxy.zig   # MiddleProxy (mtprotoproxy.py) auth & encapsulation
│   ├── obfuscation.zig   # Handshake tag parsing and AES-CTR key derivation
│   └── tls.zig           # ClientHello/ServerHello verification and anti-DPI
├── crypto/               # AES-CTR and SHA256/HMAC primitives
deploy/
├── install.sh            # One-line VPS bootstrap & updater (Zig + build + systemd + TCPMSS + IPv6)
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

### Threading & Memory Model
- **One thread per connection**: Spawned from the accept loop.
- **Atomic Slot Reservation**: The `accept` loop reserves a slot (`fetchAdd(1)`) **before** spawning a thread. If `max_connections` is hit, it immediately rejects and decrements the counter. This prevents burst overshoots caused by asynchronous thread startup.
- **Configurable Thread Stack**: Tunable via `[server].thread_stack_kb` (default 256KB).
- **Heap-over-Stack Buffers**: Instead of large stack-allocated arrays, the proxy uses `ProxyState.allocator` to dynamically allocate buffers (TLS ciphertext, TLS plaintext, pipe buffers) only when a connection becomes active. This allows high concurrency (10,000+ threads) on small VPS instances without risking Stack Overflow.
- Non-blocking sockets + `poll()` in relay loop.
- No global mutable state — `ProxyState` passed by reference.
- Proxy binds on `[::]` (IPv6 wildcard) — automatically accepts both IPv4 and IPv6 connections.

### Capacity Estimation & RAM Detection
At startup, `src/main.zig` detects the total Host RAM via `/proc/meminfo` (Linux).
- **Safe Capacity Formula**:
  ```text
  budget_bytes = (Host_RAM * 0.70) - max(256MB, Host_RAM * 0.10)
  tls_working  = max_tls_ciphertext_size * 3 + (max_tls_plaintext_size + 5) * 2
  per_conn     = thread_stack + tls_working + middleproxy_buffers(if ME) + 64KB_overhead
  safe_connections = budget_bytes / per_conn
  ```
- **Banner Warning**: If `max_connections` exceeds the `safe_connections` estimate, the proxy prints a yellow warning on startup.

## Telegram Client Behavior Matrix (WIP)

We currently keep this section strict: no behavior claims without either (a) reproducible captures/logs, or (b) direct links to client source code with an explicit version/tag/commit.

### iOS (Telegram iOS)
- **Field evidence (our captures/logs)**: iOS pre-warms multiple idle sockets, can fragment the 64-byte obfuscation handshake across TLS records, and may delay first payload after `ServerHello`.
- **Version-pinned source snapshot**: `TelegramMessenger/Telegram-iOS` tag `build-26855` (target commit `b16d9acdffa9b3f88db68e26b77a3713e87a92e3`).
- In this source snapshot, TCP connect timeout is `12s`. Response watchdog is reset on partial reads. Transport-level connection watchdog is `20s`. 
- Reconnect backoff is stepped (`1s` for early retries, then `4s`, then `8s`).

**Proxy-side handling used for iOS compatibility:**
- Two-stage timeout model: `poll()` idle phase (5 min), then active `SO_RCVTIMEO=10s` after payload starts.
- Handshake assembly loop collects full 64 bytes before switching relay into normal mode.
- Handshake-stage receive timeout widened to 60s before tightening to normal relay timeout.

### Android (Telegram Android)
- **Version-pinned source snapshot**: `DrKLO/Telegram` tag `release-11.4.2-5469`.
- Socket setup uses `TCP_NODELAY`, `O_NONBLOCK`, edge-triggered epoll.
- Connection type split is explicit (`ConnectionTypeGeneric/Download/Upload/Push/Temp/Proxy`).
- Datacenter keeps separate connection objects/arrays per type and lazily creates/connects them.

### Windows / Linux (Telegram Desktop)
- **Version-pinned source snapshot**: `telegramdesktop/tdesktop` tag `v6.7.2`.
- MTProto layer prepares multiple "test connections" across endpoint/protocol variants and selects by priority.
- Initial TCP path transport full-connect timeout is `8s`.
- After first success, Desktop may wait `kWaitForBetterTimeout = 2000ms` for a better candidate.

## ТСПУ / DPI Evasion (Russian ISP Blocking)

### Anatomy of the Block
Российский ТСПУ работает в **два этапа**:
1. **Пассивный анализ**: видит FakeTLS ClientHello с SNI `wb.ru` к неизвестному VPS → SNI-IP mismatch → IP ставится в очередь на проверку.
2. **Активные пробы («Ревизор»)**: через 5-10 минут сканер РКН подключается к серверу и делает Replay Attack.
3. IP улетает в BGP-blackhole за ~20 минут.

### Solution 1: Anti-Replay Cache (код в `proxy.zig`)
`ReplayCache` хранит 4096 последних виденных `client_digest`. При повторении выносится решение, что это Ревизор. В ответ маскируется подключение на реальный домен (например, wb.ru).

### Solution 2: TCPMSS Clamping (iptables на сервере)
```bash
iptables -t mangle -A OUTPUT -p tcp --sport 443 --tcp-flags SYN,ACK SYN,ACK -j TCPMSS --set-mss 88
```
Объявляет MSS=88 байт. iOS дробит ClientHello. Реплики не собирают.

### Solution 3: IPv6 Address Hopping (`deploy/ipv6-hop.sh`)
Генерирует случайный IPv6 из `/64` каждые N минут. Обновляет Cloudflare AAAA-запись через API (TTL=60s).

### Solution 4: Nginx Template ServerHello (код в `tls.zig`)
Comptime-шаблон генерирует структуру Nginx ServerHello. Правильный порядок расширений, фиксированный размер AppData=2878 байт, детерминированное тело.

### Solution 5: Split-TLS Desync (код в `proxy.zig`)
Серверный аналог zapret split — разбивает ServerHello на два TCP-сегмента (1 байт и оставшаяся часть) с паузой 3ms.

### Solution 6: nfqws OS-Level Desync (`deploy/setup_nfqws.sh`)
Для максимальной защиты — OS-level TCP desync через zapret `nfqws`.

### Solution 7: Local Nginx Masking (`deploy/setup_masking.sh`)

Timing side-channel: при маскировке bad clients проксирование на удалённый `wb.ru:443` добавляет 30-60ms RTT. DPI может сравнить RTT «нашего wb.ru» с реальным и обнаружить аномалию.

Решение: локальный Nginx на `127.0.0.1:8443` с self-signed (или Let's Encrypt) сертификатом. RTT маскировки < 1ms — неотличимо от реального сервера.

```bash
sudo bash deploy/setup_masking.sh wb.ru
```

### Конфигурация для работы с ТСПУ (Серверные Тюнинги)
```toml
[server]
max_connections = 65535         # Жесткий лимит соединений (защита от thread exhaustion)
thread_stack_kb = 256           # Размер стека потока (чем меньше, тем больше потоков влезет в RAM)
idle_timeout_sec = 300          # Таймаут ожидания первого байта (важно для iOS)
handshake_timeout_sec = 60      # Таймаут на сборку 64-байтового рукопожатия

[censorship]
tls_domain = "wb.ru"   # ВАЖНО: должен совпадать с hex-суффиксом в ee-секрете
mask = true             # Прозрачный проброс на реальный wb.ru для неизвестных клиентов
```

### Статистика производительности (на 1 vCPU / 1 GB RAM)
| Реализация | Соединений (ESTABLISHED) | Стабильность | Память (RSS) |
|------------|-------------------------|--------------|--------------|
| **mtproto.zig** | **13,000** | **100%** | **144 MB** |
| Official MTProxy | 12,000 | 100% | 72 MB |
| Telemt | 8,000 | 100% | 51 MB |
| mtg | 4,000 | 100% | 124 MB |

*Полная методология и профили в [test/README.md](file:///c:/Users/Dmitry/Antigravity/mtproto.zig/test/README.md).*

### Хронология блокировок
- **IP сжигается**: ~10 мин после первого FakeTLS соединения (пассивный детект)
- **BGP-blackhole**: ~20 мин (0 пакетов до сервера)
- **IPv6 не блокируется**: /64-подсети не трогают — слишком большой риск collateral damage

### Commercial / Premium VPNs Filtering
If connecting to the proxy while behind a **Commercial/Premium VPN**, the VPN provider's firewall often drops MTProto traffic by design:
- **DPI**: They perform Deep Packet Inspection and drop FakeTLS connections that do not act identically to standard browsers.
- **IP Blocking**: They silently block TCP routing to Telegram Datacenter IPs.
- **Symptoms**: Proxy sits in "Updating..." state indefinitely. The proxy instance receives 0 packets from the VPN exit node.
- **Solution**: Use self-hosted VPNs (like the co-located AmneziaWG above) which do not perform traffic filtering or DPI on outbound connections.

## Co-located AmneziaVPN / WireGuard
When the proxy and AmneziaVPN run on the same server, iOS VPN clients cannot reach `host:443` by default.
**Fix**:
```bash
iptables -I DOCKER-USER -s 10.8.1.0/24 -p tcp --dport 443 -j ACCEPT
iptables -I DOCKER-USER -s 172.29.172.0/24 -p tcp --dport 443 -j ACCEPT
netfilter-persistent save
```
