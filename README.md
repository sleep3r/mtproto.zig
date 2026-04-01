<div align="center">

# mtproto.zig

**High-performance Telegram MTProto proxy written in Zig**

Disguises Telegram traffic as standard TLS 1.3 HTTPS to bypass network censorship.

<p align="center">
  <strong>126 KB binary. ~120 KB RAM. Boots in <2 ms. Zero dependencies.</strong>
</p>

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/zig-0.15.2-f7a41d.svg?logo=zig&logoColor=white)](https://ziglang.org)
[![LOC](https://img.shields.io/badge/lines_of_code-1.7k-informational)](src/)
[![Dependencies](https://img.shields.io/badge/dependencies-0-success)](build.zig)

---

[Features](#-features) &nbsp;&bull;&nbsp;
[How It Works](#-how-it-works) &nbsp;&bull;&nbsp;
[Quick Start](#-quick-start) &nbsp;&bull;&nbsp;
[Deploy](#-deploy-to-server) &nbsp;&bull;&nbsp;
[Configuration](#-configuration) &nbsp;&bull;&nbsp;
[Security](#-security) &nbsp;&bull;&nbsp;
[Project Structure](#-project-structure)

</div>

## &nbsp; Features

| | Feature | Description |
|---|---------|-------------|
| **TLS 1.3** | Fake Handshake | Connections are indistinguishable from normal HTTPS to DPI systems |
| **MTProto v2** | Obfuscation | AES-256-CTR encrypted tunneling (abridged, intermediate, secure) |
| **DRS** | Dynamic Record Sizing | Mimics real browser TLS behavior (Chrome/Firefox) to resist fingerprinting |
| **Multi-user** | Access Control | Independent secret-based authentication per user |
| **Anti-replay** | Timestamp + Digest Cache | Rejects replayed handshakes outside ±2 min window AND detects ТСПУ Revisor active probes |
| **Masking** | Connection Cloaking | Forwards unauthenticated clients to a real domain |
| **Fast Mode** | Zero-copy S2C | Drastically reduces CPU usage by delegating Server-to-Client AES encryption to the DC |
| **Promotion** | Tag Support | Optional promotion tag for sponsored proxy channel registration |
| **IPv6 Hopping** | DPI Evasion | Auto-rotates IPv6 from /64 subnet on ban detection via Cloudflare API |
| **TCPMSS=88** | DPI Evasion | Forces ClientHello fragmentation across 6 TCP packets, breaking ISP DPI reassembly |
| **0 deps** | Stdlib Only | Built entirely on the Zig standard library |
| **0 globals** | Thread Safety | Dependency injection -- no global mutable state |

## &nbsp; How It Works

```mermaid
%%{init: {'theme': 'dark'}}%%
sequenceDiagram
    participant C as Client
    participant P as Proxy
    participant DC as Telegram DC

    rect rgb(30, 30, 80)
    Note over C,P: Layer 1 — Fake TLS 1.3
    C->>P: TLS ClientHello (HMAC-SHA256 in random)
    P-->>C: TLS ServerHello + ChangeCipherSpec
    end

    rect rgb(20, 70, 30)
    Note over C,DC: Layer 2 — MTProto Obfuscation
    C->>P: TLS AppData ← 64-byte obfuscated handshake
    P->>DC: Obfuscated handshake (AES-256-CTR keys derived)
    DC-->>P: Obfuscated response
    end

    rect rgb(90, 30, 30)
    Note over C,DC: Layer 3 — Encrypted Relay
    C->>P: TLS( AES-CTR( data ) )
    P->>DC: AES-CTR( data )
    DC-->>P: AES-CTR( data )
    P-->>C: TLS( AES-CTR( data ) )
    end
```

> **Layer 1 -- Fake TLS 1.3** &nbsp; The client embeds an HMAC-SHA256 digest (derived from its secret) in the ClientHello `random` field. The proxy validates it and responds with an indistinguishable ServerHello.

> **Layer 2 -- MTProto Obfuscation** &nbsp; Inside the TLS tunnel, a 64-byte obfuscated handshake is exchanged. AES-256-CTR keys are derived via SHA-256 for bidirectional encryption.

> **Layer 3 -- DC Relay** &nbsp; The proxy connects to the target Telegram datacenter (DC1-DC5), performs its own obfuscated handshake, and relays traffic between client and DC with re-encryption.

> **Anti-censorship -- Masking** &nbsp; When an unauthenticated client connects (e.g. a DPI active probe), the proxy transparently forwards the connection to the real `tls_domain` (e.g. `wb.ru`). The prober receives a genuine TLS certificate and HTTP response, making the proxy indistinguishable from a real web server.

## &nbsp; Benchmark Snapshot

Measured locally (ReleaseSmall) and on a 1 vCPU Linux VPS under load.

| | [mtprotoproxy](https://github.com/alexbers/mtprotoproxy) | [telemt](https://github.com/telemt/telemt) | **[mtproto.zig](https://github.com/sleep3r/mtproto.zig)** |
|---|---|---|---|
| **Language** | Python | Rust | **Zig** |
| **RAM (Peak)** | > 50 MB | ~11.6 MB | **~6.8 MB** |
| **RAM (Idle)**  | ~30 MB | ~3.0 MB | **~120 KB** |
| **Binary Size** | N/A (Scripts) | ~17.0 MB | **126 KB** |
| **Dependencies**| `cryptography`, `uvloop` | 150+ Crates | **0 (None)** |

> Measured via systemd status and `/usr/bin/time -v` on an Ubuntu 24.04 server.
> `mtproto.zig` is compiled statically via `zig build -Doptimize=ReleaseSmall -Dtarget=x86_64-linux` and uses the standard library entirely for its cryptography, handshakes, and event loops.

## &nbsp; Quick Start

### Prerequisites

- [Zig](https://ziglang.org/download/) **0.15.2** or later

### Build & Run locally

```bash
# Clone
git clone https://github.com/sleep3r/mtproto.zig.git
cd mtproto.zig

# Build (debug)
make build

# Build (optimized for production)
make release

# Run with default config.toml
make run
```

### Run Tests

```bash
make test
```

<details>
<summary>All Make targets</summary>

| Target | Description |
|--------|-------------|
| `make build` | Debug build |
| `make release` | Optimized build (`ReleaseFast`) |
| `make run CONFIG=<path>` | Run proxy (default: `config.toml`) |
| `make test` | Run unit tests |
| `make clean` | Remove build artifacts |
| `make fmt` | Format all Zig source files |
| `make deploy` | Cross-compile, upload to VPS, restart service |
| `make deploy SERVER=<ip>` | Deploy to a specific server |

</details>

## &nbsp; Deploy to Server

### One-line install (Ubuntu/Debian)

```bash
curl -sSf https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/install.sh | sudo bash
```

This will:
1. Install **Zig 0.15.2** (if not present)
2. Clone and build the proxy with `ReleaseFast`
3. Generate a random 16-byte secret
4. Create a `systemd` service (`mtproto-proxy`)
5. Open port 443 in `ufw` (if active)
6. Apply **TCPMSS=88** iptables rule (passive DPI bypass)
7. Install **IPv6 hop script** (optional cron auto-rotation with `CF_TOKEN`+`CF_ZONE`)
8. Print a ready-to-use `tg://` connection link

To enable IPv6 auto-hopping (Cloudflare DNS rotation on ban detection), you must provide Cloudflare API credentials. The script uses these to update your domain's AAAA record to a new random IPv6 address from your server's `/64` pool when it detects DPI active probing.

#### Obtaining Cloudflare Credentials

1. **`CF_ZONE` (Zone ID)**:
   - Go to your Cloudflare dashboard and select your active domain.
   - On the right sidebar of the Overview page, scroll down to the "API" section and copy the **Zone ID**.
2. **`CF_TOKEN` (API Token)**:
   - Click "Get your API token" below the Zone ID (or go to *My Profile -> API Tokens*).
   - Click **Create Token** -> **Create Custom Token**.
   - Permissions: `Zone` | `DNS` | `Edit`.
   - Zone Resources: `Include` | `Specific zone` | `<Your Domain>`.
   - Create the token and copy the secret string.

#### Enabling the Bypass during Installation

You can either pass variables directly inline:

```bash
curl -sSf https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/install.sh | \
  sudo CF_TOKEN=<your_cf_token> CF_ZONE=<your_zone_id> bash
```

Or, for a cleaner and more secure approach, create a `.env` file first (you can copy `.env.example` as a template):

```bash
export $(cat .env | xargs)
curl -sSf https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/install.sh | sudo -E bash
```

### Manual deploy

<details>
<summary>Step-by-step instructions</summary>

**1. Install Zig on the server**

```bash
# x86_64
curl -sSfL https://ziglang.org/download/0.15.2/zig-linux-x86_64-0.15.2.tar.xz | \
  sudo tar xJ -C /usr/local
sudo ln -sf /usr/local/zig-linux-x86_64-0.15.2/zig /usr/local/bin/zig

# Verify
zig version   # → 0.15.2
```

**2. Build the proxy**

```bash
git clone https://github.com/sleep3r/mtproto.zig.git
cd mtproto.zig
zig build -Doptimize=ReleaseFast
```

Or cross-compile on your Mac:

```bash
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux
scp zig-out/bin/mtproto-proxy root@<SERVER_IP>:/opt/mtproto-proxy/
```

**3. Configure**

```bash
sudo mkdir -p /opt/mtproto-proxy
sudo cp zig-out/bin/mtproto-proxy /opt/mtproto-proxy/

# Generate a random secret
SECRET=$(openssl rand -hex 16)
echo $SECRET

sudo tee /opt/mtproto-proxy/config.toml <<EOF
[server]
port = 443
# tag = "<your-promotion-tag>"   # Optional: 32 hex-char promotion tag from @MTProxybot

[censorship]
tls_domain = "wb.ru"
mask = true
fast_mode = true

[access.users]
user = "$SECRET"
EOF
```

**4. Install the systemd service**

```bash
sudo cp deploy/mtproto-proxy.service /etc/systemd/system/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mtproto
sudo chown -R mtproto:mtproto /opt/mtproto-proxy

sudo systemctl daemon-reload
sudo systemctl enable mtproto-proxy
sudo systemctl start mtproto-proxy
```

**5. Open port 443**

```bash
sudo ufw allow 443/tcp
```

**6. Generate connection link**

The proxy prints links on startup. Check them with:

```bash
journalctl -u mtproto-proxy | head -30
```

Or build it manually:

```
tg://proxy?server=<SERVER_IP>&port=443&secret=ee<SECRET><HEX_DOMAIN>
```

Where `<HEX_DOMAIN>` is your `tls_domain` encoded as hex:

```bash
echo -n "wb.ru" | xxd -p     # → 77622e7275
```

</details>

### Managing the service

```bash
# Status
sudo systemctl status mtproto-proxy

# Live logs
sudo journalctl -u mtproto-proxy -f

# Restart (e.g., after config change)
sudo systemctl restart mtproto-proxy

# Stop
sudo systemctl stop mtproto-proxy
```

## &nbsp; Configuration

Create a `config.toml` in the project root:

```toml
[server]
port = 443
tag = "1234567890abcdef1234567890abcdef"   # Optional: promotion tag from @MTProxybot

[censorship]
tls_domain = "wb.ru"
mask = true
fast_mode = true

[access.users]
alice = "00112233445566778899aabbccddeeff"
bob   = "ffeeddccbbaa99887766554433221100"
```

<details>
<summary>Configuration reference</summary>

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `[server]` | `port` | `443` | TCP port to listen on |
| `[server]` | `tag` | _(none)_ | Optional 32 hex-char promotion tag from [@MTProxybot](https://t.me/MTProxybot) |
| `[censorship]` | `tls_domain` | `"wb.ru"` | Domain to impersonate / forward bad clients to |
| `[censorship]` | `mask` | `true` | Forward unauthenticated connections to `tls_domain` to defeat DPI |
| `[censorship]` | `fast_mode` | `false` | **Recommended**. Drastically reduces RAM/CPU usage by natively delegating S2C AES encryption to the Telegram DC |
| `[access.users]` | `<name>` | -- | 32 hex-char secret (16 bytes) per user |

</details>

> **Tip** &nbsp; Generate a random secret: `openssl rand -hex 16`

> **Note** &nbsp; The configuration format is compatible with the Rust-based `telemt` proxy.

## &nbsp; Security

| Measure | Details |
|---------|---------|
| Constant-time comparison | HMAC validation uses constant-time byte comparison to prevent timing attacks |
| Key wiping | All key material is zeroed from memory after use |
| Secure randomness | Cryptographically secure RNG for all nonces and key generation |
| Anti-replay (timestamp) | Embedded timestamp validation rejects handshakes outside +/- 2 min window |
| Anti-replay (digest cache) | 4096-entry ring buffer detects ТСПУ Revisor replay probes, forwards them to real `tls_domain` |
| Nonce validation | Rejects nonces matching HTTP, plain MTProto, or TLS patterns |
| Dynamic Record Sizing | TLS record sizes mimic real browsers, preventing traffic fingerprinting |
| Connection masking | Invalid clients are proxied to the real `tls_domain`, defeating DPI active probes |
| TCPMSS clamping | MSS=88 forces ClientHello fragmentation, breaking passive DPI signature detection |
| IPv6 address hopping | Rotates server IPv6 from /64 subnet on ban detection (TSPU can't ban /64 blocks) |
| Systemd hardening | Runs as unprivileged user with `NoNewPrivileges`, `ProtectSystem=strict` |

## &nbsp; Project Structure

```
├── deploy/
│   ├── install.sh                One-line installer (incl. TCPMSS + IPv6 hop setup)
│   ├── ipv6-hop.sh               IPv6 address rotation for DPI evasion
│   └── mtproto-proxy.service     Systemd unit file
│
└── src/
    ├── main.zig                  Entry point, banner, IP detection
    ├── config.zig                TOML-like configuration parser
    │
    ├── crypto/
    │   └── crypto.zig            AES-256-CTR/CBC, SHA-256, HMAC, SHA-1, MD5
    │
    ├── protocol/
    │   ├── constants.zig         DC addresses, protocol tags, TLS constants
    │   ├── tls.zig               Fake TLS 1.3 (ClientHello validation, ServerHello)
    │   └── obfuscation.zig       MTProto v2 obfuscation & key derivation
    │
    └── proxy/
        └── proxy.zig             TCP listener, connection handler, relay, DRS, ReplayCache
```

## &nbsp; iOS Compatibility

The proxy includes specific handling for iOS Telegram clients:

- **Fast Mode (`fast_mode = true`)** — Highly recommended for iOS clients to fix the "Updating..." connection loop. This bypasses proxy S2C encryption and relies on the Telegram DC directly.

- **Fragmented handshake assembly** — iOS may split the 64-byte MTProto handshake across multiple TLS AppData records or interleave CCS records
- **Two-stage timeouts** — idle pool connections (common on iOS) get a generous 5-minute poll timeout; active data gets a tight 10s `SO_RCVTIMEO`
- **Generous handshake timeout** — 60s timeout during handshake assembly (iOS may delay after ServerHello)
- **Fixed record sizing** — TLS records are kept at MSS-sized 1369 bytes for maximum compatibility

> **Important**   Russian ISPs (МГТС/Ростелеком/МегаФон) use ТСПУ DPI that detects FakeTLS signatures within ~10 minutes, then bans the VPS IP via BGP blackhole. Three countermeasures are built in:
> - **Anti-Replay Cache** — detects "Revisor" active probes (replay attacks), forwards them to real `wb.ru`
> - **TCPMSS=88** — forces iOS to fragment ClientHello into 6+ TCP packets, breaking DPI signature detection
> - **IPv6 Address Hopping** — auto-rotates `/64` subnet addresses on ban detection (ТСПУ never bans /64 blocks)

## &nbsp; Running alongside AmneziaVPN / WireGuard

If you run both the proxy and AmneziaVPN (or any WireGuard-based VPN) **on the same server**, iOS clients connected through the VPN will not be able to reach the proxy by default.

**The problem:** iOS routes all traffic (including proxy connections) through the VPN tunnel. The packets exit the tunnel inside a Docker network (e.g. `172.29.172.0/24`), but Docker's default `FORWARD policy DROP` silently blocks them from reaching port 443 on the host. macOS VPN clients are not affected because they route traffic to the VPN server's own IP outside the tunnel.

**The fix** — allow VPN clients to reach the proxy:

```bash
# Allow traffic from the VPN Docker subnet to the proxy port
iptables -I DOCKER-USER -s 172.29.172.0/24 -p tcp --dport 443 -j ACCEPT

# Make the rule persistent across reboots
apt-get install -y iptables-persistent
netfilter-persistent save
```

> **Note** &nbsp; Replace `172.29.172.0/24` with your AmneziaVPN Docker subnet. For standard WireGuard without Docker, you might need to allow traffic from `10.8.1.0/24` (or whatever your `AllowedIPs` subnet is).

### Commercial / Premium VPNs Block MTProto

If your iPhone is connected to a **commercial/premium VPN** (even if using the Amnezia client or WireGuard protocol) and your MTProto proxy is stuck on "Updating...", the VPN provider is likely blocking the traffic.

- **DPI & TLS Inspection**: Commercial VPNs often use DPI to inspect TLS traffic. FakeTLS mimics a normal HTTPS handshake, but if the VPN actively probes the connection or analyzes the payload structure, they may detect MTProto traffic and drop it.
- **IP Blocking**: The VPN may outright block connections to Telegram datacenter IP ranges.

**Solution**: Use a self-hosted VPN (like AmneziaWG) on your own server. Your own server won't restrict outbound MTProto traffic.

## &nbsp; License

[MIT](LICENSE) &copy; 2026 Aleksandr Kalashnikov
