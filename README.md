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
[Quick Start](#-quick-start) &nbsp;&bull;&nbsp;
[Update](#-update-existing-server) &nbsp;&bull;&nbsp;
[Deploy](#-deploy-to-server) &nbsp;&bull;&nbsp;
[Configuration](#-configuration) &nbsp;&bull;&nbsp;
[Troubleshooting](#-troubleshooting-updating)

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
| **MiddleProxy** | Telemt-Compatible ME | Optional ME transport for regular DC1..5 (`use_middle_proxy`) + required DC203 media relay |
| **Auto Refresh** | Telegram Metadata | Periodically updates MiddleProxy endpoint and secret from Telegram core endpoints |
| **Promotion** | Tag Support | Optional promotion tag for sponsored proxy channel registration |
| **IPv6 Hopping** | DPI Evasion | Auto-rotates IPv6 from /64 subnet on ban detection via Cloudflare API |
| **TCPMSS=88** | DPI Evasion | Forces ClientHello fragmentation across 6 TCP packets, breaking ISP DPI reassembly |
| **TCP Desync** | DPI Evasion | Integrated `zapret` (`nfqws`) OS-level desynchronization (fake packets + TTL spoofing) |
| **Split-TLS** | DPI Evasion | 1-byte Application-level record chunking to defeat passive DPI signatures |
| **Zero-RTT** | DPI Evasion | Local Nginx server deployed on-the-fly (`127.0.0.1:8443`) to defeat active probing timing analysis |
| **0 deps** | Stdlib Only | Built entirely on the Zig standard library |
| **0 globals** | Thread Safety | Dependency injection -- no global mutable state |

> **Engineering Notes:** For deep technical details, cryptography internals, systemd hardening, and benchmarks, see [GEMINI.md](GEMINI.md) (Engineering Notes).

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

### Performance & Stability Checks

```bash
# Fast microbenchmark for C2S encapsulation
make bench

# 30-second multithreaded soak (crash/stability guard)
make soak

# Custom soak shape
zig build -Doptimize=ReleaseFast soak -- --seconds=120 --threads=8 --max-payload=131072
```

`bench` prints per-payload throughput (`in_mib_per_s`, `out_mib_per_s`) and `ns_per_op`.
`soak` prints aggregate `ops/s`, throughput, and `errors`; non-zero errors fail the step.

<details>
<summary>All Make targets</summary>

| Target | Description |
|--------|-------------|
| `make build` | Debug build |
| `make release` | Optimized build (`ReleaseFast`) |
| `make run CONFIG=<path>` | Run proxy (default: `config.toml`) |
| `make test` | Run unit tests |
| `make bench` | Run ReleaseFast encapsulation microbenchmarks |
| `make soak` | Run ReleaseFast multithreaded soak stress test (30s default) |
| `make clean` | Remove build artifacts |
| `make fmt` | Format all Zig source files |
| `make deploy` | Cross-compile, upload binary/scripts/config to VPS, restart service |
| `make deploy SERVER=<ip>` | Deploy to a specific server |
| `make update-server SERVER=<ip> [VERSION=vX.Y.Z]` | Update server binary from GitHub Release artifacts |

</details>

## &nbsp; Update existing server

The easiest way to upgrade an already installed proxy is to pull a prebuilt binary from GitHub Releases and restart the service.

From your local machine:

```bash
make update-server SERVER=<SERVER_IP>
```

Pin to a specific version:

```bash
make update-server SERVER=<SERVER_IP> VERSION=v0.1.0
```

What `update-server` does on the VPS:
1. Downloads the latest (or pinned) release artifact for server architecture.
2. Stops `mtproto-proxy`, replaces binary, and keeps `config.toml`/`env.sh` untouched.
3. Refreshes helper scripts and service unit from the same release tag.
4. Restarts service and rolls back binary automatically if restart fails.

If you are already on the server:

```bash
curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/update.sh | sudo bash
```

Or pinned version:

```bash
curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/update.sh | sudo bash -s -- v0.1.0
```

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
curl -sSfL https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz | \
  sudo tar xJ -C /usr/local
sudo ln -sf /usr/local/zig-x86_64-linux-0.15.2/zig /usr/local/bin/zig

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
[general]
use_middle_proxy = true                         # Telemt-compatible ME mode for promo parity
ad_tag = "1234567890abcdef1234567890abcdef"    # Optional alias for [server].tag

[server]
port = 443
tag = "1234567890abcdef1234567890abcdef"   # Optional: promotion tag from @MTProxybot

[censorship]
tls_domain = "wb.ru"
mask = true
mask_port = 8443
desync = true
fast_mode = true

[access.users]
alice = "00112233445566778899aabbccddeeff"
bob   = "ffeeddccbbaa99887766554433221100"
```

<details>
<summary>Configuration reference</summary>

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `[general]` | `use_middle_proxy` | `false` | Telemt-compatible ME mode for regular DC1..5 (recommended for promo-channel parity) |
| `[general]` | `ad_tag` | _(none)_ | Telemt-compatible alias for promotion tag; ignored if `[server].tag` is set |
| `[server]` | `port` | `443` | TCP port to listen on |
| `[server]` | `tag` | _(none)_ | Optional 32 hex-char promotion tag from [@MTProxybot](https://t.me/MTProxybot) |
| `[censorship]` | `tls_domain` | `"google.com"` | Domain to impersonate / forward bad clients to |
| `[censorship]` | `mask` | `true` | Forward unauthenticated connections to `tls_domain` to defeat DPI |
| `[censorship]` | `mask_port` | `443` | Non-standard port override for masking locally (e.g. `8443` for zero-RTT local Nginx) |
| `[censorship]` | `desync` | `true` | Application-level Split-TLS (1-byte chunking) for passive DPI evasion |
| `[censorship]` | `fast_mode` | `false` | **Recommended**. Drastically reduces RAM/CPU usage by natively delegating S2C AES encryption to the Telegram DC |
| `[access.users]` | `<name>` | -- | 32 hex-char secret (16 bytes) per user |

</details>

> **Operational note** &nbsp; High-churn mobile networks can produce many normal disconnects (`ConnectionResetByPeer`/`EndOfStream`). In release builds these are logged at debug level to keep production logs signal-focused.

> **Tip** &nbsp; Generate a random secret: `openssl rand -hex 16`

> **Note** &nbsp; The configuration format is compatible with the Rust-based `telemt` proxy.

> **Note** &nbsp; MiddleProxy settings (regular DC1..5 endpoints + media DC203 endpoint + shared secret) are refreshed automatically from Telegram (`getProxyConfig`, `getProxySecret`) with a bundled fallback.

## &nbsp; Troubleshooting ("Updating...")

If your Telegram app is stuck on "Updating...", your provider or network is dropping the connection.

### 1. Home Wi-Fi restricts IPv4

Often, mobile networks will connect instantly because they use **IPv6**, but Home Wi-Fi internet providers block the destination's IPv4 address directly at the gateway.
**Solution:** Enable **IPv6 Prefix Delegation** on your home Wi-Fi router. 
- Go to your router's admin panel (e.g., `192.168.1.1`).
- Find the **IPv6** or **WAN/LAN** settings.
- Enable `IPv6`, and specifically check **IA_PD** (Prefix Delegation) for the WAN/DHCP client, and **IA_NA** for the LAN/DHCP Server.
- Reboot the router and verify your phone gets an IPv6 address at [test-ipv6.com](https://test-ipv6.com). 

### 2. Commercial / Premium VPNs Block Traffic

If your iPhone is connected to a **commercial/premium VPN** and stuck on "Updating...", the VPN provider is actively dropping the MTProto TLS traffic using their own DPI.
**Solutions**:
- **Switch Protocol**: Try switching the VPN protocol (e.g., Xray/VLESS to WireGuard).
- **Self-Host**: Use a self-hosted VPN (like AmneziaWG) on your own server.

### 3. Co-located WireGuard (Docker routing)

If you run both this proxy and AmneziaVPN (or a WireGuard Docker container) **on the same server**, iOS clients will route proxy traffic inside the VPN tunnel, and Docker will drop the bridge packets.
**Solution**: Allow traffic from the VPN Docker subnet:
```bash
iptables -I DOCKER-USER -s 172.29.172.0/24 -p tcp --dport 443 -j ACCEPT
```

### 4. DC203 media resets

If only media-heavy sessions fail on non-premium clients, check MiddleProxy logs first:

```bash
sudo journalctl -u mtproto-proxy --since "15 min ago" | grep -E "dc=203|Middle-proxy"
```

On startup the proxy now refreshes DC203 metadata from Telegram automatically. If your server cannot reach `core.telegram.org`, it falls back to bundled defaults.

## &nbsp; License

[MIT](LICENSE) &copy; 2026 Aleksandr Kalashnikov
