<div align="center">

# mtproto.zig

**High-performance Telegram MTProto proxy written in Zig**

Disguises Telegram traffic as standard TLS 1.3 HTTPS to bypass network censorship.

<p align="center">
  <strong>126 KB binary. Extreme Scalability: 13,000+ stable connections on 1GB RAM. Zero dependencies.</strong>
</p>

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/zig-0.15.2-f7a41d.svg?logo=zig&logoColor=white)](https://ziglang.org)
[![LOC](https://img.shields.io/badge/lines_of_code-1.7k-informational)](src/)
[![Dependencies](https://img.shields.io/badge/dependencies-0-success)](build.zig)

---

[Features](#-features) &nbsp;&bull;&nbsp;
[Quick Start](#-quick-start) &nbsp;&bull;&nbsp;
[Update](#-update-existing-server) &nbsp;&bull;&nbsp;
[Docker](#docker-image) &nbsp;&bull;&nbsp;
[Deploy](#-deploy-to-server) &nbsp;&bull;&nbsp;
[Tunnel](#-amneziawg-tunnel-blocked-regions) &nbsp;&bull;&nbsp;
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
| **Fast Mode** | Direct-Path S2C Offload | Reduces CPU usage by delegating S2C AES work to Telegram DCs on direct paths (non-MiddleProxy) |
| **MiddleProxy** | Telemt-Compatible ME | Optional ME transport for DC1..5 (`use_middle_proxy`); media-path traffic prefers ME endpoints with direct fallback when unavailable |
| **Auto Refresh** | Telegram Metadata | Periodically updates MiddleProxy endpoint and secret from Telegram core endpoints |
| **Promotion** | Tag Support | Optional promotion tag for sponsored proxy channel registration |
| **IPv6 Hopping** | DPI Evasion | Auto-rotates IPv6 from /64 subnet on ban detection via Cloudflare API |
| **TCPMSS=88** | DPI Evasion | Forces ClientHello fragmentation across 6 TCP packets, breaking ISP DPI reassembly |
| **TCP Desync** | DPI Evasion | Integrated `zapret` (`nfqws`) OS-level desynchronization (fake packets + TTL spoofing) |
| **Split-TLS** | DPI Evasion | Splits fake `ServerHello` write into `1 byte + short pause + rest` to desynchronize passive DPI |
| **Zero-RTT** | DPI Evasion | Local Nginx server deployed on-the-fly (`127.0.0.1:8443`) to defeat active probing timing analysis |
| **0 deps** | Stdlib Only | No third-party Zig packages (proxy core uses Zig standard library only) |
| **0 globals** | Thread Safety | Dependency injection -- no global mutable state |

> **Engineering Notes:** For deep technical details, cryptography internals, systemd hardening, and benchmarks, refer to the `.agent/skills` and `.agent/workflows` directories.

Connection-capacity methodology and command profiles: `test/README.md`.

## Runtime Model

- Client relay is handled by a single-threaded Linux `epoll` event loop.
- A background updater thread periodically refreshes MiddleProxy metadata from Telegram core endpoints.
- Handshake and relay lifetimes are controlled by event-loop timers (`idle_timeout_sec`, `handshake_timeout_sec`), not by `SO_RCVTIMEO`.

## &nbsp; Quick Start

### Prerequisites

- [Zig](https://ziglang.org/download/) **0.15.2** or later

### Build & Run locally

```bash
# Clone
git clone https://github.com/XXcipherX/mtproto.zig.git
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
| `make capacity-probe-idle` | Run idle-socket capacity probe for `mtproto.zig` |
| `make capacity-probe-active` | Run TLS-auth (active) capacity probe for `mtproto.zig` |
| `make clean` | Remove build artifacts |
| `make fmt` | Format all Zig source files |
| `make deploy` | Cross-compile, upload binary/scripts/config to VPS, restart service |
| `make deploy SERVER=<ip>` | Deploy to a specific server |
| `make deploy-tunnel SERVER=<ip> AWG_CONF=<path> [PASSWORD=<pass>]` | Full migration + AmneziaWG tunnel for blocked regions |
| `make deploy-tunnel-only SERVER=<ip> AWG_CONF=<path>` | Add AmneziaWG tunnel to existing installation |

</details>

## &nbsp; Update existing server

To update an already installed proxy, simply re-run the same install command:

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | sudo bash
```

The script is **idempotent**: it rebuilds from latest source, replaces the binary, and preserves your existing `config.toml` and `env.sh`. User secrets and connection links remain unchanged.

## Docker image

The repository includes a **multi-stage Dockerfile**: Zig is bootstrapped from the official tarball inside the build stage; the runtime image is Debian **bookworm-slim** with `curl` and CA certs (startup banner resolves the public IP via `curl`). The process runs as **root** inside the container (simple bind to port 443). The image ships `config.toml.example` as `/etc/mtproto-proxy/config.toml` for a quick start; mount your own file for real secrets and settings.

### Build

```bash
docker build -t mtproto-zig .
```

### Build arguments

| Argument       | Default   | Description |
|----------------|-----------|-------------|
| `ZIG_VERSION`  | `0.15.2`  | Version string passed to `ziglang.org/download/…/zig-<arch>-linux-<version>.tar.xz`. Must match a published Zig release. |
| `ZIG_SHA256`   | _(empty)_ | Optional pinned SHA256 for the downloaded Zig tarball. If set, Docker build verifies integrity before extraction. |

Example:

```bash
docker build --build-arg ZIG_VERSION=0.15.2 -t mtproto-zig .
```

### Architecture (`TARGETARCH`)

The **builder** stage maps Docker’s auto-injected `TARGETARCH` to Zig’s Linux tarball name:

| `TARGETARCH` (BuildKit) | Zig tarball |
|-------------------------|-------------|
| `amd64`                 | `x86_64`    |
| `arm64`                 | `aarch64`   |

You normally **do not** pass `TARGETARCH` yourself; BuildKit sets it from the requested platform.  
If BuildKit auto-args are unavailable, the Dockerfile falls back to host architecture detection.

**Build for a specific CPU architecture** (e.g. from an Apple Silicon Mac to run on an `amd64` VPS):

```bash
docker build --platform linux/amd64 -t mtproto-zig:amd64 .
docker build --platform linux/arm64 -t mtproto-zig:arm64 .
```

**Multi-platform image** (push requires a registry and `buildx`):

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t your-registry/mtproto-zig:latest \
  --push .
```

### Run

Publish the listen port from your config (the bundled example listens on `443`). For production, mount your `config.toml` over the default:

```bash
docker run --rm \
  -p 443:443 \
  -v "$PWD/config.toml:/etc/mtproto-proxy/config.toml:ro" \
  mtproto-zig
```

`docker run --rm -p 443:443 mtproto-zig` also works using the in-image example config (replace example user secrets before exposing the service).

If your config sets `server.port = 8443`, publish `-p 8443:8443` instead.

OS-level mitigations from `deploy/` (iptables `TCPMSS`, `nfqws`, etc.) are **not** applied inside the container; only the proxy binary runs there.

## &nbsp; Deploy to Server

### One-line install (Ubuntu/Debian)

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | sudo bash
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
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | \
  sudo CF_TOKEN=<your_cf_token> CF_ZONE=<your_zone_id> bash
```

Or, for a cleaner and more secure approach, create a `.env` file first (you can copy `.env.example` as a template):

```bash
export $(cat .env | xargs)
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | sudo -E bash
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
git clone https://github.com/XXcipherX/mtproto.zig.git
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

# Server tunables for high capacity
# max_connections = 10000
EOF

### &nbsp; Capacity & RAM Monitoring
On startup, the proxy automatically detects your Host RAM and prints a **CAPACITY** banner. It calculates a "Safe cap" based on your current settings and memory overhead. If your `max_connections` is dangerously high for your VPS RAM, it will display a warning.
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

## &nbsp; AmneziaWG Tunnel (Blocked Regions)

If your server is in a country that blocks Telegram at the network level (e.g., Russia — ТСПУ blocks TCP to Telegram DCs), you can route proxy traffic through an **AmneziaWG VPN tunnel** inside an isolated **network namespace**.

```
Client ──→ VPS:443 ──→ [iptables DNAT] ──→ 10.200.200.2:443
              (host)        (host)              (tg_proxy_ns)
                                                     │
                                                mtproto-proxy
                                                     │
                                               awg0 (tunnel)
                                                     │
                                             Telegram DC servers
```

**Key design:** the tunnel runs strictly inside a network namespace. Host SSH and other services are completely unaffected.

### Prerequisites

- An **AmneziaWG client config file** (`.conf`) — export it from the AmneziaVPN app or get it from your VPN provider
- The `.conf` must contain `[Interface]` (with `PrivateKey`, AmneziaWG junk fields) and `[Peer]` (with `Endpoint`)
- A VPS with **Ubuntu 24.04** in the target region

### One-command deploy (new server)

From your workstation:

```bash
make deploy-tunnel SERVER=<VPS_IP> AWG_CONF=awg.conf PASSWORD=<root_password>
```

This will:
1. Set up SSH key, install deps, build and deploy the proxy (via `make migrate`)
2. Install **amneziawg-tools** (DKMS kernel module + userspace tools)
3. Create network namespace `tg_proxy_ns` with AmneziaWG tunnel inside
4. Set up **DNAT** (incoming `:443` → namespace) and **policy routing** (responses go back to client, not into tunnel)
5. Patch the systemd service to run the proxy inside the namespace in **direct mode**
6. Validate connectivity to all 5 Telegram DCs through the tunnel
7. Print the ready-to-use `tg://` link

### Add tunnel to existing proxy

If the proxy is already installed and running:

```bash
make deploy-tunnel-only SERVER=<VPS_IP> AWG_CONF=awg.conf
```

### On the server directly

```bash
scp awg.conf root@<VPS_IP>:/tmp/awg.conf
ssh root@<VPS_IP> 'bash /opt/mtproto-proxy/setup_tunnel.sh /tmp/awg.conf'
```

### How it works

| Component | Location | Purpose |
|-----------|----------|---------|
| `awg0` | Inside `tg_proxy_ns` | Encrypted tunnel to Telegram DCs |
| `veth_main` ↔ `veth_ns` | Host ↔ Namespace | Bridge for client traffic |
| iptables DNAT | Host | Forwards `:443` → `10.200.200.2:443` |
| Policy routing (`from 10.200.200.2 table 100`) | Inside namespace | Response packets return via veth (not via tunnel) |
| `mtproto-proxy` | Inside `tg_proxy_ns` | Listens on `:443`, connects to Telegram via `awg0` |

> **Note** &nbsp; The tunnel setup automatically switches the proxy to **direct mode** (`use_middle_proxy = false`). Middleproxy mode requires per-IP registration with `@MTProxyBot`, which doesn't work when the proxy's outgoing IP is the VPN exit node.

> **Note** &nbsp; To check tunnel status: `ssh root@<VPS_IP> 'ip netns exec tg_proxy_ns awg show'`

### Managing the tunnel

```bash
# Check tunnel status
ssh root@<VPS_IP> 'ip netns exec tg_proxy_ns awg show'

# Check proxy logs
ssh root@<VPS_IP> 'journalctl -u mtproto-proxy -f'

# Restart (recreates namespace + tunnel)
ssh root@<VPS_IP> 'systemctl restart mtproto-proxy'

# Test DC connectivity through tunnel
ssh root@<VPS_IP> 'ip netns exec tg_proxy_ns nc -zw3 149.154.167.50 443 && echo OK'
```

## &nbsp; Configuration

Create a `config.toml` in the project root:

```toml
[general]
use_middle_proxy = true                         # Telemt-compatible ME mode for promo parity
ad_tag = "1234567890abcdef1234567890abcdef"    # Optional alias for [server].tag

[server]
port = 443
backlog = 4096                             # TCP listen queue size
middleproxy_buffer_kb = 256               # Per-connection ME buffers (4x this size), tune for VPS RAM
tag = "1234567890abcdef1234567890abcdef"   # Optional: promotion tag from @MTProxybot

[censorship]
tls_domain = "wb.ru"
mask = true
mask_port = 8443
desync = true
drs = false
fast_mode = true

[access.users]
alice = "00112233445566778899aabbccddeeff"
bob   = "ffeeddccbbaa99887766554433221100"
```

<details>
<summary>Configuration reference</summary>

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `[general]` | `use_middle_proxy` | `false` | Telemt-compatible ME mode for regular DC1..5. Media-path requests still prefer ME endpoints when available; direct fallback can be used if ME endpoints are unavailable |
| `[general]` | `ad_tag` | _(none)_ | Telemt-compatible alias for promotion tag; ignored if `[server].tag` is set |
| `[server]` | `port` | `443` | TCP port to listen on |
| `[server]` | `backlog` | `4096` | TCP listen queue size (for high-traffic loads) |
| `[server]` | `max_connections` | `65535` | Concurrent connection cap. On Linux, runtime is auto-clamped by `RLIMIT_NOFILE` if configured higher than available FD budget |
| `[server]` | `idle_timeout_sec` | `300` | Timeout before first byte from client (helps mobile pool stability) |
| `[server]` | `handshake_timeout_sec` | `60` | Handshake timeout after first byte arrives |
| `[server]` | `middleproxy_buffer_kb` | `256` | MiddleProxy per-connection buffer size in KiB |
| `[server]` | `tag` | _(none)_ | Optional 32 hex-char promotion tag from [@MTProxybot](https://t.me/MTProxybot) |
| `[censorship]` | `tls_domain` | `"google.com"` | Domain to impersonate / forward bad clients to |
| `[censorship]` | `mask` | `true` | Forward unauthenticated connections to `tls_domain` to defeat DPI |
| `[censorship]` | `mask_port` | `443` | Non-standard port override for masking locally (e.g. `8443` for zero-RTT local Nginx) |
| `[censorship]` | `desync` | `true` | Split fake `ServerHello` into `1 byte + short pause + rest` to desynchronize passive DPI |
| `[censorship]` | `drs` | `false` | Dynamic Record Sizing: ramp TLS records from 1369→16384 bytes after warmup (mimics Chrome/Firefox) |
| `[censorship]` | `fast_mode` | `false` | **Recommended** for direct-path traffic. Delegates S2C AES encryption to Telegram DC and reduces proxy CPU/RAM pressure |
| `[access.users]` | `<name>` | -- | 32 hex-char secret (16 bytes) per user |

</details>

> **Operational note** &nbsp; High-churn mobile networks can produce many normal disconnects (`ConnectionResetByPeer`/`EndOfStream`). In release builds these are logged at debug level to keep production logs signal-focused.

> **Operational note** &nbsp; `deploy/mtproto-proxy.service` ships with `LimitNOFILE=131582` (fits `max_connections=65535` with reserve). If your host applies a lower limit, the proxy auto-clamps effective `max_connections` at startup and logs a warning.

> **Tip** &nbsp; Generate a random secret: `openssl rand -hex 16`

> **Note** &nbsp; The configuration format is compatible with the Rust-based `telemt` proxy.

> **Note** &nbsp; MiddleProxy settings (regular DC1..5 endpoints + media-path endpoints + shared secret) are refreshed automatically from Telegram (`getProxyConfig`, `getProxySecret`) with bundled defaults as fallback.

## &nbsp; Troubleshooting ("Updating...")

If your Telegram app is stuck on "Updating...", your provider or network is dropping the connection.

### 0. Runtime expectations (important)

This proxy uses a Linux `epoll` event loop (single-thread relay path). Timeouts are controlled by config (`idle_timeout_sec`, `handshake_timeout_sec`) and event-loop timers. If you see stale guidance mentioning `poll()`/`SO_RCVTIMEO`/fixed max-lifetime, treat it as outdated.

### 1. AAAA exists, but server IPv6 is not actually working

This proxy supports IPv6, but your VPS must have real end-to-end IPv6 routing.
If DNS has an `AAAA` record and the server has no usable global IPv6 route, iOS often tries IPv6 first, waits for timeout, then falls back to IPv4. This usually looks like a ~3-8 second connect delay.

Quick checks:

```bash
dig +short proxy.example.com A
dig +short proxy.example.com AAAA
ip -6 addr show scope global
ip -6 route
```

If `AAAA` exists but the server has no working global IPv6/default route, remove `AAAA` and keep only `A` until IPv6 is fully configured.

### 2. Home Wi-Fi restricts IPv4

Often, mobile networks will connect instantly because they use **IPv6**, but Home Wi-Fi internet providers block the destination's IPv4 address directly at the gateway.
**Solution:** Enable **IPv6 Prefix Delegation** on your home Wi-Fi router. 
- Go to your router's admin panel (e.g., `192.168.1.1`).
- Find the **IPv6** or **WAN/LAN** settings.
- Enable `IPv6`, and specifically check **IA_PD** (Prefix Delegation) for the WAN/DHCP client, and **IA_NA** for the LAN/DHCP Server.
- Reboot the router and verify your phone gets an IPv6 address at [test-ipv6.com](https://test-ipv6.com). 

### 3. Commercial / Premium VPNs Block Traffic

If your iPhone is connected to a **commercial/premium VPN** and stuck on "Updating...", the VPN provider is actively dropping the MTProto TLS traffic using their own DPI.
**Solutions**:
- **Switch Protocol**: Try switching the VPN protocol (e.g., Xray/VLESS to WireGuard).
- **Self-Host**: Use a self-hosted VPN (like AmneziaWG) on your own server.

### 4. Co-located WireGuard (Docker routing)

If you run both this proxy and AmneziaVPN (or a WireGuard Docker container) **on the same server**, iOS clients will route proxy traffic inside the VPN tunnel, and Docker will drop the bridge packets.
**Solution**: Allow traffic from the VPN Docker subnet:
```bash
iptables -I DOCKER-USER -s 172.29.172.0/24 -p tcp --dport 443 -j ACCEPT
```

### 5. DC203 media resets

If only media-heavy sessions fail on non-premium clients, check MiddleProxy logs first:

```bash
sudo journalctl -u mtproto-proxy --since "15 min ago" | grep -E "dc=203|Middle-proxy"
```

On startup the proxy now refreshes DC203 metadata from Telegram automatically. If your server cannot reach `core.telegram.org`, it falls back to bundled defaults.

## &nbsp; License

[MIT](LICENSE) &copy; 2026 XXcipherX
