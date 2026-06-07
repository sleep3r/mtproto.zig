<div align="center">

# mtproto.zig

**让你所爱的人始终保持联系。**

一个运行在你自己服务器上的小巧 Telegram 代理。它隐藏在普通的 HTTPS 流量之中，让审查无从发现 —— 你的家人也不会再失去它。一条命令即可部署，一个链接即可分享。

`177 KB · under 1 MB RAM · 0 dependencies` —— 没错，它就是这么精简 *(详见下文 ↓)*

<sub>技术上讲：一个用 Zig 编写、零依赖的小巧 MTProto 代理，能将 Telegram 流量伪装成标准的 TLS 1.3 HTTPS。</sub>

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/zig-0.16.0-f7a41d.svg?logo=zig&logoColor=white)](https://ziglang.org)
[![Platform](https://img.shields.io/badge/platform-linux-blueviolet.svg?logo=linux&logoColor=white)](#install)

<div align="center">

| [🇬🇧 English](README.md) | [🇷🇺 Русский](README.ru.md) | **🇨🇳 中文** | [🇮🇷 فارسی](README.fa.md) | [🇻🇳 Tiếng Việt](README.vi.md) |
| :-: | :-: | :-: | :-: | :-: |

</div>

</div>

---

<p align="center">
<a href="#为什么不直接用-vpn">为何选它？</a> · <a href="#安装">安装</a> · <a href="#更新">更新</a> · <a href="#其他-mtbuddy-命令">命令</a> · <a href="#上游路由">路由</a> · <a href="#配置">配置</a> · <a href="#监控面板">监控面板</a> · <a href="#本地构建">构建</a> · <a href="#docker">Docker</a> · <a href="#信任与安全">信任</a> · <a href="#已知限制与兼容性">兼容性</a> · <a href="#故障排查--卡在-updating">FAQ</a>
</p>

---

## 适用人群

- **你所在的地方 Telegram 被限速或被封锁**，而你只想把它找回来。
- **你是家人遇事会求助的那个人** —— 你希望用一个只需点一次、之后再也无需操心的链接，保护你的父母和朋友。

它运行在**你自己的服务器**上 —— 你的消息绝不会经过我们的服务器，也无需注册任何账号。基于 MIT 开源；代理刻意从不记录密钥，也不记录谁连接过。

## 为什么不直接用 VPN？

VPN 会暴露自己 —— 审查者能识别其协议并加以封锁，而全设备 VPN 既慢又耗电。本项目看起来就像一个普通的 HTTPS 网站，只承载 Telegram 流量，而你分享给的人**无需安装任何东西**：他们点一下链接，剩下的交给 Telegram。它足够小巧，能跑在你能租到的最便宜的 VPS 上，启动即用，无需任何额外设置。

## 与其他 MTProto 代理的对比

大多数 MTProto 代理体积庞大、依赖繁多、占用大量内存。本项目则截然不同：

| 代理 | 语言 | 二进制大小 | 基准 RSS | 启动时间 | 依赖 |
|---|---|---:|---:|---|---|
| **mtproto.zig** | Zig | **177 KB** | **0.75 MB** | **< 10 ms** | **0** |
| 官方 MTProxy | C | 524 KB | 8.0 MB | < 10 ms | openssl, zlib |
| Telemt | Rust | 15 MB | 12.1 MB | ~ 5-6 s | 423 个 crate |
| mtg | Go | 13 MB | 11.6 MB | ~ 30 ms | 78 个模块 |
| MTProtoProxy | Python | N/A | ~ 30 MB | ~ 300 ms | python3, cryptography |
| JSMTProxy | Node.js | N/A | ~ 45 MB | ~ 400 ms | nodejs, openssl |

## 为什么选 Zig？

我们选择 Zig，是因为它提供了 C 那样的原始性能和极小的体积，却没有内存不安全问题，也没有构建系统的噩梦：
- **无任意分配：** 所有连接槽和缓冲区都在启动时预先分配。没有垃圾回收器在高负载下丢帧。
- **封闭式交叉编译：** 在 macOS 上运行 `zig build`，就能产出一个静态链接的 Linux 二进制文件。无需 Docker，也没有 `glibc` 版本不匹配的问题。
- **Comptime（编译期计算）：** 协议定义映射、字节序转换以及 `mtbuddy` 的双语字符串查找等昂贵操作都在编译期完成，从而实现瞬时启动。

**下面这些名词你完全不用懂 —— 默认安装会为你全部开启。** 在底层，本代理叠加的反审查技术比任何其他 MTProto 代理都多，并且会随着封锁手段变得更聪明而持续适配：

| 技术 | 作用 |
|---|---|
| **Fake TLS 1.3** | 在 DPI 看来，连接就像普通的 HTTPS |
| **DRS** | 模仿 Chrome/Firefox 的 TLS 记录大小 |
| **主动探测伪装** | 如果审查者主动探测你的服务器，它会从本地 Web 后端获得一次真实的 TLS 握手（如果你拥有该域名则用真实证书，否则用自签名证书），而不是一个会暴露身份、沉默不语的代理。可选：为 single-round-x25519 域名直接前置真实的 `tls_domain:443` |
| **TCPMSS=88** | 将 ClientHello 分片到 6 个 TCP 包中，破坏 DPI 的重组 |
| **nfqws TCP desync** | 发送伪造数据包 + TTL 受限的分片，迷惑有状态的 DPI |
| **Split-TLS** | 使用 1 字节的 Application 记录，挫败被动特征匹配 |
| **VPN 隧道** | 在 DC 被封锁时，通过显式的套接字策略路由（SO_MARK）经 WireGuard/AmneziaWG 转发 |
| **IPv6 跳变** | 检测到被封时，通过 Cloudflare API 从 /64 段自动轮换 IPv6 地址 |
| **防重放** | 拒绝重放的握手 + 检测 ТСПУ Revisor 主动探测 |
| **多用户** | 每个用户拥有独立的密钥 |
| **MiddleProxy** | ME 传输，自动刷新 Telegram 元数据 |

推广标签（promotion tag）以及非 Premium 账号的媒体内容都需要 MiddleProxy。没有它，非 Premium 账号上的照片、视频、故事及其他媒体应被视为不可用，而非时好时坏。本代理不支持 Telegram 通话：Telegram 只通过 SOCKS 风格的路径路由通话，而暴露的 SOCKS 流量无法被 mtproto.zig 伪装成普通的 HTTPS。

---

## 安装

所有的安装、更新和管理都通过 **mtbuddy** 完成 —— 这是一个随代理一同发布的原生 Zig 命令行工具。

### 一条命令

```bash
curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/bootstrap.sh | sudo bash

# Explicitly allow unsigned bootstrap mode (not recommended)
curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/bootstrap.sh | sudo bash -s -- --insecure
# or: MTPROTO_INSECURE=1
```

这会下载最新的 `mtbuddy` 二进制文件，从 GitHub Release 验证 minisign 签名 + SHA-256 校验和，然后运行 `mtbuddy --help`。接着安装代理：

```bash
# Minimal — auto-generates a secret, enables all DPI bypass modules
sudo mtbuddy install --port 443 --domain rutube.ru --yes

# Bring your own secret and username
sudo mtbuddy install --port 443 --domain rutube.ru --secret <32-hex> --user alice --yes

# Disable all DPI modules (bare proxy only)
sudo mtbuddy install --port 443 --domain rutube.ru --no-dpi --yes

# Install using an existing config file (auto-maps port and domain)
sudo mtbuddy install --config /path/to/config.toml --yes

# Explicitly allow unsigned mode (not recommended)
sudo mtbuddy install --insecure --port 443 --domain rutube.ru --yes
```

最后，mtbuddy 会打印一条可直接使用的 `tg://` 连接链接。

> **把它分享给你所爱的人。** 把下面这段话连同链接一起发给他们：
> *“我为我们搭了一扇通往 Telegram 的私人之门。点一下这个链接，选择「连接」，Telegram 就又能用了 —— 无需安装、无需付费，而且只属于我们。”*

### 交互式向导

如果你更希望有人一步步引导你完成设置：

```bash
sudo mtbuddy --interactive
```

<details>
<summary>演示：交互式安装程序</summary>
<br>
<p align="center">
  <img src="https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/assets/buddy.gif" alt="演示：交互式安装程序" width="80%">
</p>
<br>

</details>

### 安装过程做了什么

1. 从 GitHub Releases 下载**预编译的代理二进制文件**（自动检测 CPU：`x86_64_v3` → `x86_64` → `aarch64`）
2. 生成一个随机密钥（或使用 `--secret`）
3. 创建一个 systemd 服务（`mtproto-proxy`）
4. 在 `ufw` 中开放端口（如果 ufw 已启用）
5. 应用 TCPMSS=88 的 iptables 规则
6. 设置 Nginx 伪装 + nfqws TCP desync（除非使用 `--no-dpi`）
7. 打印 `tg://` 链接

### 安装选项

| 选项 | 默认值 | 说明 |
|---|---|---|
| `--port, -p` | `443` | 代理监听端口 |
| `--public-port` | — | 在生成的 Telegram 链接中公布的端口 |
| `--domain, -d` | `rutube.ru` | TLS 伪装域名（⚠️ **不可更改** —— 见下方注意事项） |
| `--secret, -s` | auto | 用户密钥（32 个十六进制字符） |
| `--user, -u` | `user` | `config.toml` 中的用户名 |
| `--config, -c` | — | 使用现有的 `config.toml` 文件 |
| `--yes, -y` | — | 跳过确认提示 |
| `--max-connections <N>` | `512` | 最大代理连接数 |
| `--bind, -b` | — | 绑定到指定 IP（默认：所有网络接口） |
| `--no-masking` | — | 禁用 Nginx 伪装 |
| `--no-nfqws` | — | 禁用 nfqws TCP desync |
| `--no-tcpmss` | — | 禁用 TCPMSS 钳制 |
| `--tcpmss <n>` | `88` | TCPMSS 钳制值（强制 ClientHello 分片） |
| `--no-dpi` | — | 禁用所有 DPI 模块 |
| `--middle-proxy` | — | 启用 Telegram MiddleProxy 中继 |
| `--ipv6-hop` | — | 启用 IPv6 自动跳变 |
| `--version, -v <tag>` | `latest` | 要安装的发布版本 |
| `--insecure` | — | 允许未签名的文件（不推荐） |

> ⚠️ **`--domain` 只能选定一次。** tg:// 链接中嵌入了 `tls_domain`，因此在已上线的部署上更改它
> （包括通过 `mtbuddy setup masking --domain …`）**会使你已经分享出去的每一个链接
> 全部失效。** 参见 [ARCHITECTURE.md](ARCHITECTURE.md) / [COMPATIBILITY.md](COMPATIBILITY.md)。

---

## 更新

```bash
# Update to latest release (verifies minisign + checksum, checks CPU compat, auto-rollback on failure)
sudo mtbuddy update

# Pin to a specific version
sudo mtbuddy update --version v0.11.1

# Explicitly allow unsigned mode (not recommended)
sudo mtbuddy update --insecure
```

---

## 其他 mtbuddy 命令

```bash
# Show proxy and module status
sudo mtbuddy status

# Validate and inspect config
sudo mtbuddy config validate
sudo mtbuddy config doctor
sudo mtbuddy config doctor --network
sudo mtbuddy config print-effective

# Print Telegram proxy links from config.toml (FakeTLS ee by default; +dd when fake_tls_only=false; sensitive output)
sudo mtbuddy links
sudo mtbuddy links --server proxy.example.com --config /opt/mtproto-proxy/config.toml

# Generate a fresh 32-hex user secret
mtbuddy secret

# Hot-reload config (SIGHUP, reloadable settings only)
sudo mtbuddy reload

# Setup DPI modules after the fact
sudo mtbuddy setup masking --domain rutube.ru
sudo mtbuddy setup nfqws
sudo mtbuddy setup recovery

# Install web monitoring dashboard
sudo mtbuddy setup dashboard

# VPN tunnel (for servers where Telegram DCs are blocked)
sudo mtbuddy setup tunnel /path/to/awg0.conf
sudo mtbuddy setup tunnel 'vpn://...'
sudo mtbuddy setup tunnel --iface awg1 /path/to/awg1.conf

# IPv6 hopping
sudo mtbuddy ipv6-hop --check
sudo mtbuddy ipv6-hop --auto --prefix 2a01:abcd:ef00:: --threshold 5

# Update Cloudflare DNS A record
sudo mtbuddy update-dns 1.2.3.4

# Full help
mtbuddy --help
mtbuddy --lang ru --help
```

---

## 服务管理

```bash
sudo systemctl status mtproto-proxy
sudo journalctl -u mtproto-proxy -f
sudo systemctl reload mtproto-proxy   # SIGHUP hot-reload (where possible)
sudo systemctl restart mtproto-proxy
```

---

## 上游路由

本代理支持多种方式将出站连接路由到 Telegram DC 服务器。

### 路由模式

| `[upstream].type` | 工作方式 | 适用场景 |
|---|---|---|
| `auto`（默认） | 直接出站，不带隧道策略标记 | 大多数部署 |
| `direct` | 从主机直接连接 Telegram DC | 服务器可直达 DC |
| `tunnel` | 直接连接，通过 `SO_MARK=200` 经 VPN 隧道池进行策略路由 | DC 被 ISP 封锁 |
| `socks5` | 通过外部 SOCKS5 代理路由，可选认证 | 已有代理基础设施 |
| `http` | 通过 HTTP CONNECT 代理路由，可选认证 | 企业代理环境 |

### VPN 隧道

如果你的 VPS 位于 Telegram DC 在网络层被封锁的地区，你可以通过带显式套接字策略路由的 VPN 隧道池来路由代理流量。代理运行在主机命名空间中；只有被代理标记（`SO_MARK=200`）的套接字才会经由路由表 200 转发。`mtbuddy` 会让该路由表始终指向配置顺序中第一个健康的隧道。

当前支持的 VPN 类型：
- **AmneziaWG** —— 抗 DPI 的 WireGuard 分支（推荐用于俄罗斯/伊朗）
- **WireGuard** —— 标准 WireGuard（计划中）

```
Client → mtproto-proxy (host namespace)
                     │
                SO_MARK=200
                     │
        Linux policy routing table 200
                     │
          awg0 / awg1 / ... (pool)
                     │
             Telegram DC servers
```

```bash
sudo mtbuddy setup tunnel /path/to/awg0.conf
# or paste an Amnezia share link directly
sudo mtbuddy setup tunnel 'vpn://...'

# Add or replace a specific pool member
sudo mtbuddy setup tunnel --iface awg1 /path/to/awg1.conf
```

在 `mtbuddy` 的交互式菜单中，隧道设置会先询问 VPN 类型（目前为 AmneziaWG），然后显示当前的隧道池。选择 **Create new tunnel** 可追加下一个空闲的 `awgN`，或选择某个现有接口来替换该隧道池成员的配置。

`mtbuddy` 会保持 `[general].use_middle_proxy` 不变，只配置传输方式（`[upstream].type = "tunnel"`）。
设置完成后，它会安装 `mtproto-tunnel-pool.timer`，校验通往 Telegram DC 地址段的策略路由（`mark 200`），并打印操作命令。隧道池控制器会通过每条隧道探测 Telegram，并用 `ip route replace` 重写路由表 200；自动故障切换不会重启 `mtproto-proxy`。

你也可以在 `config.toml` 中显式配置隧道接口：

```toml
[upstream]
type = "tunnel"

[upstream.tunnel]
interface = "awg0"
interfaces = ["awg0", "awg1"]
pinned_interface = ""   # optional; empty means priority auto-failback
```

### SOCKS5 代理

通过外部 SOCKS5 代理路由 DC 连接。支持 RFC 1928 认证。

```toml
[upstream]
type = "socks5"

[upstream.socks5]
host = "127.0.0.1"
port = 1080
username = "admin"    # optional, omit for no-auth
password = "secret"
```

### HTTP CONNECT 代理

通过 HTTP CONNECT 代理路由 DC 连接。支持 Basic 认证。

```toml
[upstream]
type = "http"

[upstream.http]
host = "127.0.0.1"
port = 8080
username = "admin"    # optional, omit for no-auth
password = "secret"
```

> **注意：** 通往 DC 的中继流量以及 MiddleProxy 元数据刷新（`getProxyConfig` / `getProxySecret`）会使用所配置的上游。伪装（掩护）连接始终直连。
>
> **依赖说明：** “零依赖”的说法适用于默认的 `auto`/`direct` 出站方式。在 `socks5`、`http` 或 `tunnel` 上游模式下，MiddleProxy 元数据刷新会调用外部的 `curl`，因此主机上必须安装 `curl`（标准安装程序会自动安装它）。

---

## 配置

配置文件位于 `/opt/mtproto-proxy/config.toml`。MTBuddy 会在安装时生成它；你也可以手动编辑后重启：

```toml
[general]
use_middle_proxy = true   # ME mode for promo-channel parity

[upstream]
type = "auto"            # auto | direct | tunnel | socks5 | http
# allow_direct_fallback = false   # fail-closed by default for socks5/http misconfig

[server]
port = 443
# public_ip = "proxy.example.com"   # Inbound IP/domain used in client links
# public_port = 443                 # Link port when behind HAProxy/Nginx
# middle_proxy_nat_ip = "203.0.113.10"   # Outbound IPv4 seen by Telegram MiddleProxy
max_connections = 512
# workers = 1            # SO_REUSEPORT epoll workers: 1 = single-threaded (default); 0 = one per CPU; N spreads load across cores
idle_timeout_sec = 120
handshake_timeout_sec = 15
graceful_shutdown_timeout_sec = 15
log_level = "info"        # debug | info | warn | err
rate_limit_per_subnet = 0   # 0 = disabled (default; avoids carrier-NAT false positives). Set e.g. 30 for non-NAT hosts
handshake_flood_guard_enabled = true
handshake_flood_guard_threshold = 20
handshake_flood_guard_window_sec = 30
handshake_flood_guard_block_sec = 120
tag = ""                  # Optional: promotion tag from @MTProxybot

[censorship]
tls_domain = "rutube.ru"
mask = true
# mask_target = "host.docker.internal" # Optional: custom masking backend host (Docker/remote Nginx)
mask_port = 8443          # 8443 = local Nginx backend (what mtbuddy installs); 443 = front the real tls_domain (opt-in, single-round-x25519 domains only)
fast_mode = true          # Recommended: delegates S2C AES to the DC, saves CPU/RAM
drs = true                # Dynamic Record Sizing (mimics Chrome/Firefox)

[access.users]
alice = "00112233445566778899aabbccddeeff"
bob   = "ffeeddccbbaa99887766554433221100"

[access.direct_users]
alice = true   # bypass MiddleProxy for this user
```

<details>
<summary>完整配置参考</summary>

| 配置项 | 默认值 | 说明 |
|-----|---------|-------------|
| `[upstream].type` | `auto` | 出站模式：`auto`（直连）、`direct`、`tunnel`（通过套接字策略路由走 VPN）、`socks5` 或 `http` |
| `[upstream] allow_direct_fallback` | `false` | 若为 `true`，则在上游不可用时允许 socks5/http 模式回退到直接出站 |
| `[upstream.tunnel] interface` | `"awg0"` | 旧版单隧道接口 / SO_MARK 路由的回退项 |
| `[upstream.tunnel] interfaces` | `["awg0"]` | 有序的隧道池；第一个健康的接口优先生效 |
| `[upstream.tunnel] pinned_interface` | — | 可选的手动优先项，在其健康时优先于有序隧道池使用 |
| `[upstream.socks5] host` | — | SOCKS5 代理地址 |
| `[upstream.socks5] port` | — | SOCKS5 代理端口 |
| `[upstream.socks5] username` | — | SOCKS5 用户名（留空 = 无认证） |
| `[upstream.socks5] password` | — | SOCKS5 密码 |
| `[upstream.http] host` | — | HTTP CONNECT 代理地址 |
| `[upstream.http] port` | — | HTTP CONNECT 代理端口 |
| `[upstream.http] username` | — | HTTP 代理用户名（留空 = 无认证） |
| `[upstream.http] password` | — | HTTP 代理密码 |
| `[general] use_middle_proxy` | `false` | 针对 DC1..5 的 ME 模式（推荐，以与推广功能保持一致） |
| `[general] ad_tag` | — | `[server].tag` 的别名 |
| `[server] port` | `443` | TCP 监听端口 |
| `[server] bind_address` | — | 用于绑定监听套接字的指定 IP（默认：所有网络接口） |
| `[server] public_ip` | auto | 在客户端链接中显示的入站 IP/域名。使用 VPN 隧道时必填；若客户端在 IPv6 链接上连接失败，请显式设置 IPv4 |
| `[server] public_port` | `[server].port` | 在客户端链接中显示的端口；当 HAProxy/Nginx 对外暴露不同的公共端口时很有用 |
| `[server] middle_proxy_nat_ip` | auto | 用于 MiddleProxy 密钥派生的出站 IPv4；与 `public_ip` 相互独立地自动检测，当 DC 流量经 VPN/NAT IP 出站时请显式设置 |
| `[server] backlog` | `4096` | TCP 监听队列深度 |
| `[server] max_connections` | `512` | 并发连接上限，会根据 RAM 和 `RLIMIT_NOFILE` 自动钳制 |
| `[server] workers` | `1` | SO_REUSEPORT epoll 工作线程数。`1` = 单线程；`0` = 每个 CPU 一个；`N` 将中继/加密负载分散到多个核心。当 `>1` 时，SIGHUP 配置重载需要重启 |
| `[server] idle_timeout_sec` | `120` | 连接空闲超时 |
| `[server] handshake_timeout_sec` | `15` | 握手完成超时 |
| `[server] graceful_shutdown_timeout_sec` | `15` | 强制关闭前 SIGTERM 排空超时 |
| `[server] middleproxy_buffer_kb` | `1024` | ME 每连接缓冲区（KiB）。低于 1024 在媒体流量下可能导致溢出 |
| `[server] tag` | — | 来自 [@MTProxybot](https://t.me/MTProxybot) 的 32 个十六进制字符推广标签 |
| `[server] log_level` | `"info"` | `debug` / `info` / `warn` / `err` |
| `[server] rate_limit_per_subnet` | `0` | 每个 /24（IPv4）或 /48（IPv6）每秒最大新建连接数。`0` = 禁用（默认，对 NAT 友好）；非 NAT 主机可设为如 `30` |
| `[server] handshake_flood_guard_enabled` | `true` | 临时拒绝那些反复 MTProto 握手失败的具体源 IP |
| `[server] handshake_flood_guard_threshold` | `20` | 每个源 IP 触发临时拒绝前所允许的错误握手/限速/预算事件数 |
| `[server] handshake_flood_guard_window_sec` | `30` | `handshake_flood_guard_threshold` 的滚动时间窗口 |
| `[server] handshake_flood_guard_block_sec` | `120` | 对喧闹源 IP 的临时拒绝时长 |
| `[server] unsafe_override_limits` | `false` | 禁用对 `max_connections` 的自动钳制 |
| `[monitor] host` | `"127.0.0.1"` | 面板绑定地址 |
| `[monitor] port` | `61208` | 面板端口 |
| `[metrics] enabled` | `false` | 启用内置的 Prometheus `/metrics` 端点 |
| `[metrics] host` | `"127.0.0.1"` | 指标绑定地址 |
| `[metrics] port` | `9400` | 指标端口 |
| `[censorship] tls_domain` | `"google.com"` | 要冒充的域名 |
| `[censorship] mask` | `true` | 将未认证的客户端转发到 `tls_domain` |
| `[censorship] mask_target` | unset | 被伪装客户端的可选后端主机 |
| `[censorship] mask_port` | `443` | 本地伪装端口（Nginx zero-RTT 时使用 `8443`） |
| `[censorship] desync` | `true` | Split-TLS：1 字节的 Application 记录 |
| `[censorship] drs` | `false` | 动态记录大小调整（Dynamic Record Sizing） |
| `[censorship] fast_mode` | `false` | 将 S2C 加密委托给 DC（推荐） |
| `[access.users] <name>` | — | 每个用户的 32 个十六进制字符密钥 |
| `[access.direct_users] <name>` | — | 为该用户绕过 ME |

</details>

> 生成密钥：`mtbuddy secret` 或 `openssl rand -hex 16`
>
> 显式打印客户端链接：`sudo mtbuddy links`。默认情况下它只打印 FakeTLS（`ee...domain`）链接；当启用 `dd` 传输（`fake_tls_only = false`）时，它也会打印安全填充（`dd...`）链接。运行时的代理日志会刻意隐藏密钥和代理链接。
>
> **`dd`（“安全”/填充）传输默认被拒绝**（`[censorship].fake_tls_only = true`）—— 它是纯粹混淆的 MTProto，**没有任何 TLS 伪装**，可被 DPI 直接识别为 MTProto 特征。默认情况下代理只接受 FakeTLS（`ee`），且 `mtbuddy links` 只打印 `ee` 链接。若要发放 `dd` 链接（低 DPI / 兼容性场景），请设置 `fake_tls_only = false`。参见 [THREAT_MODEL.md](THREAT_MODEL.md)。
>
> 每子网的新建连接速率限制**默认关闭**（`rate_limit_per_subnet = 0`），以免大型运营商 NAT 或共享办公网络（许多合法客户端共用一个 IP/子网）被误判。握手洪水防护保持开启，但在子网限制关闭的情况下，它只对被放弃/未完成的握手起作用 —— 而合法的密钥持有者几乎从不产生这类握手。如果你仍看到 `flood_guard+` 在突发流量中拦截真实用户，请调高 `handshake_flood_guard_threshold` / 窗口 / 拦截时长，或设置 `handshake_flood_guard_enabled = false`。只在单租户 / 非 NAT 主机上启用 `rate_limit_per_subnet`。

---

## 监控面板

一个轻量级的 Web 面板（约 30 MB RAM）展示实时连接、CPU/内存、网络吞吐、代理统计、隧道池健康/故障切换状态、用户管理以及流式日志。

该面板**直接内嵌在 `mtbuddy` 二进制文件中** —— 无需任何额外文件。

```bash
# Install the dashboard on the server
sudo mtbuddy setup dashboard

# Open via SSH tunnel (binds to 127.0.0.1:61208 by default)
ssh -L 61208:localhost:61208 root@<server_ip>
# → http://localhost:61208
```

该面板需要 **HTTP Basic 认证**（用户名：任意；密码自动生成于 `/opt/mtproto-proxy/monitor/dashboard.token` —— 在服务器上 `cat` 查看）。它是一个具有 root 权限的控制平面，因此请将其保留在回环/SSH 隧道路径上，切勿将明文 HTTP 暴露到公网 —— 如确有需要，请在其前面加上 HTTPS + 反向代理。

<details>
<summary>演示：监控面板</summary>
<br>
<p align="center">
  <img src="https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/assets/dashboard.gif" alt="演示：监控面板" width="80%">
</p>
<br>

</details>

---

## Prometheus 指标

`mtproto-proxy` 可以在专用端口上暴露一个内置的、兼容 Prometheus 的指标端点。

若需要一套完整的、基于 Docker 的监控栈（包含 `mtproto-zig`、Prometheus、Grafana 以及可导入的仪表盘），请参见 [hack/docker/README.md](hack/docker/README.md)。

```toml
[metrics]
enabled = true
host = "127.0.0.1"
port = 9400
```

该端点为明文 HTTP，提供：

```text
GET /metrics
```

典型的 Docker 用法：

```bash
docker run --rm \
  -p 443:443 \
  -p 9400:9400 \
  -v "$PWD/config.toml:/etc/mtproto-proxy/config.toml:ro" \
  mtproto-zig
```

它会暴露代理计数器，以及诸如 RSS、虚拟内存、CPU 时间和已打开文件描述符等进程指标。

---

## 本地构建

需要 [Zig 0.16.0](https://ziglang.org/download/)。

```bash
git clone https://github.com/sleep3r/mtproto.zig.git
cd mtproto.zig

make build      # cross-compile ReleaseFast binaries for Linux x86_64_v3+aes
make test       # run Zig tests
make e2e        # run E2E/integration harness
make fmt        # format Zig sources
make deploy     # build + deploy to SERVER (see Makefile)
make dashboard  # SSH tunnel for web dashboard (localhost:61208)

# optional performance checks
zig build bench
zig build soak
```

发布构建者如有需要，可以覆盖默认固定的 minisign 密钥：

```bash
zig build -Dminisign_pubkey=RW... -Doptimize=ReleaseFast -Dtarget=x86_64-linux
```

在 macOS 上交叉编译 Linux 版本：

```bash
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux -Dcpu=x86_64_v3+aes
scp zig-out/bin/mtproto-proxy root@<SERVER>:/opt/mtproto-proxy/
```

---

## Docker

提供 Docker 支持是为了测试、打包实验，以及只需要代理二进制文件的简单部署。本项目主要面向由 `mtbuddy` 管理的原生 Linux 主机：DPI 模块、隧道池故障切换、策略路由、Nginx 伪装、nfqws 以及恢复定时器都是主机级别的集成，容器无法完整体现这些功能。

```bash
docker pull ghcr.io/sleep3r/mtproto.zig:latest

docker run --rm \
  -p 443:443 \
  -v "$PWD/config.toml:/etc/mtproto-proxy/config.toml:ro" \
  ghcr.io/sleep3r/mtproto.zig:latest
```

MiddleProxy 的媒体/推广流量对其加密握手中使用的出站源 IP:port 很敏感。对于需要 MiddleProxy 的 Docker 部署，建议使用主机网络（`--network host`）或原生的 `mtbuddy` 安装。`[server].public_ip` 只是显示给客户端的入站地址；如果出站 DC 流量经由 VPN/NAT IP 出去，请将 `[server].middle_proxy_nat_ip` 设置为该出站 IPv4。会重写源端口的桥接或远程 NAT 仍可能破坏 MiddleProxy 握手。

本地构建：

```bash
docker build -t mtproto-zig .
# multi-arch
docker buildx build --platform linux/amd64,linux/arm64 -t your-registry/mtproto-zig:latest --push .
```

发布的 `linux/amd64` 镜像使用可移植的 CPU 配置（`-Dcpu=x86_64`）构建，以避免在较旧的 VPS CPU 上出现 `Illegal instruction` 崩溃。

> 对于生产环境的反审查部署，请优先使用原生的 `mtbuddy install` 流程。操作系统级别的缓解措施（iptables TCPMSS、nfqws、隧道策略路由、伪装/恢复单元）不会在容器内应用；容器中只运行代理二进制文件。

---

## 信任与安全

- [SECURITY.md](SECURITY.md) - 漏洞报告政策与响应流程
- [THREAT_MODEL.md](THREAT_MODEL.md) - 安全目标、非目标、对手模型、残余风险
- [CONTRIBUTING.md](CONTRIBUTING.md) - 开发工作流（`fmt`/`test`/`e2e`/`bench`）与 PR 期望
- [CHANGELOG.md](CHANGELOG.md) - 发布历史
- [LICENSE](LICENSE) - MIT 许可证条款

仓库治理：
- [`.github/CODEOWNERS`](.github/CODEOWNERS)
- [`.github/ISSUE_TEMPLATE`](.github/ISSUE_TEMPLATE) 下的 issue 模板

---

## 已知限制与兼容性

完整模型请参见 [THREAT_MODEL.md](THREAT_MODEL.md)。以下是简要的运行要点：

- **已知限制**
  - 这是一个用于加固传输的代理，而非匿名网络。
  - 随着 DPI 策略不断演进，绕过效果可能会下降。
  - 面板/指标默认为明文；未经认证/TLS 时切勿公开暴露。
  - Telegram 通话无法通过本代理使用。通话需要 Telegram 的 SOCKS 风格通话路径，这超出了 MTProto/TLS 伪装模型的范围，在此无法被干净地伪装成普通 HTTPS。
  - 没有 MiddleProxy（`[general].use_middle_proxy = true`），非 Premium 账号上的媒体内容将无法加载。照片、视频、故事和推广标签都需要 MiddleProxy。
- **特定地区注意事项**
  - ISP 的行为因国家/地区而异；配置无法通用移植。
  - IPv6 与 AAAA 的处理在不同服务商之间差异很大，可能影响 iOS/桌面端的连接延迟。
  - 隧道路由取决于主机的策略路由以及该地区所允许的 VPN 协议。
- **Telegram 客户端兼容性**
  - 官方 Telegram Android/iOS/桌面端：预期在当前版本上可正常工作。
  - 第三方客户端：仅尽力而为。
- **内核/操作系统兼容性矩阵**
  - Linux `x86_64`：支持（主要目标）
  - Linux `aarch64`：支持
  - Linux 上的 Docker：有保留地支持（操作系统级别的 DPI 模块在主机侧）
  - macOS/Windows 运行时：不支持（仅支持 Linux 运行时目标）
- **Telegram/DC 变更后可能出问题的地方**
  - MiddleProxy 元数据与端点行为
  - 较新 Telegram 客户端中的握手预期
  - DC/媒体路由的边缘情况（例如 DC203 的行为）

---

## 故障排查 — 卡在 “Updating...”

**1. 存在 AAAA 记录，但服务器上的 IPv6 不可用。**
DNS 中有 AAAA → iOS 会先尝试 IPv6 → 超时 → 缓慢回退到 IPv4。
解决：在 IPv6 路由完全配置好之前移除 AAAA 记录。

```bash
dig +short proxy.example.com AAAA
ip -6 route
```

**2. 家庭 Wi-Fi 封锁了服务器的 IPv4。**
移动网络通常可用（它们使用 IPv6）。家用路由器常常会封锁目标 IPv4。
解决：在你的路由器上启用 IPv6 前缀委派（IA_PD）。

**3. VPN 正在丢弃 MTProto 流量。**
商业 VPN 常常会对流量做 DPI 并丢弃代理流量。
解决：更换 VPN 协议，或使用自建的 AmneziaWG。

**4. 同一服务器上同时部署了 WireGuard/Docker。**
Docker 的网桥会丢弃来自 VPN 子网的数据包。
解决：`iptables -I DOCKER-USER -s 172.29.172.0/24 -p tcp --dport 443 -j ACCEPT`

**5. 非 Premium 客户端上 DC203 媒体连接被重置。**
检查日志：`journalctl -u mtproto-proxy | grep -E "dc=203|Middle"`。
代理会在启动时从 Telegram 自动刷新 DC203 元数据。如果 `core.telegram.org` 不可达，它会使用内置的回退地址。
在 `[upstream].type = "socks5"` 或 `"http"` 下，元数据刷新会使用该上游；运行 `sudo mtbuddy config doctor --network` 以验证代理端点和 Telegram 元数据获取路径。

---

## 许可证

[MIT](LICENSE) © 2026 Aleksandr Kalashnikov
