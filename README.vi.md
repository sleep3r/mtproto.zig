<div align="center">

# mtproto.zig

**Giữ kết nối cho những người bạn yêu thương.**

Một proxy Telegram nhỏ gọn mà bạn tự chạy trên máy chủ của riêng mình. Nó ẩn mình bên trong lưu lượng HTTPS thông thường, nên kiểm duyệt không thể tìm ra — và gia đình bạn cũng không thể mất nó. Một lệnh để cài đặt, một liên kết để chia sẻ.

`177 KB · under 1 MB RAM · 0 dependencies` — đúng vậy, nó gọn nhẹ đến thế *(chi tiết bên dưới ↓)*

<sub>Về mặt kỹ thuật: một MTProto proxy nhỏ gọn, không phụ thuộc, viết bằng Zig, ngụy trang lưu lượng Telegram thành HTTPS TLS 1.3 tiêu chuẩn.</sub>

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/zig-0.16.0-f7a41d.svg?logo=zig&logoColor=white)](https://ziglang.org)
[![Platform](https://img.shields.io/badge/platform-linux-blueviolet.svg?logo=linux&logoColor=white)](#cài-đặt)

<div align="center">

| [🇬🇧 English](README.md) | [🇷🇺 Русский](README.ru.md) | [🇨🇳 中文](README.zh.md) | [🇮🇷 فارسی](README.fa.md) | **🇻🇳 Tiếng Việt** |
| :-: | :-: | :-: | :-: | :-: |

</div>

</div>

---

<p align="center">
<a href="#so-với-các-mtproto-proxy-khác">Vì sao chọn nó?</a> · <a href="#cài-đặt">Cài đặt</a> · <a href="#cập-nhật">Cập nhật</a> · <a href="#các-lệnh-mtbuddy-khác">Lệnh</a> · <a href="#định-tuyến-upstream">Định tuyến</a> · <a href="#cấu-hình">Cấu hình</a> · <a href="#bảng-điều-khiển-giám-sát">Bảng điều khiển</a> · <a href="#tự-build-cục-bộ">Build</a> · <a href="#docker">Docker</a> · <a href="#tin-cậy--bảo-mật">Tin cậy</a> · <a href="#hạn-chế-đã-biết--khả-năng-tương-thích">Tương thích</a> · <a href="#khắc-phục-sự-cố--kẹt-ở-updating">Hỏi đáp</a>
</p>

---

## Dành cho ai

- **Bạn sống ở nơi Telegram bị bóp băng thông hoặc bị chặn** và bạn chỉ muốn dùng lại nó.
- **Bạn là người mà gia đình tìm đến khi cần giúp đỡ** — và bạn muốn bảo vệ cha mẹ cùng bạn bè bằng một liên kết họ chỉ cần chạm một lần rồi không bao giờ phải bận tâm nữa.

Nó chạy trên **máy chủ của riêng bạn** — tin nhắn của bạn không bao giờ đi qua máy chủ của chúng tôi, và không có gì phải đăng ký. Mã nguồn mở theo giấy phép MIT; proxy được thiết kế để không bao giờ ghi log các secret hay ai đã kết nối.

## Tại sao không chỉ dùng VPN?

Một VPN tự để lộ mình — bên kiểm duyệt nhận ra giao thức và chặn nó, hơn nữa VPN cho toàn thiết bị thì chậm và hao pin. Cái này trông như một website HTTPS bình thường, chỉ chuyển lưu lượng Telegram, và những người bạn chia sẻ **không phải cài gì cả**: họ chạm một liên kết và Telegram lo phần còn lại. Đủ nhỏ để chạy trên chiếc VPS rẻ nhất bạn có thể thuê, nó khởi động tức thì, và không có gì khác phải thiết lập.

## So với các MTProto proxy khác

Hầu hết các MTProto proxy đều cồng kềnh, lệ thuộc nhiều thư viện và ngốn nhiều bộ nhớ. Cái này thì khác:

| Proxy | Ngôn ngữ | Binary | RSS cơ bản | Khởi động | Phụ thuộc |
|---|---|---:|---:|---|---|
| **mtproto.zig** | Zig | **177 KB** | **0.75 MB** | **< 10 ms** | **0** |
| Official MTProxy | C | 524 KB | 8.0 MB | < 10 ms | openssl, zlib |
| Telemt | Rust | 15 MB | 12.1 MB | ~ 5-6 s | 423 crates |
| mtg | Go | 13 MB | 11.6 MB | ~ 30 ms | 78 mô-đun |
| MTProtoProxy | Python | N/A | ~ 30 MB | ~ 300 ms | python3, cryptography |
| JSMTProxy | Node.js | N/A | ~ 45 MB | ~ 400 ms | nodejs, openssl |

## Tại sao chọn Zig?

Chúng tôi chọn Zig vì nó mang lại hiệu năng thô và dung lượng siêu nhỏ như C, nhưng không kèm theo sự mất an toàn bộ nhớ hay những cơn ác mộng về hệ thống build:
- **Không cấp phát tùy tiện:** Tất cả các slot kết nối và bộ đệm đều được cấp phát trước khi khởi động. Không có bộ thu gom rác làm rớt khung dữ liệu khi tải nặng.
- **Biên dịch chéo khép kín:** Chạy `zig build` trên macOS, và bạn nhận được một binary Linux liên kết tĩnh. Không cần Docker, không lo lệch phiên bản `glibc`.
- **Comptime:** Các thao tác tốn kém như ánh xạ định nghĩa giao thức, chuyển đổi thứ tự byte, và tra cứu chuỗi song ngữ cho `mtbuddy` đều được giải quyết ngay trong lúc biên dịch, mang lại thời gian khởi động tức thì.

**Bạn không cần hiểu bất kỳ thuật ngữ nào bên dưới — bản cài đặt mặc định bật tất cả chúng cho bạn.** Bên dưới lớp vỏ, proxy này xếp chồng nhiều kỹ thuật chống kiểm duyệt hơn bất kỳ MTProto proxy nào khác, và liên tục thích nghi khi các biện pháp chặn ngày càng tinh vi:

| Kỹ thuật | Tác dụng |
|---|---|
| **Fake TLS 1.3** | Kết nối trông như HTTPS bình thường đối với DPI |
| **DRS** | Bắt chước kích thước bản ghi TLS của Chrome/Firefox |
| **Che giấu thăm dò chủ động** | Nếu bên kiểm duyệt thăm dò máy chủ của bạn, nó sẽ nhận được một bắt tay TLS thật từ một web backend cục bộ (chứng chỉ thật nếu bạn sở hữu tên miền, nếu không thì tự ký) thay vì một proxy im lặng dễ bị lộ. Tùy chọn: đặt trực tiếp `tls_domain:443` thật cho các tên miền single-round-x25519 |
| **TCPMSS=88** | Phân mảnh ClientHello thành 6 gói TCP, phá vỡ việc ráp lại của DPI |
| **nfqws TCP desync** | Gửi các gói giả + cắt giới hạn TTL để gây nhiễu DPI có trạng thái |
| **Split-TLS** | Các bản ghi Application 1 byte để đánh bại chữ ký thụ động |
| **Đường hầm VPN** | Định tuyến qua WireGuard/AmneziaWG bằng định tuyến chính sách socket tường minh (SO_MARK) khi các DC bị chặn |
| **Nhảy IPv6** | Tự động luân chuyển địa chỉ IPv6 từ dải /64 khi phát hiện bị chặn, thông qua Cloudflare API |
| **Chống phát lại** | Từ chối các bắt tay bị phát lại + phát hiện thăm dò chủ động ТСПУ Revisor |
| **Đa người dùng** | Mỗi người dùng có secret độc lập |
| **MiddleProxy** | Truyền tải ME với metadata Telegram tự động làm mới |

MiddleProxy là bắt buộc đối với thẻ quảng bá và đối với media trên các tài khoản không phải Premium. Nếu không có nó, ảnh, video, story và các media khác trên tài khoản không phải Premium nên được xem là không khả dụng chứ không phải chập chờn. Proxy này không hỗ trợ cuộc gọi Telegram: Telegram chỉ định tuyến cuộc gọi qua các đường kiểu SOCKS, và việc để lộ lưu lượng SOCKS thì mtproto.zig không thể ngụy trang thành HTTPS bình thường.

---

## Cài đặt

Mọi việc cài đặt, cập nhật và quản lý đều được thực hiện qua **mtbuddy** — một CLI Zig gốc đi kèm với proxy.

### Một lệnh duy nhất

```bash
curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/bootstrap.sh | sudo bash

# Explicitly allow unsigned bootstrap mode (not recommended)
curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/bootstrap.sh | sudo bash -s -- --insecure
# or: MTPROTO_INSECURE=1
```

Lệnh này tải về binary `mtbuddy` mới nhất, xác minh chữ ký minisign + checksum SHA-256 từ GitHub Release, rồi chạy `mtbuddy --help`. Sau đó cài đặt proxy:

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

Cuối cùng, mtbuddy in ra một liên kết kết nối `tg://` sẵn sàng để dùng.

> **Hãy chia sẻ nó với người bạn yêu thương.** Gửi cho họ lời này, kèm theo liên kết:
> *"Mình đã lập một cánh cửa riêng vào Telegram cho chúng ta. Chạm vào liên kết này, chọn Connect, và Telegram sẽ hoạt động trở lại — không phải cài gì, không phải trả tiền, và nó chỉ của riêng chúng ta thôi."*

### Trình hướng dẫn tương tác

Nếu bạn muốn được dẫn dắt qua từng bước cài đặt:

```bash
sudo mtbuddy --interactive
```

<details>
<summary>Demo: trình cài đặt tương tác</summary>
<br>
<p align="center">
  <img src="https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/assets/buddy.gif" alt="Demo: trình cài đặt tương tác" width="80%">
</p>
<br>

</details>

### Bản cài đặt làm những gì

1. Tải về **binary proxy dựng sẵn** từ GitHub Releases (tự phát hiện CPU: `x86_64_v3` → `x86_64` → `aarch64`)
2. Tạo một secret ngẫu nhiên (hoặc dùng `--secret`)
3. Tạo một dịch vụ systemd (`mtproto-proxy`)
4. Mở cổng trong `ufw` (nếu đang bật)
5. Áp dụng các quy tắc iptables TCPMSS=88
6. Thiết lập che giấu Nginx + nfqws TCP desync (trừ khi dùng `--no-dpi`)
7. In ra liên kết `tg://`

### Tùy chọn cài đặt

| Cờ | Mặc định | Mô tả |
|---|---|---|
| `--port, -p` | `443` | Cổng lắng nghe của proxy |
| `--public-port` | — | Cổng được quảng bá trong các liên kết Telegram được tạo ra |
| `--domain, -d` | `rutube.ru` | Tên miền che giấu TLS (⚠️ **bất biến** — xem ghi chú bên dưới) |
| `--secret, -s` | auto | Secret người dùng (32 ký tự hex) |
| `--user, -u` | `user` | Tên người dùng trong `config.toml` |
| `--config, -c` | — | Dùng file `config.toml` có sẵn |
| `--yes, -y` | — | Bỏ qua lời nhắc xác nhận |
| `--max-connections <N>` | `512` | Số kết nối proxy tối đa |
| `--bind, -b` | — | Gắn vào một IP cụ thể (mặc định: tất cả giao diện) |
| `--no-masking` | — | Tắt che giấu Nginx |
| `--no-nfqws` | — | Tắt nfqws TCP desync |
| `--no-tcpmss` | — | Tắt giới hạn TCPMSS |
| `--tcpmss <n>` | `88` | Giá trị giới hạn TCPMSS (buộc phân mảnh ClientHello) |
| `--no-dpi` | — | Tắt tất cả các mô-đun DPI |
| `--middle-proxy` | — | Bật chuyển tiếp Telegram MiddleProxy |
| `--ipv6-hop` | — | Bật tự động nhảy IPv6 |
| `--version, -v <tag>` | `latest` | Phiên bản phát hành cần cài |
| `--insecure` | — | Cho phép các tệp không được ký (không khuyến nghị) |

> ⚠️ **Chỉ chọn `--domain` một lần.** Các liên kết tg:// nhúng `tls_domain`, nên việc thay đổi nó trên một
> triển khai đang chạy (kể cả qua `mtbuddy setup masking --domain …`) **sẽ làm vô hiệu mọi
> liên kết bạn đã chia sẻ.** Xem [ARCHITECTURE.md](ARCHITECTURE.md) / [COMPATIBILITY.md](COMPATIBILITY.md).

---

## Cập nhật

```bash
# Update to latest release (verifies minisign + checksum, checks CPU compat, auto-rollback on failure)
sudo mtbuddy update

# Pin to a specific version
sudo mtbuddy update --version v0.11.1

# Explicitly allow unsigned mode (not recommended)
sudo mtbuddy update --insecure
```

---

## Các lệnh mtbuddy khác

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

# Tùy chọn: giới hạn tốc độ SYN theo mỗi IP ở cấp kernel (chống lụt, MẶC ĐỊNH TẮT).
# Chặn các đợt SYN-đầu-tiên gây lạm dụng ngay trong kernel TRƯỚC accept(); một systemd
# oneshot riêng để CAP_NET_ADMIN không bao giờ được cấp cho proxy. Preset mặc định an toàn hơn cho CGNAT.
sudo mtbuddy setup syn-limit --preset soft   # soft 2/s·5 | medium 1/s·3 | hard 1/s·1
sudo mtbuddy setup syn-limit --status
sudo mtbuddy setup syn-limit --remove

# Install web monitoring dashboard
sudo mtbuddy setup dashboard

# VPN tunnel (for servers where Telegram DCs are blocked)
sudo mtbuddy setup tunnel /path/to/awg0.conf
sudo mtbuddy setup tunnel 'vpn://...'
sudo mtbuddy setup tunnel --iface awg1 /path/to/awg1.conf

# Egress qua liên kết chia sẻ VPN — upstream sạch, khó chặn cho chặng proxy→Telegram.
#   vless:// vmess:// trojan:// ss://  -> tunnel sing-box TUN cục bộ (type=tunnel; VLESS-Reality
#                                        ngụy trang chặng nhảy thành TLS thật).
#   wireguard://                       -> tunnel WG kernel gốc (giống `setup tunnel`).
#   nhiều liên kết                     -> pool tự chuyển dự phòng (urltest).
sudo mtbuddy setup egress 'vless://...@host:443?security=reality&pbk=...&sni=...&flow=xtls-rprx-vision'
sudo mtbuddy setup egress 'wireguard://<privkey>@host:51820?publickey=...&address=10.0.0.2/32'

# IPv6 hopping
sudo mtbuddy ipv6-hop --check
sudo mtbuddy ipv6-hop --auto --prefix 2a01:abcd:ef00:: --threshold 5

# Update Cloudflare DNS A record
sudo mtbuddy update-dns 1.2.3.4 proxy.example.com

# Full help
mtbuddy --help
mtbuddy --lang ru --help
```

---

## Quản lý dịch vụ

```bash
sudo systemctl status mtproto-proxy
sudo journalctl -u mtproto-proxy -f
sudo systemctl reload mtproto-proxy   # SIGHUP hot-reload (where possible)
sudo systemctl restart mtproto-proxy
```

---

## Định tuyến Upstream

Proxy hỗ trợ nhiều cách để định tuyến các kết nối đi ra tới các máy chủ DC của Telegram.

### Các chế độ định tuyến

| `[upstream].type` | Cách hoạt động | Khi nào dùng |
|---|---|---|
| `auto` (mặc định) | Đi ra trực tiếp, không có mark định tuyến chính sách đường hầm | Hầu hết các triển khai |
| `direct` | Kết nối trực tiếp tới các DC Telegram từ máy chủ | Các DC truy cập được từ máy chủ |
| `tunnel` | Kết nối trực tiếp với `SO_MARK=200`, được định tuyến chính sách qua một nhóm đường hầm VPN | Các DC bị ISP chặn |
| `socks5` | Định tuyến qua một SOCKS5 proxy bên ngoài, tùy chọn xác thực | Hạ tầng proxy có sẵn |
| `http` | Định tuyến qua một HTTP CONNECT proxy, tùy chọn xác thực | Môi trường proxy doanh nghiệp |

### Đường hầm VPN

Nếu VPS của bạn ở một khu vực nơi các DC Telegram bị chặn ở cấp mạng, bạn có thể định tuyến lưu lượng proxy qua một nhóm đường hầm VPN bằng định tuyến chính sách socket tường minh. Proxy chạy trong namespace của host; chỉ những socket được proxy đánh dấu (`SO_MARK=200`) mới được định tuyến qua bảng 200. `mtbuddy` luôn trỏ bảng đó tới đường hầm khỏe mạnh đầu tiên theo thứ tự đã cấu hình.

Các loại VPN hiện được hỗ trợ:
- **AmneziaWG** — bản fork WireGuard kháng DPI (khuyến nghị cho Nga/Iran)
- **WireGuard** — WireGuard tiêu chuẩn (đang lên kế hoạch)

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

Trong menu tương tác của `mtbuddy`, phần thiết lập đường hầm trước tiên hỏi loại VPN (hiện là AmneziaWG), rồi hiển thị nhóm đường hầm hiện tại. Chọn **Create new tunnel** để thêm `awgN` còn trống tiếp theo, hoặc chọn một giao diện có sẵn để thay thế cấu hình của thành viên nhóm đó.

`mtbuddy` giữ nguyên `[general].use_middle_proxy` và chỉ cấu hình lớp truyền tải (`[upstream].type = "tunnel"`).
Sau khi thiết lập, nó cài đặt `mtproto-tunnel-pool.timer`, xác thực các tuyến chính sách (`mark 200`) tới các dải DC Telegram, và in ra các lệnh vận hành. Bộ điều khiển nhóm thăm dò Telegram qua từng đường hầm và ghi lại bảng 200 bằng `ip route replace`; việc tự động chuyển dự phòng không khởi động lại `mtproto-proxy`.

Bạn cũng có thể cấu hình tường minh giao diện đường hầm trong `config.toml`:

```toml
[upstream]
type = "tunnel"

[upstream.tunnel]
interface = "awg0"
interfaces = ["awg0", "awg1"]
pinned_interface = ""   # optional; empty means priority auto-failback
```

### SOCKS5 proxy

Định tuyến các kết nối DC qua một SOCKS5 proxy bên ngoài. Hỗ trợ xác thực RFC 1928.

```toml
[upstream]
type = "socks5"

[upstream.socks5]
host = "127.0.0.1"
port = 1080
username = "admin"    # optional, omit for no-auth
password = "secret"
```

### HTTP CONNECT proxy

Định tuyến các kết nối DC qua một HTTP CONNECT proxy. Hỗ trợ xác thực Basic.

```toml
[upstream]
type = "http"

[upstream.http]
host = "127.0.0.1"
port = 8080
username = "admin"    # optional, omit for no-auth
password = "secret"
```

> **Lưu ý:** Lưu lượng chuyển tiếp hướng tới DC và việc làm mới metadata MiddleProxy (`getProxyConfig` / `getProxySecret`) đều dùng upstream đã cấu hình. Các kết nối che giấu (ngụy trang) luôn đi trực tiếp.
>
> **Lưu ý về phụ thuộc:** tuyên bố "không phụ thuộc" đúng với chế độ đi ra mặc định `auto`/`direct`. Với các chế độ upstream `socks5`, `http`, hoặc `tunnel`, việc làm mới metadata MiddleProxy sẽ gọi ra `curl`, nên `curl` phải được cài trên máy chủ (trình cài đặt tiêu chuẩn sẽ tự kéo nó về).

---

## Cấu hình

Cấu hình nằm tại `/opt/mtproto-proxy/config.toml`. MTBuddy tạo nó khi cài đặt; bạn có thể tự chỉnh sửa rồi khởi động lại:

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
# client_silence_close_sec = 0   # Close a relay whose server reply went unanswered by the client for N sec (breaks an iOS bad_salt wedge where "Updating" hangs ~90-120s) → instant clean reconnect. 0 = off; best-effort, can occasionally close a healthy conn — ~10-15 if you enable it
handshake_timeout_sec = 15
# dc_connect_timeout_sec = 10   # Hạn chót TCP-connect cho mỗi endpoint tới một DC Telegram; làm hỏng nhanh một endpoint bị black-hole để failover chuyển sang endpoint kế tiếp (trong phạm vi handshake_timeout_sec). 0 = tắt; không bao giờ ảnh hưởng các kết nối khỏe mạnh (<1s)
graceful_shutdown_timeout_sec = 15
log_level = "info"        # debug | info | warn | err
rate_limit_per_subnet = 0   # 0 = disabled (default; avoids carrier-NAT false positives). Set e.g. 30 for non-NAT hosts
handshake_flood_guard_enabled = false
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
<summary>Tham chiếu cấu hình đầy đủ</summary>

| Khóa | Mặc định | Mô tả |
|-----|---------|-------------|
| `[upstream].type` | `auto` | Chế độ đi ra: `auto` (trực tiếp), `direct`, `tunnel` (VPN qua định tuyến chính sách socket), `socks5`, hoặc `http` |
| `[upstream] allow_direct_fallback` | `false` | Nếu `true`, cho phép các chế độ socks5/http quay về đi ra trực tiếp khi upstream không khả dụng |
| `[upstream.tunnel] interface` | `"awg0"` | Giao diện đường hầm đơn kiểu cũ / phương án dự phòng cho định tuyến SO_MARK |
| `[upstream.tunnel] interfaces` | `["awg0"]` | Nhóm đường hầm có thứ tự; giao diện khỏe mạnh đầu tiên được chọn |
| `[upstream.tunnel] pinned_interface` | — | Tùy chọn ưu tiên thủ công, được dùng trước nhóm có thứ tự khi nó khỏe mạnh |
| `[upstream.socks5] host` | — | Địa chỉ SOCKS5 proxy |
| `[upstream.socks5] port` | — | Cổng SOCKS5 proxy |
| `[upstream.socks5] username` | — | Tên người dùng SOCKS5 (để trống = không xác thực) |
| `[upstream.socks5] password` | — | Mật khẩu SOCKS5 |
| `[upstream.http] host` | — | Địa chỉ HTTP CONNECT proxy |
| `[upstream.http] port` | — | Cổng HTTP CONNECT proxy |
| `[upstream.http] username` | — | Tên người dùng HTTP proxy (để trống = không xác thực) |
| `[upstream.http] password` | — | Mật khẩu HTTP proxy |
| `[general] use_middle_proxy` | `false` | Chế độ ME cho DC1..5 (khuyến nghị để tương đương về quảng bá) |
| `[general] ad_tag` | — | Bí danh của `[server].tag` |
| `[server] port` | `443` | Cổng lắng nghe TCP |
| `[server] bind_address` | — | IP cụ thể để gắn socket lắng nghe (mặc định: tất cả giao diện) |
| `[server] public_ip` | auto | IP/tên miền vào được hiển thị trong liên kết của client. Bắt buộc khi dùng đường hầm VPN; hãy đặt IPv4 tường minh nếu client gặp lỗi với liên kết IPv6 |
| `[server] public_port` | `[server].port` | Cổng hiển thị trong liên kết của client; hữu ích khi HAProxy/Nginx mở một cổng công khai khác |
| `[server] middle_proxy_nat_ip` | auto | IPv4 đi ra dùng trong việc dẫn xuất khóa MiddleProxy; được tự phát hiện độc lập với `public_ip`, hãy đặt tường minh khi lưu lượng DC thoát ra qua một IP VPN/NAT |
| `[server] backlog` | `4096` | Độ sâu hàng đợi lắng nghe TCP |
| `[server] max_connections` | `512` | Giới hạn kết nối đồng thời, tự động giới hạn theo RAM và `RLIMIT_NOFILE` |
| `[server] workers` | `1` | Số luồng worker epoll SO_REUSEPORT. `1` = đơn luồng; `0` = một luồng mỗi CPU; `N` phân tán tải chuyển tiếp/mã hóa qua các nhân. Việc nạp lại cấu hình bằng SIGHUP cần khởi động lại khi `>1` |
| `[server] idle_timeout_sec` | `120` | Thời gian chờ kết nối nhàn rỗi |
| `[server] idle_timeout_jitter_pct` | `15` | Jitter ±% trên mỗi kết nối cho thời gian chờ nhàn rỗi để một giá trị cố định không trở thành dấu vân tay (`0` để tắt) |
| `[server] client_silence_close_sec` | `0` | Đóng một relay đã thiết lập mà phản hồi cuối của máy chủ không được client trả lời trong N giây, kích hoạt kết nối lại sạch tức thì (~450ms). Khắc phục một lỗi treo của iOS MtProtoKit: sau khi bị từ chối do salt cũ, client vứt bỏ salt và ngừng gửi, "Đang cập nhật" treo ~90-120s cho đến khi DC đóng socket. Chỉ kích hoạt khi payload cuối là server→client (một kết nối idle khỏe mạnh mà động thái cuối là ping/ack của chính nó sẽ không bị đụng tới). Đây là giải pháp tạm thời best-effort: giá trị thấp hơn phản hồi hợp lệ chậm nhất đôi khi cũng đóng một kết nối khỏe mạnh (chỉ ~450ms kết nối lại). `0` = tắt (mặc định); nếu bật, ~`10`–`15` là điểm khởi đầu hợp lý, tự điều chỉnh |
| `[server] dc_connect_timeout_sec` | `10` | Hạn chót cho mỗi endpoint đối với việc TCP connect tới một endpoint DC Telegram. Một endpoint bị lọc/black-hole không gửi RST, nên kernel nằm chờ ở SYN_SENT ~2 phút; handshake_timeout_sec đã giới hạn toàn bộ bắt tay nhưng theo cách toàn cục, nên một endpoint đầu tiên chậm sẽ bỏ đói failover của phần còn lại. Cái này làm hỏng nhanh một endpoint chết và chuyển sang endpoint kế tiếp (trong phạm vi trần handshake_timeout_sec). Giữ thấp hơn handshake_timeout_sec. 0 = tắt; các kết nối khỏe mạnh hoàn tất trong <1s nên nó không bao giờ ảnh hưởng đến chúng |
| `[server] handshake_timeout_sec` | `15` | Thời gian chờ hoàn tất bắt tay |
| `[server] graceful_shutdown_timeout_sec` | `15` | Thời gian chờ rút cạn khi SIGTERM trước khi buộc đóng |
| `[server] middleproxy_buffer_kb` | `1024` | Bộ đệm ME cho mỗi kết nối (KiB). Dưới 1024 có thể gây tràn với lưu lượng media |
| `[server] tag` | — | Thẻ quảng bá 32 ký tự hex từ [@MTProxybot](https://t.me/MTProxybot) |
| `[server] log_level` | `"info"` | `debug` / `info` / `warn` / `err` |
| `[server] rate_limit_per_subnet` | `0` | Số kết nối mới tối đa/giây cho mỗi /24 (IPv4) hoặc /48 (IPv6). `0` = tắt (mặc định, thân thiện NAT); ví dụ đặt `30` cho các máy không NAT |
| `[server] handshake_flood_guard_enabled` | `false` | Tạm thời từ chối các IP nguồn cụ thể liên tục thất bại trong bắt tay MTProto (mặc định tắt — an toàn cho NAT/VPN) |
| `[server] handshake_flood_guard_threshold` | `20` | Số sự kiện bắt tay lỗi/vượt tốc độ/vượt ngân sách trên mỗi IP nguồn trước khi tạm từ chối |
| `[server] handshake_flood_guard_window_sec` | `30` | Cửa sổ trượt cho `handshake_flood_guard_threshold` |
| `[server] handshake_flood_guard_block_sec` | `120` | Thời lượng tạm từ chối đối với các IP nguồn gây nhiễu |
| `[server] unsafe_override_limits` | `false` | Tắt việc tự động giới hạn `max_connections` |
| `[monitor] host` | `"127.0.0.1"` | Địa chỉ gắn của bảng điều khiển |
| `[monitor] port` | `61208` | Cổng bảng điều khiển |
| `[metrics] enabled` | `false` | Bật endpoint Prometheus `/metrics` tích hợp |
| `[metrics] host` | `"127.0.0.1"` | Địa chỉ gắn của metrics |
| `[metrics] port` | `9400` | Cổng metrics |
| `[censorship] tls_domain` | `"google.com"` | Tên miền để giả mạo |
| `[censorship] mask` | `true` | Chuyển tiếp các client chưa xác thực tới `tls_domain` |
| `[censorship] unknown_sni_action` | `"mask"` | ClientHello với SNI không xác định: `mask` (chuyển tiếp), `reject` (cảnh báo TLS nghiêm trọng như một máy chủ từ chối), hoặc `drop` |
| `[censorship] mask_target` | unset | Máy backend tùy chọn cho các client bị che giấu |
| `[censorship] mask_port` | `443` | Cổng che giấu cục bộ (dùng `8443` cho Nginx zero-RTT) |
| `[censorship] desync` | `true` | Split-TLS: các bản ghi Application 1 byte |
| `[censorship] drs` | `false` | Định cỡ bản ghi động (Dynamic Record Sizing) |
| `[censorship] fast_mode` | `false` | Ủy thác mã hóa S2C cho DC (khuyến nghị) |
| `[access.users] <name>` | — | Secret 32 ký tự hex cho mỗi người dùng |
| `[access.direct_users] <name>` | — | Bỏ qua ME cho người dùng này |
| `[access.user_max_conns] <name>` | — | Giới hạn số kết nối đồng thời cho mỗi người dùng (cần khởi động lại để thay đổi) |
| `[access.user_expirations] <name>` | — | Ngày hết hạn cho mỗi người dùng `"YYYY-MM-DD"` (cần khởi động lại để thay đổi) |

</details>

> Tạo một secret: `mtbuddy secret` hoặc `openssl rand -hex 16`
>
> In các liên kết client một cách tường minh: `sudo mtbuddy links`. Mặc định nó chỉ in các liên kết FakeTLS (`ee...domain`); nó cũng in các liên kết secure padded (`dd...`) khi lớp truyền tải `dd` được bật (`fake_tls_only = false`). Log của proxy lúc chạy cố tình ẩn các secret và liên kết proxy.
>
> **Lớp truyền tải `dd` ("secure"/padded) bị từ chối theo mặc định** (`[censorship].fake_tls_only = true`) — đó là MTProto được làm rối thông thường, **không có ngụy trang TLS**, có thể bị DPI nhận diện trực tiếp là MTProto. Theo mặc định proxy chỉ chấp nhận FakeTLS (`ee`), và `mtbuddy links` chỉ in các liên kết `ee`. Để phát các liên kết `dd` (cho các tình huống ít DPI / tương thích), hãy đặt `fake_tls_only = false`. Xem [THREAT_MODEL.md](THREAT_MODEL.md).
>
> Cả hai bộ chống lạm dụng đều **mặc định bị tắt** để các mạng carrier-NAT lớn, mạng VPN-egress hoặc mạng văn phòng dùng chung (nhiều client hợp lệ sau một IP/subnet nguồn) không bị nhận diện nhầm và chặn cùng nhau: giới hạn tốc độ kết nối mới theo mỗi subnet (`rate_limit_per_subnet = 0`) và bộ chống lụt bắt tay theo IP chính xác (`handshake_flood_guard_enabled = false`). Quyền truy cập đã được kiểm soát bởi secret theo từng người dùng, ngân sách bắt tay đang chờ toàn cục và `max_connections`. Trên một máy đơn người thuê / không NAT khi thực sự bị lạm dụng, hãy bật chúng lên: đặt `rate_limit_per_subnet` (ví dụ `30`) và `handshake_flood_guard_enabled = true` (tinh chỉnh `handshake_flood_guard_threshold` / cửa sổ / thời gian chặn).
>
> Cả hai bộ ở trên đều chạy sau `accept()` (chúng nằm trong proxy). Để có thêm một lớp ở cấp kernel chặn các đợt SYN-đầu-tiên gây lạm dụng trước khi chúng tốn một socket/`accept()`, có một bộ giới hạn tốc độ SYN theo mỗi IP nguồn tùy chọn: `sudo mtbuddy setup syn-limit --preset soft`. Đó là một quy tắc `iptables hashlimit` được cài như một `mtproto-syn-limit.service` oneshot riêng, nên `CAP_NET_ADMIN` không bao giờ được cấp cho proxy. Cũng mặc định tắt và chịu cùng lưu ý về carrier-NAT (preset soft 2/s·burst-5 là mặc định an toàn hơn cho CGNAT); `--remove` để gỡ bỏ, status + bộ đếm drop trong `mtbuddy status`. Chạy lại nó sau khi thay đổi cổng proxy.

---

## Bảng điều khiển giám sát

Một bảng điều khiển web nhẹ (~30 MB RAM) hiển thị các kết nối trực tiếp, CPU/bộ nhớ, thông lượng mạng, thống kê proxy, tình trạng/trạng thái chuyển dự phòng của nhóm đường hầm, quản lý người dùng, và log theo luồng.

Bảng điều khiển được **nhúng trực tiếp vào binary `mtbuddy`** — không cần tệp bổ sung nào.

```bash
# Install the dashboard on the server
sudo mtbuddy setup dashboard

# Open via SSH tunnel (binds to 127.0.0.1:61208 by default)
ssh -L 61208:localhost:61208 root@<server_ip>
# → http://localhost:61208
```

Bảng điều khiển yêu cầu **HTTP Basic auth** (tên người dùng: bất kỳ; mật khẩu được tạo tự động tại `/opt/mtproto-proxy/monitor/dashboard.token` — hãy `cat` nó trên máy chủ). Đây là một control plane có đặc quyền root, nên hãy giữ nó trên đường loopback/đường hầm SSH và đừng bao giờ phơi HTTP trần ra internet — nếu buộc phải, hãy đặt HTTPS + một reverse proxy phía trước.

<details>
<summary>Demo: bảng điều khiển giám sát</summary>
<br>
<p align="center">
  <img src="https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/assets/dashboard.gif" alt="Demo: bảng điều khiển giám sát" width="80%">
</p>
<br>

</details>

---

## Số liệu Prometheus

`mtproto-proxy` có thể cung cấp một endpoint số liệu tương thích Prometheus tích hợp trên một cổng riêng.

Để có một ngăn xếp giám sát hoàn chỉnh dựa trên Docker với `mtproto-zig`, Prometheus, Grafana, và một bảng điều khiển có thể nhập vào, xem [hack/docker/README.md](hack/docker/README.md).

```toml
[metrics]
enabled = true
host = "127.0.0.1"
port = 9400
```

Endpoint này là HTTP thuần và phục vụ:

```text
GET /metrics
```

Cách dùng Docker điển hình:

```bash
docker run --rm \
  -p 443:443 \
  -p 9400:9400 \
  -v "$PWD/config.toml:/etc/mtproto-proxy/config.toml:ro" \
  mtproto-zig
```

Nó cung cấp các bộ đếm của proxy cùng với các số liệu tiến trình như RSS, bộ nhớ ảo, thời gian CPU, và số file descriptor đang mở.

---

## Tự build cục bộ

Yêu cầu [Zig 0.16.0](https://ziglang.org/download/).

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

Người dựng bản phát hành có thể ghi đè khóa minisign mặc định được ghim nếu cần:

```bash
zig build -Dminisign_pubkey=RW... -Doptimize=ReleaseFast -Dtarget=x86_64-linux
```

Biên dịch chéo cho Linux từ macOS:

```bash
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux -Dcpu=x86_64_v3+aes
scp zig-out/bin/mtproto-proxy root@<SERVER>:/opt/mtproto-proxy/
```

---

## Docker

Hỗ trợ Docker được cung cấp cho việc kiểm thử, thử nghiệm đóng gói, và các triển khai đơn giản chỉ cần binary proxy. Dự án chủ yếu được thiết kế cho một host Linux gốc do `mtbuddy` quản lý: các mô-đun DPI, chuyển dự phòng nhóm đường hầm, định tuyến chính sách, che giấu Nginx, nfqws, và các bộ hẹn giờ phục hồi đều là các tích hợp ở cấp host và không được container thể hiện đầy đủ.

```bash
docker pull ghcr.io/sleep3r/mtproto.zig:latest

docker run --rm \
  -p 443:443 \
  -v "$PWD/config.toml:/etc/mtproto-proxy/config.toml:ro" \
  ghcr.io/sleep3r/mtproto.zig:latest
```

Lưu lượng media/quảng bá MiddleProxy nhạy cảm với IP:port nguồn đi ra dùng trong bắt tay được mã hóa của nó. Với các triển khai Docker cần MiddleProxy, hãy ưu tiên dùng mạng host (`--network host`) hoặc một bản cài `mtbuddy` gốc. `[server].public_ip` chỉ là địa chỉ vào được hiển thị cho client; nếu lưu lượng DC đi ra thoát qua một IP VPN/NAT, hãy đặt `[server].middle_proxy_nat_ip` thành IPv4 đi ra đó. Bridge hoặc NAT từ xa ghi lại cổng nguồn vẫn có thể phá vỡ các bắt tay MiddleProxy.

Build cục bộ:

```bash
docker build -t mtproto-zig .
# multi-arch
docker buildx build --platform linux/amd64,linux/arm64 -t your-registry/mtproto-zig:latest --push .
```

Các image `linux/amd64` được phát hành được dựng với một hồ sơ CPU di động (`-Dcpu=x86_64`) để tránh sự cố `Illegal instruction` trên các CPU VPS cũ.

> Đối với các triển khai vượt kiểm duyệt trong môi trường thực tế, hãy ưu tiên quy trình `mtbuddy install` gốc. Các biện pháp giảm thiểu ở cấp hệ điều hành (iptables TCPMSS, nfqws, định tuyến chính sách đường hầm, các unit che giấu/phục hồi) không được áp dụng bên trong container; chỉ có binary proxy chạy ở đó.

---

## Tin cậy & Bảo mật

- [SECURITY.md](SECURITY.md) - chính sách báo cáo lỗ hổng và quy trình phản hồi
- [THREAT_MODEL.md](THREAT_MODEL.md) - mục tiêu bảo mật, những điều ngoài mục tiêu, mô hình đối thủ, rủi ro còn lại
- [CONTRIBUTING.md](CONTRIBUTING.md) - quy trình phát triển (`fmt`/`test`/`e2e`/`bench`) và kỳ vọng đối với PR
- [CHANGELOG.md](CHANGELOG.md) - lịch sử phát hành
- [LICENSE](LICENSE) - các điều khoản giấy phép MIT

Quản trị kho mã:
- [`.github/CODEOWNERS`](.github/CODEOWNERS)
- các mẫu issue trong [`.github/ISSUE_TEMPLATE`](.github/ISSUE_TEMPLATE)

---

## Hạn chế đã biết & Khả năng tương thích

Để xem mô hình đầy đủ, hãy đọc [THREAT_MODEL.md](THREAT_MODEL.md). Tóm tắt vận hành nhanh:

- **Hạn chế đã biết**
  - Đây là một proxy gia cố lớp truyền tải, không phải một mạng ẩn danh.
  - Chất lượng vượt qua có thể giảm khi các chiến lược DPI tiến hóa.
  - Bảng điều khiển/số liệu mặc định là văn bản thuần; đừng phơi công khai khi chưa có xác thực/TLS.
  - Cuộc gọi Telegram không hoạt động qua proxy này. Cuộc gọi cần đường gọi kiểu SOCKS của Telegram, vốn nằm ngoài mô hình MTProto/che giấu TLS và không thể được ngụy trang gọn gàng thành HTTPS bình thường ở đây.
  - Nếu không có MiddleProxy (`[general].use_middle_proxy = true`), media trên các tài khoản không phải Premium sẽ không tải được. MiddleProxy là bắt buộc đối với ảnh, video, story, và thẻ quảng bá.
- **Lưu ý theo từng khu vực**
  - Hành vi của ISP khác nhau theo quốc gia/khu vực; các cấu hình không phải lúc nào cũng dùng chung được.
  - Cách xử lý IPv6 và AAAA khác nhau rất nhiều giữa các nhà cung cấp và có thể ảnh hưởng đến độ trễ kết nối trên iOS/Desktop.
  - Định tuyến đường hầm phụ thuộc vào định tuyến chính sách của host và các giao thức VPN được phép ở khu vực đó.
- **Khả năng tương thích của client Telegram**
  - Telegram chính thức trên Android/iOS/Desktop: dự kiến hoạt động trên các bản phát hành hiện tại.
  - Các client bên thứ ba: chỉ ở mức nỗ lực tối đa.
- **Ma trận tương thích nhân/hệ điều hành**
  - Linux `x86_64`: được hỗ trợ (mục tiêu chính)
  - Linux `aarch64`: được hỗ trợ
  - Docker trên Linux: được hỗ trợ kèm lưu ý (các mô-đun DPI cấp hệ điều hành nằm ở phía host)
  - Môi trường chạy macOS/Windows: không được hỗ trợ (chỉ nhắm môi trường chạy Linux)
- **Những gì có thể hỏng sau khi Telegram/DC thay đổi**
  - Metadata và hành vi endpoint của MiddleProxy
  - Kỳ vọng về bắt tay ở các client Telegram mới hơn
  - Các trường hợp đặc biệt về định tuyến DC/media (ví dụ hành vi DC203)

---

## Khắc phục sự cố — kẹt ở "Updating..."

**1. Có bản ghi AAAA nhưng IPv6 không hoạt động trên máy chủ.**
DNS có một bản ghi AAAA → iOS thử IPv6 trước → hết thời gian chờ → chậm chạp quay về IPv4.
Khắc phục: xóa AAAA cho đến khi định tuyến IPv6 được cấu hình hoàn chỉnh.

```bash
dig +short proxy.example.com AAAA
ip -6 route
```

**2. Wi-Fi tại nhà chặn IPv4 của máy chủ.**
Mạng di động thường hoạt động (chúng dùng IPv6). Router tại nhà thường chặn IPv4 đích.
Khắc phục: bật IPv6 Prefix Delegation (IA_PD) trên router của bạn.

**3. VPN đang loại bỏ lưu lượng MTProto.**
Các VPN thương mại thường dùng DPI và loại bỏ lưu lượng proxy.
Khắc phục: đổi giao thức VPN, hoặc dùng một AmneziaWG tự lưu trữ.

**4. WireGuard/Docker đặt chung trên cùng một máy chủ.**
Bridge của Docker loại bỏ các gói từ subnet VPN.
Khắc phục: `iptables -I DOCKER-USER -s 172.29.172.0/24 -p tcp --dport 443 -j ACCEPT`

**5. Media DC203 bị reset trên các client không phải premium.**
Kiểm tra log: `journalctl -u mtproto-proxy | grep -E "dc=203|Middle"`.
Proxy tự động làm mới metadata DC203 từ Telegram khi khởi động. Nếu không truy cập được `core.telegram.org`, nó dùng các địa chỉ dự phòng đi kèm.
Với `[upstream].type = "socks5"` hoặc `"http"`, việc làm mới metadata dùng upstream đó; chạy `sudo mtbuddy config doctor --network` để xác minh endpoint của proxy và đường lấy metadata của Telegram.

---

## Giấy phép

[MIT](LICENSE) © 2026 Aleksandr Kalashnikov
