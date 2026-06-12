<div align="center">

# mtproto.zig

**عزیزانتان را در ارتباط نگه دارید.**

یک پراکسی کوچک Telegram که روی سرور خودتان اجرا می‌کنید. درون HTTPS معمولی پنهان می‌شود، پس سانسور نمی‌تواند آن را پیدا کند — و خانواده‌تان هم نمی‌تواند آن را از دست بدهد. یک دستور برای راه‌اندازی، یک لینک برای به‌اشتراک‌گذاری.

`177 KB · under 1 MB RAM · 0 dependencies` — بله، واقعاً همین‌قدر سبک است *(جزئیات در ادامه ↓)*

<sub>از نظر فنی: یک پراکسی MTProto کوچک و بدون وابستگی که با Zig نوشته شده و ترافیک Telegram را به‌شکل HTTPS استاندارد TLS 1.3 استتار می‌کند.</sub>

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/zig-0.16.0-f7a41d.svg?logo=zig&logoColor=white)](https://ziglang.org)
[![Platform](https://img.shields.io/badge/platform-linux-blueviolet.svg?logo=linux&logoColor=white)](#install)

<div align="center">

| [🇬🇧 English](README.md) | [🇷🇺 Русский](README.ru.md) | [🇨🇳 中文](README.zh.md) | **🇮🇷 فارسی** | [🇻🇳 Tiếng Việt](README.vi.md) |
| :-: | :-: | :-: | :-: | :-: |

</div>

</div>

---

<p align="center">
<a href="#why-this-one">چرا این یکی؟</a> · <a href="#نصب">نصب</a> · <a href="#بهروزرسانی">به‌روزرسانی</a> · <a href="#سایر-دستورات-mtbuddy">دستورات</a> · <a href="#مسیریابی-بالادست">مسیریابی</a> · <a href="#پیکربندی">پیکربندی</a> · <a href="#داشبورد-نظارت">داشبورد</a> · <a href="#ساخت-محلی">ساخت</a> · <a href="#docker">Docker</a> · <a href="#اعتماد-و-امنیت">اعتماد</a> · <a href="#محدودیتهای-شناختهشده-و-سازگاری">سازگاری</a> · <a href="#عیبیابی--گیر-کردن-روی-updating">عیب‌یابی</a>
</p>

---

## این برنامه برای چه کسانی است

- **جایی زندگی می‌کنید که Telegram کند یا مسدود شده** و فقط می‌خواهید دوباره به آن دسترسی داشته باشید.
- **شما همان کسی هستید که خانواده برای کمک سراغش می‌آید** — و می‌خواهید از پدر و مادر و دوستانتان با لینکی محافظت کنید که فقط یک‌بار رویش می‌زنند و دیگر هرگز به آن فکر نمی‌کنند.

روی **سرور خودتان** اجرا می‌شود — پیام‌هایتان هرگز از سرورهای ما عبور نمی‌کنند و هیچ ثبت‌نامی لازم نیست. متن‌باز تحت مجوز MIT؛ پراکسی به‌عمد هرگز اسرار (secret) یا اینکه چه کسی متصل می‌شود را ثبت (log) نمی‌کند.

## چرا فقط از یک VPN استفاده نکنیم؟

یک VPN خودش را لو می‌دهد — سانسورچی‌ها پروتکل را تشخیص می‌دهند و مسدودش می‌کنند، ضمن اینکه VPNِ سراسری دستگاه کند است و باتری را تمام می‌کند. این یکی شبیه یک وب‌سایت ساده‌ی HTTPS به نظر می‌رسد، فقط ترافیک Telegram را حمل می‌کند، و کسانی که لینک را با آن‌ها به اشتراک می‌گذارید **هیچ چیزی نصب نمی‌کنند**: روی یک لینک می‌زنند و بقیه‌اش را Telegram انجام می‌دهد. آن‌قدر کوچک است که روی ارزان‌ترین VPSی که می‌توانید اجاره کنید جا می‌شود، بلافاصله اجرا می‌شود و چیز دیگری برای راه‌اندازی وجود ندارد.

## در مقایسه با سایر پراکسی‌های MTProto

بیشتر پراکسی‌های MTProto بزرگ‌اند، وابستگی‌های زیادی دارند و حافظه‌ی زیادی مصرف می‌کنند. این یکی فرق دارد:

| پراکسی | زبان | فایل اجرایی | RSS پایه | راه‌اندازی | وابستگی‌ها |
|---|---|---:|---:|---|---|
| **mtproto.zig** | Zig | **177 KB** | **0.75 MB** | **< 10 ms** | **0** |
| Official MTProxy | C | 524 KB | 8.0 MB | < 10 ms | openssl, zlib |
| Telemt | Rust | 15 MB | 12.1 MB | ~ 5-6 s | 423 کریت |
| mtg | Go | 13 MB | 11.6 MB | ~ 30 ms | 78 ماژول |
| MTProtoProxy | Python | N/A | ~ 30 MB | ~ 300 ms | python3, cryptography |
| JSMTProxy | Node.js | N/A | ~ 45 MB | ~ 400 ms | nodejs, openssl |

## چرا Zig؟

ما Zig را انتخاب کردیم چون کارایی خام و ردپای حافظه‌ی بسیار کوچکِ C را فراهم می‌کند، اما بدون ناامنی حافظه یا کابوس‌های سیستم ساخت (build):
- **بدون تخصیص حافظه‌ی دلخواه:** همه‌ی اسلات‌های اتصال و بافرها هنگام راه‌اندازی از پیش تخصیص داده می‌شوند. هیچ زباله‌روبی (garbage collector) وجود ندارد که زیر بار سنگین فریم‌ها را بیندازد.
- **کامپایل متقابلِ کاملاً ایزوله:** روی macOS دستور `zig build` را اجرا کنید و یک فایل اجرایی Linux با لینک ایستا (static) بیرون می‌آید. نه Docker لازم است، نه ناسازگاری نسخه‌ی `glibc`.
- **Comptime:** عملیات پرهزینه مانند نگاشت تعریف پروتکل، تبدیل ترتیب بایت‌ها (endianness) و جست‌وجوی رشته‌های دوزبانه برای `mtbuddy` در زمان کامپایل حل می‌شوند و زمان راه‌اندازی آنی را به ارمغان می‌آورند.

**لازم نیست هیچ‌کدام از نام‌های زیر را بفهمید — نصب پیش‌فرض همه‌ی آن‌ها را برایتان روشن می‌کند.** در پشت صحنه، این پراکسی تکنیک‌های ضدسانسور بیشتری نسبت به هر پراکسی MTProto دیگری روی هم می‌چیند و همان‌طور که روش‌های مسدودسازی هوشمندتر می‌شوند، خود را تطبیق می‌دهد:

| تکنیک | چه کاری می‌کند |
|---|---|
| **Fake TLS 1.3** | اتصال‌ها برای DPI شبیه HTTPS معمولی به نظر می‌رسند |
| **DRS** | اندازه‌ی رکوردهای TLS مرورگر Chrome/Firefox را تقلید می‌کند |
| **Active-probe masking** | اگر سانسورچی سرور شما را پروب کند، به‌جای یک پراکسی خاموشِ لو دهنده، یک هندشیک واقعی TLS از یک بک‌اند وب محلی دریافت می‌کند (اگر مالک دامنه باشید گواهی واقعی، در غیر این صورت خود-امضا). اختیاری: قرار دادن `tls_domain:443` واقعی در جلو برای دامنه‌های single-round-x25519 |
| **TCPMSS=88** | ClientHello را در 6 بسته‌ی TCP تکه‌تکه می‌کند و بازچینیِ DPI را می‌شکند |
| **nfqws TCP desync** | بسته‌های جعلی + تقسیم‌های محدودشده با TTL می‌فرستد تا DPIِ حالت‌دار (stateful) را گیج کند |
| **Split-TLS** | رکوردهای Application یک‌بایتی برای شکست دادن امضاهای منفعل (passive) |
| **VPN tunnel** | وقتی DCها مسدود باشند، با مسیریابی صریحِ مبتنی بر سیاستِ سوکت (SO_MARK) از طریق WireGuard/AmneziaWG مسیردهی می‌کند |
| **IPv6 hopping** | هنگام تشخیص مسدودسازی، آدرس IPv6 را به‌صورت خودکار از یک /64 از طریق Cloudflare API می‌چرخاند |
| **Anti-replay** | هندشیک‌های بازپخش‌شده را رد می‌کند + پروب‌های فعالِ ТСПУ Revisor را تشخیص می‌دهد |
| **Multi-user** | اسرار (secret) مستقل برای هر کاربر |
| **MiddleProxy** | ترابریِ ME با فراداده‌ی Telegram که به‌صورت خودکار تازه‌سازی می‌شود |

MiddleProxy برای برچسب‌های تبلیغاتی (promotion tags) و برای رسانه روی حساب‌های غیر-Premium لازم است. بدون آن، عکس‌ها، ویدیوها، استوری‌ها و سایر رسانه‌ها روی حساب‌های غیر-Premium را باید به‌جای ناپایدار، در دسترس‌نبودن تلقی کرد. تماس‌های Telegram توسط این پراکسی پشتیبانی نمی‌شوند: Telegram تماس‌ها را فقط از مسیرهای SOCKS-مانند هدایت می‌کند و قرار دادن ترافیک SOCKS در معرض دید را mtproto.zig نمی‌تواند به‌شکل HTTPS معمولی استتار کند.

---

## نصب

همه‌ی نصب، به‌روزرسانی و مدیریت از طریق **mtbuddy** انجام می‌شود — یک ابزار خط فرمان (CLI) بومیِ Zig که همراه پراکسی عرضه می‌شود.

### یک دستور

```bash
curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/bootstrap.sh | sudo bash

# Explicitly allow unsigned bootstrap mode (not recommended)
curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/bootstrap.sh | sudo bash -s -- --insecure
# or: MTPROTO_INSECURE=1
```

این کار آخرین فایل اجرایی `mtbuddy` را دانلود می‌کند، امضای minisign + جمع کنترلی SHA-256 را از GitHub Release بررسی می‌کند و `mtbuddy --help` را اجرا می‌کند. سپس پراکسی را نصب کنید:

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

در پایان، mtbuddy یک لینک اتصال `tg://` آماده‌ی استفاده را چاپ می‌کند.

> **آن را با کسی که دوستش دارید به اشتراک بگذارید.** این پیام را همراه با لینک برایشان بفرستید:
> *«یک درِ خصوصی به Telegram برای خودمان راه انداختم. روی این لینک بزن، Connect را انتخاب کن و Telegram دوباره کار می‌کند — نه چیزی برای نصب، نه چیزی برای پرداخت، و فقط مال خودمان است.»*

### راهنمای گام‌به‌گام تعاملی

اگر ترجیح می‌دهید گام‌به‌گام در فرایند راه‌اندازی همراهی‌تان کنند:

```bash
sudo mtbuddy --interactive
```

<details>
<summary>نمایش: نصب‌کننده‌ی تعاملی</summary>
<br>
<p align="center">
  <img src="https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/assets/buddy.gif" alt="نمایش: نصب‌کننده‌ی تعاملی" width="80%">
</p>
<br>

</details>

### نصب چه کاری انجام می‌دهد

1. **فایل اجرایی از پیش‌ساخته‌ی پراکسی** را از GitHub Releases دانلود می‌کند (CPU را به‌صورت خودکار تشخیص می‌دهد: `x86_64_v3` → `x86_64` → `aarch64`)
2. یک secret تصادفی تولید می‌کند (یا از `--secret` استفاده می‌کند)
3. یک سرویس systemd می‌سازد (`mtproto-proxy`)
4. پورت را در `ufw` باز می‌کند (اگر فعال باشد)
5. قوانین iptables با TCPMSS=88 را اعمال می‌کند
6. استتار Nginx + nfqws TCP desync را راه‌اندازی می‌کند (مگر با `--no-dpi`)
7. لینک `tg://` را چاپ می‌کند

### گزینه‌های نصب

| پرچم (Flag) | پیش‌فرض | توضیحات |
|---|---|---|
| `--port, -p` | `443` | پورت گوش‌دادن پراکسی |
| `--public-port` | — | پورتی که در لینک‌های تولیدشده‌ی Telegram اعلام می‌شود |
| `--domain, -d` | `rutube.ru` | دامنه‌ی استتار TLS (⚠️ **غیرقابل‌تغییر** — به یادداشت زیر مراجعه کنید) |
| `--secret, -s` | خودکار | secret کاربر (32 کاراکتر hex) |
| `--user, -u` | `user` | نام کاربری در `config.toml` |
| `--config, -c` | — | استفاده از فایل `config.toml` موجود |
| `--yes, -y` | — | رد کردن پیام تأیید |
| `--max-connections <N>` | `512` | حداکثر اتصال‌های پراکسی |
| `--bind, -b` | — | اتصال (bind) به یک IP مشخص (پیش‌فرض: همه‌ی رابط‌ها) |
| `--no-masking` | — | غیرفعال کردن استتار Nginx |
| `--no-nfqws` | — | غیرفعال کردن nfqws TCP desync |
| `--no-tcpmss` | — | غیرفعال کردن کلمپ TCPMSS |
| `--tcpmss <n>` | `88` | مقدار کلمپ TCPMSS (تکه‌تکه‌سازی ClientHello را اجبار می‌کند) |
| `--no-dpi` | — | غیرفعال کردن همه‌ی ماژول‌های DPI |
| `--middle-proxy` | — | فعال کردن رله‌ی MiddleProxy تلگرام |
| `--ipv6-hop` | — | فعال کردن چرخش خودکار IPv6 |
| `--version, -v <tag>` | `latest` | نسخه‌ی انتشار برای نصب |
| `--insecure` | — | اجازه‌ی فایل‌های امضانشده (توصیه نمی‌شود) |

> ⚠️ **`--domain` را فقط یک‌بار انتخاب کنید.** لینک‌های tg:// مقدار `tls_domain` را در خود جای می‌دهند، بنابراین تغییر آن روی یک
> استقرار فعال (از جمله از طریق `mtbuddy setup masking --domain …`) **هر لینکی را که قبلاً به اشتراک
> گذاشته‌اید بی‌اعتبار می‌کند.** به [ARCHITECTURE.md](ARCHITECTURE.md) / [COMPATIBILITY.md](COMPATIBILITY.md) مراجعه کنید.

---

## به‌روزرسانی

```bash
# Update to latest release (verifies minisign + checksum, checks CPU compat, auto-rollback on failure)
sudo mtbuddy update

# Pin to a specific version
sudo mtbuddy update --version v0.11.1

# Explicitly allow unsigned mode (not recommended)
sudo mtbuddy update --insecure
```

---

## سایر دستورات mtbuddy

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

# خروج از طریق لینک اشتراکی VPN — مسیر بالادست تمیز و سخت‌مسدودشدنی برای پرش پروکسی→تلگرام.
#   vless:// vmess:// trojan:// ss://  -> تونل محلی sing-box TUN (type=tunnel؛ VLESS-Reality پرش را مانند TLS واقعی استتار می‌کند).
#   wireguard://                       -> تونل WG کرنل بومی (مانند `setup tunnel`).
#   چند لینک                            -> استخر failover با urltest.
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

## مدیریت سرویس

```bash
sudo systemctl status mtproto-proxy
sudo journalctl -u mtproto-proxy -f
sudo systemctl reload mtproto-proxy   # SIGHUP hot-reload (where possible)
sudo systemctl restart mtproto-proxy
```

---

## مسیریابی بالادست

این پراکسی چند روش برای مسیریابیِ اتصال‌های خروجی به سرورهای DC تلگرام پشتیبانی می‌کند.

### حالت‌های مسیریابی

| `[upstream].type` | چگونه کار می‌کند | چه زمانی استفاده شود |
|---|---|---|
| `auto` (پیش‌فرض) | خروج مستقیم بدون نشانه‌های سیاست تونل | بیشتر استقرارها |
| `direct` | اتصال مستقیم به DCهای تلگرام از روی هاست | DCها از سرور قابل دسترسی‌اند |
| `tunnel` | اتصال مستقیم با `SO_MARK=200` که از طریق یک استخر تونل VPN مسیریابی‌شده با سیاست است | DCها توسط ISP مسدود شده‌اند |
| `socks5` | مسیریابی از طریق یک پراکسی SOCKS5 خارجی با احراز هویت اختیاری | زیرساخت پراکسی موجود |
| `http` | مسیریابی از طریق یک پراکسی HTTP CONNECT با احراز هویت اختیاری | محیط‌های پراکسی سازمانی |

### تونل VPN

اگر VPS شما در منطقه‌ای است که DCهای تلگرام در سطح شبکه مسدود شده‌اند، می‌توانید ترافیک پراکسی را از طریق یک استخر تونل VPN با مسیریابیِ صریحِ مبتنی بر سیاستِ سوکت هدایت کنید. پراکسی در namespace هاست اجرا می‌شود؛ فقط سوکت‌هایی که توسط پراکسی نشانه‌گذاری شده‌اند (`SO_MARK=200`) از طریق table 200 مسیریابی می‌شوند. `mtbuddy` آن جدول را همواره به نخستین تونلِ سالم در ترتیب پیکربندی‌شده اشاره می‌دهد.

انواع VPN پشتیبانی‌شده در حال حاضر:
- **AmneziaWG** — فورکِ مقاوم در برابر DPI از WireGuard (توصیه‌شده برای روسیه/ایران)
- **WireGuard** — WireGuard استاندارد (برنامه‌ریزی‌شده)

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

در منوی تعاملی `mtbuddy`، راه‌اندازی تونل ابتدا نوع VPN را می‌پرسد (فعلاً AmneziaWG)، سپس استخر تونل فعلی را نشان می‌دهد. برای افزودن `awgN` آزاد بعدی **Create new tunnel** را انتخاب کنید، یا یک رابط موجود را انتخاب کنید تا پیکربندی آن عضو استخر جایگزین شود.

`mtbuddy` مقدار `[general].use_middle_proxy` را بدون تغییر نگه می‌دارد و فقط ترابری را پیکربندی می‌کند (`[upstream].type = "tunnel"`).
پس از راه‌اندازی، `mtproto-tunnel-pool.timer` را نصب می‌کند، مسیرهای سیاستی (`mark 200`) به محدوده‌های DC تلگرام را اعتبارسنجی می‌کند و دستورات عملیاتی را چاپ می‌کند. کنترل‌کننده‌ی استخر، تلگرام را از طریق هر تونل پروب می‌کند و table 200 را با `ip route replace` بازنویسی می‌کند؛ جابه‌جاییِ خودکار در زمان خطا (failover) باعث ری‌استارت `mtproto-proxy` نمی‌شود.

همچنین می‌توانید رابط تونل را به‌صراحت در `config.toml` پیکربندی کنید:

```toml
[upstream]
type = "tunnel"

[upstream.tunnel]
interface = "awg0"
interfaces = ["awg0", "awg1"]
pinned_interface = ""   # optional; empty means priority auto-failback
```

### پراکسی SOCKS5

اتصال‌های DC را از طریق یک پراکسی SOCKS5 خارجی مسیریابی کنید. از احراز هویت RFC 1928 پشتیبانی می‌کند.

```toml
[upstream]
type = "socks5"

[upstream.socks5]
host = "127.0.0.1"
port = 1080
username = "admin"    # optional, omit for no-auth
password = "secret"
```

### پراکسی HTTP CONNECT

اتصال‌های DC را از طریق یک پراکسی HTTP CONNECT مسیریابی کنید. از احراز هویت Basic پشتیبانی می‌کند.

```toml
[upstream]
type = "http"

[upstream.http]
host = "127.0.0.1"
port = 8080
username = "admin"    # optional, omit for no-auth
password = "secret"
```

> **توجه:** ترافیک رله‌ی مقصدِ DC و تازه‌سازی‌های فراداده‌ی MiddleProxy (`getProxyConfig` / `getProxySecret`) از بالادستِ پیکربندی‌شده استفاده می‌کنند. اتصال‌های استتار (camouflage) همیشه مستقیم می‌روند.
>
> **توجه درباره‌ی وابستگی‌ها:** ادعای «صفر وابستگی» برای خروجِ پیش‌فرض `auto`/`direct` صادق است. با حالت‌های بالادستِ `socks5`، `http` یا `tunnel`، تازه‌سازی فراداده‌ی MiddleProxy به `curl` ارجاع می‌دهد، پس `curl` باید روی هاست نصب باشد (نصب‌کننده‌ی استاندارد آن را نصب می‌کند).

---

## پیکربندی

پیکربندی در `/opt/mtproto-proxy/config.toml` قرار دارد. MTBuddy آن را هنگام نصب تولید می‌کند؛ می‌توانید آن را دستی ویرایش کرده و سرویس را ری‌استارت کنید:

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
# max_connection_lifetime_sec = 0   # Recycle a relay older than N sec (TCP RST) so mobile clients reconnect cleanly after a long background — fixes the "updating" hang on resume. 0 = unlimited; try 1800-3600
handshake_timeout_sec = 15
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
<summary>مرجع کامل پیکربندی</summary>

| کلید | پیش‌فرض | توضیحات |
|-----|---------|-------------|
| `[upstream].type` | `auto` | حالت خروج: `auto` (مستقیم)، `direct`، `tunnel` (VPN از طریق مسیریابیِ مبتنی بر سیاست سوکت)، `socks5`، یا `http` |
| `[upstream] allow_direct_fallback` | `false` | اگر `true` باشد، به حالت‌های socks5/http اجازه می‌دهد در صورت در دسترس نبودن بالادست به خروج مستقیم بازگردند |
| `[upstream.tunnel] interface` | `"awg0"` | رابط تک‌تونلِ قدیمی / جایگزین برای مسیریابی SO_MARK |
| `[upstream.tunnel] interfaces` | `["awg0"]` | استخر تونلِ مرتب‌شده؛ نخستین رابط سالم برنده است |
| `[upstream.tunnel] pinned_interface` | — | ترجیح دستیِ اختیاری که در صورت سالم بودن پیش از استخر مرتب‌شده استفاده می‌شود |
| `[upstream.socks5] host` | — | آدرس پراکسی SOCKS5 |
| `[upstream.socks5] port` | — | پورت پراکسی SOCKS5 |
| `[upstream.socks5] username` | — | نام کاربری SOCKS5 (خالی = بدون احراز هویت) |
| `[upstream.socks5] password` | — | گذرواژه‌ی SOCKS5 |
| `[upstream.http] host` | — | آدرس پراکسی HTTP CONNECT |
| `[upstream.http] port` | — | پورت پراکسی HTTP CONNECT |
| `[upstream.http] username` | — | نام کاربری پراکسی HTTP (خالی = بدون احراز هویت) |
| `[upstream.http] password` | — | گذرواژه‌ی پراکسی HTTP |
| `[general] use_middle_proxy` | `false` | حالت ME برای DC1..5 (برای هم‌ترازیِ کانال‌های تبلیغاتی توصیه می‌شود) |
| `[general] ad_tag` | — | نام مستعار برای `[server].tag` |
| `[server] port` | `443` | پورت گوش‌دادن TCP |
| `[server] bind_address` | — | IP مشخص برای اتصال سوکت گوش‌دادن (پیش‌فرض: همه‌ی رابط‌ها) |
| `[server] public_ip` | خودکار | IP/دامنه‌ی ورودی که در لینک‌های کلاینت نمایش داده می‌شود. با تونل VPN لازم است؛ اگر کلاینت‌ها روی لینک‌های IPv6 ناموفق‌اند، IPv4 را به‌صراحت تنظیم کنید |
| `[server] public_port` | `[server].port` | پورتی که در لینک‌های کلاینت نمایش داده می‌شود؛ زمانی مفید است که HAProxy/Nginx پورت عمومی متفاوتی را در معرض قرار می‌دهد |
| `[server] middle_proxy_nat_ip` | خودکار | IPv4 خروجی که در استخراج کلید MiddleProxy استفاده می‌شود؛ مستقل از `public_ip` به‌صورت خودکار تشخیص داده می‌شود، زمانی که ترافیک DC از طریق یک IP مربوط به VPN/NAT خارج می‌شود آن را به‌صراحت تنظیم کنید |
| `[server] backlog` | `4096` | عمق صف گوش‌دادن TCP |
| `[server] max_connections` | `512` | سقف اتصال‌های هم‌زمان که به‌صورت خودکار بر اساس RAM و `RLIMIT_NOFILE` محدود می‌شود |
| `[server] workers` | `1` | نخ‌های کارگرِ epoll با SO_REUSEPORT. `1` = تک‌نخی؛ `0` = یکی به ازای هر CPU؛ `N` بار رله/رمزنگاری را روی هسته‌ها پخش می‌کند. وقتی `>1` باشد، بارگذاری مجدد پیکربندی با SIGHUP نیازمند ری‌استارت است |
| `[server] idle_timeout_sec` | `120` | مهلت بی‌کاریِ اتصال |
| `[server] idle_timeout_jitter_pct` | `15` | لرزش ±٪ به ازای هر اتصال روی مهلت بی‌کاری تا یک مقدار ثابت به اثر انگشت تبدیل نشود (`0` غیرفعال می‌کند) |
| `[server] max_connection_lifetime_sec` | `0` | بازیافت یک ریلهٔ برقرارشدهٔ قدیمی‌تر از N ثانیه با یک TCP RST، تا کلاینت تمیز دوباره وصل شود. هنگ «در حال به‌روزرسانی» موبایل پس از بازگشت از پس‌زمینهٔ طولانی را برطرف می‌کند (یک TCP طولانی‌عمر پنجرهٔ ازدحام را فرومی‌ریزد و همگام‌سازی کند می‌شود). `0` = نامحدود؛ `1800`–`3600` را امتحان کنید |
| `[server] handshake_timeout_sec` | `15` | مهلت تکمیل هندشیک |
| `[server] graceful_shutdown_timeout_sec` | `15` | مهلت تخلیه‌ی SIGTERM پیش از بستن اجباری |
| `[server] middleproxy_buffer_kb` | `1024` | بافر ME برای هر اتصال (KiB). کمتر از 1024 ممکن است در ترافیک رسانه‌ای باعث سرریز شود |
| `[server] tag` | — | برچسب تبلیغاتیِ 32 کاراکتر hex از [@MTProxybot](https://t.me/MTProxybot) |
| `[server] log_level` | `"info"` | `debug` / `info` / `warn` / `err` |
| `[server] rate_limit_per_subnet` | `0` | حداکثر اتصال‌های جدید در ثانیه به ازای هر /24 (IPv4) یا /48 (IPv6). `0` = غیرفعال (پیش‌فرض، سازگار با NAT)؛ برای هاست‌های بدون NAT مثلاً `30` تنظیم کنید |
| `[server] handshake_flood_guard_enabled` | `false` | مسدودسازیِ موقت IPهای مبدأِ دقیقی که مکرراً در هندشیک MTProto ناموفق‌اند (پیش‌فرض خاموش — امن برای NAT/VPN) |
| `[server] handshake_flood_guard_threshold` | `20` | تعداد رویدادهای هندشیک/نرخ/بودجه‌ی نامعتبر به ازای هر IP مبدأ پیش از مسدودسازی موقت |
| `[server] handshake_flood_guard_window_sec` | `30` | پنجره‌ی متحرک برای `handshake_flood_guard_threshold` |
| `[server] handshake_flood_guard_block_sec` | `120` | مدت‌زمان مسدودسازی موقت برای IPهای مبدأِ پر سر و صدا |
| `[server] unsafe_override_limits` | `false` | غیرفعال کردن محدودسازی خودکار `max_connections` |
| `[monitor] host` | `"127.0.0.1"` | آدرس اتصال (bind) داشبورد |
| `[monitor] port` | `61208` | پورت داشبورد |
| `[metrics] enabled` | `false` | فعال کردن نقطه‌ی پایانیِ توکار `/metrics` سازگار با Prometheus |
| `[metrics] host` | `"127.0.0.1"` | آدرس اتصال (bind) متریک‌ها |
| `[metrics] port` | `9400` | پورت متریک‌ها |
| `[censorship] tls_domain` | `"google.com"` | دامنه‌ای که جعل هویت می‌شود |
| `[censorship] mask` | `true` | هدایت کلاینت‌های احراز هویت‌نشده به `tls_domain` |
| `[censorship] unknown_sni_action` | `"mask"` | ClientHello با SNI ناشناخته: `mask` (هدایت)، `reject` (هشدار مرگبار TLS مانند سروری که رد می‌کند)، یا `drop` |
| `[censorship] mask_target` | تنظیم‌نشده | هاست بک‌اند اختیاری برای کلاینت‌های استتارشده |
| `[censorship] mask_port` | `443` | پورت استتار محلی (برای Nginx با zero-RTT از `8443` استفاده کنید) |
| `[censorship] desync` | `true` | Split-TLS: رکوردهای Application یک‌بایتی |
| `[censorship] drs` | `false` | اندازه‌گیری پویای رکورد (Dynamic Record Sizing) |
| `[censorship] fast_mode` | `false` | واگذاری رمزنگاریِ S2C به DC (توصیه‌شده) |
| `[access.users] <name>` | — | secret‏ 32 کاراکتر hex برای هر کاربر |
| `[access.direct_users] <name>` | — | دور زدن ME برای این کاربر |
| `[access.user_max_conns] <name>` | — | سقف اتصال‌های هم‌زمان به ازای هر کاربر (برای تغییر، ری‌استارت لازم است) |
| `[access.user_expirations] <name>` | — | تاریخ انقضای هر کاربر `"YYYY-MM-DD"` (برای تغییر، ری‌استارت لازم است) |

</details>

> یک secret تولید کنید: `mtbuddy secret` یا `openssl rand -hex 16`
>
> چاپ صریح لینک‌های کلاینت: `sudo mtbuddy links`. به‌صورت پیش‌فرض فقط لینک‌های FakeTLS (`ee...domain`) را چاپ می‌کند؛ همچنین وقتی ترابری `dd` فعال باشد (`fake_tls_only = false`) لینک‌های امنِ بالشتک‌دار (`dd...`) را نیز چاپ می‌کند. لاگ‌های زمان اجرای پراکسی عمداً اسرار و لینک‌های پراکسی را پنهان می‌کنند.
>
> **ترابری `dd` («امن»/بالشتک‌دار) به‌صورت پیش‌فرض رد می‌شود** (`[censorship].fake_tls_only = true`) — این فقط MTProto مبهم‌سازی‌شده با **بدون استتار TLS** است که مستقیماً توسط DPI به‌عنوان MTProto قابل‌اثرانگشت‌گیری است. به‌صورت پیش‌فرض پراکسی فقط FakeTLS (`ee`) را می‌پذیرد و `mtbuddy links` فقط لینک‌های `ee` را چاپ می‌کند. برای ارائه‌ی لینک‌های `dd` (سناریوهای سازگاری / DPI ضعیف‌تر)، مقدار `fake_tls_only = false` را تنظیم کنید. به [THREAT_MODEL.md](THREAT_MODEL.md) مراجعه کنید.
>
> هر دو نگهبانِ سوءاستفاده **به‌صورت پیش‌فرض خاموش‌اند** تا شبکه‌های بزرگ carrier-NAT، خروجی VPN یا دفاتر اشتراکی (با کلاینت‌های مشروع زیاد پشت یک IP/زیرشبکه) به‌اشتباه شناسایی و یکجا مسدود نشوند: محدودیت نرخ اتصال جدید به ازای هر زیرشبکه (`rate_limit_per_subnet = 0`) و نگهبان سیلِ هندشیکِ مبتنی بر IP دقیق (`handshake_flood_guard_enabled = false`). دسترسی پیشاپیش با secret هر کاربر، بودجهٔ سراسریِ هندشیک‌های در جریان و `max_connections` کنترل می‌شود. روی یک هاست تک‌مستأجر / بدون NAT که زیر سوءاستفادهٔ واقعی است، آن‌ها را روشن کنید: `rate_limit_per_subnet` را تنظیم کنید (مثلاً `30`) و `handshake_flood_guard_enabled = true` را قرار دهید (مقادیر `handshake_flood_guard_threshold` / پنجره / مدت مسدودسازی را تنظیم کنید).

---

## داشبورد نظارت

یک داشبورد وب سبک (~30 MB RAM) اتصال‌های زنده، CPU/حافظه، توان عبوری شبکه، آمار پراکسی، وضعیت سلامت/failover استخر تونل، مدیریت کاربران و لاگ‌های جریانی را نشان می‌دهد.

داشبورد **مستقیماً درون فایل اجرایی `mtbuddy` تعبیه شده است** — به فایل اضافه‌ای نیاز نیست.

```bash
# Install the dashboard on the server
sudo mtbuddy setup dashboard

# Open via SSH tunnel (binds to 127.0.0.1:61208 by default)
ssh -L 61208:localhost:61208 root@<server_ip>
# → http://localhost:61208
```

داشبورد به **HTTP Basic auth** نیاز دارد (نام کاربری: هر چیزی؛ گذرواژه به‌صورت خودکار در `/opt/mtproto-proxy/monitor/dashboard.token` تولید می‌شود — روی سرور آن را `cat` کنید). این یک صفحه‌ی کنترلِ دارای دسترسی root است، پس آن را روی مسیر loopback/SSH-tunnel نگه دارید و هرگز HTTP ساده را در معرض اینترنت قرار ندهید — اگر مجبورید، آن را پشت HTTPS + یک reverse proxy قرار دهید.

<details>
<summary>نمایش: داشبورد نظارت</summary>
<br>
<p align="center">
  <img src="https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/assets/dashboard.gif" alt="نمایش: داشبورد نظارت" width="80%">
</p>
<br>

</details>

---

## متریک‌های Prometheus

`mtproto-proxy` می‌تواند یک نقطه‌ی پایانیِ متریکِ توکار و سازگار با Prometheus را روی یک پورت اختصاصی در دسترس قرار دهد.

برای یک پشته‌ی نظارت کامل مبتنی بر Docker با `mtproto-zig`، Prometheus، Grafana و یک داشبورد قابل‌وارد کردن، به [hack/docker/README.md](hack/docker/README.md) مراجعه کنید.

```toml
[metrics]
enabled = true
host = "127.0.0.1"
port = 9400
```

این نقطه‌ی پایانی، HTTPِ متنیِ ساده است و این مسیر را ارائه می‌دهد:

```text
GET /metrics
```

استفاده‌ی معمول با Docker:

```bash
docker run --rm \
  -p 443:443 \
  -p 9400:9400 \
  -v "$PWD/config.toml:/etc/mtproto-proxy/config.toml:ro" \
  mtproto-zig
```

این شمارنده‌های پراکسی به‌علاوه‌ی متریک‌های فرایند مانند RSS، حافظه‌ی مجازی، زمان CPU و توصیف‌گرهای فایل باز را در دسترس قرار می‌دهد.

---

## ساخت محلی

نیازمند [Zig 0.16.0](https://ziglang.org/download/) است.

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

سازندگان نسخه‌های انتشار می‌توانند در صورت نیاز کلید پیش‌فرض و پین‌شده‌ی minisign را بازنویسی کنند:

```bash
zig build -Dminisign_pubkey=RW... -Doptimize=ReleaseFast -Dtarget=x86_64-linux
```

کامپایل متقابل برای Linux از macOS:

```bash
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux -Dcpu=x86_64_v3+aes
scp zig-out/bin/mtproto-proxy root@<SERVER>:/opt/mtproto-proxy/
```

---

## Docker

پشتیبانی از Docker برای آزمایش، آزمون‌های بسته‌بندی و استقرارهای ساده‌ای که فقط فایل اجرایی پراکسی لازم است فراهم شده. این پروژه در درجه‌ی اول برای یک هاست بومیِ Linux که توسط `mtbuddy` مدیریت می‌شود طراحی شده است: ماژول‌های DPI، failover استخر تونل، مسیریابیِ مبتنی بر سیاست، استتار Nginx، nfqws و تایمرهای بازیابی، یکپارچه‌سازی‌های سطح-هاست هستند و به‌طور کامل توسط کانتینر نمایندگی نمی‌شوند.

```bash
docker pull ghcr.io/sleep3r/mtproto.zig:latest

docker run --rm \
  -p 443:443 \
  -v "$PWD/config.toml:/etc/mtproto-proxy/config.toml:ro" \
  ghcr.io/sleep3r/mtproto.zig:latest
```

ترافیک رسانه/تبلیغِ MiddleProxy به IP:port مبدأِ خروجی که در هندشیک رمزنگاری‌شده‌اش استفاده می‌شود حساس است. برای استقرارهای Docker که به MiddleProxy نیاز دارند، شبکه‌ی هاست (`--network host`) یا نصب بومیِ `mtbuddy` را ترجیح دهید. `[server].public_ip` فقط آدرس ورودی است که به کلاینت‌ها نمایش داده می‌شود؛ اگر ترافیک خروجیِ DC از طریق یک IP مربوط به VPN/NAT خارج می‌شود، `[server].middle_proxy_nat_ip` را روی آن IPv4 خروجی تنظیم کنید. Bridge یا NAT راه دور که پورت‌های مبدأ را بازنویسی می‌کند، همچنان می‌تواند هندشیک‌های MiddleProxy را بشکند.

ساخت محلی:

```bash
docker build -t mtproto-zig .
# multi-arch
docker buildx build --platform linux/amd64,linux/arm64 -t your-registry/mtproto-zig:latest --push .
```

ایمیج‌های منتشرشده‌ی `linux/amd64` با یک پروفایل CPU قابل‌حمل (`-Dcpu=x86_64`) ساخته می‌شوند تا از کرش‌های `Illegal instruction` روی CPUهای قدیمی‌ترِ VPS جلوگیری شود.

> برای استقرارهای تولیدیِ دور زدن سانسور، جریان بومیِ `mtbuddy install` را ترجیح دهید. کاهش‌دهنده‌های سطح-سیستم‌عامل (iptables TCPMSS، nfqws، مسیریابیِ سیاستیِ تونل، واحدهای استتار/بازیابی) درون کانتینر اعمال نمی‌شوند؛ فقط فایل اجرایی پراکسی آنجا اجرا می‌شود.

---

## اعتماد و امنیت

- [SECURITY.md](SECURITY.md) - سیاست گزارش آسیب‌پذیری و فرایند پاسخ‌دهی
- [THREAT_MODEL.md](THREAT_MODEL.md) - اهداف امنیتی، غیر-اهداف، مدل دشمن، خطرات باقیمانده
- [CONTRIBUTING.md](CONTRIBUTING.md) - جریان کار توسعه (`fmt`/`test`/`e2e`/`bench`) و انتظارات PR
- [CHANGELOG.md](CHANGELOG.md) - تاریخچه‌ی انتشار
- [LICENSE](LICENSE) - شرایط مجوز MIT

حاکمیت مخزن:
- [`.github/CODEOWNERS`](.github/CODEOWNERS)
- قالب‌های issue در [`.github/ISSUE_TEMPLATE`](.github/ISSUE_TEMPLATE)

---

## محدودیت‌های شناخته‌شده و سازگاری

برای مدل کامل به [THREAT_MODEL.md](THREAT_MODEL.md) مراجعه کنید. خلاصه‌ی عملیاتیِ سریع:

- **محدودیت‌های شناخته‌شده**
  - این یک پراکسیِ مقاوم‌سازِ ترابری است، نه یک شبکه‌ی ناشناس‌سازی.
  - کیفیت دور زدن سانسور می‌تواند با تکامل راهبردهای DPI افت کند.
  - داشبورد/متریک‌ها به‌صورت پیش‌فرض متنیِ ساده هستند؛ بدون احراز هویت/TLS آن‌ها را به‌صورت عمومی در معرض قرار ندهید.
  - تماس‌های Telegram از طریق این پراکسی کار نمی‌کنند. تماس‌ها به مسیر تماسِ SOCKS-مانندِ Telegram نیاز دارند که خارج از مدل MTProto/استتار TLS است و در اینجا نمی‌توان آن را به‌طور تمیز به‌شکل HTTPS معمولی استتار کرد.
  - بدون MiddleProxy (`[general].use_middle_proxy = true`)، رسانه روی حساب‌های غیر-Premium بارگذاری نمی‌شود. MiddleProxy برای عکس‌ها، ویدیوها، استوری‌ها و برچسب‌های تبلیغاتی لازم است.
- **ملاحظات خاصِ هر منطقه**
  - رفتار ISP بسته به کشور/منطقه فرق می‌کند؛ پیکربندی‌ها به‌طور جهانی قابل‌انتقال نیستند.
  - مدیریت IPv6 و AAAA میان ارائه‌دهندگان به‌شدت متفاوت است و می‌تواند بر تأخیر اتصال iOS/Desktop اثر بگذارد.
  - مسیریابیِ تونل به مسیریابیِ سیاستیِ هاست و پروتکل‌های VPN مجاز در آن منطقه بستگی دارد.
- **سازگاری کلاینت‌های Telegram**
  - Telegram رسمی روی Android/iOS/Desktop: انتظار می‌رود روی نسخه‌های فعلی کار کند.
  - کلاینت‌های شخص‌ثالث: فقط در حد تلاش بهینه (best effort).
- **ماتریس سازگاری کرنل/سیستم‌عامل**
  - Linux `x86_64`: پشتیبانی‌می‌شود (هدف اصلی)
  - Linux `aarch64`: پشتیبانی‌می‌شود
  - Docker روی Linux: با ملاحظاتی پشتیبانی‌می‌شود (ماژول‌های DPI سطح-سیستم‌عامل سمت هاست هستند)
  - اجرای روی macOS/Windows: پشتیبانی نمی‌شود (فقط هدف اجرای Linux)
- **چه چیزهایی پس از تغییرات Telegram/DC ممکن است خراب شوند**
  - فراداده‌ی MiddleProxy و رفتار نقطه‌ی پایانی
  - انتظارات هندشیک در کلاینت‌های جدیدتر Telegram
  - موارد حاشیه‌ای مسیریابیِ DC/رسانه (برای مثال رفتار DC203)

---

## عیب‌یابی — گیر کردن روی «Updating...»

**1. رکورد AAAA وجود دارد اما IPv6 روی سرور کار نمی‌کند.**
DNS یک AAAA دارد → iOS ابتدا IPv6 را امتحان می‌کند → مهلت تمام می‌شود → بازگشت کند به IPv4.
راه‌حل: تا زمانی که مسیریابی IPv6 کاملاً پیکربندی شود، AAAA را حذف کنید.

```bash
dig +short proxy.example.com AAAA
ip -6 route
```

**2. Wi-Fi خانگی، IPv4 سرور را مسدود می‌کند.**
شبکه‌های موبایل معمولاً کار می‌کنند (از IPv6 استفاده می‌کنند). روترهای خانگی اغلب IPv4 مقصد را مسدود می‌کنند.
راه‌حل: روی روتر خود IPv6 Prefix Delegation (IA_PD) را فعال کنید.

**3. VPN ترافیک MTProto را می‌اندازد.**
VPNهای تجاری اغلب DPI انجام می‌دهند و ترافیک پراکسی را می‌اندازند.
راه‌حل: پروتکل VPN را عوض کنید، یا از یک AmneziaWGِ خودمیزبان استفاده کنید.

**4. هم‌مکانیِ WireGuard/Docker روی یک سرور.**
پلِ (bridge) Docker بسته‌های آمده از زیرشبکه‌ی VPN را می‌اندازد.
راه‌حل: `iptables -I DOCKER-USER -s 172.29.172.0/24 -p tcp --dport 443 -j ACCEPT`

**5. رسانه‌ی DC203 روی کلاینت‌های غیر-premium ریست می‌شود.**
لاگ‌ها را بررسی کنید: `journalctl -u mtproto-proxy | grep -E "dc=203|Middle"`.
پراکسی هنگام راه‌اندازی فراداده‌ی DC203 را به‌صورت خودکار از Telegram تازه‌سازی می‌کند. اگر `core.telegram.org` در دسترس نباشد، از آدرس‌های جایگزینِ همراهِ بسته استفاده می‌کند.
با `[upstream].type = "socks5"` یا `"http"`، تازه‌سازی‌های فراداده از همان بالادست استفاده می‌کنند؛ برای بررسی نقطه‌ی پایانیِ پراکسی و مسیر دریافت فراداده‌ی Telegram دستور `sudo mtbuddy config doctor --network` را اجرا کنید.

---

## مجوز

[MIT](LICENSE) © 2026 Aleksandr Kalashnikov
