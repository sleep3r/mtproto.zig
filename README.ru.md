<div align="center">

# mtproto.zig

**Держите близких на связи.**

Крошечный Telegram-прокси, который вы запускаете на своём сервере. Он прячется в обычном HTTPS — цензуре его не найти, а вашим близким не потерять. Установка одной командой, одна ссылка, чтобы поделиться.

`177 КБ · меньше 1 МБ RAM · 0 зависимостей` — да, он настолько лёгкий *(подробности ниже ↓)*

<sub>Технически: крошечный MTProto-прокси на Zig без зависимостей, маскирует трафик Telegram под обычный TLS 1.3 HTTPS.</sub>

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/zig-0.16.0-f7a41d.svg?logo=zig&logoColor=white)](https://ziglang.org)
[![Platform](https://img.shields.io/badge/platform-linux-blueviolet.svg?logo=linux&logoColor=white)](#установка)

<div align="center">

| [🇬🇧 English](README.md) | **🇷🇺 Русский** | [🇨🇳 中文](README.zh.md) | [🇮🇷 فارسی](README.fa.md) | [🇻🇳 Tiếng Việt](README.vi.md) |
| :-: | :-: | :-: | :-: | :-: |

</div>

</div>

---

<p align="center">
<a href="#почему-этот-прокси">Почему этот?</a> · <a href="#установка">Установка</a> · <a href="#обновление">Обновление</a> · <a href="#команды-mtbuddy">Команды</a> · <a href="#маршрутизация-upstream">Маршрутизация</a> · <a href="#конфигурация">Конфиг</a> · <a href="#дашборд-мониторинга">Дашборд</a> · <a href="#локальная-сборка">Сборка</a> · <a href="#docker">Docker</a> · <a href="#доверие-и-безопасность">Безопасность</a> · <a href="#ограничения-и-совместимость">Совместимость</a> · <a href="#troubleshooting--застряло-на-updating">FAQ</a>
</p>

---

## Для кого это

- **Вы там, где Telegram режут или блокируют**, и хотите просто вернуть его.
- **Вы — тот, к кому семья идёт за помощью**, и хотите защитить родителей и друзей ссылкой, которую они нажимают один раз и больше о ней не думают.

Прокси работает на **вашем сервере** — ваши сообщения никогда не идут через наш, и регистрироваться нигде не нужно. Открытый код под лицензией MIT; прокси намеренно не пишет в логи ни секреты, ни кто подключается.

## Чем это лучше VPN?

VPN заметен — цензор узнаёт протокол и блокирует его, а VPN на всё устройство медленный и сажает батарею. Этот прокси выглядит как обычный HTTPS-сайт, ведёт только Telegram, и тем, кому вы дали ссылку, **не нужно ничего устанавливать**: они нажимают одну ссылку, остальное Telegram делает сам. Помещается на самый дешёвый VPS, стартует мгновенно, больше ничего настраивать не нужно.

## В сравнении с другими MTProto-прокси

Большинство MTProto-прокси крупные, тянут зависимости и потребляют много памяти. Этот проект устроен иначе:

| Proxy | Язык | Бинарник | Baseline RSS | Старт | Зависимости |
|---|---|---:|---:|---|---|
| **mtproto.zig** | Zig | **177 КБ** | **0.75 МБ** | **< 10 мс** | **0** |
| Official MTProxy | C | 524 КБ | 8.0 МБ | < 10 мс | openssl, zlib |
| Telemt | Rust | 15 МБ | 12.1 МБ | ~ 5-6 с | 423 crates |
| mtg | Go | 13 МБ | 11.6 МБ | ~ 30 мс | 78 modules |
| MTProtoProxy | Python | N/A | ~ 30 МБ | ~ 300 мс | python3, cryptography |
| JSMTProxy | Node.js | N/A | ~ 45 МБ | ~ 400 мс | nodejs, openssl |

## Почему Zig?

Zig даёт производительность и минимальный footprint уровня C, но без привычной боли C-проектов:
- **Без произвольных аллокаций:** слоты соединений и буферы заранее выделяются на старте. Нет GC, который может уронить кадры под нагрузкой.
- **Герметичная кросс-компиляция:** можно запустить `zig build` на macOS и получить статически слинкованный Linux-бинарник. Без Docker и несовпадений `glibc`.
- **Comptime:** маппинг протокола, endian-конверсии и двуязычные строки `mtbuddy` вычисляются при компиляции.

Прокси также включает набор техник обхода DPI:

| Техника | Что делает |
|---|---|
| **Fake TLS 1.3** | Соединения выглядят как обычный HTTPS |
| **DRS** | Имитирует размеры TLS-record у Chrome/Firefox |
| **Маскировка от активных проб** | Если цензор проверяет ваш сервер, он получает настоящий TLS-хендшейк от локального веб-бэкенда (реальный серт, если домен ваш, иначе self-signed), а не молчащий прокси. Опционально: фронтить реальный `tls_domain:443` для доменов с одноходовым x25519 |
| **TCPMSS=88** | Дробит ClientHello на маленькие TCP-пакеты |
| **nfqws TCP desync** | Fake packets + TTL-limited splits против stateful DPI |
| **Split-TLS** | 1-байтовые Application records против пассивных сигнатур |
| **VPN tunnel pool** | Маршрутизация через WireGuard/AmneziaWG с `SO_MARK` и failover |
| **IPv6 hopping** | Авто-ротация IPv6 из /64 при банах через Cloudflare API |
| **Anti-replay** | Отбрасывает replay handshakes и активные пробы ТСПУ Revisor |
| **Multi-user** | Отдельные secret для разных пользователей |
| **MiddleProxy** | ME transport с автообновлением Telegram metadata |

MiddleProxy нужен для промо-тега и медиа на аккаунтах без Premium. Без него фото, видео, истории и другое медиа на non-Premium аккаунтах нужно считать недоступными, а не «иногда лагающими». Звонки Telegram не поддерживаются: Telegram ведёт звонки через SOCKS-пути, а такой трафик нельзя нормально замаскировать в mtproto.zig под обычный HTTPS.

---

## Установка

Установка, обновление и управление делаются через **mtbuddy** — нативный Zig CLI, который поставляется вместе с прокси.

### Одна команда

```bash
curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/bootstrap.sh | sudo bash

# Явно разрешить unsigned bootstrap mode (не рекомендуется)
curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/bootstrap.sh | sudo bash -s -- --insecure
# или: MTPROTO_INSECURE=1
```

Скрипт скачивает последний `mtbuddy`, проверяет minisign-подпись и SHA-256 checksum из GitHub Release, затем запускает `mtbuddy --help`. После этого установите прокси:

```bash
# Минимально: secret генерируется автоматически, DPI-модули включены
sudo mtbuddy install --port 443 --domain rutube.ru --yes

# Свой secret и имя пользователя
sudo mtbuddy install --port 443 --domain rutube.ru --secret <32-hex> --user alice --yes

# Без DPI-модулей, только bare proxy
sudo mtbuddy install --port 443 --domain rutube.ru --no-dpi --yes

# Установка из существующего config.toml
sudo mtbuddy install --config /path/to/config.toml --yes

# Явно разрешить unsigned mode (не рекомендуется)
sudo mtbuddy install --insecure --port 443 --domain rutube.ru --yes
```

В конце `mtbuddy` напечатает готовую `tg://` ссылку для подключения.

### Интерактивный мастер

```bash
sudo mtbuddy --interactive
```

<details>
<summary>Демо: интерактивная установка</summary>
<br>
<p align="center">
  <img src="https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/assets/buddy.gif" alt="Demo: interactive installer" width="80%">
</p>
<br>

</details>

### Что делает установка

1. Скачивает **готовый бинарник прокси** из GitHub Releases.
2. Генерирует случайный secret или использует `--secret`.
3. Создаёт systemd service `mtproto-proxy`.
4. Открывает порт в `ufw`, если он активен.
5. Применяет iptables-правила TCPMSS=88.
6. Настраивает Nginx masking и nfqws TCP desync, если не указан `--no-dpi`.
7. Печатает `tg://` ссылку.

### Параметры установки

| Флаг | По умолчанию | Описание |
|---|---|---|
| `--port, -p` | `443` | Порт прокси |
| `--public-port` | — | Порт, который будет указан в Telegram-ссылках |
| `--domain, -d` | `rutube.ru` | Домен TLS-маскировки (⚠️ **неизменен** — см. примечание ниже) |
| `--secret, -s` | auto | User secret, 32 hex chars |
| `--user, -u` | `user` | Имя пользователя в `config.toml` |
| `--config, -c` | — | Использовать существующий `config.toml` |
| `--yes, -y` | — | Пропустить подтверждение |
| `--max-connections <N>` | `512` | Максимум соединений |
| `--bind, -b` | — | Bind на конкретный IP |
| `--no-masking` | — | Выключить Nginx masking |
| `--no-nfqws` | — | Выключить nfqws TCP desync |
| `--no-tcpmss` | — | Выключить TCPMSS=88 |
| `--no-dpi` | — | Выключить все DPI-модули |
| `--middle-proxy` | — | Включить Telegram MiddleProxy relay |
| `--ipv6-hop` | — | Включить IPv6 auto-hopping |
| `--version, -v <tag>` | `latest` | Версия релиза |
| `--insecure` | — | Разрешить unsigned assets (не рекомендуется) |

> ⚠️ **Выберите `--domain` один раз.** tg://-ссылки вшивают `tls_domain`, поэтому смена
> домена на живом сервере (в т.ч. через `mtbuddy setup masking --domain …`)
> **инвалидирует все уже розданные ссылки.** См. [ARCHITECTURE.md](ARCHITECTURE.md) / [COMPATIBILITY.md](COMPATIBILITY.md).

---

## Обновление

```bash
# Обновиться до последнего релиза
sudo mtbuddy update

# Зафиксировать конкретную версию
sudo mtbuddy update --version v0.11.1

# Явно разрешить unsigned mode (не рекомендуется)
sudo mtbuddy update --insecure
```

---

## Команды mtbuddy

```bash
# Статус прокси и модулей
sudo mtbuddy status

# Проверка и просмотр конфига
sudo mtbuddy config validate
sudo mtbuddy config doctor
sudo mtbuddy config doctor --network
sudo mtbuddy config print-effective

# Напечатать ссылки из config.toml (по умолчанию FakeTLS ee; +dd при fake_tls_only=false; секретный вывод)
sudo mtbuddy links
sudo mtbuddy links --server proxy.example.com --config /opt/mtproto-proxy/config.toml

# Сгенерировать новый 32-hex secret
mtbuddy secret

# Hot-reload config
sudo mtbuddy reload

# Настроить DPI-модули после установки
sudo mtbuddy setup masking --domain rutube.ru
sudo mtbuddy setup nfqws
sudo mtbuddy setup recovery

# Установить web dashboard
sudo mtbuddy setup dashboard

# VPN tunnel pool
sudo mtbuddy setup tunnel /path/to/awg0.conf
sudo mtbuddy setup tunnel 'vpn://...'
sudo mtbuddy setup tunnel --iface awg1 /path/to/awg1.conf

# IPv6 hopping
sudo mtbuddy ipv6-hop --check
sudo mtbuddy ipv6-hop --auto --prefix 2a01:abcd:ef00:: --threshold 5

# Обновить Cloudflare DNS A record
sudo mtbuddy update-dns 1.2.3.4

# Помощь
mtbuddy --help
mtbuddy --lang ru --help
```

---

## Управление сервисом

```bash
sudo systemctl status mtproto-proxy
sudo journalctl -u mtproto-proxy -f
sudo systemctl reload mtproto-proxy
sudo systemctl restart mtproto-proxy
```

---

## Маршрутизация upstream

Прокси поддерживает несколько способов маршрутизации исходящих соединений к Telegram DC.

| `[upstream].type` | Как работает | Когда использовать |
|---|---|---|
| `auto` | Direct egress без policy mark | Большинство установок |
| `direct` | Прямое соединение с Telegram DC | DC доступны с сервера |
| `tunnel` | `SO_MARK=200` и policy routing через VPN tunnel pool | DC заблокированы провайдером |
| `socks5` | Внешний SOCKS5 proxy с опциональной auth | Уже есть proxy-инфраструктура |
| `http` | HTTP CONNECT proxy с Basic auth | Corporate proxy environments |

### VPN tunnel pool

Если Telegram DC заблокированы на уровне сети, можно вести proxy-трафик через пул VPN-туннелей с явным socket policy routing. Прокси работает в host namespace; только сокеты с `SO_MARK=200` идут через table 200. `mtbuddy` держит table 200 на первом живом туннеле из заданного порядка.

Поддерживаемые типы:
- **AmneziaWG** — DPI-resistant fork WireGuard, основной вариант для Russia/Iran.
- **WireGuard** — стандартный WireGuard (planned).

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
sudo mtbuddy setup tunnel 'vpn://...'
sudo mtbuddy setup tunnel --iface awg1 /path/to/awg1.conf
```

В интерактивном меню `mtbuddy` настройка туннеля сначала спрашивает тип VPN (пока доступен только AmneziaWG), затем показывает текущий пул. Выберите **Создать новый туннель**, чтобы добавить следующий свободный `awgN`, или выберите существующий интерфейс, чтобы заменить конфиг этого участника пула.

`mtbuddy` не трогает `[general].use_middle_proxy`, а настраивает только transport (`[upstream].type = "tunnel"`). После setup он ставит `mtproto-tunnel-pool.timer`, проверяет `mark 200` к Telegram DC и печатает команды для эксплуатации. Контроллер пула пробует Telegram через каждый туннель и делает `ip route replace`; автоматический failover не перезапускает `mtproto-proxy`.

Пример конфига:

```toml
[upstream]
type = "tunnel"

[upstream.tunnel]
interface = "awg0"       # legacy / fallback
interfaces = ["awg0", "awg1"]
pinned_interface = ""    # пусто = priority auto-failback
```

### SOCKS5 proxy

```toml
[upstream]
type = "socks5"

[upstream.socks5]
host = "127.0.0.1"
port = 1080
username = "admin"    # optional
password = "secret"
```

### HTTP CONNECT proxy

```toml
[upstream]
type = "http"

[upstream.http]
host = "127.0.0.1"
port = 8080
username = "admin"    # optional
password = "secret"
```

> **Важно:** через upstream маршрутизируется трафик к DC и refresh MiddleProxy metadata (`getProxyConfig` / `getProxySecret`). Mask/camouflage-соединения всегда идут напрямую.

> **О зависимостях:** «ноль зависимостей» верно для дефолтного `auto`/`direct`. В режимах `socks5`, `http` или `tunnel` refresh метаданных MiddleProxy вызывает `curl`, поэтому `curl` должен быть установлен на хосте (штатный установщик ставит его сам).

---

## Конфигурация

Конфиг находится в `/opt/mtproto-proxy/config.toml`. `mtbuddy` создаёт его при установке; можно редактировать вручную и перезапускать сервис.

```toml
[general]
use_middle_proxy = true

[upstream]
type = "auto"            # auto | direct | tunnel | socks5 | http
# allow_direct_fallback = false

[server]
port = 443
# public_ip = "proxy.example.com"   # входящий IP/domain для клиентских ссылок
# public_port = 443                 # порт в ссылках при HAProxy/Nginx
# middle_proxy_nat_ip = "203.0.113.10"   # исходящий IPv4, который видит Telegram MiddleProxy
max_connections = 512
# workers = 1            # SO_REUSEPORT epoll-воркеры: 1 = однопоточно (дефолт); 0 = по числу CPU; N распределяет нагрузку по ядрам
idle_timeout_sec = 120
handshake_timeout_sec = 15
graceful_shutdown_timeout_sec = 15
log_level = "info"
rate_limit_per_subnet = 0   # 0 = выключено (по умолчанию; не ложно-срабатывает на carrier-NAT). Для не-NAT хостов задайте напр. 30
handshake_flood_guard_enabled = true
handshake_flood_guard_threshold = 20
handshake_flood_guard_window_sec = 30
handshake_flood_guard_block_sec = 120
tag = ""                  # Optional: promotion tag from @MTProxybot

[censorship]
tls_domain = "rutube.ru"
mask = true
# mask_target = "host.docker.internal" # Optional: custom masking backend host для Docker/remote Nginx
mask_port = 8443          # 8443 = локальный Nginx (так ставит mtbuddy); 443 = фронт реального tls_domain (опционально, только домены с одноходовым x25519)
fast_mode = true
drs = true

[access.users]
alice = "00112233445566778899aabbccddeeff"
bob   = "ffeeddccbbaa99887766554433221100"

[access.direct_users]
alice = true
```

Ключевые параметры:

| Key | Default | Описание |
|---|---|---|
| `[upstream].type` | `auto` | `auto`, `direct`, `tunnel`, `socks5`, `http` |
| `[upstream] allow_direct_fallback` | `false` | Разрешить fallback на direct для socks5/http |
| `[upstream.tunnel] interface` | `"awg0"` | Legacy single interface / fallback |
| `[upstream.tunnel] interfaces` | `["awg0"]` | Ordered tunnel pool |
| `[upstream.tunnel] pinned_interface` | — | Ручной preferred interface, если он жив |
| `[general] use_middle_proxy` | `false` | ME mode для DC1..5 |
| `[server] port` | `443` | TCP listen port |
| `[server] public_ip` | auto | Входящий IP/domain для клиентских ссылок |
| `[server] public_port` | `[server].port` | Порт для клиентских ссылок, если публичный порт отличается от listen-port |
| `[server] middle_proxy_nat_ip` | auto | Исходящий IPv4 для MiddleProxy key derivation; auto-detect не использует `public_ip`, задайте явно при VPN/NAT egress |
| `[server] max_connections` | `512` | Лимит одновременных соединений |
| `[server] workers` | `1` | SO_REUSEPORT epoll-воркеры: `1` = однопоточно; `0` = по числу CPU; `N` распределяет нагрузку relay/crypto по ядрам. При `>1` перезагрузка конфига по SIGHUP требует рестарта |
| `[server] middleproxy_buffer_kb` | `1024` | Буфер MiddleProxy на соединение |
| `[server] tag` | — | 32-hex promotion tag от [@MTProxybot](https://t.me/MTProxybot) |
| `[server] rate_limit_per_subnet` | `0` | Лимит новых соединений/сек на /24 (IPv4) или /48 (IPv6). `0` = выключено (по умолчанию, NAT-friendly); для не-NAT хостов задайте напр. `30` |
| `[server] handshake_flood_guard_enabled` | `true` | Временно отклонять IP, которые часто не проходят MTProto handshake |
| `[server] handshake_flood_guard_threshold` | `20` | Число плохих handshake/rate/budget событий с одного IP до временного deny |
| `[server] handshake_flood_guard_window_sec` | `30` | Окно подсчёта для `handshake_flood_guard_threshold` |
| `[server] handshake_flood_guard_block_sec` | `120` | Длительность временного deny для шумного IP |
| `[censorship] tls_domain` | `"google.com"` | Домен для TLS-маскировки |
| `[censorship] mask` | `true` | Forward invalid clients на `tls_domain` |
| `[censorship] mask_target` | unset | Optional backend host для masked clients |
| `[censorship] mask_port` | `443` | Local masking port (`8443` для Nginx zero-RTT) |
| `[censorship] fast_mode` | `false` | Делегировать S2C encryption DC |
| `[access.users] <name>` | — | 32-hex secret на пользователя |
| `[access.direct_users] <name>` | — | Bypass MiddleProxy для пользователя |

> Secret можно сгенерировать через `mtbuddy secret` или `openssl rand -hex 16`.
>
> Ссылки печатаются командой `sudo mtbuddy links`: по умолчанию показываются только FakeTLS (`ee...domain`) ссылки; secure padded (`dd...`) варианты выводятся, когда включён транспорт `dd` (`fake_tls_only = false`). Runtime-логи намеренно скрывают secrets и proxy links.
>
> **Транспорт `dd` («secure»/padded) по умолчанию отключён** (`[censorship].fake_tls_only = true`) — это обычный обфусцированный MTProto **без TLS-маскировки**, который DPI фингерпринтит напрямую как MTProto. По умолчанию прокси принимает только FakeTLS (`ee`), и `mtbuddy links` печатает только `ee`-ссылки. Чтобы раздавать `dd`-ссылки (сценарии с низким DPI / совместимость), задайте `fake_tls_only = false`. См. [THREAT_MODEL.md](THREAT_MODEL.md).
>
> Per-subnet rate limit **по умолчанию выключен** (`rate_limit_per_subnet = 0`), чтобы carrier-NAT/офисные сети (много легитимных клиентов за одним IP/подсетью) не получали ложных блокировок. Handshake flood guard остаётся включённым, но с выключенным subnet-лимитом он реагирует только на брошенные/незавершённые handshake — которые легитимные владельцы secret практически не создают. Если `flood_guard+` всё же блокирует реальных пользователей при burst, поднимите `handshake_flood_guard_threshold` / window / block или задайте `handshake_flood_guard_enabled = false`. `rate_limit_per_subnet` включайте только на single-tenant / не-NAT хостах.

---

## Дашборд мониторинга

Лёгкий web dashboard (~30 МБ RAM) показывает live connections, CPU/RAM, network throughput, proxy stats, состояние tunnel pool/failover, пользователей и streaming logs.

```bash
sudo mtbuddy setup dashboard

# Открыть через SSH tunnel
ssh -L 61208:localhost:61208 root@<server_ip>
# → http://localhost:61208
```

Dashboard требует **HTTP Basic auth** (имя пользователя: любое; пароль генерируется автоматически в `/opt/mtproto-proxy/monitor/dashboard.token` — выведите его командой `cat` на сервере). Это root-привилегированная панель управления, поэтому держите её на loopback/SSH-туннеле и никогда не публикуйте по plain HTTP — только за HTTPS + reverse proxy.

<details>
<summary>Демо: dashboard</summary>
<br>
<p align="center">
  <img src="https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/assets/dashboard.gif" alt="Demo: monitoring dashboard" width="80%">
</p>
<br>

</details>

---

## Prometheus metrics

`mtproto-proxy` может отдавать Prometheus-compatible endpoint на отдельном порту.

```toml
[metrics]
enabled = true
host = "127.0.0.1"
port = 9400
```

Endpoint plaintext HTTP:

```text
GET /metrics
```

Docker-пример для метрик:

```bash
docker run --rm \
  -p 443:443 \
  -p 9400:9400 \
  -v "$PWD/config.toml:/etc/mtproto-proxy/config.toml:ro" \
  mtproto-zig
```

---

## Локальная сборка

Нужен [Zig 0.16.0](https://ziglang.org/download/).

```bash
git clone https://github.com/sleep3r/mtproto.zig.git
cd mtproto.zig

make build
make test
make e2e
make fmt
make deploy
make dashboard

# optional
zig build bench
zig build soak
```

Кросс-компиляция под Linux с macOS:

```bash
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux -Dcpu=x86_64_v3+aes
scp zig-out/bin/mtproto-proxy root@<SERVER>:/opt/mtproto-proxy/
```

---

## Docker

Docker поддерживается для тестов, упаковочных экспериментов и простых сценариев, где нужен только бинарник прокси. Основной production-путь проекта — нативный Linux host под управлением `mtbuddy`: DPI-модули, tunnel pool failover, policy routing, Nginx masking, nfqws и recovery timers являются host-level интеграциями и не представлены контейнером полностью.

```bash
docker pull ghcr.io/sleep3r/mtproto.zig:latest

docker run --rm \
  -p 443:443 \
  -v "$PWD/config.toml:/etc/mtproto-proxy/config.toml:ro" \
  ghcr.io/sleep3r/mtproto.zig:latest
```

MiddleProxy для медиа/промо чувствителен к исходному source IP:port, который попадает в encrypted handshake. Для Docker-деплоя с MiddleProxy лучше использовать host networking (`--network host`) или нативный `mtbuddy install`. `[server].public_ip` теперь только входящий адрес для клиентов; если DC-трафик выходит через VPN/NAT IP, задайте `[server].middle_proxy_nat_ip` этим egress IPv4. Bridge или удаленный NAT, переписывающий source port, всё равно может ломать MiddleProxy handshake.

Локальная сборка:

```bash
docker build -t mtproto-zig .
docker buildx build --platform linux/amd64,linux/arm64 -t your-registry/mtproto-zig:latest --push .
```

> Для production censorship-bypass deployments лучше использовать `mtbuddy install`. OS-level mitigations (iptables TCPMSS, nfqws, tunnel policy routing, masking/recovery units) внутри контейнера не применяются; в контейнере запускается только proxy binary.

---

## Доверие и безопасность

- [SECURITY.md](SECURITY.md) — vulnerability reporting policy.
- [THREAT_MODEL.md](THREAT_MODEL.md) — security goals, non-goals, adversary model, residual risks.
- [CONTRIBUTING.md](CONTRIBUTING.md) — dev workflow и PR expectations.
- [CHANGELOG.md](CHANGELOG.md) — история релизов.
- [LICENSE](LICENSE) — MIT license.

---

## Ограничения и совместимость

Полная модель описана в [THREAT_MODEL.md](THREAT_MODEL.md). Кратко:

- **Известные ограничения**
  - Это transport-hardening proxy, а не анонимная сеть.
  - Качество обхода может меняться по мере развития DPI.
  - Dashboard/metrics по умолчанию plaintext; не публикуйте их без auth/TLS.
  - Звонки Telegram через этот прокси не работают. Звонки требуют SOCKS-style path, который не вписывается в MTProto/TLS masking.
  - Без MiddleProxy (`[general].use_middle_proxy = true`) медиа на non-Premium аккаунтах не будут грузиться.
- **Региональные caveats**
  - Поведение провайдеров отличается по странам и регионам.
  - IPv6/AAAA сильно зависят от провайдера и могут влиять на iOS/Desktop latency.
  - Tunnel routing зависит от host policy routing и разрешённых VPN-протоколов.
- **Telegram clients**
  - Official Telegram Android/iOS/Desktop: ожидается работа на актуальных версиях.
  - Third-party clients: best effort.
- **OS/kernel**
  - Linux `x86_64`: supported.
  - Linux `aarch64`: supported.
  - Docker on Linux: supported with caveats.
  - macOS/Windows runtime: not supported.
- **Что может сломаться после изменений Telegram/DC**
  - MiddleProxy metadata и endpoint behavior.
  - handshake expectations новых клиентов.
  - DC/media routing edge cases.

---

## Troubleshooting — застряло на "Updating..."

**1. Есть AAAA record, но IPv6 на сервере не работает.**
DNS отдаёт AAAA, iOS пробует IPv6 первым, получает timeout и медленно падает на IPv4.
Решение: убрать AAAA, пока IPv6 routing не настроен полностью.

```bash
dig +short proxy.example.com AAAA
ip -6 route
```

**2. Домашний Wi-Fi блокирует IPv4 сервера.**
Мобильные сети часто работают, потому что используют IPv6. Домашние роутеры могут блокировать destination IPv4.
Решение: включить IPv6 Prefix Delegation (IA_PD) на роутере.

**3. VPN режет MTProto traffic.**
Коммерческие VPN часто DPI'ят и дропают proxy traffic.
Решение: сменить VPN protocol или использовать self-hosted AmneziaWG.

**4. WireGuard/Docker на том же сервере.**
Docker bridge может дропать пакеты из VPN subnet.
Решение: `iptables -I DOCKER-USER -s 172.29.172.0/24 -p tcp --dport 443 -j ACCEPT`

**5. DC203 media resets на non-premium clients.**
Проверьте логи:

```bash
journalctl -u mtproto-proxy | grep -E "dc=203|Middle"
```

Прокси обновляет DC203 metadata с Telegram на старте. Если `core.telegram.org` недоступен, используются bundled fallback addresses.
При `[upstream].type = "socks5"` или `"http"` metadata refresh идёт через этот upstream; проверьте путь командой `sudo mtbuddy config doctor --network`.

---

## License

[MIT](LICENSE) © 2026 Aleksandr Kalashnikov
