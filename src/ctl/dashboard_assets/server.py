#!/usr/bin/env python3
"""MTProto Proxy Dashboard — API server."""

import asyncio
import base64
import hmac
import json
import os
import re
import secrets
import time
import threading
import queue
import subprocess
import sys
import shutil
from pathlib import Path
from urllib.parse import quote, urlparse

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        tomllib = None

import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
import uvicorn


def _proxy_config_candidates():
    return [
        Path(__file__).parent.parent / "config.toml",  # /opt/mtproto-proxy/config.toml
        Path("/opt/mtproto-proxy/config.toml"),
    ]


def _load_dashboard_config() -> dict:
    """Load [monitor] section from config.toml (host, port).

    Uses the same line-by-line parser as _load_proxy_runtime_config() to avoid
    silent failures when tomllib rejects slightly non-standard config files.
    """
    defaults = {"host": "127.0.0.1", "port": 61208}
    for p in _proxy_config_candidates():
        if not p.is_file():
            continue
        try:
            section = ""
            result = dict(defaults)
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("[") and line.endswith("]"):
                        section = line.lower()
                        continue
                    if section != "[monitor]":
                        continue
                    if "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip()
                    if "#" in value:
                        value = value.split("#", 1)[0].strip()
                    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
                        value = value[1:-1]
                    if key == "host":
                        result["host"] = value
                    elif key == "port":
                        digits = "".join(ch for ch in value if ch.isdigit())
                        if digits:
                            result["port"] = int(digits)
            return result
        except Exception as exc:
            print(
                f"[dashboard] warning: failed to parse {p}: {exc}", file=sys.stderr
            )
    return defaults


DASHBOARD_CFG = _load_dashboard_config()

STATIC_DIR = Path(__file__).parent / "static"

_version_cache = {"ts": 0, "version": None}
VERSION_CACHE_TTL = 300  # 5 minutes


def _proxy_version() -> str | None:
    """Detect proxy version. Cached for 5 minutes."""
    now = time.time()
    if now - _version_cache["ts"] < VERSION_CACHE_TTL and _version_cache["version"]:
        return _version_cache["version"]

    version = None

    # 1. Try running the binary
    for binary in ("/opt/mtproto-proxy/mtproto-proxy",):
        if not Path(binary).is_file():
            continue
        try:
            out = subprocess.check_output(
                [binary, "--version"],
                text=True,
                timeout=3,
                stderr=subprocess.STDOUT,
            ).strip()
            # Output may be like "mtproto-proxy 0.17.1" or just "0.17.1"
            m = re.search(r"(\d+\.\d+\.\d+)", out)
            if m:
                version = m[1]
                break
        except Exception:
            pass

    # 2. Fallback: parse version.zig from install directory
    if not version:
        for p in (
            Path(__file__).parent.parent / "version.zig",  # dev layout
            Path("/opt/mtproto-proxy/version.zig"),
        ):
            if p.is_file():
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                    m = re.search(r'"(\d+\.\d+\.\d+)"', text)
                    if m:
                        version = m[1]
                        break
                except Exception:
                    pass

    _version_cache.update(ts=now, version=version)
    return version


app = FastAPI()

# ── Dashboard authentication & hardening ─────────────────────────────────────
# The dashboard is a ROOT-privileged control plane: it can rewrite config.toml,
# delete WireGuard tunnels, restart the proxy, and read every MTProto user
# secret. It is gated behind:
#   1. HTTP Basic auth using an auto-generated 0600 token file (password = token,
#      username ignored). With auth required, /api/stats returning secrets is
#      only reachable by the authenticated operator who already owns them.
#   2. Host-header pinning for loopback binds — defeats DNS-rebinding that would
#      otherwise let a page in the operator's browser drive a 127.0.0.1 bind.
#   3. An Origin check on state-changing requests — defeats CSRF (a cross-origin
#      "simple" POST the browser would auto-attach Basic credentials to).
# Default bind stays 127.0.0.1; reach it over an SSH tunnel.
_DASHBOARD_TOKEN_FILE = Path(__file__).parent / "dashboard.token"


def _load_or_create_dashboard_token() -> str:
    try:
        if _DASHBOARD_TOKEN_FILE.is_file():
            tok = _DASHBOARD_TOKEN_FILE.read_text(encoding="utf-8").strip()
            if tok:
                return tok
    except OSError:
        pass
    tok = secrets.token_urlsafe(32)
    try:
        fd = os.open(str(_DASHBOARD_TOKEN_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(tok + "\n")
    except OSError as exc:
        print(f"[dashboard] WARNING: could not persist auth token: {exc}", file=sys.stderr)
    return tok


DASHBOARD_TOKEN = _load_or_create_dashboard_token()
_DASH_BIND_HOST = str(DASHBOARD_CFG.get("host", "127.0.0.1")).strip().lower()
# Only pin Host for loopback binds (the DNS-rebinding scenario). If the operator
# deliberately bound a routable address, Basic auth is the gate.
_DASH_ENFORCE_HOST = _DASH_BIND_HOST in ("127.0.0.1", "::1", "localhost", "")
_DASH_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _dashboard_auth_ok(authorization) -> bool:
    if not authorization or not authorization.startswith("Basic "):
        return False
    try:
        raw = base64.b64decode(authorization[6:]).decode("utf-8", "replace")
    except Exception:
        return False
    _, _, pw = raw.partition(":")
    return hmac.compare_digest(pw, DASHBOARD_TOKEN)


def _host_hostname(host_header: str) -> str:
    h = host_header
    if h.startswith("["):  # [::1]:port
        h = h[1:].split("]", 1)[0]
    else:
        h = h.split(":", 1)[0]
    return h.strip().lower()


@app.middleware("http")
async def _dashboard_security(request: Request, call_next):
    host_header = (request.headers.get("host") or "").strip()
    if _DASH_ENFORCE_HOST and _host_hostname(host_header) not in _DASH_LOOPBACK_HOSTS:
        return PlainTextResponse("forbidden host", status_code=403)

    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin")
        if origin and urlparse(origin).netloc != host_header:
            return PlainTextResponse("cross-origin request blocked", status_code=403)

    if not _dashboard_auth_ok(request.headers.get("authorization")):
        return PlainTextResponse(
            "authentication required",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="mtproto dashboard"'},
        )

    response = await call_next(request)
    # Conservative hardening headers (no source restrictions, so the UI keeps
    # rendering): block framing/clickjacking and MIME sniffing, drop referrers.
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    # Real CSP, not just frame-ancestors: block injected/external SCRIPT (the dashboard's
    # only script is the external /app.js — there are no inline <script> blocks), which
    # bounds the blast radius of any future escaping mistake on this root control plane.
    # style-src keeps 'unsafe-inline' for the page's inline style= attributes + Google
    # Fonts CSS; style injection is far less dangerous than script execution.
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'",
    )
    # index.html carries no cache-busting query string (only style.css/app.js do),
    # so browsers heuristically cache it and keep loading the OLD asset URLs after a
    # redeploy. Force revalidation of the HTML entry (ETag still yields a 304 when it
    # is unchanged) so a freshly deployed dashboard shows up immediately.
    if response.headers.get("content-type", "").startswith("text/html"):
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
    return response


_prev_net = {"ts": 0, "rx": 0, "tx": 0}
_net_history = []
_cpu_history = []
_mem_history = []
MAX_HISTORY = 90

# --- Thread-safe log buffer ---
_log_buffer = queue.Queue(maxsize=500)
_log_thread_started = False


def _log_reader_thread():
    while True:
        try:
            proc = subprocess.Popen(
                ["journalctl", "-u", "mtproto-proxy", "-f", "--no-pager", "-n", "80"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            for line in proc.stdout:
                text = line.strip()
                if not text:
                    continue
                cls = "info"
                if "error" in text.lower() or "err(" in text:
                    cls = "error"
                elif "warn" in text.lower():
                    cls = "warn"
                elif "drops:" in text:
                    cls = "drops"
                elif "conn stats:" in text:
                    cls = "stats"
                m = re.match(r"^.*?\s+\S+\s+\S+\[\d+\]:\s*(.*)", text)
                short = m.group(1) if m else text
                entry = {"text": short, "cls": cls, "ts": time.strftime("%H:%M:%S")}
                try:
                    _log_buffer.put_nowait(entry)
                except queue.Full:
                    try:
                        _log_buffer.get_nowait()
                    except queue.Empty:
                        pass
                    _log_buffer.put_nowait(entry)
            proc.wait()
        except Exception:
            pass
        time.sleep(2)


def ensure_log_thread():
    global _log_thread_started
    if not _log_thread_started:
        _log_thread_started = True
        threading.Thread(target=_log_reader_thread, daemon=True).start()


ensure_log_thread()

_recent_logs = []
# Absolute sequence number of _recent_logs[0]. Each appended line has a monotonically
# increasing seq; trimming the front advances this base. WebSocket clients track their own
# cursor against these seqs so concurrent /ws/logs viewers each get the FULL stream — the
# old code let whichever client's drain happened to pop a line be the only one to see it.
_recent_base_seq = 0
_recent_lock = threading.Lock()
MAX_RECENT = 100
USER_SECRET_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def _drain_to_recent():
    """Move any buffered journal lines into the shared _recent_logs ring (idempotent)."""
    global _recent_base_seq
    drained = []
    while True:
        try:
            drained.append(_log_buffer.get_nowait())
        except queue.Empty:
            break
    if drained:
        with _recent_lock:
            _recent_logs.extend(drained)
            overflow = max(0, len(_recent_logs) - MAX_RECENT)
            if overflow:
                del _recent_logs[:overflow]
                _recent_base_seq += overflow
    return drained


def _logs_since(cursor):
    """Return (new_entries, next_cursor) for entries with seq >= cursor. Non-destructive,
    so every client reads independently."""
    with _recent_lock:
        end = _recent_base_seq + len(_recent_logs)
        start_idx = max(0, cursor - _recent_base_seq)
        return list(_recent_logs[start_idx:]), end


def _proxy_stats() -> dict:
    try:
        out = subprocess.check_output(
            ["journalctl", "-u", "mtproto-proxy", "--no-pager", "-n", "40"],
            text=True,
            timeout=3,
            stderr=subprocess.DEVNULL,
        )
        s = dict(
            active=0,
            max=0,
            hs_inflight=0,
            total=0,
            accepted=0,
            closed=0,
            tracked_fds=0,
            rate_drops=0,
            cap_drops=0,
            sat_drops=0,
            hs_budget_drops=0,
            hs_timeout=0,
            per_user_active={},
        )
        for line in reversed(out.strip().split("\n")):
            if "conn stats:" in line:
                m = re.search(r"active=(\d+)/(\d+)", line)
                if m:
                    s["active"], s["max"] = int(m[1]), int(m[2])
                for k, p in [
                    ("hs_inflight", r"hs_inflight=(\d+)"),
                    ("total", r"total=(\d+)"),
                    ("accepted", r"accepted\+=(\d+)"),
                    ("closed", r"closed\+=(\d+)"),
                    ("tracked_fds", r"tracked_fds=(\d+)"),
                ]:
                    m2 = re.search(p, line)
                    if m2:
                        s[k] = int(m2[1])
                # Parse users{admin=5,regular=2} from same line
                mu = re.search(r"users\{([^}]*)\}", line)
                if mu and mu.group(1):
                    for pair in mu.group(1).split(","):
                        parts = pair.split("=", 1)
                        if len(parts) == 2:
                            try:
                                s["per_user_active"][parts[0].strip()] = int(parts[1])
                            except ValueError:
                                pass
                break
        for line in reversed(out.strip().split("\n")):
            if "drops:" in line:
                for k, p in [
                    ("rate_drops", r"rate\+=(\d+)"),
                    ("cap_drops", r"cap\+=(\d+)"),
                    ("sat_drops", r"sat\+=(\d+)"),
                    ("pool_drops", r"pool\+=(\d+)"),
                    ("hs_budget_drops", r"hs_budget\+=(\d+)"),
                    ("hs_timeout", r"hs_timeout\+=(\d+)"),
                ]:
                    m2 = re.search(p, line)
                    if m2:
                        s[k] = int(m2[1])
                break

        users_active_total = sum(
            int(v) for v in s.get("per_user_active", {}).values() if isinstance(v, int)
        )
        active_total = int(s.get("active", 0) or 0)
        s["users_active_total"] = users_active_total
        s["unassigned_active"] = max(active_total - users_active_total, 0)

        return s
    except Exception:
        return {}


def _proxy_listening(port: int) -> bool:
    """True if the proxy holds a LISTEN socket on `port`.

    Reads /proc/net/tcp{,6} instead of connect()-ing: a real connection would be
    accepted and counted by the proxy (inflating Total Connections by one per poll),
    and a loopback connect would also wrongly report 'stalled' when the proxy binds a
    specific non-loopback bind_address. A LISTEN-state lookup avoids both. This is a
    LOCAL check — it confirms the listener is up, not that a censor isn't blocking the
    public port.
    """
    if not port:
        return False
    want = format(int(port), "04X")  # /proc/net/tcp local port is uppercase hex
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path, "r") as f:
                next(f, None)  # skip the header row
                for line in f:
                    parts = line.split()
                    # parts[1] = "HEXADDR:HEXPORT", parts[3] = state (0A == LISTEN)
                    if len(parts) > 3 and parts[3] == "0A" and parts[1].rsplit(":", 1)[-1].upper() == want:
                        return True
        except OSError:
            continue
    return False


def _proxy_info() -> dict:
    for proc in psutil.process_iter(["name", "create_time", "pid", "memory_info"]):
        if proc.info["name"] == "mtproto-proxy":
            el = time.time() - proc.info["create_time"]
            h, rem = divmod(int(el), 3600)
            m, sec = divmod(rem, 60)
            d, h = divmod(h, 24)
            up = f"{d}d {h}h {m}m" if d else f"{h}h {m}m {sec}s"
            rss = (
                proc.info["memory_info"].rss / 1048576
                if proc.info["memory_info"]
                else 0
            )
            try:
                listen_port = int(_load_proxy_runtime_config().get("port", 443))
            except Exception:
                listen_port = 443
            listening = _proxy_listening(listen_port)
            # Process up but the port isn't accepting → the event loop is wedged.
            return dict(
                uptime=up,
                pid=proc.info["pid"],
                rss_mb=round(rss, 1),
                online=True,
                listening=listening,
                state="online" if listening else "stalled",
            )
    return dict(uptime="offline", pid=0, rss_mb=0, online=False, listening=False, state="offline")


_awg_cache = {"ts": 0, "data": None}
AWG_CACHE_TTL = 10  # seconds

_egress_cache = {"ts": 0, "data": None}
EGRESS_CACHE_TTL = 12  # seconds (allows 2-3 quality checks per poll, avoiding hammering)


def _awg_status() -> dict:
    """Check AmneziaWG tunnel status (host namespace)."""
    now = time.time()
    if now - _awg_cache["ts"] < AWG_CACHE_TTL:
        return _awg_cache["data"]

    import shutil

    if not shutil.which("awg"):
        _awg_cache.update(ts=now, data=None)
        return None

    tunnel = _detect_tunnel_interface("awg0", "awg")
    result = {
        "installed": True,
        "active": bool(tunnel.get("active")),
        "endpoint": tunnel.get("endpoint"),
        "handshake": tunnel.get("handshake"),
        "rx": tunnel.get("rx"),
        "tx": tunnel.get("tx"),
    }
    if not result["active"]:
        result["reason"] = tunnel.get("reason") or "awg0 not active"

    _awg_cache.update(ts=now, data=result)
    return result


_mask_cache = {"ts": 0, "data": None}
MASK_CACHE_TTL = 8  # seconds


def _parse_bool(value, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    return default


def _parse_toml_string_array(value) -> list[str]:
    raw = str(value or "").strip()
    if not raw.startswith("[") or not raw.endswith("]"):
        return []

    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [str(v).strip() for v in parsed if str(v).strip()]
    except Exception:
        pass

    raw = raw[1:-1]
    out: list[str] = []
    for item in raw.split(","):
        item = item.strip().strip('"').strip("'").strip()
        if item:
            out.append(item)
    return out


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        v = str(value or "").strip()
        if not v or v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def _load_proxy_runtime_config() -> dict:
    defaults = {
        "public_ip": "",
        "port": 443,
        "public_port": 0,
        "mask": True,
        "mask_target": "",
        "mask_port": 443,
        "tls_domain": "google.com",
        "use_middle_proxy": False,
        "upstream_type": "auto",
        "upstream_tunnel_interface": "awg0",
        "upstream_tunnel_interfaces": [],
        "upstream_tunnel_interfaces_configured": False,
        "upstream_tunnel_pinned_interface": "",
        "upstream_socks5_host": "",
        "upstream_socks5_port": 0,
        "upstream_socks5_username": "",
        "upstream_socks5_password": "",
        "upstream_http_host": "",
        "upstream_http_port": 0,
        "upstream_http_username": "",
        "upstream_http_password": "",
        "users": {},
        "direct_users": set(),
        "disabled_users": {},
    }

    cfg_path = None
    for p in _proxy_config_candidates():
        if p.is_file():
            cfg_path = p
            break

    if cfg_path is None:
        return defaults

    result = {
        "public_ip": defaults["public_ip"],
        "port": defaults["port"],
        "public_port": defaults["public_port"],
        "mask": defaults["mask"],
        "mask_target": defaults["mask_target"],
        "mask_port": defaults["mask_port"],
        "tls_domain": defaults["tls_domain"],
        "use_middle_proxy": defaults["use_middle_proxy"],
        "upstream_type": defaults["upstream_type"],
        "upstream_tunnel_interface": defaults["upstream_tunnel_interface"],
        "upstream_tunnel_interfaces": [],
        "upstream_tunnel_interfaces_configured": False,
        "upstream_tunnel_pinned_interface": "",
        "upstream_socks5_host": defaults["upstream_socks5_host"],
        "upstream_socks5_port": defaults["upstream_socks5_port"],
        "upstream_socks5_username": defaults["upstream_socks5_username"],
        "upstream_socks5_password": defaults["upstream_socks5_password"],
        "upstream_http_host": defaults["upstream_http_host"],
        "upstream_http_port": defaults["upstream_http_port"],
        "upstream_http_username": defaults["upstream_http_username"],
        "upstream_http_password": defaults["upstream_http_password"],
        "users": {},
        "direct_users": set(),
        "disabled_users": {},
    }

    section = ""
    try:
        with open(cfg_path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                if line.startswith("[") and line.endswith("]"):
                    section = line.strip().lower()
                    continue

                if "=" not in line:
                    continue

                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()

                if "#" in value:
                    value = value.split("#", 1)[0].strip()
                if ";" in value:
                    value = value.split(";", 1)[0].strip()

                if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
                    value = value[1:-1]

                if section == "[server]":
                    if key == "public_ip":
                        result["public_ip"] = value
                    elif key == "port":
                        digits = "".join(ch for ch in value if ch.isdigit())
                        if digits:
                            result["port"] = int(digits)
                    elif key == "public_port":
                        digits = "".join(ch for ch in value if ch.isdigit())
                        if digits:
                            result["public_port"] = int(digits)

                elif section == "[general]":
                    if key == "use_middle_proxy":
                        result["use_middle_proxy"] = _parse_bool(
                            value, defaults["use_middle_proxy"]
                        )

                elif section == "[upstream]":
                    if key == "type" and value:
                        result["upstream_type"] = value.lower()

                elif section == "[upstream.tunnel]":
                    if key == "interface" and value:
                        result["upstream_tunnel_interface"] = value
                    elif key == "interfaces":
                        result["upstream_tunnel_interfaces"] = _parse_toml_string_array(value)
                        result["upstream_tunnel_interfaces_configured"] = True
                    elif key == "pinned_interface":
                        result["upstream_tunnel_pinned_interface"] = value

                elif section == "[upstream.socks5]":
                    if key == "host":
                        result["upstream_socks5_host"] = value
                    elif key == "port":
                        digits = "".join(ch for ch in value if ch.isdigit())
                        if digits:
                            result["upstream_socks5_port"] = int(digits)
                    elif key == "username":
                        result["upstream_socks5_username"] = value
                    elif key == "password":
                        result["upstream_socks5_password"] = value

                elif section == "[upstream.http]":
                    if key == "host":
                        result["upstream_http_host"] = value
                    elif key == "port":
                        digits = "".join(ch for ch in value if ch.isdigit())
                        if digits:
                            result["upstream_http_port"] = int(digits)
                    elif key == "username":
                        result["upstream_http_username"] = value
                    elif key == "password":
                        result["upstream_http_password"] = value

                elif section == "[censorship]":
                    if key == "mask":
                        result["mask"] = _parse_bool(value, defaults["mask"])
                    elif key == "mask_target":
                        result["mask_target"] = value
                    elif key == "mask_port":
                        digits = "".join(ch for ch in value if ch.isdigit())
                        if digits:
                            result["mask_port"] = int(digits)
                    elif key == "tls_domain":
                        if value:
                            result["tls_domain"] = value

                elif section == "[access.users]":
                    if key and value:
                        result["users"][key] = value

                elif section in ("[access.direct_users]", "[access.admins]"):
                    if key and _parse_bool(value, False):
                        result["direct_users"].add(key)

                elif section == "[access.disabled_users]":
                    if key and value:
                        result["disabled_users"][key] = value

    except Exception:
        return defaults

    if not result["upstream_tunnel_interfaces"] and not result["upstream_tunnel_interfaces_configured"]:
        iface = str(result.get("upstream_tunnel_interface") or "awg0").strip()
        result["upstream_tunnel_interfaces"] = [iface] if iface else ["awg0"]

    return result


def _load_censorship_config() -> dict:
    cfg = _load_proxy_runtime_config()
    return {
        "mask": bool(cfg["mask"]),
        "mask_target": str(cfg["mask_target"]),
        "mask_port": int(cfg["mask_port"]),
        "tls_domain": str(cfg["tls_domain"]),
    }


_routing_cache = {"ts": 0, "data": None}
ROUTING_CACHE_TTL = 8  # seconds
TUNNEL_POOL_STATE = Path("/run/mtproto-proxy/tunnel-pool.state")
TUNNEL_POOL_SCRIPT = Path("/usr/local/bin/setup_tunnel.sh")
TUNNEL_POOL_SERVICE = Path("/etc/systemd/system/mtproto-tunnel-pool.service")
TUNNEL_POOL_TIMER = Path("/etc/systemd/system/mtproto-tunnel-pool.timer")
PROXY_SERVICE_FILE = Path("/etc/systemd/system/mtproto-proxy.service")
TUNNEL_PROBE_URL = "https://core.telegram.org/getProxyConfig"


def _parse_transfer_bytes(value: str | None) -> float:
    """Parse a WireGuard transfer string like '5.69 KiB' into bytes."""
    if not value:
        return 0.0
    m = re.match(r"([\d.]+)\s*(\S+)", value.strip())
    if not m:
        return 0.0
    num = float(m[1])
    unit = m[2].lower()
    multipliers = {"b": 1, "kib": 1024, "mib": 1048576, "gib": 1073741824, "tib": 1099511627776}
    return num * multipliers.get(unit, 1)


def _has_valid_handshake(handshake: str | None) -> bool:
    """Check whether the WireGuard handshake value indicates a completed handshake.

    Returns False for None, empty, 'none (idle)', or '0' (epoch = never).
    """
    if not handshake:
        return False
    hs = handshake.strip().lower()
    return hs not in ("", "0", "none", "none (idle)")


def _tunnel_tool_hint(interface: str) -> str | None:
    if interface.startswith("awg"):
        return "awg"
    if interface.startswith("wg"):
        return "wg"
    return None


def _effective_tunnel_pool(cfg: dict) -> list[str]:
    pool = _dedupe([str(v) for v in cfg.get("upstream_tunnel_interfaces", [])])
    if pool or cfg.get("upstream_tunnel_interfaces_configured"):
        return pool
    iface = str(cfg.get("upstream_tunnel_interface", "awg0") or "awg0").strip()
    return [iface] if iface else ["awg0"]


def _tunnel_candidates(cfg: dict) -> list[str]:
    pinned = str(cfg.get("upstream_tunnel_pinned_interface", "") or "").strip()
    return _dedupe(([pinned] if pinned else []) + _effective_tunnel_pool(cfg))


def _read_tunnel_pool_state() -> dict:
    result = {
        "active": "",
        "status": "",
        "reason": "",
        "pinned": "",
        "pool": "",
        "last_switch": "",
        "checked_at": "",
    }
    try:
        text = TUNNEL_POOL_STATE.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return result

    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in result:
            result[key] = value.strip()
    return result


def _probe_tunnel_interface(interface: str) -> dict:
    if not shutil.which("curl"):
        return {"ok": None, "reason": "curl unavailable"}
    try:
        r = subprocess.run(
            [
                "curl",
                "--interface",
                interface,
                "-fsS",
                "--connect-timeout",
                "2",
                "--max-time",
                "4",
                TUNNEL_PROBE_URL,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except Exception:
        return {"ok": False, "reason": "probe failed to run"}
    if r.returncode == 0:
        return {"ok": True, "reason": "Telegram probe ok"}
    return {"ok": False, "reason": "Telegram probe failed"}


# ── Egress / tunnel quality probing ──────────────────────────────────────────
# Surfaces whether the upstream VPN tunnel (awg0/wg0/…) is the bottleneck:
# link state, last WireGuard/AmneziaWG handshake age, RTT and packet loss to a
# Telegram DC reached *via that interface*. Everything degrades to None when the
# deployment is not a tunnel or the tools are missing — never an error.

# A Telegram DC IPv4 (DC2, the canonical core endpoint) so the probe traverses
# the same path real proxy traffic would, rather than a generic public host.
EGRESS_PROBE_IP = "149.154.167.51"


def _tunnel_handshake_age(interface: str, tool_hint: str | None = None) -> int | None:
    """Return the age in seconds of the most recent WG/AWG handshake on the
    interface, or None if no handshake / tool unavailable.

    Uses `<tool> show <iface> latest-handshakes` which reports a unix epoch per
    peer; age = now - max(epoch). An epoch of 0 means "never" → None.
    """
    tools: list[str] = []
    if tool_hint:
        tools.append(tool_hint)
    for name in ("awg", "wg"):
        if name not in tools:
            tools.append(name)

    for tool in tools:
        if not shutil.which(tool):
            continue
        try:
            out = subprocess.check_output(
                [tool, "show", interface, "latest-handshakes"],
                text=True,
                timeout=3,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            continue

        best_epoch = 0
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            try:
                epoch = int(parts[-1])
            except ValueError:
                continue
            if epoch > best_epoch:
                best_epoch = epoch

        if best_epoch <= 0:
            return None
        age = int(time.time()) - best_epoch
        return age if age >= 0 else 0

    return None


def _tunnel_rtt(interface: str, gateway_ip: str = EGRESS_PROBE_IP, timeout: int = 3) -> float | None:
    """Measure RTT to a DC via the specified interface using ping.

    Returns RTT in milliseconds (float), or None if unavailable/timeout.
    On error or tool unavailable, returns None silently (dashboard displays as "—").
    """
    if not shutil.which("ping"):
        return None

    try:
        # -I binds the interface, -c 1 a single packet. On Linux iputils, -W is the
        # per-reply wait in SECONDS (not ms) — passing timeout*1000 means "wait 3000s".
        result = subprocess.run(
            ["ping", "-I", interface, "-c", "1", "-W", "2", gateway_ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout + 1,
        )
        if result.returncode != 0:
            return None

        # Parse "time=X.XXX ms" from output
        m = re.search(r"time=([\d.]+)\s*ms", result.stdout)
        if m:
            return float(m[1])
    except Exception:
        pass

    return None


def _tunnel_packet_loss(interface: str, gateway_ip: str = EGRESS_PROBE_IP, count: int = 10, timeout: int = 5) -> float | None:
    """Measure packet loss % to DC via interface.

    Sends `count` pings, returns loss as % (0-100), or None if unavailable.
    """
    if not shutil.which("ping"):
        return None

    try:
        # -i 0.2 sends the `count` packets in ~count*0.2s (default 1s interval would
        # blow the subprocess timeout before the summary prints); -W is per-reply wait
        # in SECONDS on Linux iputils (not ms). Subprocess timeout covers send + waits.
        result = subprocess.run(
            ["ping", "-I", interface, "-c", str(count), "-i", "0.2", "-W", "2", gateway_ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=count * 0.3 + 3,
        )

        # Parse "X% packet loss" (works on Linux, macOS)
        m = re.search(r"([\d.]+)%\s+(?:packet\s+)?loss", result.stdout)
        if m:
            return float(m[1])
    except Exception:
        pass

    return None


def _tunnel_egress_health(interface: str, tool_hint: str | None = None) -> dict:
    """Comprehensive egress/tunnel health check.

    Returns:
    {
        "interface": str,
        "up": bool,                    # link is operational
        "handshake_age_sec": int | None,  # age of last WG/AWG handshake
        "rtt_ms": float | None,        # round-trip time in ms
        "packet_loss_pct": float | None,  # 0-100
        "quality": str,                # "good", "degraded", "poor", or "unknown"
    }
    """
    result = {
        "interface": interface,
        "up": False,
        "handshake_age_sec": None,
        "rtt_ms": None,
        "packet_loss_pct": None,
        "quality": "unknown",
    }

    # Check if interface is up
    try:
        link_check = subprocess.run(
            ["ip", "link", "show", "dev", interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        if link_check.returncode != 0:
            result["quality"] = "down"
            return result
        result["up"] = True
    except Exception:
        result["quality"] = "unknown"
        return result

    # Last WireGuard/AmneziaWG handshake age (advisory; cross-checks RTT/loss)
    result["handshake_age_sec"] = _tunnel_handshake_age(interface, tool_hint)

    # Measure RTT and packet loss (non-blocking; silent failure if tools unavailable)
    rtt = _tunnel_rtt(interface)
    loss = _tunnel_packet_loss(interface, count=5, timeout=3)

    result["rtt_ms"] = rtt
    result["packet_loss_pct"] = loss

    # Determine quality based on metrics
    if loss is None and rtt is None:
        # Tools not available, but interface is up
        result["quality"] = "up"
    elif loss is not None and loss > 0:
        # Packet loss detected
        if loss > 10:
            result["quality"] = "poor"
        else:
            result["quality"] = "degraded"
    elif rtt is not None:
        # RTT-based heuristic (good = <100ms, degraded = 100-300ms, poor = >300ms)
        if rtt > 300:
            result["quality"] = "poor"
        elif rtt > 100:
            result["quality"] = "degraded"
        else:
            result["quality"] = "good"
    else:
        result["quality"] = "up"  # up but metrics unavailable

    return result


def _detect_tunnel_interface(interface: str, tool_hint: str | None = None) -> dict:
    result = {
        "interface": interface,
        "tool": tool_hint or "-",
        "link_up": False,
        "active": False,
        "endpoint": None,
        "handshake": None,
        "handshake_ok": False,
        "healthy": False,
        "probe_ok": None,
        "probe": None,
        "rx": None,
        "tx": None,
        "reason": None,
    }

    try:
        link_check = subprocess.run(
            ["ip", "link", "show", "dev", interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        result["link_up"] = link_check.returncode == 0
    except Exception:
        result["link_up"] = False

    tools: list[str] = []
    if tool_hint:
        tools.append(tool_hint)
    for name in ("awg", "wg"):
        if name not in tools:
            tools.append(name)

    for tool in tools:
        if not shutil.which(tool):
            continue

        try:
            out = subprocess.check_output(
                [tool, "show", interface],
                text=True,
                timeout=3,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            continue

        result["tool"] = tool

        m = re.search(r"endpoint:\s*(\S+)", out)
        if m:
            result["endpoint"] = m[1]

        m = re.search(r"latest handshake:\s*(.+)", out)
        if m:
            result["handshake"] = m[1].strip()

        m = re.search(
            r"transfer:\s*([\d.]+\s*\S+)\s+received,\s*([\d.]+\s*\S+)\s+sent",
            out,
        )
        if m:
            result["rx"] = m[1]
            result["tx"] = m[2]

        # A tunnel is truly active only if the handshake completed AND
        # we have received data. A configured endpoint with handshake=0
        # and rx=0 means the VPN server is unreachable.
        hs_ok = _has_valid_handshake(result.get("handshake"))
        rx_ok = _parse_transfer_bytes(result.get("rx")) > 0
        result["handshake_ok"] = hs_ok

        if result.get("endpoint"):
            if hs_ok and rx_ok:
                result["active"] = True
            elif hs_ok:
                result["active"] = True  # handshake done, rx may lag behind
            else:
                # endpoint configured but handshake never completed
                result["active"] = False
                result["reason"] = "endpoint configured, no handshake (VPN server unreachable)"
            if not result.get("handshake"):
                result["handshake"] = "none (idle)"
        elif result["link_up"]:
            result["reason"] = "interface up, no endpoint"
        else:
            result["reason"] = "interface down"

        probe = _probe_tunnel_interface(interface) if result["link_up"] and hs_ok else {"ok": False, "reason": result["reason"] or "handshake missing"}
        result["probe_ok"] = probe.get("ok")
        result["probe"] = probe.get("reason")
        result["healthy"] = bool(result["link_up"] and hs_ok and probe.get("ok") is True)
        if not result["healthy"] and probe.get("reason"):
            result["reason"] = str(probe.get("reason"))

        return result

    if result["link_up"]:
        result["reason"] = "interface up, tool output unavailable"
    else:
        result["reason"] = "interface down"
    result["probe_ok"] = False
    result["probe"] = result["reason"]
    result["healthy"] = False
    return result


def _policy_routing_status() -> dict:
    result = {
        "mark": 200,
        "table": 200,
        "rule_ok": False,
        "route_ok": False,
        "route_dev": None,
    }

    try:
        rules = subprocess.check_output(
            ["ip", "-4", "rule", "show"],
            text=True,
            timeout=2,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        rules = ""

    for line in rules.splitlines():
        low = line.lower()
        has_mark = ("fwmark 200" in low) or ("fwmark 0xc8" in low)
        has_table = ("lookup 200" in low) or ("table 200" in low)
        if has_mark and has_table:
            result["rule_ok"] = True
            break

    try:
        routes = subprocess.check_output(
            ["ip", "-4", "route", "show", "table", "200"],
            text=True,
            timeout=2,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        routes = ""

    m = re.search(r"default\s+dev\s+(\S+)", routes)
    if m:
        result["route_ok"] = True
        result["route_dev"] = m[1]

    return result


def _list_system_interfaces() -> list[str]:
    names: list[str] = []
    try:
        out = subprocess.check_output(
            ["ip", "-o", "link", "show"],
            text=True,
            timeout=2,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return names

    for line in out.splitlines():
        m = re.match(r"\d+:\s*([^:]+):", line)
        if not m:
            continue

        name = m.group(1).strip()
        if "@" in name:
            name = name.split("@", 1)[0]

        if not name or name == "lo":
            continue
        if name not in names:
            names.append(name)

    return names


def _list_tunnel_config_interfaces() -> list[str]:
    names: list[str] = []
    for base in (Path("/etc/amnezia/amneziawg"), Path("/etc/wireguard")):
        try:
            entries = sorted(base.glob("*.conf"))
        except Exception:
            entries = []
        for path in entries:
            iface = path.stem.strip()
            if not _valid_tunnel_interface_name(iface):
                continue
            if iface not in names:
                names.append(iface)
    return names


def _upstream_target_from_cfg(cfg: dict, policy: dict) -> str:
    upstream_type = str(cfg.get("upstream_type", "auto") or "auto").lower().strip()

    if upstream_type == "socks5":
        host = str(cfg.get("upstream_socks5_host", "") or "").strip()
        port = int(cfg.get("upstream_socks5_port", 0) or 0)
        return f"{host}:{port}" if host and port > 0 else "proxy host/port not set"

    if upstream_type == "http":
        host = str(cfg.get("upstream_http_host", "") or "").strip()
        port = int(cfg.get("upstream_http_port", 0) or 0)
        return f"{host}:{port}" if host and port > 0 else "proxy host/port not set"

    if upstream_type == "tunnel":
        route_dev = policy.get("route_dev")
        if route_dev:
            return f"mark 200 -> table 200 -> dev {route_dev}"
        pool = _effective_tunnel_pool(cfg)
        return f"mark 200 -> table 200 (pool {', '.join(pool)})"

    if upstream_type == "direct":
        return "direct host routing"

    return "auto (direct unless tunnel mode is selected)"


def _routing_status() -> dict:
    now = time.time()
    if now - _routing_cache["ts"] < ROUTING_CACHE_TTL:
        return _routing_cache["data"]

    cfg = _load_proxy_runtime_config()
    upstream_type = str(cfg.get("upstream_type", "auto") or "auto").lower().strip()
    pool = _effective_tunnel_pool(cfg)
    pinned_iface = str(cfg.get("upstream_tunnel_pinned_interface", "") or "").strip()
    fallback_iface = str(cfg.get("upstream_tunnel_interface", "") or "").strip()
    if not fallback_iface and not cfg.get("upstream_tunnel_interfaces_configured"):
        fallback_iface = "awg0"
    selected_iface = pinned_iface or (pool[0] if pool else fallback_iface)

    if not selected_iface and not cfg.get("upstream_tunnel_interfaces_configured"):
        selected_iface = "awg0"

    system_ifaces = _list_system_interfaces()
    config_ifaces = _list_tunnel_config_interfaces()
    available_tunnel_ifaces: list[str] = []
    for iface in system_ifaces + config_ifaces:
        low = iface.lower()
        if not (
            low.startswith(("awg", "wg", "tun", "tap"))
            or iface in pool
            or iface == selected_iface
            or iface in config_ifaces
        ):
            continue
        if iface and iface not in available_tunnel_ifaces:
            available_tunnel_ifaces.append(iface)

    candidates = _tunnel_candidates(cfg)
    interfaces = _dedupe(candidates + list(available_tunnel_ifaces))
    for iface in ("awg0", "wg0"):
        if iface not in interfaces:
            interfaces.append(iface)

    tunnels = []
    for iface in interfaces:
        tunnel = _detect_tunnel_interface(iface, _tunnel_tool_hint(iface))
        tunnel["in_pool"] = iface in pool
        tunnel["config_present"] = iface in config_ifaces
        tunnel["pinned"] = bool(pinned_iface and iface == pinned_iface)
        if (
            iface == selected_iface
            or iface in pool
            or iface in config_ifaces
            or tunnel.get("link_up")
            or tunnel.get("active")
            or tunnel.get("endpoint")
        ):
            tunnels.append(tunnel)

    policy = _policy_routing_status()
    pool_state = _read_tunnel_pool_state()
    target = _upstream_target_from_cfg(cfg, policy)

    primary_tunnel = None
    route_dev = policy.get("route_dev")
    if route_dev:
        primary_tunnel = next((t for t in tunnels if t["interface"] == route_dev), None)
    if primary_tunnel is None:
        primary_tunnel = next(
            (t for t in tunnels if t["interface"] == selected_iface), None
        )
    if primary_tunnel is None and tunnels:
        primary_tunnel = tunnels[0]

    active_tunnels = sum(1 for t in tunnels if t.get("active"))
    healthy_tunnels = sum(1 for t in tunnels if t.get("healthy"))

    if upstream_type == "tunnel":
        healthy = bool(
            policy.get("rule_ok")
            and policy.get("route_ok")
            and primary_tunnel
            and primary_tunnel.get("link_up")
            and primary_tunnel.get("healthy")
        )
    elif upstream_type == "socks5":
        healthy = bool(
            str(cfg.get("upstream_socks5_host", "") or "").strip()
            and int(cfg.get("upstream_socks5_port", 0) or 0) > 0
        )
    elif upstream_type == "http":
        healthy = bool(
            str(cfg.get("upstream_http_host", "") or "").strip()
            and int(cfg.get("upstream_http_port", 0) or 0) > 0
        )
    else:
        healthy = True

    result = {
        "middle_proxy_enabled": bool(cfg.get("use_middle_proxy", False)),
        "upstream_type": upstream_type,
        "upstream_target": target,
        "selected_tunnel_interface": selected_iface,
        "active_tunnel_interface": route_dev or pool_state.get("active") or "",
        "pinned_tunnel_interface": pinned_iface,
        "tunnel_pool": pool,
        "tunnel_candidates": candidates,
        "last_switch": pool_state.get("last_switch") or "",
        "pool_status": pool_state.get("status") or "",
        "pool_reason": pool_state.get("reason") or "",
        "pool_checked_at": pool_state.get("checked_at") or "",
        "available_tunnel_interfaces": available_tunnel_ifaces,
        "policy": policy,
        "tunnels": tunnels,
        "active_tunnels": active_tunnels,
        "healthy_tunnels": healthy_tunnels,
        "detected_tunnels": len(tunnels),
        "primary_tunnel": primary_tunnel,
        "upstream_socks5": {
            "host": str(cfg.get("upstream_socks5_host", "") or ""),
            "port": int(cfg.get("upstream_socks5_port", 0) or 0),
            "username": str(cfg.get("upstream_socks5_username", "") or ""),
            "password": str(cfg.get("upstream_socks5_password", "") or ""),
        },
        "upstream_http": {
            "host": str(cfg.get("upstream_http_host", "") or ""),
            "port": int(cfg.get("upstream_http_port", 0) or 0),
            "username": str(cfg.get("upstream_http_username", "") or ""),
            "password": str(cfg.get("upstream_http_password", "") or ""),
        },
        "healthy": healthy,
    }

    _routing_cache.update(ts=now, data=result)
    return result


def _unit_active(unit: str) -> bool:
    return (
        subprocess.run(
            ["systemctl", "is-active", "--quiet", unit],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )


def _unit_enabled(unit: str) -> bool:
    return (
        subprocess.run(
            ["systemctl", "is-enabled", "--quiet", unit],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )


def _probe_mask_endpoint(target: str, port: int) -> bool:
    if not shutil.which("curl"):
        return False

    url = f"https://{target}:{port}/"
    cmd = ["curl", "-sk", "--max-time", "2", url]

    try:
        return (
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
            ).returncode
            == 0
        )
    except Exception:
        return False


def _masking_status() -> dict:
    now = time.time()
    if now - _mask_cache["ts"] < MASK_CACHE_TTL:
        return _mask_cache["data"]

    censorship = _load_censorship_config()
    mask_enabled = bool(censorship["mask"])
    mask_target = str(censorship.get("mask_target") or "").strip()
    mask_port = int(censorship["mask_port"])
    # Client-facing port for the FakeTLS endpoint shown in the UI: public_port if set
    # (e.g. behind a load balancer), else the proxy's listen port. NOT mask_port (that's
    # the internal masking backend), and never a hardcoded 443.
    _proxy_cfg = _load_proxy_runtime_config()
    client_port = int(_proxy_cfg.get("public_port") or 0) or int(_proxy_cfg.get("port") or 443)
    tls_domain = censorship["tls_domain"]

    using_netns_target = False

    if not mask_enabled:
        mode = "disabled"
        target_host = "-"
    elif mask_target:
        mode = "custom"
        target_host = mask_target
    elif mask_port == 443:
        mode = "remote"
        target_host = tls_domain
    else:
        mode = "local"
        target_host = "127.0.0.1"

    endpoint_ok = None
    if mode in ("local", "custom"):
        endpoint_ok = _probe_mask_endpoint(target_host, mask_port)

    nginx_active = _unit_active("nginx.service")
    nginx_enabled = _unit_enabled("nginx.service")
    timer_active = _unit_active("mtproto-mask-health.timer")
    timer_enabled = _unit_enabled("mtproto-mask-health.timer")

    healthy = True
    if mode == "local":
        healthy = nginx_active and timer_active and bool(endpoint_ok)
    elif mode == "custom":
        healthy = bool(endpoint_ok)

    result = {
        "enabled": mask_enabled,
        "mode": mode,
        "mask_port": mask_port,
        "mask_target": mask_target,
        "tls_domain": tls_domain,
        "port": client_port,
        "target": f"{target_host}:{mask_port}" if mode != "disabled" else "-",
        "using_netns": using_netns_target,
        "endpoint_ok": endpoint_ok,
        "nginx_active": nginx_active,
        "nginx_enabled": nginx_enabled,
        "health_timer_active": timer_active,
        "health_timer_enabled": timer_enabled,
        "healthy": healthy,
    }

    _mask_cache.update(ts=now, data=result)
    return result


_users_cache = {"ts": 0, "data": None}
USERS_CACHE_TTL = 8  # seconds

_public_ip_cache = {"ts": 0, "ip": ""}
PUBLIC_IP_TTL = 300  # 5 minutes


def _detect_public_ip() -> str:
    """Auto-detect public IP, cached for 5 minutes."""
    now = time.time()
    if now - _public_ip_cache["ts"] < PUBLIC_IP_TTL and _public_ip_cache["ip"]:
        return _public_ip_cache["ip"]

    for url in (
        "https://ifconfig.me/ip",
        "https://api.ipify.org",
        "https://icanhazip.com",
    ):
        try:
            out = subprocess.check_output(
                ["curl", "-s", "--max-time", "3", url],
                text=True,
                timeout=5,
                stderr=subprocess.DEVNULL,
            ).strip()
            if out and re.match(r"^[\d.]+$", out):
                _public_ip_cache.update(ts=now, ip=out)
                return out
        except Exception:
            continue

    _public_ip_cache.update(ts=now, ip="")
    return ""


def _users_status() -> dict:
    now = time.time()
    if now - _users_cache["ts"] < USERS_CACHE_TTL:
        return _users_cache["data"]

    cfg = _load_proxy_runtime_config()
    server = str(cfg.get("public_ip") or "").strip()
    if not server:
        server = _detect_public_ip()
    port = int(cfg.get("public_port", 0) or cfg.get("port", 443))
    tls_domain = str(cfg.get("tls_domain", "google.com"))
    domain_hex = tls_domain.encode("utf-8", errors="ignore").hex()

    direct_users = set(cfg.get("direct_users", set()))
    labels = _load_labels()
    items = []

    users = cfg.get("users", {})
    for name in sorted(users.keys()):
        secret_raw = str(users[name]).strip().lower()
        if not USER_SECRET_RE.fullmatch(secret_raw):
            continue

        ee_secret = f"ee{secret_raw}{domain_hex}"
        tg_link = None
        tme_link = None
        if server:
            safe_server = quote(server)
            tg_link = f"tg://proxy?server={safe_server}&port={port}&secret={ee_secret}"
            tme_link = (
                f"https://t.me/proxy?server={safe_server}&port={port}&secret={ee_secret}"
            )

        items.append(
            {
                "name": name,
                "label": labels.get(name, ""),
                "secret": secret_raw,
                "direct": name in direct_users,
                "enabled": True,
                "tg_link": tg_link,
                "tme_link": tme_link,
            }
        )

    # Include disabled users (shown in dashboard but not active in proxy)
    disabled_users = cfg.get("disabled_users", {})
    for name in sorted(disabled_users.keys()):
        secret_raw = str(disabled_users[name]).strip().lower()
        if not USER_SECRET_RE.fullmatch(secret_raw):
            continue
        items.append(
            {
                "name": name,
                "label": labels.get(name, ""),
                "secret": secret_raw,
                "direct": False,
                "enabled": False,
                "tg_link": None,
                "tme_link": None,
            }
        )

    active_count = sum(1 for item in items if item["enabled"])

    result = {
        "total": active_count,
        "disabled_total": len(items) - active_count,
        "direct_total": sum(1 for item in items if item["direct"]),
        "links_ready": bool(server),
        "server": server,
        "port": port,
        "listen_port": int(cfg.get("port", 443)),
        "tls_domain": tls_domain,
        "items": items,
    }

    _users_cache.update(ts=now, data=result)
    return result


# ── Config file manipulation helpers ──


def _find_config_path() -> Path | None:
    for p in _proxy_config_candidates():
        if p.is_file():
            return p
    return None


def _restart_proxy():
    """Restart mtproto-proxy systemd service."""
    try:
        subprocess.run(
            ["systemctl", "restart", "mtproto-proxy"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except Exception:
        pass
    # Invalidate caches
    _users_cache["ts"] = 0
    _mask_cache["ts"] = 0
    _routing_cache["ts"] = 0


def _set_toml_key(
    lines: list[str],
    section_header: str,
    key: str,
    value_literal: str,
) -> list[str]:
    section_l = section_header.strip().lower()
    key_l = key.strip().lower()

    in_section = False
    section_found = False
    insert_idx = None

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_section and insert_idx is None:
                insert_idx = i
            in_section = stripped.lower() == section_l
            if in_section:
                section_found = True
                insert_idx = i + 1
            continue

        if not in_section:
            continue

        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue

        if "=" not in stripped:
            continue

        key_part = stripped.split("=", 1)[0].strip().lower()
        if key_part != key_l:
            continue

        indent_len = len(line) - len(line.lstrip(" \t"))
        indent = line[:indent_len]
        lines[i] = f"{indent}{key} = {value_literal}\n"
        return lines

    if section_found:
        if insert_idx is None:
            insert_idx = len(lines)
        lines.insert(insert_idx, f"{key} = {value_literal}\n")
        return lines

    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    if lines and lines[-1].strip():
        lines.append("\n")

    lines.append(f"{section_header}\n")
    lines.append(f"{key} = {value_literal}\n")
    return lines


def _toml_string_literal(value: str) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def _set_middle_proxy_enabled(enabled: bool) -> bool:
    cfg_path = _find_config_path()
    if cfg_path is None:
        return False

    lines = cfg_path.read_text(encoding="utf-8", errors="replace").splitlines(
        keepends=True
    )
    value = "true" if enabled else "false"
    lines = _set_toml_key(lines, "[general]", "use_middle_proxy", value)
    cfg_path.write_text("".join(lines), encoding="utf-8")
    return True


def _set_upstream_type(upstream_type: str) -> bool:
    cfg_path = _find_config_path()
    if cfg_path is None:
        return False

    allowed = {"auto", "direct", "tunnel", "socks5", "http"}
    if upstream_type not in allowed:
        return False

    lines = cfg_path.read_text(encoding="utf-8", errors="replace").splitlines(
        keepends=True
    )
    lines = _set_toml_key(
        lines, "[upstream]", "type", _toml_string_literal(upstream_type)
    )

    cfg_path.write_text("".join(lines), encoding="utf-8")
    return True


def _set_upstream_tunnel_interface(interface: str) -> bool:
    cfg_path = _find_config_path()
    if cfg_path is None:
        return False

    iface = str(interface or "").strip()
    if iface and not re.fullmatch(r"[A-Za-z0-9_.:-]+", iface):
        return False

    lines = cfg_path.read_text(encoding="utf-8", errors="replace").splitlines(
        keepends=True
    )
    lines = _set_toml_key(
        lines, "[upstream.tunnel]", "pinned_interface", _toml_string_literal(iface)
    )
    cfg_path.write_text("".join(lines), encoding="utf-8")
    return True


def _valid_tunnel_interface_name(interface: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", str(interface or "").strip()))


def _toml_string_array_literal(values: list[str]) -> str:
    return json.dumps([str(v) for v in values], ensure_ascii=False)


def _tunnel_config_paths(interface: str) -> list[Path]:
    iface = str(interface or "").strip()
    paths = [
        Path("/etc/amnezia/amneziawg") / f"{iface}.conf",
        Path("/etc/wireguard") / f"{iface}.conf",
    ]
    if iface == "awg0":
        paths.append(Path("/etc/amnezia/awg0.conf"))
    return paths


def _tunnel_config_exists(interface: str) -> bool:
    return any(path.exists() for path in _tunnel_config_paths(interface))


def _remove_tunnel_from_config(interface: str) -> dict | None:
    cfg_path = _find_config_path()
    if cfg_path is None:
        return None

    iface = str(interface or "").strip()
    if not _valid_tunnel_interface_name(iface):
        return None

    cfg = _load_proxy_runtime_config()
    pool = _effective_tunnel_pool(cfg)
    in_pool = iface in pool
    if not in_pool and not _tunnel_config_exists(iface):
        return None

    remaining = [value for value in pool if value != iface]
    removed_last = bool(in_pool and not remaining)

    if in_pool:
        lines = cfg_path.read_text(encoding="utf-8", errors="replace").splitlines(
            keepends=True
        )
        if remaining:
            lines = _set_toml_key(
                lines,
                "[upstream.tunnel]",
                "interface",
                _toml_string_literal(remaining[0]),
            )
        else:
            lines = _set_toml_key(
                lines, "[upstream]", "type", _toml_string_literal("auto")
            )
            lines = _set_toml_key(
                lines, "[upstream.tunnel]", "interface", _toml_string_literal("")
            )

        lines = _set_toml_key(
            lines,
            "[upstream.tunnel]",
            "interfaces",
            _toml_string_array_literal(remaining),
        )

        pinned = str(cfg.get("upstream_tunnel_pinned_interface", "") or "").strip()
        if pinned == iface or removed_last:
            lines = _set_toml_key(
                lines,
                "[upstream.tunnel]",
                "pinned_interface",
                _toml_string_literal(""),
            )

        cfg_path.write_text("".join(lines), encoding="utf-8")

    return {
        "removed_from_pool": in_pool,
        "removed_last": removed_last,
        "remaining_pool": remaining,
    }


def _clear_tunnel_config() -> bool:
    cfg_path = _find_config_path()
    if cfg_path is None:
        return False

    lines = cfg_path.read_text(encoding="utf-8", errors="replace").splitlines(
        keepends=True
    )
    lines = _set_toml_key(lines, "[upstream]", "type", _toml_string_literal("auto"))
    lines = _set_toml_key(
        lines, "[upstream.tunnel]", "interface", _toml_string_literal("")
    )
    lines = _set_toml_key(lines, "[upstream.tunnel]", "interfaces", "[]")
    lines = _set_toml_key(
        lines, "[upstream.tunnel]", "pinned_interface", _toml_string_literal("")
    )
    cfg_path.write_text("".join(lines), encoding="utf-8")
    return True


def _quick_tool_for_interface(interface: str) -> str | None:
    iface = str(interface or "")
    if iface.startswith("wg") and shutil.which("wg-quick"):
        return "wg-quick"
    if shutil.which("awg-quick"):
        return "awg-quick"
    if shutil.which("wg-quick"):
        return "wg-quick"
    return None


def _run_silent(args: list[str], timeout: int = 10) -> int | None:
    try:
        r = subprocess.run(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
        return r.returncode
    except Exception:
        return None


def _stop_tunnel_interface(interface: str) -> None:
    tool = _quick_tool_for_interface(interface)
    if tool:
        for path in _tunnel_config_paths(interface):
            if path.exists():
                _run_silent([tool, "down", str(path)])
        _run_silent([tool, "down", interface])
    _run_silent(["ip", "link", "delete", "dev", interface])


def _delete_tunnel_config_files(interface: str) -> None:
    for path in _tunnel_config_paths(interface):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except Exception:
            pass


def _write_default_proxy_service() -> bool:
    content = """[Unit]
Description=MTProto Proxy (Zig)
Documentation=https://github.com/sleep3r/mtproto.zig
After=network-online.target
Wants=network-online.target

[Service]
# Type=simple (NOT notify): must match the installer (release.zig / tunnel.zig).
# Containerized systemd (Docker/LXC) often fails to deliver the sd_notify datagram,
# which with Restart=always restart-loops a perfectly healthy proxy. Re-enable
# Type=notify + WatchdogSec only behind container detection + ping validation.
Type=simple
User=mtproto
Group=mtproto
WorkingDirectory=/opt/mtproto-proxy
ExecStart=/opt/mtproto-proxy/mtproto-proxy /opt/mtproto-proxy/config.toml
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGTERM
TimeoutStopSec=25
Restart=always
RestartSec=3

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=/opt/mtproto-proxy

# Syscall + kernel surface reduction (mirrors deploy/mtproto-proxy.service).
SystemCallFilter=@system-service
SystemCallArchitectures=native
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
PrivateDevices=yes
RemoveIPC=yes
UMask=0077

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

LimitNOFILE=131582
TasksMax=65535

[Install]
WantedBy=multi-user.target
"""
    try:
        PROXY_SERVICE_FILE.write_text(content, encoding="utf-8")
        return True
    except Exception:
        return False


def _disable_tunnel_pool_runtime() -> None:
    _run_silent(["systemctl", "disable", "--now", "mtproto-tunnel-pool.timer"])
    _run_silent(["systemctl", "stop", "mtproto-tunnel-pool.service"])
    _run_silent(
        [
            "sh",
            "-c",
            "while ip -4 rule del priority 1200 fwmark 200 table 200 2>/dev/null; do :; done; "
            "while ip -4 rule del fwmark 200 table 200 2>/dev/null; do :; done; "
            "ip -4 route flush table 200 2>/dev/null || true",
        ]
    )
    for path in (TUNNEL_POOL_SCRIPT, TUNNEL_POOL_STATE, TUNNEL_POOL_SERVICE, TUNNEL_POOL_TIMER):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except Exception:
            pass
    _write_default_proxy_service()
    _run_silent(["systemctl", "daemon-reload"])


def _delete_tunnel_interface(interface: str) -> dict | None:
    iface = str(interface or "").strip()
    if not _valid_tunnel_interface_name(iface):
        return None

    known_before = _list_tunnel_config_interfaces()
    result = _remove_tunnel_from_config(iface)
    if result is None:
        return None

    stale_last = (
        not result["removed_from_pool"]
        and not result["remaining_pool"]
        and set(known_before).issubset({iface})
    )
    if stale_last:
        _clear_tunnel_config()
        result["removed_last"] = True

    _stop_tunnel_interface(iface)
    _delete_tunnel_config_files(iface)

    if result["removed_last"]:
        _disable_tunnel_pool_runtime()
    elif result["removed_from_pool"]:
        result["controller_ok"] = _run_tunnel_pool_once()
    else:
        result["controller_ok"] = None

    _restart_proxy()
    _awg_cache["ts"] = 0
    _routing_cache["ts"] = 0
    result["interface"] = iface
    result["restarted"] = True
    return result


def _run_tunnel_pool_once() -> bool:
    if not TUNNEL_POOL_SCRIPT.is_file():
        return False
    try:
        r = subprocess.run(
            [str(TUNNEL_POOL_SCRIPT)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=12,
        )
        _routing_cache["ts"] = 0
        return r.returncode == 0
    except Exception:
        _routing_cache["ts"] = 0
        return False


def _set_upstream_proxy_target(
    proxy_type: str,
    host: str,
    port: int,
    username: str,
    password: str,
) -> bool:
    cfg_path = _find_config_path()
    if cfg_path is None:
        return False

    ptype = str(proxy_type or "").strip().lower()
    if ptype not in {"socks5", "http"}:
        return False

    host_value = str(host or "").strip()
    if not host_value or any(ch.isspace() for ch in host_value):
        return False

    if not isinstance(port, int) or port < 1 or port > 65535:
        return False

    user_value = str(username or "")
    pass_value = str(password or "")

    if "\n" in user_value or "\r" in user_value:
        return False
    if "\n" in pass_value or "\r" in pass_value:
        return False

    section = "[upstream.socks5]" if ptype == "socks5" else "[upstream.http]"

    lines = cfg_path.read_text(encoding="utf-8", errors="replace").splitlines(
        keepends=True
    )
    lines = _set_toml_key(lines, section, "host", _toml_string_literal(host_value))
    lines = _set_toml_key(lines, section, "port", str(port))
    lines = _set_toml_key(lines, section, "username", _toml_string_literal(user_value))
    lines = _set_toml_key(lines, section, "password", _toml_string_literal(pass_value))
    cfg_path.write_text("".join(lines), encoding="utf-8")
    return True


def _add_user_to_config(name: str, secret: str) -> bool:
    """Add a user to [access.users] section. Returns True on success."""
    cfg_path = _find_config_path()
    if cfg_path is None:
        return False

    lines = cfg_path.read_text(encoding="utf-8", errors="replace").splitlines(
        keepends=True
    )
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"

    # Find [access.users] section
    insert_idx = None
    in_users = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.lower() == "[access.users]":
            in_users = True
            continue
        if in_users:
            if stripped.startswith("[") and stripped.endswith("]"):
                # Insert before next section
                insert_idx = i
                break
            if not stripped or stripped.startswith("#"):
                continue
        if in_users and i == len(lines) - 1:
            insert_idx = len(lines)

    if insert_idx is None:
        if in_users:
            insert_idx = len(lines)
        else:
            # No [access.users] section, append one
            lines.append("\n[access.users]\n")
            insert_idx = len(lines)

    new_line = f'{name} = "{secret}"\n'
    lines.insert(insert_idx, new_line)
    cfg_path.write_text("".join(lines), encoding="utf-8")
    return True


def _remove_user_from_config(name: str) -> bool:
    """Remove a user from [access.users] and [access.direct_users]. Returns True on success."""
    cfg_path = _find_config_path()
    if cfg_path is None:
        return False

    lines = cfg_path.read_text(encoding="utf-8", errors="replace").splitlines(
        keepends=True
    )
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    new_lines = []
    in_users = False
    in_direct = False
    removed = False

    for line in lines:
        stripped = line.strip()
        if stripped.lower() == "[access.users]":
            in_users = True
            in_direct = False
            new_lines.append(line)
            continue
        elif stripped.lower() in ("[access.direct_users]", "[access.admins]"):
            in_users = False
            in_direct = True
            new_lines.append(line)
            continue
        elif stripped.startswith("[") and stripped.endswith("]"):
            in_users = False
            in_direct = False
            new_lines.append(line)
            continue

        if (in_users or in_direct) and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key == name:
                removed = True
                continue  # skip this line

        new_lines.append(line)

    if removed:
        cfg_path.write_text("".join(new_lines), encoding="utf-8")
    return removed


def _set_user_direct(name: str, direct: bool) -> bool:
    """Set or unset direct status for a user. Returns True on success."""
    cfg_path = _find_config_path()
    if cfg_path is None:
        return False

    lines = cfg_path.read_text(encoding="utf-8", errors="replace").splitlines(
        keepends=True
    )
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    new_lines = []
    found_direct_section = False
    in_direct = False
    user_line_found = False
    direct_section_end = None

    # First pass: find and optionally remove existing entry
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.lower() in ("[access.direct_users]", "[access.admins]"):
            found_direct_section = True
            in_direct = True
            new_lines.append(line)
            continue
        elif stripped.startswith("[") and stripped.endswith("]"):
            if in_direct:
                direct_section_end = len(new_lines)
            in_direct = False
            new_lines.append(line)
            continue

        if in_direct and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key == name:
                user_line_found = True
                if direct:
                    # Keep it but ensure it says true
                    new_lines.append(f"{name} = true\n")
                # If not direct, skip the line (remove)
                continue

        new_lines.append(line)

    # If in_direct was still true at EOF, mark end
    if in_direct:
        direct_section_end = len(new_lines)

    # If we need to add and didn't find the line
    if direct and not user_line_found:
        if found_direct_section and direct_section_end is not None:
            new_lines.insert(direct_section_end, f"{name} = true\n")
        elif found_direct_section:
            new_lines.append(f"{name} = true\n")
        else:
            # Create section
            new_lines.append("\n[access.direct_users]\n")
            new_lines.append(f"{name} = true\n")

    cfg_path.write_text("".join(new_lines), encoding="utf-8")
    return True


def _disable_user_in_config(name: str) -> bool:
    """Move user from [access.users] to [access.disabled_users]. Returns True on success."""
    cfg_path = _find_config_path()
    if cfg_path is None:
        return False

    cfg = _load_proxy_runtime_config()
    secret = cfg.get("users", {}).get(name)
    if not secret:
        return False  # user not found or already disabled

    lines = cfg_path.read_text(encoding="utf-8", errors="replace").splitlines(
        keepends=True
    )
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"

    # Remove from [access.users] and [access.direct_users]
    new_lines = []
    in_users = False
    in_direct = False
    for line in lines:
        stripped = line.strip()
        if stripped.lower() == "[access.users]":
            in_users = True
            in_direct = False
            new_lines.append(line)
            continue
        elif stripped.lower() in ("[access.direct_users]", "[access.admins]"):
            in_users = False
            in_direct = True
            new_lines.append(line)
            continue
        elif stripped.startswith("[") and stripped.endswith("]"):
            in_users = False
            in_direct = False
            new_lines.append(line)
            continue

        if (in_users or in_direct) and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key == name:
                continue  # skip — removing this user

        new_lines.append(line)

    # Add to [access.disabled_users]
    found_disabled = False
    disabled_end = None
    in_disabled = False
    for i, line in enumerate(new_lines):
        stripped = line.strip()
        if stripped.lower() == "[access.disabled_users]":
            found_disabled = True
            in_disabled = True
            continue
        if in_disabled:
            if stripped.startswith("[") and stripped.endswith("]"):
                disabled_end = i
                in_disabled = False
            elif i == len(new_lines) - 1:
                disabled_end = len(new_lines)

    if found_disabled and disabled_end is not None:
        new_lines.insert(disabled_end, f'{name} = "{secret}"\n')
    elif found_disabled:
        new_lines.append(f'{name} = "{secret}"\n')
    else:
        new_lines.append(f"\n[access.disabled_users]\n")
        new_lines.append(f'{name} = "{secret}"\n')

    cfg_path.write_text("".join(new_lines), encoding="utf-8")
    return True


def _enable_user_in_config(name: str) -> bool:
    """Move user from [access.disabled_users] back to [access.users]. Returns True on success."""
    cfg_path = _find_config_path()
    if cfg_path is None:
        return False

    cfg = _load_proxy_runtime_config()
    secret = cfg.get("disabled_users", {}).get(name)
    if not secret:
        return False  # not in disabled list

    # Remove from [access.disabled_users]
    lines = cfg_path.read_text(encoding="utf-8", errors="replace").splitlines(
        keepends=True
    )
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"

    new_lines = []
    in_disabled = False
    for line in lines:
        stripped = line.strip()
        if stripped.lower() == "[access.disabled_users]":
            in_disabled = True
            new_lines.append(line)
            continue
        elif stripped.startswith("[") and stripped.endswith("]"):
            in_disabled = False
            new_lines.append(line)
            continue

        if in_disabled and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key == name:
                continue  # skip — removing from disabled

        new_lines.append(line)

    # Add back to [access.users]
    if not _add_user_to_config_lines(new_lines, name, secret):
        # Fallback: just write the lines and use existing helper
        cfg_path.write_text("".join(new_lines), encoding="utf-8")
        return _add_user_to_config(name, secret)

    cfg_path.write_text("".join(new_lines), encoding="utf-8")
    return True


def _add_user_to_config_lines(lines: list[str], name: str, secret: str) -> bool:
    """Insert a user into [access.users] section within an in-memory lines list."""
    insert_idx = None
    in_users = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.lower() == "[access.users]":
            in_users = True
            continue
        if in_users:
            if stripped.startswith("[") and stripped.endswith("]"):
                insert_idx = i
                break
            if not stripped or stripped.startswith("#"):
                continue
        if in_users and i == len(lines) - 1:
            insert_idx = len(lines)

    if insert_idx is None:
        if in_users:
            insert_idx = len(lines)
        else:
            return False

    lines.insert(insert_idx, f'{name} = "{secret}"\n')
    return True




@app.get("/api/stats")
def api_stats():
    global _prev_net, _net_history, _cpu_history, _mem_history
    cpu = psutil.cpu_percent(interval=0.3)
    mem = psutil.virtual_memory()
    net = psutil.net_io_counters()
    d, rem = divmod(int(time.time() - psutil.boot_time()), 86400)
    h, rem2 = divmod(rem, 3600)

    now = time.time()
    rx_rate = tx_rate = 0.0
    if _prev_net["ts"]:
        dt = now - _prev_net["ts"]
        if dt > 0:
            rx_rate = (net.bytes_recv - _prev_net["rx"]) / dt
            tx_rate = (net.bytes_sent - _prev_net["tx"]) / dt
    _prev_net = {"ts": now, "rx": net.bytes_recv, "tx": net.bytes_sent}

    _net_history.append({"ts": int(now * 1000), "rx": rx_rate, "tx": tx_rate})
    _cpu_history.append({"ts": int(now * 1000), "v": round(cpu, 1)})
    _mem_history.append({"ts": int(now * 1000), "v": round(mem.percent, 1)})
    for lst in (_net_history, _cpu_history, _mem_history):
        while len(lst) > MAX_HISTORY:
            lst.pop(0)

    return JSONResponse(
        {
            "cpu": round(cpu, 1),
            "cpu_history": list(_cpu_history),
            "mem_used": round(mem.used / 1048576),
            "mem_total": round(mem.total / 1048576),
            "mem_pct": round(mem.percent, 1),
            "mem_history": list(_mem_history),
            "net_rx": round(rx_rate),
            "net_tx": round(tx_rate),
            "net_rx_total": net.bytes_recv,
            "net_tx_total": net.bytes_sent,
            "net_history": _net_history[-MAX_HISTORY:],
            "uptime": f"{d}d {h}h {rem2 // 60}m",
            "proxy": _proxy_stats(),
            "proxy_info": _proxy_info(),
            "proxy_version": _proxy_version(),
            "awg": _awg_status(),
            "routing": _routing_status(),
            "masking": _masking_status(),
            "users": _users_status(),
        }
    )


@app.get("/api/egress")
def api_egress():
    """Return tunnel/egress health metrics for all active interfaces.

    Returns:
    {
        "ok": true,
        "primary_interface": str | None,
        "tunnels": [
            {
                "interface": str,
                "up": bool,
                "handshake_age_sec": int | None,
                "rtt_ms": float | None,
                "packet_loss_pct": float | None,
                "quality": str,  // "good", "degraded", "poor", "up", "down", "unknown"
                "is_primary": bool,
            }
        ],
        "summary": {"en": str, "ru": str},  // overall quality message
    }
    """
    global _egress_cache
    now = time.time()
    if now - _egress_cache["ts"] < EGRESS_CACHE_TTL and _egress_cache["data"]:
        return JSONResponse(_egress_cache["data"])

    cfg = _load_proxy_runtime_config()
    routing = _routing_status()

    # Determine which interfaces to check
    tunnels = []
    primary_iface = routing.get("active_tunnel_interface") or routing.get("selected_tunnel_interface")

    # Gather all tunnel interfaces to monitor
    candidates = []
    if routing.get("tunnels"):
        for tun in routing["tunnels"]:
            iface = tun.get("interface")
            if iface and (tun.get("active") or tun.get("link_up") or tun.get("in_pool")):
                if iface not in candidates:
                    candidates.append(iface)

    # If upstream_mode is tunnel, check health for all active/pool members
    upstream_type = str(cfg.get("upstream_type", "auto") or "auto").lower().strip()
    if upstream_type == "tunnel" and candidates:
        for iface in candidates:
            health = _tunnel_egress_health(iface, _tunnel_tool_hint(iface))
            health["is_primary"] = (iface == primary_iface)
            tunnels.append(health)

    # Generate summary (bilingual; rendered client-side per LANG)
    if not tunnels:
        primary_iface = None
        summary_en = "Tunnel monitoring not active (upstream mode is not 'tunnel')"
        summary_ru = "Мониторинг туннеля не активен (режим upstream не 'tunnel')"
    else:
        good_count = sum(1 for t in tunnels if t["quality"] in ("good", "up"))
        total_count = len(tunnels)

        if good_count == total_count:
            summary_en = f"All {total_count} tunnel(s) healthy"
            summary_ru = f"Все {total_count} туннель(и) здоровы"
        elif good_count > 0:
            summary_en = f"{good_count}/{total_count} tunnel(s) healthy"
            summary_ru = f"{good_count}/{total_count} туннель(и) здоровы"
        else:
            summary_en = "All tunnels degraded or down"
            summary_ru = "Все туннели деградированы или отключены"

    result = {
        "ok": True,
        "primary_interface": primary_iface,
        "tunnels": tunnels,
        "summary": {"en": summary_en, "ru": summary_ru},
    }

    _egress_cache.update(ts=now, data=result)
    return JSONResponse(result)


# ── Routing Management API ──


@app.post("/api/routing/middle")
async def api_routing_middle(request: Request):
    """Set [general].use_middle_proxy. Body: { enabled: bool }"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)

    raw_enabled = body.get("enabled", None)
    if not isinstance(raw_enabled, bool):
        return JSONResponse(
            {"ok": False, "error": "enabled must be boolean"}, status_code=400
        )

    if not _set_middle_proxy_enabled(raw_enabled):
        return JSONResponse(
            {"ok": False, "error": "failed to update config"}, status_code=500
        )

    _restart_proxy()
    return JSONResponse({"ok": True, "enabled": raw_enabled, "restarted": True})


@app.post("/api/routing/upstream")
async def api_routing_upstream(request: Request):
    """Set [upstream].type. Body: { type: auto|direct|tunnel|socks5|http }"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)

    upstream_type = str(body.get("type", "")).strip().lower()
    if upstream_type not in {"auto", "direct", "tunnel", "socks5", "http"}:
        return JSONResponse(
            {
                "ok": False,
                "error": "type must be one of: auto, direct, tunnel, socks5, http",
            },
            status_code=400,
        )

    if not _set_upstream_type(upstream_type):
        return JSONResponse(
            {"ok": False, "error": "failed to update config"}, status_code=500
        )

    _restart_proxy()

    cfg = _load_proxy_runtime_config()
    warning = None
    if upstream_type == "socks5":
        host = str(cfg.get("upstream_socks5_host", "") or "").strip()
        port = int(cfg.get("upstream_socks5_port", 0) or 0)
        if not host or port <= 0:
            warning = (
                "socks5 selected but [upstream.socks5] host/port are not configured"
            )
    elif upstream_type == "http":
        host = str(cfg.get("upstream_http_host", "") or "").strip()
        port = int(cfg.get("upstream_http_port", 0) or 0)
        if not host or port <= 0:
            warning = "http selected but [upstream.http] host/port are not configured"

    return JSONResponse(
        {
            "ok": True,
            "type": upstream_type,
            "restarted": True,
            "warning": warning,
        }
    )


@app.post("/api/routing/tunnel-interface")
async def api_routing_tunnel_interface(request: Request):
    """Set [upstream.tunnel].pinned_interface. Body: { interface: str }"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)

    clear = bool(body.get("clear", False))
    iface = "" if clear else str(body.get("interface", "")).strip()

    cfg = _load_proxy_runtime_config()
    pool = _effective_tunnel_pool(cfg)
    if iface and iface not in pool:
        return JSONResponse(
            {"ok": False, "error": "interface is not in configured tunnel pool"},
            status_code=400,
        )

    if not _set_upstream_tunnel_interface(iface):
        return JSONResponse(
            {"ok": False, "error": "failed to update config"}, status_code=500
        )

    controller_ok = _run_tunnel_pool_once()
    return JSONResponse(
        {
            "ok": True,
            "interface": iface,
            "pinned_interface": iface,
            "controller_ok": controller_ok,
            "restarted": False,
        }
    )


@app.post("/api/routing/tunnel-delete")
async def api_routing_tunnel_delete(request: Request):
    """Hard-delete a tunnel interface. Body: { interface: str }"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)

    iface = str(body.get("interface", "")).strip()
    if not _valid_tunnel_interface_name(iface):
        return JSONResponse(
            {"ok": False, "error": "invalid tunnel interface"}, status_code=400
        )

    result = _delete_tunnel_interface(iface)
    if result is None:
        return JSONResponse(
            {"ok": False, "error": "tunnel interface is not configured"},
            status_code=404,
        )

    return JSONResponse({"ok": True, **result})


@app.post("/api/routing/proxy-target")
async def api_routing_proxy_target(request: Request):
    """Set [upstream.socks5]/[upstream.http] target + auth.
    Body: { type: socks5|http, host: str, port: int, username?: str, password?: str }
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)

    proxy_type = str(body.get("type", "")).strip().lower()
    if proxy_type not in {"socks5", "http"}:
        return JSONResponse(
            {"ok": False, "error": "type must be socks5 or http"},
            status_code=400,
        )

    host = str(body.get("host", "")).strip()
    if not host:
        return JSONResponse({"ok": False, "error": "host is required"}, status_code=400)

    try:
        port = int(body.get("port", 0))
    except Exception:
        port = 0

    if port < 1 or port > 65535:
        return JSONResponse(
            {"ok": False, "error": "port must be 1..65535"}, status_code=400
        )

    username = str(body.get("username", "") or "")
    password = str(body.get("password", "") or "")

    if "\n" in username or "\r" in username or "\n" in password or "\r" in password:
        return JSONResponse(
            {"ok": False, "error": "username/password must not contain newlines"},
            status_code=400,
        )

    if not _set_upstream_proxy_target(proxy_type, host, port, username, password):
        return JSONResponse(
            {"ok": False, "error": "failed to update config"}, status_code=500
        )

    _restart_proxy()
    return JSONResponse(
        {
            "ok": True,
            "type": proxy_type,
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "restarted": True,
        }
    )


def _labels_path() -> Path:
    """Sidecar file for human display labels (e.g. "Мама", "work 💼"). The proxy
    never reads this — it only consumes [access.users] — so labels can be any
    language without touching the config format the proxy parses."""
    for p in _proxy_config_candidates():
        if p.exists():
            return p.parent / "user-labels.json"
    return Path("/opt/mtproto-proxy/user-labels.json")


def _load_labels() -> dict:
    try:
        with open(_labels_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_labels(labels: dict) -> None:
    try:
        path = _labels_path()
        tmp = path.with_name(path.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(labels, f, ensure_ascii=False)
        tmp.replace(path)
    except Exception:
        pass


@app.get("/api/qr")
async def api_qr(text: str = ""):
    """Render a QR (SVG) for a connection link so it can be scanned from a phone.

    Only ever encodes our own proxy links — this bounds the input and keeps the
    endpoint from being a generic QR oracle. The dashboard is localhost-only.
    """
    text = (text or "").strip()
    if (
        not text
        or len(text) > 512
        or not (text.startswith("https://t.me/proxy") or text.startswith("tg://proxy"))
    ):
        return PlainTextResponse("invalid link", status_code=400)
    try:
        # Feed the link over STDIN, not as an argv element: the link embeds the per-user
        # MTProto secret (ee<32-hex>...), and an argv copy is visible to any local user via
        # ps / /proc/<pid>/cmdline. argv (no shell) already prevents command injection.
        out = subprocess.run(
            ["qrencode", "-t", "SVG", "-m", "2", "-o", "-"],
            input=text.encode(),
            capture_output=True,
            timeout=5,
        )
    except FileNotFoundError:
        return PlainTextResponse("qrencode not installed", status_code=503)
    except Exception:
        return PlainTextResponse("qr render failed", status_code=503)
    if out.returncode != 0 or not out.stdout:
        return PlainTextResponse("qr render failed", status_code=503)
    return Response(content=out.stdout, media_type="image/svg+xml")


# ── User Management API ──


@app.post("/api/users/add")
async def api_user_add(request: Request):
    """Add a new user. Body: { name: str, secret?: str }"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)

    raw_name = str(body.get("name", "")).strip()
    if not raw_name or len(raw_name) > 64:
        return JSONResponse(
            {"ok": False, "error": "name is required (max 64 characters)"},
            status_code=400,
        )

    secret = str(body.get("secret", "")).strip().lower()
    if not secret:
        secret = secrets.token_hex(16)
    if not USER_SECRET_RE.fullmatch(secret):
        return JSONResponse(
            {"ok": False, "error": "invalid secret (must be 32 hex chars)"},
            status_code=400,
        )

    # The display name can be any language ("Мама", "work laptop"); derive a stable
    # ASCII key for the TOML [access.users] section and keep the original as a label.
    cfg = _load_proxy_runtime_config()
    existing = set(cfg.get("users", {}).keys()) | set(cfg.get("disabled_users", {}).keys())
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", raw_name).strip("_").lower()
    if len(slug) < 2:
        slug = "user_" + secrets.token_hex(3)
    key = slug
    n = 2
    while key in existing:
        key = f"{slug}_{n}"
        n += 1
    label = raw_name if raw_name != key else ""

    if not _add_user_to_config(key, secret):
        return JSONResponse(
            {"ok": False, "error": "failed to write config"}, status_code=500
        )
    if label:
        labels = _load_labels()
        labels[key] = label
        _save_labels(labels)

    _users_cache["ts"] = 0
    _restart_proxy()
    return JSONResponse(
        {"ok": True, "name": key, "label": label, "secret": secret, "restarted": True}
    )


@app.post("/api/users/remove")
async def api_user_remove(request: Request):
    """Remove a user. Body: { name: str }"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)

    name = str(body.get("name", "")).strip()
    if not name:
        return JSONResponse({"ok": False, "error": "name is required"}, status_code=400)

    if not _remove_user_from_config(name):
        return JSONResponse({"ok": False, "error": "user not found"}, status_code=404)

    _users_cache["ts"] = 0
    _restart_proxy()
    return JSONResponse({"ok": True, "name": name, "restarted": True})


@app.post("/api/users/direct")
async def api_user_direct(request: Request):
    """Toggle direct status. Body: { name: str, direct: bool }"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)

    name = str(body.get("name", "")).strip()
    direct = bool(body.get("direct", False))

    if not name:
        return JSONResponse({"ok": False, "error": "name is required"}, status_code=400)

    # Verify user exists
    cfg = _load_proxy_runtime_config()
    if name not in cfg.get("users", {}):
        return JSONResponse({"ok": False, "error": "user not found"}, status_code=404)

    if not _set_user_direct(name, direct):
        return JSONResponse(
            {"ok": False, "error": "failed to write config"}, status_code=500
        )

    _users_cache["ts"] = 0
    _restart_proxy()
    return JSONResponse({"ok": True, "name": name, "direct": direct, "restarted": True})


@app.post("/api/users/toggle")
async def api_user_toggle(request: Request):
    """Enable or disable a user. Body: { name: str, enabled: bool }"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)

    name = str(body.get("name", "")).strip()
    if not name:
        return JSONResponse({"ok": False, "error": "name is required"}, status_code=400)

    enabled = body.get("enabled", None)
    if not isinstance(enabled, bool):
        return JSONResponse(
            {"ok": False, "error": "enabled must be boolean"}, status_code=400
        )

    if enabled:
        if not _enable_user_in_config(name):
            return JSONResponse(
                {"ok": False, "error": "user not found in disabled list"},
                status_code=404,
            )
    else:
        if not _disable_user_in_config(name):
            return JSONResponse(
                {"ok": False, "error": "user not found or already disabled"},
                status_code=404,
            )

    _users_cache["ts"] = 0
    _restart_proxy()
    return JSONResponse(
        {"ok": True, "name": name, "enabled": enabled, "restarted": True}
    )


@app.get("/api/logs")
def api_logs():
    _drain_to_recent()
    with _recent_lock:
        return JSONResponse(list(_recent_logs))


@app.websocket("/ws/logs")
async def ws_logs(ws: WebSocket):
    # WebSocket upgrades bypass HTTP middleware, so enforce the same gates here as
    # _dashboard_security: the loopback Host-pin (DNS-rebinding defense) AND Basic auth
    # (browsers replay cached same-origin Basic credentials on the handshake).
    if _DASH_ENFORCE_HOST and _host_hostname(ws.headers.get("host", "")) not in _DASH_LOOPBACK_HOSTS:
        await ws.close(code=1008)
        return
    # WebSocket reads bypass CORS, so a cross-origin page (e.g. evil.com) could otherwise
    # open ws://localhost/ws/logs, pass the loopback Host-pin, ride the browser's cached
    # Basic credentials, and stream the proxy logs. Mirror the HTTP middleware's Origin gate.
    ws_origin = ws.headers.get("origin")
    if ws_origin and urlparse(ws_origin).netloc != ws.headers.get("host", ""):
        await ws.close(code=1008)
        return
    if not _dashboard_auth_ok(ws.headers.get("authorization")):
        await ws.close(code=1008)
        return
    await ws.accept()
    _drain_to_recent()
    # Per-client cursor: send the current backlog, then only entries newer than what THIS
    # client has already seen. No destructive sharing between concurrent viewers.
    backlog, cursor = _logs_since(0)
    for e in backlog:
        await ws.send_json(e)
    try:
        while True:
            _drain_to_recent()
            new, cursor = _logs_since(cursor)
            for item in new:
                await ws.send_json(item)
            if not new:
                await asyncio.sleep(0.5)
    except (WebSocketDisconnect, Exception):
        pass


# Static files (index.html, style.css, app.js) — mounted last so API routes take priority
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

if __name__ == "__main__":
    print(
        f"[dashboard] HTTP Basic auth required (username: any, password in "
        f"{_DASHBOARD_TOKEN_FILE}). Listening on "
        f"{DASHBOARD_CFG['host']}:{DASHBOARD_CFG['port']} — reach it over an SSH tunnel.",
        file=sys.stderr,
    )
    uvicorn.run(
        app, host=DASHBOARD_CFG["host"], port=DASHBOARD_CFG["port"], log_level="warning"
    )
