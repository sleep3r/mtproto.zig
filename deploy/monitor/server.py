#!/usr/bin/env python3
"""MTProto Proxy Monitor — API server."""

import asyncio
import json
import re
import time
import threading
import queue
import subprocess
import sys
import shutil
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        tomllib = None

import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn


def _proxy_config_candidates():
    return [
        Path(__file__).parent.parent / "config.toml",  # /opt/mtproto-proxy/config.toml
        Path("/opt/mtproto-proxy/config.toml"),
    ]


def _load_monitor_config() -> dict:
    """Load [monitor] section from config.toml (host, port)."""
    defaults = {"host": "127.0.0.1", "port": 61208}
    if tomllib is None:
        return defaults
    # Look for config.toml relative to the install directory
    for p in _proxy_config_candidates():
        if p.is_file():
            try:
                with open(p, "rb") as f:
                    cfg = tomllib.load(f)
                mon = cfg.get("monitor", {})
                return {
                    "host": str(mon.get("host", defaults["host"])),
                    "port": int(mon.get("port", defaults["port"])),
                }
            except Exception as exc:
                print(f"[monitor] warning: failed to parse {p}: {exc}", file=sys.stderr)
    return defaults


MONITOR_CFG = _load_monitor_config()

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI()

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
_recent_lock = threading.Lock()
MAX_RECENT = 100
USER_SECRET_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def _drain_to_recent():
    drained = []
    while True:
        try:
            drained.append(_log_buffer.get_nowait())
        except queue.Empty:
            break
    if drained:
        with _recent_lock:
            _recent_logs.extend(drained)
            del _recent_logs[: max(0, len(_recent_logs) - MAX_RECENT)]
    return drained


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
                break
        for line in reversed(out.strip().split("\n")):
            if "drops:" in line:
                for k, p in [
                    ("rate_drops", r"rate\+=(\d+)"),
                    ("cap_drops", r"cap\+=(\d+)"),
                    ("sat_drops", r"sat\+=(\d+)"),
                    ("hs_budget_drops", r"hs_budget\+=(\d+)"),
                    ("hs_timeout", r"hs_timeout\+=(\d+)"),
                ]:
                    m2 = re.search(p, line)
                    if m2:
                        s[k] = int(m2[1])
                break
        return s
    except Exception:
        return {}


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
            return dict(
                uptime=up, pid=proc.info["pid"], rss_mb=round(rss, 1), online=True
            )
    return dict(uptime="offline", pid=0, rss_mb=0, online=False)


_awg_cache = {"ts": 0, "data": None}
AWG_CACHE_TTL = 10  # seconds


def _awg_status() -> dict:
    """Check AmneziaWG tunnel status. Returns None if not installed."""
    now = time.time()
    if now - _awg_cache["ts"] < AWG_CACHE_TTL:
        return _awg_cache["data"]

    import shutil

    if not shutil.which("awg"):
        _awg_cache.update(ts=now, data=None)
        return None

    # Check if namespace exists
    try:
        ns_out = subprocess.check_output(
            ["ip", "netns", "list"], text=True, timeout=2, stderr=subprocess.DEVNULL
        )
        if "tg_proxy_ns" not in ns_out:
            result = {
                "installed": True,
                "active": False,
                "reason": "namespace not found",
            }
            _awg_cache.update(ts=now, data=result)
            return result
    except Exception:
        _awg_cache.update(ts=now, data=None)
        return None

    try:
        out = subprocess.check_output(
            ["ip", "netns", "exec", "tg_proxy_ns", "awg", "show"],
            text=True,
            timeout=3,
            stderr=subprocess.DEVNULL,
        )
        result = {
            "installed": True,
            "active": False,
            "endpoint": None,
            "handshake": None,
            "rx": None,
            "tx": None,
        }

        m = re.search(r"endpoint:\s*(\S+)", out)
        if m:
            result["endpoint"] = m[1]

        m = re.search(r"latest handshake:\s*(.+)", out)
        if m:
            result["handshake"] = m[1].strip()

        m = re.search(
            r"transfer:\s*([\d.]+\s*\S+)\s+received,\s*([\d.]+\s*\S+)\s+sent", out
        )
        if m:
            result["rx"] = m[1]
            result["tx"] = m[2]

        if result.get("endpoint"):
            result["active"] = True
            if not result.get("handshake"):
                result["handshake"] = "none (idle)"
        else:
            result["reason"] = "no endpoint configured"

        _awg_cache.update(ts=now, data=result)
        return result
    except Exception:
        result = {"installed": True, "active": False, "reason": "awg show failed"}
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


def _load_proxy_runtime_config() -> dict:
    defaults = {
        "public_ip": "",
        "port": 443,
        "mask": True,
        "mask_port": 443,
        "tls_domain": "google.com",
        "users": {},
        "direct_users": set(),
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
        "mask": defaults["mask"],
        "mask_port": defaults["mask_port"],
        "tls_domain": defaults["tls_domain"],
        "users": {},
        "direct_users": set(),
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

                elif section == "[censorship]":
                    if key == "mask":
                        result["mask"] = _parse_bool(value, defaults["mask"])
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

    except Exception:
        return defaults

    return result


def _load_censorship_config() -> dict:
    cfg = _load_proxy_runtime_config()
    return {
        "mask": bool(cfg["mask"]),
        "mask_port": int(cfg["mask_port"]),
        "tls_domain": str(cfg["tls_domain"]),
    }


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


def _probe_mask_endpoint(target: str, port: int, use_netns: bool) -> bool:
    if not shutil.which("curl"):
        return False

    url = f"https://{target}:{port}/"
    if use_netns:
        cmd = [
            "ip",
            "netns",
            "exec",
            "tg_proxy_ns",
            "curl",
            "-sk",
            "--max-time",
            "2",
            url,
        ]
    else:
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
    mask_port = int(censorship["mask_port"])
    tls_domain = censorship["tls_domain"]

    netns_present = False
    host_veth_present = False
    try:
        ns_out = subprocess.check_output(
            ["ip", "netns", "list"], text=True, timeout=2, stderr=subprocess.DEVNULL
        )
        netns_present = "tg_proxy_ns" in ns_out
    except Exception:
        netns_present = False

    try:
        addr_out = subprocess.check_output(
            ["ip", "-4", "addr", "show"],
            text=True,
            timeout=2,
            stderr=subprocess.DEVNULL,
        )
        host_veth_present = "10.200.200.1/" in addr_out
    except Exception:
        host_veth_present = False

    using_netns_target = (
        mask_enabled and mask_port != 443 and netns_present and host_veth_present
    )

    if not mask_enabled:
        mode = "disabled"
        target_host = "-"
    elif mask_port == 443:
        mode = "remote"
        target_host = tls_domain
    else:
        mode = "local"
        target_host = "10.200.200.1" if using_netns_target else "127.0.0.1"

    endpoint_ok = None
    if mode == "local":
        endpoint_ok = _probe_mask_endpoint(target_host, mask_port, using_netns_target)

    nginx_active = _unit_active("nginx.service")
    nginx_enabled = _unit_enabled("nginx.service")
    timer_active = _unit_active("mtproto-mask-health.timer")
    timer_enabled = _unit_enabled("mtproto-mask-health.timer")

    healthy = True
    if mode == "local":
        healthy = nginx_active and timer_active and bool(endpoint_ok)

    result = {
        "enabled": mask_enabled,
        "mode": mode,
        "mask_port": mask_port,
        "tls_domain": tls_domain,
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


def _users_status() -> dict:
    now = time.time()
    if now - _users_cache["ts"] < USERS_CACHE_TTL:
        return _users_cache["data"]

    cfg = _load_proxy_runtime_config()
    server = str(cfg.get("public_ip") or "").strip()
    port = int(cfg.get("port", 443))
    tls_domain = str(cfg.get("tls_domain", "google.com"))
    domain_hex = tls_domain.encode("utf-8", errors="ignore").hex()

    direct_users = set(cfg.get("direct_users", set()))
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
            tg_link = f"tg://proxy?server={server}&port={port}&secret={ee_secret}"
            tme_link = (
                f"https://t.me/proxy?server={server}&port={port}&secret={ee_secret}"
            )

        items.append(
            {
                "name": name,
                "direct": name in direct_users,
                "tg_link": tg_link,
                "tme_link": tme_link,
            }
        )

    result = {
        "total": len(items),
        "direct_total": sum(1 for item in items if item["direct"]),
        "links_ready": bool(server),
        "server": server,
        "port": port,
        "tls_domain": tls_domain,
        "items": items,
    }

    _users_cache.update(ts=now, data=result)
    return result


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
            "awg": _awg_status(),
            "masking": _masking_status(),
            "users": _users_status(),
        }
    )


@app.get("/api/logs")
def api_logs():
    _drain_to_recent()
    with _recent_lock:
        return JSONResponse(list(_recent_logs))


@app.websocket("/ws/logs")
async def ws_logs(ws: WebSocket):
    await ws.accept()
    _drain_to_recent()
    with _recent_lock:
        backlog = list(_recent_logs)
    for e in backlog:
        await ws.send_json(e)
    try:
        while True:
            new = _drain_to_recent()
            for item in new:
                await ws.send_json(item)
            if not new:
                await asyncio.sleep(0.5)
    except (WebSocketDisconnect, Exception):
        pass


# Static files (index.html, style.css, app.js) — mounted last so API routes take priority
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

if __name__ == "__main__":
    uvicorn.run(
        app, host=MONITOR_CFG["host"], port=MONITOR_CFG["port"], log_level="warning"
    )
