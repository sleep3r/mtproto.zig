#!/usr/bin/env python3
"""MTProto Proxy Dashboard — API server."""

import asyncio
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
from urllib.parse import quote

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        tomllib = None

import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn


def _proxy_config_candidates():
    return [
        Path(__file__).parent.parent / "config.toml",  # /opt/mtproto-proxy/config.toml
        Path("/opt/mtproto-proxy/config.toml"),
    ]


def _load_dashboard_config() -> dict:
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


def _load_proxy_runtime_config() -> dict:
    defaults = {
        "public_ip": "",
        "port": 443,
        "mask": True,
        "mask_port": 443,
        "tls_domain": "google.com",
        "use_middle_proxy": False,
        "upstream_type": "auto",
        "upstream_tunnel_interface": "awg0",
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
        "use_middle_proxy": defaults["use_middle_proxy"],
        "upstream_type": defaults["upstream_type"],
        "upstream_tunnel_interface": defaults["upstream_tunnel_interface"],
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


_routing_cache = {"ts": 0, "data": None}
ROUTING_CACHE_TTL = 8  # seconds


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


def _detect_tunnel_interface(interface: str, tool_hint: str | None = None) -> dict:
    result = {
        "interface": interface,
        "tool": tool_hint or "-",
        "link_up": False,
        "active": False,
        "endpoint": None,
        "handshake": None,
        "handshake_ok": False,
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

        return result

    if result["link_up"]:
        result["reason"] = "interface up, tool output unavailable"
    else:
        result["reason"] = "interface down"
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
        iface = str(cfg.get("upstream_tunnel_interface", "awg0") or "awg0").strip()
        route_dev = policy.get("route_dev")
        if route_dev:
            return f"mark 200 -> table 200 -> dev {route_dev}"
        return f"mark 200 -> table 200 (iface {iface})"

    if upstream_type == "direct":
        return "direct host routing"

    return "auto (direct unless tunnel mode is selected)"


def _routing_status() -> dict:
    now = time.time()
    if now - _routing_cache["ts"] < ROUTING_CACHE_TTL:
        return _routing_cache["data"]

    cfg = _load_proxy_runtime_config()
    upstream_type = str(cfg.get("upstream_type", "auto") or "auto").lower().strip()
    selected_iface = str(cfg.get("upstream_tunnel_interface", "awg0") or "awg0").strip()

    if not selected_iface:
        selected_iface = "awg0"

    system_ifaces = _list_system_interfaces()
    available_tunnel_ifaces: list[str] = []
    for iface in system_ifaces:
        low = iface.lower()
        if not (low.startswith(("awg", "wg", "tun", "tap")) or iface == selected_iface):
            continue
        if iface and iface not in available_tunnel_ifaces:
            available_tunnel_ifaces.append(iface)

    interfaces = list(available_tunnel_ifaces)
    for iface in ("awg0", "wg0"):
        if iface not in interfaces:
            interfaces.append(iface)

    tunnels = []
    for iface in interfaces:
        hint = None
        if iface.startswith("awg"):
            hint = "awg"
        elif iface.startswith("wg"):
            hint = "wg"

        tunnel = _detect_tunnel_interface(iface, hint)
        if (
            iface == selected_iface
            or tunnel.get("link_up")
            or tunnel.get("active")
            or tunnel.get("endpoint")
        ):
            tunnels.append(tunnel)

    policy = _policy_routing_status()
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

    if upstream_type == "tunnel":
        healthy = bool(
            policy.get("rule_ok")
            and policy.get("route_ok")
            and primary_tunnel
            and primary_tunnel.get("link_up")
            and primary_tunnel.get("active")
            and primary_tunnel.get("handshake_ok")
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
        "available_tunnel_interfaces": available_tunnel_ifaces,
        "policy": policy,
        "tunnels": tunnels,
        "active_tunnels": active_tunnels,
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
    mask_port = int(censorship["mask_port"])
    tls_domain = censorship["tls_domain"]

    using_netns_target = False

    if not mask_enabled:
        mode = "disabled"
        target_host = "-"
    elif mask_port == 443:
        mode = "remote"
        target_host = tls_domain
    else:
        mode = "local"
        target_host = "127.0.0.1"

    endpoint_ok = None
    if mode == "local":
        endpoint_ok = _probe_mask_endpoint(target_host, mask_port)

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
            safe_server = quote(server)
            tg_link = f"tg://proxy?server={safe_server}&port={port}&secret={ee_secret}"
            tme_link = (
                f"https://t.me/proxy?server={safe_server}&port={port}&secret={ee_secret}"
            )

        items.append(
            {
                "name": name,
                "secret": secret_raw,
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

    if upstream_type == "tunnel":
        lines = _set_toml_key(lines, "[upstream.tunnel]", "interface", '"awg0"')

    cfg_path.write_text("".join(lines), encoding="utf-8")
    return True


def _set_upstream_tunnel_interface(interface: str) -> bool:
    cfg_path = _find_config_path()
    if cfg_path is None:
        return False

    iface = str(interface or "").strip()
    if not iface:
        return False

    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", iface):
        return False

    lines = cfg_path.read_text(encoding="utf-8", errors="replace").splitlines(
        keepends=True
    )
    lines = _set_toml_key(
        lines, "[upstream.tunnel]", "interface", _toml_string_literal(iface)
    )
    cfg_path.write_text("".join(lines), encoding="utf-8")
    return True


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
    """Set [upstream.tunnel].interface. Body: { interface: str }"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)

    iface = str(body.get("interface", "")).strip()
    if not iface:
        return JSONResponse(
            {"ok": False, "error": "interface is required"}, status_code=400
        )

    available = _list_system_interfaces()
    if available and iface not in available:
        return JSONResponse(
            {"ok": False, "error": "interface is not present on host"},
            status_code=400,
        )

    if not _set_upstream_tunnel_interface(iface):
        return JSONResponse(
            {"ok": False, "error": "failed to update config"}, status_code=500
        )

    _restart_proxy()
    return JSONResponse({"ok": True, "interface": iface, "restarted": True})


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


# ── User Management API ──


@app.post("/api/users/add")
async def api_user_add(request: Request):
    """Add a new user. Body: { name: str, secret?: str }"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)

    name = str(body.get("name", "")).strip()
    if not name or not re.match(r"^[a-zA-Z0-9_-]+$", name):
        return JSONResponse(
            {"ok": False, "error": "invalid name (use a-z, 0-9, _, -)"}, status_code=400
        )

    # Check if user already exists
    cfg = _load_proxy_runtime_config()
    if name in cfg.get("users", {}):
        return JSONResponse(
            {"ok": False, "error": "user already exists"}, status_code=409
        )

    secret = str(body.get("secret", "")).strip().lower()
    if not secret:
        secret = secrets.token_hex(16)
    if not USER_SECRET_RE.fullmatch(secret):
        return JSONResponse(
            {"ok": False, "error": "invalid secret (must be 32 hex chars)"},
            status_code=400,
        )

    if not _add_user_to_config(name, secret):
        return JSONResponse(
            {"ok": False, "error": "failed to write config"}, status_code=500
        )

    _users_cache["ts"] = 0
    _restart_proxy()
    return JSONResponse({"ok": True, "name": name, "secret": secret, "restarted": True})


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
        app, host=DASHBOARD_CFG["host"], port=DASHBOARD_CFG["port"], log_level="warning"
    )
