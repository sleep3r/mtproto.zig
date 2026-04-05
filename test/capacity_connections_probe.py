#!/usr/bin/env python3
"""
Connection capacity probe for MTProto proxy implementations.

What it measures:
- held concurrent TCP sessions (server-side ESTABLISHED count)
- process tree RSS growth while connections are held

Default profile paths are tuned for the benchmark host layout used in README:
- binaries/configs under /root/benchmarks
- mtproto_proxy release script at /opt/mtp_proxy/bin/mtp_proxy
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import resource
import signal
import socket
import struct
import subprocess
import time
import ssl
import select
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Profile:
    name: str
    port: int
    command: list[str]
    levels: list[int]
    secret_hex: Optional[str] = None
    prep: Optional[str] = None


def build_profiles(bench_dir: Path) -> list[Profile]:
    bin_dir = bench_dir / "bin"
    cfg_dir = bench_dir / "configs"
    work_dir = bench_dir / "work"

    secret = "00112233445566778899aabbccddeeff"

    return [
        Profile(
            name="mtproto.zig",
            port=16543,
            command=[
                str(bin_dir / "mtproto-zig-local"),
                str(cfg_dir / "capacity-mtproto-zig.toml"),
            ],
            secret_hex=secret,
            prep="mtproto_zig_autocap",
            levels=[200, 500, 1000, 2000, 4000, 8000, 12000],
        ),
        Profile(
            name="Official MTProxy",
            port=16544,
            command=[
                str(bin_dir / "official-mtproxy"),
                "-u",
                "nobody",
                "-p",
                "18888",
                "-H",
                "16544",
                "-S",
                secret,
                "--aes-pwd",
                str(work_dir / "proxy-secret"),
                str(work_dir / "proxy-multi.conf"),
            ],
            secret_hex=secret,
            prep="set_low_pid",
            levels=[200, 500, 1000, 2000, 4000, 8000, 12000],
        ),
        Profile(
            name="Teleproxy",
            port=16545,
            command=[
                str(bin_dir / "teleproxy-release"),
                "-u",
                "root",
                "-p",
                "18890",
                "-H",
                "16545",
                "-S",
                secret,
                "--aes-pwd",
                str(work_dir / "proxy-secret"),
                str(work_dir / "proxy-multi.conf"),
            ],
            secret_hex=secret,
            levels=[200, 500, 1000, 2000, 4000, 8000, 12000],
        ),
        Profile(
            name="Telemt",
            port=16546,
            command=[
                str(bin_dir / "telemt"),
                str(cfg_dir / "capacity-telemt.toml"),
            ],
            secret_hex=secret,
            levels=[100, 200, 500, 1000, 2000, 4000, 8000],
        ),
        Profile(
            name="mtg",
            port=16547,
            command=[
                str(bin_dir / "mtg-release"),
                "run",
                str(cfg_dir / "capacity-mtg.toml"),
            ],
            secret_hex=secret,
            levels=[200, 500, 1000, 2000, 4000, 8000, 12000],
        ),
        Profile(
            name="mtprotoproxy",
            port=16548,
            command=[
                "python3",
                str(bin_dir / "mtprotoproxy.py"),
                str(cfg_dir / "capacity-mtprotoproxy.py"),
            ],
            secret_hex=secret,
            levels=[200, 500, 1000, 2000, 4000, 8000],
        ),
        Profile(
            name="mtproto_proxy",
            port=1443,
            command=["/opt/mtp_proxy/bin/mtp_proxy", "foreground"],
            secret_hex=secret,
            levels=[100, 200, 500, 1000, 2000],
        ),
    ]


def parse_ppid_map() -> dict[int, int]:
    out: dict[int, int] = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            stat = Path(f"/proc/{pid}/stat").read_text().split()
            out[pid] = int(stat[3])
        except OSError:
            continue
    return out


def descendants(root_pid: int) -> set[int]:
    ppid = parse_ppid_map()
    children: dict[int, list[int]] = {}
    for pid, pp in ppid.items():
        children.setdefault(pp, []).append(pid)

    seen: set[int] = set()
    stack = [root_pid]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        stack.extend(children.get(cur, []))
    return seen


def rss_kb_for_pid(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except OSError:
        return 0
    return 0


def tree_rss_kb(pid: int) -> int:
    return sum(rss_kb_for_pid(p) for p in descendants(pid))


def listener_pid(port: int) -> Optional[int]:
    ids = listener_pids(port)
    if not ids:
        return None
    return ids[0]


def listener_pids(port: int) -> list[int]:
    try:
        out = subprocess.check_output(
            ["ss", "-ltnp"], text=True, stderr=subprocess.DEVNULL
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return []

    ids: list[int] = []
    needle = f":{port} "
    for line in out.splitlines():
        if needle not in line:
            continue
        ids.extend(int(m.group(1)) for m in re.finditer(r"pid=(\d+)", line))

    if not ids:
        return []
    return sorted(set(ids))


def established_count(port: int) -> int:
    est_state = "01"
    port_hex = f"{port:04X}"

    def count_in(path: str) -> int:
        p = Path(path)
        if not p.exists():
            return 0
        try:
            lines = p.read_text().splitlines()
        except OSError:
            return 0

        total = 0
        for line in lines[1:]:
            cols = line.split()
            if len(cols) < 4:
                continue
            local = cols[1]
            state = cols[3]
            if state != est_state:
                continue
            if ":" not in local:
                continue
            local_port = local.split(":", 1)[1]
            if local_port.upper() == port_hex:
                total += 1
        return total

    return count_in("/proc/net/tcp") + count_in("/proc/net/tcp6")


def kill_tree(root_pid: Optional[int]) -> None:
    if not root_pid:
        return
    for pid in sorted(descendants(root_pid), reverse=True):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    time.sleep(0.25)
    for pid in sorted(descendants(root_pid), reverse=True):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def cleanup_port(port: int) -> None:
    for _ in range(3):
        pids = listener_pids(port)
        if not pids:
            break
        for pid in pids:
            kill_tree(pid)
        time.sleep(0.15)


def read_cmdline_args(pid: int) -> list[str]:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return []
    if not raw:
        return []
    parts = [p for p in raw.split(b"\x00") if p]
    out: list[str] = []
    for part in parts:
        try:
            out.append(part.decode("utf-8", errors="replace"))
        except Exception:
            out.append("")
    return out


def command_matches_profile(pid_args: list[str], profile_cmd: list[str]) -> bool:
    if not pid_args or not profile_cmd:
        return False

    target0 = profile_cmd[0]
    if target0.startswith("/"):
        return target0 in pid_args

    target0_base = os.path.basename(target0)
    pid0_base = os.path.basename(pid_args[0])
    if target0_base.startswith("python"):
        script_markers = [x for x in profile_cmd[1:] if x.endswith(".py")]
        if not script_markers:
            return False
        return pid0_base.startswith("python") and all(
            m in pid_args for m in script_markers
        )

    return pid0_base == target0_base


def kill_profile_processes(
    profile: Profile, exclude: Optional[set[int]] = None
) -> None:
    excluded = exclude or set()
    matched: list[int] = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid in excluded or pid == os.getpid():
            continue
        pid_args = read_cmdline_args(pid)
        if command_matches_profile(pid_args, profile.command):
            matched.append(pid)

    for pid in matched:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    if matched:
        time.sleep(0.2)
    for pid in matched:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def wait_for_listen(port: int, timeout_sec: float) -> bool:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        try:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        finally:
            s.close()
        time.sleep(0.02)
    return False


def wait_for_profile_listen(
    process: subprocess.Popen[object], port: int, timeout_sec: float
) -> tuple[bool, str]:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        listen_pid = listener_pid(port)
        if listen_pid is not None:
            if listen_pid in descendants(process.pid):
                return True, "ok"

        if process.poll() is not None:
            return False, "exited"

        time.sleep(0.02)

    return False, "timeout"


def read_log_tail(path: Path, max_lines: int = 30) -> list[str]:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return []
    if len(lines) <= max_lines:
        return lines
    return lines[-max_lines:]


def build_tls_auth_client_hello(secret: bytes, hostname: str) -> bytes:
    """Build MTProto TLS-auth ClientHello with valid SNI extension.

    Keeps MTProto-specific fixed offsets:
    - digest/random field at 11..43
    - session_id_len at 43
    while making the packet structurally parseable by strict ClientHello/SNI parsing.
    """

    host = hostname.encode("ascii", errors="ignore")
    if not host:
        host = b"www.google.com"

    sni_list_len = 1 + 2 + len(host)
    sni_ext_len = 2 + sni_list_len
    supported_versions_ext_len = 3

    body_len = (
        2  # legacy_version
        + 32  # random (digest field)
        + 1  # session_id_len
        + 32  # session_id
        + 2  # cipher_suites_len
        + 2  # single cipher suite
        + 1  # compression_methods_len
        + 1  # compression method
        + 2  # extensions_len
        + 4  # sni ext header (type+len)
        + sni_ext_len
        + 4  # supported_versions ext header
        + supported_versions_ext_len
    )

    record_payload_len = 4 + body_len
    packet = bytearray(5 + record_payload_len)

    # TLS record header
    packet[0] = 0x16
    packet[1] = 0x03
    packet[2] = 0x01
    packet[3:5] = struct.pack(">H", record_payload_len)

    # Handshake header
    packet[5] = 0x01  # ClientHello
    packet[6] = (body_len >> 16) & 0xFF
    packet[7] = (body_len >> 8) & 0xFF
    packet[8] = body_len & 0xFF

    pos = 9
    packet[pos : pos + 2] = b"\x03\x03"
    pos += 2

    # random/digest field at 11..43
    random_pos = pos
    pos += 32

    packet[pos] = 0x20
    pos += 1
    packet[pos : pos + 32] = os.urandom(32)
    pos += 32

    packet[pos : pos + 2] = struct.pack(">H", 2)
    pos += 2
    packet[pos : pos + 2] = b"\x13\x01"
    pos += 2

    packet[pos] = 1
    pos += 1
    packet[pos] = 0
    pos += 1

    packet[pos : pos + 2] = struct.pack(
        ">H", 4 + sni_ext_len + 4 + supported_versions_ext_len
    )
    pos += 2

    # SNI extension
    packet[pos : pos + 2] = b"\x00\x00"
    pos += 2
    packet[pos : pos + 2] = struct.pack(">H", sni_ext_len)
    pos += 2
    packet[pos : pos + 2] = struct.pack(">H", sni_list_len)
    pos += 2
    packet[pos] = 0
    pos += 1
    packet[pos : pos + 2] = struct.pack(">H", len(host))
    pos += 2
    packet[pos : pos + len(host)] = host
    pos += len(host)

    # supported_versions extension (TLS 1.3)
    packet[pos : pos + 2] = b"\x00\x2b"
    pos += 2
    packet[pos : pos + 2] = struct.pack(">H", supported_versions_ext_len)
    pos += 2
    packet[pos] = 2
    pos += 1
    packet[pos : pos + 2] = b"\x03\x04"
    pos += 2

    if pos != len(packet):
        raise RuntimeError("internal tls-auth packet builder length mismatch")

    mac_input = bytearray(packet)
    for i in range(random_pos, random_pos + 32):
        mac_input[i] = 0

    mac = bytearray(hmac.new(secret, mac_input, hashlib.sha256).digest())
    ts = int(time.time())
    ts_bytes = struct.pack("<I", ts)
    mac[28] ^= ts_bytes[0]
    mac[29] ^= ts_bytes[1]
    mac[30] ^= ts_bytes[2]
    mac[31] ^= ts_bytes[3]

    packet[random_pos : random_pos + 32] = mac
    return bytes(packet)


def build_realistic_client_hello(hostname: str) -> bytes:
    """Build a realistic TLS ClientHello with SNI using stdlib ssl."""

    client_sock, server_sock = socket.socketpair()
    try:
        client_sock.setblocking(False)
        server_sock.setblocking(False)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls_client = ctx.wrap_socket(
            client_sock,
            server_hostname=hostname,
            do_handshake_on_connect=False,
        )

        chunks: list[bytes] = []
        for _ in range(32):
            try:
                tls_client.do_handshake()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            except ssl.SSLError:
                break

            try:
                data = server_sock.recv(8192)
                if data:
                    chunks.append(data)
                    if len(b"".join(chunks)) >= 128:
                        break
            except BlockingIOError:
                pass

        payload = b"".join(chunks)
        if not payload:
            raise RuntimeError("failed to synthesize TLS ClientHello")
        return payload
    finally:
        try:
            server_sock.close()
        except OSError:
            pass
        try:
            client_sock.close()
        except OSError:
            pass


def maybe_send_payload(
    s: socket.socket,
    traffic_mode: str,
    secret_bytes: Optional[bytes],
    tls_domain: str,
) -> bool:
    if traffic_mode == "idle":
        return True
    if traffic_mode == "tls-auth":
        if not secret_bytes:
            return False
        payload = build_tls_auth_client_hello(secret_bytes, tls_domain)
        try:
            s.sendall(payload)
            return True
        except OSError:
            return False
    if traffic_mode == "tls-clienthello":
        payload = build_realistic_client_hello(tls_domain)
        try:
            s.sendall(payload)
            return True
        except OSError:
            return False
    if traffic_mode == "tls-auth-full":
        if not secret_bytes:
            return False
        payload = build_tls_auth_client_hello(secret_bytes, tls_domain)
        try:
            s.sendall(payload)
        except OSError:
            return False

        deadline = time.time() + 0.8
        got = b""
        while time.time() < deadline and len(got) < 16:
            timeout = max(0.0, deadline - time.time())
            r, _, _ = select.select([s], [], [], timeout)
            if not r:
                continue
            try:
                chunk = s.recv(4096)
            except OSError:
                return False
            if not chunk:
                break
            got += chunk

        if len(got) < 11:
            return False
        if not (got[0] == 0x16 and got[1] == 0x03 and got[2] == 0x03):
            return False

        rec1_len = struct.unpack(">H", got[3:5])[0]
        need = 5 + rec1_len + 6 + 5
        while len(got) < need and time.time() < deadline:
            timeout = max(0.0, deadline - time.time())
            r, _, _ = select.select([s], [], [], timeout)
            if not r:
                continue
            try:
                chunk = s.recv(4096)
            except OSError:
                return False
            if not chunk:
                break
            got += chunk

        if len(got) < need:
            return False

        ccs_start = 5 + rec1_len
        if got[ccs_start : ccs_start + 6] != b"\x14\x03\x03\x00\x01\x01":
            return False
        app_start = ccs_start + 6
        if got[app_start : app_start + 3] != b"\x17\x03\x03":
            return False
        return True
    return False


def should_expect_established(traffic_mode: str) -> bool:
    # Strict modes can trigger active masking/deny logic, where client-side
    # connect/send succeeds but server intentionally does not keep ESTABLISHED.
    return traffic_mode in ("idle", "tls-auth", "tls-auth-full")


def open_connections(
    port: int,
    target: int,
    connect_timeout_sec: float,
    open_budget_sec: float,
    fail_streak_limit: int,
    traffic_mode: str,
    secret_bytes: Optional[bytes],
    tls_domain: str,
) -> tuple[list[socket.socket], int, int, int]:
    sockets: list[socket.socket] = []
    failures = 0
    connect_ok = 0
    payload_ok = 0
    fail_streak = 0
    deadline = time.time() + open_budget_sec

    while len(sockets) < target and time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(connect_timeout_sec)
        rc = s.connect_ex(("127.0.0.1", port))
        if rc == 0:
            connect_ok += 1
            if maybe_send_payload(s, traffic_mode, secret_bytes, tls_domain):
                payload_ok += 1
                s.settimeout(None)
                sockets.append(s)
                fail_streak = 0
            else:
                failures += 1
                fail_streak += 1
                s.close()
        else:
            failures += 1
            fail_streak += 1
            s.close()
            if fail_streak >= fail_streak_limit:
                break

    return sockets, failures, connect_ok, payload_ok


def close_connections(connections: list[socket.socket]) -> None:
    for s in connections:
        try:
            s.close()
        except OSError:
            pass


def tune_nofile(target: int) -> None:
    if target <= 0:
        return
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    desired = target
    if hard != resource.RLIM_INFINITY:
        desired = min(desired, hard)
    desired = max(desired, soft)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (desired, hard))
    except (OSError, ValueError):
        pass


def tune_nproc(target: int) -> None:
    if target <= 0 or not hasattr(resource, "RLIMIT_NPROC"):
        return
    soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    desired = target
    if hard != resource.RLIM_INFINITY:
        desired = min(desired, hard)
    desired = max(desired, soft)
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (desired, hard))
    except (OSError, ValueError):
        pass


def maybe_apply_sysctl(args: argparse.Namespace) -> None:
    if not args.sysctl_tune:
        return
    cmds = [
        ["sysctl", "-w", "net.ipv4.ip_local_port_range=10000 65535"],
        ["sysctl", "-w", "net.ipv4.tcp_tw_reuse=1"],
    ]
    for cmd in cmds:
        try:
            subprocess.run(
                cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except (OSError, FileNotFoundError):
            pass


def run_profile(
    profile: Profile, args: argparse.Namespace, results_dir: Path
) -> dict[str, object]:
    cleanup_port(profile.port)
    kill_profile_processes(profile)
    cleanup_port(profile.port)

    if profile.prep == "set_low_pid":
        try:
            Path("/proc/sys/kernel/ns_last_pid").write_text("50000")
        except OSError:
            pass
    elif profile.prep == "mtproto_zig_autocap":
        # Keep max_connections comfortably above the highest probed level,
        # so the probe measures host/runtime limits rather than config cap.
        levels = profile.levels
        if args.levels:
            levels = [int(x) for x in args.levels.split(",") if x.strip()]
        max_target = max(levels) if levels else 0
        # Epoll build pre-allocates the slot pool by max_connections, so avoid
        # forcing a very high cap for low/medium target sweeps. Keep a small
        # headroom above requested levels to avoid clipping during burst opens.
        desired = max(512, max_target + 256)

        cfg_path = Path(profile.command[-1])
        try:
            cfg_text = cfg_path.read_text()
            next_text, replaced = re.subn(
                r"(?m)^\s*max_connections\s*=\s*\d+\s*$",
                f"max_connections = {desired}",
                cfg_text,
                count=1,
            )
            if replaced:
                cfg_path.write_text(next_text)
        except OSError:
            pass

    safe = profile.name.replace(" ", "_").replace(".", "_")
    log_path = results_dir / f"capacity_{safe}.log"

    with log_path.open("w") as log_file:
        process = subprocess.Popen(profile.command, stdout=log_file, stderr=log_file)

    startup_wait_total = args.startup_timeout_sec
    started, startup_state = wait_for_profile_listen(
        process, profile.port, args.startup_timeout_sec
    )
    if (not started) and startup_state != "exited" and args.startup_grace_sec > 0:
        startup_wait_total += args.startup_grace_sec
        started, startup_state = wait_for_profile_listen(
            process, profile.port, args.startup_grace_sec
        )

    if not started:
        rc = process.poll()
        err = "startup_exited" if startup_state == "exited" else "startup_timeout"
        if rc is None:
            kill_tree(process.pid)
            rc = -999
        kill_profile_processes(profile, exclude={process.pid})
        tail = read_log_tail(log_path)
        return {
            "name": profile.name,
            "ok": False,
            "error": err,
            "rc": rc,
            "startup_wait_sec": startup_wait_total,
            "log_tail": tail,
            "log": str(log_path),
            "command": profile.command,
        }

    time.sleep(1.0)
    root_pid = listener_pid(profile.port) or process.pid
    base_rss = tree_rss_kb(root_pid)

    levels = profile.levels
    if args.levels:
        levels = [int(x) for x in args.levels.split(",") if x.strip()]

    level_results: list[dict[str, object]] = []
    max_established = 0
    max_stable_target = 0
    secret_bytes = bytes.fromhex(profile.secret_hex) if profile.secret_hex else None

    if args.traffic_mode in ("tls-auth", "tls-auth-full") and not secret_bytes:
        kill_tree(root_pid)
        kill_tree(process.pid)
        cleanup_port(profile.port)
        return {
            "name": profile.name,
            "ok": False,
            "error": "missing_profile_secret",
            "log": str(log_path),
            "command": profile.command,
            "traffic_mode": args.traffic_mode,
        }

    for level in levels:
        connections, failures, connect_ok, payload_ok = open_connections(
            profile.port,
            level,
            args.connect_timeout_sec,
            args.open_budget_sec,
            args.fail_streak_limit,
            args.traffic_mode,
            secret_bytes,
            args.tls_domain,
        )
        time.sleep(args.hold_seconds)

        established = established_count(profile.port)
        rss_now = tree_rss_kb(root_pid)
        if should_expect_established(args.traffic_mode):
            stable = established >= int(level * args.stable_ratio)
        else:
            stable = payload_ok >= int(level * args.stable_ratio)

        if established > max_established:
            max_established = established
        if stable and level > max_stable_target:
            max_stable_target = level

        level_results.append(
            {
                "target": level,
                "connect_ok": connect_ok,
                "connected_client_side": len(connections),
                "payload_ok": payload_ok,
                "established_server_side": established,
                "failures": failures,
                "rss_kb": rss_now,
                "stable": stable,
            }
        )

        close_connections(connections)
        time.sleep(args.settle_seconds)

    kill_tree(root_pid)
    kill_tree(process.pid)
    kill_profile_processes(profile, exclude={process.pid, root_pid})
    cleanup_port(profile.port)

    return {
        "name": profile.name,
        "ok": True,
        "base_rss_kb": base_rss,
        "max_established_observed": max_established,
        "max_stable_target": max_stable_target,
        "levels": level_results,
        "log": str(log_path),
        "command": profile.command,
        "traffic_mode": args.traffic_mode,
    }


def select_profiles(all_profiles: list[Profile], selectors: list[str]) -> list[Profile]:
    if not selectors or "all" in {s.lower() for s in selectors}:
        return all_profiles

    selected: list[Profile] = []
    lowered = [s.lower() for s in selectors]
    for profile in all_profiles:
        name = profile.name.lower()
        if any(sel == name or sel in name for sel in lowered):
            selected.append(profile)
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description="Concurrent connection capacity probe")
    parser.add_argument(
        "--profile",
        action="append",
        default=[],
        help="Profile name (repeatable). Use 'all' for full run.",
    )
    parser.add_argument(
        "--list-profiles", action="store_true", help="Print profile names and exit"
    )
    parser.add_argument(
        "--bench-dir", default="/root/benchmarks", help="Benchmark workspace root"
    )
    parser.add_argument(
        "--results-dir",
        default="/root/benchmarks/results",
        help="Directory for logs/json",
    )
    parser.add_argument("--output", default="", help="Override output JSON path")
    parser.add_argument(
        "--levels",
        default="",
        help="Override levels for all selected profiles, e.g. 200,500,1000",
    )
    parser.add_argument(
        "--stable-ratio",
        type=float,
        default=0.98,
        help="Stable threshold: established >= target * ratio",
    )
    parser.add_argument("--startup-timeout-sec", type=float, default=45.0)
    parser.add_argument(
        "--startup-grace-sec",
        type=float,
        default=45.0,
        help="Extra listen wait after startup timeout before declaring failure",
    )
    parser.add_argument(
        "--traffic-mode",
        choices=["idle", "tls-auth", "tls-auth-full", "tls-clienthello"],
        default="idle",
        help="Connection traffic model: idle sockets, MTProto TLS-auth, full TLS-auth(+ServerHello verify), or realistic TLS ClientHello",
    )
    parser.add_argument(
        "--tls-domain",
        default="www.google.com",
        help="SNI host for tls-clienthello mode",
    )
    parser.add_argument("--connect-timeout-sec", type=float, default=0.08)
    parser.add_argument("--open-budget-sec", type=float, default=8.0)
    parser.add_argument("--hold-seconds", type=float, default=0.25)
    parser.add_argument("--settle-seconds", type=float, default=0.45)
    parser.add_argument("--fail-streak-limit", type=int, default=128)
    parser.add_argument(
        "--nofile",
        type=int,
        default=200000,
        help="Attempt to raise RLIMIT_NOFILE soft limit",
    )
    parser.add_argument(
        "--nproc",
        type=int,
        default=12000,
        help="Attempt to raise RLIMIT_NPROC soft limit",
    )
    parser.add_argument(
        "--sysctl-tune",
        action="store_true",
        help="Try best-effort sysctl tuning for local load generation",
    )
    args = parser.parse_args()

    profiles = build_profiles(Path(args.bench_dir))

    if args.list_profiles:
        for p in profiles:
            print(p.name)
        return 0

    selected = select_profiles(profiles, args.profile)
    if not selected:
        print("No matching profiles selected.")
        return 2

    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    tune_nofile(args.nofile)
    tune_nproc(args.nproc)
    maybe_apply_sysctl(args)

    all_results: list[dict[str, object]] = []
    for profile in selected:
        print(f"=== {profile.name} ===", flush=True)
        result = run_profile(profile, args, results_dir)
        all_results.append(result)
        print(json.dumps(result, ensure_ascii=False), flush=True)

    if args.output:
        output_path = Path(args.output)
    elif len(selected) == 1:
        safe_name = selected[0].name.lower().replace(" ", "_").replace(".", "_")
        output_path = results_dir / f"capacity_connections_{safe_name}.json"
    else:
        output_path = results_dir / "capacity_connections.json"

    output_path.write_text(json.dumps(all_results, indent=2, ensure_ascii=False))
    print(f"RESULT_FILE {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
