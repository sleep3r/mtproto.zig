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
import json
import os
import re
import resource
import signal
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Profile:
    name: str
    port: int
    command: list[str]
    levels: list[int]
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
            levels=[200, 500, 1000, 2000, 4000, 8000, 12000],
        ),
        Profile(
            name="Telemt",
            port=16546,
            command=[
                str(bin_dir / "telemt"),
                str(cfg_dir / "capacity-telemt.toml"),
            ],
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
            levels=[200, 500, 1000, 2000, 4000, 8000],
        ),
        Profile(
            name="mtproto_proxy",
            port=1443,
            command=["/opt/mtp_proxy/bin/mtp_proxy", "foreground"],
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
    try:
        out = subprocess.check_output(
            ["ss", "-ltnp"], text=True, stderr=subprocess.DEVNULL
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return None

    ids: list[int] = []
    needle = f":{port} "
    for line in out.splitlines():
        if needle not in line:
            continue
        ids.extend(int(m.group(1)) for m in re.finditer(r"pid=(\d+)", line))

    if not ids:
        return None
    return sorted(ids)[0]


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
    kill_tree(listener_pid(port))
    time.sleep(0.15)


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


def open_connections(
    port: int,
    target: int,
    connect_timeout_sec: float,
    open_budget_sec: float,
    fail_streak_limit: int,
) -> tuple[list[socket.socket], int]:
    sockets: list[socket.socket] = []
    failures = 0
    fail_streak = 0
    deadline = time.time() + open_budget_sec

    while len(sockets) < target and time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(connect_timeout_sec)
        rc = s.connect_ex(("127.0.0.1", port))
        if rc == 0:
            s.settimeout(None)
            sockets.append(s)
            fail_streak = 0
        else:
            failures += 1
            fail_streak += 1
            s.close()
            if fail_streak >= fail_streak_limit:
                break

    return sockets, failures


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
        desired = max(65535, max_target + 1024)

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

    if not wait_for_listen(profile.port, args.startup_timeout_sec):
        rc = process.poll()
        if rc is None:
            kill_tree(process.pid)
            rc = -999
        return {
            "name": profile.name,
            "ok": False,
            "error": "startup_failed",
            "rc": rc,
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
    for level in levels:
        connections, failures = open_connections(
            profile.port,
            level,
            args.connect_timeout_sec,
            args.open_budget_sec,
            args.fail_streak_limit,
        )
        time.sleep(args.hold_seconds)

        established = established_count(profile.port)
        rss_now = tree_rss_kb(root_pid)
        stable = established >= int(level * args.stable_ratio)

        if established > max_established:
            max_established = established
        if stable and level > max_stable_target:
            max_stable_target = level

        level_results.append(
            {
                "target": level,
                "connected_client_side": len(connections),
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
