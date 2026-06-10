#!/usr/bin/env python3
"""
Connection stability harness: connection churn + idle pool pressure.

Designed for Linux VPS where mtproto-proxy is already running.
It fails when memory/threads/fds do not recover after
idle-connection pressure (leak-like behavior).
"""

from __future__ import annotations

import argparse
import errno
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class ProcStats:
    rss_kb: Optional[int]
    vms_kb: Optional[int]
    threads: Optional[int]
    fds: Optional[int]


def read_proc_stats(pid: int) -> ProcStats:
    status_path = f"/proc/{pid}/status"
    fd_path = f"/proc/{pid}/fd"

    rss_kb = None
    vms_kb = None
    threads = None
    fds = None

    try:
        with open(status_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss_kb = int(line.split()[1])
                elif line.startswith("VmSize:"):
                    vms_kb = int(line.split()[1])
                elif line.startswith("Threads:"):
                    threads = int(line.split()[1])
    except (FileNotFoundError, OSError):
        pass

    try:
        fds = len(os.listdir(fd_path))
    except (FileNotFoundError, OSError):
        pass

    return ProcStats(rss_kb=rss_kb, vms_kb=vms_kb, threads=threads, fds=fds)


def tcp_states(port: int) -> Dict[str, int]:
    try:
        out = subprocess.check_output(["ss", "-tan"], text=True)
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return {}

    want = str(port)
    states: Dict[str, int] = {}

    def port_of(addr: str) -> str:
        # ss prints addr:port; IPv6 is [::1]:443. rsplit on the last ':' gives the port.
        return addr.rsplit(":", 1)[-1]

    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("State"):
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        state, local_addr, peer_addr = parts[0], parts[3], parts[4]
        # Exact port match, not substring: `:443` must not also count :4433/:44310 etc.
        # (unrelated services on a shared VPS), which would skew the CLOSE-WAIT assertions.
        if port_of(local_addr) == want or port_of(peer_addr) == want:
            states[state] = states.get(state, 0) + 1

    return states


def print_snapshot(label: str, pid: Optional[int], port: int) -> Dict[str, object]:
    stats = (
        read_proc_stats(pid) if pid is not None else ProcStats(None, None, None, None)
    )
    states = tcp_states(port)
    print(
        f"[{label}] rss_kb={stats.rss_kb} vms_kb={stats.vms_kb} "
        f"threads={stats.threads} fds={stats.fds} states={states}"
    )
    return {
        "stats": stats,
        "states": states,
    }


def has_stats(stats: ProcStats) -> bool:
    return any(
        v is not None for v in (stats.rss_kb, stats.vms_kb, stats.threads, stats.fds)
    )


def open_idle_connections(
    host: str, port: int, count: int, timeout: float
) -> tuple[list[socket.socket], int]:
    conns: list[socket.socket] = []
    failed = 0

    for i in range(count):
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            conns.append(s)
        except OSError as err:
            failed += 1
            if err.errno == errno.EMFILE:
                failed += count - i - 1
                break

    return conns, failed


def close_connections(conns: list[socket.socket]) -> None:
    for s in conns:
        try:
            s.close()
        except OSError:
            pass


def run_churn(
    host: str,
    port: int,
    total: int,
    concurrency: int,
    timeout: float,
    payload: bytes,
) -> tuple[int, int, float]:
    idx = 0
    lock = threading.Lock()
    ok = 0
    fail = 0
    ok_fail_lock = threading.Lock()

    def worker() -> None:
        nonlocal idx, ok, fail

        while True:
            with lock:
                if idx >= total:
                    return
                idx += 1

            try:
                s = socket.create_connection((host, port), timeout=timeout)
                if payload:
                    s.sendall(payload)
                    s.settimeout(0.3)
                    try:
                        _ = s.recv(128)
                    except OSError:
                        pass
                s.close()
                with ok_fail_lock:
                    ok += 1
            except OSError:
                with ok_fail_lock:
                    fail += 1

    threads = [
        threading.Thread(target=worker, daemon=True) for _ in range(max(1, concurrency))
    ]
    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - start
    return ok, fail, elapsed


def assert_threshold(
    name: str,
    value: Optional[int],
    baseline: Optional[int],
    delta_limit: int,
    failures: list[str],
) -> None:
    if value is None or baseline is None:
        return
    if value > baseline + delta_limit:
        failures.append(
            f"{name} too high after settle: baseline={baseline}, now={value}, limit={baseline + delta_limit}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Connection memory/socket stability harness"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument(
        "--pid", type=int, default=None, help="mtproto-proxy PID for /proc monitoring"
    )

    parser.add_argument("--idle-connections", type=int, default=6000)
    parser.add_argument("--idle-cycles", type=int, default=3)
    parser.add_argument("--idle-hold-seconds", type=int, default=30)
    parser.add_argument("--idle-settle-seconds", type=int, default=8)
    parser.add_argument("--connect-timeout", type=float, default=1.0)

    parser.add_argument("--churn-total", type=int, default=30000)
    parser.add_argument("--churn-concurrency", type=int, default=300)

    parser.add_argument("--rss-delta-mb", type=int, default=48)
    parser.add_argument("--threads-delta", type=int, default=64)
    parser.add_argument("--fds-delta", type=int, default=128)
    parser.add_argument("--close-wait-limit", type=int, default=128)

    args = parser.parse_args()

    if args.pid is not None and not os.path.exists(f"/proc/{args.pid}"):
        print(f"error: /proc/{args.pid} not found. pass a valid proxy PID")
        return 2

    if args.idle_connections <= 0 or args.churn_total <= 0:
        print("error: idle-connections and churn-total must be > 0")
        return 2

    print("== stability check start ==")
    print(
        f"target={args.host}:{args.port} pid={args.pid} "
        f"idle={args.idle_connections}x{args.idle_cycles} hold={args.idle_hold_seconds}s "
        f"churn={args.churn_total}x{args.churn_concurrency}"
    )

    baseline = print_snapshot("baseline", args.pid, args.port)

    idle_closes: list[Dict[str, object]] = []
    stats_skipped_cycles = 0
    for cycle in range(1, args.idle_cycles + 1):
        conns, failed_open = open_idle_connections(
            args.host,
            args.port,
            args.idle_connections,
            args.connect_timeout,
        )
        print(f"idle_open[{cycle}]: opened={len(conns)} failed={failed_open}")
        open_snap = print_snapshot(f"idle_open_{cycle}", args.pid, args.port)
        if args.pid is not None and not has_stats(open_snap["stats"]):  # type: ignore[arg-type]
            stats_skipped_cycles += 1

        time.sleep(max(0, args.idle_hold_seconds))
        hold_snap = print_snapshot(f"idle_hold_done_{cycle}", args.pid, args.port)
        if args.pid is not None and not has_stats(hold_snap["stats"]):  # type: ignore[arg-type]
            stats_skipped_cycles += 1

        close_connections(conns)
        print(f"idle_close[{cycle}]: closed all sockets")
        time.sleep(max(0, args.idle_settle_seconds))
        close_snap = print_snapshot(f"after_idle_close_{cycle}", args.pid, args.port)
        if args.pid is not None and not has_stats(close_snap["stats"]):  # type: ignore[arg-type]
            stats_skipped_cycles += 1
        idle_closes.append(close_snap)

    after_idle_close = idle_closes[-1]

    payload = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n"
    ok, fail, elapsed = run_churn(
        args.host,
        args.port,
        args.churn_total,
        args.churn_concurrency,
        args.connect_timeout,
        payload,
    )
    print(f"churn_done: ok={ok} fail={fail} elapsed={elapsed:.2f}s")

    time.sleep(2)
    after_churn = print_snapshot("after_churn", args.pid, args.port)
    if args.pid is not None and not has_stats(after_churn["stats"]):  # type: ignore[arg-type]
        stats_skipped_cycles += 1

    if args.pid is None:
        print("PASS (load-only mode, no PID assertions)")
        return 0

    failures: list[str] = []

    # Hard fail if the proxy died at any point: a crashed PID makes every /proc read return
    # None, so all threshold asserts early-return and the script would otherwise print PASS
    # for a wedged/crashed proxy.
    if not os.path.exists(f"/proc/{args.pid}"):
        failures.append(
            f"proxy PID {args.pid} no longer exists — it crashed or exited during the run"
        )

    # Churn results were previously never asserted (ok=0/fail=N still PASSed). Require the
    # bulk of churn connections to have succeeded.
    min_ok = int(args.churn_total * 0.95)
    if ok < min_ok:
        failures.append(
            f"churn success ratio too low: ok={ok}/{args.churn_total} (min {min_ok}, fail={fail})"
        )

    base_stats: ProcStats = baseline["stats"]  # type: ignore[assignment]
    idle_close_stats: ProcStats = after_idle_close["stats"]  # type: ignore[assignment]
    churn_stats: ProcStats = after_churn["stats"]  # type: ignore[assignment]

    rss_delta_kb = args.rss_delta_mb * 1024
    assert_threshold(
        "rss_kb", idle_close_stats.rss_kb, base_stats.rss_kb, rss_delta_kb, failures
    )
    assert_threshold(
        "threads",
        idle_close_stats.threads,
        base_stats.threads,
        args.threads_delta,
        failures,
    )
    assert_threshold(
        "fds", idle_close_stats.fds, base_stats.fds, args.fds_delta, failures
    )

    assert_threshold(
        "rss_kb(churn)", churn_stats.rss_kb, base_stats.rss_kb, rss_delta_kb, failures
    )
    assert_threshold(
        "threads(churn)",
        churn_stats.threads,
        base_stats.threads,
        args.threads_delta,
        failures,
    )
    assert_threshold(
        "fds(churn)", churn_stats.fds, base_stats.fds, args.fds_delta, failures
    )

    idle_close_states: Dict[str, int] = after_idle_close["states"]  # type: ignore[assignment]
    churn_states: Dict[str, int] = after_churn["states"]  # type: ignore[assignment]

    for i, snap in enumerate(idle_closes, start=1):
        snap_stats: ProcStats = snap["stats"]  # type: ignore[assignment]
        assert_threshold(
            f"rss_kb(cycle{i})",
            snap_stats.rss_kb,
            base_stats.rss_kb,
            rss_delta_kb,
            failures,
        )
        assert_threshold(
            f"threads(cycle{i})",
            snap_stats.threads,
            base_stats.threads,
            args.threads_delta,
            failures,
        )
        assert_threshold(
            f"fds(cycle{i})", snap_stats.fds, base_stats.fds, args.fds_delta, failures
        )

        snap_states: Dict[str, int] = snap["states"]  # type: ignore[assignment]
        close_wait_cycle = snap_states.get("CLOSE-WAIT", 0)
        if close_wait_cycle > args.close_wait_limit:
            failures.append(
                f"CLOSE-WAIT too high after idle cycle {i}: {close_wait_cycle} > {args.close_wait_limit}"
            )

    close_wait_idle = idle_close_states.get("CLOSE-WAIT", 0)
    close_wait_churn = churn_states.get("CLOSE-WAIT", 0)
    if close_wait_idle > args.close_wait_limit:
        failures.append(
            f"CLOSE-WAIT too high after idle settle: {close_wait_idle} > {args.close_wait_limit}"
        )
    if close_wait_churn > args.close_wait_limit:
        failures.append(
            f"CLOSE-WAIT too high after churn settle: {close_wait_churn} > {args.close_wait_limit}"
        )

    if stats_skipped_cycles > 0:
        print(
            "WARN: snapshot stats were unavailable during high-fd pressure "
            f"({stats_skipped_cycles} points). Increase launcher nofile for cleaner metrics."
        )

    if failures:
        print("FAIL")
        for item in failures:
            print(f" - {item}")
        return 1

    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
