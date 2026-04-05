# Bench & Validation Guide

This folder contains practical tools to validate **capacity**, **stability**, and **memory behavior** of `mtproto.zig` and reference implementations.

## Tools

- `capacity_connections_probe.py` — concurrent connection sweeps with RSS tracking.
- `connection_stability_check.py` — churn + idle-pool stability harness (leak/regression detector).

## What We Measure

The capacity probe reports, per target level:

- `connect_ok` — successful TCP connect attempts from the probe client.
- `payload_ok` — successful payload submission for selected traffic mode.
- `established_server_side` — server-side held `ESTABLISHED` sockets.
- `rss_kb` — process-tree RSS (listener process + children).
- `stable` — level considered stable per probe criteria.

This is a capacity/memory harness, not an end-user Telegram UX benchmark.

## Traffic Modes

- `idle`
  - Connect and hold sockets without payload.
  - Best for FD/socket ceilings and idle memory.
- `tls-auth`
  - Sends MTProto TLS-auth ClientHello with valid SNI and digest layout.
  - Best for apples-to-apples active auth memory comparison.
- `tls-auth-full`
  - Same as `tls-auth`, plus checks proxy response framing (`ServerHello + CCS + AppData` header sequence).
  - Best for strict handshake sanity smoke checks.
- `tls-clienthello`
  - Sends realistic TLS ClientHello synthesized via Python `ssl` with SNI.
  - Useful for strict parser/masking behavior checks.

## Environment

- Linux host with `/proc` and `ss` (`iproute2`).
- Python 3.10+.
- Benchmark workspace ready under `/root/benchmarks` (default layout).

## Quick Start

```bash
# Show available profiles
python3 test/capacity_connections_probe.py --list-profiles

# Single profile, default mode (idle)
sudo -E python3 test/capacity_connections_probe.py --profile mtproto.zig

# Full matrix run
sudo -E python3 test/capacity_connections_probe.py --profile all --sysctl-tune
```

## Recommended Runs

### 1) Final cross-proxy TLS-auth comparison

```bash
sudo -E python3 test/capacity_connections_probe.py \
  --profile all \
  --traffic-mode tls-auth \
  --tls-domain google.com \
  --levels 500,1000,1500,2000 \
  --open-budget-sec 14 \
  --hold-seconds 0.8 \
  --settle-seconds 1.0 \
  --connect-timeout-sec 0.1 \
  --nofile 200000 \
  --nproc 12000 \
  --output /root/benchmarks/results/capacity_connections_tls_auth.final_all.json
```

### 2) Final cross-proxy idle comparison

```bash
sudo -E python3 test/capacity_connections_probe.py \
  --profile all \
  --traffic-mode idle \
  --levels 4000,8000,12000 \
  --open-budget-sec 24 \
  --hold-seconds 0.8 \
  --settle-seconds 1.0 \
  --connect-timeout-sec 0.1 \
  --nofile 300000 \
  --nproc 20000 \
  --output /root/benchmarks/results/capacity_connections_idle.final_all.json
```

### 3) Strict handshake smoke (`tls-auth-full`)

```bash
sudo -E python3 test/capacity_connections_probe.py \
  --profile mtproto.zig \
  --traffic-mode tls-auth-full \
  --tls-domain google.com \
  --levels 100,200 \
  --open-budget-sec 8 \
  --hold-seconds 0.5 \
  --settle-seconds 0.8 \
  --connect-timeout-sec 0.1 \
  --nofile 200000 \
  --nproc 12000 \
  --output /root/benchmarks/results/capacity_connections_mtproto_zig.tls_auth_full_smoke_v2.json
```

## Final Snapshot (Current)

Host: (1 vCPU / 1 GB RAM)

Notes:

- Startup failures are now classified as `startup_exited` vs `startup_timeout` and include `log_tail` for root-cause visibility.

### TLS-auth @ 2000

| Proxy | RSS (KB) | Established | Stable |
|---|---:|---:|---|
| **mtproto.zig** | **8,832** | **2,000** | ✅ |
| Official MTProxy | 23,296 | 2,000 | ✅ |
| Teleproxy | 20,952 | 2,000 | ✅ |
| Telemt | 38,272 | 2,000 | ✅ |
| mtg | 55,296 | 0 | ⚠ partial (payload_ok=2000, established=0) |
| mtprotoproxy | 50,944 | 2,000 | ✅ |
| mtproto_proxy | startup_exited | - | - |

`mtproto.zig` vs historical baseline (`84,544 KB`): **-89.55% RSS** at 2000.

### Idle @ 12000

| Proxy | RSS (KB) | Established | Stable |
|---|---:|---:|---|
| **mtproto.zig** | **49,024** | **12,000** | ✅ |
| Telemt | 70,032 | 11,023 | ⚠ partial @12000 (stable up to 8000) |
| Official MTProxy | 74,116 | 12,000 | ✅ |
| Teleproxy | 77,864 | 12,000 | ✅ |
| mtg | 97,792 | 7,287 | ⚠ partial @12000 (stable up to 4000) |
| mtprotoproxy | 123,724 | 12,000 | ✅ |
| mtproto_proxy | 396,328 | 12,000 | ✅ (idle-only; TLS-auth startup_exited) |

## Interpreting Results Correctly

- Compare proxies at the **same target level**.
- Prefer **total RSS at level** over only delta-per-conn.
- Watch both `payload_ok` and `established_server_side`.
- For strict parser checks, use `tls-auth-full` or `tls-clienthello`.

## Stability Harness

`connection_stability_check.py` is useful for leak-like regressions after churn and idle pressure.

Example:

```bash
python3 test/connection_stability_check.py \
  --host 127.0.0.1 --port 443 --pid <proxy_pid> \
  --idle-connections 6000 --idle-cycles 3 \
  --churn-total 30000 --churn-concurrency 300
```

## Practical Tuning Notes

Primary bottlenecks typically are:

1. `max_connections` runtime cap.
2. Host FD limits (`ulimit -n`, systemd `LimitNOFILE`).
3. Available RAM.

When pushing higher levels, tune config and probe limits together.
