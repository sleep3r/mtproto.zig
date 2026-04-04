# Test Utilities

This directory contains lightweight tools used for local and remote validation.

- `capacity_connections_probe.py`: concurrent connection capacity sweeps
- `connection_stability_check.py`: long-running stability harness

## Capacity Probe

`capacity_connections_probe.py` estimates how many concurrent TCP sessions each implementation can hold on one host.

### What it measures

- server-side held sockets (`ESTABLISHED`)
- process-tree memory (`RSS`) while sockets are held

This is a capacity snapshot, not a full Telegram real-user throughput benchmark.

## Environment

- Linux host with `ss` (`iproute2`)
- Python 3.10+
- benchmark workspace prepared under `/root/benchmarks` (default)

## Quick Start

```bash
# list profiles
python3 test/capacity_connections_probe.py --list-profiles

# run one profile with defaults
sudo -E python3 test/capacity_connections_probe.py --profile mtproto.zig

# full sweep for all configured profiles
sudo -E python3 test/capacity_connections_probe.py --profile all --sysctl-tune
```

## Recommended mtproto.zig runs

```bash
# baseline profile (safe, production-like)
sudo -E python3 test/capacity_connections_probe.py \
  --profile mtproto.zig \
  --levels 2000,3000,3500,4000,4500,5000 \
  --open-budget-sec 16 \
  --hold-seconds 0.8 \
  --settle-seconds 1.0 \
  --connect-timeout-sec 0.1 \
  --nofile 200000 \
  --nproc 12000

# high-capacity profile (find host ceiling)
sudo -E python3 test/capacity_connections_probe.py \
  --profile mtproto.zig \
  --levels 6000,8000,10000,12000 \
  --open-budget-sec 24 \
  --hold-seconds 0.8 \
  --settle-seconds 1.0 \
  --connect-timeout-sec 0.1 \
  --nofile 300000 \
  --nproc 20000

# explicit ceiling probe
sudo -E python3 test/capacity_connections_probe.py \
  --profile mtproto.zig \
  --levels 13000,14000 \
  --open-budget-sec 26 \
  --hold-seconds 0.8 \
  --settle-seconds 1.0 \
  --connect-timeout-sec 0.1 \
  --nofile 350000 \
  --nproc 20000
```

For `mtproto.zig`, the probe auto-raises `max_connections` in benchmark config above requested `--levels`.
This prevents config clipping and reflects runtime and host limits.

## Output

Default output directory: `/root/benchmarks/results/`

- single profile: `capacity_connections_<profile>.json`
- multi profile: `capacity_connections.json`

Each result includes:

- `max_established_observed`
- `max_stable_target` (`established >= target * stable_ratio`)
- per-level `connected_client_side`, `established_server_side`, `rss_kb`, `failures`

## Latest Snapshot (2026-04-04)

Host: `38.180.236.207` (1 vCPU / 1 GB RAM)

### Cross-proxy snapshot (baseline run)

| Proxy | Max observed ESTABLISHED | Max fully stable target* | RSS at peak target |
|-------|---------------------------|---------------------------|--------------------|
| **mtproto.zig** | 12,000 | 12,000 | 144.3 MB |
| Official MTProxy | 12,000 | 12,000 | 72.4 MB |
| Teleproxy | 12,000 | 12,000 | 76.1 MB |
| Telemt | 8,000 | 8,000 | 50.7 MB |
| mtg | 8,172 | 4,000 | 124.0 MB |
| mtprotoproxy | 8,000 | 8,000 | 92.0 MB |
| mtproto_proxy | 2,000 | 2,000 | 138.7 MB |

### mtproto.zig tuned snapshot (latest)

Baseline sweep (`2000..5000`) shows:

- stable through `5000/5000`
- no connection failures in probe client
- memory scales near-linearly with held sockets

### High-capacity sweeps

- `6000,8000,10000,12000`: all stable (`12000/12000`)
- `13000,14000`: `13000` stable, `14000` unstable (`~7371` established)

Practical ceiling on this host/profile: about 13k held sockets.

### Memory growth (mtproto.zig)

| Held sockets | RSS |
|--------------|-----|
| 5000 | 60.6 MB |
| 8000 | 96.5 MB |
| 10000 | 120.5 MB |
| 12000 | 144.3 MB |

Observed slope is roughly +12 MB per additional 1000 held sockets on this VPS.

\* "Fully stable target" means `established_server_side == target` at that level.

## Tuning Notes

Primary bottlenecks are, in order:

1. config cap (`max_connections`)
2. host process/thread limits (`ulimit -u`, cgroup `pids.max`)
3. available memory

When pushing higher, tune these together:

- `[server].max_connections`
- `[server].thread_stack_kb`
- probe flags `--nofile` and `--nproc`
