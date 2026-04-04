# Test Utilities

## Capacity Probe

`capacity_connections_probe.py` estimates how many concurrent TCP sessions each implementation can hold on one host.

### What it measures

- held concurrent sockets (`ESTABLISHED` on server side)
- process-tree RSS while those sockets are held

This is a **capacity snapshot**, not full real-user throughput under Telegram traffic mix.

### Prerequisites

- Linux host with `ss` command (`iproute2`)
- Python 3.10+
- benchmark workspace prepared under `/root/benchmarks` (default)

### Typical usage

```bash
# list available profiles
python3 test/capacity_connections_probe.py --list-profiles

# full sweep with best-effort local tuning
sudo -E python3 test/capacity_connections_probe.py --profile all --sysctl-tune

# single implementation
sudo -E python3 test/capacity_connections_probe.py --profile mtproto.zig

# custom levels / budget / nofile
sudo -E python3 test/capacity_connections_probe.py \
  --profile mtproto.zig \
  --levels 500,1000,2000,4000,8000 \
  --open-budget-sec 12 \
  --nofile 300000 \
  --nproc 12000
```

### Recommended mtproto.zig profiles

```bash
# "safe" profile for this VPS
sudo -E python3 test/capacity_connections_probe.py \
  --profile mtproto.zig \
  --levels 2000,3000,3500,4000,4500 \
  --open-budget-sec 16 \
  --hold-seconds 0.8 \
  --settle-seconds 1.0 \
  --connect-timeout-sec 0.1 \
  --nofile 200000 \
  --nproc 12000

# "stress" profile (checks post-4.5k behavior)
sudo -E python3 test/capacity_connections_probe.py \
  --profile mtproto.zig \
  --levels 4000,4500,5000,5500,6000 \
  --open-budget-sec 18 \
  --hold-seconds 0.8 \
  --settle-seconds 1.0 \
  --connect-timeout-sec 0.1 \
  --nofile 250000 \
  --nproc 12000

# high-capacity profile (host/perf ceiling discovery)
sudo -E python3 test/capacity_connections_probe.py \
  --profile mtproto.zig \
  --levels 6000,8000,10000,12000 \
  --open-budget-sec 24 \
  --hold-seconds 0.8 \
  --settle-seconds 1.0 \
  --connect-timeout-sec 0.1 \
  --nofile 300000 \
  --nproc 20000
```

For `mtproto.zig`, the probe now auto-raises `max_connections` in the benchmark config
above the requested `--levels`, so results reflect runtime/host capacity instead of
being clipped by config.

### Output

By default, JSON is written to `/root/benchmarks/results/`:

- multi-profile: `capacity_connections.json`
- single-profile: `capacity_connections_<profile>.json`

Each profile result includes:

- `max_established_observed`
- `max_stable_target` (stable when `established >= target * stable_ratio`)
- per-level `rss_kb`, client-side successes, failures

### Current snapshot (`38.180.236.207`, 1 vCPU / 1 GB)

| Proxy | Max observed ESTABLISHED | Max fully stable target* | RSS at peak target |
|-------|---------------------------|---------------------------|--------------------|
| **mtproto.zig** | 2,000 | 2,000 | 31.5 MB |
| Official MTProxy | 12,000 | 12,000 | 72.4 MB |
| Teleproxy | 12,000 | 12,000 | 76.1 MB |
| Telemt | 8,000 | 8,000 | 50.7 MB |
| mtg | 8,172 | 4,000 | 124.0 MB |
| mtprotoproxy | 8,000 | 8,000 | 92.0 MB |
| mtproto_proxy | 2,000 | 2,000 | 138.7 MB |

### Tuned mtproto.zig snapshot (same VPS)

Applied runtime config:

```toml
[server]
max_connections = 4500
thread_stack_kb = 128
idle_timeout_sec = 300
handshake_timeout_sec = 30
backlog = 8192
```

Probe result (`--levels 2000,3000,3500,4000,4500,5000`):

- `max_established_observed`: **4517**
- `max_stable_target`: **4500**
- RSS at stable 4500 target: **72.5 MB**
- at target 5000: accepted on client side, but only ~4517 reached `ESTABLISHED`

### Updated tuned snapshot (same VPS, stable baseline)

With stack-safe runtime changes and capacity probe auto-lifting `max_connections`:

- levels `2000..5000`: stable through **5000** (`5000/5000` established)
- levels `6000,7000,8000`: stable through **8000**
- levels `9000,10000,11000,12000`: stable through **12000**
- upper sweep `13000,14000` (with explicit high cap):
  - **13000 stable**
  - **14000 unstable** (about `7371` established)

So current practical ceiling on this host/profile is around **13k concurrent held sockets**.

\* "Fully stable target" means `established_server_side == target` at that level.

### Notes for tuning mtproto.zig

Primary bottlenecks on this VPS are config cap (`max_connections`) first, then host thread/process budget and memory pressure.
To push higher safely:

- host limits (`ulimit -u`, cgroup `pids.max`)
- `[server].thread_stack_kb`
- `[server].max_connections`
- probe launcher `--nofile`, `--nproc`, and optional `--sysctl-tune`
