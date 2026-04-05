---
description: Operational diagnostics workflow for the current epoll-based proxy.
---

# Diagnostics Workflow

Use this workflow to diagnose runtime issues quickly on a deployed Linux host.

## 1) Service Health

```bash
ssh root@<SERVER_IP> 'systemctl status mtproto-proxy --no-pager'
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "30 minutes ago" --no-pager'
```

## 2) Socket and Process Snapshot

```bash
ssh root@<SERVER_IP> 'ss -tnp | grep mtproto || true'
ssh root@<SERVER_IP> 'ps -o pid,pcpu,pmem,nlwp,rss,vsz,args -p $(pgrep -f mtproto-proxy)'
ssh root@<SERVER_IP> 'cat /proc/$(pgrep -f mtproto-proxy)/status | grep -E "Threads|State|VmRSS|VmSize"'
```

## 3) Capacity / Memory Validation

```bash
ssh root@<SERVER_IP> 'python3 /root/benchmarks/capacity_connections_probe.py --profile mtproto.zig --traffic-mode tls-auth --tls-domain google.com --levels 500,1000,1500,2000 --open-budget-sec 14 --hold-seconds 0.8 --settle-seconds 1.0 --connect-timeout-sec 0.1 --nofile 200000 --nproc 12000'
```

For strict handshake response sanity:

```bash
ssh root@<SERVER_IP> 'python3 /root/benchmarks/capacity_connections_probe.py --profile mtproto.zig --traffic-mode tls-auth-full --tls-domain google.com --levels 100,200 --open-budget-sec 8 --hold-seconds 0.5 --settle-seconds 0.8 --connect-timeout-sec 0.1 --nofile 200000 --nproc 12000'
```

## 4) Stability Harness

```bash
ssh root@<SERVER_IP> 'python3 /root/benchmarks/connection_stability_check.py --host 127.0.0.1 --port 443 --pid $(pgrep -f mtproto-proxy | head -n1) --idle-connections 6000 --idle-cycles 3 --churn-total 30000 --churn-concurrency 300'
```

## 5) Useful Failure Signatures

- Frequent `startup_failed` in benchmark output: binary/config/runtime mismatch.
- `payload_ok` high but `established_server_side` low in strict modes: expected in masking/deny scenarios, verify traffic-mode semantics.
- Repeating `epoll hup/err` close reasons with low throughput: investigate peer behavior and kernel socket limits.
