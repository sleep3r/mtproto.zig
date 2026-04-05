---
description: Useful commands for diagnosing proxy anomalies or connection issues.
---

# Proxy Diagnostics Workflow

Use these checks on the deployed VPS to inspect service health, routing, and fallback behavior.

## Service and Process Health

```bash
# Service status
ssh root@<SERVER_IP> 'systemctl status mtproto-proxy --no-pager'

# Active sockets
ssh root@<SERVER_IP> 'ss -tnp | grep mtproto'

# Process footprint
ssh root@<SERVER_IP> 'ps -o pid,pcpu,pmem,nlwp,rss,vsz,args -p $(pgrep -f mtproto-proxy)'
```

## Log Checks (current message patterns)

```bash
# Recent logs
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager'

# Connect-path and fallback signals
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager | grep -E "middle-proxy exhausted|middle-proxy handshake failed|media path connect failed|epoll hup/err"'

# Timeout signals from event-loop timers
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager | grep -E "idle pre-first-byte timeout|handshake timeout|relay idle timeout"'

# MiddleProxy metadata refresh state
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "24 hours ago" --no-pager | grep -E "Middle-proxy cache updated|Initial middle-proxy refresh failed|Middle-proxy refresh failed"'
```

Note:

- Older grep patterns like `DIAG: Short read`, `DC4 MiddleProxy timeout`, `DC203 MiddleProxy timeout` are legacy and not emitted by current code.

## IPv6 Hopping and DNS

```bash
# Last hop log lines
ssh root@<SERVER_IP> 'tail -20 /var/log/mtproto-ipv6-hop.log'

# Current active IPv6
ssh root@<SERVER_IP> 'cat /tmp/mtproto-ipv6-current'

# Cron wiring
ssh root@<SERVER_IP> 'cat /etc/cron.d/mtproto-ipv6'
```

## Low-level Network Checks

```bash
# CLOSE-WAIT sockets
ssh root@<SERVER_IP> 'ss -tnp state close-wait | grep mtproto'

# Process state summary
ssh root@<SERVER_IP> 'cat /proc/$(pgrep -f mtproto-proxy)/status | grep -E "Threads|State"'

# TCPMSS clamp rule
ssh root@<SERVER_IP> 'iptables -t mangle -L OUTPUT -n -v | grep TCPMSS'
```

## Capacity and Stability

```bash
# Startup banner with RAM/capacity estimate
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy -n 80 --no-pager'

# Idle capacity probe
ssh root@<SERVER_IP> 'sudo python3 /opt/mtproto-proxy/test/capacity_connections_probe.py --profile mtproto.zig --traffic-mode idle'

# Active (TLS-auth) capacity probe
ssh root@<SERVER_IP> 'sudo python3 /opt/mtproto-proxy/test/capacity_connections_probe.py --profile mtproto.zig --traffic-mode tls-auth --tls-domain google.com --levels 500,1000,1500,2000 --open-budget-sec 14 --hold-seconds 0.8 --settle-seconds 1.0 --connect-timeout-sec 0.1 --nofile 200000 --nproc 12000'

# Stability harness
ssh root@<SERVER_IP> 'sudo python3 /opt/mtproto-proxy/test/connection_stability_check.py --host 127.0.0.1 --port 443 --pid $(pgrep -f mtproto-proxy | head -n1) --idle-connections 6000 --idle-cycles 3 --churn-total 30000 --churn-concurrency 300'
```

