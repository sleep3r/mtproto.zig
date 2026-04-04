---
description: Useful commands for diagnosing proxy anomalies or connection issues
---

# Proxy Diagnostics Workflow

Use these diagnostic commands to investigate service statuses, monitor logs, and analyze process health on the VPS where the proxy is deployed.

## Service & Process Monitoring

```bash
# Check service status
ssh root@<SERVER_IP> 'systemctl status mtproto-proxy --no-pager'

# Check active connections (IPv4 + IPv6)
ssh root@<SERVER_IP> 'ss -tnp | grep mtproto'

# Check process stats (CPU, threads, memory)
ssh root@<SERVER_IP> 'ps -o pid,pcpu,pmem,nlwp,rss,vsz,args -p $(pgrep -f mtproto-proxy)'
```

## Log Analysis

```bash
# Check recent logs
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager'

# Check for Replay attacks detected (ТСПУ Revisor)
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --no-pager | grep "Replay attack"'

# Check IPv6 hopping log
ssh root@<SERVER_IP> 'cat /var/log/mtproto-ipv6-hop.log | tail -20'

# Check current active IPv6
ssh root@<SERVER_IP> 'cat /tmp/mtproto-ipv6-current'

# Check short-read diagnostics (fragmented ClientHello / partial reads)
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager | grep "DIAG: Short read"'

# Check MiddleProxy route instability for media/non-media
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager | grep -E "MiddleProxy connect|DC4 MiddleProxy timeout|DC203 MiddleProxy timeout"'
```

## IPv6 Hopping Scripts

```bash
# Manual hop to new IPv6 address
ssh root@<SERVER_IP> '/opt/mtproto-proxy/ipv6-hop.sh'

# Check hop status
ssh root@<SERVER_IP> '/opt/mtproto-proxy/ipv6-hop.sh --check'

# Check cron job
ssh root@<SERVER_IP> 'cat /etc/cron.d/mtproto-ipv6'
```

## Low-level Debugging

```bash
# Check for CLOSE-WAIT sockets
ssh root@<SERVER_IP> 'ss -tnp state close-wait | grep mtproto'

# Check thread states in Linux /proc
ssh root@<SERVER_IP> 'cat /proc/$(pgrep -f mtproto-proxy)/status | grep -E "Threads|State"'

# Verify TCPMSS clamping rule (against DPI)
ssh root@<SERVER_IP> 'iptables -t mangle -L OUTPUT -n -v | grep TCPMSS'
```
