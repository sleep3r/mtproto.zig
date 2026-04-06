---
description: Guide on how to migrate the MTProto proxy server.
---

# Server Migration Guide

Use this flow when old VPS IP is blocked and you need a controlled cutover without changing client secrets.

## Step 1: Provision New VPS

Install/update proxy with official installer:

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | ssh root@<NEW_VPS_IP> "bash"
```

If you use IPv6 auto-hopping, provide Cloudflare vars during install:

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | ssh root@<NEW_VPS_IP> "export CF_TOKEN='...'; export CF_ZONE='...'; bash"
```

## Step 2: Preserve Access Secrets

Keep `[access.users]` secrets identical so existing `tg://` links remain valid.

1. Copy old `/opt/mtproto-proxy/config.toml` to new host.
2. Restart proxy on new host.

```bash
ssh root@<NEW_VPS_IP> 'systemctl restart mtproto-proxy'
```

## Step 3: Switch DNS

- Update `A` record to new VPS IPv4.
- If IPv6 hopping is enabled, run hop script once to force AAAA update from new host:

```bash
ssh root@<NEW_VPS_IP> '/opt/mtproto-proxy/ipv6-hop.sh'
```

## Step 4: Validate Before Decommission

```bash
# Service is healthy
ssh root@<NEW_VPS_IP> 'systemctl status mtproto-proxy --no-pager'

# Capacity smoke
ssh root@<NEW_VPS_IP> 'sudo python3 /opt/mtproto-proxy/test/capacity_connections_probe.py --profile mtproto.zig --traffic-mode tls-auth --tls-domain google.com --levels 200,500 --open-budget-sec 8 --hold-seconds 0.5 --settle-seconds 0.8 --connect-timeout-sec 0.1 --nofile 200000 --nproc 12000'

# Fallback/refresh visibility
ssh root@<NEW_VPS_IP> 'journalctl -u mtproto-proxy --since "30 min ago" --no-pager | grep -E "Middle-proxy cache updated|Initial middle-proxy refresh failed|middle-proxy exhausted|middle-proxy handshake failed"'
```

Operational note:

- If `core.telegram.org` is temporarily unreachable, proxy continues with bundled MiddleProxy defaults and should still start.
