---
description: Safe migration procedure to a new VPS without breaking client links.
---

# Server Migration Workflow

Use when current server is blocked/degraded and traffic must move quickly.

## 1) Provision New VPS

Install and start proxy stack on new host:

```bash
cat deploy/install.sh | ssh root@<NEW_VPS_IP> "bash"
```

If you use optional IPv6 hopping automation, provide required environment variables expected by your deploy scripts.

## 2) Preserve Access Secrets

Keep `[access.users]` secrets unchanged to preserve existing `tg://proxy?...&secret=...` links.

Copy production config from old host to new host:

```bash
scp root@<OLD_VPS_IP>:/opt/mtproto-proxy/config.toml root@<NEW_VPS_IP>:/opt/mtproto-proxy/config.toml
ssh root@<NEW_VPS_IP> 'systemctl restart mtproto-proxy'
```

## 3) Switch DNS

Move A/AAAA records of proxy domain to new host addresses.

Verify:

```bash
dig +short <PROXY_DOMAIN>
```

## 4) Validate New Host Before Decommissioning Old

```bash
ssh root@<NEW_VPS_IP> 'systemctl status mtproto-proxy --no-pager'
ssh root@<NEW_VPS_IP> 'python3 /root/benchmarks/capacity_connections_probe.py --profile mtproto.zig --traffic-mode tls-auth --tls-domain google.com --levels 200,500 --open-budget-sec 8 --hold-seconds 0.5 --settle-seconds 0.8 --connect-timeout-sec 0.1 --nofile 200000 --nproc 12000'
```

Only after successful validation, disable old host.
