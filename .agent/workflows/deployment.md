---
description: Build, deploy, update, and validate workflow for mtproto.zig.
---

# Deployment Workflow

## Build and Verify Locally

```bash
make release
make test
```

Or explicit Linux build:

```bash
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux
```

## Deploy to Server

```bash
make deploy SERVER=<SERVER_IP>
```

Typical flow:

1. Cross-compile Linux binary.
2. Upload binary and deploy assets.
3. Restart `mtproto-proxy` service.
4. Verify service status.

## Update Existing Server (Release Artifact Path)

Recommended for operators:

```bash
make update-server SERVER=<SERVER_IP>
make update-server SERVER=<SERVER_IP> VERSION=vX.Y.Z
```

Directly on host:

```bash
curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/update.sh | sudo bash
```

## Post-Deploy Validation

```bash
ssh root@<SERVER_IP> 'systemctl status mtproto-proxy --no-pager'
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "10 minutes ago" --no-pager'
```

Quick capacity sanity:

```bash
ssh root@<SERVER_IP> 'python3 /root/benchmarks/capacity_connections_probe.py --profile mtproto.zig --traffic-mode tls-auth --tls-domain google.com --levels 500,1000 --open-budget-sec 10 --hold-seconds 0.6 --settle-seconds 0.8 --connect-timeout-sec 0.1 --nofile 200000 --nproc 12000'
```

## Operational Notes

- Runtime target is Linux.
- Keep config secrets in deployed config file, not in repository defaults.
- If benchmark modes change, keep `test/README.md` and main `README.md` synchronized.
