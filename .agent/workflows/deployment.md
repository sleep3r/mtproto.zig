---
description: Build, deploy, update, and validate workflow for mtproto.zig.
---

# Deployment Workflow

## Available Makefile Targets

```
make help     — show all targets
make build    — cross-compile proxy + mtbuddy for Linux x86_64
make fmt      — format all Zig source files
make test     — run unit tests
make deploy   — build and push proxy + mtbuddy to server
```

Default server: `mtproto.sleep3r.ru` (override with `SERVER=<host>`).

## Local Dev Iteration

```bash
make build          # cross-compile both binaries
make fmt            # format source
make test           # run unit tests
```

## Deploy to Server

```bash
make deploy                            # uses default SERVER
make deploy SERVER=mtproto.sleep3r.ru  # explicit
```

`deploy` depends on `build`, so it always cross-compiles first. Flow:

1. `zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux -Dcpu=x86_64_v3`
2. `systemctl stop mtproto-proxy`
3. Upload `mtproto-proxy` → `/opt/mtproto-proxy/`
4. Upload `mtbuddy` → `/usr/local/bin/mtbuddy`
5. Upload `config.toml` (if present locally)
6. Upload `.env` → `env.sh` (if present locally)
7. `chown` + `systemctl start mtproto-proxy`

## Update via mtbuddy (Release Artifact Path)

Directly on host:

```bash
curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/bootstrap.sh | sudo bash
```

Or if mtbuddy is already installed:

```bash
mtbuddy update
mtbuddy update --version vX.Y.Z
```

## Post-Deploy Validation

```bash
ssh root@<SERVER> 'systemctl status mtproto-proxy --no-pager'
ssh root@<SERVER> 'journalctl -u mtproto-proxy --since "10 minutes ago" --no-pager'
```

## Operational Notes

- Runtime target is Linux x86_64.
- Both `mtproto-proxy` and `mtbuddy` are cross-compiled and deployed together.
- Keep config secrets in deployed config file, not in repository defaults.
- The `mtbuddy` binary lives at `/usr/local/bin/mtbuddy` on the server.
- The proxy binary and config live at `/opt/mtproto-proxy/`.
