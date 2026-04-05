---
description: How to build, run, and deploy the MTProto Zig proxy.
---

# Deployment Workflow

This workflow documents current build and deploy paths as implemented in `Makefile` and `deploy/install.sh`.

## Prerequisites

- Zig 0.15.2 for local builds
- SSH access to VPS
- systemd on target host

## Key Commands

- `make build` : debug build
- `make release` : release build (`ReleaseFast`)
- `make run CONFIG=<path>` : run proxy with selected config
- `make test` : run unit tests
- `make bench` : encapsulation microbench
- `make soak` : 30s multithreaded soak
- `make deploy SERVER=<ip>` : cross-compile and deploy to VPS
- `make migrate SERVER=<ip>` : bootstrap + push config + deploy

## `make deploy` (current behavior)

1. Builds Linux target: `zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux`.
2. Stops remote service (`systemctl stop mtproto-proxy`).
3. Uploads binary and deploy scripts via `scp`.
4. Uploads config when local config file exists.
5. Starts service and prints status.

Why service stop is required:

- Unit file contains `ProtectSystem=strict` and `ReadOnlyPaths=/opt/mtproto-proxy`.
- Replacing binaries safely is simplest when service is stopped first.

## One-line operator update path

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | sudo bash
```

The installer is idempotent and preserves existing operational config/secrets on update.

## Systemd Unit Notes (`deploy/mtproto-proxy.service`)

- `LimitNOFILE=65535` for high socket count.
- `TasksMax=65535` kept as operational headroom.
- Runtime relay model is still single-thread `epoll` in proxy core.
- `ReadOnlyPaths=/opt/mtproto-proxy` and capability bounds for privileged port binding.

