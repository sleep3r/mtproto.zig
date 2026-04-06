---
description: How to build, run, and deploy the MTProto Zig proxy.
---

# Deployment Workflow

This workflow documents current build and deploy paths as implemented in `Makefile`, `deploy/install.sh`, and `deploy/setup_tunnel.sh`.

## Prerequisites

- Zig 0.15.2 for local builds
- SSH access to VPS
- systemd on target host
- Ubuntu 24.04 + root access for blocked-region tunnel mode
- AmneziaWG client config (`.conf`) when using tunnel deploys

## Key Commands

- `make build` : debug build
- `make release` : release build (`ReleaseFast`)
- `make run CONFIG=<path>` : run proxy with selected config
- `make test` : run unit tests
- `make bench` : encapsulation microbench
- `make soak` : 30s multithreaded soak
- `make deploy SERVER=<ip>` : cross-compile and deploy to VPS
- `make migrate SERVER=<ip> [PASSWORD=<pass>]` : bootstrap + push config + deploy
- `make deploy-tunnel SERVER=<ip> AWG_CONF=<path> [PASSWORD=<pass>]` : full migration + AmneziaWG tunnel
- `make deploy-tunnel-only SERVER=<ip> AWG_CONF=<path>` : add tunnel to an already-installed node

## `make deploy` (current behavior)

1. Builds Linux target: `zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux`.
2. Stops remote service (`systemctl stop mtproto-proxy`).
3. Uploads binary and `deploy/*.sh` via `scp`.
4. Uploads config when local config file exists.
5. Uploads `.env` as `/opt/mtproto-proxy/env.sh` when present locally.
6. Starts service and prints status.

Why service stop is required:

- Unit file contains `ProtectSystem=strict` and `ReadOnlyPaths=/opt/mtproto-proxy`.
- Replacing binaries safely is simplest when service is stopped first.

## `make migrate`

1. Optionally seeds the root SSH authorized key when `PASSWORD=` is provided.
2. Runs `deploy/install.sh` remotely.
3. Uploads local `config.toml`.
4. Calls `make deploy`.
5. Optionally runs `make update-dns` when `UPDATE_DNS=1|true`.

## Tunnel Workflows

`make deploy-tunnel` first runs `make migrate`, then uploads the AmneziaWG client config plus `deploy/setup_tunnel.sh` and executes the script remotely.

`make deploy-tunnel-only` skips bootstrap/redeploy and only applies the tunnel plumbing to an existing installation.

Remote tunnel setup currently:

- Installs `amneziawg-tools`.
- Creates network namespace `tg_proxy_ns` plus a `veth_main`/`veth_ns` pair and namespace-local DNS.
- Brings up `awg0` inside the namespace only.
- Adds host DNAT `:443 -> 10.200.200.2:443` and namespace policy routing so replies go back through the veth path, not the tunnel.
- Rewrites the systemd unit to `ip netns exec tg_proxy_ns /opt/mtproto-proxy/mtproto-proxy ...`.
- Switches proxy config to direct mode (`use_middle_proxy = false`) and removes `tag`.
- Validates all 5 Telegram DCs through the tunnel before finishing.

Important operational notes:

- Tunnel mode is intentionally direct-only: MiddleProxy registration is tied to the egress IP, which becomes the AWG exit node.
- Host SSH and host-network services stay outside the namespace; only proxy traffic is redirected through AWG.

## One-line operator update path

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | sudo bash
```

The installer is idempotent and preserves existing operational config/secrets on update.

## Systemd Unit Notes (`deploy/mtproto-proxy.service`)

- Default unit ships with `LimitNOFILE=131582` and `TasksMax=65535`.
- Proxy auto-clamps effective `max_connections` downward at startup if host `RLIMIT_NOFILE` is lower than the configured FD budget.
- Runtime relay model is still single-thread `epoll` in proxy core.
- Default unit keeps `ReadOnlyPaths=/opt/mtproto-proxy` and only `CAP_NET_BIND_SERVICE`.
- Tunnel-patched unit adds `CAP_NET_ADMIN` + `CAP_SYS_ADMIN` and uses `ExecStartPre=/usr/local/bin/setup_netns.sh` to recreate the namespace on every restart.
