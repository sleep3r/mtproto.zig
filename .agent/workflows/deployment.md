---
description: How to build, run and deploy the MTProto Zig Proxy
---

# Deployment Workflow

This workflow documents how to build, deploy, and update the MTProto proxy, along with configuration handling.

## Building and Running

### Prerequisites
- Zig 0.15.2
- SSH access to VPS for deployment

### Key Commands

- `make build` : Debug build (native)
- `make release` : Release build (native)
- `make deploy` : Cross-compile for Linux + stop + scp + start
- `make migrate` : Fresh setup on new VPS (uses install.sh)
- `make test` : Run unit tests
- `make bench` : ReleaseFast encapsulation microbench
- `make soak` : ReleaseFast 30s multithreaded soak stress

### Deployment Execution

`make deploy` performs the following steps:
1. Cross-compile for Linux (`x86_64-linux`).
2. `systemctl stop mtproto-proxy`.
3. `scp` binary and deploy scripts to VPS.
4. If `$(CONFIG)` exists locally, upload it as `/opt/mtproto-proxy/config.toml`.
5. `systemctl start mtproto-proxy`.

> [!IMPORTANT]
> You must stop the service before using `scp` because the systemd unit has `ReadOnlyPaths=/opt/mtproto-proxy`, which prevents overwriting the binary while it is running.

## Server Update Path (Recommended for Operators)

To update an already installed proxy, re-run the same install command:

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | sudo bash
```

The script is idempotent: it rebuilds from latest source, replaces the binary, and preserves existing `config.toml` and `env.sh`.

## Systemd Unit (`deploy/mtproto-proxy.service`)
Key performance and security settings:
- `LimitNOFILE=65535`: Enough file descriptors for thousands of concurrent connections.
- `TasksMax=65535`: Enough threads for the one-thread-per-connection model.
- `ReadOnlyPaths=/opt/mtproto-proxy`: Security hardening.
