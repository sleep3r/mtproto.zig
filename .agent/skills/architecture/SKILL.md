---
name: MTProto Proxy Architecture
description: Current architecture and design rules for the Linux epoll-based Zig MTProto proxy.
---

# MTProto Proxy Architecture (Current)

This project is a production MTProto proxy in Zig with FakeTLS fronting, active anti-replay protection, and Linux-first deployment.

## Build Artifacts

The project produces two binaries via `build.zig`:

| Binary | Source | Install Path | Purpose |
|--------|--------|-------------|---------|
| `mtproto-proxy` | `src/main.zig` | `/opt/mtproto-proxy/mtproto-proxy` | The proxy server |
| `mtbuddy` | `src/ctl/main.zig` | `/usr/local/bin/mtbuddy` | Installer & control panel (TUI) |

Cross-compile for production: `make build` (or `zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux -Dcpu=x86_64_v3`).

## Runtime Model

- **Single-threaded network core**: one Linux `epoll` event loop handles socket I/O.
- **No thread-per-connection**: connection handling is state-machine driven.
- **Connection slots** are allocated lazily and reused.
- **Per-connection heavy buffers** are on-demand, not permanently embedded in idle slots.

Primary file: `src/proxy/proxy.zig`.

## Core Flow

1. Accept client socket (non-blocking).
2. Parse TLS ClientHello record header/body incrementally.
3. Validate TLS-auth HMAC.
4. Validate SNI against configured `tls_domain`.
5. Build/send fake `ServerHello` (+ optional split/desync behavior).
6. Read 64-byte MTProto obfuscation handshake.
7. Resolve route: direct DC or MiddleProxy route.
8. Enter relay mode (C2S/S2C transform pipeline).

## Relay Pipeline

### C2S

- TLS unwrap
- client AES-CTR decrypt
- transport encapsulation:
  - direct DC: AES-CTR encrypt for DC
  - MiddleProxy: `RPC_PROXY_REQ` framing + CBC layer

### S2C

- transport decapsulation/decrypt
- client-side AES-CTR encrypt (unless fast-mode path)
- TLS application record wrapping

## MiddleProxy

- Runtime path is non-blocking and event-loop integrated.
- Legacy blocking handshake helpers were removed.
- Endpoint/secret metadata refresh is periodic.

## Anti-Replay

- Handshake digest is validated with timestamp skew window.
- Replay cache key uses canonical HMAC value from validation path.

## Message Queue Strategy

- Write path uses chained blocks + `writev` flush.
- Queue head uses index progression (not repeated `orderedRemove(0)` hot-path shifts).

## mtbuddy (Installer & Control Panel)

Source tree: `src/ctl/`. Interactive TUI with raw terminal mode, arrow-key navigation, and Unicode box-drawing.

Key modules:

| Module | Purpose |
|--------|---------|
| `main.zig` | CLI arg dispatch + interactive menu |
| `tui.zig` | Terminal UI engine (raw mode, rendering) |
| `install.zig` | Fresh proxy installation |
| `update.zig` | Self-update from GitHub releases |
| `tunnel.zig` | AmneziaWG tunnel + network namespace setup |
| `dashboard.zig` | Monitoring dashboard installer |
| `recovery.zig` | Service recovery & masking health |
| `uninstall.zig` | Clean uninstall |
| `i18n.zig` | English / Russian localization |

## Deployment Layout (Server)

```
/opt/mtproto-proxy/
├── mtproto-proxy          # proxy binary
├── config.toml            # runtime configuration
├── env.sh                 # optional env vars (TAG, etc.)
└── monitor/               # dashboard assets (optional)

/usr/local/bin/mtbuddy     # installer/control binary
/etc/systemd/system/mtproto-proxy.service
```

## Platform Scope

- **Linux-only runtime target**.
- macOS is supported for development/cross-compile, not for production runtime.

## Design Principles

- Keep the hot path non-blocking.
- Favor explicit state transitions over hidden control flow.
- Keep security checks in the handshake path strict and cheap.
- Avoid stale parallel implementations of the same protocol path.
