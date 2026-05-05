# Contributing

Thanks for helping improve `mtproto.zig`.

## Prerequisites

- Zig `0.16.0`
- Python 3 (for E2E harness)
- Linux target assumptions for runtime tests

## Local Workflow

```bash
git clone https://github.com/sleep3r/mtproto.zig.git
cd mtproto.zig
```

### Format

```bash
make fmt
```

### Unit tests

```bash
make test
```

### E2E / integration tests

```bash
make e2e
# or
zig build e2e
```

### Bench / soak

```bash
zig build bench
zig build soak
```

## Pull Request Checklist

Before opening a PR:

1. Run `make fmt`, `make test`, and `make e2e`.
2. Update docs when behavior/config/CLI changes.
3. Add or update tests for bug fixes and new behavior.
4. Keep commits focused and explain security-sensitive changes in the PR description.

## Commit Style

Conventional commits are preferred (for example: `fix(proxy): ...`, `docs(readme): ...`).

## Security-Sensitive Changes

If your change affects:
- handshake parsing
- updater/install verification
- secret handling
- tunnel/routing behavior

include a short threat/risk note in the PR body and add tests where feasible.

## Reporting Security Issues

Please follow [SECURITY.md](SECURITY.md) and use private vulnerability reporting.
