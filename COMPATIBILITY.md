# Compatibility & stability policy

`1.0.0` means **these surfaces are stable**. This document enumerates exactly what SemVer covers, so
operators can upgrade safely and contributors know what they may not break without a major bump.

Versioning follows [SemVer](https://semver.org/): given `MAJOR.MINOR.PATCH`, a **breaking change** to
any surface below requires a MAJOR bump; backward-compatible additions are MINOR; fixes are PATCH.

## Covered surfaces (stable from 1.0)

### 1. `tg://` / `https://t.me/proxy` link & secret format
- The FakeTLS (`ee` + tls_domain hex) and dd (`dd`) secret encodings, and the `server`/`port`/`secret`
  link parameters, are stable. Existing links keep working across MINOR/PATCH upgrades.
- ⚠️ **`tls_domain` is part of the `ee` secret** (encoded as hex), so the link is a function of
  `(secret, tls_domain)`. **Never change `tls_domain` (or the secret) on a live deployment** — it
  invalidates every distributed link. The fronting domain must be chosen well at install time and then
  treated as frozen; see [ARCHITECTURE.md](ARCHITECTURE.md) "FakeTLS fronting & domain selection".

### 2. Configuration file (`config.toml`)
- Existing **keys, sections, value semantics, and defaults** are stable. New keys may be added (MINOR);
  existing keys are not removed or repurposed without a MAJOR bump. Deprecated keys keep working for at
  least one MAJOR cycle. telemt-compatible aliases are preserved.
- `mtproto-proxy --check-config <path>` validates a config and exits 0 (valid) / 1 (invalid).

### 3. Prometheus `/metrics` names & the metrics endpoints
- Exported metric **names and label keys** are stable (e.g. `mtproto_connections_active`,
  `mtproto_connection_close_reason_total{reason}`, `mtproto_handshake_timeouts_total`). New metrics may
  be added; existing ones are not renamed/removed without a MAJOR bump. Dashboards and alerts may rely
  on them.
- `/healthz` (liveness) and `/readyz` (readiness) return `200`/`503` and are stable for LB/k8s probes.

### 4. CLI flags & behaviors
- `mtproto-proxy` flags (`--help`, `--version`, `--check-config`) and `mtbuddy` subcommand names and
  their documented behaviors are stable. New flags/subcommands may be added.

### 5. systemd units & deployment layout
- Unit names (`mtproto-proxy.service`) and the install layout (`/opt/mtproto-proxy/…`,
  `/usr/local/bin/mtbuddy`) are stable. The installed unit is `Type=simple` (robust in
  containers); `Type=notify`/watchdog is implemented but dormant pending container detection.
  Hardening directives may be tightened in a MINOR release **only if** they do not break a
  documented egress mode.

### 6. Release artifacts & verification
- Release binaries are minisign-signed against the public key pinned at build time (`build.zig`,
  overridable for rebuilds via `-Dminisign_pubkey=…`), and the `mtbuddy update` verify flow
  (signature + SHA-256 against that embedded key) is stable.
- **Not yet provided**: an operator-facing key **rotation/revocation** procedure. Today a key change
  ships only via a new signed release built with a new pinned key; there is no out-of-band revocation
  channel. A documented rotation path + offline/SLSA signing is a planned follow-up
  (`harden-signing-slsa`).

## NOT covered (may change in any release)

- Internal Zig APIs, module layout, and function signatures (`src/**`).
- Log line **wording** (only `/metrics` is a stable machine contract — do not parse logs).
- The FakeTLS ServerHello byte template internals, evasion heuristics, DRS parameters, and desync
  strategy details — these intentionally evolve to track censor behavior. The *observable goal*
  (indistinguishability from the fronted domain) is the contract, not the bytes.
- The bundled middle-proxy defaults, DC address tables, and timeouts (operationally tuned).
- Dashboard internals (FastAPI app, pinned dependency versions).
- Anything explicitly marked experimental/opt-in in `config.toml` or the README.

## Supported platforms

- **Runtime**: Linux only. **Build/test/dev**: Linux + macOS (cross-compile).
- **Toolchain**: the Zig version pinned in `build.zig.zon` / `.zig-version`. Other versions are
  unsupported and may fail to build.

## Deprecation process

A surface is deprecated by (1) documenting it here and in release notes, (2) keeping it working with a
warning for ≥1 MAJOR cycle, (3) removing it only in a MAJOR release. Security fixes may shorten this
when leaving a surface in place is itself the vulnerability.
