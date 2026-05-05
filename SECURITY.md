# Security Policy

## Supported Versions

Security fixes are prioritized for:

| Branch / release line | Status |
| --- | --- |
| `main` | actively supported |
| latest tagged release | actively supported |
| older releases | best effort only |

If you run an older release, upgrade first and re-test before reporting.

## Reporting a Vulnerability

Please do not open public issues for security problems.

Use GitHub private vulnerability reporting:
- https://github.com/sleep3r/mtproto.zig/security/advisories/new

Include:
- affected version (`mtproto-proxy --version`)
- deployment model (bare metal / VM / container)
- minimal reproduction steps
- impact and attack preconditions
- logs/config snippets with secrets removed

## Response Targets

- initial acknowledgment: within 72 hours
- triage update: within 7 days
- fix timeline: depends on severity and reproducibility

## Disclosure

Please allow maintainers time to patch before public disclosure.
Coordinated disclosure is preferred for all critical and high-severity issues.
