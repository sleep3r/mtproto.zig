# Threat Model

This document describes what `mtproto.zig` is designed to protect against, what it does not protect against, and the operational constraints you should expect in production.

## Scope

In scope:
- `mtproto-proxy` data plane
- `mtbuddy` install/update/control workflows
- default masking and upstream routing modes

Out of scope:
- Telegram protocol internals and Telegram backend security
- host OS hardening beyond what project configs apply
- physical access, hypervisor compromise, or root compromise on your VPS

## Assets

Primary assets:
- availability of proxy service
- confidentiality of user secrets and runtime config
- integrity of update/install artifacts

Secondary assets:
- operational privacy (traffic shape camouflage, anti-probe behavior)
- predictable behavior under load and hostile input

## Adversaries

- passive DPI observers
- active probing systems (invalid handshake probes, replay probes)
- network attackers causing packet loss, fragmentation, and reset patterns
- opportunistic abuse (scanners, connection floods)

## Security Goals

`mtproto.zig` aims to:
- make MTProto traffic resemble common TLS traffic
- reduce fingerprinting by DPI and active probes
- enforce connection caps and per-subnet throttling
- fail safely on invalid handshakes and malformed frames
- verify release artifacts (signature + checksum) in default install/update flows

## Non-Goals

`mtproto.zig` does not aim to:
- provide anonymity (it is not Tor)
- hide destination IP from your hosting provider
- defend against compromised client devices
- guarantee bypass in every country/network forever
- guarantee zero downtime during all upgrades on every deployment model

## Known Limitations

- Censorship techniques evolve quickly; bypass methods can degrade without prior notice.
- Traffic camouflage can be weakened by network-level heuristics outside proxy control.
- Some mitigations depend on host networking setup (iptables/nftables, kernel routing, NIC offload behavior).
- The dashboard requires HTTP Basic auth (auto-generated token at `/opt/mtproto-proxy/monitor/dashboard.token`) and pins the Host header on loopback binds, but it is still plain HTTP and runs a root-privileged control plane — reach it over an SSH tunnel and only ever expose it behind HTTPS + a reverse proxy. The Prometheus `/metrics` endpoint has no auth; keep it on loopback.
- Proxy behavior depends on Telegram DC availability and protocol expectations that can change.
- Telegram calls are out of scope and do not work through this proxy. Calls use Telegram's SOCKS-style call path, which is outside the MTProto/TLS-masking model and cannot be disguised cleanly as normal HTTPS here.
- Media for non-Premium accounts requires MiddleProxy (`[general].use_middle_proxy = true`). Without it, photos, videos, stories, and other media on non-Premium accounts should be considered unavailable.

## Client Transports: FakeTLS vs direct-obfuscated (dd)

The proxy accepts two client transports on the same port:

- **FakeTLS (`ee...` secret, recommended):** the obfuscated MTProto handshake is
  wrapped in a TLS 1.3 ClientHello/ServerHello so the connection looks like normal
  HTTPS to DPI. This is the transport the camouflage design (FakeTLS, DRS, desync,
  masking) is built around.
- **Direct-obfuscated (`dd...` secret, "secure"/padded mode):** plain obfuscated
  MTProto with random padding and **no TLS wrapper**. It still requires a valid
  user secret, but it is **not disguised as TLS** and is therefore directly
  fingerprintable as MTProto by DPI. The `dd` name refers to the padding mode, not
  to any DPI-resistance property.

Implications:

- The `dd` transport is **rejected by default** (`[censorship].fake_tls_only =
  true`): non-TLS first bytes are masked immediately (matching the masking
  target) instead of being parsed as an obfuscated handshake, so there is no dd
  active-probe timing difference and the proxy only ever speaks FakeTLS on the
  wire. This is the secure default for a TLS-camouflage proxy.
- To hand out `dd` links (lower-DPI / compatibility scenarios), set
  `fake_tls_only = false`. Only then does `mtbuddy links` print dd links, and
  only then does the proxy accept the DPI-fingerprintable dd transport. Prefer
  `ee`/FakeTLS links wherever active DPI is a concern.

## Region-Specific Caveats

- Blocking patterns differ by ISP and country. A configuration that works in one region can fail in another.
- IPv6 behavior is especially region/provider dependent; dual-stack DNS can cause client-side delays when AAAA is published but upstream IPv6 is broken.
- Tunnel mode success depends on local policy routing support and allowed VPN protocols in that region.

## Compatibility Matrix

### Telegram clients

| Client family | Status | Notes |
| --- | --- | --- |
| Official Telegram Android | expected to work | test with latest stable app before rollout |
| Official Telegram iOS | expected to work | IPv6/AAAA issues are a common deployment pitfall |
| Telegram Desktop | expected to work | verify with your selected masking domain |
| Third-party Telegram clients | best effort | protocol edge cases may differ |

Compatibility here covers chat and media transport. Telegram calls are unsupported in both direct and MiddleProxy modes.

### OS / kernel

| Platform | Status | Notes |
| --- | --- | --- |
| Linux x86_64 | supported | primary production target |
| Linux aarch64 | supported | verify release artifact/CPU compatibility on target host |
| Linux in Docker | supported with caveats | OS-level DPI modules are not applied inside container by default |
| macOS / Windows runtime | not supported | cross-compilation host is fine; runtime target is Linux |

## What Can Break After Telegram/DC Changes

Potential breakage vectors:
- DC endpoint changes and transport policy updates
- MiddleProxy metadata format or refresh endpoint changes
- handshake/timing expectations used by client versions
- media path specifics (for example DC203 behavior)

Operational guidance:
- keep to latest release
- monitor logs after each Telegram client or DC behavior shift
- keep fallback paths tested (direct/tunnel/upstream)
- run `mtbuddy config doctor` and E2E checks after major updates

## Residual Risk

Even with all mitigations enabled, this project cannot guarantee uninterrupted bypass against adaptive nation-state censorship systems. Treat this as a hardened transport tool, not a universal censorship-proof channel.
