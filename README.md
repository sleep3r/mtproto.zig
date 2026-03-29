<div align="center">

# mtproto.zig

**High-performance Telegram MTProto proxy written in Zig**

Disguises Telegram traffic as standard TLS 1.3 HTTPS to bypass network censorship.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/zig-0.15.2-f7a41d.svg?logo=zig&logoColor=white)](https://ziglang.org)
[![LOC](https://img.shields.io/badge/lines_of_code-1.7k-informational)](src/)
[![Dependencies](https://img.shields.io/badge/dependencies-0-success)](build.zig)

---

[Features](#-features) &nbsp;&bull;&nbsp;
[How It Works](#-how-it-works) &nbsp;&bull;&nbsp;
[Quick Start](#-quick-start) &nbsp;&bull;&nbsp;
[Configuration](#-configuration) &nbsp;&bull;&nbsp;
[Security](#-security) &nbsp;&bull;&nbsp;
[Project Structure](#-project-structure)

</div>

## &nbsp; Features

| | Feature | Description |
|---|---------|-------------|
| **TLS 1.3** | Fake Handshake | Connections are indistinguishable from normal HTTPS to DPI systems |
| **MTProto v2** | Obfuscation | AES-256-CTR encrypted tunneling (abridged, intermediate, secure) |
| **DRS** | Dynamic Record Sizing | Mimics real browser TLS behavior (Chrome/Firefox) to resist fingerprinting |
| **Multi-user** | Access Control | Independent secret-based authentication per user |
| **Anti-replay** | Timestamp Validation | Rejects replayed handshakes outside a +/- 2 min window |
| **Masking** | Connection Cloaking | Forwards unauthenticated clients to a real domain |
| **0 deps** | Stdlib Only | Built entirely on the Zig standard library |
| **0 globals** | Thread Safety | Dependency injection -- no global mutable state |

## &nbsp; How It Works

```
 Client                       Proxy                        Telegram DC
   |                            |                                |
   |---- TLS ClientHello ------>|                                |
   |<--- TLS ServerHello -------|                                |
   |                            |                                |
   |-- TLS(MTProto Handshake) ->|--- Obfuscated Handshake ------>|
   |                            |                                |
   |== TLS(AES-CTR(data)) ====>|==== AES-CTR(data) ============>|
   |<= TLS(AES-CTR(data)) =====|<=== AES-CTR(data) =============|
```

> **Layer 1 -- Fake TLS 1.3** &nbsp; The client embeds an HMAC-SHA256 digest (derived from its secret) in the ClientHello `random` field. The proxy validates it and responds with an indistinguishable ServerHello.

> **Layer 2 -- MTProto Obfuscation** &nbsp; Inside the TLS tunnel, a 64-byte obfuscated handshake is exchanged. AES-256-CTR keys are derived via SHA-256 for bidirectional encryption.

> **Layer 3 -- DC Relay** &nbsp; The proxy connects to the target Telegram datacenter (DC1-DC5), performs its own obfuscated handshake, and relays traffic between client and DC with re-encryption.

## &nbsp; Quick Start

### Prerequisites

- [Zig](https://ziglang.org/download/) **0.15.2** or later

### Build & Run

```bash
# Build (debug)
zig build

# Build (optimized)
make release

# Run with default config.toml
zig build run

# Run with a specific config
zig build run -- /path/to/config.toml
```

### Run Tests

```bash
zig build test
```

<details>
<summary>All Make targets</summary>

| Target | Description |
|--------|-------------|
| `make build` | Debug build |
| `make release` | Optimized build (`ReleaseFast`) |
| `make run CONFIG=<path>` | Run proxy (default: `config.toml`) |
| `make test` | Run unit tests |
| `make clean` | Remove build artifacts |
| `make fmt` | Format all Zig source files |

</details>

## &nbsp; Configuration

Create a `config.toml` in the project root:

```toml
[server]
port = 443

[censorship]
tls_domain = "google.com"
mask = true

[access.users]
alice = "00112233445566778899aabbccddeeff"
bob   = "ffeeddccbbaa99887766554433221100"
```

<details>
<summary>Configuration reference</summary>

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `[server]` | `port` | `443` | TCP port to listen on |
| `[censorship]` | `tls_domain` | `"google.com"` | Domain to impersonate / forward bad clients to |
| `[censorship]` | `mask` | `true` | Forward unauthenticated connections to `tls_domain` |
| `[access.users]` | `<name>` | -- | 32 hex-char secret (16 bytes) per user |

</details>

> **Note** &nbsp; The configuration format is compatible with the Rust-based `telemt` proxy.

## &nbsp; Security

| Measure | Details |
|---------|---------|
| Constant-time comparison | HMAC validation uses constant-time byte comparison to prevent timing attacks |
| Key wiping | All key material is zeroed from memory after use |
| Secure randomness | Cryptographically secure RNG for all nonces and key generation |
| Anti-replay | Embedded timestamp validation rejects handshakes outside +/- 2 min window |
| Nonce validation | Rejects nonces matching HTTP, plain MTProto, or TLS patterns |
| Dynamic Record Sizing | TLS record sizes mimic real browsers, preventing traffic fingerprinting |

## &nbsp; Project Structure

```
src/
├── main.zig                  Entry point, allocator setup, config loading
├── config.zig                TOML-like configuration parser
│
├── crypto/
│   └── crypto.zig            AES-256-CTR/CBC, SHA-256, HMAC, SHA-1, MD5
│
├── protocol/
│   ├── constants.zig         DC addresses, protocol tags, TLS constants
│   ├── tls.zig               Fake TLS 1.3 (ClientHello validation, ServerHello)
│   └── obfuscation.zig       MTProto v2 obfuscation & key derivation
│
└── proxy/
    └── proxy.zig             TCP listener, connection handler, relay, DRS
```

## &nbsp; License

[MIT](LICENSE) &copy; 2026 Aleksandr Kalashnikov
