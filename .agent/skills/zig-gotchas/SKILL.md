---
name: MTProto Proxy Zig Gotchas
description: Practical Zig/runtime pitfalls and invariants for this codebase after epoll rewrite.
---

# Zig Gotchas (Current)

This is the short list of things that matter in this repository now.

## 1) Do not re-introduce thread-per-connection behavior

- The proxy core is event-loop based.
- Any reintroduction of per-connection threads/stacks will explode memory under high connection counts.

## 2) Keep I/O path non-blocking

- Socket reads/writes/connect must remain non-blocking in runtime path.
- If adding new protocol phases, model them as explicit state transitions.

## 3) Keep handshake checks strict

- TLS-auth validation is not enough by itself.
- SNI must match configured `tls_domain` in runtime path.

## 4) Replay protection keying

- Replay cache should key on canonical HMAC output, not mutable wire representation.
- This avoids shape-based bypasses on timestamp-masked bytes.

## 5) Avoid hidden O(N) queue drains in hot path

- For message queues, avoid repeated front-removal copies.
- Use head index/ring style progression and periodic compaction.

## 6) Allocation policy

- Keep large per-connection buffers on-demand.
- Idle connections should hold minimal state.

## 7) Logging policy

- Keep hot path logs minimal.
- Avoid debug-level flood in production traffic path.

## 8) Security fetch policy

- No insecure TLS fallback for Telegram metadata fetches.
- If refresh fails, keep last known-good state and warn.

## 9) Linux assumptions

- Runtime behavior is Linux-specific (`epoll`, socket options, `/proc`-style benchmarking assumptions).

## 10) Keep docs and probe modes in sync

- If probe traffic modes or semantics change, update:
  - `test/README.md`
  - main `README.md` benchmark references
