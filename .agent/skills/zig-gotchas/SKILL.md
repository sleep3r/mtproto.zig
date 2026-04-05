---
name: MTProto Proxy Zig Gotchas
description: Critical Zig-specific execution gotchas, profiling, stability fixes, and development conventions for this project.
---

# Zig Gotchas and Stability Notes

This file tracks practical pitfalls and current runtime constraints for `mtproto.zig`.

## Current Architecture Baseline

- Relay core is Linux `epoll` event loop, single-threaded on hot path.
- Connection state is pooled (`ConnectionSlot`) and mostly heap-backed on demand.
- Non-blocking writes are queue-based (`MessageQueue`) and flushed with `writev`.
- MiddleProxy metadata refresh runs in a detached updater thread.

Do not reintroduce thread-per-connection or blocking relay loops.

## Logging Gotchas

- `std.log.defaultLog` can serialize on global stderr lock and hurt throughput under load.
- Project uses custom lock-free `logFn` in `src/main.zig`.
- Keep hot-path logging minimal (`debug` only where needed, avoid noisy per-packet logs).
- Do not force global `.log_level = .debug` in production builds.

## Allocator and Concurrency

- Runtime uses `std.heap.page_allocator` to avoid allocator mutex contention seen with GPA under heavy connection churn.
- Keep ownership boundaries explicit and wipe crypto material on teardown (`resetOwnedBuffers` paths).
- Avoid hidden allocations inside event callbacks when possible.

## Socket and I/O Realities

- Sockets are non-blocking and epoll-driven.
- `SO_SNDTIMEO` and TCP keepalive are configured for relay sockets.
- Handshake/idle behavior is timer-driven (`idle_timeout_sec`, `handshake_timeout_sec`) in `runTimers`.
- There is no active `SO_RCVTIMEO`-based relay timeout path in current code.

## Queueing and Partial Write Model

- Outbound data is queued in block classes (tiny/small/standard).
- Flush path uses scatter-gather `writev` with explicit queue consumption.
- Backpressure is represented by pending queue state and epoll `OUT` interest toggles.
- Legacy `writeAll` assumptions are outdated for this codebase.

## MiddleProxy Specific Notes

- Endpoints and secret are refreshed from Telegram core endpoints; bundled defaults remain fallback.
- Candidate rotation and direct fallback behavior are part of normal operation.
- Non-media requests may reconnect direct when ME candidates are exhausted.

## Timeout and Lifetime Notes

- Current runtime enforces pre-first-byte idle timeout, handshake timeout after first byte, and relay idle timeout.
- Fixed max connection lifetime (for example "30 minutes hard cap") is not implemented in current code.

## Practical Change Guardrails

- Keep epoll interest synchronization correct (`IN`/`OUT` toggles per phase).
- Preserve handshake assembly correctness for fragmented TLS records.
- Preserve replay-cache behavior (`canonical_hmac` keying).
- Keep docs aligned with real log messages and runtime flow.

## Development Conventions

- Pass allocators explicitly and free deterministically.
- Use error unions and avoid swallowing critical errors on control-path boundaries.
- Keep tests close to protocol primitives and relay helpers.
- For substantial behavior changes, update `README.md` and relevant `.agent` docs in the same change.
