---
name: MTProto Client Behavior Matrix
description: Version-pinned Telegram client connection behavior notes for proxy compatibility debugging.
---

# MTProto Client Behavior Matrix

Use this skill when behavior differs by client platform (iOS/Android/Desktop) or when tuning relay/handshake timeouts.

## Evidence Policy

- Do not publish behavior claims without evidence.
- Accept only:
  - reproducible local captures/logs, or
  - direct client source links pinned to a tag and commit.
- Mark each claim as `source-backed` or `field-capture`.

## iOS (Telegram iOS)

Version snapshot:

- Repo/tag: `TelegramMessenger/Telegram-iOS` `build-26855`
- Commit: `b16d9acdffa9b3f88db68e26b77a3713e87a92e3`

Source-backed behavior:

- TCP connect timeout: `12s`
  - https://github.com/TelegramMessenger/Telegram-iOS/blob/b16d9acdffa9b3f88db68e26b77a3713e87a92e3/submodules/MtProtoKit/Sources/MTTcpConnection.m#L980
- Response watchdog base: `MTMinTcpResponseTimeout = 12.0`
  - https://github.com/TelegramMessenger/Telegram-iOS/blob/b16d9acdffa9b3f88db68e26b77a3713e87a92e3/submodules/MtProtoKit/Sources/MTTcpConnection.m#L576
- Response timeout includes payload-dependent term and resets on partial reads
  - https://github.com/TelegramMessenger/Telegram-iOS/blob/b16d9acdffa9b3f88db68e26b77a3713e87a92e3/submodules/MtProtoKit/Sources/MTTcpConnection.m#L1339
  - https://github.com/TelegramMessenger/Telegram-iOS/blob/b16d9acdffa9b3f88db68e26b77a3713e87a92e3/submodules/MtProtoKit/Sources/MTTcpConnection.m#L1398
- Transport-level watchdog: `20s`
  - https://github.com/TelegramMessenger/Telegram-iOS/blob/b16d9acdffa9b3f88db68e26b77a3713e87a92e3/submodules/MtProtoKit/Sources/MTTcpTransport.m#L312
- Reconnect backoff steps (`1s`, then `4s`, then `8s`)
  - https://github.com/TelegramMessenger/Telegram-iOS/blob/b16d9acdffa9b3f88db68e26b77a3713e87a92e3/submodules/MtProtoKit/Sources/MTTcpConnectionBehaviour.m#L66

Field-capture behavior (proxy-side observations):

- Pre-warms multiple idle sockets.
- Can split 64-byte obfuscation handshake across TLS records.
- May delay first payload after `ServerHello`.

Proxy implications:

- Assemble handshake bytes until full 64-byte payload is complete.
- Keep generous handshake stage timeout; tighten only after relay is active.
- Do not treat short idle prewarmed sockets as protocol failure.

## Android (Telegram Android)

Version snapshot:

- Repo/tag: `DrKLO/Telegram` `release-11.4.2-5469`
- Commit: `fb2e545101f41303f1e2712de2e7611a9335f1c3`

Source-backed behavior:

- Enables `TCP_NODELAY`, switches socket to `O_NONBLOCK`, uses `connect(..., EINPROGRESS)` with edge-triggered epoll.
  - https://github.com/DrKLO/Telegram/blob/fb2e545101f41303f1e2712de2e7611a9335f1c3/TMessagesProj/jni/tgnet/ConnectionSocket.cpp#L571
- Timeout model is logical/internal (`setTimeout` / `checkTimeout`).
  - https://github.com/DrKLO/Telegram/blob/fb2e545101f41303f1e2712de2e7611a9335f1c3/TMessagesProj/jni/tgnet/ConnectionSocket.cpp#L1066
- Explicit connection-type split (`Generic`, `Download`, `Upload`, `Push`, `Temp`, `Proxy`) and multiple parallel slots.
  - https://github.com/DrKLO/Telegram/blob/fb2e545101f41303f1e2712de2e7611a9335f1c3/TMessagesProj/jni/tgnet/Defines.h#L68
  - https://github.com/DrKLO/Telegram/blob/fb2e545101f41303f1e2712de2e7611a9335f1c3/TMessagesProj/jni/tgnet/Defines.h#L26

Proxy implications:

- Expect several concurrent connection attempts from one device/session.
- Treat connect churn as normal; optimize for quick accept + cheap close path.

## Desktop (Windows/Linux/macOS via Telegram Desktop)

Version snapshot:

- Repo/tag: `telegramdesktop/tdesktop` `v6.7.2`
- Commit: `085c4ba65d1f8aa13abf0fd7fc8489f094552542`

Source-backed behavior:

- Builds multiple test connections and chooses by priority.
  - https://github.com/telegramdesktop/tdesktop/blob/085c4ba65d1f8aa13abf0fd7fc8489f094552542/Telegram/SourceFiles/mtproto/session_private.cpp#L1010
- Wait-for-connected starts at `1000ms` and grows on failures.
  - https://github.com/telegramdesktop/tdesktop/blob/085c4ba65d1f8aa13abf0fd7fc8489f094552542/Telegram/SourceFiles/mtproto/session_private.cpp#L34
  - https://github.com/telegramdesktop/tdesktop/blob/085c4ba65d1f8aa13abf0fd7fc8489f094552542/Telegram/SourceFiles/mtproto/session_private.cpp#L1236
- TCP/HTTP transport full-connect timeout: `8s`.
  - https://github.com/telegramdesktop/tdesktop/blob/085c4ba65d1f8aa13abf0fd7fc8489f094552542/Telegram/SourceFiles/mtproto/connection_tcp.cpp#L21
  - https://github.com/telegramdesktop/tdesktop/blob/085c4ba65d1f8aa13abf0fd7fc8489f094552542/Telegram/SourceFiles/mtproto/connection_http.cpp#L18
- Resolver path uses per-IP timeout `4000ms` and scales by resolved IP count.
  - https://github.com/telegramdesktop/tdesktop/blob/085c4ba65d1f8aa13abf0fd7fc8489f094552542/Telegram/SourceFiles/mtproto/connection_resolving.cpp#L16
- After first success, may wait `2000ms` for a better candidate.
  - https://github.com/telegramdesktop/tdesktop/blob/085c4ba65d1f8aa13abf0fd7fc8489f094552542/Telegram/SourceFiles/mtproto/session_private.cpp#L33

Linux/macOS note:

- In reviewed MTProto sources, timeout/retry logic is shared with Windows path (no observed OS-specific branching there).
- Validate package/channel specifics separately (Snap/DEB/Flatpak/macOS build IDs) before asserting behavioral deltas.

Proxy implications:

- Expect candidate racing and early cancellation patterns.
- Keep reconnect path cheap and non-blocking.
- Do not overfit timeout policy to a single desktop platform.

## Practical Use Checklist

- If one platform fails and others pass, first compare known timeout model for that client.
- Verify whether failures happen pre-handshake, in 64-byte obfuscation phase, or after relay starts.
- Inspect whether client behavior is expected parallel racing vs actual proxy regression.
- Update this skill only with pinned sources or reproducible captures.
