---
name: discover-zig
description: Router skill for Zig-related tasks in this repository; points to local architecture, gotchas, and client-behavior skills.
---

# Zig Skill Router

Use this skill as an entrypoint whenever work touches Zig code in this repository.

## Use This For

- `src/**/*.zig` changes
- runtime architecture questions
- performance/memory tuning
- debugging event-loop behavior
- protocol/crypto safety checks

## Load Next Skills

For system design and flow:

Read ../architecture/SKILL.md

For implementation pitfalls and invariants:

Read ../zig-gotchas/SKILL.md

For platform-specific Telegram client timeout/retry behavior:

Read ../client-behavior/SKILL.md

## Repository-Specific Notes

- Runtime target is Linux (`epoll` core).
- The proxy is state-machine/event-loop based (no thread-per-connection model).
- Keep docs synchronized when behavior changes:
  - `README.md`
  - `test/README.md`
  - `.agent/workflows/*`
