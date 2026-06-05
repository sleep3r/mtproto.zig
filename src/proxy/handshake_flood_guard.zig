const std = @import("std");
const posix = std.posix;
const crypto = @import("../crypto/crypto.zig");

const Address = std.Io.net.IpAddress;

fn nowSeconds() i64 {
    var ts: posix.timespec = undefined;
    const rc = posix.system.clock_gettime(.MONOTONIC, &ts);
    if (posix.errno(rc) != .SUCCESS) return 0;
    return @intCast(ts.sec);
}

/// Tracks short-lived handshake failures by exact client IP.
///
/// This complements the coarser /24 subnet rate limiter: a noisy client can
/// be temporarily denied without punishing the whole provider subnet.
pub const HandshakeFloodGuard = struct {
    pub const BUCKETS = 8192;
    pub const MAX_PROBES = 8;
    pub const stale_after_s: i64 = 300;

    pub const Settings = struct {
        enabled: bool = true,
        threshold: u16 = 20,
        window_sec: u16 = 30,
        block_sec: u16 = 120,
    };

    pub const Event = enum {
        rate_limit,
        handshake_budget,
        handshake_timeout,
    };

    pub const ClientKey = struct {
        const Family = enum(u8) { ip4, ip6 };

        family: Family = .ip4,
        bytes: [16]u8 = [_]u8{0} ** 16,

        fn eql(self: ClientKey, other: ClientKey) bool {
            return self.family == other.family and std.mem.eql(u8, &self.bytes, &other.bytes);
        }
    };

    pub const Entry = struct {
        used: bool = false,
        key: ClientKey = .{},
        total: u16 = 0,
        rate_limit: u16 = 0,
        handshake_budget: u16 = 0,
        handshake_timeout: u16 = 0,
        window_start_s: i64 = 0,
        last_event_s: i64 = 0,
        blocked_until_s: i64 = 0,
    };

    pub const TopEntry = struct {
        key: ClientKey,
        total: u16,
        rate_limit: u16,
        handshake_budget: u16,
        handshake_timeout: u16,
        blocked_until_s: i64,

        fn desc(_: void, a: TopEntry, b: TopEntry) bool {
            if (a.total == b.total) return a.blocked_until_s > b.blocked_until_s;
            return a.total > b.total;
        }
    };

    hash_seed: u64 = 0,
    entries: [BUCKETS]Entry = [_]Entry{.{}} ** BUCKETS,

    pub fn init() HandshakeFloodGuard {
        return .{ .hash_seed = crypto.randomInt(u64) };
    }

    pub fn create(allocator: std.mem.Allocator) !*HandshakeFloodGuard {
        const guard = try allocator.create(HandshakeFloodGuard);
        guard.hash_seed = crypto.randomInt(u64);
        @memset(guard.entries[0..], .{});
        return guard;
    }

    pub fn destroy(self: *HandshakeFloodGuard, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }

    pub fn settings(
        enabled: bool,
        threshold: u16,
        window_sec: u16,
        block_sec: u16,
    ) Settings {
        return .{
            .enabled = enabled,
            .threshold = @max(@as(u16, 1), threshold),
            .window_sec = @max(@as(u16, 1), window_sec),
            .block_sec = @max(@as(u16, 1), block_sec),
        };
    }

    pub fn isBlocked(self: *HandshakeFloodGuard, addr: Address, cfg: Settings) bool {
        return self.isBlockedAt(addr, cfg, nowSeconds());
    }

    pub fn isBlockedAt(self: *HandshakeFloodGuard, addr: Address, cfg: Settings, now_s: i64) bool {
        if (!cfg.enabled) return false;
        const key = keyFromAddress(addr);
        const entry = self.findEntry(key) orelse return false;
        return entry.blocked_until_s > now_s;
    }

    /// Records a bad handshake-related event.
    /// Returns true when the client is blocked after this event.
    pub fn record(self: *HandshakeFloodGuard, addr: Address, event: Event, cfg: Settings) bool {
        return self.recordAt(addr, event, cfg, nowSeconds());
    }

    pub fn recordAt(
        self: *HandshakeFloodGuard,
        addr: Address,
        event: Event,
        cfg: Settings,
        now_s: i64,
    ) bool {
        if (!cfg.enabled) return false;

        const key = keyFromAddress(addr);
        const entry = self.getOrPutEntry(key, now_s);

        if (now_s - entry.window_start_s >= cfg.window_sec) {
            entry.total = 0;
            entry.rate_limit = 0;
            entry.handshake_budget = 0;
            entry.handshake_timeout = 0;
            entry.window_start_s = now_s;
        }

        increment(&entry.total);
        switch (event) {
            .rate_limit => increment(&entry.rate_limit),
            .handshake_budget => increment(&entry.handshake_budget),
            .handshake_timeout => increment(&entry.handshake_timeout),
        }
        entry.last_event_s = now_s;

        if (entry.total >= cfg.threshold) {
            entry.blocked_until_s = @max(entry.blocked_until_s, now_s + cfg.block_sec);
            return true;
        }
        return entry.blocked_until_s > now_s;
    }

    pub fn top(self: *HandshakeFloodGuard, cfg: Settings, out: []TopEntry) usize {
        return self.topAt(cfg, nowSeconds(), out);
    }

    pub fn topAt(self: *HandshakeFloodGuard, cfg: Settings, now_s: i64, out: []TopEntry) usize {
        if (!cfg.enabled or out.len == 0) return 0;

        var len: usize = 0;
        for (&self.entries) |*entry| {
            if (!entry.used or entry.total == 0) continue;
            const active_window = now_s - entry.window_start_s < cfg.window_sec;
            const blocked = entry.blocked_until_s > now_s;
            if (!active_window and !blocked) continue;

            const item = TopEntry{
                .key = entry.key,
                .total = entry.total,
                .rate_limit = entry.rate_limit,
                .handshake_budget = entry.handshake_budget,
                .handshake_timeout = entry.handshake_timeout,
                .blocked_until_s = entry.blocked_until_s,
            };

            if (len < out.len) {
                out[len] = item;
                len += 1;
                continue;
            }

            var min_idx: usize = 0;
            for (out[1..], 1..) |existing, idx| {
                if (existing.total < out[min_idx].total) min_idx = idx;
            }
            if (item.total > out[min_idx].total) out[min_idx] = item;
        }

        std.mem.sort(TopEntry, out[0..len], {}, TopEntry.desc);
        return len;
    }

    pub fn keyFromAddress(addr: Address) ClientKey {
        return switch (addr) {
            .ip4 => |ip4_addr| blk: {
                var key = ClientKey{ .family = .ip4 };
                @memcpy(key.bytes[0..4], &ip4_addr.bytes);
                break :blk key;
            },
            .ip6 => |ip6_addr| blk: {
                const b = &ip6_addr.bytes;
                const is_ipv4_mapped = std.mem.eql(u8, b[0..10], &[_]u8{0} ** 10) and
                    b[10] == 0xff and b[11] == 0xff;
                if (is_ipv4_mapped) {
                    var key = ClientKey{ .family = .ip4 };
                    @memcpy(key.bytes[0..4], b[12..16]);
                    break :blk key;
                }

                var key = ClientKey{ .family = .ip6 };
                @memcpy(&key.bytes, b);
                break :blk key;
            },
        };
    }

    pub fn formatKey(key: ClientKey, buf: []u8) []const u8 {
        return switch (key.family) {
            .ip4 => std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
                key.bytes[0],
                key.bytes[1],
                key.bytes[2],
                key.bytes[3],
            }) catch "",
            .ip6 => blk: {
                const groups = [_]u16{
                    std.mem.readInt(u16, key.bytes[0..2], .big),
                    std.mem.readInt(u16, key.bytes[2..4], .big),
                    std.mem.readInt(u16, key.bytes[4..6], .big),
                    std.mem.readInt(u16, key.bytes[6..8], .big),
                    std.mem.readInt(u16, key.bytes[8..10], .big),
                    std.mem.readInt(u16, key.bytes[10..12], .big),
                    std.mem.readInt(u16, key.bytes[12..14], .big),
                    std.mem.readInt(u16, key.bytes[14..16], .big),
                };
                break :blk std.fmt.bufPrint(
                    buf,
                    "{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}",
                    .{ groups[0], groups[1], groups[2], groups[3], groups[4], groups[5], groups[6], groups[7] },
                ) catch "";
            },
        };
    }

    fn findEntry(self: *HandshakeFloodGuard, key: ClientKey) ?*Entry {
        const start = self.indexFor(key);
        var probe: usize = 0;
        while (probe < MAX_PROBES) : (probe += 1) {
            const idx = (start + probe) & (BUCKETS - 1);
            const entry = &self.entries[idx];
            if (!entry.used) return null;
            if (entry.key.eql(key)) return entry;
        }
        return null;
    }

    fn getOrPutEntry(self: *HandshakeFloodGuard, key: ClientKey, now_s: i64) *Entry {
        const start = self.indexFor(key);
        var first_stale_idx: ?usize = null;
        var oldest_idx: usize = start;
        var oldest_ts: i64 = std.math.maxInt(i64);

        var probe: usize = 0;
        while (probe < MAX_PROBES) : (probe += 1) {
            const idx = (start + probe) & (BUCKETS - 1);
            const entry = &self.entries[idx];

            if (!entry.used) {
                entry.* = freshEntry(key, now_s);
                return entry;
            }
            if (entry.key.eql(key)) return entry;

            if (now_s - entry.last_event_s > stale_after_s and first_stale_idx == null) {
                first_stale_idx = idx;
            }
            if (entry.last_event_s < oldest_ts) {
                oldest_ts = entry.last_event_s;
                oldest_idx = idx;
            }
        }

        const victim_idx = first_stale_idx orelse oldest_idx;
        self.entries[victim_idx] = freshEntry(key, now_s);
        return &self.entries[victim_idx];
    }

    fn indexFor(self: *const HandshakeFloodGuard, key: ClientKey) usize {
        var hasher = std.hash.Wyhash.init(self.hash_seed);
        const family_byte: u8 = @intFromEnum(key.family);
        hasher.update(&[_]u8{family_byte});
        hasher.update(&key.bytes);
        return @as(usize, @intCast(hasher.final() & (BUCKETS - 1)));
    }

    fn freshEntry(key: ClientKey, now_s: i64) Entry {
        return .{
            .used = true,
            .key = key,
            .window_start_s = now_s,
            .last_event_s = now_s,
        };
    }

    fn increment(value: *u16) void {
        if (value.* < std.math.maxInt(u16)) value.* += 1;
    }
};

fn ip4(bytes: [4]u8, port: u16) Address {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}

fn ip6(bytes: [16]u8, port: u16, flow: u32, scope_id: u32) Address {
    return .{ .ip6 = .{
        .bytes = bytes,
        .port = port,
        .flow = flow,
        .interface = .{ .index = scope_id },
    } };
}

test "handshake flood guard blocks exact IP after threshold" {
    var guard = HandshakeFloodGuard{};
    const cfg = HandshakeFloodGuard.settings(true, 3, 30, 120);
    const addr = ip4(.{ 203, 0, 113, 10 }, 443);

    try std.testing.expect(!guard.recordAt(addr, .handshake_timeout, cfg, 100));
    try std.testing.expect(!guard.recordAt(addr, .handshake_timeout, cfg, 101));
    try std.testing.expect(guard.recordAt(addr, .handshake_timeout, cfg, 102));
    try std.testing.expect(guard.isBlockedAt(addr, cfg, 103));
    try std.testing.expect(!guard.isBlockedAt(addr, cfg, 223));
}

test "handshake flood guard window expiry resets score" {
    var guard = HandshakeFloodGuard{};
    const cfg = HandshakeFloodGuard.settings(true, 3, 10, 120);
    const addr = ip4(.{ 198, 51, 100, 42 }, 443);

    try std.testing.expect(!guard.recordAt(addr, .rate_limit, cfg, 100));
    try std.testing.expect(!guard.recordAt(addr, .rate_limit, cfg, 101));
    try std.testing.expect(!guard.recordAt(addr, .rate_limit, cfg, 112));
    try std.testing.expect(!guard.isBlockedAt(addr, cfg, 113));
}

test "handshake flood guard tracks top offenders and event mix" {
    var guard = HandshakeFloodGuard{};
    const cfg = HandshakeFloodGuard.settings(true, 4, 30, 120);
    const noisy = ip4(.{ 203, 0, 113, 77 }, 443);
    const quieter = ip4(.{ 203, 0, 113, 88 }, 443);

    _ = guard.recordAt(noisy, .rate_limit, cfg, 10);
    _ = guard.recordAt(noisy, .handshake_budget, cfg, 11);
    _ = guard.recordAt(noisy, .handshake_timeout, cfg, 12);
    _ = guard.recordAt(noisy, .handshake_timeout, cfg, 13);
    _ = guard.recordAt(quieter, .handshake_timeout, cfg, 14);

    var top_entries: [2]HandshakeFloodGuard.TopEntry = undefined;
    const len = guard.topAt(cfg, 15, top_entries[0..]);
    try std.testing.expectEqual(@as(usize, 2), len);
    try std.testing.expectEqual(@as(u16, 4), top_entries[0].total);
    try std.testing.expectEqual(@as(u16, 1), top_entries[0].rate_limit);
    try std.testing.expectEqual(@as(u16, 1), top_entries[0].handshake_budget);
    try std.testing.expectEqual(@as(u16, 2), top_entries[0].handshake_timeout);

    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("203.0.113.77", HandshakeFloodGuard.formatKey(top_entries[0].key, &buf));
}

test "handshake flood guard disabled records nothing" {
    var guard = HandshakeFloodGuard{};
    const cfg = HandshakeFloodGuard.settings(false, 1, 30, 120);
    const addr = ip4(.{ 192, 0, 2, 9 }, 443);

    try std.testing.expect(!guard.recordAt(addr, .handshake_timeout, cfg, 100));
    try std.testing.expect(!guard.isBlockedAt(addr, cfg, 100));

    var top_entries: [1]HandshakeFloodGuard.TopEntry = undefined;
    try std.testing.expectEqual(@as(usize, 0), guard.topAt(cfg, 100, top_entries[0..]));
}

test "handshake flood guard normalizes IPv4-mapped IPv6 addresses" {
    var guard = HandshakeFloodGuard{};
    const cfg = HandshakeFloodGuard.settings(true, 2, 30, 120);
    const native = ip4(.{ 192, 0, 2, 44 }, 443);
    const mapped_bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ [_]u8{ 192, 0, 2, 44 };
    const mapped = ip6(mapped_bytes, 443, 0, 0);

    try std.testing.expect(!guard.recordAt(native, .handshake_timeout, cfg, 100));
    try std.testing.expect(guard.recordAt(mapped, .handshake_timeout, cfg, 101));
    try std.testing.expect(guard.isBlockedAt(native, cfg, 102));
}
