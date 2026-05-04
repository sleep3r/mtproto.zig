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

/// Per-/24 (IPv4) or /48 (IPv6) subnet rate limiter.
/// Fixed-size open-addressed hash table — zero heap allocation.
/// Token bucket per subnet: each second refills up to max_per_sec tokens.
pub const SubnetRateLimit = struct {
    pub const BUCKETS = 65536;
    pub const MAX_PROBES = 8;
    pub const stale_after_s: i64 = 60;

    pub const Entry = struct {
        used: bool = false,
        subnet_key: u32 = 0,
        tokens: u8 = 0,
        last_refill_s: i64 = 0,
    };

    hash_seed: u64 = 0,
    entries: [BUCKETS]Entry = [_]Entry{.{}} ** BUCKETS,

    pub fn init() SubnetRateLimit {
        return .{
            .hash_seed = crypto.randomInt(u64),
        };
    }

    fn indexFor(self: *const SubnetRateLimit, key: u32) usize {
        var x = self.hash_seed ^ @as(u64, key);
        x +%= 0x9E3779B97F4A7C15;
        x ^= x >> 30;
        x *%= 0xBF58476D1CE4E5B9;
        x ^= x >> 27;
        x *%= 0x94D049BB133111EB;
        x ^= x >> 31;
        return @as(usize, @intCast(x & (BUCKETS - 1)));
    }

    pub fn findEntry(self: *SubnetRateLimit, key: u32) ?*Entry {
        const start = self.indexFor(key);
        var probe: usize = 0;
        while (probe < MAX_PROBES) : (probe += 1) {
            const idx = (start + probe) & (BUCKETS - 1);
            const e = &self.entries[idx];
            if (!e.used) return null;
            if (e.subnet_key == key) return e;
        }
        return null;
    }

    /// Returns true if the connection is allowed, false if rate-limited.
    pub fn check(self: *SubnetRateLimit, addr: Address, max_per_sec: u8) bool {
        if (max_per_sec == 0) return true;
        const key = subnetKey(addr);
        const now_s = nowSeconds();

        const start = self.indexFor(key);
        var first_stale_idx: ?usize = null;
        var oldest_idx: usize = start;
        var oldest_ts: i64 = std.math.maxInt(i64);

        var probe: usize = 0;
        while (probe < MAX_PROBES) : (probe += 1) {
            const idx = (start + probe) & (BUCKETS - 1);
            const e = &self.entries[idx];

            if (!e.used) {
                e.* = .{ .used = true, .subnet_key = key, .tokens = max_per_sec -| 1, .last_refill_s = now_s };
                return true;
            }

            if (e.subnet_key == key) {
                const elapsed = now_s - e.last_refill_s;
                if (elapsed > 0) {
                    const refill: u16 = @intCast(@min(elapsed, 255));
                    const topped = @as(u16, e.tokens) + refill * @as(u16, max_per_sec);
                    e.tokens = @intCast(@min(@as(u16, max_per_sec), topped));
                    e.last_refill_s = now_s;
                }

                if (e.tokens > 0) {
                    e.tokens -= 1;
                    return true;
                }
                return false;
            }

            if (now_s - e.last_refill_s > stale_after_s and first_stale_idx == null) {
                first_stale_idx = idx;
            }
            if (e.last_refill_s < oldest_ts) {
                oldest_ts = e.last_refill_s;
                oldest_idx = idx;
            }
        }

        const victim_idx = first_stale_idx orelse oldest_idx;
        self.entries[victim_idx] = .{ .used = true, .subnet_key = key, .tokens = max_per_sec -| 1, .last_refill_s = now_s };
        return true;
    }

    pub fn subnetKey(addr: Address) u32 {
        return switch (addr) {
            .ip4 => |ip4_addr| @as(u32, ip4_addr.bytes[0]) << 16 |
                @as(u32, ip4_addr.bytes[1]) << 8 |
                @as(u32, ip4_addr.bytes[2]),
            .ip6 => |ip6_addr| blk: {
                const ip6_bytes = &ip6_addr.bytes;

                const is_ipv4_mapped = std.mem.eql(u8, ip6_bytes[0..10], &[_]u8{0} ** 10) and
                    ip6_bytes[10] == 0xff and ip6_bytes[11] == 0xff;
                if (is_ipv4_mapped) {
                    break :blk @as(u32, ip6_bytes[12]) << 16 |
                        @as(u32, ip6_bytes[13]) << 8 |
                        @as(u32, ip6_bytes[14]);
                }

                break :blk @as(u32, ip6_bytes[0]) << 24 |
                    @as(u32, ip6_bytes[1]) << 16 |
                    @as(u32, ip6_bytes[2]) << 8 |
                    @as(u32, ip6_bytes[3]) ^
                    (@as(u32, ip6_bytes[4]) << 8 | @as(u32, ip6_bytes[5]));
            },
        };
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

test "subnet rate limit - subnet key groups /24 IPv4" {
    // 10.0.1.5 and 10.0.1.200 should have the same /24 key
    const addr1 = ip4(.{ 10, 0, 1, 5 }, 443);
    const addr2 = ip4(.{ 10, 0, 1, 200 }, 443);
    const addr3 = ip4(.{ 10, 0, 2, 5 }, 443);

    const key1 = SubnetRateLimit.subnetKey(addr1);
    const key2 = SubnetRateLimit.subnetKey(addr2);
    const key3 = SubnetRateLimit.subnetKey(addr3);

    try std.testing.expectEqual(key1, key2); // same /24
    try std.testing.expect(key1 != key3); // different /24
}

test "subnet rate limit - IPv4-mapped IPv6 keys match native IPv4 /24" {
    // On dual-stack [::] listeners IPv4 clients arrive as ::ffff:a.b.c.d.
    // Regression: prior to the mapped-detection branch every mapped address
    // produced key = 0, collapsing the whole IPv4 internet into one bucket.
    const native_v4 = ip4(.{ 203, 0, 113, 42 }, 443);

    const mapped_bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ [_]u8{ 203, 0, 113, 42 };
    const mapped = ip6(mapped_bytes, 443, 0, 0);

    const k_native = SubnetRateLimit.subnetKey(native_v4);
    const k_mapped = SubnetRateLimit.subnetKey(mapped);
    try std.testing.expectEqual(k_native, k_mapped);

    // Two different mapped /24s must diverge (otherwise we'd still have the
    // global IPv4 collision after the fix).
    const mapped_other_bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ [_]u8{ 198, 51, 100, 1 };
    const mapped_other = ip6(mapped_other_bytes, 443, 0, 0);
    try std.testing.expect(SubnetRateLimit.subnetKey(mapped_other) != k_mapped);

    // Native IPv6 path must stay on the /48 hash (not collide with mapped form).
    const native6_bytes = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 12;
    const native6 = ip6(native6_bytes, 443, 0, 0);
    try std.testing.expect(SubnetRateLimit.subnetKey(native6) != k_mapped);
}

test "subnet rate limit - allows up to max then blocks" {
    var limiter = SubnetRateLimit{};
    const addr = ip4(.{ 192, 168, 1, 100 }, 443);

    // max_per_sec = 3 → should allow 3 then block
    // First call resets entry with tokens = max-1 = 2, returns true
    try std.testing.expect(limiter.check(addr, 3));
    // Two more with existing tokens
    try std.testing.expect(limiter.check(addr, 3));
    try std.testing.expect(limiter.check(addr, 3));
    // Now should be blocked
    try std.testing.expect(!limiter.check(addr, 3));
    try std.testing.expect(!limiter.check(addr, 3));
}

test "subnet rate limit - disabled when max_per_sec is 0" {
    var limiter = SubnetRateLimit{};
    const addr = ip4(.{ 1, 2, 3, 4 }, 443);

    // With max_per_sec = 0, always allows
    for (0..100) |_| {
        try std.testing.expect(limiter.check(addr, 0));
    }
}

test "subnet rate limit - stale entry resets" {
    var limiter = SubnetRateLimit{};
    const addr = ip4(.{ 10, 20, 30, 40 }, 443);

    // Drain tokens
    _ = limiter.check(addr, 1);
    try std.testing.expect(!limiter.check(addr, 1));

    // Make entry stale (>60s old)
    const key = SubnetRateLimit.subnetKey(addr);
    const entry = limiter.findEntry(key) orelse return error.TestExpectedEqual;
    entry.last_refill_s -= SubnetRateLimit.stale_after_s + 1;

    // Should reset and allow again
    try std.testing.expect(limiter.check(addr, 1));
}

test "subnet rate limit - different subnets are independent" {
    var limiter = SubnetRateLimit{};
    const addr_a = ip4(.{ 10, 0, 1, 100 }, 443);
    const addr_b = ip4(.{ 10, 0, 2, 100 }, 443);

    // Drain subnet A
    _ = limiter.check(addr_a, 1);
    try std.testing.expect(!limiter.check(addr_a, 1));

    // Subnet B should still work
    try std.testing.expect(limiter.check(addr_b, 1));
}
