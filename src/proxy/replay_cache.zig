const std = @import("std");
const posix = std.posix;
const crypto = @import("../crypto/crypto.zig");

fn nowSeconds() i64 {
    var ts: posix.timespec = undefined;
    const rc = posix.system.clock_gettime(.MONOTONIC, &ts);
    if (posix.errno(rc) != .SUCCESS) return 0;
    return @intCast(ts.sec);
}

pub const ReplayCache = struct {
    const BUCKETS = 8192;
    const MAX_PROBES = 8;
    const stale_after_s: i64 = 60 * 60;

    const Entry = struct {
        used: bool = false,
        key: u64 = 0,
        last_seen_s: i64 = 0,
    };

    hash_seed: u64 = 0,
    entries: [BUCKETS]Entry = [_]Entry{.{}} ** BUCKETS,

    pub fn init() ReplayCache {
        return .{
            .hash_seed = crypto.randomInt(u64),
        };
    }

    fn digestKey(digest: *const [32]u8) u64 {
        return std.mem.readInt(u64, digest[0..8], .little);
    }

    fn indexFor(self: *const ReplayCache, key: u64) usize {
        var x = self.hash_seed ^ key;
        x +%= 0x9E3779B97F4A7C15;
        x ^= x >> 30;
        x *%= 0xBF58476D1CE4E5B9;
        x ^= x >> 27;
        x *%= 0x94D049BB133111EB;
        x ^= x >> 31;
        return @as(usize, @intCast(x & (BUCKETS - 1)));
    }

    /// Returns true if this digest was already seen (duplicate replay),
    /// false when inserted as a new digest.
    pub fn checkAndInsert(self: *ReplayCache, digest: *const [32]u8) bool {
        const key = digestKey(digest);
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
                e.* = .{ .used = true, .key = key, .last_seen_s = now_s };
                return false;
            }

            if (e.key == key) {
                e.last_seen_s = now_s;
                return true;
            }

            if (now_s - e.last_seen_s > stale_after_s and first_stale_idx == null) {
                first_stale_idx = idx;
            }
            if (e.last_seen_s < oldest_ts) {
                oldest_ts = e.last_seen_s;
                oldest_idx = idx;
            }
        }

        const victim_idx = first_stale_idx orelse oldest_idx;
        self.entries[victim_idx] = .{ .used = true, .key = key, .last_seen_s = now_s };
        return false;
    }
};

test "replay cache detects duplicate digest" {
    var cache = ReplayCache.init();
    const digest = [_]u8{0xAB} ** 32;

    try std.testing.expect(!cache.checkAndInsert(&digest));
    try std.testing.expect(cache.checkAndInsert(&digest));
}

test "replay cache accepts distinct digests" {
    var cache = ReplayCache.init();
    const digest_a = [_]u8{0x11} ** 32;
    const digest_b = [_]u8{0x22} ** 32;

    try std.testing.expect(!cache.checkAndInsert(&digest_a));
    try std.testing.expect(!cache.checkAndInsert(&digest_b));
}
