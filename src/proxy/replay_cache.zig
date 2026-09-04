const std = @import("std");
const posix = std.posix;
const crypto = @import("../crypto/crypto.zig");

test "concurrent workers admit the same replay digest exactly once" {
    const cache = try std.testing.allocator.create(ReplayCache);
    defer std.testing.allocator.destroy(cache);
    cache.* = ReplayCache.init();
    var admitted = std.atomic.Value(u32).init(0);
    const Worker = struct {
        fn run(shared: *ReplayCache, count: *std.atomic.Value(u32)) void {
            const digest = [_]u8{0x7b} ** 32;
            for (0..1000) |_| {
                if (!shared.checkAndInsert(&digest)) _ = count.fetchAdd(1, .monotonic);
            }
        }
    };
    var threads: [4]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Worker.run, .{ cache, &admitted });
    for (threads) |thread| thread.join();
    try std.testing.expectEqual(@as(u32, 1), admitted.load(.monotonic));
}

fn nowSeconds() i64 {
    var ts: posix.timespec = undefined;
    const rc = posix.system.clock_gettime(.MONOTONIC, &ts);
    if (posix.errno(rc) != .SUCCESS) return 0;
    return @intCast(ts.sec);
}

pub const ReplayCache = struct {
    const BUCKETS = 8192;
    const MAX_PROBES = 8;
    const stale_after_s: i64 = 240;

    const Entry = struct {
        used: bool = false,
        key: u64 = 0,
        last_seen_s: i64 = 0,
    };

    hash_seed: u64 = 0,
    entries: [BUCKETS]Entry = [_]Entry{.{}} ** BUCKETS,
    /// Guards the table. The replay cache is shared ProxyState read+written by
    /// every worker on the handshake path (not the per-byte relay path), so under
    /// the SO_REUSEPORT multi-worker model N threads call checkAndInsert
    /// concurrently — without this lock that is a data race on the bucket array
    /// and a security regression (a replay landing on another worker could slip
    /// through). std.Io.Mutex is a real cross-thread futex mutex (Zig 0.16 has no
    /// std.Thread.Mutex); uncontended (≈free) at workers=1.
    lock: std.Io.Mutex = .init,

    fn lockIo() std.Io {
        return std.Io.Threaded.global_single_threaded.io();
    }

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
        return self.checkAndInsertAt(digest, nowSeconds());
    }

    fn checkAndInsertAt(self: *ReplayCache, digest: *const [32]u8, now_s: i64) bool {
        const io = lockIo();
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);

        const key = digestKey(digest);
        const start = self.indexFor(key);

        var first_stale_idx: ?usize = null;

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
        }

        // Saturation must reject the new handshake, never forget a live digest.
        const victim_idx = first_stale_idx orelse return true;
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

test "saturated replay probe window never evicts a live entry" {
    var cache = ReplayCache.init();
    const digest = [_]u8{0xab} ** 32;
    const start = cache.indexFor(ReplayCache.digestKey(&digest));
    for (0..ReplayCache.MAX_PROBES) |i| {
        cache.entries[(start + i) & (ReplayCache.BUCKETS - 1)] = .{ .used = true, .key = i, .last_seen_s = nowSeconds() };
    }
    try std.testing.expect(cache.checkAndInsert(&digest));
    try std.testing.expectEqual(@as(u64, 0), cache.entries[start].key);
    const expired_now = nowSeconds() + 241;
    try std.testing.expect(!cache.checkAndInsertAt(&digest, expired_now));
    try std.testing.expect(cache.checkAndInsertAt(&digest, expired_now));
}

test "replay cache accepts distinct digests" {
    var cache = ReplayCache.init();
    const digest_a = [_]u8{0x11} ** 32;
    const digest_b = [_]u8{0x22} ** 32;

    try std.testing.expect(!cache.checkAndInsert(&digest_a));
    try std.testing.expect(!cache.checkAndInsert(&digest_b));
}

test "replay cache - property fuzz and replay invariants" {
    var cache = ReplayCache.init();
    var prng = std.Random.DefaultPrng.init(0xA11CECA6E);
    const random = prng.random();

    var digest: [32]u8 = undefined;
    for (0..6000) |i| {
        random.bytes(&digest);

        if ((i % 11) == 0) {
            // Force explicit replay path.
            digest = [_]u8{0xAB} ** 32;
        }

        const first = cache.checkAndInsert(&digest);
        const second = cache.checkAndInsert(&digest);
        try std.testing.expect(second);
        if (!first) {
            // First observation can be either new(false) or existing(true) under collisions;
            // second call must still be treated as replay.
            try std.testing.expect(cache.checkAndInsert(&digest));
        }
    }
}
