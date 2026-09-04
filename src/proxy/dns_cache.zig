//! Owned background DNS refresh. Event loops only copy bounded snapshots.
const std = @import("std");
const builtin = @import("builtin");
const net = @import("net_helpers.zig");

pub const Cache = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    mutex: std.Io.Mutex = .init,
    stopping: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,
    const Entry = struct { host: []const u8, port: u16, addresses: net.AddressCandidates, literal: bool };
    const Resolver = *const fn (std.mem.Allocator, []const u8, u16) anyerror!net.AddressList;

    fn io() std.Io {
        return std.Io.Threaded.global_single_threaded.io();
    }

    pub fn create(allocator: std.mem.Allocator) !*Cache {
        const self = try allocator.create(Cache);
        self.* = .{ .allocator = allocator };
        return self;
    }

    /// Registration is startup-only; the worker never resizes the entries array.
    pub fn add(self: *Cache, host: []const u8, port: u16, initial: net.AddressCandidates) !usize {
        std.debug.assert(self.thread == null);
        const owned = try self.allocator.dupe(u8, host);
        errdefer self.allocator.free(owned);
        const literal = if (net.Address.parse(host, port)) |_| true else |_| false;
        try self.entries.append(self.allocator, .{ .host = owned, .port = port, .addresses = initial, .literal = literal });
        return self.entries.items.len - 1;
    }

    pub fn start(self: *Cache) !void {
        std.debug.assert(self.thread == null);
        for (self.entries.items) |entry| {
            if (!entry.literal) {
                self.thread = try std.Thread.spawn(.{}, run, .{self});
                return;
            }
        }
    }

    pub fn snapshot(self: *Cache, id: usize) net.AddressCandidates {
        self.mutex.lockUncancelable(io());
        defer self.mutex.unlock(io());
        return self.entries.items[id].addresses;
    }

    pub fn destroy(self: *Cache) void {
        self.stopping.store(true, .release);
        if (self.thread) |thread| thread.join();
        for (self.entries.items) |entry| self.allocator.free(entry.host);
        self.entries.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    fn resolve(allocator: std.mem.Allocator, host: []const u8, port: u16) !net.AddressList {
        // Production is Linux. NSS resolution in a deadline-bounded child also
        // bounds shutdown even if the system resolver is wedged (five seconds).
        return if (builtin.os.tag == .linux) net.lookupViaGetent(allocator, host, port) else net.getAddressList(allocator, host, port);
    }

    fn refresh(self: *Cache, resolver: Resolver) void {
        for (self.entries.items, 0..) |entry, id| {
            if (self.stopping.load(.acquire)) return;
            if (entry.literal) continue;
            const list = resolver(self.allocator, entry.host, entry.port) catch continue;
            defer list.deinit();
            if (list.addrs.len == 0) continue; // Keep the last good answer.
            // Stable family preference matches startup resolution.
            std.mem.sort(net.Address, list.addrs, {}, struct {
                fn less(_: void, a: net.Address, b: net.Address) bool {
                    return !net.isIpv6(a) and net.isIpv6(b);
                }
            }.less);
            self.mutex.lockUncancelable(io());
            self.entries.items[id].addresses = .init(list.addrs);
            self.mutex.unlock(io());
        }
    }

    fn run(self: *Cache) void {
        while (!self.stopping.load(.acquire)) {
            for (0..600) |_| {
                if (self.stopping.load(.acquire)) return;
                std.Io.sleep(io(), .fromMilliseconds(100), .awake) catch return;
            }
            self.refresh(resolve);
        }
    }
};

test "DNS refresh replaces snapshots, preserves last good answers, skips literals" {
    const cache = try Cache.create(std.testing.allocator);
    defer cache.destroy();
    const original = net.AddressCandidates.init(&.{net.ip4(.{ 192, 0, 2, 1 }, 443)});
    const id = try cache.add("example.test", 443, original);
    const literal_id = try cache.add("127.0.0.1", 443, original);
    const frozen = cache.snapshot(id);
    const Fake = struct {
        fn good(a: std.mem.Allocator, _: []const u8, port: u16) !net.AddressList {
            const addresses = try a.alloc(net.Address, 2);
            addresses[0] = net.ip6(@splat(1), port, 0, 0);
            addresses[1] = net.ip4(.{ 192, 0, 2, 2 }, port);
            return .{ .allocator = a, .addrs = addresses };
        }
        fn bad(_: std.mem.Allocator, _: []const u8, _: u16) !net.AddressList {
            return error.ResolveFailed;
        }
        fn empty(a: std.mem.Allocator, _: []const u8, _: u16) !net.AddressList {
            return .{ .allocator = a, .addrs = try a.alloc(net.Address, 0) };
        }
    };
    cache.refresh(Fake.good);
    const updated = cache.snapshot(id);
    try std.testing.expectEqual(@as(u8, 2), updated.len);
    try std.testing.expect(net.addressEql(updated.addresses[0], net.ip4(.{ 192, 0, 2, 2 }, 443)));
    try std.testing.expect(net.addressEql(frozen.addresses[0], original.addresses[0]));
    try std.testing.expect(net.addressEql(cache.snapshot(literal_id).addresses[0], original.addresses[0]));
    cache.refresh(Fake.bad);
    cache.refresh(Fake.empty);
    try std.testing.expectEqual(@as(u8, 2), cache.snapshot(id).len);
    cache.stopping.store(true, .release);
    cache.refresh(Fake.good);
}

test "DNS worker joins on shutdown and literal-only caches need no worker" {
    const cache = try Cache.create(std.testing.allocator);
    _ = try cache.add("example.test", 443, .{});
    try cache.start();
    cache.destroy();
    const literals = try Cache.create(std.testing.allocator);
    defer literals.destroy();
    _ = try literals.add("127.0.0.1", 443, .{});
    try literals.start();
    try std.testing.expect(literals.thread == null);
}

test "DNS snapshots remain coherent across concurrent readers and refresh" {
    const cache = try Cache.create(std.testing.allocator);
    defer cache.destroy();
    const initial = net.AddressCandidates.init(&.{net.ip4(.{ 192, 0, 2, 1 }, 443)});
    _ = try cache.add("example.test", 443, initial);
    const Reader = struct {
        fn run(c: *Cache) void {
            for (0..1000) |_| {
                const snapshot = c.snapshot(0);
                std.debug.assert(snapshot.len == 1);
                std.debug.assert(snapshot.addresses[0].getPort() == 443);
                std.debug.assert(!net.isIpv6(snapshot.addresses[0]));
            }
        }
        fn resolve(a: std.mem.Allocator, _: []const u8, port: u16) !net.AddressList {
            const addresses = try a.alloc(net.Address, 1);
            addresses[0] = net.ip4(.{ 192, 0, 2, 2 }, port);
            return .{ .allocator = a, .addrs = addresses };
        }
    };
    const first = try std.Thread.spawn(.{}, Reader.run, .{cache});
    defer first.join();
    const second = try std.Thread.spawn(.{}, Reader.run, .{cache});
    defer second.join();
    for (0..100) |_| cache.refresh(Reader.resolve);
    try std.testing.expect(net.addressEql(cache.snapshot(0).addresses[0], net.ip4(.{ 192, 0, 2, 2 }, 443)));
}
