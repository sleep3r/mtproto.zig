const std = @import("std");
const Address = std.Io.net.IpAddress;

/// Small per-worker negative cache. Never removes the last route to a DC.
pub const EndpointPenalties = struct {
    entries: [64]?Entry = .{null} ** 64,
    next: usize = 0,
    const Entry = struct { addr: Address, until_ms: i64 };

    pub fn failed(self: *EndpointPenalties, addr: Address, now: i64) void {
        for (&self.entries) |*entry| {
            if (entry.*) |old| if (old.addr.eql(&addr)) {
                entry.* = .{ .addr = addr, .until_ms = now +| 60_000 };
                return;
            };
        }
        self.entries[self.next] = .{ .addr = addr, .until_ms = now +| 60_000 };
        self.next = (self.next + 1) % self.entries.len;
    }

    pub fn succeeded(self: *EndpointPenalties, addr: Address) void {
        for (&self.entries) |*entry| if (entry.*) |old| {
            if (old.addr.eql(&addr)) entry.* = null;
        };
    }

    fn blocked(self: *const EndpointPenalties, addr: Address, now: i64) bool {
        for (self.entries) |entry| if (entry) |old| {
            if (old.addr.eql(&addr) and old.until_ms > now) return true;
        };
        return false;
    }

    pub fn prioritize(self: *const EndpointPenalties, addresses: []Address, now: i64) void {
        var insert: usize = 0;
        for (0..addresses.len) |i| {
            if (self.blocked(addresses[i], now)) continue;
            const addr = addresses[i];
            std.mem.copyBackwards(Address, addresses[insert + 1 .. i + 1], addresses[insert..i]);
            addresses[insert] = addr;
            insert += 1;
        }
    }
};

test "endpoint cooldown prefers healthy peers, expires, clears, retains last route" {
    const a: Address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 443 } };
    const b: Address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 2 }, .port = 443 } };
    var cache: EndpointPenalties = .{};
    cache.failed(a, 100);
    var list = [_]Address{ a, b };
    cache.prioritize(&list, 200);
    try std.testing.expect(list[0].eql(&b));
    try std.testing.expect(!cache.blocked(a, 60_100));
    cache.succeeded(a);
    try std.testing.expect(!cache.blocked(a, 200));
    cache.failed(b, 200);
    var sole = [_]Address{b};
    cache.prioritize(&sole, 300);
    try std.testing.expect(sole[0].eql(&b));
}
