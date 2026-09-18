//! Bounded, short-lived carrier credentials; never derived from the user's secret.
const std = @import("std");

pub const Token = [43]u8;
pub const lifetime_ms: i64 = 120_000;
const Entry = struct { token: Token, user: []const u8, expires: i64, active: ?i32 = null };
pub const Store = struct {
    entries: std.ArrayList(Entry) = .empty,
    pub fn deinit(self: *Store, allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
    }
    pub fn issue(self: *Store, allocator: std.mem.Allocator, user: []const u8, now: i64, limit: usize) !Token {
        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (self.entries.items[i].expires <= now) {
                _ = self.entries.swapRemove(i);
            } else {
                i += 1;
            }
        }
        if (self.entries.items.len >= limit) return error.Capacity;
        var entropy: [32]u8 = undefined;
        try std.Io.randomSecure(std.Io.Threaded.global_single_threaded.io(), &entropy);
        var token: Token = undefined;
        _ = std.base64.url_safe_no_pad.Encoder.encode(&token, &entropy);
        try self.entries.append(allocator, .{ .token = token, .user = user, .expires = now + lifetime_ms });
        return token;
    }
    pub fn acquire(self: *Store, text: []const u8, fd: i32, now: i64) ?[]const u8 {
        if (text.len != 43) return null;
        var matched: ?usize = null;
        for (self.entries.items, 0..) |entry, i| {
            if (std.crypto.timing_safe.eql(Token, text[0..43].*, entry.token)) matched = i;
        }
        const entry = &self.entries.items[matched orelse return null];
        if (now >= entry.expires or entry.active != null) return null;
        entry.active = fd;
        return entry.user;
    }
    pub fn release(self: *Store, text: []const u8, fd: i32, consumed: bool) void {
        for (self.entries.items, 0..) |*entry, i| {
            if (entry.active == fd and std.mem.eql(u8, text, &entry.token)) {
                if (consumed) {
                    _ = self.entries.swapRemove(i);
                } else {
                    entry.active = null;
                }
                return;
            }
        }
    }
};

test "carrier credentials expire and cannot attach twice or resume an adopted session" {
    const a = std.testing.allocator;
    var store = Store{};
    defer store.deinit(a);
    const token = try store.issue(a, "alice", 1000, 4);
    try std.testing.expectEqualStrings("alice", store.acquire(&token, 8, 1001).?);
    try std.testing.expect(store.acquire(&token, 9, 1002) == null);
    store.release(&token, 8, false);
    try std.testing.expectEqualStrings("alice", store.acquire(&token, 9, 1003).?);
    store.release(&token, 9, true);
    try std.testing.expect(store.acquire(&token, 10, 1004) == null);
    const fresh = try store.issue(a, "bob", 2000, 4);
    try std.testing.expect(store.acquire(&fresh, 11, 2000 + lifetime_ms) == null);
}

test "expired entries release issuance capacity and failed acquisition does not consume" {
    const a = std.testing.allocator;
    var store = Store{};
    defer store.deinit(a);
    const first = try store.issue(a, "alice", 0, 1);
    try std.testing.expectError(error.Capacity, store.issue(a, "bob", 1, 1));
    try std.testing.expect(store.acquire("bad", 1, 2) == null);
    const next = try store.issue(a, "bob", lifetime_ms, 1);
    try std.testing.expect(!std.mem.eql(u8, &first, &next));
    try std.testing.expectEqualStrings("bob", store.acquire(&next, 1, lifetime_ms + 1).?);
}
