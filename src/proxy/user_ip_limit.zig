//! Per-user concurrent unique-IP quota — `[access.user_max_ips]` (issue #381).
//!
//! A link (an `[access.users]` entry) is a shared secret: whoever has it can hand
//! it to anyone. `[access.user_max_conns]` caps how many *sockets* one user holds,
//! but a Telegram client opens several sockets on its own, so a connection cap
//! cannot express "this link is for two devices". This does: it caps how many
//! distinct client networks may hold connections for that user AT THE SAME TIME.
//!
//! Semantics are strictly concurrent, never historical. A network occupies a slot
//! for exactly as long as it has at least one live connection for that user; the
//! moment its last connection closes the slot frees. So a user may move between
//! networks freely — they just cannot be on more than N of them at once.
//!
//! Addresses are normalised before comparison (`addrKey`):
//!   - IPv4, and the IPv4-mapped form (`::ffff:a.b.c.d`) a dual-stack `[::]`
//!     listener reports, collapse to the same key — otherwise the same phone
//!     would occupy two slots depending on which listener accepted it.
//!   - Native IPv6 is keyed on its /64 prefix. IPv6 privacy extensions rotate the
//!     host part of an address constantly and SLAAC hands every device on one LAN
//!     an address in the same /64, so a /64 is the "one network" unit here; keying
//!     on the full /128 would burn a user's whole quota in minutes.
//!
//! The table is a plain linear array sized to the configured cap (caps are small —
//! single digits in practice), so acquire/release are a scan of at most `cap`
//! 16-byte comparisons. The lock matters only for `[server].workers > 1`, where
//! several SO_REUSEPORT loops share one `UserMetrics`; it is `std.Io.Mutex` because
//! Zig 0.16 has no `std.Thread.Mutex`, and it is uncontended (≈free) at workers=1.

const std = @import("std");

const net = std.Io.net;
const Address = net.IpAddress;

test "concurrent workers preserve quota references" {
    var limit = try UserIpLimit.init(std.testing.allocator, 1);
    defer limit.deinit(std.testing.allocator);
    const key = [_]u8{1} ** 16;
    try std.testing.expect(limit.acquire(key));
    var failed = std.atomic.Value(bool).init(false);
    const Worker = struct {
        fn run(shared: *UserIpLimit, errors: *std.atomic.Value(bool)) void {
            for (0..1000) |_| {
                if (shared.acquire([_]u8{1} ** 16)) {
                    shared.release([_]u8{1} ** 16);
                } else errors.store(true, .monotonic);
                if (shared.acquire([_]u8{2} ** 16)) {
                    errors.store(true, .monotonic);
                    shared.release([_]u8{2} ** 16);
                }
            }
        }
    };
    var threads: [4]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Worker.run, .{ &limit, &failed });
    for (threads) |thread| thread.join();
    try std.testing.expect(!failed.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 1), limit.activeCount());
    limit.release(key);
    try std.testing.expectEqual(@as(u32, 0), limit.activeCount());
}

pub const UserIpLimit = struct {
    /// Upper bound on a configured cap. The table is a linear scan and is allocated
    /// eagerly for every capped user, so this both bounds the memory a typo
    /// (`user1 = 100000000`) can ask for and keeps the structure honest about the
    /// range it accepts. Nobody legitimately shares one link across 256 networks.
    pub const max_cap: u32 = 256;

    pub const Slot = struct {
        key: [16]u8 = @splat(0),
        /// Live connections from this network. 0 == the slot is free.
        ///
        /// Every lookup checks this BEFORE comparing keys, and that ordering is
        /// load-bearing: `::`, `::1` and `::x` all normalise to an all-zero key,
        /// which is byte-identical to a free slot's default. Compare keys first and
        /// an IPv6 loopback client starts matching empty slots.
        refs: u32 = 0,
    };

    /// Never copy a `UserIpLimit` by value: the lock is inline but `slots` is shared,
    /// so a copy would guard the same table with a different mutex. Reach for it as
    /// `if (opt) |*limit|`, never `if (opt) |limit|`.
    slots: []Slot,
    lock: std.Io.Mutex = .init,

    fn lockIo() std.Io {
        return std.Io.Threaded.global_single_threaded.io();
    }

    /// `cap` is clamped into [1, max_cap] rather than asserted: an assert is compiled
    /// out in ReleaseFast (what `make build` ships), and a zero-length table refuses
    /// EVERY connection for that user forever — a config slip must not fail closed.
    pub fn init(allocator: std.mem.Allocator, cap: u32) !UserIpLimit {
        const slots = try allocator.alloc(Slot, std.math.clamp(cap, 1, max_cap));
        @memset(slots, .{});
        return .{ .slots = slots };
    }

    pub fn deinit(self: *UserIpLimit, allocator: std.mem.Allocator) void {
        allocator.free(self.slots);
        self.slots = &.{};
    }

    /// Normalise a client address to the unit this quota counts: a full IPv4
    /// address (native or IPv4-mapped), or an IPv6 /64 prefix.
    pub fn addrKey(addr: Address) [16]u8 {
        var key: [16]u8 = @splat(0);
        switch (addr) {
            .ip4 => |ip4_addr| {
                key[10] = 0xff;
                key[11] = 0xff;
                @memcpy(key[12..16], &ip4_addr.bytes);
            },
            .ip6 => |ip6_addr| {
                const bytes = &ip6_addr.bytes;
                const is_ipv4_mapped = std.mem.eql(u8, bytes[0..10], &[_]u8{0} ** 10) and
                    bytes[10] == 0xff and bytes[11] == 0xff;
                if (is_ipv4_mapped) {
                    key[10] = 0xff;
                    key[11] = 0xff;
                    @memcpy(key[12..16], bytes[12..16]);
                } else {
                    // /64 prefix; the host part stays zero (see the module doc).
                    @memcpy(key[0..8], bytes[0..8]);
                }
            },
        }
        return key;
    }

    /// Take a reference for `key`. Returns true when the connection is admitted:
    /// either the network already holds a slot, or a free slot was available.
    /// Returns false — taking nothing — when every slot belongs to another network.
    pub fn acquire(self: *UserIpLimit, key: [16]u8) bool {
        const io = lockIo();
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);

        var free_slot: ?*Slot = null;
        for (self.slots) |*slot| {
            if (slot.refs == 0) {
                if (free_slot == null) free_slot = slot;
                continue;
            }
            if (std.mem.eql(u8, &slot.key, &key)) {
                // Saturating: a refs overflow would free the slot for someone else.
                slot.refs +|= 1;
                return true;
            }
        }

        const slot = free_slot orelse return false;
        slot.* = .{ .key = key, .refs = 1 };
        return true;
    }

    /// Drop a reference taken by a successful `acquire` with the same key. Call it
    /// exactly once per successful acquire: a release of a key this table does not
    /// hold is ignored, but a SECOND release of a key that some other connection has
    /// since re-acquired would drop that connection's reference instead. The proxy
    /// upholds this by keying the release on `ConnectionSlot.user_ip_key`, which is
    /// captured at admission and cleared by the same `closeSlot` that releases it.
    pub fn release(self: *UserIpLimit, key: [16]u8) void {
        const io = lockIo();
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);

        for (self.slots) |*slot| {
            if (slot.refs == 0) continue;
            if (!std.mem.eql(u8, &slot.key, &key)) continue;
            slot.refs -= 1;
            if (slot.refs == 0) slot.* = .{};
            return;
        }
    }

    /// Networks currently holding at least one connection. Exported per user as
    /// `mtproto_user_unique_ips_active`.
    pub fn activeCount(self: *UserIpLimit) u32 {
        const io = lockIo();
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);

        var count: u32 = 0;
        for (self.slots) |*slot| {
            if (slot.refs != 0) count += 1;
        }
        return count;
    }
};

fn ip4(bytes: [4]u8, port: u16) Address {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}

fn ip6(bytes: [16]u8, port: u16) Address {
    return .{ .ip6 = .{
        .bytes = bytes,
        .port = port,
        .flow = 0,
        .interface = .{ .index = 0 },
    } };
}

test "user ip limit - IPv4 and its IPv4-mapped form share one key" {
    const native = ip4(.{ 203, 0, 113, 42 }, 443);
    const mapped = ip6([_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ [_]u8{ 203, 0, 113, 42 }, 443);

    try std.testing.expectEqual(
        UserIpLimit.addrKey(native),
        UserIpLimit.addrKey(mapped),
    );

    // Different hosts inside one /24 are still different networks for this quota
    // (unlike the per-subnet rate limiter, which deliberately groups a /24).
    const neighbour = ip4(.{ 203, 0, 113, 43 }, 443);
    try std.testing.expect(!std.mem.eql(
        u8,
        &UserIpLimit.addrKey(native),
        &UserIpLimit.addrKey(neighbour),
    ));

    // The port must not be part of the key: every connection from one device
    // arrives on a different source port.
    try std.testing.expectEqual(
        UserIpLimit.addrKey(native),
        UserIpLimit.addrKey(ip4(.{ 203, 0, 113, 42 }, 51234)),
    );
}

test "user ip limit - native IPv6 is keyed on the /64 prefix" {
    const prefix = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1 };
    const a = ip6(prefix ++ [_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 }, 443);
    // Same LAN, privacy-extension address — must not cost a second slot.
    const b = ip6(prefix ++ [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x00, 0x11 }, 443);
    const other_64 = ip6([_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 2 } ++ [_]u8{0} ** 8, 443);

    try std.testing.expectEqual(UserIpLimit.addrKey(a), UserIpLimit.addrKey(b));
    try std.testing.expect(!std.mem.eql(u8, &UserIpLimit.addrKey(a), &UserIpLimit.addrKey(other_64)));

    // A native IPv6 /64 must never collide with the IPv4-mapped encoding.
    const mapped = ip6([_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ [_]u8{ 203, 0, 113, 42 }, 443);
    try std.testing.expect(!std.mem.eql(u8, &UserIpLimit.addrKey(a), &UserIpLimit.addrKey(mapped)));
}

test "user ip limit - admits up to cap distinct networks, refuses the next" {
    var limit = try UserIpLimit.init(std.testing.allocator, 2);
    defer limit.deinit(std.testing.allocator);

    const a = UserIpLimit.addrKey(ip4(.{ 10, 0, 0, 1 }, 443));
    const b = UserIpLimit.addrKey(ip4(.{ 10, 0, 0, 2 }, 443));
    const c = UserIpLimit.addrKey(ip4(.{ 10, 0, 0, 3 }, 443));

    try std.testing.expect(limit.acquire(a));
    try std.testing.expect(limit.acquire(b));
    try std.testing.expectEqual(@as(u32, 2), limit.activeCount());

    // A third network is refused while the first two are live.
    try std.testing.expect(!limit.acquire(c));

    // More connections from an already-admitted network are always fine: one
    // Telegram client opens several sockets, and they must not each cost a slot.
    try std.testing.expect(limit.acquire(a));
    try std.testing.expect(limit.acquire(a));
    try std.testing.expectEqual(@as(u32, 2), limit.activeCount());
    try std.testing.expect(!limit.acquire(c));
}

test "user ip limit - a slot frees only when its last connection closes" {
    var limit = try UserIpLimit.init(std.testing.allocator, 1);
    defer limit.deinit(std.testing.allocator);

    const a = UserIpLimit.addrKey(ip4(.{ 10, 0, 0, 1 }, 443));
    const b = UserIpLimit.addrKey(ip4(.{ 10, 0, 0, 2 }, 443));

    try std.testing.expect(limit.acquire(a));
    try std.testing.expect(limit.acquire(a));

    limit.release(a);
    try std.testing.expect(!limit.acquire(b)); // one connection still holds it
    try std.testing.expectEqual(@as(u32, 1), limit.activeCount());

    limit.release(a);
    try std.testing.expectEqual(@as(u32, 0), limit.activeCount());
    try std.testing.expect(limit.acquire(b)); // the user roamed to a new network
}

test "user ip limit - releasing an unheld key cannot free a live slot" {
    var limit = try UserIpLimit.init(std.testing.allocator, 1);
    defer limit.deinit(std.testing.allocator);

    const a = UserIpLimit.addrKey(ip4(.{ 10, 0, 0, 1 }, 443));
    const b = UserIpLimit.addrKey(ip4(.{ 10, 0, 0, 2 }, 443));

    try std.testing.expect(limit.acquire(a));

    limit.release(b); // never acquired
    // The live slot must be untouched — assert it explicitly, or a release that
    // ignored its key argument entirely would satisfy every line below.
    try std.testing.expectEqual(@as(u32, 1), limit.activeCount());
    try std.testing.expect(!limit.acquire(b));

    limit.release(a);
    limit.release(a); // double release
    try std.testing.expectEqual(@as(u32, 0), limit.activeCount());

    // The table is intact after the bogus releases.
    try std.testing.expect(limit.acquire(b));
    try std.testing.expectEqual(@as(u32, 1), limit.activeCount());
}

test "user ip limit - a refused acquire takes no reference" {
    var limit = try UserIpLimit.init(std.testing.allocator, 1);
    defer limit.deinit(std.testing.allocator);

    const a = UserIpLimit.addrKey(ip4(.{ 10, 0, 0, 1 }, 443));
    const b = UserIpLimit.addrKey(ip4(.{ 10, 0, 0, 2 }, 443));

    try std.testing.expect(limit.acquire(a));
    try std.testing.expect(!limit.acquire(b));
    try std.testing.expect(!limit.acquire(b));

    // The refusals must not have left b in the table, nor bumped a's refcount:
    // one release of a frees the slot.
    limit.release(a);
    try std.testing.expectEqual(@as(u32, 0), limit.activeCount());
}

test "user ip limit - a zero cap is clamped to 1 rather than refusing everything" {
    // std.debug.assert is compiled out in ReleaseFast, so a cap of 0 reaching init
    // must not produce a zero-length table that refuses the user forever.
    var limit = try UserIpLimit.init(std.testing.allocator, 0);
    defer limit.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), limit.slots.len);
    try std.testing.expect(limit.acquire(UserIpLimit.addrKey(ip4(.{ 10, 0, 0, 1 }, 443))));
}

test "user ip limit - an oversized cap is clamped to max_cap" {
    var limit = try UserIpLimit.init(std.testing.allocator, 1_000_000);
    defer limit.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, UserIpLimit.max_cap), limit.slots.len);
}

test "user ip limit - IPv6 loopback does not match free slots" {
    // ::1 normalises to an all-zero key, the same bytes a free slot carries.
    var limit = try UserIpLimit.init(std.testing.allocator, 2);
    defer limit.deinit(std.testing.allocator);

    var v6_loopback: [16]u8 = @splat(0);
    v6_loopback[15] = 1;
    const key = UserIpLimit.addrKey(ip6(v6_loopback, 443));
    try std.testing.expectEqual([_]u8{0} ** 16, key);

    // Put a FREE slot in front of the held one, so a scan that compared keys before
    // checking refs would hit the zeroed free slot first and hand this one network a
    // second slot out of the same quota.
    const other = UserIpLimit.addrKey(ip4(.{ 10, 0, 0, 1 }, 443));
    try std.testing.expect(limit.acquire(other)); // slot 0
    try std.testing.expect(limit.acquire(key)); // slot 1
    limit.release(other); // slot 0 is free again, and its key is all zeros

    try std.testing.expect(limit.acquire(key));
    try std.testing.expectEqual(@as(u32, 1), limit.activeCount()); // one slot, not two

    // A release must find the held slot, not the free one that shares its key bytes.
    limit.release(key);
    limit.release(key);
    try std.testing.expectEqual(@as(u32, 0), limit.activeCount());
}

test "user ip limit - release frees the caller's own slot, not whichever comes first" {
    // With more than one network live, release() has to pick the right slot. A scan
    // that matched on anything but the whole key (position, or an IPv6-style /64
    // prefix, which is all zeros for every IPv4 key) would free a stranger's slot.
    var limit = try UserIpLimit.init(std.testing.allocator, 2);
    defer limit.deinit(std.testing.allocator);

    const a = UserIpLimit.addrKey(ip4(.{ 10, 0, 0, 1 }, 443));
    const b = UserIpLimit.addrKey(ip4(.{ 10, 0, 0, 2 }, 443));

    try std.testing.expect(limit.acquire(a)); // takes the first slot
    try std.testing.expect(limit.acquire(b)); // takes the second
    try std.testing.expectEqual(@as(u32, 2), limit.activeCount());

    limit.release(b);
    try std.testing.expectEqual(@as(u32, 1), limit.activeCount());

    // `a` must be the survivor: another connection from it joins the slot it already
    // owns instead of claiming the one `b` just freed.
    try std.testing.expect(limit.acquire(a));
    try std.testing.expectEqual(@as(u32, 1), limit.activeCount());

    limit.release(a);
    limit.release(a);
    try std.testing.expectEqual(@as(u32, 0), limit.activeCount());
}
