//! Which peers may speak the direct-obfuscated (`dd`) transport while `fake_tls_only`
//! is on, and may announce a real client address with a PROXY-protocol header.
//!
//! `fake_tls_only` is the default and the point of a TLS-camouflage proxy: a non-TLS
//! first byte is masked immediately, so the public internet never gets a `dd` responder
//! to fingerprint. But the WEB proxy relay is a *dumb byte pipe* — it carries the
//! client's own MTProxy stream, whose secret is `dd…` because Telegram Desktop rejects
//! `ee` (FakeTLS) secrets for WEB proxies. So the relay's connections, and only those,
//! must be allowed through that gate.
//!
//! Trust is decided from the **accepted** socket address, never from `peer_addr`: the
//! PROXY-protocol path overwrites `peer_addr` with an address the *client* supplied, so
//! gating on it would let anyone on the internet claim `127.0.0.1` and unlock `dd`.
//!
//! Loopback is trusted whenever `[web].enabled` is set — the relay is a local process by
//! default, and any local process could read `config.toml` anyway. A relay on another
//! host is named explicitly in `[web].relay_sources`.

const std = @import("std");
const net_helpers = @import("net_helpers.zig");

const Address = net_helpers.Address;

pub const TrustedPeers = struct {
    /// Off entirely unless `[web].enabled`.
    enabled: bool = false,
    /// Extra source addresses from `[web].relay_sources`, resolved once at startup.
    /// Ports are ignored — only the address is compared.
    extra: []const Address = &.{},

    pub fn contains(self: *const TrustedPeers, addr: Address) bool {
        if (!self.enabled) return false;
        if (isLoopback(addr)) return true;
        for (self.extra) |candidate| {
            if (sameHost(candidate, addr)) return true;
        }
        return false;
    }
};

/// True for `127.0.0.0/8`, `::1`, and the IPv4-mapped form a dual-stack `[::]` listener
/// reports for a loopback IPv4 connection (`::ffff:127.0.0.1`).
pub fn isLoopback(addr: Address) bool {
    return switch (normalize(addr)) {
        .ip4 => |v4| v4.bytes[0] == 127,
        .ip6 => |v6| blk: {
            const b = v6.bytes;
            break :blk std.mem.allEqual(u8, b[0..15], 0) and b[15] == 1;
        },
    };
}

/// Address-only equality: the relay dials from an ephemeral port, so ports never match.
pub fn sameHost(a: Address, b: Address) bool {
    const na = normalize(a);
    const nb = normalize(b);
    return switch (na) {
        .ip4 => |x| switch (nb) {
            .ip4 => |y| std.mem.eql(u8, &x.bytes, &y.bytes),
            .ip6 => false,
        },
        .ip6 => |x| switch (nb) {
            .ip6 => |y| std.mem.eql(u8, &x.bytes, &y.bytes) and x.interface.index == y.interface.index,
            .ip4 => false,
        },
    };
}

/// Collapse an IPv4-mapped IPv6 address to plain IPv4, the same normalization the flood
/// guard and the per-/24 limiter already apply.
fn normalize(addr: Address) Address {
    switch (addr) {
        .ip4 => return addr,
        .ip6 => |v6| {
            const b = v6.bytes;
            const mapped = std.mem.allEqual(u8, b[0..10], 0) and b[10] == 0xff and b[11] == 0xff;
            if (!mapped) return addr;
            return net_helpers.ip4(.{ b[12], b[13], b[14], b[15] }, v6.port);
        },
    }
}

/// Parse `[web].relay_sources` (plain IP literals, never CIDRs) into addresses.
/// Unparseable entries are skipped by the caller's warning path.
pub fn parseSources(
    allocator: std.mem.Allocator,
    sources: []const []const u8,
    on_bad: ?*const fn ([]const u8) void,
) ![]Address {
    if (sources.len == 0) return &.{};
    var list: std.ArrayList(Address) = .empty;
    errdefer list.deinit(allocator);
    for (sources) |text| {
        const trimmed = std.mem.trim(u8, text, " \t");
        const addr = Address.parse(trimmed, 0) catch {
            if (on_bad) |cb| cb(trimmed);
            continue;
        };
        try list.append(allocator, addr);
    }
    return list.toOwnedSlice(allocator);
}

// ── tests ─────────────────────────────────────────────────────────────────────

test "loopback detection covers v4, v6 and the ipv4-mapped form" {
    try std.testing.expect(isLoopback(net_helpers.ip4(.{ 127, 0, 0, 1 }, 1234)));
    try std.testing.expect(isLoopback(net_helpers.ip4(.{ 127, 4, 5, 6 }, 0)));
    try std.testing.expect(!isLoopback(net_helpers.ip4(.{ 10, 0, 0, 1 }, 0)));

    var v6_loopback: [16]u8 = [_]u8{0} ** 16;
    v6_loopback[15] = 1;
    try std.testing.expect(isLoopback(net_helpers.ip6(v6_loopback, 0, 0, 0)));

    var mapped: [16]u8 = [_]u8{0} ** 16;
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    mapped[12] = 127;
    mapped[15] = 1;
    try std.testing.expect(isLoopback(net_helpers.ip6(mapped, 0, 0, 0)));

    var mapped_public: [16]u8 = mapped;
    mapped_public[12] = 203;
    mapped_public[13] = 0;
    mapped_public[14] = 113;
    mapped_public[15] = 7;
    try std.testing.expect(!isLoopback(net_helpers.ip6(mapped_public, 0, 0, 0)));
}

test "trust is off unless the web relay is enabled" {
    const disabled = TrustedPeers{};
    try std.testing.expect(!disabled.contains(net_helpers.ip4(.{ 127, 0, 0, 1 }, 0)));

    const enabled = TrustedPeers{ .enabled = true };
    try std.testing.expect(enabled.contains(net_helpers.ip4(.{ 127, 0, 0, 1 }, 0)));
    try std.testing.expect(!enabled.contains(net_helpers.ip4(.{ 203, 0, 113, 7 }, 0)));
}

test "explicit sources are matched on address only, ignoring the ephemeral port" {
    const sources = [_][]const u8{ "10.8.0.2", "2001:db8::5", "not-an-ip" };
    const parsed = try parseSources(std.testing.allocator, &sources, null);
    defer std.testing.allocator.free(parsed);
    try std.testing.expectEqual(@as(usize, 2), parsed.len);

    const peers = TrustedPeers{ .enabled = true, .extra = parsed };
    try std.testing.expect(peers.contains(net_helpers.ip4(.{ 10, 8, 0, 2 }, 54321)));
    try std.testing.expect(!peers.contains(net_helpers.ip4(.{ 10, 8, 0, 3 }, 54321)));

    var v6: [16]u8 = [_]u8{0} ** 16;
    v6[0] = 0x20;
    v6[1] = 0x01;
    v6[2] = 0x0d;
    v6[3] = 0xb8;
    v6[15] = 0x05;
    try std.testing.expect(peers.contains(net_helpers.ip6(v6, 9999, 0, 0)));
}

test "an empty source list allocates nothing" {
    const parsed = try parseSources(std.testing.allocator, &.{}, null);
    try std.testing.expectEqual(@as(usize, 0), parsed.len);
}

test "v4 and v6 never match each other" {
    var v6: [16]u8 = [_]u8{0} ** 16;
    v6[15] = 2;
    try std.testing.expect(!sameHost(net_helpers.ip4(.{ 0, 0, 0, 2 }, 0), net_helpers.ip6(v6, 0, 0, 0)));
}
