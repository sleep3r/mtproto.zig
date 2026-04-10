//! Generic tunnel abstraction for proxy transport.
//!
//! Defines the `Tunnel` metadata type that describes which tunnel
//! (if any) is active for outgoing proxy connections. This is a
//! capability/metadata struct — not a socket connector — because
//! some tunnels (e.g. AmneziaWG) work by running the proxy inside
//! a network namespace rather than wrapping individual connect() calls.
//!
//! New tunnel types (SOCKS5, HTTP CONNECT, etc.) can be added by
//! extending the `Tag` enum and implementing type-specific behavior.

const std = @import("std");

pub const Tunnel = struct {
    pub const Tag = enum {
        /// Direct connection — no tunnel active.
        none,
        /// AmneziaWG tunnel via Linux network namespace.
        /// The proxy process runs inside `tg_proxy_ns` and all
        /// outgoing TCP connects traverse the AWG interface.
        amnezia_wg,
        // Future variants:
        // socks5,
        // http_connect,
    };

    tag: Tag = .none,

    /// Human-readable name for logging and status display.
    pub fn name(self: *const Tunnel) []const u8 {
        return switch (self.tag) {
            .none => "direct",
            .amnezia_wg => "AmneziaWG",
        };
    }

    /// Whether this tunnel type requires running inside a network namespace.
    pub fn requiresNetns(self: *const Tunnel) bool {
        return switch (self.tag) {
            .none => false,
            .amnezia_wg => true,
        };
    }

    /// The network namespace name, if applicable.
    pub fn netnsName(self: *const Tunnel) ?[]const u8 {
        return switch (self.tag) {
            .none => null,
            .amnezia_wg => "tg_proxy_ns",
        };
    }

    /// Parse a tunnel type string from configuration.
    /// Returns `.none` for unrecognized values.
    pub fn fromString(s: []const u8) Tag {
        if (std.mem.eql(u8, s, "amnezia_wg") or std.mem.eql(u8, s, "amneziawg")) {
            return .amnezia_wg;
        }
        if (std.mem.eql(u8, s, "none") or std.mem.eql(u8, s, "direct")) {
            return .none;
        }
        return .none;
    }
};

// ============= Tests =============

test "tunnel - name returns human-readable string" {
    const direct = Tunnel{ .tag = .none };
    try std.testing.expectEqualStrings("direct", direct.name());

    const awg = Tunnel{ .tag = .amnezia_wg };
    try std.testing.expectEqualStrings("AmneziaWG", awg.name());
}

test "tunnel - requiresNetns" {
    const direct = Tunnel{ .tag = .none };
    try std.testing.expect(!direct.requiresNetns());

    const awg = Tunnel{ .tag = .amnezia_wg };
    try std.testing.expect(awg.requiresNetns());
}

test "tunnel - netnsName" {
    const direct = Tunnel{ .tag = .none };
    try std.testing.expect(direct.netnsName() == null);

    const awg = Tunnel{ .tag = .amnezia_wg };
    try std.testing.expectEqualStrings("tg_proxy_ns", awg.netnsName().?);
}

test "tunnel - fromString parsing" {
    try std.testing.expectEqual(Tunnel.Tag.amnezia_wg, Tunnel.fromString("amnezia_wg"));
    try std.testing.expectEqual(Tunnel.Tag.amnezia_wg, Tunnel.fromString("amneziawg"));
    try std.testing.expectEqual(Tunnel.Tag.none, Tunnel.fromString("none"));
    try std.testing.expectEqual(Tunnel.Tag.none, Tunnel.fromString("direct"));
    try std.testing.expectEqual(Tunnel.Tag.none, Tunnel.fromString("unknown_value"));
}
