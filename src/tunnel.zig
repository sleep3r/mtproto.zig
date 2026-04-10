//! Generic tunnel abstraction for proxy transport.
//!
//! Defines the `Tunnel` metadata type that describes which tunnel
//! (if any) is active for outgoing proxy connections. This is a
//! capability/metadata struct — not a socket connector — because
//! network-level tunnels (AmneziaWG, WireGuard, ...) are configured
//! by mtbuddy and selected at runtime via socket policy routing marks.
//! The specific VPN type is an mtbuddy concern.
//!
//! Socket-level proxy types (SOCKS5, HTTP CONNECT) are also tracked
//! here for logging and status display, even though their actual I/O
//! is handled by the upstream transport layer.

const std = @import("std");

pub const Tunnel = struct {
    pub const Tag = enum {
        /// Direct connection — no tunnel active.
        none,
        /// VPN tunnel selected via socket policy routing (SO_MARK).
        tunnel,
        /// SOCKS5 proxy — socket-level upstream wrapping.
        socks5,
        /// HTTP CONNECT proxy — socket-level upstream wrapping.
        http_connect,
    };

    tag: Tag = .none,

    /// Human-readable name for logging and status display.
    pub fn name(self: *const Tunnel) []const u8 {
        return switch (self.tag) {
            .none => "direct",
            .tunnel => "VPN tunnel",
            .socks5 => "SOCKS5",
            .http_connect => "HTTP CONNECT",
        };
    }

    /// Whether this tunnel type requires running inside a network namespace.
    pub fn requiresNetns(self: *const Tunnel) bool {
        return switch (self.tag) {
            .none => false,
            .tunnel => false,
            .socks5 => false,
            .http_connect => false,
        };
    }

    /// The network namespace name, if applicable.
    pub fn netnsName(self: *const Tunnel) ?[]const u8 {
        return switch (self.tag) {
            .none => null,
            .tunnel => null,
            .socks5 => null,
            .http_connect => null,
        };
    }

    /// Parse a tunnel type string from configuration.
    /// Returns `.none` for unrecognized values.
    pub fn fromString(s: []const u8) Tag {
        if (std.mem.eql(u8, s, "tunnel")) {
            return .tunnel;
        }
        // Backward compat: specific VPN names map to generic .tunnel
        if (std.mem.eql(u8, s, "amnezia_wg") or std.mem.eql(u8, s, "amneziawg")) {
            return .tunnel;
        }
        if (std.mem.eql(u8, s, "wireguard") or std.mem.eql(u8, s, "wg")) {
            return .tunnel;
        }
        if (std.mem.eql(u8, s, "socks5")) {
            return .socks5;
        }
        if (std.mem.eql(u8, s, "http") or std.mem.eql(u8, s, "http_connect")) {
            return .http_connect;
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

    const vpn = Tunnel{ .tag = .tunnel };
    try std.testing.expectEqualStrings("VPN tunnel", vpn.name());

    const socks = Tunnel{ .tag = .socks5 };
    try std.testing.expectEqualStrings("SOCKS5", socks.name());

    const http = Tunnel{ .tag = .http_connect };
    try std.testing.expectEqualStrings("HTTP CONNECT", http.name());
}

test "tunnel - requiresNetns" {
    const direct = Tunnel{ .tag = .none };
    try std.testing.expect(!direct.requiresNetns());

    const vpn = Tunnel{ .tag = .tunnel };
    try std.testing.expect(!vpn.requiresNetns());

    const socks = Tunnel{ .tag = .socks5 };
    try std.testing.expect(!socks.requiresNetns());

    const http = Tunnel{ .tag = .http_connect };
    try std.testing.expect(!http.requiresNetns());
}

test "tunnel - netnsName" {
    const direct = Tunnel{ .tag = .none };
    try std.testing.expect(direct.netnsName() == null);

    const vpn = Tunnel{ .tag = .tunnel };
    try std.testing.expect(vpn.netnsName() == null);

    const socks = Tunnel{ .tag = .socks5 };
    try std.testing.expect(socks.netnsName() == null);

    const http = Tunnel{ .tag = .http_connect };
    try std.testing.expect(http.netnsName() == null);
}

test "tunnel - fromString parsing" {
    try std.testing.expectEqual(Tunnel.Tag.tunnel, Tunnel.fromString("tunnel"));
    try std.testing.expectEqual(Tunnel.Tag.tunnel, Tunnel.fromString("amnezia_wg"));
    try std.testing.expectEqual(Tunnel.Tag.tunnel, Tunnel.fromString("amneziawg"));
    try std.testing.expectEqual(Tunnel.Tag.tunnel, Tunnel.fromString("wireguard"));
    try std.testing.expectEqual(Tunnel.Tag.tunnel, Tunnel.fromString("wg"));
    try std.testing.expectEqual(Tunnel.Tag.socks5, Tunnel.fromString("socks5"));
    try std.testing.expectEqual(Tunnel.Tag.http_connect, Tunnel.fromString("http"));
    try std.testing.expectEqual(Tunnel.Tag.http_connect, Tunnel.fromString("http_connect"));
    try std.testing.expectEqual(Tunnel.Tag.none, Tunnel.fromString("none"));
    try std.testing.expectEqual(Tunnel.Tag.none, Tunnel.fromString("direct"));
    try std.testing.expectEqual(Tunnel.Tag.none, Tunnel.fromString("unknown_value"));
}
