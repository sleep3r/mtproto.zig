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
