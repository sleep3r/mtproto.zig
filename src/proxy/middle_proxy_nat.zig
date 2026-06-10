const std = @import("std");

const Config = @import("../config.zig").Config;
const network_detect = @import("network_detect.zig");

const log = std.log.scoped(.proxy);

pub fn detectIpv4(
    allocator: std.mem.Allocator,
    cfg: *const Config,
    comptime detect_awg: fn (std.mem.Allocator) ?[4]u8,
    comptime detect_public: fn (std.mem.Allocator, *const Config) ?[4]u8,
) ?[4]u8 {
    if (cfg.middle_proxy_nat_ip) |configured_nat_ip| {
        if (network_detect.parseIpv4Literal(configured_nat_ip)) |parsed_ip| {
            var ip_buf: [16]u8 = undefined;
            log.info("Using server.middle_proxy_nat_ip for middle-proxy NAT translation: {s}", .{network_detect.formatIpv4Bytes(parsed_ip, &ip_buf)});
            return parsed_ip;
        }
        log.info("server.middle_proxy_nat_ip='{s}' is not an IPv4 literal; falling back to egress detection", .{configured_nat_ip});
    }

    // PRIMARY: probe the public IP THROUGH the configured egress (socks5/http/tunnel/direct),
    // so the detected IP is exactly what Telegram's MiddleProxy sees — making socks/tunnel +
    // ad-tag work out of the box without a hand-set middle_proxy_nat_ip. (detect_public is
    // egress-aware; in direct/auto it's a plain probe, under socks5/http it goes through the
    // proxy, under tunnel it goes through the tunnel interface.)
    if (detect_public(allocator, cfg)) |ip| {
        var ip_buf: [16]u8 = undefined;
        log.info("Detected egress public IPv4 for middle-proxy NAT translation: {s} (upstream={s})", .{ network_detect.formatIpv4Bytes(ip, &ip_buf), @tagName(cfg.upstream_mode) });
        return ip;
    }

    // FALLBACK (tunnel only): if the through-tunnel probe couldn't reach an echo service,
    // fall back to the WireGuard endpoint IP from the tunnel config. Only valid in tunnel
    // mode — in other modes the endpoint IP has no relation to the egress IP.
    if (cfg.upstream_mode == .tunnel) {
        if (detect_awg(allocator)) |awg_ip| {
            var awg_ip_buf: [16]u8 = undefined;
            log.info("Egress probe failed; using AWG endpoint IPv4 for middle-proxy NAT translation: {s}", .{network_detect.formatIpv4Bytes(awg_ip, &awg_ip_buf)});
            return awg_ip;
        }
    }

    return null;
}

fn emptyConfig() Config {
    return .{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
    };
}

test "middle-proxy NAT detection does not derive from public_ip" {
    const Callbacks = struct {
        fn noAwg(_: std.mem.Allocator) ?[4]u8 {
            return null;
        }

        fn publicEgress(_: std.mem.Allocator, _: *const Config) ?[4]u8 {
            return .{ 203, 0, 113, 9 };
        }
    };

    var cfg = emptyConfig();
    defer cfg.users.deinit();
    defer cfg.direct_users.deinit();
    cfg.public_ip = "198.51.100.10";

    const got = detectIpv4(std.testing.allocator, &cfg, Callbacks.noAwg, Callbacks.publicEgress).?;
    try std.testing.expectEqual([4]u8{ 203, 0, 113, 9 }, got);
}

test "middle-proxy NAT detection prefers explicit override" {
    const Callbacks = struct {
        fn awgEgress(_: std.mem.Allocator) ?[4]u8 {
            return .{ 203, 0, 113, 9 };
        }

        fn publicEgress(_: std.mem.Allocator, _: *const Config) ?[4]u8 {
            return .{ 198, 51, 100, 20 };
        }
    };

    var cfg = emptyConfig();
    defer cfg.users.deinit();
    defer cfg.direct_users.deinit();
    cfg.middle_proxy_nat_ip = "192.0.2.7";

    const got = detectIpv4(std.testing.allocator, &cfg, Callbacks.awgEgress, Callbacks.publicEgress).?;
    try std.testing.expectEqual([4]u8{ 192, 0, 2, 7 }, got);
}

test "middle-proxy NAT detection prefers the egress probe over the AWG endpoint in tunnel mode" {
    // The egress probe returns the IP Telegram actually sees through the tunnel; the AWG
    // endpoint IP is only a fallback. When the probe succeeds it must win.
    const Callbacks = struct {
        fn awgEgress(_: std.mem.Allocator) ?[4]u8 {
            return .{ 203, 0, 113, 9 };
        }

        fn publicEgress(_: std.mem.Allocator, _: *const Config) ?[4]u8 {
            return .{ 198, 51, 100, 20 };
        }
    };

    var cfg = emptyConfig();
    defer cfg.users.deinit();
    defer cfg.direct_users.deinit();
    cfg.upstream_mode = .tunnel;

    const got = detectIpv4(std.testing.allocator, &cfg, Callbacks.awgEgress, Callbacks.publicEgress).?;
    try std.testing.expectEqual([4]u8{ 198, 51, 100, 20 }, got);
}

test "middle-proxy NAT detection falls back to AWG endpoint in tunnel mode when the egress probe fails" {
    const Callbacks = struct {
        fn awgEgress(_: std.mem.Allocator) ?[4]u8 {
            return .{ 203, 0, 113, 9 };
        }

        // No echo service reachable through the tunnel at startup.
        fn noPublic(_: std.mem.Allocator, _: *const Config) ?[4]u8 {
            return null;
        }
    };

    var cfg = emptyConfig();
    defer cfg.users.deinit();
    defer cfg.direct_users.deinit();
    cfg.upstream_mode = .tunnel;

    const got = detectIpv4(std.testing.allocator, &cfg, Callbacks.awgEgress, Callbacks.noPublic).?;
    try std.testing.expectEqual([4]u8{ 203, 0, 113, 9 }, got);
}

test "middle-proxy NAT detection ignores AWG endpoint when egress is not tunnelled" {
    const Callbacks = struct {
        fn awgEgress(_: std.mem.Allocator) ?[4]u8 {
            // A WG config exists on the host, but egress is direct — its endpoint IP must
            // NOT be used (it would mismatch the IP Telegram observes), and a failed direct
            // probe must not silently consult it.
            return .{ 203, 0, 113, 9 };
        }

        fn noPublic(_: std.mem.Allocator, _: *const Config) ?[4]u8 {
            return null;
        }
    };

    var cfg = emptyConfig();
    defer cfg.users.deinit();
    defer cfg.direct_users.deinit();
    cfg.upstream_mode = .auto;

    try std.testing.expectEqual(@as(?[4]u8, null), detectIpv4(std.testing.allocator, &cfg, Callbacks.awgEgress, Callbacks.noPublic));
}
