const std = @import("std");

const Config = @import("../config.zig").Config;
const network_detect = @import("network_detect.zig");

const log = std.log.scoped(.proxy);

pub fn detectIpv4(
    allocator: std.mem.Allocator,
    cfg: *const Config,
    comptime detect_awg: fn (std.mem.Allocator) ?[4]u8,
    comptime detect_public: fn (std.mem.Allocator) ?[4]u8,
) ?[4]u8 {
    if (cfg.middle_proxy_nat_ip) |configured_nat_ip| {
        if (network_detect.parseIpv4Literal(configured_nat_ip)) |parsed_ip| {
            var ip_buf: [16]u8 = undefined;
            log.info("Using server.middle_proxy_nat_ip for middle-proxy NAT translation: {s}", .{network_detect.formatIpv4Bytes(parsed_ip, &ip_buf)});
            return parsed_ip;
        }
        log.info("server.middle_proxy_nat_ip='{s}' is not an IPv4 literal; falling back to AWG/public detection", .{configured_nat_ip});
    }

    if (detect_awg(allocator)) |awg_ip| {
        var awg_ip_buf: [16]u8 = undefined;
        log.info("Using AWG endpoint IPv4 for middle-proxy NAT translation: {s}", .{network_detect.formatIpv4Bytes(awg_ip, &awg_ip_buf)});
        return awg_ip;
    }

    if (detect_public(allocator)) |ip| {
        var ip_buf: [16]u8 = undefined;
        log.info("Detected public IPv4 for middle-proxy NAT translation: {s}", .{network_detect.formatIpv4Bytes(ip, &ip_buf)});
        return ip;
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

        fn publicEgress(_: std.mem.Allocator) ?[4]u8 {
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

        fn publicEgress(_: std.mem.Allocator) ?[4]u8 {
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

test "middle-proxy NAT detection prefers AWG endpoint before public egress probe" {
    const Callbacks = struct {
        fn awgEgress(_: std.mem.Allocator) ?[4]u8 {
            return .{ 203, 0, 113, 9 };
        }

        fn publicEgress(_: std.mem.Allocator) ?[4]u8 {
            return .{ 198, 51, 100, 20 };
        }
    };

    var cfg = emptyConfig();
    defer cfg.users.deinit();
    defer cfg.direct_users.deinit();

    const got = detectIpv4(std.testing.allocator, &cfg, Callbacks.awgEgress, Callbacks.publicEgress).?;
    try std.testing.expectEqual([4]u8{ 203, 0, 113, 9 }, got);
}
