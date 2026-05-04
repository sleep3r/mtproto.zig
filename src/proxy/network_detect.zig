const std = @import("std");
const net = std.Io.net;

const Address = net.IpAddress;

fn ip4(bytes: [4]u8, port: u16) Address {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}

pub fn parseIpv4Literal(text: []const u8) ?[4]u8 {
    var parts = std.mem.splitScalar(u8, text, '.');
    var out: [4]u8 = undefined;
    var i: usize = 0;
    while (parts.next()) |p| {
        if (i >= 4 or p.len == 0) return null;
        const n = std.fmt.parseInt(u16, p, 10) catch return null;
        if (n > 255) return null;
        out[i] = @intCast(n);
        i += 1;
    }
    if (i != 4) return null;
    return out;
}

/// Parse a user-supplied bind address string into an Address.
/// Accepts IPv4 literals like "1.2.3.4" and IPv6 literals like "::1".
pub fn parseListenAddress(text: []const u8, port: u16) ?Address {
    // Try IPv4 first
    if (parseIpv4Literal(text)) |ip4_bytes| {
        return ip4(ip4_bytes, port);
    }
    // Try IPv6 (may or may not have brackets)
    var ip6_str = text;
    if (ip6_str.len >= 2 and ip6_str[0] == '[' and ip6_str[ip6_str.len - 1] == ']') {
        ip6_str = ip6_str[1 .. ip6_str.len - 1];
    }
    return net.IpAddress.parseIp6(ip6_str, port) catch return null;
}

pub fn isRunningInNonInitNetns() bool {
    var self_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var init_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const io_ctx = std.Io.Threaded.global_single_threaded.io();

    const self_len = std.Io.Dir.readLinkAbsolute(io_ctx, "/proc/self/ns/net", &self_buf) catch return false;
    const init_len = std.Io.Dir.readLinkAbsolute(io_ctx, "/proc/1/ns/net", &init_buf) catch return false;
    const self_ns = self_buf[0..self_len];
    const init_ns = init_buf[0..init_len];

    return !std.mem.eql(u8, self_ns, init_ns);
}

pub fn parseEndpointHost(endpoint: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, endpoint, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (trimmed.len == 0) return null;

    if (trimmed[0] == '[') {
        const close_idx = std.mem.indexOfScalar(u8, trimmed, ']') orelse return null;
        const host = trimmed[1..close_idx];
        if (host.len == 0) return null;
        return host;
    }

    if (std.mem.lastIndexOfScalar(u8, trimmed, ':')) |sep| {
        if (sep == 0) return null;
        return std.mem.trim(u8, trimmed[0..sep], &[_]u8{ ' ', '\t', '\r', '\n' });
    }

    return trimmed;
}

fn resolveHostAddresses(allocator: std.mem.Allocator, host: []const u8, port: u16) ![]Address {
    if (net.IpAddress.parse(host, port)) |literal| {
        const addrs = try allocator.alloc(Address, 1);
        addrs[0] = literal;
        return addrs;
    } else |_| {}

    const host_name = try net.HostName.init(host);
    const io_ctx = std.Io.Threaded.global_single_threaded.io();

    var results_buf: [32]net.HostName.LookupResult = undefined;
    var results: std.Io.Queue(net.HostName.LookupResult) = .init(&results_buf);

    try host_name.lookup(io_ctx, &results, .{ .port = port });

    var addrs: std.ArrayList(Address) = .empty;
    defer addrs.deinit(allocator);

    while (results.getOneUncancelable(io_ctx)) |entry| {
        switch (entry) {
            .address => |addr| try addrs.append(allocator, addr),
            .canonical_name => {},
        }
    } else |_| {}

    if (addrs.items.len == 0) return error.NoAddressReturned;
    return try addrs.toOwnedSlice(allocator);
}

pub fn resolveHostnameIpv4(allocator: std.mem.Allocator, host: []const u8) ?[4]u8 {
    const addrs = resolveHostAddresses(allocator, host, 443) catch return null;
    defer allocator.free(addrs);

    for (addrs) |addr| {
        switch (addr) {
            .ip4 => |ip4_addr| return ip4_addr.bytes,
            .ip6 => {},
        }
    }

    return null;
}

pub fn parseAwgEndpointIpv4FromConfig(allocator: std.mem.Allocator, content: []const u8) ?[4]u8 {
    var in_peer = false;
    var lines = std.mem.splitScalar(u8, content, '\n');

    while (lines.next()) |raw_line| {
        const line_no_cr = std.mem.trim(u8, raw_line, "\r");
        const line = std.mem.trim(u8, line_no_cr, &[_]u8{ ' ', '\t' });
        if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;

        if (line[0] == '[' and line[line.len - 1] == ']') {
            in_peer = std.ascii.eqlIgnoreCase(line, "[Peer]");
            continue;
        }
        if (!in_peer) continue;

        const eq_pos = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq_pos], &[_]u8{ ' ', '\t' });
        if (!std.ascii.eqlIgnoreCase(key, "Endpoint")) continue;

        var value = std.mem.trim(u8, line[eq_pos + 1 ..], &[_]u8{ ' ', '\t' });
        if (std.mem.indexOfScalar(u8, value, '#')) |idx| value = value[0..idx];
        if (std.mem.indexOfScalar(u8, value, ';')) |idx| value = value[0..idx];
        value = std.mem.trim(u8, value, &[_]u8{ ' ', '\t' });
        const host = parseEndpointHost(value) orelse continue;

        if (parseIpv4Literal(host)) |ip| return ip;
        if (resolveHostnameIpv4(allocator, host)) |resolved_ip| return resolved_ip;
    }

    return null;
}

pub fn detectAwgEndpointIpv4(allocator: std.mem.Allocator) ?[4]u8 {
    const paths = [_][]const u8{
        "/etc/amnezia/amneziawg/awg0.conf",
        "/etc/amnezia/amneziawg/wg0.conf",
        "/etc/wireguard/wg0.conf",
    };

    for (paths) |path| {
        const io_ctx = std.Io.Threaded.global_single_threaded.io();
        const content = std.Io.Dir.cwd().readFileAlloc(io_ctx, path, allocator, .limited(64 * 1024)) catch continue;
        defer allocator.free(content);

        if (parseAwgEndpointIpv4FromConfig(allocator, content)) |ip| return ip;
    }

    return null;
}

pub fn detectPublicIpv4(allocator: std.mem.Allocator, comptime fetchBytes: anytype) ?[4]u8 {
    const services = [_][]const u8{
        "https://api.ipify.org",
        "https://ifconfig.me",
        "https://ipv4.icanhazip.com",
    };

    for (services) |url| {
        const stdout = fetchBytes(allocator, url) catch continue;
        const trimmed = std.mem.trim(u8, stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
        const parsed = parseIpv4Literal(trimmed);
        allocator.free(stdout);
        if (parsed) |ip| return ip;
    }

    return null;
}

pub fn formatIpv4Bytes(ip: [4]u8, buf: *[16]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch "?.?.?.?";
}

pub fn ipv4NetworkToHostBytes(ip: [4]u8) [4]u8 {
    return .{ ip[3], ip[2], ip[1], ip[0] };
}

test "parse ipv4 literal" {
    const parsed = parseIpv4Literal("179.43.141.146") orelse return error.TestExpectedEqual;
    try std.testing.expectEqual([4]u8{ 179, 43, 141, 146 }, parsed);
    try std.testing.expect(parseIpv4Literal("179.43.141") == null);
    try std.testing.expect(parseIpv4Literal("179.43.141.999") == null);
}

test "parse endpoint host" {
    try std.testing.expectEqualStrings("179.43.141.146", parseEndpointHost("179.43.141.146:41182").?);
    try std.testing.expectEqualStrings("vpn.example.com", parseEndpointHost("vpn.example.com:51820").?);
    try std.testing.expectEqualStrings("2001:db8::1", parseEndpointHost("[2001:db8::1]:41182").?);
}

test "parse awg endpoint ipv4 from config" {
    const content =
        \\[Interface]
        \\Address = 100.83.12.60/32
        \\
        \\[Peer]
        \\PublicKey = x
        \\Endpoint = 179.43.141.146:41182
    ;

    const parsed = parseAwgEndpointIpv4FromConfig(std.testing.allocator, content) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual([4]u8{ 179, 43, 141, 146 }, parsed);
}
