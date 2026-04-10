//! SOCKS5 protocol helpers (RFC 1928 / RFC 1929).
//!
//! Pure message serialization and parsing — no socket I/O.
//! Used by the upstream transport layer to drive the SOCKS5
//! handshake through the non-blocking epoll event loop.

const std = @import("std");
const net = std.net;

// ─── Constants ───────────────────────────────────────────────

pub const version: u8 = 0x05;
pub const auth_version: u8 = 0x01; // RFC 1929

pub const Method = enum(u8) {
    no_auth = 0x00,
    username_password = 0x02,
    no_acceptable = 0xFF,
};

pub const Command = enum(u8) {
    connect = 0x01,
    bind = 0x02,
    udp_associate = 0x03,
};

pub const AddressType = enum(u8) {
    ipv4 = 0x01,
    domain = 0x03,
    ipv6 = 0x04,
};

pub const Reply = enum(u8) {
    succeeded = 0x00,
    general_failure = 0x01,
    connection_not_allowed = 0x02,
    network_unreachable = 0x03,
    host_unreachable = 0x04,
    connection_refused = 0x05,
    ttl_expired = 0x06,
    command_not_supported = 0x07,
    address_type_not_supported = 0x08,
    _,
};

// ─── Greeting ────────────────────────────────────────────────

/// Build a SOCKS5 greeting message.
/// If `use_auth` is true, offers both no-auth and username/password.
/// Otherwise offers only no-auth.
pub fn buildGreeting(buf: []u8, use_auth: bool) []u8 {
    if (use_auth) {
        if (buf.len < 4) return buf[0..0];
        buf[0] = version;
        buf[1] = 2; // 2 methods
        buf[2] = @intFromEnum(Method.no_auth);
        buf[3] = @intFromEnum(Method.username_password);
        return buf[0..4];
    } else {
        if (buf.len < 3) return buf[0..0];
        buf[0] = version;
        buf[1] = 1; // 1 method
        buf[2] = @intFromEnum(Method.no_auth);
        return buf[0..3];
    }
}

/// Parse a SOCKS5 greeting response (2 bytes: version + method).
/// Returns the selected method or null on invalid data.
pub fn parseGreetingResponse(data: []const u8) ?Method {
    if (data.len < 2) return null;
    if (data[0] != version) return null;
    return std.meta.intToEnum(Method, data[1]) catch .no_acceptable;
}

/// Minimum bytes needed for greeting response.
pub const greeting_response_len: usize = 2;

// ─── Username/Password Auth (RFC 1929) ───────────────────────

/// Build a username/password authentication request.
/// Returns the slice of `buf` that was written, or empty on overflow.
pub fn buildAuthRequest(buf: []u8, username: []const u8, password: []const u8) []u8 {
    const ulen = username.len;
    const plen = password.len;

    // VER(1) + ULEN(1) + UNAME(ulen) + PLEN(1) + PASSWD(plen)
    const total = 1 + 1 + ulen + 1 + plen;
    if (total > buf.len or ulen > 255 or plen > 255) return buf[0..0];

    buf[0] = auth_version;
    buf[1] = @intCast(ulen);
    @memcpy(buf[2 .. 2 + ulen], username);
    buf[2 + ulen] = @intCast(plen);
    @memcpy(buf[3 + ulen .. 3 + ulen + plen], password);
    return buf[0..total];
}

/// Parse an auth response (2 bytes: version + status).
/// Returns true if authentication succeeded.
pub fn parseAuthResponse(data: []const u8) ?bool {
    if (data.len < 2) return null;
    if (data[0] != auth_version) return null;
    return data[1] == 0x00;
}

/// Minimum bytes needed for auth response.
pub const auth_response_len: usize = 2;

// ─── CONNECT Command ─────────────────────────────────────────

/// Build a SOCKS5 CONNECT request to the given target address.
/// Returns the slice of `buf` that was written, or empty on overflow.
pub fn buildConnectRequest(buf: []u8, addr: net.Address) []u8 {
    if (addr.any.family == std.posix.AF.INET) {
        // VER(1) + CMD(1) + RSV(1) + ATYP(1) + IPv4(4) + PORT(2) = 10
        const total: usize = 10;
        if (buf.len < total) return buf[0..0];

        buf[0] = version;
        buf[1] = @intFromEnum(Command.connect);
        buf[2] = 0x00; // reserved
        buf[3] = @intFromEnum(AddressType.ipv4);

        const ip_bytes = std.mem.asBytes(&addr.in.sa.addr);
        @memcpy(buf[4..8], ip_bytes);

        const port = addr.in.sa.port; // network byte order already
        const port_bytes = std.mem.asBytes(&port);
        buf[8] = port_bytes[0];
        buf[9] = port_bytes[1];

        return buf[0..total];
    } else if (addr.any.family == std.posix.AF.INET6) {
        // VER(1) + CMD(1) + RSV(1) + ATYP(1) + IPv6(16) + PORT(2) = 22
        const total: usize = 22;
        if (buf.len < total) return buf[0..0];

        buf[0] = version;
        buf[1] = @intFromEnum(Command.connect);
        buf[2] = 0x00; // reserved
        buf[3] = @intFromEnum(AddressType.ipv6);

        @memcpy(buf[4..20], &addr.in6.sa.addr);

        const port = addr.in6.sa.port;
        const port_bytes = std.mem.asBytes(&port);
        buf[20] = port_bytes[0];
        buf[21] = port_bytes[1];

        return buf[0..total];
    }
    return buf[0..0];
}

/// Parse a SOCKS5 CONNECT response.
/// Returns the reply code, or null if not enough data.
/// The minimum response is 10 bytes (IPv4) but we only need the
/// first 4 to determine success/failure. We read the full response
/// to consume it from the stream.
pub fn parseConnectResponse(data: []const u8) ?struct { reply: Reply, consumed: usize } {
    if (data.len < 4) return null;
    if (data[0] != version) return .{ .reply = .general_failure, .consumed = data.len };

    const reply: Reply = @enumFromInt(data[1]);
    // data[2] is reserved
    const atyp = data[3];

    // Calculate total response length based on address type
    const total: usize = switch (atyp) {
        @intFromEnum(AddressType.ipv4) => 10, // 4 + 4 + 2
        @intFromEnum(AddressType.ipv6) => 22, // 4 + 16 + 2
        @intFromEnum(AddressType.domain) => blk: {
            if (data.len < 5) return null;
            const dlen: usize = data[4];
            break :blk 4 + 1 + dlen + 2;
        },
        else => return .{ .reply = .general_failure, .consumed = data.len },
    };

    if (data.len < total) return null;
    return .{ .reply = reply, .consumed = total };
}

/// Minimum bytes needed to start parsing a connect response
/// (enough to read version + reply + reserved + atyp).
pub const connect_response_min_len: usize = 4;

// ─── Tests ───────────────────────────────────────────────────

test "socks5 - greeting with auth" {
    var buf: [16]u8 = undefined;
    const msg = buildGreeting(&buf, true);
    try std.testing.expectEqual(@as(usize, 4), msg.len);
    try std.testing.expectEqual(version, msg[0]);
    try std.testing.expectEqual(@as(u8, 2), msg[1]);
    try std.testing.expectEqual(@as(u8, 0x00), msg[2]);
    try std.testing.expectEqual(@as(u8, 0x02), msg[3]);
}

test "socks5 - greeting without auth" {
    var buf: [16]u8 = undefined;
    const msg = buildGreeting(&buf, false);
    try std.testing.expectEqual(@as(usize, 3), msg.len);
    try std.testing.expectEqual(version, msg[0]);
    try std.testing.expectEqual(@as(u8, 1), msg[1]);
    try std.testing.expectEqual(@as(u8, 0x00), msg[2]);
}

test "socks5 - parse greeting response" {
    const ok = parseGreetingResponse(&[_]u8{ 0x05, 0x02 });
    try std.testing.expectEqual(Method.username_password, ok.?);

    const no_auth = parseGreetingResponse(&[_]u8{ 0x05, 0x00 });
    try std.testing.expectEqual(Method.no_auth, no_auth.?);

    const rejected = parseGreetingResponse(&[_]u8{ 0x05, 0xFF });
    try std.testing.expectEqual(Method.no_acceptable, rejected.?);

    const too_short = parseGreetingResponse(&[_]u8{0x05});
    try std.testing.expect(too_short == null);

    const bad_ver = parseGreetingResponse(&[_]u8{ 0x04, 0x00 });
    try std.testing.expect(bad_ver == null);
}

test "socks5 - auth request" {
    var buf: [512]u8 = undefined;
    const msg = buildAuthRequest(&buf, "admin", "fr6CgjUvxFEAn5vs");

    try std.testing.expectEqual(auth_version, msg[0]);
    try std.testing.expectEqual(@as(u8, 5), msg[1]); // username len
    try std.testing.expectEqualStrings("admin", msg[2..7]);
    try std.testing.expectEqual(@as(u8, 16), msg[7]); // password len
    try std.testing.expectEqualStrings("fr6CgjUvxFEAn5vs", msg[8..24]);
}

test "socks5 - parse auth response" {
    const ok = parseAuthResponse(&[_]u8{ 0x01, 0x00 });
    try std.testing.expect(ok.? == true);

    const fail = parseAuthResponse(&[_]u8{ 0x01, 0x01 });
    try std.testing.expect(fail.? == false);

    const short = parseAuthResponse(&[_]u8{0x01});
    try std.testing.expect(short == null);
}

test "socks5 - connect request ipv4" {
    var buf: [64]u8 = undefined;
    // Construct an IPv4 address: 149.154.167.51:443
    const addr = net.Address.initIp4(.{ 149, 154, 167, 51 }, 443);
    const msg = buildConnectRequest(&buf, addr);

    try std.testing.expectEqual(@as(usize, 10), msg.len);
    try std.testing.expectEqual(version, msg[0]);
    try std.testing.expectEqual(@as(u8, 0x01), msg[1]); // CONNECT
    try std.testing.expectEqual(@as(u8, 0x00), msg[2]); // RSV
    try std.testing.expectEqual(@as(u8, 0x01), msg[3]); // IPv4

    // IP bytes
    try std.testing.expectEqual(@as(u8, 149), msg[4]);
    try std.testing.expectEqual(@as(u8, 154), msg[5]);
    try std.testing.expectEqual(@as(u8, 167), msg[6]);
    try std.testing.expectEqual(@as(u8, 51), msg[7]);
}

test "socks5 - parse connect response success ipv4" {
    // Typical success response: ver=5, rep=0, rsv=0, atyp=1, ip=0.0.0.0, port=0
    const resp = [_]u8{ 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = parseConnectResponse(&resp);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(Reply.succeeded, result.?.reply);
    try std.testing.expectEqual(@as(usize, 10), result.?.consumed);
}

test "socks5 - parse connect response failure" {
    const resp = [_]u8{ 0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = parseConnectResponse(&resp);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(Reply.connection_refused, result.?.reply);
}

test "socks5 - parse connect response too short" {
    const resp = [_]u8{ 0x05, 0x00, 0x00 };
    const result = parseConnectResponse(&resp);
    try std.testing.expect(result == null);
}
