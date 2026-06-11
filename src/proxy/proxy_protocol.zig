//! HAProxy PROXY protocol (v1 text + v2 binary) header parsing.
//!
//! When the proxy sits behind a TLS-terminating load balancer (HAProxy / nginx stream),
//! the real client address is carried in a PROXY header prepended before the MTProto /
//! FakeTLS bytes. Parsing it lets per-subnet limits, flood records, and metrics attribute
//! to the real client instead of the load balancer's IP.

const std = @import("std");
const net_helpers = @import("net_helpers.zig");
const net = std.Io.net;

const Address = net_helpers.Address;

pub const ParseResult = union(enum) {
    /// Not enough bytes buffered yet — read more, then re-parse.
    incomplete,
    /// Not a valid PROXY header — caller should reject the connection.
    invalid,
    /// A complete header. `consumed` bytes must be drained; `src` is the real client
    /// address, or null for `UNKNOWN`/`LOCAL` (no address — keep the observed peer).
    ok: struct { consumed: usize, src: ?Address },
};

const v2_sig = [_]u8{ 0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a };
const v1_prefix = "PROXY";

/// Parse a PROXY protocol header from the front of `buf` (which may contain trailing
/// application bytes — only the header is consumed).
pub fn parse(buf: []const u8) ParseResult {
    if (buf.len == 0) return .incomplete;
    // v2 binary
    if (buf[0] == 0x0d) {
        if (buf.len < v2_sig.len) {
            return if (std.mem.startsWith(u8, &v2_sig, buf)) .incomplete else .invalid;
        }
        if (!std.mem.eql(u8, buf[0..v2_sig.len], &v2_sig)) return .invalid;
        return parseV2(buf);
    }
    // v1 text
    if (buf.len >= 1 and buf[0] == 'P') {
        if (buf.len < v1_prefix.len) {
            return if (std.mem.startsWith(u8, v1_prefix, buf)) .incomplete else .invalid;
        }
        if (!std.mem.startsWith(u8, buf, v1_prefix)) return .invalid;
        return parseV1(buf);
    }
    return .invalid;
}

fn parseV1(buf: []const u8) ParseResult {
    // "PROXY TCP4 <src> <dst> <sport> <dport>\r\n", max 107 bytes, terminated by CRLF.
    const max_v1 = 107;
    const crlf = std.mem.indexOf(u8, buf[0..@min(buf.len, max_v1)], "\r\n") orelse {
        return if (buf.len < max_v1) .incomplete else .invalid;
    };
    const line = buf[0..crlf];
    const consumed = crlf + 2;

    var it = std.mem.tokenizeScalar(u8, line, ' ');
    _ = it.next(); // "PROXY"
    const proto = it.next() orelse return .invalid;
    if (std.mem.eql(u8, proto, "UNKNOWN")) return .{ .ok = .{ .consumed = consumed, .src = null } };
    if (!std.mem.eql(u8, proto, "TCP4") and !std.mem.eql(u8, proto, "TCP6")) return .invalid;
    const src_ip = it.next() orelse return .invalid;
    _ = it.next() orelse return .invalid; // dst ip
    const src_port_s = it.next() orelse return .invalid;
    const src_port = std.fmt.parseInt(u16, src_port_s, 10) catch return .invalid;

    const addr = net.IpAddress.parse(src_ip, src_port) catch return .invalid;
    return .{ .ok = .{ .consumed = consumed, .src = addr } };
}

fn parseV2(buf: []const u8) ParseResult {
    // 12-byte sig, 1 byte ver/cmd, 1 byte fam/proto, 2 bytes addr-len, then addr block.
    if (buf.len < 16) return .incomplete;
    const ver_cmd = buf[12];
    if (ver_cmd >> 4 != 0x2) return .invalid; // version must be 2
    const cmd = ver_cmd & 0x0f; // 0=LOCAL, 1=PROXY
    const fam = buf[13];
    const addr_len = std.mem.readInt(u16, buf[14..16], .big);
    const total = 16 + @as(usize, addr_len);
    if (buf.len < total) return .incomplete;

    if (cmd == 0) return .{ .ok = .{ .consumed = total, .src = null } }; // LOCAL: no address

    const ab = buf[16 .. 16 + addr_len];
    switch (fam) {
        0x11 => { // TCP over IPv4
            if (ab.len < 12) return .invalid;
            const ip: [4]u8 = ab[0..4].*;
            const port = std.mem.readInt(u16, ab[8..10], .big);
            return .{ .ok = .{ .consumed = total, .src = net_helpers.ip4(ip, port) } };
        },
        0x21 => { // TCP over IPv6
            if (ab.len < 36) return .invalid;
            const ip: [16]u8 = ab[0..16].*;
            const port = std.mem.readInt(u16, ab[32..34], .big);
            return .{ .ok = .{ .consumed = total, .src = net_helpers.ip6(ip, port, 0, 0) } };
        },
        else => return .{ .ok = .{ .consumed = total, .src = null } }, // unspec / unix: keep peer
    }
}

test "parse v1 TCP4" {
    const r = parse("PROXY TCP4 1.2.3.4 5.6.7.8 12345 443\r\nGET /");
    try std.testing.expect(r == .ok);
    try std.testing.expectEqual(@as(usize, 38), r.ok.consumed);
    try std.testing.expect(r.ok.src != null);
    try std.testing.expectEqual(@as(u16, 12345), r.ok.src.?.getPort());
}

test "parse v1 UNKNOWN keeps no address" {
    const r = parse("PROXY UNKNOWN\r\nx");
    try std.testing.expect(r == .ok);
    try std.testing.expectEqual(@as(?Address, null), r.ok.src);
}

test "parse v1 incomplete then invalid" {
    try std.testing.expect(parse("PROXY TCP4 1.2.3.4") == .incomplete);
    try std.testing.expect(parse("HELLO WORLD\r\n") == .invalid);
}

test "parse v2 TCP4" {
    var b: [16 + 12]u8 = undefined;
    @memcpy(b[0..12], &v2_sig);
    b[12] = 0x21; // ver 2, cmd PROXY
    b[13] = 0x11; // TCP/IPv4
    std.mem.writeInt(u16, b[14..16], 12, .big);
    b[16] = 9;
    b[17] = 8;
    b[18] = 7;
    b[19] = 6; // src ip 9.8.7.6
    @memset(b[20..24], 0); // dst ip
    std.mem.writeInt(u16, b[24..26], 4444, .big); // src port
    std.mem.writeInt(u16, b[26..28], 443, .big); // dst port
    const r = parse(&b);
    try std.testing.expect(r == .ok);
    try std.testing.expectEqual(@as(usize, 28), r.ok.consumed);
    try std.testing.expectEqual(@as(u16, 4444), r.ok.src.?.getPort());
}

test "parse v2 incomplete" {
    try std.testing.expect(parse(v2_sig[0..8]) == .incomplete);
}
