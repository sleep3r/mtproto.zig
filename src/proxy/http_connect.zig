//! HTTP CONNECT proxy protocol helpers.
//!
//! Pure message serialization and parsing — no socket I/O.
//! Used by the upstream transport layer to drive the HTTP CONNECT
//! handshake through the non-blocking epoll event loop.

const std = @import("std");
const net = std.net;

// ─── Request Building ────────────────────────────────────────

/// Build an HTTP CONNECT request.
///
/// Format:
///   CONNECT host:port HTTP/1.1\r\n
///   Host: host:port\r\n
///   [Proxy-Authorization: Basic base64(user:pass)\r\n]
///   \r\n
///
/// Returns the slice of `buf` used, or empty on overflow.
pub fn buildConnectRequest(
    buf: []u8,
    addr: net.Address,
    username: ?[]const u8,
    password: ?[]const u8,
) []u8 {
    var pos: usize = 0;

    // Format the address as host:port
    var addr_buf: [64]u8 = undefined;
    const addr_str = formatAddress(addr, &addr_buf);

    // CONNECT host:port HTTP/1.1\r\n
    pos += copyInto(buf[pos..], "CONNECT ") orelse return buf[0..0];
    pos += copyInto(buf[pos..], addr_str) orelse return buf[0..0];
    pos += copyInto(buf[pos..], " HTTP/1.1\r\n") orelse return buf[0..0];

    // Host: host:port\r\n
    pos += copyInto(buf[pos..], "Host: ") orelse return buf[0..0];
    pos += copyInto(buf[pos..], addr_str) orelse return buf[0..0];
    pos += copyInto(buf[pos..], "\r\n") orelse return buf[0..0];

    // Proxy-Authorization: Basic base64(user:pass)\r\n
    if (username) |user| {
        if (user.len > 0) {
            const pass = password orelse "";

            // Encode user:pass as base64
            // Max input: 255 + 1 + 255 = 511 bytes → base64 ≤ 684 chars
            var cred_buf: [512]u8 = undefined;
            if (user.len + 1 + pass.len > cred_buf.len) return buf[0..0];

            @memcpy(cred_buf[0..user.len], user);
            cred_buf[user.len] = ':';
            @memcpy(cred_buf[user.len + 1 .. user.len + 1 + pass.len], pass);
            const cred_slice = cred_buf[0 .. user.len + 1 + pass.len];

            var b64_buf: [700]u8 = undefined;
            const encoded = std.base64.standard.Encoder.encode(&b64_buf, cred_slice);

            pos += copyInto(buf[pos..], "Proxy-Authorization: Basic ") orelse return buf[0..0];
            pos += copyInto(buf[pos..], encoded) orelse return buf[0..0];
            pos += copyInto(buf[pos..], "\r\n") orelse return buf[0..0];
        }
    }

    // Final \r\n
    pos += copyInto(buf[pos..], "\r\n") orelse return buf[0..0];

    return buf[0..pos];
}

// ─── Response Parsing ────────────────────────────────────────

pub const ParseResult = struct {
    status: u16,
    header_end: usize, // offset past the final \r\n\r\n
};

/// Parse an HTTP CONNECT response.
/// Looks for `HTTP/1.x NNN` status line and `\r\n\r\n` terminator.
/// Returns null if not enough data has been received yet.
pub fn parseResponse(data: []const u8) ?ParseResult {
    // Find the end of headers
    const header_end = findHeaderEnd(data) orelse return null;

    // Parse status line: "HTTP/1.x NNN ..."
    const status = parseStatusCode(data) orelse return null;

    return .{
        .status = status,
        .header_end = header_end,
    };
}

/// Check if we have received the complete header block.
/// Returns the offset past `\r\n\r\n`, or null.
fn findHeaderEnd(data: []const u8) ?usize {
    if (data.len < 4) return null;

    var i: usize = 0;
    while (i + 3 < data.len) : (i += 1) {
        if (data[i] == '\r' and data[i + 1] == '\n' and
            data[i + 2] == '\r' and data[i + 3] == '\n')
        {
            return i + 4;
        }
    }
    return null;
}

/// Extract HTTP status code from the first line.
/// Expects "HTTP/1.x NNN" format.
fn parseStatusCode(data: []const u8) ?u16 {
    // Find end of first line
    var line_end: usize = 0;
    while (line_end < data.len) : (line_end += 1) {
        if (data[line_end] == '\r' or data[line_end] == '\n') break;
    }
    if (line_end < 12) return null; // "HTTP/1.x NNN" minimum

    const line = data[0..line_end];

    // Must start with "HTTP/"
    if (!std.mem.startsWith(u8, line, "HTTP/")) return null;

    // Find space after version
    const space_idx = std.mem.indexOfScalar(u8, line, ' ') orelse return null;
    if (space_idx + 4 > line.len) return null;

    // Parse 3-digit status code
    const code_str = line[space_idx + 1 .. space_idx + 4];
    return std.fmt.parseInt(u16, code_str, 10) catch null;
}

/// Maximum response size we'll buffer before giving up.
/// HTTP CONNECT responses are typically < 200 bytes.
pub const max_response_size: usize = 4096;

// ─── Internal Helpers ────────────────────────────────────────

fn copyInto(dst: []u8, src: []const u8) ?usize {
    if (src.len > dst.len) return null;
    @memcpy(dst[0..src.len], src);
    return src.len;
}

fn formatAddress(addr: net.Address, buf: []u8) []const u8 {
    if (addr.any.family == std.posix.AF.INET) {
        const ip = std.mem.asBytes(&addr.in.sa.addr);
        const port = std.mem.bigToNative(u16, addr.in.sa.port);
        const str = std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{
            ip[0], ip[1], ip[2], ip[3], port,
        }) catch return "";
        return str;
    } else if (addr.any.family == std.posix.AF.INET6) {
        const port = std.mem.bigToNative(u16, addr.in6.sa.port);
        // For IPv6, use bracket notation
        var ip_buf: [46]u8 = undefined;
        var ip_len: usize = 0;
        const ip6 = &addr.in6.sa.addr;

        // Simple hex format for IPv6
        var i: usize = 0;
        while (i < 16) : (i += 2) {
            if (i > 0) {
                ip_buf[ip_len] = ':';
                ip_len += 1;
            }
            const word = @as(u16, ip6[i]) << 8 | @as(u16, ip6[i + 1]);
            const hex = std.fmt.bufPrint(ip_buf[ip_len..], "{x}", .{word}) catch return "";
            ip_len += hex.len;
        }

        const str = std.fmt.bufPrint(buf, "[{s}]:{d}", .{
            ip_buf[0..ip_len], port,
        }) catch return "";
        return str;
    }
    return "";
}

// ─── Tests ───────────────────────────────────────────────────

test "http_connect - build request without auth" {
    var buf: [1024]u8 = undefined;
    const addr = net.Address.initIp4(.{ 149, 154, 167, 51 }, 443);
    const msg = buildConnectRequest(&buf, addr, null, null);

    try std.testing.expect(msg.len > 0);
    try std.testing.expect(std.mem.startsWith(u8, msg, "CONNECT 149.154.167.51:443 HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, msg, "\r\n\r\n"));
    // No auth header
    try std.testing.expect(std.mem.indexOf(u8, msg, "Proxy-Authorization") == null);
}

test "http_connect - build request with auth" {
    var buf: [1024]u8 = undefined;
    const addr = net.Address.initIp4(.{ 149, 154, 167, 51 }, 443);
    const msg = buildConnectRequest(&buf, addr, "admin", "fr6CgjUvxFEAn5vs");

    try std.testing.expect(msg.len > 0);
    try std.testing.expect(std.mem.startsWith(u8, msg, "CONNECT 149.154.167.51:443 HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, msg, "Proxy-Authorization: Basic ") != null);
    try std.testing.expect(std.mem.endsWith(u8, msg, "\r\n\r\n"));
}

test "http_connect - build request with empty username skips auth" {
    var buf: [1024]u8 = undefined;
    const addr = net.Address.initIp4(.{ 149, 154, 167, 51 }, 443);
    const msg = buildConnectRequest(&buf, addr, "", "");

    try std.testing.expect(std.mem.indexOf(u8, msg, "Proxy-Authorization") == null);
}

test "http_connect - parse response success" {
    const data = "HTTP/1.1 200 Connection Established\r\n\r\n";
    const result = parseResponse(data);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u16, 200), result.?.status);
    try std.testing.expectEqual(data.len, result.?.header_end);
}

test "http_connect - parse response 407 proxy auth required" {
    const data = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n";
    const result = parseResponse(data);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u16, 407), result.?.status);
}

test "http_connect - parse response incomplete" {
    const data = "HTTP/1.1 200 Connection";
    const result = parseResponse(data);
    try std.testing.expect(result == null);
}

test "http_connect - parse response no terminator yet" {
    const data = "HTTP/1.1 200 Connection Established\r\n";
    const result = parseResponse(data);
    try std.testing.expect(result == null);
}

test "http_connect - parse response with pipelined payload" {
    const data = "HTTP/1.1 200 Connection Established\r\nX-Test: 1\r\n\r\n\x01\x02";
    const result = parseResponse(data);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u16, 200), result.?.status);
    try std.testing.expectEqualSlices(u8, "\x01\x02", data[result.?.header_end..]);
}

test "http_connect - address formatting ipv4" {
    var buf: [64]u8 = undefined;
    const addr = net.Address.initIp4(.{ 10, 0, 0, 1 }, 8080);
    const str = formatAddress(addr, &buf);
    try std.testing.expectEqualStrings("10.0.0.1:8080", str);
}
