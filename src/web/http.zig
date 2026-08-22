//! Minimal HTTP/1.1 request parsing for the WEB proxy relay.
//!
//! The relay is a small public website: it serves a cover page, one bridge page, and a
//! WebSocket upgrade. It never proxies HTTP, never reads a request body, and only ever
//! answers `GET`/`HEAD`. That makes the safe subset tiny — and lets us reject the whole
//! class of smuggling tricks (bodies, `Transfer-Encoding`, duplicate `Content-Length`)
//! outright instead of implementing them correctly.
//!
//! `src/monitoring.zig` already serves `/metrics` with prefix matching and a single
//! 2 KiB read. That is fine for a loopback endpoint but cannot extract
//! `Sec-WebSocket-Key`, so the relay needs real header parsing — kept here, separate
//! from the event loop, so it is exhaustively unit-testable.

const std = @import("std");

/// Largest request head we will buffer. tdesktop bounds its own loopback HTTP boundary
/// at the same 16 KiB; browsers never send more for a plain GET.
pub const max_head_bytes: usize = 16 * 1024;

/// Headers beyond this are a client we do not want to talk to.
pub const max_headers: usize = 48;

pub const Method = enum { get, head, other };

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const ParseError = error{
    /// Malformed request line, bad version, illegal header, a body, or too many headers.
    Malformed,
    /// The head exceeded `max_head_bytes` before `\r\n\r\n` appeared.
    HeadTooLarge,
};

pub const Request = struct {
    method: Method,
    /// Request target as sent, e.g. `/?bridge=abc`.
    target: []const u8,
    /// Bytes the complete head occupies, including the terminating blank line.
    head_len: usize,
    /// HTTP/1.0 request — different keep-alive default.
    http_1_0: bool,
    headers_buf: [max_headers]Header,
    headers_len: usize,

    pub fn headers(self: *const Request) []const Header {
        return self.headers_buf[0..self.headers_len];
    }

    /// First header matching `name` (ASCII case-insensitive), or null.
    pub fn header(self: *const Request, name: []const u8) ?[]const u8 {
        for (self.headers()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    /// True when a comma-separated list header contains `token` (case-insensitive).
    /// `Connection: keep-alive, Upgrade` must match `Upgrade`, so a plain equality
    /// check on the whole value is not enough.
    pub fn headerHasToken(self: *const Request, name: []const u8, token: []const u8) bool {
        const value = self.header(name) orelse return false;
        return listHasToken(value, token);
    }

    /// Path portion of the target (everything before `?`).
    pub fn path(self: *const Request) []const u8 {
        return pathOf(self.target);
    }

    /// Raw (still percent-encoded) value of query parameter `key`, or null.
    pub fn query(self: *const Request, key: []const u8) ?[]const u8 {
        return queryValue(self.target, key);
    }

    /// Whether the connection may be reused after this response. HTTP/1.1 defaults to
    /// keep-alive and HTTP/1.0 to close; the relay honours both so its cover site
    /// behaves like an ordinary server rather than a one-shot responder.
    pub fn keepAlive(self: *const Request) bool {
        if (self.headerHasToken("connection", "close")) return false;
        if (self.http_1_0) return self.headerHasToken("connection", "keep-alive");
        return true;
    }
};

pub fn listHasToken(value: []const u8, token: []const u8) bool {
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |part| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, part, " \t"), token)) return true;
    }
    return false;
}

pub fn pathOf(target: []const u8) []const u8 {
    const q = std.mem.indexOfScalar(u8, target, '?') orelse return target;
    return target[0..q];
}

pub fn queryValue(target: []const u8, key: []const u8) ?[]const u8 {
    const q = std.mem.indexOfScalar(u8, target, '?') orelse return null;
    var it = std.mem.splitScalar(u8, target[q + 1 ..], '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], key)) return pair[eq + 1 ..];
    }
    return null;
}

/// Offset just past `\r\n\r\n`, or null while the head is still incomplete.
pub fn headEnd(buf: []const u8) ?usize {
    const idx = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse return null;
    return idx + 4;
}

/// Parse a complete request head. `buf` must contain at least one `\r\n\r\n`.
pub fn parse(buf: []const u8) ParseError!Request {
    const end = headEnd(buf) orelse {
        return if (buf.len >= max_head_bytes) error.HeadTooLarge else error.Malformed;
    };
    if (end > max_head_bytes) return error.HeadTooLarge;

    const head = buf[0 .. end - 4]; // everything before the terminating blank line
    var lines = std.mem.splitSequence(u8, head, "\r\n");

    const request_line = lines.next() orelse return error.Malformed;
    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method_text = parts.next() orelse return error.Malformed;
    const target = parts.next() orelse return error.Malformed;
    const version = parts.next() orelse return error.Malformed;
    if (parts.next() != null) return error.Malformed;
    const http_1_0 = std.mem.eql(u8, version, "HTTP/1.0");
    if (!std.mem.eql(u8, version, "HTTP/1.1") and !http_1_0) return error.Malformed;
    if (target.len == 0 or target[0] != '/') return error.Malformed;
    for (target) |c| {
        if (c <= 0x20 or c == 0x7f) return error.Malformed;
    }

    const method: Method = if (std.mem.eql(u8, method_text, "GET"))
        .get
    else if (std.mem.eql(u8, method_text, "HEAD"))
        .head
    else
        .other;

    var request = Request{
        .method = method,
        .target = target,
        .head_len = end,
        .http_1_0 = http_1_0,
        .headers_buf = undefined,
        .headers_len = 0,
    };

    while (lines.next()) |line| {
        if (line.len == 0) return error.Malformed; // an empty line inside the head
        // Obsolete line folding is a smuggling primitive; refuse it.
        if (line[0] == ' ' or line[0] == '\t') return error.Malformed;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.Malformed;
        const name = line[0..colon];
        if (name.len == 0) return error.Malformed;
        for (name) |c| {
            // RFC 9110 field-name: no spaces, no controls, no separators we care about.
            if (c <= 0x20 or c == 0x7f or c == ':') return error.Malformed;
        }
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        for (value) |c| {
            if (c < 0x20 and c != '\t') return error.Malformed;
        }
        // We serve no endpoint that takes a body, so no body may be framed. Refusing
        // `Transfer-Encoding` outright and allowing only a single `Content-Length: 0`
        // keeps the anti-smuggling property — there is nothing to consume, so nothing to
        // desynchronise — while still answering the one request an ordinary static host
        // would answer. Rejecting `Content-Length: 0` outright is a free discriminator:
        // one header, no secret, and every real site returns 200 where we would 400.
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) return error.Malformed;
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            if (!std.mem.eql(u8, value, "0")) return error.Malformed;
            if (request.header("content-length") != null) return error.Malformed;
        }
        if (request.headers_len >= max_headers) return error.Malformed;
        request.headers_buf[request.headers_len] = .{ .name = name, .value = value };
        request.headers_len += 1;
    }

    return request;
}

/// True when the request is a well-formed RFC 6455 upgrade handshake.
pub fn isWebSocketUpgrade(req: *const Request) bool {
    if (req.method != .get) return false;
    if (!req.headerHasToken("upgrade", "websocket")) return false;
    if (!req.headerHasToken("connection", "upgrade")) return false;
    const version = req.header("sec-websocket-version") orelse return false;
    if (!std.mem.eql(u8, version, "13")) return false;
    return req.header("sec-websocket-key") != null;
}

/// The **right-most** entry of a forwarded-for list.
///
/// The left-most entry is the one everybody reaches for, and it is the one an attacker
/// controls: a proxy that appends with `$proxy_add_x_forwarded_for` keeps whatever the
/// client sent and adds the address it observed, so `X-Forwarded-For: 1.2.3.4` from a
/// hostile client becomes `1.2.3.4, <real address>` and the left-most read hands the
/// attacker an arbitrary identity.
///
/// The right-most entry is always written by the hop directly in front of us — ours —
/// and cannot be forged. With a terminator that overwrites rather than appends (which is
/// what our own vhost does) the list has exactly one entry and the two readings agree.
/// A single-value header such as `CF-Connecting-IP` also lands here unchanged.
pub fn forwardedForClient(value: []const u8) ?[]const u8 {
    var it = std.mem.splitBackwardsScalar(u8, value, ',');
    const last = std.mem.trim(u8, it.next() orelse return null, " \t");
    return if (last.len == 0) null else last;
}

// ── tests ─────────────────────────────────────────────────────────────────────

const sample_get =
    "GET /?bridge=abc HTTP/1.1\r\n" ++
    "Host: proxy.example.com\r\n" ++
    "User-Agent: test\r\n" ++
    "Accept: */*\r\n" ++
    "\r\n";

test "parses a plain GET" {
    const req = try parse(sample_get);
    try std.testing.expectEqual(Method.get, req.method);
    try std.testing.expectEqualStrings("/?bridge=abc", req.target);
    try std.testing.expectEqualStrings("/", req.path());
    try std.testing.expectEqualStrings("abc", req.query("bridge").?);
    try std.testing.expectEqual(@as(?[]const u8, null), req.query("nope"));
    try std.testing.expectEqualStrings("proxy.example.com", req.header("HOST").?);
    try std.testing.expectEqual(@as(usize, 3), req.headers_len);
    try std.testing.expectEqual(sample_get.len, req.head_len);
    try std.testing.expect(req.keepAlive());
}

test "head boundary detection ignores an incomplete head" {
    try std.testing.expectEqual(@as(?usize, null), headEnd("GET / HTTP/1.1\r\nHost: x\r\n"));
    try std.testing.expectEqual(@as(?usize, 27), headEnd("GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"));
}

test "recognises a WebSocket upgrade and its variations" {
    const upgrade =
        "GET /api/v1/socket?b=cap HTTP/1.1\r\n" ++
        "Host: proxy.example.com\r\n" ++
        "Connection: keep-alive, Upgrade\r\n" ++
        "Upgrade: WebSocket\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Origin: https://proxy.example.com\r\n" ++
        "\r\n";
    const req = try parse(upgrade);
    try std.testing.expect(isWebSocketUpgrade(&req));
    try std.testing.expectEqualStrings("/api/v1/socket", req.path());
    try std.testing.expectEqualStrings("cap", req.query("b").?);
    try std.testing.expectEqualStrings("dGhlIHNhbXBsZSBub25jZQ==", req.header("sec-websocket-key").?);
}

test "an upgrade missing version 13 is not an upgrade" {
    const bad =
        "GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" ++
        "Sec-WebSocket-Version: 8\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    const req = try parse(bad);
    try std.testing.expect(!isWebSocketUpgrade(&req));
}

test "an empty body declaration is accepted, the way a static host would" {
    // Refusing this is a one-request, secret-less way to tell the relay apart from any
    // ordinary website, which is exactly what the cover page exists to prevent.
    const req = try parse("GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n");
    try std.testing.expectEqualStrings("/", req.path());
    try std.testing.expectEqual(@as(usize, 2), req.headers_len);
}

test "a duplicated content-length is still refused" {
    const dup = "GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n";
    try std.testing.expectError(error.Malformed, parse(dup));
}

test "bodies and folded headers are refused" {
    const with_len = "GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc";
    try std.testing.expectError(error.Malformed, parse(with_len));
    const chunked = "GET / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    try std.testing.expectError(error.Malformed, parse(chunked));
    const folded = "GET / HTTP/1.1\r\nHost: h\r\n  continued\r\n\r\n";
    try std.testing.expectError(error.Malformed, parse(folded));
}

test "malformed request lines are refused" {
    try std.testing.expectError(error.Malformed, parse("GET /\r\n\r\n"));
    try std.testing.expectError(error.Malformed, parse("GET / HTTP/2.0\r\n\r\n"));
    try std.testing.expectError(error.Malformed, parse("GET http://x/ HTTP/1.1\r\n\r\n"));
    try std.testing.expectError(error.Malformed, parse("GET / HTTP/1.1 extra\r\n\r\n"));
    try std.testing.expectError(error.Malformed, parse("GET / HTTP/1.1\r\nBad Header: x\r\n\r\n"));
    try std.testing.expectError(error.Malformed, parse("GET / HTTP/1.1\r\nnovalue\r\n\r\n"));
}

test "non-GET methods parse but are classified as other" {
    const req = try parse("POST / HTTP/1.1\r\nHost: h\r\n\r\n");
    try std.testing.expectEqual(Method.other, req.method);
}

test "connection close is honoured, and HTTP/1.0 defaults to close" {
    const closed = try parse("GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");
    try std.testing.expect(!closed.keepAlive());
    const old = try parse("GET / HTTP/1.0\r\nHost: h\r\n\r\n");
    try std.testing.expect(!old.keepAlive());
    const old_keep = try parse("GET / HTTP/1.0\r\nHost: h\r\nConnection: keep-alive\r\n\r\n");
    try std.testing.expect(old_keep.keepAlive());
}

test "too many headers is refused" {
    var buf: [max_head_bytes]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeAll("GET / HTTP/1.1\r\n");
    for (0..max_headers + 1) |i| try w.print("X-{d}: v\r\n", .{i});
    try w.writeAll("\r\n");
    try std.testing.expectError(error.Malformed, parse(w.buffered()));
}

test "forwarded-for takes the right-most entry, which the client cannot forge" {
    // "1.2.3.4" here is what a hostile client sent; "10.0.0.1" is what our own hop saw.
    try std.testing.expectEqualStrings("10.0.0.1", forwardedForClient("1.2.3.4, 10.0.0.1").?);
    try std.testing.expectEqualStrings("203.0.113.7", forwardedForClient("203.0.113.7").?);
    try std.testing.expectEqualStrings("2001:db8::1", forwardedForClient(" 2001:db8::1 ").?);
    try std.testing.expectEqual(@as(?[]const u8, null), forwardedForClient(""));
    try std.testing.expectEqual(@as(?[]const u8, null), forwardedForClient("1.2.3.4, "));
}

test "token list matching is case-insensitive and comma aware" {
    try std.testing.expect(listHasToken("keep-alive, Upgrade", "upgrade"));
    try std.testing.expect(listHasToken("Upgrade", "UPGRADE"));
    try std.testing.expect(!listHasToken("upgraded", "upgrade"));
}
