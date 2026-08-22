//! WEB proxy relay frames — the v1 multiplexing format shared with Telegram Desktop.
//!
//! Telegram Desktop 7.1 added a fourth proxy type (`WEB`, serialized type code `4`).
//! It is an ordinary MTProxy whose *carrier* is a browser: a hidden native WebView
//! loads `https://<host>/?bridge=<capability>`, and the page shuttles opaque frames
//! between the client and this relay over same-origin HTTPS. The relay then dials a
//! stock MTProxy — us — and pipes the bytes through untouched.
//!
//! Everything on the wire here is defined by tdesktop's `docs/web-proxy-plan.md` §6
//! and implemented by `Telegram/SourceFiles/mtproto/web_proxy/web_proxy_frame.cpp`.
//! We are the server half, so this module must be byte-exact:
//!
//!     type:u8 | stream_id:u24 | length:u32 | payload:length      (all big-endian)
//!
//! A carrier message carries one or more *complete* frames; a trailing partial frame
//! or an empty message is a protocol error on the client side, so we never emit one.
//!
//! Nothing here allocates or does I/O — `relay.zig` owns all buffers.

const std = @import("std");

/// Fixed frame header size: type(1) + stream_id(3) + length(4).
pub const header_size: usize = 8;

/// Maximum payload of a single frame. tdesktop rejects anything larger
/// (`kMaxFramePayload`), so a bigger DATA must be split by the sender.
pub const max_payload: usize = 1024 * 1024;

/// Maximum frames tdesktop will parse out of one carrier message
/// (`kMaxBatchFrames`). We stay well under it when batching.
pub const max_batch_frames: usize = 4096;

/// Both directions start with this implicit per-stream window (`kInitialStreamWindow`).
/// It is never negotiated — it is simply assumed by both halves at OPEN time.
pub const initial_stream_window: u32 = 4 * 1024 * 1024;

/// Largest PING payload tdesktop accepts before failing the carrier
/// (`processRelayFrame`, FrameType::Ping). PONG must echo it verbatim.
pub const max_ping_payload: usize = 64;

/// Stream ids are 24-bit; 0 is the reserved session ("control") stream.
pub const max_stream_id: u32 = 0x00FF_FFFF;

pub const FrameType = enum(u8) {
    /// stream > 0. Client-only: opens one logical socket. A relay that sends OPEN
    /// is a protocol error, so we never do.
    open = 0x01,
    /// stream > 0. Opaque MTProxy bytes. Never empty.
    data = 0x02,
    /// stream > 0. Empty payload. Abort in both directions — undelivered DATA on a
    /// closed stream is dropped, matching tdesktop's TCP path (it never half-closes).
    close = 0x03,
    /// stream > 0. Four-byte big-endian credit delta, never zero.
    window = 0x04,
    /// stream 0. Relay→client keepalive, payload <= 64 bytes.
    ping = 0x05,
    /// stream 0. Client→relay, echoes the PING payload exactly.
    pong = 0x06,
    /// stream 0. Client→relay, payload `01` = protocol v1. Always the first frame.
    hello = 0x10,
    /// stream 0. Relay→client, empty. Must be the first frame we ever send.
    welcome = 0x11,
    /// stream 0. Reserved for relay-auth v2; rejected in v1.
    auth_challenge = 0x12,
    /// stream 0. Reserved for relay-auth v2; rejected in v1.
    auth_response = 0x13,
    /// stream 0. Fails the client's live streams and closes the carrier.
    bye = 0x1f,
    _,

    /// True for the eleven types tdesktop's `IsKnownType` accepts. An unknown type
    /// anywhere in a batch makes tdesktop drop the whole carrier, so we mirror its
    /// strictness when parsing the client's side.
    pub fn known(self: FrameType) bool {
        return switch (self) {
            .open, .data, .close, .window, .ping, .pong => true,
            .hello, .welcome, .auth_challenge, .auth_response, .bye => true,
            _ => false,
        };
    }

    /// True for the frames that belong on the session stream (id 0).
    pub fn sessionScoped(self: FrameType) bool {
        return switch (self) {
            .ping, .pong, .hello, .welcome, .auth_challenge, .auth_response, .bye => true,
            else => false,
        };
    }
};

pub const Frame = struct {
    type: FrameType,
    stream_id: u32,
    /// Borrowed from the caller's buffer — valid only until that buffer is reused.
    payload: []const u8,
};

pub const ParseError = error{
    /// Unknown frame type, or a length above `max_payload`. Fatal for the carrier.
    Malformed,
};

pub const Parsed = union(enum) {
    /// A complete frame plus the total bytes it consumed (header + payload).
    frame: struct { value: Frame, consumed: usize },
    /// Fewer bytes than one complete frame — read more, then re-parse from the same
    /// offset. Never an error: carriers may deliver partial buffers.
    incomplete,
};

/// Parse one frame from the front of `buf`.
///
/// Mirrors `ParseFrames` in tdesktop: an unknown type or an oversized length is fatal,
/// a short buffer is not.
pub fn parseOne(buf: []const u8) ParseError!Parsed {
    if (buf.len < header_size) return .incomplete;
    const raw_type: FrameType = @enumFromInt(buf[0]);
    if (!raw_type.known()) return error.Malformed;
    const stream_id = (@as(u32, buf[1]) << 16) | (@as(u32, buf[2]) << 8) | @as(u32, buf[3]);
    const length = std.mem.readInt(u32, buf[4..8], .big);
    if (length > max_payload) return error.Malformed;
    const total = header_size + @as(usize, length);
    if (buf.len < total) return .incomplete;
    return .{ .frame = .{
        .value = .{
            .type = raw_type,
            .stream_id = stream_id,
            .payload = buf[header_size..total],
        },
        .consumed = total,
    } };
}

/// Walks a byte buffer yielding complete frames. `rest()` returns the unconsumed
/// tail, which the caller must keep for the next carrier message.
pub const Iterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Iterator {
        return .{ .buf = buf };
    }

    /// Next complete frame, or null when the remainder is a partial frame (or empty).
    pub fn next(self: *Iterator) ParseError!?Frame {
        switch (try parseOne(self.buf[self.pos..])) {
            .incomplete => return null,
            .frame => |f| {
                self.pos += f.consumed;
                return f.value;
            },
        }
    }

    pub fn rest(self: *const Iterator) []const u8 {
        return self.buf[self.pos..];
    }
};

/// Write a frame header into `out`. `payload_len` must already be <= `max_payload`.
pub fn writeHeader(out: *[header_size]u8, kind: FrameType, stream_id: u32, payload_len: u32) void {
    std.debug.assert(stream_id <= max_stream_id);
    std.debug.assert(payload_len <= max_payload);
    out[0] = @intFromEnum(kind);
    out[1] = @intCast((stream_id >> 16) & 0xff);
    out[2] = @intCast((stream_id >> 8) & 0xff);
    out[3] = @intCast(stream_id & 0xff);
    std.mem.writeInt(u32, out[4..8], payload_len, .big);
}

pub const SerializeError = error{
    /// `dest` cannot hold header + payload.
    NoSpace,
    /// Payload above `max_payload`, which tdesktop would reject.
    PayloadTooLarge,
};

/// Serialize one frame into `dest`, returning the written slice.
pub fn serialize(dest: []u8, kind: FrameType, stream_id: u32, payload: []const u8) SerializeError![]u8 {
    if (payload.len > max_payload) return error.PayloadTooLarge;
    const total = header_size + payload.len;
    if (dest.len < total) return error.NoSpace;
    writeHeader(dest[0..header_size], kind, stream_id, @intCast(payload.len));
    if (payload.len > 0) @memcpy(dest[header_size..total], payload);
    return dest[0..total];
}

/// Size a frame will occupy once serialized.
pub fn framedLen(payload_len: usize) usize {
    return header_size + payload_len;
}

/// Encode a WINDOW credit delta. Zero is a protocol error on both sides, so callers
/// must never flush an empty grant.
pub fn windowPayload(amount: u32) [4]u8 {
    std.debug.assert(amount != 0);
    var out: [4]u8 = undefined;
    std.mem.writeInt(u32, &out, amount, .big);
    return out;
}

/// Decode a WINDOW credit delta; null when the payload is not exactly four bytes or
/// the delta is zero (both are protocol errors).
pub fn readWindow(payload: []const u8) ?u32 {
    if (payload.len != 4) return null;
    const amount = std.mem.readInt(u32, payload[0..4], .big);
    return if (amount == 0) null else amount;
}

// ── tests ─────────────────────────────────────────────────────────────────────

test "serialize/parse roundtrip" {
    var buf: [64]u8 = undefined;
    const out = try serialize(&buf, .data, 0x123456, "hello");
    try std.testing.expectEqual(@as(usize, 13), out.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x12, 0x34, 0x56, 0, 0, 0, 5 }, out[0..8]);

    switch (try parseOne(out)) {
        .incomplete => return error.TestUnexpectedResult,
        .frame => |f| {
            try std.testing.expectEqual(FrameType.data, f.value.type);
            try std.testing.expectEqual(@as(u32, 0x123456), f.value.stream_id);
            try std.testing.expectEqualStrings("hello", f.value.payload);
            try std.testing.expectEqual(@as(usize, 13), f.consumed);
        },
    }
}

test "welcome frame is exactly the eight header bytes tdesktop expects" {
    var buf: [16]u8 = undefined;
    const out = try serialize(&buf, .welcome, 0, "");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0, 0, 0, 0, 0, 0, 0 }, out);
}

test "hello frame from the client carries payload 01" {
    var buf: [16]u8 = undefined;
    const out = try serialize(&buf, .hello, 0, &[_]u8{1});
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x10, 0, 0, 0, 0, 0, 0, 1, 1 }, out);
}

test "iterator walks a concatenated batch and reports the partial tail" {
    var buf: [64]u8 = undefined;
    const a = try serialize(buf[0..], .open, 1, "");
    const b = try serialize(buf[a.len..], .data, 1, "abc");
    const total = a.len + b.len;
    // Truncate the last frame by one byte: the iterator must yield only the first.
    var it = Iterator.init(buf[0 .. total - 1]);
    const first = (try it.next()).?;
    try std.testing.expectEqual(FrameType.open, first.type);
    try std.testing.expectEqual(@as(?Frame, null), try it.next());
    try std.testing.expectEqual(@as(usize, b.len - 1), it.rest().len);

    var full = Iterator.init(buf[0..total]);
    _ = (try full.next()).?;
    const second = (try full.next()).?;
    try std.testing.expectEqualStrings("abc", second.payload);
    try std.testing.expectEqual(@as(usize, 0), full.rest().len);
}

test "unknown type and oversized length are fatal" {
    var buf: [16]u8 = undefined;
    @memset(&buf, 0);
    buf[0] = 0x77; // not in IsKnownType
    try std.testing.expectError(error.Malformed, parseOne(&buf));

    buf[0] = @intFromEnum(FrameType.data);
    std.mem.writeInt(u32, buf[4..8], @as(u32, max_payload + 1), .big);
    try std.testing.expectError(error.Malformed, parseOne(&buf));
}

test "short buffer is incomplete, never an error" {
    try std.testing.expect((try parseOne(&[_]u8{})) == .incomplete);
    try std.testing.expect((try parseOne(&[_]u8{ 0x02, 0, 0, 1 })) == .incomplete);
}

test "window payload roundtrip rejects zero and wrong sizes" {
    const encoded = windowPayload(65536);
    try std.testing.expectEqual(@as(?u32, 65536), readWindow(&encoded));
    try std.testing.expectEqual(@as(?u32, null), readWindow(&[_]u8{ 0, 0, 0, 0 }));
    try std.testing.expectEqual(@as(?u32, null), readWindow(&[_]u8{ 0, 0, 1 }));
}

test "frame type classification matches tdesktop" {
    try std.testing.expect(FrameType.open.known());
    try std.testing.expect(FrameType.bye.known());
    try std.testing.expect(!(@as(FrameType, @enumFromInt(0x00))).known());
    try std.testing.expect(!(@as(FrameType, @enumFromInt(0x07))).known());
    try std.testing.expect(!(@as(FrameType, @enumFromInt(0x20))).known());
    try std.testing.expect(FrameType.ping.sessionScoped());
    try std.testing.expect(!FrameType.data.sessionScoped());
}

test "serialize rejects oversized payload and short buffers" {
    var small: [4]u8 = undefined;
    try std.testing.expectError(error.NoSpace, serialize(&small, .welcome, 0, ""));
}
