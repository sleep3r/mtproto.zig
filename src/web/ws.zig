//! Minimal RFC 6455 server-side WebSocket framing.
//!
//! The relay's carrier between the bridge page and us is a same-origin WebSocket.
//! That is the fastest carrier tdesktop's restricted WebView profile permits: its
//! injected lock script allows *only* inline script plus `fetch`/`WebSocket` to the
//! page's exact origin, so `wss://<our host>/…` is available while everything else
//! (workers, WebRTC, WebTransport, WebAssembly, storage) is not.
//!
//! Scope is deliberately narrow — we are both endpoints' only peer:
//!
//!  * server side only: we never mask what we send, and we reject an unmasked client
//!    frame as RFC 6455 requires;
//!  * one frame must be fully buffered before it is processed, which is safe because
//!    tdesktop emits exactly one relay frame per carrier message and caps its own DATA
//!    frames at 64 KiB (`kDataFrameSize`);
//!  * no permessage-deflate, no extensions.

const std = @import("std");

/// RFC 6455 §1.3 magic used to derive `Sec-WebSocket-Accept`.
pub const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// base64 of a 20-byte SHA-1 digest.
pub const accept_len: usize = 28;

/// Largest client frame we will buffer. tdesktop sends one relay frame per carrier
/// message and never exceeds 64 KiB of DATA, so this leaves >2x headroom while keeping
/// per-session memory bounded and predictable.
pub const max_message: usize = 128 * 1024;

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,
    _,

    pub fn isControl(self: Opcode) bool {
        return (@intFromEnum(self) & 0x8) != 0;
    }

    pub fn known(self: Opcode) bool {
        return switch (self) {
            .continuation, .text, .binary, .close, .ping, .pong => true,
            _ => false,
        };
    }
};

/// Close codes we actually emit.
pub const close_normal: u16 = 1000;
pub const close_protocol_error: u16 = 1002;
pub const close_unsupported_data: u16 = 1003;
pub const close_policy_violation: u16 = 1008;
pub const close_message_too_big: u16 = 1009;
pub const close_internal_error: u16 = 1011;

/// Compute `Sec-WebSocket-Accept` for a client's `Sec-WebSocket-Key`.
pub fn acceptKey(client_key: []const u8) [accept_len]u8 {
    var sha = std.crypto.hash.Sha1.init(.{});
    sha.update(client_key);
    sha.update(guid);
    var digest: [20]u8 = undefined;
    sha.final(&digest);

    var out: [accept_len]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&out, &digest);
    std.debug.assert(encoded.len == accept_len);
    return out;
}

/// True when `Sec-WebSocket-Key` decodes to exactly 16 bytes, as RFC 6455 §4.1 requires.
/// A client that sends anything else is not a browser WebSocket and gets no upgrade.
pub fn validKey(client_key: []const u8) bool {
    if (client_key.len != 24) return false;
    var decoded: [18]u8 = undefined;
    const size = std.base64.standard.Decoder.calcSizeForSlice(client_key) catch return false;
    if (size != 16) return false;
    std.base64.standard.Decoder.decode(decoded[0..size], client_key) catch return false;
    return true;
}

pub const FrameError = error{
    /// Reserved bits set, unknown opcode, a fragmented control frame, an oversized
    /// control payload, or an unmasked client frame — all fatal per RFC 6455.
    Protocol,
    /// Payload beyond `max_message`.
    TooBig,
};

pub const Header = struct {
    fin: bool,
    opcode: Opcode,
    mask: [4]u8,
    payload_len: usize,
    /// Bytes of framing before the payload.
    header_len: usize,

    pub fn totalLen(self: Header) usize {
        return self.header_len + self.payload_len;
    }
};

pub const Incoming = union(enum) {
    header: Header,
    /// Not enough bytes for a complete header yet.
    incomplete,
};

/// Parse a client frame header from the front of `buf`.
///
/// Only the header is required to be present; `Header.totalLen()` tells the caller how
/// many bytes the whole frame occupies.
pub fn parseHeader(buf: []const u8) FrameError!Incoming {
    if (buf.len < 2) return .incomplete;
    const b0 = buf[0];
    const b1 = buf[1];

    // RSV1..3 must be zero: we negotiate no extensions.
    if ((b0 & 0x70) != 0) return error.Protocol;

    const opcode: Opcode = @enumFromInt(@as(u4, @truncate(b0 & 0x0f)));
    if (!opcode.known()) return error.Protocol;

    const fin = (b0 & 0x80) != 0;
    const masked = (b1 & 0x80) != 0;
    // RFC 6455 §5.1: every client-to-server frame must be masked.
    if (!masked) return error.Protocol;

    const short_len: u7 = @truncate(b1 & 0x7f);
    var cursor: usize = 2;
    var payload_len: u64 = short_len;

    if (short_len == 126) {
        if (buf.len < cursor + 2) return .incomplete;
        payload_len = std.mem.readInt(u16, buf[cursor..][0..2], .big);
        cursor += 2;
        // Minimal-length encoding is required; a padded length is a protocol error.
        if (payload_len < 126) return error.Protocol;
    } else if (short_len == 127) {
        if (buf.len < cursor + 8) return .incomplete;
        payload_len = std.mem.readInt(u64, buf[cursor..][0..8], .big);
        cursor += 8;
        if (payload_len <= 0xffff) return error.Protocol;
        if ((payload_len >> 63) != 0) return error.Protocol;
    }

    if (opcode.isControl()) {
        // RFC 6455 §5.5: control frames are never fragmented and carry <= 125 bytes.
        if (!fin or payload_len > 125) return error.Protocol;
    }
    if (payload_len > max_message) return error.TooBig;

    if (buf.len < cursor + 4) return .incomplete;
    const mask: [4]u8 = buf[cursor..][0..4].*;
    cursor += 4;

    return .{ .header = .{
        .fin = fin,
        .opcode = opcode,
        .mask = mask,
        .payload_len = @intCast(payload_len),
        .header_len = cursor,
    } };
}

/// Unmask a payload in place. `offset` is the payload byte index the slice starts at,
/// so a payload can be unmasked in several chunks.
pub fn unmask(payload: []u8, mask: [4]u8, offset: usize) void {
    for (payload, 0..) |*byte, i| {
        byte.* ^= mask[(offset + i) % 4];
    }
}

/// Longest framing a server frame can need: 2 bytes plus a 64-bit length (never masked).
pub const max_server_header: usize = 10;

/// Write a server frame header (never masked) into `out`, returning the written slice.
pub fn writeHeader(out: []u8, fin: bool, opcode: Opcode, payload_len: usize) error{NoSpace}![]u8 {
    if (out.len < 2) return error.NoSpace;
    out[0] = (if (fin) @as(u8, 0x80) else 0) | @as(u8, @intFromEnum(opcode));
    if (payload_len < 126) {
        out[1] = @intCast(payload_len);
        return out[0..2];
    } else if (payload_len <= 0xffff) {
        if (out.len < 4) return error.NoSpace;
        out[1] = 126;
        std.mem.writeInt(u16, out[2..4], @intCast(payload_len), .big);
        return out[0..4];
    }
    if (out.len < 10) return error.NoSpace;
    out[1] = 127;
    std.mem.writeInt(u64, out[2..10], payload_len, .big);
    return out[0..10];
}

/// Build a CLOSE frame with `code` and no reason text, into `out` (needs >= 4 bytes).
pub fn closeFrame(out: []u8, code: u16) error{NoSpace}![]u8 {
    if (out.len < 4) return error.NoSpace;
    const head = try writeHeader(out, true, .close, 2);
    std.mem.writeInt(u16, out[head.len..][0..2], code, .big);
    return out[0 .. head.len + 2];
}

// ── tests ─────────────────────────────────────────────────────────────────────

test "accept key matches the RFC 6455 example" {
    // RFC 6455 §1.3.
    try std.testing.expectEqualStrings(
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        &acceptKey("dGhlIHNhbXBsZSBub25jZQ=="),
    );
}

test "key validation requires 16 decoded bytes" {
    try std.testing.expect(validKey("dGhlIHNhbXBsZSBub25jZQ=="));
    try std.testing.expect(!validKey("short"));
    try std.testing.expect(!validKey("")); // missing header
    try std.testing.expect(!validKey("!!!!!!!!!!!!!!!!!!!!!!!!"));
}

test "parses a masked binary frame and unmasks it" {
    // "Hello" masked with 0x37fa213d — RFC 6455 §5.7 (opcode changed to binary).
    var frame = [_]u8{ 0x82, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    const parsed = try parseHeader(&frame);
    const header = parsed.header;
    try std.testing.expectEqual(Opcode.binary, header.opcode);
    try std.testing.expect(header.fin);
    try std.testing.expectEqual(@as(usize, 5), header.payload_len);
    try std.testing.expectEqual(@as(usize, 6), header.header_len);

    const payload = frame[header.header_len..][0..header.payload_len];
    unmask(payload, header.mask, 0);
    try std.testing.expectEqualStrings("Hello", payload);
}

test "unmasking in chunks matches unmasking in one pass" {
    var payload = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    var reference = payload;
    const mask = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    unmask(&reference, mask, 0);
    unmask(payload[0..3], mask, 0);
    unmask(payload[3..7], mask, 3);
    unmask(payload[7..], mask, 7);
    try std.testing.expectEqualSlices(u8, &reference, &payload);
}

test "unmasked client frames are rejected" {
    const frame = [_]u8{ 0x82, 0x05, 'H', 'e', 'l', 'l', 'o' };
    try std.testing.expectError(error.Protocol, parseHeader(&frame));
}

test "reserved bits, unknown opcodes and fragmented control frames are protocol errors" {
    try std.testing.expectError(error.Protocol, parseHeader(&[_]u8{ 0xc2, 0x80, 0, 0, 0, 0 }));
    try std.testing.expectError(error.Protocol, parseHeader(&[_]u8{ 0x83, 0x80, 0, 0, 0, 0 }));
    // control frame with FIN clear
    try std.testing.expectError(error.Protocol, parseHeader(&[_]u8{ 0x09, 0x80, 0, 0, 0, 0 }));
    // control frame longer than 125
    try std.testing.expectError(error.Protocol, parseHeader(&[_]u8{ 0x89, 0xfe, 0x00, 0x7e, 0, 0, 0, 0 }));
}

test "non-minimal length encodings are rejected" {
    // 16-bit length carrying a value that fits in 7 bits.
    try std.testing.expectError(error.Protocol, parseHeader(&[_]u8{ 0x82, 0xfe, 0x00, 0x10, 0, 0, 0, 0 }));
    // 64-bit length carrying a value that fits in 16 bits.
    var buf = [_]u8{ 0x82, 0xff, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0 };
    try std.testing.expectError(error.Protocol, parseHeader(&buf));
}

test "oversized payloads are refused before allocation" {
    var buf: [14]u8 = undefined;
    buf[0] = 0x82;
    buf[1] = 0xff;
    std.mem.writeInt(u64, buf[2..10], max_message + 1, .big);
    @memset(buf[10..], 0);
    try std.testing.expectError(error.TooBig, parseHeader(&buf));
}

test "partial headers report incomplete" {
    try std.testing.expect((try parseHeader(&[_]u8{})) == .incomplete);
    try std.testing.expect((try parseHeader(&[_]u8{0x82})) == .incomplete);
    // masked, 16-bit length, mask bytes missing
    try std.testing.expect((try parseHeader(&[_]u8{ 0x82, 0xfe, 0x01, 0x00, 0x00 })) == .incomplete);
}

test "server headers use the shortest length form and never mask" {
    var out: [max_server_header]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x82, 0x05 }, try writeHeader(&out, true, .binary, 5));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x82, 126, 0x01, 0x00 }, try writeHeader(&out, true, .binary, 256));
    const big = try writeHeader(&out, true, .binary, 0x1_0000);
    try std.testing.expectEqual(@as(usize, 10), big.len);
    try std.testing.expectEqual(@as(u8, 127), big[1]);
    // continuation of a fragmented message
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 }, try writeHeader(&out, false, .continuation, 1));
}

test "close frame carries the code" {
    var out: [8]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x88, 0x02, 0x03, 0xf1 },
        try closeFrame(&out, close_message_too_big),
    );
}
