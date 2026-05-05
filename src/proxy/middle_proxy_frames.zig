const std = @import("std");
const posix = std.posix;

const crypto = @import("../crypto/crypto.zig");
const middleproxy = @import("../protocol/middleproxy.zig");

const log = std.log.scoped(.proxy);

pub fn readReset(slot: anytype, encrypted: bool) void {
    slot.mp_frame_have = 0;
    slot.mp_frame_total_len = 0;
    slot.mp_frame_padded_len = 0;
    slot.mp_frame_encrypted = encrypted;
    slot.mp_frame_first_decrypted = false;
    slot.mp_frame_need = if (encrypted) 16 else 4;
}

pub fn ensureFrameBuf(slot: anytype, allocator: std.mem.Allocator, comptime frame_buf_size: usize) ![]u8 {
    if (slot.mp_frame_buf) |buf| return buf;
    const buf = try allocator.alloc(u8, frame_buf_size);
    slot.mp_frame_buf = buf;
    return buf;
}

pub fn writeFrame(
    slot: anytype,
    allocator: std.mem.Allocator,
    payload: []const u8,
    encrypted: bool,
    comptime frame_buf_size: usize,
    comptime queue_upstream: fn (@TypeOf(slot), std.mem.Allocator, []const u8) anyerror!bool,
) !void {
    var plain: [frame_buf_size]u8 = undefined;
    const total_len: usize = payload.len + 12;
    if (total_len > plain.len) return error.BadMiddleProxyFrameSize;

    std.mem.writeInt(u32, plain[0..4], @intCast(total_len), .little);
    std.mem.writeInt(i32, plain[4..8], slot.mp_write_seq_no, .little);
    slot.mp_write_seq_no += 1;

    @memcpy(plain[8 .. 8 + payload.len], payload);
    const checksum = middleproxy.crc32(plain[0 .. 8 + payload.len]);
    std.mem.writeInt(u32, plain[8 + payload.len ..][0..4], checksum, .little);

    var frame_len = total_len;
    if (encrypted) {
        const pad = (16 - (frame_len % 16)) % 16;
        if (frame_len + pad > plain.len) return error.BadMiddleProxyFrameSize;
        var i: usize = 0;
        while (i < pad) : (i += 4) {
            std.mem.writeInt(u32, plain[frame_len + i ..][0..4], 4, .little);
        }
        frame_len += pad;
        try slot.mp_enc.?.encryptInPlace(plain[0..frame_len]);
    }

    _ = try queue_upstream(slot, allocator, plain[0..frame_len]);
}

pub fn tryReadFrame(
    slot: anytype,
    allocator: std.mem.Allocator,
    encrypted: bool,
    comptime frame_buf_size: usize,
) !?[]const u8 {
    const frame_buf = try ensureFrameBuf(slot, allocator, frame_buf_size);

    while (true) {
        if (slot.mp_frame_need == 0) {
            readReset(slot, encrypted);
        }

        if (slot.mp_frame_have < slot.mp_frame_need) {
            const n = posix.read(slot.upstream_fd, frame_buf[slot.mp_frame_have..slot.mp_frame_need]) catch |err| {
                if (err == error.WouldBlock) return null;
                log.debug("[{d}] mp read error: step={s} encrypted={} have={d} need={d} err={any}", .{
                    slot.conn_id,
                    @tagName(slot.mp_step),
                    encrypted,
                    slot.mp_frame_have,
                    slot.mp_frame_need,
                    err,
                });
                return err;
            };
            if (n == 0) {
                log.debug("[{d}] mp upstream eof: step={s} encrypted={} have={d} need={d}", .{
                    slot.conn_id,
                    @tagName(slot.mp_step),
                    encrypted,
                    slot.mp_frame_have,
                    slot.mp_frame_need,
                });
                return error.EndOfStream;
            }
            slot.mp_frame_have += n;
            if (slot.mp_frame_have < slot.mp_frame_need) return null;
        }

        if (!encrypted) {
            if (slot.mp_frame_total_len == 0) {
                slot.mp_frame_total_len = std.mem.readInt(u32, frame_buf[0..4], .little);
                if (slot.mp_frame_total_len < 12 or slot.mp_frame_total_len > frame_buf.len) {
                    log.debug("[{d}] mp plain frame size invalid: total_len={d} have={d} need={d}", .{
                        slot.conn_id,
                        slot.mp_frame_total_len,
                        slot.mp_frame_have,
                        slot.mp_frame_need,
                    });
                    return error.BadMiddleProxyFrameSize;
                }
                slot.mp_frame_need = slot.mp_frame_total_len;
                continue;
            }
        } else {
            if (!slot.mp_frame_first_decrypted) {
                slot.mp_dec.?.decryptInPlace(frame_buf[0..16]) catch |err| {
                    log.debug("[{d}] mp decrypt first block failed: step={s} err={any}", .{
                        slot.conn_id,
                        @tagName(slot.mp_step),
                        err,
                    });
                    return err;
                };
                slot.mp_frame_first_decrypted = true;
                slot.mp_frame_total_len = std.mem.readInt(u32, frame_buf[0..4], .little);
                if (slot.mp_frame_total_len < 12 or slot.mp_frame_total_len > (1 << 24)) {
                    const first4_le = std.mem.readInt(u32, frame_buf[0..4], .little);
                    const first4_be = std.mem.readInt(u32, frame_buf[0..4], .big);
                    log.debug("[{d}] mp encrypted frame size invalid: total_len={d} first4_le=0x{x} first4_be=0x{x}", .{
                        slot.conn_id,
                        slot.mp_frame_total_len,
                        first4_le,
                        first4_be,
                    });
                    return error.BadMiddleProxyFrameSize;
                }
                slot.mp_frame_padded_len = if (slot.mp_frame_total_len % 16 == 0)
                    slot.mp_frame_total_len
                else
                    slot.mp_frame_total_len + (16 - (slot.mp_frame_total_len % 16));
                if (slot.mp_frame_padded_len > frame_buf.len) {
                    log.debug("[{d}] mp encrypted padded size invalid: total_len={d} padded_len={d} frame_buf={d}", .{
                        slot.conn_id,
                        slot.mp_frame_total_len,
                        slot.mp_frame_padded_len,
                        frame_buf.len,
                    });
                    return error.BadMiddleProxyFrameSize;
                }
                slot.mp_frame_need = slot.mp_frame_padded_len;
                if (slot.mp_frame_have < slot.mp_frame_need) return null;
            }

            if (slot.mp_frame_padded_len > 16) {
                slot.mp_dec.?.decryptInPlace(frame_buf[16..slot.mp_frame_padded_len]) catch |err| {
                    log.debug("[{d}] mp decrypt payload failed: step={s} padded_len={d} err={any}", .{
                        slot.conn_id,
                        @tagName(slot.mp_step),
                        slot.mp_frame_padded_len,
                        err,
                    });
                    return err;
                };
            }
        }

        const frame = frame_buf[0..slot.mp_frame_total_len];
        const msg_seq = std.mem.readInt(i32, frame[4..8], .little);
        if (msg_seq != slot.mp_read_seq_no) {
            log.debug("[{d}] mp seq mismatch: got={d} expected={d} step={s}", .{
                slot.conn_id,
                msg_seq,
                slot.mp_read_seq_no,
                @tagName(slot.mp_step),
            });
            return error.BadMiddleProxySeqNo;
        }
        slot.mp_read_seq_no += 1;

        const expected_checksum = std.mem.readInt(u32, frame[frame.len - 4 ..][0..4], .little);
        const computed_checksum = middleproxy.crc32(frame[0 .. frame.len - 4]);
        if (expected_checksum != computed_checksum) {
            log.debug("[{d}] mp checksum mismatch: expected=0x{x} computed=0x{x} frame_len={d}", .{
                slot.conn_id,
                expected_checksum,
                computed_checksum,
                frame.len,
            });
            return error.BadMiddleProxyChecksum;
        }

        // Copy payload into front of frame_buf so caller can consume before reset.
        const payload_len = frame.len - 12;
        std.mem.copyForwards(u8, frame_buf[0..payload_len], frame[8 .. frame.len - 4]);
        const payload = frame_buf[0..payload_len];

        readReset(slot, encrypted);
        return payload;
    }
}

const TestStep = enum {
    fuzz,
};

const TestSlot = struct {
    conn_id: u64 = 1,
    mp_step: TestStep = .fuzz,
    upstream_fd: posix.fd_t = -1,

    mp_frame_have: usize = 0,
    mp_frame_total_len: usize = 0,
    mp_frame_padded_len: usize = 0,
    mp_frame_encrypted: bool = false,
    mp_frame_first_decrypted: bool = false,
    mp_frame_need: usize = 0,
    mp_frame_buf: ?[]u8 = null,

    mp_read_seq_no: i32 = -2,
    mp_write_seq_no: i32 = -2,

    mp_enc: ?crypto.AesCbc = null,
    mp_dec: ?crypto.AesCbc = null,
};

fn makePipe() ![2]posix.fd_t {
    return try std.Io.Threaded.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
}

fn closeFd(fd: posix.fd_t) void {
    while (true) switch (posix.errno(posix.system.close(fd))) {
        .SUCCESS => return,
        .INTR => continue,
        else => return,
    };
}

fn writeAll(fd: posix.fd_t, data: []const u8) !void {
    var off: usize = 0;
    while (off < data.len) {
        const rc = posix.system.write(fd, data[off..].ptr, data.len - off);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return error.Unexpected;
                off += @intCast(rc);
            },
            .INTR => continue,
            .AGAIN => continue,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn buildPlainFrame(seq: i32, payload: []const u8, out: []u8) []const u8 {
    const total_len = payload.len + 12;
    std.mem.writeInt(u32, out[0..4], @intCast(total_len), .little);
    std.mem.writeInt(i32, out[4..8], seq, .little);
    @memcpy(out[8 .. 8 + payload.len], payload);
    const checksum = middleproxy.crc32(out[0 .. 8 + payload.len]);
    std.mem.writeInt(u32, out[8 + payload.len ..][0..4], checksum, .little);
    return out[0..total_len];
}

fn buildEncryptedFrame(
    seq: i32,
    payload: []const u8,
    out: []u8,
    key: *const [32]u8,
    iv: *const [16]u8,
) ![]const u8 {
    const plain = buildPlainFrame(seq, payload, out);
    var frame_len = plain.len;
    const pad = (16 - (frame_len % 16)) % 16;
    var i: usize = 0;
    while (i < pad) : (i += 4) {
        std.mem.writeInt(u32, out[frame_len + i ..][0..4], 4, .little);
    }
    frame_len += pad;

    var enc = crypto.AesCbc.init(key, iv);
    try enc.encryptInPlace(out[0..frame_len]);
    return out[0..frame_len];
}

test "middle proxy frame parser - fragmented plain frame" {
    const fds = try makePipe();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    var slot = TestSlot{ .upstream_fd = fds[0] };
    readReset(&slot, false);

    var frame_buf: [128]u8 = undefined;
    const payload = "hello-middle-proxy";
    const frame = buildPlainFrame(-2, payload, &frame_buf);

    try writeAll(fds[1], frame[0..4]);
    try std.testing.expect(try tryReadFrame(&slot, std.testing.allocator, false, 512) == null);

    try writeAll(fds[1], frame[4..]);
    closeFd(fds[1]);

    var parsed: ?[]const u8 = null;
    var got_error = false;
    for (0..8) |_| {
        parsed = tryReadFrame(&slot, std.testing.allocator, false, 512) catch |err| {
            if (err == error.EndOfStream) {
                got_error = true;
                break;
            }
            return err;
        };
        if (parsed != null) break;
    }

    try std.testing.expect(!got_error);
    try std.testing.expect(parsed != null);
    try std.testing.expectEqualSlices(u8, payload, parsed.?);
    try std.testing.expectEqual(@as(i32, -1), slot.mp_read_seq_no);

    if (slot.mp_frame_buf) |buf| std.testing.allocator.free(buf);
}

test "middle proxy frame parser - encrypted frame and fuzz malformed input" {
    const key = [_]u8{0x11} ** 32;
    const iv = [_]u8{0x22} ** 16;

    // Deterministic encrypted roundtrip.
    {
        const fds = try makePipe();
        defer closeFd(fds[0]);
        defer closeFd(fds[1]);

        var slot = TestSlot{
            .upstream_fd = fds[0],
            .mp_dec = crypto.AesCbc.init(&key, &iv),
        };
        readReset(&slot, true);

        var wire: [256]u8 = undefined;
        const encrypted = try buildEncryptedFrame(-2, "abc12345", &wire, &key, &iv);
        try writeAll(fds[1], encrypted);
        closeFd(fds[1]);

        var parsed: ?[]const u8 = null;
        for (0..8) |_| {
            parsed = tryReadFrame(&slot, std.testing.allocator, true, 512) catch |err| {
                if (err == error.EndOfStream) break;
                return err;
            };
            if (parsed != null) break;
        }
        try std.testing.expect(parsed != null);
        try std.testing.expectEqualSlices(u8, "abc12345", parsed.?);
        if (slot.mp_frame_buf) |buf| std.testing.allocator.free(buf);
    }

    // Fuzz malformed encrypted/plain wire bytes (no panics, only controlled errors/null).
    var prng = std.Random.DefaultPrng.init(0xFACE1234);
    const random = prng.random();
    var fuzz_buf: [192]u8 = undefined;

    for (0..1500) |i| {
        const fds = try makePipe();
        defer closeFd(fds[0]);
        defer closeFd(fds[1]);

        const wire_len: usize = @as(usize, random.int(u8)) % fuzz_buf.len;
        random.bytes(fuzz_buf[0..wire_len]);
        try writeAll(fds[1], fuzz_buf[0..wire_len]);
        closeFd(fds[1]);

        var slot = TestSlot{
            .upstream_fd = fds[0],
            .mp_dec = crypto.AesCbc.init(&key, &iv),
        };
        const encrypted = (i % 2) == 0;
        readReset(&slot, encrypted);

        for (0..6) |_| {
            const maybe_payload = tryReadFrame(&slot, std.testing.allocator, encrypted, 512) catch |err| switch (err) {
                error.EndOfStream,
                error.BadMiddleProxyFrameSize,
                error.BadMiddleProxyChecksum,
                error.BadMiddleProxySeqNo,
                => break,
                else => return err,
            };
            if (maybe_payload != null) break;
        }

        if (slot.mp_frame_buf) |buf| std.testing.allocator.free(buf);
    }
}
