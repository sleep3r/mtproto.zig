const std = @import("std");
const posix = std.posix;

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
