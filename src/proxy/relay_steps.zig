const std = @import("std");
const posix = std.posix;
const constants = @import("../protocol/constants.zig");
const socket_utils = @import("socket_utils.zig");

const nowMs = socket_utils.nowMs;

pub const RelayProgress = enum {
    none,
    partial,
    forwarded,
};

test "TLS relay chunk parser handles every TCP split across multiple records" {
    const Cipher = struct {
        fn apply(_: *@This(), _: []u8) void {}
    };
    const Mp = struct {
        fn encapsulateC2S(_: *@This(), data: []u8, _: []u8) ![]u8 {
            return data;
        }
    };
    const Slot = struct {
        relay_tls_hdr: [5]u8 = undefined,
        relay_tls_hdr_pos: u8 = 0,
        relay_tls_body_pos: u16 = 0,
        relay_tls_body_len: u16 = 0,
        relay_record_type: u8 = 0,
        client_decryptor: ?Cipher = null,
        tg_encryptor: ?Cipher = .{},
        middle_ctx: ?Mp = null,
        c2s_bytes: usize = 0,
        output: [5]u8 = undefined,
        count: usize = 0,
        fn queue(self: *@This(), _: std.mem.Allocator, data: []const u8) !bool {
            @memcpy(self.output[self.count..][0..data.len], data);
            self.count += data.len;
            return true;
        }
    };
    const input = [_]u8{ 0x17, 3, 3, 0, 3, 'a', 'b', 'c', 0x14, 3, 3, 0, 1, 1, 0x17, 3, 3, 0, 2, 'd', 'e' };
    for (1..input.len) |split| {
        var data = input;
        var slot = Slot{};
        _ = try consumeClientTlsBytes(&slot, std.testing.allocator, null, data[0..split], Slot.queue);
        _ = try consumeClientTlsBytes(&slot, std.testing.allocator, null, data[split..], Slot.queue);
        try std.testing.expectEqualStrings("abcde", &slot.output);
        try std.testing.expectEqual(@as(usize, 5), slot.c2s_bytes);
        try std.testing.expectEqual(@as(u8, 0), slot.relay_tls_hdr_pos);
    }
}

pub fn relayClientToUpstreamStep(
    slot: anytype,
    allocator: std.mem.Allocator,
    mp_c2s_scratch: ?[]u8,
    read_buf: []u8,
    comptime queue_upstream: fn (@TypeOf(slot), std.mem.Allocator, []const u8) anyerror!bool,
) !RelayProgress {
    const n = posix.read(slot.client_fd, read_buf) catch |err| {
        if (err == error.WouldBlock) return .none;
        return err;
    };
    if (n == 0) return error.EndOfStream;
    return consumeClientTlsBytes(slot, allocator, mp_c2s_scratch, read_buf[0..n], queue_upstream);
}

/// Consume an arbitrary TCP chunk, retaining only incomplete TLS header/body positions.
fn consumeClientTlsBytes(
    slot: anytype,
    allocator: std.mem.Allocator,
    mp_c2s_scratch: ?[]u8,
    data: []u8,
    comptime queue_upstream: fn (@TypeOf(slot), std.mem.Allocator, []const u8) anyerror!bool,
) !RelayProgress {
    var pos: usize = 0;
    var forwarded = false;
    while (pos < data.len) {
        if (slot.relay_tls_hdr_pos < 5) {
            const take = @min(5 - @as(usize, slot.relay_tls_hdr_pos), data.len - pos);
            @memcpy(slot.relay_tls_hdr[slot.relay_tls_hdr_pos..][0..take], data[pos..][0..take]);
            slot.relay_tls_hdr_pos += @intCast(take);
            pos += take;
            if (slot.relay_tls_hdr_pos < 5) break;
            slot.relay_record_type = slot.relay_tls_hdr[0];
            slot.relay_tls_body_len = std.mem.readInt(u16, slot.relay_tls_hdr[3..5], .big);
            slot.relay_tls_body_pos = 0;
            if (slot.relay_record_type != constants.tls_record_change_cipher and
                slot.relay_record_type != constants.tls_record_application) return error.ConnectionReset;
            if (slot.relay_tls_body_len == 0 or slot.relay_tls_body_len > constants.max_tls_ciphertext_size)
                return error.ConnectionReset;
        }
        const take = @min(@as(usize, slot.relay_tls_body_len - slot.relay_tls_body_pos), data.len - pos);
        const payload = data[pos..][0..take];
        if (take > 0 and slot.relay_record_type == constants.tls_record_application) {
            if (slot.client_decryptor) |*dec| dec.apply(payload);
            if (slot.middle_ctx) |*mp| {
                const scratch = mp_c2s_scratch orelse return error.MissingMiddleProxyScratch;
                const output = try mp.encapsulateC2S(payload, scratch);
                if (output.len > 0) _ = try queue_upstream(slot, allocator, output);
            } else if (slot.tg_encryptor) |*enc| {
                enc.apply(payload);
                _ = try queue_upstream(slot, allocator, payload);
            } else return error.MissingUpstreamCipher;
            slot.c2s_bytes += payload.len;
            forwarded = true;
        }
        pos += take;
        slot.relay_tls_body_pos += @intCast(take);
        if (slot.relay_tls_body_pos == slot.relay_tls_body_len) {
            slot.relay_tls_hdr_pos = 0;
            slot.relay_tls_body_pos = 0;
            slot.relay_tls_body_len = 0;
        }
    }
    return if (forwarded) .forwarded else .partial;
}

pub fn relayUpstreamToClientStep(
    slot: anytype,
    allocator: std.mem.Allocator,
    mp_s2c_scratch: ?[]u8,
    read_buf: []u8,
    comptime queue_tls_records: fn (@TypeOf(slot), std.mem.Allocator, []u8) anyerror!void,
) !RelayProgress {
    const n = posix.read(slot.upstream_fd, read_buf) catch |err| {
        if (err == error.WouldBlock) return .none;
        return err;
    };
    if (n == 0) return error.EndOfStream;

    const raw = read_buf[0..n];

    if (slot.middle_ctx) |*mp| {
        const scratch = mp_s2c_scratch orelse return error.MissingMiddleProxyScratch;
        const payload = try mp.decapsulateS2C(raw, scratch);
        if (payload.len == 0) return .partial;
        if (slot.client_encryptor) |*enc| enc.apply(payload);
        try queue_tls_records(slot, allocator, payload);
        slot.s2c_bytes += payload.len;
        return .forwarded;
    }

    if (!slot.use_fast_mode) {
        if (slot.tg_decryptor) |*dec| dec.apply(raw);
        if (slot.client_encryptor) |*enc| enc.apply(raw);
    }

    try queue_tls_records(slot, allocator, raw);
    slot.s2c_bytes += raw.len;
    return .forwarded;
}

pub fn queueTlsAppRecords(
    slot: anytype,
    allocator: std.mem.Allocator,
    payload: []u8,
    comptime queue_client_parts: fn (@TypeOf(slot), std.mem.Allocator, []const []const u8) anyerror!bool,
) !void {
    var off: usize = 0;
    var headers: [32][5]u8 = undefined;
    var parts: [64][]const u8 = undefined;
    var count: usize = 0;

    while (off < payload.len) {
        // A genuine TLS 1.3 sender's on-wire application_data length is the
        // plaintext chunk plus the 1-byte inner content type and 16-byte
        // AEAD tag, so it can reach 16384+17=16401 but never lands on
        // exactly 16384 (0x4000). We forward the MTProto payload with no
        // such expansion, so letting chunk_len ride drs.nextRecordSize()'s
        // ceiling unclamped put every bulk S2C record at precisely 0x4000 —
        // a length no real TLS 1.3 stack ever emits, and a one-rule passive
        // DPI record-length discriminator for this proxy. Stay one
        // AEAD-tag-plus-content-type below the ceiling so the wire length
        // can never hit that impossible constant.
        const wire_cap = @min(payload.len - off, slot.drs.nextRecordSize());
        const chunk_len = @min(wire_cap, constants.max_tls_plaintext_size - 17);

        const header = &headers[count / 2];
        header[0] = constants.tls_record_application;
        header[1] = constants.tls_version[0];
        header[2] = constants.tls_version[1];
        std.mem.writeInt(u16, header[3..5], @intCast(chunk_len), .big);

        parts[count] = header;
        parts[count + 1] = payload[off .. off + chunk_len];
        count += 2;
        slot.drs.recordSent(chunk_len);
        off += chunk_len;
        if (count == parts.len) {
            _ = try queue_client_parts(slot, allocator, &parts);
            count = 0;
        }
    }
    if (count > 0) _ = try queue_client_parts(slot, allocator, parts[0..count]);
}

pub fn startRelay(
    loop: anytype,
    slot: anytype,
    comptime ensure_mp_c2s_scratch: fn (@TypeOf(loop)) anyerror![]u8,
    comptime queue_upstream: fn (@TypeOf(loop), @TypeOf(slot), []const u8) anyerror!bool,
    comptime close_slot: fn (@TypeOf(loop), @TypeOf(slot), []const u8) void,
) void {
    // Handshake complete — release from handshake budget exactly once (the
    // connection was charged at first byte, so hs_counted is set here).
    if (slot.hs_counted) {
        _ = loop.state.handshakes_inflight.fetchSub(1, .monotonic);
        slot.hs_counted = false;
    }
    slot.phase = .relaying;

    if (slot.pipelined_data) |buf| {
        if (slot.client_decryptor) |*dec| dec.apply(buf);

        if (slot.middle_ctx) |*mp| {
            const scratch = ensure_mp_c2s_scratch(loop) catch {
                close_slot(loop, slot, "alloc middleproxy c2s scratch failed");
                return;
            };
            const out_data = mp.encapsulateC2S(buf, scratch) catch {
                close_slot(loop, slot, "encapsulate pipelined middleproxy payload failed");
                return;
            };
            if (out_data.len > 0) {
                _ = queue_upstream(loop, slot, out_data) catch {
                    close_slot(loop, slot, "queue pipelined middleproxy payload failed");
                    return;
                };
            }
        } else if (slot.tg_encryptor) |*enc| {
            enc.apply(buf);
            _ = queue_upstream(loop, slot, buf) catch {
                close_slot(loop, slot, "queue pipelined direct payload failed");
                return;
            };
        } else {
            close_slot(loop, slot, "missing encryptor/middle_ctx");
            return;
        }

        slot.c2s_bytes += buf.len;
        loop.state.allocator.free(buf);
        slot.pipelined_data = null;
    }
}

pub fn relayRawClientToUpstream(
    loop: anytype,
    slot: anytype,
    read_buf: []u8,
    comptime queue_upstream: fn (@TypeOf(loop), @TypeOf(slot), []const u8) anyerror!bool,
    comptime close_slot: fn (@TypeOf(loop), @TypeOf(slot), []const u8) void,
    comptime read_eof: fn (@TypeOf(loop), @TypeOf(slot), posix.fd_t) void,
) void {
    if (!slot.upstream_queue.isEmpty()) return;

    const n = posix.read(slot.client_fd, read_buf) catch |err| {
        if (err == error.WouldBlock) return;
        close_slot(loop, slot, "mask relay c2s read error");
        return;
    };
    if (n == 0) {
        read_eof(loop, slot, slot.client_fd);
        return;
    }

    _ = queue_upstream(loop, slot, read_buf[0..n]) catch {
        close_slot(loop, slot, "mask relay c2s queue error");
        return;
    };
    slot.last_activity_ms = nowMs();
}

pub fn relayRawUpstreamToClient(
    loop: anytype,
    slot: anytype,
    read_buf: []u8,
    comptime queue_client: fn (@TypeOf(loop), @TypeOf(slot), []const u8) anyerror!bool,
    comptime close_slot: fn (@TypeOf(loop), @TypeOf(slot), []const u8) void,
    comptime read_eof: fn (@TypeOf(loop), @TypeOf(slot), posix.fd_t) void,
) void {
    if (!slot.client_queue.isEmpty()) return;

    const n = posix.read(slot.upstream_fd, read_buf) catch |err| {
        if (err == error.WouldBlock) return;
        close_slot(loop, slot, "mask relay s2c read error");
        return;
    };
    if (n == 0) {
        read_eof(loop, slot, slot.upstream_fd);
        return;
    }

    _ = queue_client(loop, slot, read_buf[0..n]) catch {
        close_slot(loop, slot, "mask relay s2c queue error");
        return;
    };
    slot.last_activity_ms = nowMs();
}

test "queueTlsAppRecords never emits the impossible 0x4000 TLS record length" {
    // Regression (X03-4): a real TLS 1.3 bulk sender's application_data
    // records top out at 16401 bytes and never at exactly 16384 (0x4000),
    // since 16384 is the plaintext limit before the 1-byte content type and
    // 16-byte AEAD tag are added. Before this fix chunk_len rode
    // drs.nextRecordSize()'s ceiling of 16384 unclamped, so every full-size
    // bulk S2C record hit 0x4000 exactly — a one-rule passive DPI tell.
    const drs_mod = @import("drs.zig");

    const FakeSlot = struct {
        drs: drs_mod.DynamicRecordSizer,
        lengths: [8]usize = undefined,
        count: usize = 0,

        fn queuePair(self: *@This(), allocator: std.mem.Allocator, parts: []const []const u8) !bool {
            _ = allocator;
            var i: usize = 0;
            while (i < parts.len) : (i += 2) {
                self.lengths[self.count] = std.mem.readInt(u16, parts[i][3..5], .big);
                self.count += 1;
            }
            return true;
        }
    };

    var slot = FakeSlot{ .drs = drs_mod.DynamicRecordSizer.init(false) };

    const payload = try std.testing.allocator.alloc(u8, 40000);
    defer std.testing.allocator.free(payload);
    @memset(payload, 0xAB);

    try queueTlsAppRecords(&slot, std.testing.allocator, payload, FakeSlot.queuePair);

    try std.testing.expect(slot.count > 0);
    for (slot.lengths[0..slot.count]) |len| {
        try std.testing.expect(len != constants.max_tls_plaintext_size);
        try std.testing.expect(len <= constants.max_tls_plaintext_size - 17);
    }
}
