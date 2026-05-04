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

pub fn relayClientToUpstreamStep(
    slot: anytype,
    allocator: std.mem.Allocator,
    mp_c2s_scratch: ?[]u8,
    read_buf: []u8,
    comptime queue_upstream: fn (@TypeOf(slot), std.mem.Allocator, []const u8) anyerror!bool,
) !RelayProgress {
    var consumed_any = false;

    while (true) {
        if (slot.relay_tls_hdr_pos < 5) {
            const n = posix.read(slot.client_fd, slot.relay_tls_hdr[slot.relay_tls_hdr_pos..]) catch |err| {
                if (err == error.WouldBlock) return if (consumed_any) .partial else .none;
                return err;
            };
            if (n == 0) return error.EndOfStream;
            consumed_any = true;
            slot.relay_tls_hdr_pos += @intCast(n);

            if (slot.relay_tls_hdr_pos < 5) return .partial;

            slot.relay_record_type = slot.relay_tls_hdr[0];
            slot.relay_tls_body_len = std.mem.readInt(u16, slot.relay_tls_hdr[3..5], .big);
            slot.relay_tls_body_pos = 0;

            if (slot.relay_record_type == constants.tls_record_alert) return error.ConnectionReset;
            if (slot.relay_record_type != constants.tls_record_change_cipher and
                slot.relay_record_type != constants.tls_record_application)
            {
                return error.ConnectionReset;
            }
            if (slot.relay_tls_body_len == 0 or slot.relay_tls_body_len > constants.max_tls_ciphertext_size) {
                return error.ConnectionReset;
            }
        }

        const remaining = slot.relay_tls_body_len - slot.relay_tls_body_pos;
        if (remaining == 0) {
            slot.relay_tls_hdr_pos = 0;
            slot.relay_tls_body_pos = 0;
            slot.relay_tls_body_len = 0;
            if (consumed_any) return .partial;
            continue;
        }

        const want = @min(@as(usize, remaining), read_buf.len);
        const n = posix.read(slot.client_fd, read_buf[0..want]) catch |err| {
            if (err == error.WouldBlock) return if (consumed_any) .partial else .none;
            return err;
        };
        if (n == 0) return error.EndOfStream;

        consumed_any = true;
        slot.relay_tls_body_pos += @intCast(n);

        if (slot.relay_record_type == constants.tls_record_change_cipher) {
            if (slot.relay_tls_body_pos == slot.relay_tls_body_len) {
                slot.relay_tls_hdr_pos = 0;
                slot.relay_tls_body_pos = 0;
                slot.relay_tls_body_len = 0;
            }
            return .partial;
        }

        const payload = read_buf[0..n];
        if (slot.client_decryptor) |*dec| dec.apply(payload);

        if (slot.middle_ctx) |*mp| {
            const scratch = mp_c2s_scratch orelse return error.MissingMiddleProxyScratch;
            const out_data = try mp.encapsulateC2S(payload, scratch);
            if (out_data.len > 0) {
                _ = try queue_upstream(slot, allocator, out_data);
            }
        } else if (slot.tg_encryptor) |*enc| {
            enc.apply(payload);
            _ = try queue_upstream(slot, allocator, payload);
        }

        slot.c2s_bytes += payload.len;

        if (slot.relay_tls_body_pos == slot.relay_tls_body_len) {
            slot.relay_tls_hdr_pos = 0;
            slot.relay_tls_body_pos = 0;
            slot.relay_tls_body_len = 0;
            return .forwarded;
        }

        return .partial;
    }
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
    comptime queue_client_pair: fn (@TypeOf(slot), std.mem.Allocator, []const u8, []const u8) anyerror!bool,
) !void {
    var off: usize = 0;
    var header: [5]u8 = undefined;

    while (off < payload.len) {
        const chunk_len = @min(payload.len - off, slot.drs.nextRecordSize());

        header[0] = constants.tls_record_application;
        header[1] = constants.tls_version[0];
        header[2] = constants.tls_version[1];
        std.mem.writeInt(u16, header[3..5], @intCast(chunk_len), .big);

        _ = try queue_client_pair(slot, allocator, header[0..], payload[off .. off + chunk_len]);
        slot.drs.recordSent(chunk_len);
        off += chunk_len;
    }
}

pub fn startRelay(
    loop: anytype,
    slot: anytype,
    comptime ensure_mp_c2s_scratch: fn (@TypeOf(loop)) anyerror![]u8,
    comptime queue_upstream: fn (@TypeOf(loop), @TypeOf(slot), []const u8) anyerror!bool,
    comptime close_slot: fn (@TypeOf(loop), @TypeOf(slot), []const u8) void,
) void {
    // Handshake complete — release from handshake budget.
    _ = loop.state.handshakes_inflight.fetchSub(1, .monotonic);
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
) void {
    if (!slot.upstream_queue.isEmpty()) return;

    const n = posix.read(slot.client_fd, read_buf) catch |err| {
        if (err == error.WouldBlock) return;
        close_slot(loop, slot, "mask relay c2s read error");
        return;
    };
    if (n == 0) {
        close_slot(loop, slot, "mask relay c2s eof");
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
) void {
    if (!slot.client_queue.isEmpty()) return;

    const n = posix.read(slot.upstream_fd, read_buf) catch |err| {
        if (err == error.WouldBlock) return;
        close_slot(loop, slot, "mask relay s2c read error");
        return;
    };
    if (n == 0) {
        close_slot(loop, slot, "mask relay s2c eof");
        return;
    }

    _ = queue_client(loop, slot, read_buf[0..n]) catch {
        close_slot(loop, slot, "mask relay s2c queue error");
        return;
    };
    slot.last_activity_ms = nowMs();
}
