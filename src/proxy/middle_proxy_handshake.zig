const std = @import("std");

const crypto = @import("../crypto/crypto.zig");
const middleproxy = @import("../protocol/middleproxy.zig");
const middle_proxy_frames = @import("middle_proxy_frames.zig");
const net_helpers = @import("net_helpers.zig");
const network_detect = @import("network_detect.zig");
const socket_utils = @import("socket_utils.zig");

const ip4 = net_helpers.ip4;
const localSocketAddress = socket_utils.localSocketAddress;
const realtimeSeconds = socket_utils.realtimeSeconds;
const ipv4NetworkToHostBytes = network_detect.ipv4NetworkToHostBytes;

const log = std.log.scoped(.proxy);

fn hasUpstreamPending(slot: anytype) bool {
    return !slot.upstream_queue.isEmpty();
}

pub fn begin(
    loop: anytype,
    slot: anytype,
    comptime write_frame: fn (@TypeOf(loop), @TypeOf(slot), []const u8, bool) anyerror!void,
    comptime lock_shared: fn (@TypeOf(loop)) void,
    comptime unlock_shared: fn (@TypeOf(loop)) void,
    comptime close_slot: fn (@TypeOf(loop), @TypeOf(slot), []const u8) void,
) void {
    slot.phase = .middle_proxy_handshake;
    slot.mp_step = .sending_rpc_nonce;
    slot.mp_write_seq_no = -2;
    slot.mp_read_seq_no = -2;
    slot.mp_frame_have = 0;
    slot.mp_frame_need = 0;
    slot.mp_enc = null;
    slot.mp_dec = null;

    crypto.randomBytes(&slot.mp_nonce);
    const ts: u32 = @intCast(@mod(realtimeSeconds(), 4294967296));
    slot.mp_timestamp = ts;

    var crypto_ts: [4]u8 = undefined;
    std.mem.writeInt(u32, &crypto_ts, ts, .little);

    var msg: [32]u8 = undefined;
    @memcpy(msg[0..4], &middleproxy.rpc_nonce_req);
    lock_shared(loop);
    // Defensive copy: refresh rejects secrets shorter than 16 bytes, but
    // if that invariant is ever broken we must avoid a length-mismatched
    // memcpy panic when filling the 4-byte key selector field.
    @memset(msg[4..8], 0);
    if (loop.state.middle_proxy_secret_len > 0) msg[4] = loop.state.middle_proxy_secret[0];
    if (loop.state.middle_proxy_secret_len > 1) msg[5] = loop.state.middle_proxy_secret[1];
    if (loop.state.middle_proxy_secret_len > 2) msg[6] = loop.state.middle_proxy_secret[2];
    if (loop.state.middle_proxy_secret_len > 3) msg[7] = loop.state.middle_proxy_secret[3];
    unlock_shared(loop);
    @memcpy(msg[8..12], &middleproxy.rpc_crypto_aes);
    @memcpy(msg[12..16], &crypto_ts);
    @memcpy(msg[16..32], &slot.mp_nonce);

    write_frame(loop, slot, msg[0..], false) catch {
        close_slot(loop, slot, "mp send nonce failed");
        return;
    };

    if (!hasUpstreamPending(slot)) {
        slot.mp_step = .waiting_rpc_nonce_response;
        middle_proxy_frames.readReset(slot, false);
    }
}

pub fn onWritable(slot: anytype) void {
    if (hasUpstreamPending(slot)) return;

    switch (slot.mp_step) {
        .sending_rpc_nonce => {
            slot.mp_step = .waiting_rpc_nonce_response;
            middle_proxy_frames.readReset(slot, false);
        },
        .sending_rpc_handshake => {
            slot.mp_step = .waiting_rpc_handshake_response;
            middle_proxy_frames.readReset(slot, true);
        },
        else => {},
    }
}

pub fn onReadable(
    loop: anytype,
    slot: anytype,
    comptime read_frame: fn (@TypeOf(loop), @TypeOf(slot), bool) anyerror!?[]const u8,
    comptime write_frame: fn (@TypeOf(loop), @TypeOf(slot), []const u8, bool) anyerror!void,
    comptime lock_shared: fn (@TypeOf(loop)) void,
    comptime unlock_shared: fn (@TypeOf(loop)) void,
    comptime start_relay: fn (@TypeOf(loop), @TypeOf(slot)) void,
    comptime close_slot: fn (@TypeOf(loop), @TypeOf(slot), []const u8) void,
    comptime fallback_to_direct: fn (@TypeOf(loop), @TypeOf(slot)) bool,
) void {
    switch (slot.mp_step) {
        .waiting_rpc_nonce_response => {
            const payload = read_frame(loop, slot, false) catch |err| {
                log.debug("[{d}] mp nonce frame read failed: {any}", .{ slot.conn_id, err });
                close_slot(loop, slot, "mp read nonce ans failed");
                return;
            } orelse return;

            if (payload.len != 32) {
                close_slot(loop, slot, "mp bad nonce ans len");
                return;
            }
            if (!std.mem.eql(u8, payload[0..4], &middleproxy.rpc_nonce_req)) {
                close_slot(loop, slot, "mp bad nonce ans type");
                return;
            }

            lock_shared(loop);
            const key_sel = loop.state.middle_proxy_secret[0..@min(@as(usize, 4), loop.state.middle_proxy_secret_len)];
            const secret_slice = loop.state.middle_proxy_secret[0..loop.state.middle_proxy_secret_len];
            if (!std.mem.eql(u8, payload[4..8], key_sel)) {
                unlock_shared(loop);
                close_slot(loop, slot, "mp key selector mismatch");
                return;
            }
            if (!std.mem.eql(u8, payload[8..12], &middleproxy.rpc_crypto_aes)) {
                unlock_shared(loop);
                close_slot(loop, slot, "mp crypto schema mismatch");
                return;
            }

            slot.mp_rpc_nonce_ans = payload[16..32][0..16].*;

            var ts_arr: [4]u8 = undefined;
            std.mem.writeInt(u32, &ts_arr, slot.mp_timestamp, .little);

            const tg_addr = slot.current_upstream_addr orelse {
                unlock_shared(loop);
                close_slot(loop, slot, "mp missing logical upstream addr");
                return;
            };

            const local_addr = localSocketAddress(slot.upstream_fd) catch {
                unlock_shared(loop);
                close_slot(loop, slot, "mp getsockname failed");
                return;
            };
            var middle_local_addr = local_addr;

            var tg_port: [2]u8 = undefined;
            var my_port: [2]u8 = undefined;
            var tg_ip_v4_opt: ?[4]u8 = null;
            var my_ip_v4_opt: ?[4]u8 = null;
            var tg_ip_v6_opt: ?[16]u8 = null;
            var my_ip_v6_opt: ?[16]u8 = null;

            const local_port = local_addr.getPort();
            std.mem.writeInt(u16, &my_port, local_port, .little);

            switch (tg_addr) {
                .ip4 => |tg4| {
                    var tg_ip_v4 = tg4.bytes;
                    std.mem.reverse(u8, &tg_ip_v4);
                    tg_ip_v4_opt = tg_ip_v4;

                    if (loop.state.middle_proxy_nat_ip4) |nat_ip| {
                        const my_ip_v4 = ipv4NetworkToHostBytes(nat_ip);
                        my_ip_v4_opt = my_ip_v4;
                        middle_local_addr = ip4(nat_ip, local_port);
                    }

                    std.mem.writeInt(u16, &tg_port, tg4.port, .little);
                },
                .ip6 => |tg6| {
                    tg_ip_v6_opt = tg6.bytes;

                    switch (local_addr) {
                        .ip6 => |loc6| my_ip_v6_opt = loc6.bytes,
                        .ip4 => {},
                    }

                    std.mem.writeInt(u16, &tg_port, tg6.port, .little);
                },
            }

            const tg_ip_v4_ptr: ?*const [4]u8 = if (tg_ip_v4_opt) |*ip| ip else null;
            const my_ip_v4_ptr: ?*const [4]u8 = if (my_ip_v4_opt) |*ip| ip else null;
            const my_ip_v6_ptr: ?*const [16]u8 = if (my_ip_v6_opt) |*ip| ip else null;
            const tg_ip_v6_ptr: ?*const [16]u8 = if (tg_ip_v6_opt) |*ip| ip else null;

            const enc_keys = middleproxy.getAesKeyAndIv(
                &slot.mp_rpc_nonce_ans,
                &slot.mp_nonce,
                &ts_arr,
                tg_ip_v4_ptr,
                &my_port,
                "CLIENT",
                my_ip_v4_ptr,
                &tg_port,
                secret_slice,
                my_ip_v6_ptr,
                tg_ip_v6_ptr,
            );

            const dec_keys = middleproxy.getAesKeyAndIv(
                &slot.mp_rpc_nonce_ans,
                &slot.mp_nonce,
                &ts_arr,
                tg_ip_v4_ptr,
                &my_port,
                "SERVER",
                my_ip_v4_ptr,
                &tg_port,
                secret_slice,
                my_ip_v6_ptr,
                tg_ip_v6_ptr,
            );
            unlock_shared(loop);

            slot.mp_enc = crypto.AesCbc.init(&enc_keys[0], &enc_keys[1]);
            slot.mp_dec = crypto.AesCbc.init(&dec_keys[0], &dec_keys[1]);

            var hs_msg: [32]u8 = undefined;
            @memcpy(hs_msg[0..4], &middleproxy.rpc_handshake);
            @memset(hs_msg[4..8], 0);
            @memcpy(hs_msg[8..20], "IPIPPRPDTIME");
            @memcpy(hs_msg[20..32], "IPIPPRPDTIME");

            write_frame(loop, slot, hs_msg[0..], true) catch {
                if (!fallback_to_direct(loop, slot)) {
                    close_slot(loop, slot, "mp send handshake failed");
                }
                return;
            };

            slot.mp_step = if (hasUpstreamPending(slot)) .sending_rpc_handshake else .waiting_rpc_handshake_response;
            if (!hasUpstreamPending(slot)) {
                middle_proxy_frames.readReset(slot, true);
            }
        },

        .waiting_rpc_handshake_response => {
            const payload = read_frame(loop, slot, true) catch |err| {
                log.debug("[{d}] mp handshake frame read failed: {any}", .{ slot.conn_id, err });
                if (!fallback_to_direct(loop, slot)) {
                    close_slot(loop, slot, "mp read handshake ans failed");
                }
                return;
            } orelse return;

            if (payload.len != 32) {
                if (!fallback_to_direct(loop, slot)) {
                    close_slot(loop, slot, "mp bad handshake ans len");
                }
                return;
            }
            if (!std.mem.eql(u8, payload[0..4], &middleproxy.rpc_handshake)) {
                if (!fallback_to_direct(loop, slot)) {
                    close_slot(loop, slot, "mp bad handshake ans type");
                }
                return;
            }
            if (!std.mem.eql(u8, payload[20..32], "IPIPPRPDTIME")) {
                if (!fallback_to_direct(loop, slot)) {
                    close_slot(loop, slot, "mp bad handshake pid");
                }
                return;
            }

            const local_addr = localSocketAddress(slot.upstream_fd) catch {
                if (!fallback_to_direct(loop, slot)) {
                    close_slot(loop, slot, "mp getsockname failed");
                }
                return;
            };

            var middle_local_addr = local_addr;
            if (loop.state.middle_proxy_nat_ip4) |nat_ip| {
                switch (local_addr) {
                    .ip4 => |la4| middle_local_addr = ip4(nat_ip, la4.port),
                    .ip6 => {},
                }
            }

            var conn_id: [8]u8 = undefined;
            crypto.randomBytes(&conn_id);

            slot.middle_ctx = middleproxy.MiddleProxyContext.initWithBuffer(
                loop.state.allocator,
                slot.mp_enc.?,
                slot.mp_dec.?,
                conn_id,
                slot.mp_write_seq_no,
                slot.peer_addr,
                middle_local_addr,
                slot.proto_tag,
                loop.state.config.tag,
                loop.state.config.middleProxyBufferBytes(),
            ) catch {
                if (!fallback_to_direct(loop, slot)) {
                    close_slot(loop, slot, "mp context init failed");
                }
                return;
            };

            slot.mp_step = .done;
            start_relay(loop, slot);
        },
        else => {},
    }
}
