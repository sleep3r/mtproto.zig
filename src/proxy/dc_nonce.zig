const std = @import("std");

const constants = @import("../protocol/constants.zig");
const crypto = @import("../crypto/crypto.zig");
const obfuscation = @import("../protocol/obfuscation.zig");

const log = std.log.scoped(.proxy);

pub fn send(
    loop: anytype,
    slot: anytype,
    comptime queue_upstream: fn (@TypeOf(loop), @TypeOf(slot), []const u8) anyerror!bool,
    comptime close_slot: fn (@TypeOf(loop), @TypeOf(slot), []const u8) void,
) void {
    const params = slot.obf_params orelse {
        close_slot(loop, slot, "missing obfuscation params");
        return;
    };

    var tg_nonce = obfuscation.generateNonce();

    if (slot.use_fast_mode) {
        var client_s2c_key_iv: [constants.key_len + constants.iv_len]u8 = undefined;
        @memcpy(client_s2c_key_iv[0..constants.key_len], &params.encrypt_key);
        std.mem.writeInt(u128, client_s2c_key_iv[constants.key_len..][0..constants.iv_len], params.encrypt_iv, .big);
        obfuscation.prepareTgNonce(&tg_nonce, params.proto_tag, &client_s2c_key_iv);
    } else {
        obfuscation.prepareTgNonce(&tg_nonce, params.proto_tag, null);
    }

    std.mem.writeInt(i16, tg_nonce[constants.dc_idx_pos..][0..2], params.dc_idx, .little);

    const tg_enc_key_iv = tg_nonce[constants.skip_len..][0 .. constants.key_len + constants.iv_len];
    var tg_enc_key: [constants.key_len]u8 = tg_enc_key_iv[0..constants.key_len].*;
    var tg_enc_iv_bytes: [constants.iv_len]u8 = tg_enc_key_iv[constants.key_len..][0..constants.iv_len].*;
    const tg_enc_iv = std.mem.readInt(u128, &tg_enc_iv_bytes, .big);

    var tg_dec_key_iv: [constants.key_len + constants.iv_len]u8 = undefined;
    for (0..tg_enc_key_iv.len) |i| {
        tg_dec_key_iv[i] = tg_enc_key_iv[tg_enc_key_iv.len - 1 - i];
    }
    var tg_dec_key: [constants.key_len]u8 = tg_dec_key_iv[0..constants.key_len].*;
    const tg_dec_iv = std.mem.readInt(u128, tg_dec_key_iv[constants.key_len..][0..constants.iv_len], .big);

    var tg_encryptor = crypto.AesCtr.init(&tg_enc_key, tg_enc_iv);
    var encrypted_nonce: [constants.handshake_len]u8 = undefined;
    @memcpy(&encrypted_nonce, &tg_nonce);
    tg_encryptor.apply(&encrypted_nonce);

    var nonce_to_send: [constants.handshake_len]u8 = undefined;
    @memcpy(nonce_to_send[0..constants.proto_tag_pos], tg_nonce[0..constants.proto_tag_pos]);
    @memcpy(nonce_to_send[constants.proto_tag_pos..], encrypted_nonce[constants.proto_tag_pos..]);

    if (queue_upstream(loop, slot, &nonce_to_send)) |_| {} else |err| {
        log.debug("[{d}] queue dc nonce failed: {any}", .{ slot.conn_id, err });
        close_slot(loop, slot, "queue dc nonce failed");
        return;
    }

    // Promotion tag (optional), only for primary DC1..5.
    if (loop.state.config.tag) |tag| {
        const dc_abs = if (params.dc_idx > 0) @as(usize, @intCast(params.dc_idx)) else @as(usize, @abs(params.dc_idx));
        if (dc_abs >= 1 and dc_abs <= constants.tg_datacenters_v4.len and dc_abs != 203) {
            var promote_buf: [32]u8 = undefined;
            var packet_len: usize = 0;

            const rpc_id: u32 = 0xaeaf0c42;
            var rpc_payload: [20]u8 = undefined;
            std.mem.writeInt(u32, rpc_payload[0..4], rpc_id, .little);
            @memcpy(rpc_payload[4..20], &tag);

            switch (params.proto_tag) {
                .abridged => {
                    promote_buf[0] = 5;
                    @memcpy(promote_buf[1..21], &rpc_payload);
                    packet_len = 21;
                },
                .intermediate, .secure => {
                    std.mem.writeInt(u32, promote_buf[0..4], 20, .little);
                    @memcpy(promote_buf[4..24], &rpc_payload);
                    packet_len = 24;
                },
            }

            const tail = loop.state.allocator.alloc(u8, packet_len) catch {
                close_slot(loop, slot, "alloc promotion tail failed");
                return;
            };
            @memcpy(tail, promote_buf[0..packet_len]);
            tg_encryptor.apply(tail);
            slot.dc_initial_tail = tail;
        }
    }

    slot.tg_encryptor = tg_encryptor;
    slot.tg_decryptor = crypto.AesCtr.init(&tg_dec_key, tg_dec_iv);
    slot.phase = .writing_dc_nonce;

    @memset(&tg_enc_key, 0);
    @memset(&tg_enc_iv_bytes, 0);
    @memset(&tg_dec_key, 0);
    @memset(&tg_dec_key_iv, 0);
}
