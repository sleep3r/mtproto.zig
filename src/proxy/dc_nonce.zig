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
    defer std.crypto.secureZero(u8, &tg_nonce);

    if (slot.use_fast_mode) {
        var client_s2c_key_iv: [constants.key_len + constants.iv_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &client_s2c_key_iv);
        @memcpy(client_s2c_key_iv[0..constants.key_len], &params.encrypt_key);
        std.mem.writeInt(u128, client_s2c_key_iv[constants.key_len..][0..constants.iv_len], params.encrypt_iv, .big);
        obfuscation.prepareTgNonce(&tg_nonce, params.proto_tag, &client_s2c_key_iv);
    } else {
        obfuscation.prepareTgNonce(&tg_nonce, params.proto_tag, null);
    }

    std.mem.writeInt(i16, tg_nonce[constants.dc_idx_pos..][0..2], params.dc_idx, .little);

    const tg_enc_key_iv = tg_nonce[constants.skip_len..][0 .. constants.key_len + constants.iv_len];
    var tg_enc_key: [constants.key_len]u8 = tg_enc_key_iv[0..constants.key_len].*;
    defer std.crypto.secureZero(u8, &tg_enc_key);
    var tg_enc_iv_bytes: [constants.iv_len]u8 = tg_enc_key_iv[constants.key_len..][0..constants.iv_len].*;
    defer std.crypto.secureZero(u8, &tg_enc_iv_bytes);
    const tg_enc_iv = std.mem.readInt(u128, &tg_enc_iv_bytes, .big);

    var tg_dec_key_iv: [constants.key_len + constants.iv_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &tg_dec_key_iv);
    for (0..tg_enc_key_iv.len) |i| {
        tg_dec_key_iv[i] = tg_enc_key_iv[tg_enc_key_iv.len - 1 - i];
    }
    var tg_dec_key: [constants.key_len]u8 = tg_dec_key_iv[0..constants.key_len].*;
    defer std.crypto.secureZero(u8, &tg_dec_key);
    const tg_dec_iv = std.mem.readInt(u128, tg_dec_key_iv[constants.key_len..][0..constants.iv_len], .big);

    var tg_encryptor = crypto.AesCtr.init(&tg_enc_key, tg_enc_iv);
    defer tg_encryptor.wipe();
    var encrypted_nonce: [constants.handshake_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &encrypted_nonce);
    @memcpy(&encrypted_nonce, &tg_nonce);
    tg_encryptor.apply(&encrypted_nonce);

    var nonce_to_send: [constants.handshake_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &nonce_to_send);
    @memcpy(nonce_to_send[0..constants.proto_tag_pos], tg_nonce[0..constants.proto_tag_pos]);
    @memcpy(nonce_to_send[constants.proto_tag_pos..], encrypted_nonce[constants.proto_tag_pos..]);

    if (queue_upstream(loop, slot, &nonce_to_send)) |_| {} else |err| {
        log.debug("[{d}] queue dc nonce failed: {any}", .{ slot.conn_id, err });
        close_slot(loop, slot, "queue dc nonce failed");
        return;
    }

    // Promotion tags belong exclusively in MiddleProxy RPC_PROXY_REQ frames.

    slot.tg_encryptor = tg_encryptor;
    slot.tg_decryptor = crypto.AesCtr.init(&tg_dec_key, tg_dec_iv);
    slot.phase = .writing_dc_nonce;

    // secureZero (volatile), not @memset: these transient copies of the upstream Telegram
    // AES key/IV are never read again, so a plain memset is a dead store the optimizer may
    // drop in Release builds, leaving key material on the stack.
    std.crypto.secureZero(u8, &tg_enc_key);
    std.crypto.secureZero(u8, &tg_enc_iv_bytes);
    std.crypto.secureZero(u8, &tg_dec_key);
    std.crypto.secureZero(u8, &tg_dec_key_iv);
}
