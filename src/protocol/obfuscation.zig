//! MTProto Obfuscation — handshake parsing and key derivation.
//!
//! The obfuscation layer uses AES-256-CTR to encrypt the connection
//! between client and proxy. Key material is derived from the 64-byte
//! handshake and the user's secret.

const std = @import("std");
const constants = @import("constants.zig");
const crypto = @import("../crypto/crypto.zig");

/// Obfuscation parameters extracted from a client handshake.
pub const ObfuscationParams = struct {
    /// Key for decrypting client -> proxy traffic
    decrypt_key: [32]u8,
    /// IV for decrypting client -> proxy traffic
    decrypt_iv: u128,
    /// Key for encrypting proxy -> client traffic
    encrypt_key: [32]u8,
    /// IV for encrypting proxy -> client traffic
    encrypt_iv: u128,
    /// Protocol tag (abridged/intermediate/secure)
    proto_tag: constants.ProtoTag,
    /// Datacenter index (signed: negative = test DC)
    dc_idx: i16,

    /// Try to parse obfuscation params from a 64-byte handshake.
    /// Tries each secret; returns params + matched username on success.
    pub fn fromHandshake(
        handshake: *const [constants.handshake_len]u8,
        secrets: []const UserSecret,
    ) ?struct { params: ObfuscationParams, user: []const u8 } {
        // Extract decrypt prekey (bytes 8..40) and IV (bytes 40..56)
        const dec_prekey_iv = handshake[constants.skip_len .. constants.skip_len + constants.prekey_len + constants.iv_len];
        const dec_prekey = dec_prekey_iv[0..constants.prekey_len];
        const dec_iv_bytes: *const [constants.iv_len]u8 = dec_prekey_iv[constants.prekey_len..][0..constants.iv_len];

        // Encrypt direction: reversed prekey+IV
        var enc_prekey_iv: [constants.prekey_len + constants.iv_len]u8 = undefined;
        for (0..dec_prekey_iv.len) |i| {
            enc_prekey_iv[i] = dec_prekey_iv[dec_prekey_iv.len - 1 - i];
        }
        const enc_prekey = enc_prekey_iv[0..constants.prekey_len];
        const enc_iv_bytes: *const [constants.iv_len]u8 = enc_prekey_iv[constants.prekey_len..][0..constants.iv_len];

        for (secrets) |entry| {
            // Derive decrypt key: SHA256(prekey || secret)
            var dec_key_input: [constants.prekey_len + 16]u8 = undefined;
            @memcpy(dec_key_input[0..constants.prekey_len], dec_prekey);
            @memcpy(dec_key_input[constants.prekey_len..], &entry.secret);
            const decrypt_key = crypto.sha256(&dec_key_input);

            const decrypt_iv = std.mem.readInt(u128, dec_iv_bytes, .big);

            // Decrypt the handshake to check proto tag
            var decryptor = crypto.AesCtr.init(&decrypt_key, decrypt_iv);
            defer decryptor.wipe();
            var decrypted: [constants.handshake_len]u8 = undefined;
            @memcpy(&decrypted, handshake);
            decryptor.apply(&decrypted);

            // Check proto tag at offset 56
            const tag_bytes: [4]u8 = decrypted[constants.proto_tag_pos..][0..4].*;
            const proto_tag = constants.ProtoTag.fromBytes(tag_bytes) orelse continue;

            // Extract DC index at offset 60
            const dc_idx = std.mem.readInt(i16, decrypted[constants.dc_idx_pos..][0..2], .little);

            // Derive encrypt key
            var enc_key_input: [constants.prekey_len + 16]u8 = undefined;
            @memcpy(enc_key_input[0..constants.prekey_len], enc_prekey);
            @memcpy(enc_key_input[constants.prekey_len..], &entry.secret);
            const encrypt_key = crypto.sha256(&enc_key_input);
            const encrypt_iv = std.mem.readInt(u128, enc_iv_bytes, .big);

            return .{
                .params = .{
                    .decrypt_key = decrypt_key,
                    .decrypt_iv = decrypt_iv,
                    .encrypt_key = encrypt_key,
                    .encrypt_iv = encrypt_iv,
                    .proto_tag = proto_tag,
                    .dc_idx = dc_idx,
                },
                .user = entry.name,
            };
        }

        return null;
    }

    /// Create AES-CTR decryptor for client -> proxy direction.
    pub fn createDecryptor(self: *const ObfuscationParams) crypto.AesCtr {
        return crypto.AesCtr.init(&self.decrypt_key, self.decrypt_iv);
    }

    /// Create AES-CTR encryptor for proxy -> client direction.
    pub fn createEncryptor(self: *const ObfuscationParams) crypto.AesCtr {
        return crypto.AesCtr.init(&self.encrypt_key, self.encrypt_iv);
    }

    /// Securely wipe key material.
    pub fn wipe(self: *ObfuscationParams) void {
        @memset(&self.decrypt_key, 0);
        self.decrypt_iv = 0;
        @memset(&self.encrypt_key, 0);
        self.encrypt_iv = 0;
    }
};

/// A user's name and decoded 16-byte secret.
pub const UserSecret = struct {
    name: []const u8,
    secret: [16]u8,
};

/// Check if a 64-byte nonce is valid (doesn't match reserved patterns).
pub fn isValidNonce(nonce: *const [constants.handshake_len]u8) bool {
    // Check first byte
    for (constants.reserved_nonce_first_bytes) |b| {
        if (nonce[0] == b) return false;
    }

    // Check first 4 bytes
    const first_four: [4]u8 = nonce[0..4].*;
    for (constants.reserved_nonce_beginnings) |reserved| {
        if (std.mem.eql(u8, &first_four, &reserved)) return false;
    }

    // Check bytes 4..8
    const continue_four: [4]u8 = nonce[4..8].*;
    for (constants.reserved_nonce_continues) |reserved| {
        if (std.mem.eql(u8, &continue_four, &reserved)) return false;
    }

    return true;
}

/// Generate a valid random 64-byte nonce.
pub fn generateNonce() [constants.handshake_len]u8 {
    while (true) {
        var nonce: [constants.handshake_len]u8 = undefined;
        crypto.randomBytes(&nonce);
        if (isValidNonce(&nonce)) return nonce;
    }
}

/// Prepare nonce for sending to Telegram DC.
/// Sets proto tag at offset 56 and optionally embeds reversed key+IV.
pub fn prepareTgNonce(
    nonce: *[constants.handshake_len]u8,
    proto_tag: constants.ProtoTag,
    enc_key_iv: ?[]const u8,
) void {
    const tag_bytes = proto_tag.toBytes();
    @memcpy(nonce[constants.proto_tag_pos..][0..4], &tag_bytes);

    if (enc_key_iv) |key_iv| {
        // Reverse the key+IV into the nonce
        var reversed: [constants.key_len + constants.iv_len]u8 = undefined;
        for (0..key_iv.len) |i| {
            reversed[i] = key_iv[key_iv.len - 1 - i];
        }
        @memcpy(nonce[constants.skip_len..][0 .. constants.key_len + constants.iv_len], &reversed);
    }
}

// ============= Tests =============

test "isValidNonce" {
    // Valid nonce
    var valid = [_]u8{0x42} ** constants.handshake_len;
    valid[4] = 1;
    valid[5] = 2;
    valid[6] = 3;
    valid[7] = 4;
    try std.testing.expect(isValidNonce(&valid));

    // Invalid: starts with 0xef
    var invalid1 = [_]u8{0x00} ** constants.handshake_len;
    invalid1[0] = 0xef;
    try std.testing.expect(!isValidNonce(&invalid1));

    // Invalid: starts with "HEAD"
    var invalid2 = [_]u8{0x00} ** constants.handshake_len;
    invalid2[0] = 'H';
    invalid2[1] = 'E';
    invalid2[2] = 'A';
    invalid2[3] = 'D';
    try std.testing.expect(!isValidNonce(&invalid2));

    // Invalid: bytes 4..8 are all zeros
    var invalid3 = [_]u8{0x42} ** constants.handshake_len;
    invalid3[4] = 0;
    invalid3[5] = 0;
    invalid3[6] = 0;
    invalid3[7] = 0;
    try std.testing.expect(!isValidNonce(&invalid3));
}

test "generateNonce produces valid nonces" {
    const nonce = generateNonce();
    try std.testing.expect(isValidNonce(&nonce));
    try std.testing.expectEqual(@as(usize, constants.handshake_len), nonce.len);
}

test "prepareTgNonce - intermediate tag" {
    var nonce: [64]u8 = [_]u8{0x00} ** 64;
    prepareTgNonce(&nonce, constants.ProtoTag.intermediate, null);

    // Check that bytes 56-59 are the intermediate tag (eeeeeeee)
    const expected_tag = constants.ProtoTag.intermediate.toBytes();
    try std.testing.expectEqualStrings(&expected_tag, nonce[56..60]);
}

test "prepareTgNonce - fast mode key inversion" {
    var nonce: [64]u8 = [_]u8{0x00} ** 64;

    // 32-byte key + 16-byte IV = 48 bytes
    var client_key_iv: [48]u8 = undefined;
    for (0..48) |i| client_key_iv[i] = @intCast(i);

    prepareTgNonce(&nonce, constants.ProtoTag.abridged, &client_key_iv);

    // Check proto tag
    const expected_tag = constants.ProtoTag.abridged.toBytes();
    try std.testing.expectEqualStrings(&expected_tag, nonce[56..60]);

    // Check key inversion at offset 8 (skip_len)
    // The key_iv should be written entirely in reverse
    for (0..48) |i| {
        const expected_byte = client_key_iv[48 - 1 - i];
        try std.testing.expectEqual(expected_byte, nonce[8 + i]);
    }
}

fn buildClientObfuscatedHandshake(
    secret: [16]u8,
    proto_tag: constants.ProtoTag,
    dc_idx: i16,
) [constants.handshake_len]u8 {
    var plain = generateNonce();
    const tag = proto_tag.toBytes();
    @memcpy(plain[constants.proto_tag_pos..][0..4], &tag);
    std.mem.writeInt(i16, plain[constants.dc_idx_pos..][0..2], dc_idx, .little);

    const dec_prekey = plain[constants.skip_len .. constants.skip_len + constants.prekey_len];
    const dec_iv_bytes = plain[constants.skip_len + constants.prekey_len .. constants.skip_len + constants.prekey_len + constants.iv_len];
    const dec_iv = std.mem.readInt(u128, dec_iv_bytes, .big);

    var key_input: [constants.prekey_len + 16]u8 = undefined;
    @memcpy(key_input[0..constants.prekey_len], dec_prekey);
    @memcpy(key_input[constants.prekey_len..], &secret);
    const decrypt_key = crypto.sha256(&key_input);

    var enc = crypto.AesCtr.init(&decrypt_key, dec_iv);
    defer enc.wipe();
    var encrypted = plain;
    enc.apply(&encrypted);

    var wire = plain;
    @memcpy(wire[constants.proto_tag_pos..], encrypted[constants.proto_tag_pos..]);
    return wire;
}

test "fromHandshake - valid roundtrip and wrong secret rejection" {
    const secret = [_]u8{0x42} ** 16;
    const hs = buildClientObfuscatedHandshake(secret, .intermediate, 2);

    const ok = [_]UserSecret{.{ .name = "alice", .secret = secret }};
    const parsed = ObfuscationParams.fromHandshake(&hs, &ok);
    try std.testing.expect(parsed != null);
    try std.testing.expectEqual(constants.ProtoTag.intermediate, parsed.?.params.proto_tag);
    try std.testing.expectEqual(@as(i16, 2), parsed.?.params.dc_idx);
    try std.testing.expectEqualStrings("alice", parsed.?.user);

    const wrong = [_]UserSecret{.{ .name = "bob", .secret = [_]u8{0x11} ** 16 }};
    try std.testing.expect(ObfuscationParams.fromHandshake(&hs, &wrong) == null);
}

test "fromHandshake - fuzz malformed/random handshakes" {
    var prng = std.Random.DefaultPrng.init(0x0BF016A);
    const random = prng.random();

    var hs: [constants.handshake_len]u8 = undefined;
    const secrets = [_]UserSecret{
        .{ .name = "alice", .secret = [_]u8{0x1A} ** 16 },
        .{ .name = "bob", .secret = [_]u8{0x2B} ** 16 },
    };

    for (0..3000) |i| {
        random.bytes(&hs);
        if ((i % 5) == 0) {
            hs = buildClientObfuscatedHandshake(secrets[0].secret, .abridged, -3);
            // Corrupt one random byte to exercise near-valid malformed cases.
            const idx: usize = @as(usize, random.int(u8)) % hs.len;
            hs[idx] ^=
                0x01;
        }

        if (ObfuscationParams.fromHandshake(&hs, &secrets)) |parsed| {
            try std.testing.expect(parsed.user.len > 0);
            try std.testing.expect(parsed.params.dc_idx != 0);
        }
    }
}
