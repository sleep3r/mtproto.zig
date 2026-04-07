//! Cryptographic primitives for MTProto proxy.
//!
//! Wraps Zig's std.crypto for:
//! - AES-256-CTR (obfuscation layer)
//! - AES-256-CBC (middle proxy protocol)
//! - SHA-256, HMAC-SHA256 (TLS handshake validation, key derivation)
//! - MD5, SHA-1 (protocol-mandated for middle proxy KDF — not replaceable)

const std = @import("std");
const Aes256 = std.crypto.core.aes.Aes256;

// ============= AES-256-CTR =============

/// AES-256-CTR stream cipher.
/// CTR mode is symmetric — encrypt and decrypt are the same operation.
pub const AesCtr = struct {
    key: [32]u8,
    /// Cached expanded key schedule (avoids re-computing on every apply())
    enc_ctx: EncCtx,
    /// Current counter value (big-endian u128)
    ctr: u128,
    /// Buffered keystream block
    buffer: [16]u8 = undefined,
    /// How many bytes remain in current keystream block
    buffer_pos: u8 = 16, // start exhausted so first call generates

    /// Expanded AES-256 encryption context type (backend-independent)
    const EncCtx = @TypeOf(Aes256.initEnc([_]u8{0} ** 32));

    pub fn init(key: *const [32]u8, iv: u128) AesCtr {
        return .{
            .key = key.*,
            .enc_ctx = Aes256.initEnc(key.*),
            .ctr = iv,
        };
    }

    pub fn initFromSlices(key: []const u8, iv: []const u8) !AesCtr {
        if (key.len != 32) return error.InvalidKeyLength;
        if (iv.len != 16) return error.InvalidIvLength;
        const k: *const [32]u8 = key[0..32];
        const iv_val = std.mem.readInt(u128, iv[0..16], .big);
        return init(k, iv_val);
    }

    /// Apply keystream to data in-place (encrypt or decrypt).
    pub fn apply(self: *AesCtr, data: []u8) void {
        var i: usize = 0;

        while (i < data.len) {
            if (self.buffer_pos >= 16) {
                // Generate new keystream block
                var ctr_bytes: [16]u8 = undefined;
                std.mem.writeInt(u128, &ctr_bytes, self.ctr, .big);
                self.enc_ctx.encrypt(&self.buffer, &ctr_bytes);
                self.ctr +%= 1;
                self.buffer_pos = 0;
            }

            const available = @as(usize, 16 - self.buffer_pos);
            const remaining = data.len - i;
            const take = @min(available, remaining);

            for (0..take) |j| {
                data[i + j] ^= self.buffer[self.buffer_pos + j];
            }

            self.buffer_pos += @intCast(take);
            i += take;
        }
    }

    /// Encrypt/decrypt into a new buffer.
    pub fn process(self: *AesCtr, allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        const result = try allocator.alloc(u8, data.len);
        @memcpy(result, data);
        self.apply(result);
        return result;
    }

    /// Securely wipe key material.
    pub fn wipe(self: *AesCtr) void {
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.buffer);
        self.ctr = 0;
        // Wipe expanded key schedule
        std.crypto.secureZero(u8, std.mem.asBytes(&self.enc_ctx));
    }
};

// ============= AES-256-CBC =============

/// AES-256-CBC cipher with proper chaining.
/// Unlike CTR, CBC is NOT symmetric.
pub const AesCbc = struct {
    key: [32]u8,
    /// Cached expanded AES contexts (avoid re-computing schedule per call).
    enc_ctx: EncCtx,
    dec_ctx: DecCtx,
    iv: [16]u8,

    const block_size = 16;
    const EncCtx = @TypeOf(Aes256.initEnc([_]u8{0} ** 32));
    const DecCtx = @TypeOf(Aes256.initDec([_]u8{0} ** 32));

    pub fn init(key: *const [32]u8, iv: *const [16]u8) AesCbc {
        return .{
            .key = key.*,
            .enc_ctx = Aes256.initEnc(key.*),
            .dec_ctx = Aes256.initDec(key.*),
            .iv = iv.*,
        };
    }

    fn xorBlocks(a: *const [16]u8, b: *const [16]u8) [16]u8 {
        var result: [16]u8 = undefined;
        for (0..16) |i| {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }

    /// Encrypt data in-place. Data length must be a multiple of 16.
    /// IV is updated after each call to support chaining across multiple calls.
    pub fn encryptInPlace(self: *AesCbc, data: []u8) !void {
        if (data.len % block_size != 0) return error.UnalignedData;
        if (data.len == 0) return;

        var prev: [16]u8 = self.iv;

        var offset: usize = 0;
        while (offset < data.len) : (offset += block_size) {
            const block: *[16]u8 = data[offset..][0..16];
            // XOR plaintext with previous ciphertext
            for (0..16) |j| {
                block[j] ^= prev[j];
            }
            // Encrypt
            var encrypted: [16]u8 = undefined;
            self.enc_ctx.encrypt(&encrypted, block);
            block.* = encrypted;
            prev = encrypted;
        }

        // Persist IV for chaining across calls
        self.iv = prev;
    }

    /// Decrypt data in-place. Data length must be a multiple of 16.
    /// IV is updated after each call to support chaining across multiple calls.
    pub fn decryptInPlace(self: *AesCbc, data: []u8) !void {
        if (data.len % block_size != 0) return error.UnalignedData;
        if (data.len == 0) return;

        var prev: [16]u8 = self.iv;

        var offset: usize = 0;
        while (offset < data.len) : (offset += block_size) {
            const block: *[16]u8 = data[offset..][0..16];
            const saved = block.*;
            // Decrypt
            var decrypted: [16]u8 = undefined;
            self.dec_ctx.decrypt(&decrypted, block);
            block.* = decrypted;
            // XOR with previous ciphertext
            for (0..16) |j| {
                block[j] ^= prev[j];
            }
            prev = saved;
        }

        // Persist IV for chaining across calls
        self.iv = prev;
    }

    pub fn wipe(self: *AesCbc) void {
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.iv);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.enc_ctx));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.dec_ctx));
    }
};

// ============= Hash Functions =============

/// SHA-256
pub fn sha256(data: []const u8) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(data);
    return h.finalResult();
}

/// SHA-256 HMAC
pub fn sha256Hmac(key: []const u8, data: []const u8) [32]u8 {
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [32]u8 = undefined;
    HmacSha256.create(&mac, data, key);
    return mac;
}

/// SHA-1 — protocol-required by Telegram Middle Proxy KDF.
pub fn sha1(data: []const u8) [20]u8 {
    var h = std.crypto.hash.Sha1.init(.{});
    h.update(data);
    return h.finalResult();
}

/// MD5 — protocol-required by Telegram Middle Proxy KDF.
pub fn md5(data: []const u8) [16]u8 {
    var h = std.crypto.hash.Md5.init(.{});
    h.update(data);
    var out: [16]u8 = undefined;
    h.final(&out);
    return out;
}

// ============= Secure Random =============

/// Fill buffer with cryptographically secure random bytes.
pub fn randomBytes(buf: []u8) void {
    std.crypto.random.bytes(buf);
}

/// Generate a random integer in [0, max).
pub fn randomRange(comptime T: type, max: T) T {
    if (max == 0) return 0;
    return std.crypto.random.intRangeLessThan(T, 0, max);
}

// ============= Tests =============

test "AesCtr roundtrip" {
    const key = [_]u8{0} ** 32;
    const iv: u128 = 12345;
    const original = "Hello, MTProto!";

    var enc = AesCtr.init(&key, iv);
    var buf: [original.len]u8 = undefined;
    @memcpy(&buf, original);
    enc.apply(&buf);

    // encrypted should differ
    try std.testing.expect(!std.mem.eql(u8, &buf, original));

    var dec = AesCtr.init(&key, iv);
    dec.apply(&buf);

    try std.testing.expectEqualSlices(u8, original, &buf);
}

test "AesCtr in-place symmetry" {
    const key = [_]u8{0x42} ** 32;
    const iv: u128 = 999;
    const original = "Test data for in-place encryption";

    var data: [original.len]u8 = undefined;
    @memcpy(&data, original);

    var c1 = AesCtr.init(&key, iv);
    c1.apply(&data);
    try std.testing.expect(!std.mem.eql(u8, &data, original));

    var c2 = AesCtr.init(&key, iv);
    c2.apply(&data);
    try std.testing.expectEqualSlices(u8, original, &data);
}

test "AesCbc roundtrip" {
    const key = [_]u8{0x12} ** 32;
    const iv = [_]u8{0x34} ** 16;

    var plaintext: [48]u8 = undefined;
    for (0..48) |i| {
        plaintext[i] = @intCast(i);
    }
    const original = plaintext;

    var cbc = AesCbc.init(&key, &iv);
    try cbc.encryptInPlace(&plaintext);
    try std.testing.expect(!std.mem.eql(u8, &plaintext, &original));

    // Reset IV for decryption (since encryptInPlace updated it)
    cbc.iv = iv;
    try cbc.decryptInPlace(&plaintext);
    try std.testing.expectEqualSlices(u8, &original, &plaintext);
}

test "AesCbc chaining works" {
    const key = [_]u8{0x42} ** 32;
    const iv = [_]u8{0x00} ** 16;
    var plaintext = [_]u8{0xAA} ** 32;

    var cbc = AesCbc.init(&key, &iv);
    try cbc.encryptInPlace(&plaintext);

    // With CBC chaining, identical plaintext blocks should produce different ciphertext blocks
    try std.testing.expect(!std.mem.eql(u8, plaintext[0..16], plaintext[16..32]));
}

test "sha256 basic" {
    const hash = sha256("");
    // SHA-256 of empty string
    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "sha256Hmac basic" {
    const mac = sha256Hmac("key", "The quick brown fox jumps over the lazy dog");
    // Known HMAC-SHA256 test vector
    const expected = [_]u8{
        0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24,
        0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
        0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59,
        0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8,
    };
    try std.testing.expectEqualSlices(u8, &expected, &mac);
}

test "sha1 basic" {
    const hash = sha1("abc");
    const expected = [_]u8{
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
        0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d,
    };
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "md5 basic" {
    const hash = md5("message digest");
    const expected = [_]u8{
        0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d,
        0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0,
    };
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}
