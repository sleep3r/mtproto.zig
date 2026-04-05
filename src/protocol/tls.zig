//! Fake TLS 1.3 Handshake
//!
//! Validates TLS ClientHello against user secrets (HMAC-SHA256) and
//! builds fake ServerHello responses for domain fronting.

const std = @import("std");
const constants = @import("constants.zig");
const crypto = @import("../crypto/crypto.zig");
const obfuscation = @import("obfuscation.zig");

/// Re-export for convenience
pub const UserSecret = obfuscation.UserSecret;

// ============= TLS Validation Result =============

pub const TlsValidation = struct {
    /// Username that validated
    user: []const u8,
    /// Session ID from ClientHello
    session_id: []const u8,
    /// Client digest for response generation
    digest: [constants.tls_digest_len]u8,
    /// Canonical HMAC before timestamp XOR masking (for replay protection)
    canonical_hmac: [constants.tls_digest_len]u8,
    /// Timestamp extracted from digest
    timestamp: u32,
    /// The 16-byte user secret that matched (needed for ServerHello HMAC)
    secret: [16]u8,
};

// ============= Public Functions =============

/// Validate a TLS ClientHello against user secrets.
/// Returns validation result if a matching user is found.
pub fn validateTlsHandshake(
    allocator: std.mem.Allocator,
    handshake: []const u8,
    secrets: []const UserSecret,
    ignore_time_skew: bool,
) !?TlsValidation {
    const min_len = constants.tls_digest_pos + constants.tls_digest_len + 1;
    if (handshake.len < min_len) return null;

    // Extract digest
    const digest: [constants.tls_digest_len]u8 = handshake[constants.tls_digest_pos..][0..constants.tls_digest_len].*;

    // Extract session ID
    const session_id_len_pos = constants.tls_digest_pos + constants.tls_digest_len;
    if (session_id_len_pos >= handshake.len) return null;
    const session_id_len: usize = handshake[session_id_len_pos];
    if (session_id_len > 32) return null;

    const session_id_start = session_id_len_pos + 1;
    if (handshake.len < session_id_start + session_id_len) return null;

    // Build message with zeroed digest for HMAC
    const msg = try allocator.alloc(u8, handshake.len);
    defer allocator.free(msg);
    @memcpy(msg, handshake);
    @memset(msg[constants.tls_digest_pos..][0..constants.tls_digest_len], 0);

    const now: i64 = if (!ignore_time_skew)
        @intCast(std.time.timestamp())
    else
        0;

    for (secrets) |entry| {
        const computed = crypto.sha256Hmac(&entry.secret, msg);

        // Constant-time comparison of first 28 bytes using stdlib
        if (!std.crypto.timing_safe.eql([28]u8, digest[0..28].*, computed[0..28].*)) continue;

        // Extract timestamp from last 4 bytes (XOR)
        const timestamp = std.mem.readInt(u32, &[4]u8{
            digest[28] ^ computed[28],
            digest[29] ^ computed[29],
            digest[30] ^ computed[30],
            digest[31] ^ computed[31],
        }, .little);

        if (!ignore_time_skew) {
            const time_diff = now - @as(i64, @intCast(timestamp));
            if (time_diff < constants.time_skew_min or time_diff > constants.time_skew_max) {
                continue;
            }
        }

        return .{
            .user = entry.name,
            .session_id = handshake[session_id_start .. session_id_start + session_id_len],
            .digest = digest,
            .canonical_hmac = computed,
            .timestamp = timestamp,
            .secret = entry.secret,
        };
    }

    return null;
}

/// Build a fake TLS ServerHello response using a pre-built Nginx/OpenSSL template.
///
/// The response consists of three TLS records that the client validates:
/// 1. ServerHello record (type 0x16) — contains the HMAC digest in the `random` field
/// 2. Change Cipher Spec record (type 0x14) — fixed 6 bytes
/// 3. Fake Application Data record (type 0x17) — fixed-size body simulating encrypted cert
///
/// Template approach: instead of hand-crafting bytes (which DPI fingerprints as non-Nginx),
/// we use a comptime-built template that matches real Nginx/OpenSSL TLS 1.3 fingerprint:
/// - Extensions in OpenSSL order: supported_versions THEN key_share
/// - Fixed AppData size (consistent like a real certificate, not random)
/// - Deterministic pseudo-random AppData body (high entropy, same every time)
///
/// Only three fields are patched at runtime:
/// - Server Random (offset 11..43): HMAC-SHA256 digest
/// - Session ID (offset 44..76): echoed from ClientHello
/// - X25519 key (offset 95..127): fresh random key
///
/// The client (ConnectionSocket.cpp) validates the response by:
/// - Checking for `\x16\x03\x03` prefix (ServerHello record)
/// - Reading len1 (ServerHello record payload length)
/// - Checking for `\x14\x03\x03\x00\x01\x01\x17\x03\x03` after the ServerHello record
/// - Reading len2 (Application Data payload length)
/// - Waiting for all `len1 + 5 + 11 + len2` bytes
/// - Saving bytes at offset 11..43 (the random field), zeroing them
/// - Computing HMAC-SHA256(secret, client_digest || entire_response_with_zeroed_random)
/// - Comparing the HMAC to the saved random field (straight 32-byte compare, no XOR)
pub fn buildServerHello(
    allocator: std.mem.Allocator,
    secret: []const u8,
    client_digest: *const [constants.tls_digest_len]u8,
    session_id: []const u8,
) ![]u8 {
    // 1. Copy the pre-built Nginx template (random and session_id are zeroed in template)
    const response = try allocator.alloc(u8, nginx_template.len);
    errdefer allocator.free(response);
    @memcpy(response, &nginx_template);

    // 2. Patch Session ID (echo from client). Template assumes 32-byte session ID.
    if (session_id.len == 32) {
        @memcpy(response[tmpl_session_id_offset..][0..32], session_id);
    } else if (session_id.len <= 32) {
        // Non-standard length: patch the length byte and copy what we have
        response[tmpl_session_id_offset - 1] = @intCast(session_id.len);
        @memcpy(response[tmpl_session_id_offset..][0..session_id.len], session_id);
    }

    // 3. Patch X25519 public key with fresh random bytes
    var x25519_key: [32]u8 = undefined;
    crypto.randomBytes(&x25519_key);
    @memcpy(response[tmpl_x25519_key_offset..][0..32], &x25519_key);

    // 4. Compute HMAC over full response with random field zeroed.
    //    Template already has zeros at offset 11..43, so HMAC input is correct.
    const hmac_input = try allocator.alloc(u8, constants.tls_digest_len + response.len);
    defer allocator.free(hmac_input);
    @memcpy(hmac_input[0..constants.tls_digest_len], client_digest);
    @memcpy(hmac_input[constants.tls_digest_len..], response);

    const response_digest = crypto.sha256Hmac(secret, hmac_input);

    // 5. Insert HMAC digest into Server Random field
    @memcpy(response[tmpl_random_offset..][0..32], &response_digest);

    return response;
}

// ============= Nginx/OpenSSL TLS 1.3 Template =============
//
// Pre-built at comptime to match the fingerprint of Nginx 1.25+ with OpenSSL 3.x.
// Structure: ServerHello (127 bytes) + CCS (6 bytes) + AppData (5 + 2878 bytes)
//
// Key differences from naive FakeTLS that DPI detects:
// 1. Extension ordering: OpenSSL sends supported_versions (0x002b) BEFORE key_share (0x0033)
// 2. AppData size: fixed 2878 bytes (realistic Let's Encrypt ECDSA cert chain),
//    NOT random in [1024,4096) which is an entropy fingerprint
// 3. AppData body: deterministic pseudo-random (same across connections, like a real cert)

/// Offset of Server Random field (32 bytes) — patched with HMAC at runtime
const tmpl_random_offset: usize = 11;
/// Offset of Session ID (32 bytes) — echoed from client at runtime
const tmpl_session_id_offset: usize = 44;
/// Offset of X25519 public key (32 bytes) — filled with random at runtime
const tmpl_x25519_key_offset: usize = 95;

/// Fake encrypted certificate payload size.
/// 2878 bytes matches a typical Nginx + Let's Encrypt ECDSA P-256 cert chain:
///   EncryptedExtensions (~20) + Certificate (~2400) + CertificateVerify (~100) +
///   Finished (~36) + AEAD tags (~50) + record layer overhead.
/// Fixed size eliminates the random-range fingerprint that ТСПУ detects.
const fake_cert_payload_len: u16 = 2878;

/// Total template size: ServerHello(127) + CCS(6) + AppData(5 + 2878)
const nginx_template_len: usize = 127 + 6 + 5 + fake_cert_payload_len;

/// The pre-built template, constructed at comptime.
const nginx_template: [nginx_template_len]u8 = buildNginxTemplate();

fn buildNginxTemplate() [nginx_template_len]u8 {
    @setEvalBranchQuota(100_000);
    var t: [nginx_template_len]u8 = undefined;
    var pos: usize = 0;

    // ── Record 1: ServerHello ──────────────────────────────────
    // Record header: type(1) + version(2) + length(2) = 5 bytes
    t[pos] = 0x16; // Handshake
    pos += 1;
    t[pos] = 0x03;
    t[pos + 1] = 0x03; // TLS 1.2 compat
    pos += 2;
    t[pos] = 0x00;
    t[pos + 1] = 0x7A; // Record payload length = 122
    pos += 2;

    // Handshake header: type(1) + length(3) = 4 bytes
    t[pos] = 0x02; // ServerHello
    pos += 1;
    t[pos] = 0x00;
    t[pos + 1] = 0x00;
    t[pos + 2] = 0x76; // Handshake body length = 118
    pos += 3;

    // Server version: TLS 1.2 (legacy, per RFC 8446)
    t[pos] = 0x03;
    t[pos + 1] = 0x03;
    pos += 2;

    // Server Random: 32 zero bytes (PLACEHOLDER — patched with HMAC at runtime)
    for (0..32) |i| {
        t[pos + i] = 0x00;
    }
    pos += 32;

    // Session ID length: 32 (TLS 1.3 compatibility mode)
    t[pos] = 0x20;
    pos += 1;

    // Session ID: 32 zero bytes (PLACEHOLDER — echoed from client at runtime)
    for (0..32) |i| {
        t[pos + i] = 0x00;
    }
    pos += 32;

    // Cipher suite: TLS_AES_128_GCM_SHA256 (0x1301) — most common in Nginx
    t[pos] = 0x13;
    t[pos + 1] = 0x01;
    pos += 2;

    // Compression: none
    t[pos] = 0x00;
    pos += 1;

    // Extensions length: 46 bytes (supported_versions: 6 + key_share: 40)
    t[pos] = 0x00;
    t[pos + 1] = 0x2E;
    pos += 2;

    // Extension: supported_versions (0x002b) — OpenSSL sends this FIRST
    t[pos] = 0x00;
    t[pos + 1] = 0x2B;
    t[pos + 2] = 0x00;
    t[pos + 3] = 0x02; // length
    t[pos + 4] = 0x03;
    t[pos + 5] = 0x04; // TLS 1.3
    pos += 6;

    // Extension: key_share (0x0033) — x25519
    t[pos] = 0x00;
    t[pos + 1] = 0x33;
    t[pos + 2] = 0x00;
    t[pos + 3] = 0x24; // length = 36
    t[pos + 4] = 0x00;
    t[pos + 5] = 0x1D; // x25519 group
    t[pos + 6] = 0x00;
    t[pos + 7] = 0x20; // key length = 32
    pos += 8;

    // X25519 public key: 32 zero bytes (PLACEHOLDER — random at runtime)
    for (0..32) |i| {
        t[pos + i] = 0x00;
    }
    pos += 32;

    // ── Record 2: Change Cipher Spec ──────────────────────────
    t[pos] = 0x14; // CCS type
    t[pos + 1] = 0x03;
    t[pos + 2] = 0x03; // TLS 1.2
    t[pos + 3] = 0x00;
    t[pos + 4] = 0x01; // length = 1
    t[pos + 5] = 0x01; // CCS byte
    pos += 6;

    // ── Record 3: Fake Application Data (encrypted certificate) ─
    t[pos] = 0x17; // Application Data type
    t[pos + 1] = 0x03;
    t[pos + 2] = 0x03; // TLS 1.2
    // Payload length in big-endian
    t[pos + 3] = @intCast((fake_cert_payload_len >> 8) & 0xFF);
    t[pos + 4] = @intCast(fake_cert_payload_len & 0xFF);
    pos += 5;

    // Fill with deterministic pseudo-random bytes (SplitMix64).
    // Looks like encrypted data to DPI, same every time like a real cert.
    var prng_state: u64 = 0x4E67_696E_785F_544C; // "NginX_TL" as seed
    for (0..fake_cert_payload_len) |i| {
        prng_state +%= 0x9E3779B97F4A7C15;
        var z = prng_state;
        z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
        z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;
        z = z ^ (z >> 31);
        t[pos + i] = @intCast((z >> 24) & 0xFF);
    }
    pos += fake_cert_payload_len;

    if (pos != nginx_template_len) unreachable;
    return t;
}

/// Check if bytes look like a TLS ClientHello.
pub fn isTlsHandshake(first_bytes: []const u8) bool {
    if (first_bytes.len < 3) return false;
    return first_bytes[0] == constants.tls_record_handshake and
        first_bytes[1] == 0x03 and
        (first_bytes[2] == 0x01 or first_bytes[2] == 0x03);
}

/// Extract SNI from a TLS ClientHello.
pub fn extractSni(handshake: []const u8) ?[]const u8 {
    if (handshake.len < 43 or handshake[0] != constants.tls_record_handshake) return null;

    const record_len = std.mem.readInt(u16, handshake[3..5], .big);
    if (handshake.len < @as(usize, 5) + record_len) return null;

    var pos: usize = 5;
    if (pos >= handshake.len or handshake[pos] != 0x01) return null; // not ClientHello

    pos += 4; // type + 3-byte length
    pos += 2 + 32; // version + random

    if (pos + 1 > handshake.len) return null;
    const session_id_len: usize = handshake[pos];
    pos += 1 + session_id_len;

    if (pos + 2 > handshake.len) return null;
    const cipher_suites_len = std.mem.readInt(u16, handshake[pos..][0..2], .big);
    pos += 2 + cipher_suites_len;

    if (pos + 1 > handshake.len) return null;
    const comp_len: usize = handshake[pos];
    pos += 1 + comp_len;

    if (pos + 2 > handshake.len) return null;
    const ext_total_len = std.mem.readInt(u16, handshake[pos..][0..2], .big);
    pos += 2;
    const ext_end = pos + ext_total_len;
    if (ext_end > handshake.len) return null;

    // Walk extensions
    while (pos + 4 <= ext_end) {
        const etype = std.mem.readInt(u16, handshake[pos..][0..2], .big);
        const elen = std.mem.readInt(u16, handshake[pos + 2 ..][0..2], .big);
        pos += 4;
        if (pos + elen > ext_end) break;

        if (etype == 0x0000 and elen >= 5) {
            // server_name extension
            var sn_pos = pos + 2; // skip list_len
            const sn_end = @min(pos + elen, ext_end);
            while (sn_pos + 3 <= sn_end) {
                const name_type = handshake[sn_pos];
                const name_len = std.mem.readInt(u16, handshake[sn_pos + 1 ..][0..2], .big);
                sn_pos += 3;
                if (sn_pos + name_len > sn_end) break;
                if (name_type == 0 and name_len > 0) {
                    return handshake[sn_pos .. sn_pos + name_len];
                }
                sn_pos += name_len;
            }
        }
        pos += elen;
    }

    return null;
}

// ============= Tests =============

test "isTlsHandshake" {
    try std.testing.expect(isTlsHandshake(&[_]u8{ 0x16, 0x03, 0x01 }));
    try std.testing.expect(isTlsHandshake(&[_]u8{ 0x16, 0x03, 0x03 }));
    try std.testing.expect(!isTlsHandshake(&[_]u8{ 0x16, 0x03 }));
    try std.testing.expect(!isTlsHandshake(&[_]u8{ 0x17, 0x03, 0x03 }));
}

test "timing_safe.eql" {
    const a = [_]u8{ 1, 2, 3 };
    const b = [_]u8{ 1, 2, 3 };
    const c = [_]u8{ 1, 2, 4 };
    try std.testing.expect(std.crypto.timing_safe.eql([3]u8, a, b));
    try std.testing.expect(!std.crypto.timing_safe.eql([3]u8, a, c));
}

test "buildServerHello produces valid three-record Nginx template structure" {
    const allocator = std.testing.allocator;
    var digest = [_]u8{0x42} ** 32;
    const session_id = [_]u8{0x01} ** 32;

    const response = try buildServerHello(
        allocator,
        &digest,
        &digest,
        &session_id,
    );
    defer allocator.free(response);

    // Template produces fixed-size response
    try std.testing.expectEqual(nginx_template_len, response.len);

    // Record 1: ServerHello (\x16\x03\x03)
    try std.testing.expectEqual(@as(u8, constants.tls_record_handshake), response[0]);
    try std.testing.expectEqual(@as(u8, 0x03), response[1]);
    try std.testing.expectEqual(@as(u8, 0x03), response[2]);

    const len1 = std.mem.readInt(u16, response[3..5], .big);
    try std.testing.expectEqual(@as(u16, 122), len1); // Fixed ServerHello payload
    const ccs_start = 5 + @as(usize, len1);

    // Record 2: Change Cipher Spec (\x14\x03\x03\x00\x01\x01)
    try std.testing.expect(response.len > ccs_start + 6);
    try std.testing.expectEqual(@as(u8, constants.tls_record_change_cipher), response[ccs_start]);
    try std.testing.expectEqual(@as(u8, 0x03), response[ccs_start + 1]);
    try std.testing.expectEqual(@as(u8, 0x03), response[ccs_start + 2]);
    try std.testing.expectEqual(@as(u8, 0x00), response[ccs_start + 3]);
    try std.testing.expectEqual(@as(u8, 0x01), response[ccs_start + 4]);
    try std.testing.expectEqual(@as(u8, 0x01), response[ccs_start + 5]);

    // Record 3: Application Data (\x17\x03\x03)
    const app_start = ccs_start + 6;
    try std.testing.expect(response.len > app_start + 5);
    try std.testing.expectEqual(@as(u8, constants.tls_record_application), response[app_start]);
    try std.testing.expectEqual(@as(u8, 0x03), response[app_start + 1]);
    try std.testing.expectEqual(@as(u8, 0x03), response[app_start + 2]);

    const len2 = std.mem.readInt(u16, response[app_start + 3 ..][0..2], .big);
    // AppData is now FIXED size (Nginx template), not random
    try std.testing.expectEqual(fake_cert_payload_len, len2);

    // Total response length should match all three records
    try std.testing.expectEqual(5 + @as(usize, len1) + 6 + 5 + @as(usize, len2), response.len);

    // Extension ordering: supported_versions (0x002b) BEFORE key_share (0x0033)
    // Extensions start at offset 81
    try std.testing.expectEqual(@as(u8, 0x00), response[81]); // supported_versions ext type hi
    try std.testing.expectEqual(@as(u8, 0x2B), response[82]); // supported_versions ext type lo
    try std.testing.expectEqual(@as(u8, 0x00), response[87]); // key_share ext type hi
    try std.testing.expectEqual(@as(u8, 0x33), response[88]); // key_share ext type lo

    // Session ID was echoed correctly
    try std.testing.expectEqualSlices(u8, &session_id, response[tmpl_session_id_offset..][0..32]);

    // HMAC digest is at offset 11 (tls_digest_pos) in the response
    // Verify it by recomputing: HMAC(secret, client_digest || response_with_zeroed_random)
    var zeroed = try allocator.alloc(u8, response.len);
    defer allocator.free(zeroed);
    @memcpy(zeroed, response);
    @memset(zeroed[constants.tls_digest_pos..][0..constants.tls_digest_len], 0);

    var hmac_input = try allocator.alloc(u8, constants.tls_digest_len + response.len);
    defer allocator.free(hmac_input);
    @memcpy(hmac_input[0..constants.tls_digest_len], &digest);
    @memcpy(hmac_input[constants.tls_digest_len..], zeroed);

    const expected_hmac = crypto.sha256Hmac(&digest, hmac_input);
    try std.testing.expect(std.crypto.timing_safe.eql(
        [32]u8,
        response[constants.tls_digest_pos..][0..32].*,
        expected_hmac,
    ));
}

test "buildServerHello deterministic AppData (no random size fingerprint)" {
    const allocator = std.testing.allocator;
    var digest = [_]u8{0xAA} ** 32;
    const session_id = [_]u8{0xBB} ** 32;

    // Build two responses — AppData body should be identical (deterministic template)
    const r1 = try buildServerHello(allocator, &digest, &digest, &session_id);
    defer allocator.free(r1);
    const r2 = try buildServerHello(allocator, &digest, &digest, &session_id);
    defer allocator.free(r2);

    // Same total size (fixed template)
    try std.testing.expectEqual(r1.len, r2.len);

    // AppData bodies are identical (deterministic PRNG, same "certificate" every time)
    const app_offset = 127 + 6 + 5; // after ServerHello + CCS + AppData header
    try std.testing.expectEqualSlices(u8, r1[app_offset..], r2[app_offset..]);
}

test "validateTlsHandshake - valid handshake" {
    const allocator = std.testing.allocator;

    // Create mock secrets
    var secrets = [_]UserSecret{
        .{ .name = "alice", .secret = [_]u8{0x1A} ** 16 },
        .{ .name = "bob", .secret = [_]u8{0x2B} ** 16 },
    };

    // Client hello mock
    // min_len = 11 + 32 + 1 = 44 bytes minimum
    var handshake = [_]u8{0x00} ** 64;
    // Set timestamp (say 123456789 = 0x075BCD15)
    // Wait, the client sends digest WITH timestamp XOR'd in the last 4 bytes.
    // If ignore_time_skew = true, the proxy doesn't care what timestamp is.
    // Proxy calculates HMAC on handshake with zeroed digest, then expects it to match (up to 28 bytes) the given digest.

    var hmac_input = std.mem.zeroes([64]u8);
    // Add session id len
    hmac_input[43] = 4; // session_id len
    hmac_input[44] = 0xaa; // session ID

    // Compute HMAC
    const computed_mac = crypto.sha256Hmac(&secrets[1].secret, &hmac_input);

    // Create the actual handshake by copying hmac_input and setting the digest with some timestamp
    @memcpy(&handshake, &hmac_input);
    @memcpy(handshake[constants.tls_digest_pos..][0..28], computed_mac[0..28]);

    // XOR timestamp into the last 4 bytes of digest
    const timestamp: u32 = 0x12345678;
    const ts_bytes = std.mem.toBytes(timestamp);
    handshake[constants.tls_digest_pos + 28] = computed_mac[28] ^ ts_bytes[0];
    handshake[constants.tls_digest_pos + 29] = computed_mac[29] ^ ts_bytes[1];
    handshake[constants.tls_digest_pos + 30] = computed_mac[30] ^ ts_bytes[2];
    handshake[constants.tls_digest_pos + 31] = computed_mac[31] ^ ts_bytes[3];

    const result = try validateTlsHandshake(allocator, &handshake, &secrets, true);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("bob", result.?.user);
    try std.testing.expectEqual(@as(u32, 0x12345678), result.?.timestamp);
}

test "validateTlsHandshake - invalid user" {
    const allocator = std.testing.allocator;
    var secrets = [_]UserSecret{.{ .name = "alice", .secret = [_]u8{0x1A} ** 16 }};
    var handshake = [_]u8{0xAA} ** 64; // random junk

    const result = try validateTlsHandshake(allocator, &handshake, &secrets, true);
    try std.testing.expect(result == null);
}

test "extractSni - malformed returns null" {
    // Too short
    try std.testing.expect(extractSni(&[_]u8{ 0x16, 0x03, 0x01, 0x00 }) == null);
    // Not a handshake type
    try std.testing.expect(extractSni(&[_]u8{ 0x17, 0x03, 0x01, 0x00, 0x00 }) == null);
}

test "validateTlsHandshake returns canonical_hmac" {
    const allocator = std.testing.allocator;

    var secrets = [_]UserSecret{.{ .name = "alice", .secret = [_]u8{0x1A} ** 16 }};
    var handshake = [_]u8{0x00} ** 64;

    var hmac_input = std.mem.zeroes([64]u8);
    hmac_input[43] = 4;
    hmac_input[44] = 0xaa;

    const computed_mac = crypto.sha256Hmac(&secrets[0].secret, &hmac_input);
    @memcpy(&handshake, &hmac_input);
    @memcpy(handshake[constants.tls_digest_pos..][0..28], computed_mac[0..28]);

    const timestamp: u32 = 0x01020304;
    const ts_bytes = std.mem.toBytes(timestamp);
    handshake[constants.tls_digest_pos + 28] = computed_mac[28] ^ ts_bytes[0];
    handshake[constants.tls_digest_pos + 29] = computed_mac[29] ^ ts_bytes[1];
    handshake[constants.tls_digest_pos + 30] = computed_mac[30] ^ ts_bytes[2];
    handshake[constants.tls_digest_pos + 31] = computed_mac[31] ^ ts_bytes[3];

    const result = try validateTlsHandshake(allocator, &handshake, &secrets, true);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, &computed_mac, &result.?.canonical_hmac);
}
