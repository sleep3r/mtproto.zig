//! Fake TLS 1.3 Handshake
//!
//! Validates TLS ClientHello against user secrets (HMAC-SHA256) and
//! builds fake ServerHello responses for domain fronting.

const std = @import("std");
const constants = @import("constants.zig");
const crypto = @import("../crypto/crypto.zig");
const obfuscation = @import("obfuscation.zig");

fn realtimeSeconds() i64 {
    var ts: std.posix.timespec = undefined;
    const rc = std.posix.system.clock_gettime(.REALTIME, &ts);
    if (std.posix.errno(rc) != .SUCCESS) return 0;
    return @intCast(ts.sec);
}

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
    _ = allocator;

    const min_len = constants.tls_digest_pos + constants.tls_digest_len + 1;
    if (handshake.len < min_len) return null;

    // Extract digest
    const digest: [constants.tls_digest_len]u8 = handshake[constants.tls_digest_pos..][0..constants.tls_digest_len].*;

    // Extract session ID
    const session_id_len_pos = constants.tls_digest_pos + constants.tls_digest_len;
    if (session_id_len_pos >= handshake.len) return null;
    const session_id_len: usize = handshake[session_id_len_pos];
    if (session_id_len != 32) return null;

    const session_id_start = session_id_len_pos + 1;
    if (handshake.len < session_id_start + session_id_len) return null;

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    const zero_digest = [_]u8{0} ** constants.tls_digest_len;

    const now: i64 = if (!ignore_time_skew) realtimeSeconds() else 0;

    for (secrets) |entry| {
        var hmac = HmacSha256.init(&entry.secret);
        hmac.update(handshake[0..constants.tls_digest_pos]);
        hmac.update(&zero_digest);
        hmac.update(handshake[constants.tls_digest_pos + constants.tls_digest_len ..]);
        var computed: [constants.tls_digest_len]u8 = undefined;
        hmac.final(&computed);

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
    cipher: ?u16,
) ![]u8 {
    return buildServerHelloWithTemplate(allocator, &nginx_template, secret, client_digest, session_id, cipher);
}

pub fn buildServerHelloWithTemplate(
    allocator: std.mem.Allocator,
    template: []const u8,
    secret: []const u8,
    client_digest: *const [constants.tls_digest_len]u8,
    session_id: []const u8,
    cipher: ?u16,
) ![]u8 {
    if (template.len != nginx_template_len) return error.BadServerHelloTemplate;

    // 1. Copy the pre-built Nginx template (random and session_id are zeroed in template)
    const response = try allocator.alloc(u8, template.len);
    errdefer allocator.free(response);
    @memcpy(response, template);

    // 1b. Echo a client-offered cipher suite. A real TLS server negotiates the
    //     cipher from the ClientHello and naturally varies it; emitting a constant
    //     0x1301 for every connection is a trivial passive JA3S/ServerHello
    //     distinguisher. Telegram FakeTLS clients ignore the cipher (they validate
    //     only the record framing + HMAC), so this is pure evasion upside with no
    //     client-compat risk. Patched before the HMAC (step 4) which covers it.
    if (cipher) |cs| {
        std.mem.writeInt(u16, response[tmpl_cipher_offset..][0..2], cs, .big);
    }

    // 2. Patch Session ID (echo from client). Template is fixed for 32-byte session IDs.
    if (session_id.len != 32) return error.BadSessionIdLength;
    @memcpy(response[tmpl_session_id_offset..][0..32], session_id);

    // 3. Patch X25519 public key with fresh random bytes
    var x25519_key: [32]u8 = undefined;
    crypto.randomBytes(&x25519_key);
    @memcpy(response[tmpl_x25519_key_offset..][0..32], &x25519_key);

    // 3b. Randomize the fake "encrypted certificate" AppData per connection.
    //     A real TLS 1.3 server's first AppData record is AEAD ciphertext keyed
    //     by per-connection ephemeral ECDHE, so it is never byte-identical
    //     across connections. Reusing the template's fixed 2878-byte body lets a
    //     passive observer correlate two connections to the same endpoint and
    //     see a verbatim-repeating ciphertext that no genuine TLS server emits —
    //     a passive FakeTLS distinguisher. The client never inspects this body
    //     and the HMAC in step 4 covers it, so fresh randomness is protocol-safe.
    //     The record length stays fixed, preserving the size fingerprint.
    crypto.randomBytes(response[tmpl_appdata_offset..][0..fake_cert_payload_len]);

    // 4. Compute HMAC over full response with random field zeroed.
    //    Template already has zeros at offset 11..43, so HMAC input is correct.
    //    Stream bytes sequentially into the hasher to avoid a ~3KB heap
    //    allocation for every TLS handshake (which under active DPI probing
    //    causes serious allocator pressure on this hot path).
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var hmac = HmacSha256.init(secret);
    hmac.update(client_digest);
    hmac.update(response);
    var response_digest: [32]u8 = undefined;
    hmac.final(&response_digest);

    // 5. Insert HMAC digest into Server Random field
    @memcpy(response[tmpl_random_offset..][0..32], &response_digest);

    return response;
}

// ============= Post-quantum X25519MLKEM768 ServerHello =============
//
// Modern browsers (Chrome/Firefox PQ-first) and CDNs negotiate the hybrid group
// X25519MLKEM768 (named group 0x11ec). A FakeTLS proxy that always answers a
// PQ-offering client with a plain x25519 (0x001d) key_share is a passive
// group-downgrade tell: a real server for that flow would echo 0x11ec. When the
// client offers 0x11ec we therefore emit a 0x11ec ServerHello key_share of the
// correct size (1120 = ML-KEM-768 ciphertext 1088 || X25519 32).
//
// The share is high-entropy CSPRNG bytes, NOT a real ML-KEM encapsulation. That
// is deliberate and sufficient: (a) Telegram FakeTLS clients validate only record
// framing + the HMAC in server-random, never the key_share crypto; (b) passive
// JA3S/ServerHello fingerprinting keys on the *group and size*, which match; and
// (c) we are not a TLS terminator — an active prober that completes a real hybrid
// KEX still cannot finish the handshake with us, so a cryptographically valid
// ciphertext buys nothing. (Real raw-ML-KEM ct||X25519 encapsulation against the
// client's ek is a possible future enhancement; std's MlKem768X25519 is X-Wing,
// a different combiner from the TLS 0x11ec wire format, so it can't be used as-is.)

pub const pq_named_group: u16 = 0x11ec;
/// X25519MLKEM768 server share: ML-KEM-768 ciphertext (1088) || X25519 (32).
const pq_key_share_len: usize = 1120;
/// PQ ServerHello record length: 5(rec hdr)+4(hs hdr)+2(ver)+32(rand)+1+32(sid)
///   +2(cipher)+1(comp)+2(extlen)+6(supported_versions)+4(ks ext hdr)
///   +2(group)+2(keylen)+1120(key) = 1215.
const pq_server_hello_record_len: usize = 95 + pq_key_share_len;
/// Full PQ response: ServerHello + CCS(6) + AppData(5 + cert payload).
pub const pq_server_hello_len: usize = pq_server_hello_record_len + 6 + 5 + fake_cert_payload_len;
/// Offset of the 1120-byte PQ key_share inside the response.
const pq_key_offset: usize = 95;
/// Offset of the fake AppData body inside the PQ response.
const pq_appdata_offset: usize = pq_server_hello_len - fake_cert_payload_len;

/// Return true when the ClientHello carries a key_share entry for X25519MLKEM768
/// (named group 0x11ec). Mirrors the key_share walk in formatClientHelloFingerprint.
pub fn clientOffersPqKeyShare(handshake: []const u8) bool {
    if (handshake.len < 43 or handshake[0] != constants.tls_record_handshake) return false;
    var pos: usize = 5;
    if (pos >= handshake.len or handshake[pos] != 0x01) return false; // ClientHello
    pos += 4; // hs type + 3-byte length
    pos += 2 + 32; // legacy_version + random
    if (pos + 1 > handshake.len) return false;
    const sid_len: usize = handshake[pos];
    pos += 1 + sid_len;
    if (pos + 2 > handshake.len) return false;
    const cs_len = std.mem.readInt(u16, handshake[pos..][0..2], .big);
    pos += 2;
    if (cs_len % 2 != 0 or pos + cs_len > handshake.len) return false;
    pos += cs_len;
    if (pos + 1 > handshake.len) return false;
    const comp_len: usize = handshake[pos];
    pos += 1 + comp_len;
    if (pos + 2 > handshake.len) return false;
    const ext_total = std.mem.readInt(u16, handshake[pos..][0..2], .big);
    pos += 2;
    const ext_end = @min(pos + ext_total, handshake.len);
    while (pos + 4 <= ext_end) {
        const etype = std.mem.readInt(u16, handshake[pos..][0..2], .big);
        const elen = std.mem.readInt(u16, handshake[pos + 2 ..][0..2], .big);
        pos += 4;
        if (pos + elen > ext_end) break;
        if (etype == 0x0033) { // key_share: 2-byte client_shares list_len, then entries
            var kp: usize = pos + 2;
            const ks_end = pos + elen;
            while (kp + 4 <= ks_end) {
                if (std.mem.readInt(u16, handshake[kp..][0..2], .big) == pq_named_group) return true;
                kp += 4 + @as(usize, std.mem.readInt(u16, handshake[kp + 2 ..][0..2], .big));
            }
            return false;
        }
        pos += elen;
    }
    return false;
}

/// Build a ServerHello that answers an X25519MLKEM768-offering client with a
/// 0x11ec key_share. Same HMAC-in-server-random + per-connection-random-AppData
/// construction as buildServerHelloWithTemplate; only the key_share group/size and
/// the dependent length fields differ.
pub fn buildServerHelloPq(
    allocator: std.mem.Allocator,
    secret: []const u8,
    client_digest: *const [constants.tls_digest_len]u8,
    session_id: []const u8,
    cipher: ?u16,
) ![]u8 {
    if (session_id.len != 32) return error.BadSessionIdLength;
    const r = try allocator.alloc(u8, pq_server_hello_len);
    errdefer allocator.free(r);
    @memset(r, 0);

    // ── Record 1: ServerHello with a 0x11ec key_share ──
    r[0] = constants.tls_record_handshake; // 0x16
    r[1] = 0x03;
    r[2] = 0x03; // record version (TLS 1.2 compat)
    std.mem.writeInt(u16, r[3..][0..2], @intCast(pq_server_hello_record_len - 5), .big);
    r[5] = 0x02; // ServerHello
    std.mem.writeInt(u24, r[6..][0..3], @intCast(pq_server_hello_record_len - 9), .big);
    r[9] = 0x03;
    r[10] = 0x03; // server legacy version
    // r[11..43] server random — left zero (HMAC placeholder, patched at the end)
    r[43] = 0x20; // session_id length = 32
    @memcpy(r[tmpl_session_id_offset..][0..32], session_id);
    std.mem.writeInt(u16, r[tmpl_cipher_offset..][0..2], cipher orelse 0x1301, .big);
    r[78] = 0x00; // compression: none
    std.mem.writeInt(u16, r[79..][0..2], @intCast(6 + 4 + 4 + pq_key_share_len), .big); // extensions
    // supported_versions (0x002b) FIRST — TLS 1.3
    r[81] = 0x00;
    r[82] = 0x2b;
    r[83] = 0x00;
    r[84] = 0x02;
    r[85] = 0x03;
    r[86] = 0x04;
    // key_share (0x0033)
    r[87] = 0x00;
    r[88] = 0x33;
    std.mem.writeInt(u16, r[89..][0..2], @intCast(4 + pq_key_share_len), .big);
    std.mem.writeInt(u16, r[91..][0..2], pq_named_group, .big);
    std.mem.writeInt(u16, r[93..][0..2], @intCast(pq_key_share_len), .big);
    crypto.randomBytes(r[pq_key_offset..][0..pq_key_share_len]);

    // ── Record 2: Change Cipher Spec ──
    const ccs = pq_server_hello_record_len;
    r[ccs] = 0x14;
    r[ccs + 1] = 0x03;
    r[ccs + 2] = 0x03;
    r[ccs + 3] = 0x00;
    r[ccs + 4] = 0x01;
    r[ccs + 5] = 0x01;

    // ── Record 3: fake encrypted certificate AppData ──
    const ad = ccs + 6;
    r[ad] = 0x17;
    r[ad + 1] = 0x03;
    r[ad + 2] = 0x03;
    std.mem.writeInt(u16, r[ad + 3 ..][0..2], fake_cert_payload_len, .big);
    crypto.randomBytes(r[pq_appdata_offset..][0..fake_cert_payload_len]);

    // HMAC over the full response (random field zeroed), prefixed by the client digest.
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var hmac = HmacSha256.init(secret);
    hmac.update(client_digest);
    hmac.update(r);
    var response_digest: [32]u8 = undefined;
    hmac.final(&response_digest);
    @memcpy(r[tmpl_random_offset..][0..32], &response_digest);

    return r;
}

/// A TLS **fatal** `handshake_failure` alert record — what a server sends when it
/// refuses to complete the handshake (e.g. nginx `ssl_reject_handshake on`). Send
/// this, then close, so a rejected probe sees a real server-style teardown. A *fatal*
/// alert legitimately precedes connection close; a warning-level alert followed by an
/// immediate close would itself be anomalous (a distinguisher), so this is fatal.
/// Bytes: record type 0x15 (alert), TLS 1.2 version 0x0303, length 2,
/// level 2 (fatal), description 40 (handshake_failure, RFC 8446 §6).
pub const reject_handshake_alert = [_]u8{ 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 };

// ============= Nginx/OpenSSL TLS 1.3 Template =============
//
// Pre-built at comptime to match the fingerprint of Nginx 1.25+ with OpenSSL 3.x.
// Structure: ServerHello (127 bytes) + CCS (6 bytes) + AppData (5 + 2878 bytes)
//
// Key differences from naive FakeTLS that DPI detects:
// 1. Extension ordering: OpenSSL sends supported_versions (0x002b) BEFORE key_share (0x0033)
// 2. AppData size: fixed 2878 bytes (realistic Let's Encrypt ECDSA cert chain),
//    NOT random in [1024,4096) which is an entropy fingerprint
// 3. AppData body: the comptime template seeds a deterministic body, but
//    buildServerHelloWithTemplate overwrites it with fresh random bytes on every
//    connection (a real cert record is unique per-connection AEAD ciphertext)

/// Offset of Server Random field (32 bytes) — patched with HMAC at runtime
const tmpl_random_offset: usize = 11;
/// Offset of Session ID (32 bytes) — echoed from client at runtime
const tmpl_session_id_offset: usize = 44;
/// Offset of the 2-byte cipher suite — immediately after the 32-byte session_id
/// (44 + 32). Patched at runtime with a client-offered suite.
const tmpl_cipher_offset: usize = tmpl_session_id_offset + 32;
/// Offset of X25519 public key (32 bytes) — filled with random at runtime
const tmpl_x25519_key_offset: usize = 95;
/// Offset of the fake AppData ("encrypted certificate") body — overwritten with
/// fresh per-connection random bytes at runtime so it isn't byte-identical
/// across connections (which would be a passive DPI distinguisher).
const tmpl_appdata_offset: usize = nginx_template_len - fake_cert_payload_len;

/// Fake encrypted certificate payload size.
/// 2878 bytes matches a typical Nginx + Let's Encrypt ECDSA P-256 cert chain:
///   EncryptedExtensions (~20) + Certificate (~2400) + CertificateVerify (~100) +
///   Finished (~36) + AEAD tags (~50) + record layer overhead.
/// Fixed size eliminates the random-range fingerprint that ТСПУ detects.
const fake_cert_payload_len: u16 = 2878;

/// Total template size: ServerHello(127) + CCS(6) + AppData(5 + 2878)
const nginx_template_len: usize = 127 + 6 + 5 + fake_cert_payload_len;
pub const server_hello_template_len: usize = nginx_template_len;

const default_template_seed: u64 = 0x4E67_696E_785F_544C;

/// The pre-built template, constructed at comptime.
const nginx_template: [nginx_template_len]u8 = blk: {
    @setEvalBranchQuota(100_000);
    break :blk buildNginxTemplate(default_template_seed);
};

pub fn buildServerHelloTemplate(seed: ?u64) [nginx_template_len]u8 {
    const actual_seed = seed orelse crypto.randomInt(u64);
    return buildNginxTemplate(actual_seed);
}

fn buildNginxTemplate(seed: u64) [nginx_template_len]u8 {
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

    // Fill with deterministic pseudo-random bytes (SplitMix64) as a placeholder.
    // This body is overwritten per-connection with fresh CSPRNG bytes in
    // buildServerHelloWithTemplate; only the fixed record length matters here.
    var prng_state: u64 = seed;
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
/// Return the first non-GREASE TLS 1.3 cipher suite the client offered
/// (0x1301 AES-128-GCM / 0x1302 AES-256-GCM / 0x1303 CHACHA20), or null. Used to
/// echo a client-offered cipher in the ServerHello instead of a constant, so the
/// ServerHello's chosen cipher tracks the ClientHello like a real server's.
pub fn extractFirstTls13Cipher(handshake: []const u8) ?u16 {
    if (handshake.len < 43 or handshake[0] != constants.tls_record_handshake) return null;
    var pos: usize = 5;
    if (pos >= handshake.len or handshake[pos] != 0x01) return null; // ClientHello
    pos += 4; // handshake type + 3-byte length
    pos += 2 + 32; // legacy_version + random
    if (pos + 1 > handshake.len) return null;
    const session_id_len: usize = handshake[pos];
    pos += 1 + session_id_len;
    if (pos + 2 > handshake.len) return null;
    const cs_len = std.mem.readInt(u16, handshake[pos..][0..2], .big);
    pos += 2;
    if (cs_len % 2 != 0 or pos + cs_len > handshake.len) return null;
    var i: usize = 0;
    while (i + 2 <= cs_len) : (i += 2) {
        const suite = std.mem.readInt(u16, handshake[pos + i ..][0..2], .big);
        if ((suite & 0x0f0f) == 0x0a0a) continue; // GREASE (RFC 8701)
        if (suite == 0x1301 or suite == 0x1302 or suite == 0x1303) return suite;
    }
    return null;
}

fn fpAppendStr(out: []u8, pos: usize, s: []const u8) ?usize {
    if (pos + s.len > out.len) return null;
    @memcpy(out[pos .. pos + s.len], s);
    return pos + s.len;
}

fn fpAppendHexCsv(out: []u8, pos: usize, v: u16, first: *bool) ?usize {
    var p = pos;
    if (!first.*) p = fpAppendStr(out, p, ",") orelse return null;
    first.* = false;
    const s = std.fmt.bufPrint(out[p..], "{x:0>4}", .{v}) catch return null;
    return p + s.len;
}

/// Diagnostic: summarize a client's ClientHello — the non-GREASE cipher suites it
/// offered, its supported_groups, and the groups it sent key_shares for — into
/// `out` (e.g. "ciphers=1301,1303 groups=11ec,001d keyshare=11ec"). Read-only; used
/// to learn what a real client (e.g. a Telegram app behind a censor) actually
/// presents, so the ServerHello can be matched to it instead of guessed. Returns
/// null on a malformed/truncated hello. Bounded + panic-free (attacker input).
pub fn formatClientHelloFingerprint(handshake: []const u8, out: []u8) ?[]const u8 {
    if (handshake.len < 43 or handshake[0] != constants.tls_record_handshake) return null;
    var pos: usize = 5;
    if (pos >= handshake.len or handshake[pos] != 0x01) return null; // ClientHello
    pos += 4; // hs type + 3-byte length
    pos += 2 + 32; // legacy_version + random
    if (pos + 1 > handshake.len) return null;
    const sid_len: usize = handshake[pos];
    pos += 1 + sid_len;

    if (pos + 2 > handshake.len) return null;
    const cs_len = std.mem.readInt(u16, handshake[pos..][0..2], .big);
    pos += 2;
    if (cs_len % 2 != 0 or pos + cs_len > handshake.len) return null;
    const ciphers_start = pos;
    const ciphers_end = pos + cs_len;
    pos = ciphers_end;

    if (pos + 1 > handshake.len) return null;
    const comp_len: usize = handshake[pos];
    pos += 1 + comp_len;

    var groups_start: usize = 0;
    var groups_end: usize = 0;
    var ks_groups: [16]u16 = undefined;
    var ks_count: usize = 0;
    if (pos + 2 <= handshake.len) {
        const ext_total = std.mem.readInt(u16, handshake[pos..][0..2], .big);
        pos += 2;
        const ext_end = @min(pos + ext_total, handshake.len);
        while (pos + 4 <= ext_end) {
            const etype = std.mem.readInt(u16, handshake[pos..][0..2], .big);
            const elen = std.mem.readInt(u16, handshake[pos + 2 ..][0..2], .big);
            pos += 4;
            if (pos + elen > ext_end) break;
            if (etype == 0x000a and elen >= 2) { // supported_groups
                const list_len = std.mem.readInt(u16, handshake[pos..][0..2], .big);
                if (2 + @as(usize, list_len) <= elen) {
                    groups_start = pos + 2;
                    groups_end = pos + 2 + list_len;
                }
            } else if (etype == 0x0033) { // key_share (client: list_len then entries)
                var kp: usize = pos + 2;
                const ks_end = pos + elen;
                while (kp + 4 <= ks_end and ks_count < ks_groups.len) {
                    ks_groups[ks_count] = std.mem.readInt(u16, handshake[kp..][0..2], .big);
                    ks_count += 1;
                    kp += 4 + @as(usize, std.mem.readInt(u16, handshake[kp + 2 ..][0..2], .big));
                }
            }
            pos += elen;
        }
    }

    var p: usize = 0;
    p = fpAppendStr(out, p, "ciphers=") orelse return null;
    var first = true;
    var i = ciphers_start;
    while (i + 2 <= ciphers_end) : (i += 2) {
        const c = std.mem.readInt(u16, handshake[i..][0..2], .big);
        if ((c & 0x0f0f) == 0x0a0a) continue; // skip GREASE
        p = fpAppendHexCsv(out, p, c, &first) orelse return out[0..p];
    }
    p = fpAppendStr(out, p, " groups=") orelse return out[0..p];
    first = true;
    i = groups_start;
    while (i + 2 <= groups_end) : (i += 2) {
        p = fpAppendHexCsv(out, p, std.mem.readInt(u16, handshake[i..][0..2], .big), &first) orelse return out[0..p];
    }
    p = fpAppendStr(out, p, " keyshare=") orelse return out[0..p];
    first = true;
    for (ks_groups[0..ks_count]) |g| {
        p = fpAppendHexCsv(out, p, g, &first) orelse return out[0..p];
    }
    return out[0..p];
}

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
        null,
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

test "dpi-validation: ServerHello structural invariants (JA3S regression gate)" {
    // Hermetic DPI-detectability gate (the local part of dpi-validation-ci): drive
    // a realistic ClientHello, generate the ServerHello, and assert the
    // evasion-relevant structure — so any future evasion change that drifts the
    // fingerprint fails here instead of shipping silently. (The full version also
    // diffs JA4S/record-geometry against a live reference domain; that needs a
    // Linux host + ja4 tooling and is a follow-up.)
    const allocator = std.testing.allocator;
    const isGrease = struct {
        fn f(v: u16) bool {
            return (v & 0x0f0f) == 0x0a0a;
        }
    }.f;

    // ClientHello offering [GREASE, TLS_CHACHA20 0x1303, TLS_AES_128 0x1301].
    var ch: [52]u8 = undefined;
    ch[0] = constants.tls_record_handshake;
    ch[1] = 0x03;
    ch[2] = 0x01;
    ch[3] = 0x00;
    ch[4] = 0x2f;
    ch[5] = 0x01; // ClientHello
    ch[6] = 0x00;
    ch[7] = 0x00;
    ch[8] = 0x2b;
    ch[9] = 0x03;
    ch[10] = 0x03;
    @memset(ch[11..43], 0xCD);
    ch[43] = 0x00; // session_id_len
    ch[44] = 0x00;
    ch[45] = 0x06; // cipher_suites_len = 6
    ch[46] = 0x0a;
    ch[47] = 0x0a; // GREASE (must be skipped)
    ch[48] = 0x13;
    ch[49] = 0x03; // CHACHA20 — the first non-GREASE TLS1.3 suite
    ch[50] = 0x13;
    ch[51] = 0x01;

    const echoed = extractFirstTls13Cipher(&ch);
    try std.testing.expectEqual(@as(?u16, 0x1303), echoed);

    var digest = [_]u8{0x42} ** 32;
    const session_id = [_]u8{0xA5} ** 32;
    const r1 = try buildServerHello(allocator, &digest, &digest, &session_id, echoed);
    defer allocator.free(r1);

    // 1. Cipher in the ServerHello TRACKS the ClientHello (not a constant 0x1301).
    try std.testing.expectEqual(@as(u16, 0x1303), std.mem.readInt(u16, r1[tmpl_cipher_offset..][0..2], .big));

    // 2. Extensions: supported_versions (0x2b) THEN key_share (0x33), x25519 group.
    const ext_supported_versions = std.mem.readInt(u16, r1[81..][0..2], .big);
    const ext_key_share = std.mem.readInt(u16, r1[87..][0..2], .big);
    const key_share_group = std.mem.readInt(u16, r1[91..][0..2], .big);
    try std.testing.expectEqual(@as(u16, 0x002b), ext_supported_versions);
    try std.testing.expectEqual(@as(u16, 0x0033), ext_key_share);
    try std.testing.expectEqual(@as(u16, 0x001d), key_share_group); // x25519

    // 3. NO GREASE in the structural fields (a real server never emits GREASE).
    try std.testing.expect(!isGrease(std.mem.readInt(u16, r1[tmpl_cipher_offset..][0..2], .big)));
    try std.testing.expect(!isGrease(ext_supported_versions));
    try std.testing.expect(!isGrease(ext_key_share));
    try std.testing.expect(!isGrease(key_share_group));

    // 4. Record geometry: ServerHello(122) + CCS(6) + AppData(2878), fixed.
    try std.testing.expectEqual(@as(u16, 122), std.mem.readInt(u16, r1[3..5], .big));
    try std.testing.expectEqual(fake_cert_payload_len, std.mem.readInt(u16, r1[136..][0..2], .big));

    // 5. Differ where a real server differs, constant where it is constant: a second
    //    ServerHello for the same client must keep cipher/extensions/structure
    //    identical but vary random + key_share key + AppData ciphertext.
    const r2 = try buildServerHello(allocator, &digest, &digest, &session_id, echoed);
    defer allocator.free(r2);
    // constant structural prefix: record header + handshake header up to the random
    try std.testing.expectEqualSlices(u8, r1[0..tmpl_random_offset], r2[0..tmpl_random_offset]);
    // constant cipher + extension block (session_id..key_share group)
    try std.testing.expectEqualSlices(u8, r1[tmpl_cipher_offset..tmpl_x25519_key_offset], r2[tmpl_cipher_offset..tmpl_x25519_key_offset]);
    // variable: server-random (HMAC), x25519 key, AppData body
    try std.testing.expect(!std.mem.eql(u8, r1[tmpl_random_offset..][0..32], r2[tmpl_random_offset..][0..32]));
    try std.testing.expect(!std.mem.eql(u8, r1[tmpl_x25519_key_offset..][0..32], r2[tmpl_x25519_key_offset..][0..32]));
    try std.testing.expect(!std.mem.eql(u8, r1[tmpl_appdata_offset..][0..fake_cert_payload_len], r2[tmpl_appdata_offset..][0..fake_cert_payload_len]));
}

test "buildServerHello AppData: fixed length, per-connection-random body" {
    const allocator = std.testing.allocator;
    var digest = [_]u8{0xAA} ** 32;
    const session_id = [_]u8{0xBB} ** 32;

    const r1 = try buildServerHello(allocator, &digest, &digest, &session_id, null);
    defer allocator.free(r1);
    const r2 = try buildServerHello(allocator, &digest, &digest, &session_id, null);
    defer allocator.free(r2);

    // Same total size (fixed-length cert record — no random *size* fingerprint).
    try std.testing.expectEqual(r1.len, r2.len);

    // AppData body MUST differ across connections: a real TLS 1.3 server's first
    // AppData record is unique per-connection AEAD ciphertext, so a byte-identical
    // body would be a passive DPI distinguisher.
    const app_offset = 127 + 6 + 5; // after ServerHello + CCS + AppData header
    try std.testing.expect(!std.mem.eql(u8, r1[app_offset..], r2[app_offset..]));
}

test "fuzz: TLS ClientHello parsers never panic on arbitrary input" {
    // Coverage-guided under `zig build test --fuzz`; runs deterministically as a
    // normal unit test otherwise. Asserts the attacker-reachable FakeTLS parsers
    // tolerate any byte sequence without a panic/OOB (a parser panic = remote DoS).
    try std.testing.fuzz({}, struct {
        fn one(_: void, s: *std.testing.Smith) anyerror!void {
            var buf: [4096]u8 = undefined;
            const data = buf[0..s.slice(&buf)];
            _ = extractSni(data);
            _ = extractFirstTls13Cipher(data);
            var fp_buf: [256]u8 = undefined;
            _ = formatClientHelloFingerprint(data, &fp_buf);
            const secrets = [_]UserSecret{.{ .name = "u", .secret = [_]u8{0x11} ** 16 }};
            _ = validateTlsHandshake(std.testing.allocator, data, &secrets, true) catch {};
        }
    }.one, .{});
}

test "formatClientHelloFingerprint summarizes ciphers/groups/keyshare" {
    // Hand-built ClientHello: ciphers [1301,1303], supported_groups [001d,11ec],
    // one key_share for 001d (x25519). Verifies we can read what a real client
    // offers (incl. whether it offers X25519MLKEM768 0x11ec).
    var ch: [106]u8 = undefined;
    var n: usize = 0;
    const W = struct {
        fn b(buf: []u8, i: *usize, v: u8) void {
            buf[i.*] = v;
            i.* += 1;
        }
        fn h(buf: []u8, i: *usize, v: u16) void {
            std.mem.writeInt(u16, buf[i.*..][0..2], v, .big);
            i.* += 2;
        }
    };
    W.b(&ch, &n, 0x16);
    W.b(&ch, &n, 0x03);
    W.b(&ch, &n, 0x01);
    W.h(&ch, &n, 101); // record len
    W.b(&ch, &n, 0x01);
    W.b(&ch, &n, 0x00);
    W.h(&ch, &n, 97); // hs type + 24-bit len
    W.h(&ch, &n, 0x0303); // version
    var r: usize = 0;
    while (r < 32) : (r += 1) W.b(&ch, &n, 0xAA); // random
    W.b(&ch, &n, 0x00); // session_id len
    W.h(&ch, &n, 4); // cipher_suites len
    W.h(&ch, &n, 0x1301);
    W.h(&ch, &n, 0x1303);
    W.b(&ch, &n, 0x01);
    W.b(&ch, &n, 0x00); // compression
    W.h(&ch, &n, 52); // ext_total
    W.h(&ch, &n, 0x000a);
    W.h(&ch, &n, 6);
    W.h(&ch, &n, 4);
    W.h(&ch, &n, 0x001d);
    W.h(&ch, &n, 0x11ec); // supported_groups
    W.h(&ch, &n, 0x0033);
    W.h(&ch, &n, 38);
    W.h(&ch, &n, 36);
    W.h(&ch, &n, 0x001d);
    W.h(&ch, &n, 32); // key_share entry
    var k: usize = 0;
    while (k < 32) : (k += 1) W.b(&ch, &n, 0xBB); // key
    try std.testing.expectEqual(@as(usize, 106), n);

    var out: [256]u8 = undefined;
    const fp = formatClientHelloFingerprint(&ch, &out).?;
    try std.testing.expectEqualStrings("ciphers=1301,1303 groups=001d,11ec keyshare=001d", fp);
    // Truncated input never panics.
    try std.testing.expect(formatClientHelloFingerprint(ch[0..30], &out) == null);
}

test "clientOffersPqKeyShare detects a 0x11ec key_share entry" {
    var ch: [160]u8 = undefined;
    var n: usize = 0;
    const W = struct {
        fn b(buf: []u8, i: *usize, v: u8) void {
            buf[i.*] = v;
            i.* += 1;
        }
        fn h(buf: []u8, i: *usize, v: u16) void {
            std.mem.writeInt(u16, buf[i.*..][0..2], v, .big);
            i.* += 2;
        }
    };
    W.b(&ch, &n, 0x16);
    W.b(&ch, &n, 0x03);
    W.b(&ch, &n, 0x01);
    const rec_len_at = n;
    W.h(&ch, &n, 0);
    W.b(&ch, &n, 0x01);
    W.b(&ch, &n, 0x00);
    const hs_len_at = n;
    W.h(&ch, &n, 0);
    const hs_body_start = n;
    W.h(&ch, &n, 0x0303);
    var r: usize = 0;
    while (r < 32) : (r += 1) W.b(&ch, &n, 0xAA);
    W.b(&ch, &n, 0x00); // session_id len
    W.h(&ch, &n, 2);
    W.h(&ch, &n, 0x1301); // cipher_suites
    W.b(&ch, &n, 0x01);
    W.b(&ch, &n, 0x00); // compression
    const ext_total_at = n;
    W.h(&ch, &n, 0);
    const ext_start = n;
    W.h(&ch, &n, 0x0033); // key_share ext
    const ks_len_at = n;
    W.h(&ch, &n, 0);
    const ks_payload_start = n;
    W.h(&ch, &n, 8); // client_shares list length
    W.h(&ch, &n, 0x11ec); // group
    W.h(&ch, &n, 4); // key length
    var kk: usize = 0;
    while (kk < 4) : (kk += 1) W.b(&ch, &n, 0xCC);
    std.mem.writeInt(u16, ch[ks_len_at..][0..2], @intCast(n - ks_payload_start), .big);
    std.mem.writeInt(u16, ch[ext_total_at..][0..2], @intCast(n - ext_start), .big);
    std.mem.writeInt(u16, ch[hs_len_at..][0..2], @intCast(n - hs_body_start), .big);
    std.mem.writeInt(u16, ch[rec_len_at..][0..2], @intCast(n - 5), .big);

    try std.testing.expect(clientOffersPqKeyShare(ch[0..n]));
    // Flip the offered group to x25519 -> no longer a PQ offer.
    std.mem.writeInt(u16, ch[ks_payload_start + 2 ..][0..2], 0x001d, .big);
    try std.testing.expect(!clientOffersPqKeyShare(ch[0..n]));
    // Truncated input never panics.
    try std.testing.expect(!clientOffersPqKeyShare(ch[0..20]));
}

test "buildServerHelloPq emits a 0x11ec key_share with correct framing + HMAC" {
    const allocator = std.testing.allocator;
    const digest = [_]u8{0} ** constants.tls_digest_len;
    const sid = [_]u8{0x33} ** 32;
    const secret = [_]u8{0x42} ** 16;
    const resp = try buildServerHelloPq(allocator, &secret, &digest, &sid, 0x1303);
    defer allocator.free(resp);

    try std.testing.expectEqual(pq_server_hello_len, resp.len);
    try std.testing.expectEqual(@as(u8, 0x16), resp[0]);
    try std.testing.expectEqual(@as(u16, @intCast(pq_server_hello_record_len - 5)), std.mem.readInt(u16, resp[3..][0..2], .big));
    // cipher echoed + session_id echoed
    try std.testing.expectEqual(@as(u16, 0x1303), std.mem.readInt(u16, resp[tmpl_cipher_offset..][0..2], .big));
    try std.testing.expectEqualSlices(u8, &sid, resp[tmpl_session_id_offset..][0..32]);
    // key_share: ext type 0x0033, group 0x11ec, key length 1120
    try std.testing.expectEqual(@as(u16, 0x0033), std.mem.readInt(u16, resp[87..][0..2], .big));
    try std.testing.expectEqual(pq_named_group, std.mem.readInt(u16, resp[91..][0..2], .big));
    try std.testing.expectEqual(@as(u16, @intCast(pq_key_share_len)), std.mem.readInt(u16, resp[93..][0..2], .big));
    // CCS then AppData records follow the ServerHello record.
    try std.testing.expectEqual(@as(u8, 0x14), resp[pq_server_hello_record_len]);
    try std.testing.expectEqual(@as(u8, 0x17), resp[pq_server_hello_record_len + 6]);
    // HMAC self-consistency: recompute over the response with the random field zeroed.
    const check = try allocator.dupe(u8, resp);
    defer allocator.free(check);
    @memset(check[tmpl_random_offset..][0..32], 0);
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var h = HmacSha256.init(&secret);
    h.update(&digest);
    h.update(check);
    var expected: [32]u8 = undefined;
    h.final(&expected);
    try std.testing.expectEqualSlices(u8, &expected, resp[tmpl_random_offset..][0..32]);
}

test "extractFirstTls13Cipher returns first non-GREASE TLS1.3 suite" {
    // Minimal ClientHello: record hdr, hs hdr, version, 32-byte random,
    // session_id_len=0, cipher_suites_len=6 = [GREASE 0x0a0a, 0x1303, 0x1301].
    var ch: [52]u8 = undefined;
    ch[0] = 0x16;
    ch[1] = 0x03;
    ch[2] = 0x01;
    ch[3] = 0x00;
    ch[4] = 0x2f;
    ch[5] = 0x01; // ClientHello
    ch[6] = 0x00;
    ch[7] = 0x00;
    ch[8] = 0x2b;
    ch[9] = 0x03;
    ch[10] = 0x03; // version
    @memset(ch[11..43], 0xAB); // random
    ch[43] = 0x00; // session_id_len
    ch[44] = 0x00;
    ch[45] = 0x06; // cipher_suites_len
    ch[46] = 0x0a;
    ch[47] = 0x0a; // GREASE
    ch[48] = 0x13;
    ch[49] = 0x03; // CHACHA20
    ch[50] = 0x13;
    ch[51] = 0x01; // AES-128-GCM
    try std.testing.expectEqual(@as(?u16, 0x1303), extractFirstTls13Cipher(&ch));
    try std.testing.expect(extractFirstTls13Cipher(ch[0..40]) == null); // truncated
}

test "buildServerHello echoes the chosen cipher at the cipher offset" {
    const allocator = std.testing.allocator;
    var digest = [_]u8{0xAA} ** 32;
    const session_id = [_]u8{0xBB} ** 32;
    const resp = try buildServerHello(allocator, &digest, &digest, &session_id, 0x1303);
    defer allocator.free(resp);
    try std.testing.expectEqual(@as(u8, 0x13), resp[tmpl_cipher_offset]);
    try std.testing.expectEqual(@as(u8, 0x03), resp[tmpl_cipher_offset + 1]);
    // Default (null) keeps the template's 0x1301.
    const resp2 = try buildServerHello(allocator, &digest, &digest, &session_id, null);
    defer allocator.free(resp2);
    try std.testing.expectEqual(@as(u8, 0x13), resp2[tmpl_cipher_offset]);
    try std.testing.expectEqual(@as(u8, 0x01), resp2[tmpl_cipher_offset + 1]);
}

test "buildServerHello rejects non-32-byte session id" {
    const allocator = std.testing.allocator;
    var digest = [_]u8{0xAA} ** 32;
    const session_id = [_]u8{0xBB} ** 16;

    try std.testing.expectError(
        error.BadSessionIdLength,
        buildServerHello(allocator, &digest, &digest, &session_id, null),
    );
}

test "buildServerHelloTemplate depends on seed" {
    const t1 = buildServerHelloTemplate(0x1111_2222_3333_4444);
    const t2 = buildServerHelloTemplate(0x5555_6666_7777_8888);

    const app_offset = 127 + 6 + 5;
    try std.testing.expect(!std.mem.eql(u8, t1[app_offset..], t2[app_offset..]));
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
    var handshake = [_]u8{0x00} ** 96;
    // Set timestamp (say 123456789 = 0x075BCD15)
    // Wait, the client sends digest WITH timestamp XOR'd in the last 4 bytes.
    // If ignore_time_skew = true, the proxy doesn't care what timestamp is.
    // Proxy calculates HMAC on handshake with zeroed digest, then expects it to match (up to 28 bytes) the given digest.

    var hmac_input = std.mem.zeroes([96]u8);
    // Add session id len
    hmac_input[43] = 32; // session_id len
    @memset(hmac_input[44..76], 0xaa);

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

test "validateTlsHandshake - rejects non-32 session id" {
    const allocator = std.testing.allocator;
    var secrets = [_]UserSecret{.{ .name = "alice", .secret = [_]u8{0x1A} ** 16 }};
    var handshake = [_]u8{0x00} ** 80;

    var hmac_input = std.mem.zeroes([80]u8);
    hmac_input[43] = 16;
    @memset(hmac_input[44..60], 0xaa);

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
    var handshake = [_]u8{0x00} ** 96;

    var hmac_input = std.mem.zeroes([96]u8);
    hmac_input[43] = 32;
    @memset(hmac_input[44..76], 0xaa);

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

fn buildTlsAuthClientHello(
    out: *[512]u8,
    secret: [16]u8,
    host: []const u8,
) ![]const u8 {
    if (host.len == 0 or host.len > 200) return error.BadHostLen;

    const sni_list_len: usize = 1 + 2 + host.len;
    const sni_ext_len: usize = 2 + sni_list_len;
    const supported_versions_ext_len: usize = 3;
    const ext_total_len: usize = 4 + sni_ext_len + 4 + supported_versions_ext_len;

    const body_len: usize = 2 + 32 + 1 + 32 + 2 + 2 + 1 + 1 + 2 + ext_total_len;
    const record_payload_len: usize = 4 + body_len;
    const total_len: usize = 5 + record_payload_len;
    if (total_len > out.len) return error.OutOfSpace;

    var p: usize = 0;
    out[p] = constants.tls_record_handshake;
    p += 1;
    out[p] = 0x03;
    out[p + 1] = 0x01;
    p += 2;
    std.mem.writeInt(u16, out[p..][0..2], @intCast(record_payload_len), .big);
    p += 2;

    out[p] = 0x01; // ClientHello
    p += 1;
    out[p] = @intCast((body_len >> 16) & 0xFF);
    out[p + 1] = @intCast((body_len >> 8) & 0xFF);
    out[p + 2] = @intCast(body_len & 0xFF);
    p += 3;

    out[p] = 0x03;
    out[p + 1] = 0x03;
    p += 2;

    const digest_pos = p;
    @memset(out[p .. p + 32], 0);
    p += 32;

    out[p] = 32;
    p += 1;
    @memset(out[p .. p + 32], 0xAA);
    p += 32;

    std.mem.writeInt(u16, out[p..][0..2], 2, .big);
    p += 2;
    out[p] = 0x13;
    out[p + 1] = 0x01;
    p += 2;

    out[p] = 1;
    p += 1;
    out[p] = 0;
    p += 1;

    std.mem.writeInt(u16, out[p..][0..2], @intCast(ext_total_len), .big);
    p += 2;

    // SNI extension
    out[p] = 0x00;
    out[p + 1] = 0x00;
    p += 2;
    std.mem.writeInt(u16, out[p..][0..2], @intCast(sni_ext_len), .big);
    p += 2;
    std.mem.writeInt(u16, out[p..][0..2], @intCast(sni_list_len), .big);
    p += 2;
    out[p] = 0; // host_name
    p += 1;
    std.mem.writeInt(u16, out[p..][0..2], @intCast(host.len), .big);
    p += 2;
    @memcpy(out[p .. p + host.len], host);
    p += host.len;

    // supported_versions extension (TLS 1.3)
    out[p] = 0x00;
    out[p + 1] = 0x2B;
    p += 2;
    std.mem.writeInt(u16, out[p..][0..2], supported_versions_ext_len, .big);
    p += 2;
    out[p] = 2;
    p += 1;
    out[p] = 0x03;
    out[p + 1] = 0x04;
    p += 2;

    if (p != total_len) return error.BuildMismatch;

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    const zero_digest = [_]u8{0} ** constants.tls_digest_len;
    var hmac = HmacSha256.init(&secret);
    hmac.update(out[0..constants.tls_digest_pos]);
    hmac.update(&zero_digest);
    hmac.update(out[constants.tls_digest_pos + constants.tls_digest_len .. total_len]);
    var computed: [32]u8 = undefined;
    hmac.final(&computed);

    @memcpy(out[digest_pos..][0..28], computed[0..28]);
    const ts: u32 = 0x1234_5678;
    const ts_bytes = std.mem.toBytes(ts);
    out[digest_pos + 28] = computed[28] ^ ts_bytes[0];
    out[digest_pos + 29] = computed[29] ^ ts_bytes[1];
    out[digest_pos + 30] = computed[30] ^ ts_bytes[2];
    out[digest_pos + 31] = computed[31] ^ ts_bytes[3];

    return out[0..total_len];
}

test "reject_handshake_alert wire format" {
    // record type 0x15 (alert), TLS 1.2 version, length 2, level 2 (fatal),
    // description 40 (handshake_failure).
    try std.testing.expectEqual(@as(usize, 7), reject_handshake_alert.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 }, &reject_handshake_alert);
}

test "extractSni - fragmented and overlong records" {
    var hello_buf: [512]u8 = undefined;
    const hello = try buildTlsAuthClientHello(&hello_buf, [_]u8{0x19} ** 16, "google.com");

    const sni = extractSni(hello);
    try std.testing.expect(sni != null);
    try std.testing.expectEqualStrings("google.com", sni.?);

    for (0..hello.len) |prefix_len| {
        try std.testing.expect(extractSni(hello[0..prefix_len]) == null);
    }

    var malformed = hello_buf;
    malformed[3] = 0xFF;
    malformed[4] = 0xFF;
    try std.testing.expect(extractSni(malformed[0..hello.len]) == null);
}

test "extractSni - fuzz malformed input" {
    var prng = std.Random.DefaultPrng.init(0x7155100);
    const random = prng.random();

    var buf: [640]u8 = undefined;
    for (0..2500) |_| {
        const len: usize = @as(usize, random.int(u16)) % buf.len;
        random.bytes(buf[0..len]);
        if (extractSni(buf[0..len])) |name| {
            try std.testing.expect(name.len > 0);
            try std.testing.expect(name.len <= len);
        }
    }
}

test "validateTlsHandshake - fuzz random and replayed input" {
    const allocator = std.testing.allocator;
    const secrets = [_]UserSecret{
        .{ .name = "alice", .secret = [_]u8{0x1A} ** 16 },
        .{ .name = "bob", .secret = [_]u8{0x2B} ** 16 },
    };

    var prng = std.Random.DefaultPrng.init(0xDA7A5EED);
    const random = prng.random();
    var random_buf: [768]u8 = undefined;

    for (0..3000) |_| {
        const len: usize = @as(usize, random.int(u16)) % random_buf.len;
        random.bytes(random_buf[0..len]);
        const parsed = try validateTlsHandshake(allocator, random_buf[0..len], &secrets, true);
        if (parsed) |v| {
            try std.testing.expect(v.session_id.len == 32);
            try std.testing.expect(v.user.len > 0);
        }
    }

    // Replayed bytes produce identical canonical HMAC.
    var hello_buf: [512]u8 = undefined;
    const hello = try buildTlsAuthClientHello(&hello_buf, secrets[0].secret, "google.com");
    const first = try validateTlsHandshake(allocator, hello, &secrets, true);
    const second = try validateTlsHandshake(allocator, hello, &secrets, true);
    try std.testing.expect(first != null and second != null);
    try std.testing.expectEqualSlices(u8, &first.?.canonical_hmac, &second.?.canonical_hmac);
}
