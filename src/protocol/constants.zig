//! Protocol constants and datacenter addresses for MTProto proxy.

const std = @import("std");

// ============= Telegram Datacenters =============

pub const tg_datacenter_port: u16 = 443;

pub const tg_datacenters_v4 = [5]std.net.Address{
    std.net.Address.initIp4(.{ 149, 154, 175, 50 }, tg_datacenter_port),
    std.net.Address.initIp4(.{ 149, 154, 167, 51 }, tg_datacenter_port),
    std.net.Address.initIp4(.{ 149, 154, 175, 100 }, tg_datacenter_port),
    std.net.Address.initIp4(.{ 149, 154, 167, 91 }, tg_datacenter_port),
    std.net.Address.initIp4(.{ 149, 154, 171, 5 }, tg_datacenter_port),
};

pub const tg_datacenters_v6 = [5]std.net.Address{
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x0b, 0x28, 0xf2, 0x3d, 0xf0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x0a }, tg_datacenter_port, 0, 0),
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x06, 0x7c, 0x04, 0xe8, 0xf0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0x0a }, tg_datacenter_port, 0, 0),
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x0b, 0x28, 0xf2, 0x3d, 0xf0, 0x03, 0, 0, 0, 0, 0, 0, 0, 0x0a }, tg_datacenter_port, 0, 0),
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x06, 0x7c, 0x04, 0xe8, 0xf0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0x0a }, tg_datacenter_port, 0, 0),
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x0b, 0x28, 0xf2, 0x3f, 0xf0, 0x05, 0, 0, 0, 0, 0, 0, 0, 0x0a }, tg_datacenter_port, 0, 0),
};

pub const tg_middle_proxy_port: u16 = 8888;

/// Default MiddleProxy endpoints per primary DC (1..5), regular (non-media) path.
/// Refreshed at runtime from getProxyConfig when available.
pub const tg_middle_proxies_v4 = [5]std.net.Address{
    std.net.Address.initIp4(.{ 149, 154, 175, 50 }, tg_middle_proxy_port),
    std.net.Address.initIp4(.{ 149, 154, 161, 144 }, tg_middle_proxy_port),
    std.net.Address.initIp4(.{ 149, 154, 175, 100 }, tg_middle_proxy_port),
    std.net.Address.initIp4(.{ 91, 108, 4, 136 }, tg_middle_proxy_port),
    std.net.Address.initIp4(.{ 91, 108, 56, 183 }, tg_middle_proxy_port),
};

/// Default MiddleProxy endpoints per primary DC (1..5), media path (dc_idx < 0).
/// Telegram serves media through a separate MP fleet; connecting a media
/// client to a regular MP causes large file downloads to stall or silently
/// drop. Keep these in sync with `proxy_for -N` lines in getProxyConfig.
/// Refreshed at runtime from getProxyConfig when available.
pub const tg_media_middle_proxies_v4 = [5]std.net.Address{
    std.net.Address.initIp4(.{ 149, 154, 175, 50 }, tg_middle_proxy_port),
    std.net.Address.initIp4(.{ 149, 154, 161, 184 }, tg_middle_proxy_port),
    std.net.Address.initIp4(.{ 149, 154, 175, 100 }, tg_middle_proxy_port),
    std.net.Address.initIp4(.{ 149, 154, 164, 250 }, tg_middle_proxy_port),
    std.net.Address.initIp4(.{ 91, 108, 56, 180 }, tg_middle_proxy_port),
};

/// Resolves physical Datacenter IP by its index, handling special media DCs.
pub fn getDcAddressV4(abs_dc: usize) std.net.Address {
    if (abs_dc == 203) {
        // Media DC 203 has a dedicated network, resolving to MiddleProxy IP
        return std.net.Address.initIp4(.{ 91, 105, 192, 110 }, tg_datacenter_port);
    }
    if (abs_dc >= 1 and abs_dc <= tg_datacenters_v4.len) {
        return tg_datacenters_v4[abs_dc - 1];
    }
    // Fallback to modulo arithmetic for unknown DC indices
    const fallback_idx = (abs_dc - 1) % tg_datacenters_v4.len;
    return tg_datacenters_v4[fallback_idx];
}

// ============= Protocol Tags =============

pub const ProtoTag = enum(u32) {
    abridged = 0xefefefef,
    intermediate = 0xeeeeeeee,
    secure = 0xdddddddd,

    pub fn fromBytes(bytes: [4]u8) ?ProtoTag {
        const val = std.mem.readInt(u32, &bytes, .little);
        return std.meta.intToEnum(ProtoTag, val) catch null;
    }

    pub fn toBytes(self: ProtoTag) [4]u8 {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, @intFromEnum(self), .little);
        return buf;
    }
};

// ============= Handshake Layout =============

/// Bytes to skip at the start of handshake
pub const skip_len: usize = 8;
/// Pre-key length (before hashing with secret)
pub const prekey_len: usize = 32;
/// AES key length
pub const key_len: usize = 32;
/// AES IV length
pub const iv_len: usize = 16;
/// Total handshake length
pub const handshake_len: usize = 64;
/// Position of protocol tag in decrypted handshake
pub const proto_tag_pos: usize = 56;
/// Position of datacenter index
pub const dc_idx_pos: usize = 60;

// ============= TLS Constants =============

/// TLS 1.3 version bytes (in record layer, 0x0303 = TLS 1.2 compat)
pub const tls_version = [2]u8{ 0x03, 0x03 };
/// TLS record type: Handshake
pub const tls_record_handshake: u8 = 0x16;
/// TLS record type: Change Cipher Spec
pub const tls_record_change_cipher: u8 = 0x14;
/// TLS record type: Application Data
pub const tls_record_application: u8 = 0x17;
/// TLS record type: Alert
pub const tls_record_alert: u8 = 0x15;

/// Maximum TLS plaintext record payload (RFC 8446 §5.1)
pub const max_tls_plaintext_size: usize = 16_384;
/// Maximum TLS ciphertext record payload (RFC 8446 §5.2: 2^14 + 256)
pub const max_tls_ciphertext_size: usize = 16_384 + 256;
/// Structural minimum for a valid TLS 1.3 ClientHello with SNI
pub const min_tls_client_hello_size: usize = 100;

// ============= Message Limits =============

pub const min_msg_len: usize = 12;
pub const max_msg_len: usize = 1 << 24; // 16 MB

// ============= Buffer Sizes =============

pub const default_buffer_size: usize = 16384;

// ============= TLS Handshake Constants =============

pub const tls_digest_len: usize = 32;
pub const tls_digest_pos: usize = 11;
pub const tls_digest_half_len: usize = 16;

/// Time skew limits for anti-replay (seconds)
pub const time_skew_min: i64 = -2 * 60;
pub const time_skew_max: i64 = 2 * 60;

// ============= Reserved Nonce Patterns =============

pub const reserved_nonce_first_bytes = [_]u8{0xef};

pub const reserved_nonce_beginnings = [_][4]u8{
    .{ 0x48, 0x45, 0x41, 0x44 }, // HEAD
    .{ 0x50, 0x4F, 0x53, 0x54 }, // POST
    .{ 0x47, 0x45, 0x54, 0x20 }, // GET
    .{ 0x4F, 0x50, 0x54, 0x49 }, // OPTI (OPTIONS)
    .{ 0x50, 0x55, 0x54, 0x20 }, // PUT
    .{ 0xee, 0xee, 0xee, 0xee }, // Intermediate
    .{ 0xdd, 0xdd, 0xdd, 0xdd }, // Secure
    .{ 0x16, 0x03, 0x01, 0x02 }, // TLS
};

pub const reserved_nonce_continues = [_][4]u8{
    .{ 0x00, 0x00, 0x00, 0x00 },
};

test "proto tag roundtrip" {
    inline for (.{ ProtoTag.abridged, ProtoTag.intermediate, ProtoTag.secure }) |tag| {
        const bytes = tag.toBytes();
        const parsed = ProtoTag.fromBytes(bytes);
        try std.testing.expectEqual(tag, parsed.?);
    }
}

test "invalid proto tag" {
    try std.testing.expect(ProtoTag.fromBytes(.{ 0, 0, 0, 0 }) == null);
    try std.testing.expect(ProtoTag.fromBytes(.{ 0xff, 0xff, 0xff, 0xff }) == null);
}
