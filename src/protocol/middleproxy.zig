const std = @import("std");
const net = std.net;
const posix = std.posix;
const crypto = @import("../crypto/crypto.zig");
const constants = @import("constants.zig");

pub const proxy_secret = [128]u8{
    0xc4, 0xf9, 0xfa, 0xca, 0x96, 0x78, 0xe6, 0xbb, 0x48, 0xad, 0x6c, 0x7e, 0x2c, 0xe5, 0xc0, 0xd2,
    0x44, 0x30, 0x64, 0x5d, 0x55, 0x4a, 0xdd, 0xeb, 0x55, 0x41, 0x9e, 0x03, 0x4d, 0xa6, 0x27, 0x21,
    0xd0, 0x46, 0xea, 0xab, 0x6e, 0x52, 0xab, 0x14, 0xa9, 0x5a, 0x44, 0x3e, 0xcf, 0xb3, 0x46, 0x3e,
    0x79, 0xa0, 0x5a, 0x66, 0x61, 0x2a, 0xdf, 0x9c, 0xae, 0xda, 0x8b, 0xe9, 0xa8, 0x0d, 0xa6, 0x98,
    0x6f, 0xb0, 0xa6, 0xff, 0x38, 0x7a, 0xf8, 0x4d, 0x88, 0xef, 0x3a, 0x64, 0x13, 0x71, 0x3e, 0x5c,
    0x33, 0x77, 0xf6, 0xe1, 0xa3, 0xd4, 0x7d, 0x99, 0xf5, 0xe0, 0xc5, 0x6e, 0xec, 0xe8, 0xf0, 0x5c,
    0x54, 0xc4, 0x90, 0xb0, 0x79, 0xe3, 0x1b, 0xef, 0x82, 0xff, 0x0e, 0xe8, 0xf2, 0xb0, 0xa3, 0x27,
    0x56, 0xd2, 0x49, 0xc5, 0xf2, 0x12, 0x69, 0x81, 0x6c, 0xb7, 0x06, 0x1b, 0x26, 0x5d, 0xb2, 0x12,
};

pub const rpc_proxy_req = [_]u8{ 0xee, 0xf1, 0xce, 0x36 };
pub const rpc_proxy_ans = [_]u8{ 0x0d, 0xda, 0x03, 0x44 };
pub const rpc_simple_ack = [_]u8{ 0x9b, 0x40, 0xac, 0x3b };
pub const rpc_close_ext = [_]u8{ 0xa2, 0x34, 0xb6, 0x5e };

pub const rpc_handshake = [_]u8{ 0xf5, 0xee, 0x82, 0x76 };
pub const rpc_nonce_req = [_]u8{ 0xaa, 0x87, 0xcb, 0x7a };
pub const rpc_crypto_aes = [_]u8{ 0x01, 0x00, 0x00, 0x00 };

pub const Flag = struct {
    pub const not_encrypted: u32 = 0x2;
    pub const has_ad_tag: u32 = 0x8;
    pub const magic: u32 = 0x1000;
    pub const extmode2: u32 = 0x20000;
    pub const pad: u32 = 0x8000000;
    pub const intermediate: u32 = 0x20000000;
    pub const abridged: u32 = 0x40000000;
    pub const quickack: u32 = 0x80000000;
};

pub fn getAesKeyAndIv(
    nonce_srv: *const [16]u8,
    nonce_clt: *const [16]u8,
    clt_ts: *const [4]u8,
    srv_ip: ?*const [4]u8,
    clt_port: *const [2]u8,
    purpose: []const u8,
    clt_ip: ?*const [4]u8,
    srv_port: *const [2]u8,
    secret: []const u8,
    clt_ipv6: ?*const [16]u8,
    srv_ipv6: ?*const [16]u8,
) struct { [32]u8, [16]u8 } {
    var s_buf: [512]u8 = undefined;
    var s_len: usize = 0;

    const empty_ip4 = [_]u8{0} ** 4;
    const srv_ip_bytes = if (srv_ip) |ip| ip else &empty_ip4;
    const clt_ip_bytes = if (clt_ip) |ip| ip else &empty_ip4;

    // nonce_srv + nonce_clt + clt_ts + srv_ip + clt_port + purpose + clt_ip + srv_port
    @memcpy(s_buf[s_len .. s_len + 16], nonce_srv);
    s_len += 16;
    @memcpy(s_buf[s_len .. s_len + 16], nonce_clt);
    s_len += 16;
    @memcpy(s_buf[s_len .. s_len + 4], clt_ts);
    s_len += 4;
    @memcpy(s_buf[s_len .. s_len + 4], srv_ip_bytes);
    s_len += 4;
    @memcpy(s_buf[s_len .. s_len + 2], clt_port);
    s_len += 2;
    @memcpy(s_buf[s_len .. s_len + purpose.len], purpose);
    s_len += purpose.len;
    @memcpy(s_buf[s_len .. s_len + 4], clt_ip_bytes);
    s_len += 4;
    @memcpy(s_buf[s_len .. s_len + 2], srv_port);
    s_len += 2;

    @memcpy(s_buf[s_len .. s_len + secret.len], secret);
    s_len += secret.len;
    @memcpy(s_buf[s_len .. s_len + 16], nonce_srv);
    s_len += 16;

    if (clt_ipv6 != null and srv_ipv6 != null) {
        @memcpy(s_buf[s_len .. s_len + 16], clt_ipv6.?);
        s_len += 16;
        @memcpy(s_buf[s_len .. s_len + 16], srv_ipv6.?);
        s_len += 16;
    }

    @memcpy(s_buf[s_len .. s_len + 16], nonce_clt);
    s_len += 16;

    const s = s_buf[0..s_len];

    const md5_all = crypto.md5(s[1..]);
    const sha1_all = crypto.sha1(s);

    var key: [32]u8 = undefined;
    @memcpy(key[0..12], md5_all[0..12]);
    @memcpy(key[12..32], sha1_all[0..20]);

    const iv = crypto.md5(s[2..]);

    return .{ key, iv };
}

pub const MiddleProxyContext = struct {
    encryptor: crypto.AesCbc,
    decryptor: crypto.AesCbc,
    seq_no: i32 = -2,
    read_seq_no: i32 = 0,
    conn_id: [8]u8,
    remote_ip_port: [20]u8,
    our_ip_port: [20]u8,
    proto_tag: constants.ProtoTag,
    ad_tag: ?[16]u8 = null,

    // For S2C chunk parser
    s2c_buf: []u8,
    s2c_len: usize = 0,
    s2c_decrypted_len: usize = 0,
    s2c_out_buf: []u8,

    // For C2S fragment parsing
    c2s_buf: []u8,
    c2s_len: usize = 0,
    c2s_out_buf: []u8,

    pub fn init(allocator: std.mem.Allocator, encryptor: crypto.AesCbc, decryptor: crypto.AesCbc, conn_id: [8]u8, initial_seq_no: i32, remote_addr: net.Address, our_addr: net.Address, proto_tag: constants.ProtoTag, ad_tag: ?[16]u8) !MiddleProxyContext {
        var rip: [20]u8 = undefined;
        var rport: u16 = 0;
        if (remote_addr.any.family == posix.AF.INET) {
            const ipv4_mapped = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
            @memcpy(rip[0..12], &ipv4_mapped);
            @memcpy(rip[12..16], std.mem.asBytes(&remote_addr.in.sa.addr));
            rport = remote_addr.in.sa.port;
        } else if (remote_addr.any.family == posix.AF.INET6) {
            @memcpy(rip[0..16], &remote_addr.in6.sa.addr);
            rport = remote_addr.in6.sa.port;
        } else return error.UnsupportedAddressType;
        std.mem.writeInt(u32, rip[16..20], std.mem.bigToNative(u16, rport), .little);

        var oip: [20]u8 = undefined;
        var oport: u16 = 0;
        if (our_addr.any.family == posix.AF.INET) {
            const ipv4_mapped = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
            @memcpy(oip[0..12], &ipv4_mapped);
            @memcpy(oip[12..16], std.mem.asBytes(&our_addr.in.sa.addr));
            oport = our_addr.in.sa.port;
        } else if (our_addr.any.family == posix.AF.INET6) {
            @memcpy(oip[0..16], &our_addr.in6.sa.addr);
            oport = our_addr.in6.sa.port;
        } else return error.UnsupportedAddressType;
        std.mem.writeInt(u32, oip[16..20], std.mem.bigToNative(u16, oport), .little);

        const s2c_buf = try allocator.alloc(u8, 512 * 1024); // 512KB for max TLS/MTProto frames
        errdefer allocator.free(s2c_buf);

        const s2c_out_buf = try allocator.alloc(u8, 512 * 1024);
        errdefer allocator.free(s2c_out_buf);

        const c2s_buf = try allocator.alloc(u8, 512 * 1024);
        errdefer allocator.free(c2s_buf);

        const c2s_out_buf = try allocator.alloc(u8, 512 * 1024);
        errdefer allocator.free(c2s_out_buf);

        return .{
            .encryptor = encryptor,
            .decryptor = decryptor,
            .seq_no = initial_seq_no,
            .read_seq_no = 0,
            .conn_id = conn_id,
            .remote_ip_port = rip,
            .our_ip_port = oip,
            .proto_tag = proto_tag,
            .ad_tag = ad_tag,
            .s2c_buf = s2c_buf,
            .s2c_out_buf = s2c_out_buf,
            .c2s_buf = c2s_buf,
            .c2s_out_buf = c2s_out_buf,
        };
    }

    pub fn deinit(self: *MiddleProxyContext, allocator: std.mem.Allocator) void {
        allocator.free(self.s2c_buf);
        allocator.free(self.s2c_out_buf);
        allocator.free(self.c2s_buf);
        allocator.free(self.c2s_out_buf);
    }

    /// Takes arbitrary bytes from the client stream, wraps them in RPC_PROXY_REQ,
    /// frames them into MTProtoFrame(s), encrypts with AES-CBC, and stores them in `out_buf`.
    /// Returns the number of bytes written to `out_buf` (which must be sent to the DC).
    pub fn encapsulateC2S(self: *MiddleProxyContext, client_data: []const u8) ![]const u8 {
        if (self.c2s_len + client_data.len > self.c2s_buf.len) return error.MiddleProxyBufferOverflow;
        @memcpy(self.c2s_buf[self.c2s_len .. self.c2s_len + client_data.len], client_data);
        self.c2s_len += client_data.len;

        var pos: usize = 0;
        var total_written: usize = 0;

        while (pos < self.c2s_len) {
            var payload_len: usize = 0;
            var header_len: usize = 0;
            var is_quickack: bool = false; // 1. Track QuickAck per-packet

            switch (self.proto_tag) {
                .abridged => {
                    if (self.c2s_len - pos < 1) break;
                    const first: u8 = self.c2s_buf[pos];
                    is_quickack = (first & 0x80) != 0; // Extract QuickAck

                    const len_val = first & 0x7F;
                    if (len_val < 127) {
                        header_len = 1;
                        payload_len = @as(usize, len_val) * 4;
                    } else {
                        if (self.c2s_len - pos < 4) break;
                        header_len = 4;
                        payload_len = std.mem.readInt(u32, self.c2s_buf[pos..][0..4], .little) >> 8;
                        payload_len *= 4;
                    }
                },
                .intermediate, .secure => {
                    if (self.c2s_len - pos < 4) break;
                    header_len = 4;
                    var len_u32 = std.mem.readInt(u32, self.c2s_buf[pos..][0..4], .little);
                    is_quickack = (len_u32 & 0x80000000) != 0; // Extract QuickAck
                    len_u32 &= 0x7FFFFFFF;
                    payload_len = len_u32;
                },
            }

            if (self.c2s_len - pos < header_len + payload_len) {
                break; // Need more data
            }

            var actual_payload_len = payload_len;
            if (self.proto_tag == .secure) {
                // 2. Truncate random padding DOWN to a multiple of 4.
                actual_payload_len -= payload_len % 4;
            }

            const payload = self.c2s_buf[pos + header_len .. pos + header_len + actual_payload_len];

            // 3. Pass is_quickack to the encapsulator
            const written = try self.encapsulateSingleMessageC2S(payload, is_quickack, self.c2s_out_buf[total_written..]);
            total_written += written;

            // Note: Advance `pos` by the FULL payload_len so we safely consume/discard the padding bytes
            pos += header_len + payload_len;
        }

        if (pos > 0) {
            const remaining = self.c2s_len - pos;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.c2s_buf[0..remaining], self.c2s_buf[pos..self.c2s_len]);
            }
            self.c2s_len = remaining;
        }

        return self.c2s_out_buf[0..total_written];
    }

    pub fn encapsulateSingleMessageC2S(self: *MiddleProxyContext, client_data: []const u8, is_quickack: bool, out_buf: []u8) !usize {
        var flags = Flag.magic | Flag.extmode2;
        if (self.ad_tag != null) {
            flags |= Flag.has_ad_tag;
        }
        switch (self.proto_tag) {
            .abridged => flags |= Flag.abridged,
            .intermediate => flags |= Flag.intermediate,
            .secure => flags |= Flag.intermediate | Flag.pad,
        }

        if (is_quickack) flags |= 0x80000000; // Flag.quickack

        // Check if plain (no obfuscation)
        var all_zeros = true;
        const check_len = @min(8, client_data.len);
        for (client_data[0..check_len]) |b| {
            if (b != 0) all_zeros = false;
        }
        if (all_zeros and client_data.len >= 8) flags |= Flag.not_encrypted;

        // Write directly into out_buf to avoid fixed-size stack buffer overflow
        // on large client packets.
        const extra_len: usize = if (self.ad_tag != null) 28 else 0;
        const rpc_len = 56 + extra_len + client_data.len;
        const frame_total_len = rpc_len + 12;
        const padding_needed = (16 - (frame_total_len % 16)) % 16;
        const encrypted_len = frame_total_len + padding_needed;
        if (out_buf.len < encrypted_len) return error.OutBufOverflow;

        var out_len: usize = 0;
        std.mem.writeInt(u32, out_buf[out_len..][0..4], @intCast(frame_total_len), .little);
        out_len += 4;
        std.mem.writeInt(i32, out_buf[out_len..][0..4], self.seq_no, .little);
        out_len += 4;
        self.seq_no += 1;

        @memcpy(out_buf[out_len .. out_len + 4], &rpc_proxy_req);
        out_len += 4;
        std.mem.writeInt(u32, out_buf[out_len..][0..4], flags, .little);
        out_len += 4;
        @memcpy(out_buf[out_len .. out_len + 8], &self.conn_id);
        out_len += 8;
        @memcpy(out_buf[out_len .. out_len + 20], &self.remote_ip_port);
        out_len += 20;
        @memcpy(out_buf[out_len .. out_len + 20], &self.our_ip_port);
        out_len += 20;

        if (self.ad_tag) |ad_tag| {
            const extra_size: u32 = 24;
            std.mem.writeInt(u32, out_buf[out_len..][0..4], extra_size, .little);
            out_len += 4;

            const proxy_tag = [_]u8{ 0xae, 0x26, 0x1e, 0xdb };
            @memcpy(out_buf[out_len .. out_len + 4], &proxy_tag);
            out_len += 4;

            out_buf[out_len] = 16;
            out_len += 1;

            @memcpy(out_buf[out_len .. out_len + 16], &ad_tag);
            out_len += 16;

            const aligner = [_]u8{ 0x00, 0x00, 0x00 };
            @memcpy(out_buf[out_len .. out_len + 3], &aligner);
            out_len += 3;
        }

        @memcpy(out_buf[out_len .. out_len + client_data.len], client_data);
        out_len += client_data.len;

        // CRC32 of length + seq + payload (which starts at out_buf[0])
        const checksum = crc32(out_buf[0..out_len]);
        std.mem.writeInt(u32, out_buf[out_len..][0..4], checksum, .little);
        out_len += 4;

        // AES CBC Padding requires NO-OP length markers (0x04000000)
        var i: usize = 0;
        while (i < padding_needed) : (i += 4) {
            std.mem.writeInt(u32, out_buf[out_len + i ..][0..4], 4, .little);
        }
        out_len += padding_needed;

        try self.encryptor.encryptInPlace(out_buf[0..out_len]);
        return out_len;
    }

    /// Takes raw AES-CBC bytes from DC, decrypts them block by block, parses MTProtoFrames,
    /// strips RPC_PROXY_ANS, and writes the inner payload into `out_buf`.
    pub fn decapsulateS2C(self: *MiddleProxyContext, dc_chunk: []const u8) ![]u8 {
        if (self.s2c_len + dc_chunk.len > self.s2c_buf.len) return error.MiddleProxyBufferOverflow;
        @memcpy(self.s2c_buf[self.s2c_len .. self.s2c_len + dc_chunk.len], dc_chunk);
        self.s2c_len += dc_chunk.len;

        // Decrypt any new full 16-byte blocks
        while (self.s2c_decrypted_len + 16 <= self.s2c_len) {
            try self.decryptor.decryptInPlace(self.s2c_buf[self.s2c_decrypted_len .. self.s2c_decrypted_len + 16]);
            self.s2c_decrypted_len += 16;
        }

        var out_pos: usize = 0;

        // Parse fully decrypted MTProto frames.
        // Mirrors telemt behavior: parse by frame_len, treat 0x04 words as NO-OP,
        // keep decrypt stream running continuously across arbitrary read boundaries.
        while (self.s2c_decrypted_len >= 4) {
            const frame_len = std.mem.readInt(u32, self.s2c_buf[0..4], .little);

            // MTProto CBC stream may contain standalone NO-OP padding words
            // (0x04 00 00 00). Python reference reader skips them.
            if (frame_len == 4) {
                if (self.s2c_len < 4 or self.s2c_decrypted_len < 4) break;
                const remaining_noop = self.s2c_len - 4;
                if (remaining_noop > 0) {
                    std.mem.copyForwards(u8, self.s2c_buf[0..remaining_noop], self.s2c_buf[4..self.s2c_len]);
                }
                self.s2c_len = remaining_noop;
                self.s2c_decrypted_len -= 4;
                continue;
            }

            if (frame_len < 12 or frame_len > (1 << 24)) {
                // Do not hard-fail on bad len; drop current decrypted window and resync.
                // This matches telemt strategy and avoids tearing down long-lived sessions
                // due to a single malformed/partial decrypted window.
                self.s2c_len = 0;
                self.s2c_decrypted_len = 0;
                break;
            }

            if (self.s2c_decrypted_len < frame_len) {
                break; // Not enough decrypted data yet
            }

            const expected_checksum = std.mem.readInt(u32, self.s2c_buf[frame_len - 4 ..][0..4], .little);
            const computed_checksum = crc32(self.s2c_buf[0 .. frame_len - 4]);
            if (expected_checksum != computed_checksum) return error.BadMiddleProxyChecksum;

            const frame_seq_no = std.mem.readInt(i32, self.s2c_buf[4..8], .little);
            if (frame_seq_no != self.read_seq_no) return error.BadMiddleProxySeqNo;
            self.read_seq_no += 1;

            // Payload is after Length (4) and SeqNo (4), and before CRC32 (4)
            const payload = self.s2c_buf[8 .. frame_len - 4];

            if (payload.len >= 16 and std.mem.eql(u8, payload[0..4], &rpc_simple_ack)) {
                // RPC_SIMPLE_ACK format: type(4) + conn_id(8) + confirm(4)
                const confirm = payload[12..16];
                if (out_pos + confirm.len > self.s2c_out_buf.len) return error.OutBufOverflow;
                @memcpy(self.s2c_out_buf[out_pos .. out_pos + confirm.len], confirm);
                out_pos += confirm.len;
            } else if (payload.len >= 4 and std.mem.eql(u8, payload[0..4], &rpc_close_ext)) {
                return error.ConnectionReset;
            } else if (payload.len >= 16 and std.mem.eql(u8, payload[0..4], &rpc_proxy_ans)) {
                // RPC_PROXY_ANS format: type(4) + flags(4) + conn_id(8) + conn_data
                const conn_data = payload[16..];

                var pad_len: usize = 0;
                var pad_buf: [15]u8 = undefined;
                if (self.proto_tag == .secure) {
                    pad_len = std.crypto.random.intRangeLessThan(usize, 0, 16);
                    if (pad_len > 0) {
                        std.crypto.random.bytes(pad_buf[0..pad_len]);
                    }
                }

                var header_len: usize = 0;
                var header_buf: [4]u8 = undefined;

                switch (self.proto_tag) {
                    .abridged => {
                        const len_div_4: usize = (conn_data.len + pad_len) / 4;
                        if (len_div_4 < 127) {
                            header_buf[0] = @intCast(len_div_4);
                            header_len = 1;
                        } else {
                            header_buf[0] = 127;
                            header_buf[1] = @truncate(len_div_4);
                            header_buf[2] = @truncate(len_div_4 >> 8);
                            header_buf[3] = @truncate(len_div_4 >> 16);
                            header_len = 4;
                        }
                    },
                    .intermediate, .secure => {
                        std.mem.writeInt(u32, header_buf[0..4], @intCast(conn_data.len + pad_len), .little);
                        header_len = 4;
                    },
                }

                if (out_pos + header_len + conn_data.len + pad_len > self.s2c_out_buf.len) return error.OutBufOverflow;

                @memcpy(self.s2c_out_buf[out_pos .. out_pos + header_len], header_buf[0..header_len]);
                out_pos += header_len;

                @memcpy(self.s2c_out_buf[out_pos .. out_pos + conn_data.len], conn_data);
                out_pos += conn_data.len;

                if (pad_len > 0) {
                    @memcpy(self.s2c_out_buf[out_pos .. out_pos + pad_len], pad_buf[0..pad_len]);
                    out_pos += pad_len;
                }
            }
            // Ignore other RPC types (e.g. RPC_SIMPLE_ACK, RPC_CLOSE_EXT)

            // Shift buffer
            const remaining = self.s2c_len - frame_len;
            std.mem.copyForwards(u8, self.s2c_buf[0..remaining], self.s2c_buf[frame_len..self.s2c_len]);
            self.s2c_len = remaining;
            self.s2c_decrypted_len -= frame_len;
        }

        return self.s2c_out_buf[0..out_pos];
    }
};

pub fn crc32(data: []const u8) u32 {
    return std.hash.Crc32.hash(data);
}

pub fn executeHandshake(
    allocator: std.mem.Allocator,
    dc_stream: net.Stream,
    dc_addr: net.Address,
    proto_tag: constants.ProtoTag,
    client_addr: net.Address,
    proxy_secret_bytes: []const u8,
    ad_tag: ?[16]u8,
) !MiddleProxyContext {
    _ = dc_addr;

    if (proxy_secret_bytes.len < 4) return error.BadMiddleProxySecret;

    var write_seq_no: i32 = -2;
    var read_seq_no: i32 = -2;

    // 1. Send RPC_NONCE_REQ
    var nonce: [16]u8 = undefined;
    crypto.randomBytes(&nonce);

    var crypto_ts: [4]u8 = undefined;
    const ts: u32 = @intCast(@mod(std.time.timestamp(), 4294967296));
    std.mem.writeInt(u32, &crypto_ts, ts, .little);

    var msg: [32]u8 = undefined;
    @memcpy(msg[0..4], &rpc_nonce_req);
    @memcpy(msg[4..8], proxy_secret_bytes[0..4]); // key selector
    @memcpy(msg[8..12], &rpc_crypto_aes);
    @memcpy(msg[12..16], &crypto_ts);
    @memcpy(msg[16..32], &nonce);

    try writeFrameSync(dc_stream, &write_seq_no, &msg, null);

    // 2. Receive RPC_NONCE_ANS
    var ans_buf: [128]u8 = undefined;
    const ans_msg = try readFrameSync(dc_stream, &read_seq_no, &ans_buf, null);

    if (ans_msg.len != 32) return error.BadMiddleProxyHandshakeAnsSize;
    if (!std.mem.eql(u8, ans_msg[0..4], &rpc_nonce_req)) return error.BadMiddleProxyAnsType;
    if (!std.mem.eql(u8, ans_msg[4..8], proxy_secret_bytes[0..4])) return error.BadMiddleProxyKeySelector;
    if (!std.mem.eql(u8, ans_msg[8..12], &rpc_crypto_aes)) return error.BadMiddleProxyCryptoSchema;

    const rpc_nonce_ans: *const [16]u8 = ans_msg[16..32][0..16];

    var ts_arr: [4]u8 = undefined;
    std.mem.writeInt(u32, &ts_arr, ts, .little);

    var peer_addr: net.Address = undefined;
    var peer_len: posix.socklen_t = @sizeOf(net.Address);
    try posix.getpeername(dc_stream.handle, &peer_addr.any, &peer_len);

    var local_addr: net.Address = undefined;
    var local_len: posix.socklen_t = @sizeOf(net.Address);
    try posix.getsockname(dc_stream.handle, &local_addr.any, &local_len);

    var tg_port: [2]u8 = undefined;
    var my_port: [2]u8 = undefined;

    var tg_ip_v4_opt: ?[4]u8 = null;
    var my_ip_v4_opt: ?[4]u8 = null;
    var tg_ip_v6_opt: ?[16]u8 = null;
    var my_ip_v6_opt: ?[16]u8 = null;

    if (peer_addr.any.family == posix.AF.INET and local_addr.any.family == posix.AF.INET) {
        var tg_ip_v4: [4]u8 = undefined;
        @memcpy(&tg_ip_v4, std.mem.asBytes(&peer_addr.in.sa.addr));
        std.mem.reverse(u8, &tg_ip_v4);
        tg_ip_v4_opt = tg_ip_v4;

        var my_ip_v4: [4]u8 = undefined;
        @memcpy(&my_ip_v4, std.mem.asBytes(&local_addr.in.sa.addr));
        std.mem.reverse(u8, &my_ip_v4);
        my_ip_v4_opt = my_ip_v4;

        std.mem.writeInt(u16, &tg_port, std.mem.bigToNative(u16, peer_addr.in.sa.port), .little);
        std.mem.writeInt(u16, &my_port, std.mem.bigToNative(u16, local_addr.in.sa.port), .little);
    } else if (peer_addr.any.family == posix.AF.INET6 and local_addr.any.family == posix.AF.INET6) {
        var tg_ip_v6: [16]u8 = undefined;
        @memcpy(&tg_ip_v6, &peer_addr.in6.sa.addr);
        tg_ip_v6_opt = tg_ip_v6;

        var my_ip_v6: [16]u8 = undefined;
        @memcpy(&my_ip_v6, &local_addr.in6.sa.addr);
        my_ip_v6_opt = my_ip_v6;

        std.mem.writeInt(u16, &tg_port, std.mem.bigToNative(u16, peer_addr.in6.sa.port), .little);
        std.mem.writeInt(u16, &my_port, std.mem.bigToNative(u16, local_addr.in6.sa.port), .little);
    } else {
        return error.UnsupportedMiddleProxyAddressFamily;
    }

    const tg_ip_v4_ptr: ?*const [4]u8 = if (tg_ip_v4_opt) |*ip| ip else null;
    const my_ip_v4_ptr: ?*const [4]u8 = if (my_ip_v4_opt) |*ip| ip else null;
    const my_ip_v6_ptr: ?*const [16]u8 = if (my_ip_v6_opt) |*ip| ip else null;
    const tg_ip_v6_ptr: ?*const [16]u8 = if (tg_ip_v6_opt) |*ip| ip else null;

    const enc_keys = getAesKeyAndIv(
        rpc_nonce_ans,
        &nonce,
        &ts_arr,
        tg_ip_v4_ptr,
        &my_port,
        "CLIENT",
        my_ip_v4_ptr,
        &tg_port,
        proxy_secret_bytes,
        my_ip_v6_ptr,
        tg_ip_v6_ptr,
    );
    const dec_keys = getAesKeyAndIv(
        rpc_nonce_ans,
        &nonce,
        &ts_arr,
        tg_ip_v4_ptr,
        &my_port,
        "SERVER",
        my_ip_v4_ptr,
        &tg_port,
        proxy_secret_bytes,
        my_ip_v6_ptr,
        tg_ip_v6_ptr,
    );

    var encryptor = crypto.AesCbc.init(&enc_keys[0], &enc_keys[1]);
    var decryptor = crypto.AesCbc.init(&dec_keys[0], &dec_keys[1]);

    // 3. Send RPC_HANDSHAKE encrypted
    const sender_pid = "IPIPPRPDTIME";
    const peer_pid = "IPIPPRPDTIME";

    var hs_msg: [32]u8 = undefined;
    @memcpy(hs_msg[0..4], &rpc_handshake);
    @memset(hs_msg[4..8], 0); // flags
    @memcpy(hs_msg[8..20], sender_pid);
    @memcpy(hs_msg[20..32], peer_pid);

    try writeFrameSync(dc_stream, &write_seq_no, &hs_msg, &encryptor);

    // 4. Receive and validate RPC_HANDSHAKE_ANS
    var hs_ans_buf: [128]u8 = undefined;
    const hs_ans = try readFrameSync(dc_stream, &read_seq_no, &hs_ans_buf, &decryptor);
    if (hs_ans.len != 32) return error.BadMiddleProxyHandshakeAnsSize;
    if (!std.mem.eql(u8, hs_ans[0..4], &rpc_handshake)) return error.BadMiddleProxyAnsType;
    if (!std.mem.eql(u8, hs_ans[20..32], sender_pid)) return error.BadMiddleProxyHandshakePeerPid;

    // conn_id is 8 random bytes
    var conn_id: [8]u8 = undefined;
    crypto.randomBytes(&conn_id);

    return MiddleProxyContext.init(
        allocator,
        encryptor,
        decryptor,
        conn_id,
        write_seq_no,
        client_addr,
        local_addr,
        proto_tag,
        ad_tag,
    );
}

fn writeFrameSync(stream: net.Stream, seq_no: *i32, payload: []const u8, cbc: ?*crypto.AesCbc) !void {
    var plain: [4096]u8 = undefined;
    const total_len: u32 = @intCast(payload.len + 12);

    std.mem.writeInt(u32, plain[0..4], total_len, .little);
    std.mem.writeInt(i32, plain[4..8], seq_no.*, .little);
    seq_no.* += 1;

    @memcpy(plain[8 .. 8 + payload.len], payload);
    const checksum = crc32(plain[0 .. 8 + payload.len]);
    std.mem.writeInt(u32, plain[8 + payload.len ..][0..4], checksum, .little);

    var to_send_len: usize = payload.len + 12;
    if (cbc) |encryptor| {
        // pad to 16 bytes using custom padding (e.g. 0x04000000)
        const padding_needed = (16 - (to_send_len % 16)) % 16;
        var i: usize = 0;
        while (i < padding_needed) : (i += 4) {
            std.mem.writeInt(u32, plain[to_send_len + i ..][0..4], 4, .little);
        }
        to_send_len += padding_needed;
        try encryptor.encryptInPlace(plain[0..to_send_len]);
    }

    try stream.writeAll(plain[0..to_send_len]);
}

fn readFrameSync(stream: net.Stream, seq_no: *i32, out_buf: []u8, cbc: ?*crypto.AesCbc) ![]const u8 {
    var frame_buf: [4096]u8 = undefined;

    if (cbc) |decryptor| {
        try readExactSync(stream, frame_buf[0..16]);
        try decryptor.decryptInPlace(frame_buf[0..16]);

        const total_len = std.mem.readInt(u32, frame_buf[0..4], .little);
        if (total_len < 12) return error.BadMiddleProxyFrameSize;

        const padded_len = if (total_len % 16 == 0) total_len else total_len + (16 - (total_len % 16));
        if (padded_len > frame_buf.len) return error.BadMiddleProxyFrameSize;

        if (padded_len > 16) {
            try readExactSync(stream, frame_buf[16..padded_len]);
            try decryptor.decryptInPlace(frame_buf[16..padded_len]);
        }

        return parseFrameSync(seq_no, out_buf, frame_buf[0..total_len]);
    }

    try readExactSync(stream, frame_buf[0..4]);
    const total_len = std.mem.readInt(u32, frame_buf[0..4], .little);
    if (total_len < 12 or total_len > frame_buf.len) return error.BadMiddleProxyFrameSize;

    try readExactSync(stream, frame_buf[4..total_len]);
    return parseFrameSync(seq_no, out_buf, frame_buf[0..total_len]);
}

fn parseFrameSync(seq_no: *i32, out_buf: []u8, frame: []const u8) ![]const u8 {
    const total_len = frame.len;

    const msg_seq = std.mem.readInt(i32, frame[4..8], .little);
    if (msg_seq != seq_no.*) return error.BadMiddleProxySeqNo;
    seq_no.* += 1;

    const expected_checksum = std.mem.readInt(u32, frame[total_len - 4 ..][0..4], .little);
    const computed_checksum = crc32(frame[0 .. total_len - 4]);
    if (expected_checksum != computed_checksum) return error.BadMiddleProxyChecksum;

    const payload_len = total_len - 12;
    if (payload_len > out_buf.len) return error.BadMiddleProxyFrameSize;

    @memcpy(out_buf[0..payload_len], frame[8 .. total_len - 4]);
    return out_buf[0..payload_len];
}

fn readExactSync(stream: net.Stream, out: []u8) !void {
    var offset: usize = 0;
    while (offset < out.len) {
        const nr = try stream.read(out[offset..]);
        if (nr == 0) return error.EndOfStream;
        offset += nr;
    }
}

test "encapsulated c2s keeps rpc_proxy_req header" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        std.net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        std.net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
    );
    defer ctx.deinit(allocator);

    const client_data = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    var encrypted_out: [512]u8 = undefined;

    const written = try ctx.encapsulateSingleMessageC2S(client_data[0..], false, encrypted_out[0..]);
    try std.testing.expect(written >= 16);

    var decryptor = crypto.AesCbc.init(&key, &iv);
    try decryptor.decryptInPlace(encrypted_out[0..written]);

    const total_len = std.mem.readInt(u32, encrypted_out[0..4], .little);
    try std.testing.expect(total_len >= 12 + 4);

    const payload = encrypted_out[8 .. total_len - 4];
    try std.testing.expect(payload.len >= 4);
    try std.testing.expectEqualSlices(u8, &rpc_proxy_req, payload[0..4]);
}

test "encapsulated c2s omits ad_tag block when absent" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        std.net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        std.net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
    );
    defer ctx.deinit(allocator);

    const client_data = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    var encrypted_out: [512]u8 = undefined;

    const written = try ctx.encapsulateSingleMessageC2S(client_data[0..], false, encrypted_out[0..]);
    try std.testing.expect(written >= 16);

    var decryptor = crypto.AesCbc.init(&key, &iv);
    try decryptor.decryptInPlace(encrypted_out[0..written]);

    const total_len = std.mem.readInt(u32, encrypted_out[0..4], .little);
    const payload = encrypted_out[8 .. total_len - 4];

    const flags = std.mem.readInt(u32, payload[4..8], .little);
    try std.testing.expect((flags & Flag.has_ad_tag) == 0);
    try std.testing.expectEqual(@as(usize, 56 + client_data.len), payload.len);
}

test "encapsulated c2s includes ad_tag block when present" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;
    const ad_tag = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        std.net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        std.net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        ad_tag,
    );
    defer ctx.deinit(allocator);

    const client_data = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    var encrypted_out: [512]u8 = undefined;

    const written = try ctx.encapsulateSingleMessageC2S(client_data[0..], false, encrypted_out[0..]);
    try std.testing.expect(written >= 16);

    var decryptor = crypto.AesCbc.init(&key, &iv);
    try decryptor.decryptInPlace(encrypted_out[0..written]);

    const total_len = std.mem.readInt(u32, encrypted_out[0..4], .little);
    const payload = encrypted_out[8 .. total_len - 4];

    const flags = std.mem.readInt(u32, payload[4..8], .little);
    try std.testing.expect((flags & Flag.has_ad_tag) != 0);

    const extra_size = std.mem.readInt(u32, payload[56..60], .little);
    try std.testing.expectEqual(@as(u32, 24), extra_size);
    const proxy_tag = [_]u8{ 0xae, 0x26, 0x1e, 0xdb };
    try std.testing.expectEqualSlices(u8, &proxy_tag, payload[60..64]);
    try std.testing.expectEqual(@as(u8, 16), payload[64]);
    try std.testing.expectEqualSlices(u8, &ad_tag, payload[65..81]);
}

test "decapsulate s2c skips noop padding words" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        std.net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        std.net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
    );
    defer ctx.deinit(allocator);

    // Build plaintext stream:
    // - one full 16-byte NO-OP block (4x uint32(4))
    // - one RPC_SIMPLE_ACK frame (len=28, padded to 32)
    var plain: [48]u8 = undefined;
    var off: usize = 0;

    // 16-byte NO-OP block
    var i: usize = 0;
    while (i < 16) : (i += 4) {
        std.mem.writeInt(u32, plain[off + i ..][0..4], 4, .little);
    }
    off += 16;

    // RPC_SIMPLE_ACK frame: total_len=28, payload=16
    const total_len: u32 = 28;
    std.mem.writeInt(u32, plain[off..][0..4], total_len, .little);
    std.mem.writeInt(i32, plain[off + 4 ..][0..4], 0, .little);

    // payload: type(4) + conn_id(8) + confirm(4)
    @memcpy(plain[off + 8 .. off + 12], &rpc_simple_ack);
    @memset(plain[off + 12 .. off + 20], 0);
    const confirm = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    @memcpy(plain[off + 20 .. off + 24], &confirm);

    const checksum = crc32(plain[off .. off + 24]);
    std.mem.writeInt(u32, plain[off + 24 ..][0..4], checksum, .little);

    // Padded tail for len=28 -> 32
    std.mem.writeInt(u32, plain[off + 28 ..][0..4], 4, .little);

    // Encrypt the full stream as one CBC chain
    var enc = crypto.AesCbc.init(&key, &iv);
    var wire = plain;
    try enc.encryptInPlace(wire[0..]);

    const out = try ctx.decapsulateS2C(wire[0..]);
    try std.testing.expectEqual(@as(usize, 4), out.len);
    try std.testing.expectEqualSlices(u8, &confirm, out);
}

test "decapsulate s2c validates seq and checksum" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        std.net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        std.net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
    );
    defer ctx.deinit(allocator);

    // Build one plaintext RPC_PROXY_ANS frame with seq=0 and 4-byte body.
    var plain: [32]u8 = undefined;
    const total_len: u32 = 32;
    std.mem.writeInt(u32, plain[0..4], total_len, .little);
    std.mem.writeInt(i32, plain[4..8], 0, .little);
    @memcpy(plain[8..12], &rpc_proxy_ans);
    std.mem.writeInt(u32, plain[12..16], 0, .little); // flags
    @memset(plain[16..24], 0); // conn_id
    std.mem.writeInt(u32, plain[24..28], 0x12345678, .little); // data
    const checksum = crc32(plain[0..28]);
    std.mem.writeInt(u32, plain[28..32], checksum, .little);

    var enc = crypto.AesCbc.init(&key, &iv);
    var wire = plain;
    try enc.encryptInPlace(wire[0..]);

    const out = try ctx.decapsulateS2C(wire[0..]);
    try std.testing.expectEqual(@as(usize, 8), out.len); // len(4) + data(4)

    // Send a second valid frame with wrong seq (5 instead of expected 1)
    var plain2: [32]u8 = undefined;
    std.mem.writeInt(u32, plain2[0..4], total_len, .little);
    std.mem.writeInt(i32, plain2[4..8], 5, .little);
    @memcpy(plain2[8..12], &rpc_proxy_ans);
    std.mem.writeInt(u32, plain2[12..16], 0, .little);
    @memset(plain2[16..24], 0);
    std.mem.writeInt(u32, plain2[24..28], 0x01020304, .little);
    const checksum2 = crc32(plain2[0..28]);
    std.mem.writeInt(u32, plain2[28..32], checksum2, .little);

    var wire2 = plain2;
    try enc.encryptInPlace(wire2[0..]);

    try std.testing.expectError(error.BadMiddleProxySeqNo, ctx.decapsulateS2C(wire2[0..]));
}

test "encapsulate c2s supports payloads larger than 64KiB" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        std.net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        std.net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
    );
    defer ctx.deinit(allocator);

    const payload_len = 96 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    @memset(payload, 0x42);

    const out_buf = try allocator.alloc(u8, 128 * 1024);
    defer allocator.free(out_buf);

    const written = try ctx.encapsulateSingleMessageC2S(payload, false, out_buf);
    try std.testing.expect(written > payload_len);

    var decryptor = crypto.AesCbc.init(&key, &iv);
    try decryptor.decryptInPlace(out_buf[0..written]);

    const total_len = std.mem.readInt(u32, out_buf[0..4], .little);
    try std.testing.expectEqual(@as(usize, total_len), 56 + payload_len + 12);

    const rpc_payload = out_buf[8 .. total_len - 4];
    try std.testing.expectEqualSlices(u8, &rpc_proxy_req, rpc_payload[0..4]);
}
