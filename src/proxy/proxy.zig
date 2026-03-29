//! Proxy core — TCP listener, client handler, DC connection, bidirectional relay.
//!
//! Design: ProxyState is passed by reference (DI) — no global mutable state.

const std = @import("std");
const net = std.net;
const posix = std.posix;
const constants = @import("../protocol/constants.zig");
const crypto = @import("../crypto/crypto.zig");
const obfuscation = @import("../protocol/obfuscation.zig");
const tls = @import("../protocol/tls.zig");
const Config = @import("../config.zig").Config;

const log = std.log.scoped(.proxy);

/// TLS record header size
const tls_header_len = 5;
/// Maximum TLS payload we'll write in one record
const max_tls_payload = constants.max_tls_ciphertext_size;
/// Idle timeout for relay poll() and write backpressure (5 minutes)
const relay_timeout_ms = 5 * 60 * 1000;
/// Idle Phase: wait for first byte from client (5 minutes).
/// Mobile clients (iOS Telegram) aggressively pre-warm TCP connection pools,
/// opening 2-5 idle sockets that sit empty until the app needs to send data.
/// A short timeout here kills these pooled connections, causing iOS to mark
/// the proxy as unstable and enter long reconnect cycles.
const idle_timeout_ms: i32 = 5 * 60 * 1000;
/// Active Phase: once data starts arriving, apply tight SO_RCVTIMEO
/// to protect against Slowloris-style attacks (seconds).
const active_timeout_sec: u32 = 10;

// ============= Dynamic Record Sizing (DRS) =============

/// Mimics real browser TLS behavior: start with small records (like Chrome/Firefox
/// initial record sizing for latency), then ramp up to full 16384-byte records
/// for bulk throughput.
///
/// Real browsers use small initial records (~1369 bytes = MSS - TCP/IP/TLS overhead)
/// to avoid head-of-line blocking on the first few roundtrips, then switch to
/// max-size records once the connection is established.
const DynamicRecordSizer = struct {
    /// Current maximum payload per TLS record
    current_size: usize,
    /// Number of records sent so far
    records_sent: u32,
    /// Total bytes sent (for ramp threshold)
    bytes_sent: u64,

    /// Initial record size: MSS(1460) - IP(20) - TCP(20) - TLS_header(5) - AEAD(16) - options(~30) ≈ 1369
    const initial_size: usize = 1369;
    /// Full TLS plaintext record size
    const full_size: usize = constants.max_tls_plaintext_size; // 16384
    /// Ramp up after this many initial records
    const ramp_record_threshold: u32 = 8;
    /// Or ramp up after this many total bytes
    const ramp_byte_threshold: u64 = 128 * 1024;

    fn init() DynamicRecordSizer {
        return .{
            .current_size = initial_size,
            .records_sent = 0,
            .bytes_sent = 0,
        };
    }

    /// Get the max payload size for the next TLS record.
    fn nextRecordSize(self: *DynamicRecordSizer) usize {
        return self.current_size;
    }

    /// Report that a record was sent. Handles ramp-up logic.
    fn recordSent(self: *DynamicRecordSizer, payload_len: usize) void {
        self.records_sent += 1;
        self.bytes_sent += payload_len;

        if (self.current_size < full_size) {
            if (self.records_sent >= ramp_record_threshold or
                self.bytes_sent >= ramp_byte_threshold)
            {
                self.current_size = full_size;
            }
        }
    }
};

/// Shared proxy state — passed by reference, no globals.
pub const ProxyState = struct {
    allocator: std.mem.Allocator,
    config: Config,
    /// Cached user secrets for handshake validation
    user_secrets: []const obfuscation.UserSecret,
    /// Connection counter for logging
    connection_count: std.atomic.Value(u64),

    pub fn init(allocator: std.mem.Allocator, cfg: Config) ProxyState {
        var secrets: std.ArrayList(obfuscation.UserSecret) = .empty;
        var it = @constCast(&cfg.users).iterator();
        while (it.next()) |entry| {
            secrets.append(allocator, .{
                .name = entry.key_ptr.*,
                .secret = entry.value_ptr.*,
            }) catch continue;
        }

        return .{
            .allocator = allocator,
            .config = cfg,
            .user_secrets = secrets.toOwnedSlice(allocator) catch &.{},
            .connection_count = std.atomic.Value(u64).init(0),
        };
    }

    pub fn deinit(self: *ProxyState) void {
        self.allocator.free(self.user_secrets);
    }

    /// Start the proxy server.
    pub fn run(self: *ProxyState) !void {
        const address = net.Address.initIp4(.{ 0, 0, 0, 0 }, self.config.port);
        var server = try address.listen(.{
            .reuse_address = true,
        });
        defer server.deinit();

        log.info("Listening on 0.0.0.0:{d}", .{self.config.port});

        while (true) {
            const conn = server.accept() catch |err| {
                log.err("Accept error: {any}", .{err});
                continue;
            };

            const conn_id = self.connection_count.fetchAdd(1, .monotonic);

            const thread = std.Thread.spawn(.{
                // Proxy threads just shuffle bytes between sockets + AES-CTR (no deep recursion).
                // 128 KB is plenty. Default 8-16 MB per thread would exhaust memory with thousands
                // of idle iOS pool connections (e.g. 4000 threads * 8 MB = 32 GB virtual memory).
                .stack_size = 128 * 1024,
            }, handleConnection, .{ self, conn.stream, conn.address, conn_id }) catch |err| {
                log.err("[{d}] Spawn error: {any}", .{ conn_id, err });
                conn.stream.close();
                continue;
            };
            thread.detach();
        }
    }
};

/// Handle a single client connection.
fn handleConnection(
    state: *ProxyState,
    client_stream: net.Stream,
    peer_addr: net.Address,
    conn_id: u64,
) void {
    defer client_stream.close();

    handleConnectionInner(state, client_stream, conn_id) catch |err| {
        // Idle pool closure is normal — mobile clients pre-warm connections
        // that may never send data. Don't pollute logs.
        if (err == error.IdleConnectionClosed) {
            log.debug("[{d}] Closed idle pooled connection", .{conn_id});
            return;
        }
        // WouldBlock during handshake = Slowloris or extreme lag
        if (err == error.WouldBlock) {
            log.warn("[{d}] Handshake timeout (Slowloris/lag)", .{conn_id});
            return;
        }
        log.err("[{d}] Connection error: {any}", .{ conn_id, err });
    };
    _ = peer_addr;
}

fn handleConnectionInner(
    state: *ProxyState,
    client_stream: net.Stream,
    conn_id: u64,
) !void {
    // === Two-Stage Timeout (Split Timeout) ===
    //
    // Stage 1 — Idle Phase: wait for the first byte with a long timeout.
    // Mobile clients (iOS Telegram) pre-warm TCP connection pools by opening
    // several idle sockets. Killing them too early causes reconnect storms.
    // A sleeping thread in poll() consumes zero CPU.
    //
    // Stage 2 — Active Phase: once data arrives, apply a tight SO_RCVTIMEO
    // to catch real Slowloris attacks (slow-drip partial sends).

    const fd = client_stream.handle;

    // Stage 1: wait for first byte (idle pool phase)
    var poll_fds = [_]posix.pollfd{
        .{ .fd = fd, .events = posix.POLL.IN, .revents = 0 },
    };
    const ready = posix.poll(&poll_fds, idle_timeout_ms) catch return error.ConnectionReset;
    if (ready == 0) {
        // Client held the socket open but never sent data — normal pool behavior.
        return error.IdleConnectionClosed;
    }
    // Client closed the pooled socket from their side (FIN/RST)
    if (poll_fds[0].revents & (posix.POLL.ERR | posix.POLL.HUP) != 0) {
        return error.IdleConnectionClosed;
    }

    // Stage 2: data is coming — apply tight recv timeout (anti-Slowloris)
    setRecvTimeout(fd, active_timeout_sec);

    // Read first 5 bytes to determine TLS vs direct
    var first_bytes: [5]u8 = undefined;
    const n = try readExact(client_stream, &first_bytes);
    if (n < 5) return;

    if (!tls.isTlsHandshake(&first_bytes)) {
        log.debug("[{d}] Non-TLS connection, dropping", .{conn_id});
        return;
    }

    // TLS path: read full ClientHello
    const record_len = std.mem.readInt(u16, first_bytes[3..5], .big);
    if (record_len < constants.min_tls_client_hello_size or record_len > constants.max_tls_plaintext_size) {
        return;
    }

    var client_hello_buf: [5 + constants.max_tls_plaintext_size]u8 = undefined;
    @memcpy(client_hello_buf[0..5], &first_bytes);
    const body_n = try readExact(client_stream, client_hello_buf[5..][0..record_len]);
    if (body_n < record_len) return;

    const client_hello = client_hello_buf[0 .. 5 + record_len];

    // Validate TLS handshake against secrets
    const validation = try tls.validateTlsHandshake(
        state.allocator,
        client_hello,
        state.user_secrets,
        false,
    );

    if (validation == null) {
        log.debug("[{d}] TLS auth failed", .{conn_id});
        return;
    }

    const v = validation.?;
    log.info("[{d}] TLS auth OK: user={s}", .{ conn_id, v.user });

    // Send ServerHello response
    const server_hello = try tls.buildServerHello(
        state.allocator,
        &v.secret,
        &v.digest,
        v.session_id,
        1024,
    );
    defer state.allocator.free(server_hello);

    _ = try client_stream.write(server_hello);

    // Read 64-byte MTProto handshake (wrapped in TLS Application Data)
    // The client may send a Change Cipher Spec (CCS) record first — skip it.
    var tls_header: [5]u8 = undefined;
    while (true) {
        if (try readExact(client_stream, &tls_header) < 5) return;

        if (tls_header[0] == constants.tls_record_application) break;

        if (tls_header[0] == constants.tls_record_change_cipher) {
            // Read and discard the CCS body
            const ccs_len = std.mem.readInt(u16, tls_header[3..5], .big);
            if (ccs_len > 256) return;
            var ccs_buf: [256]u8 = undefined;
            if (try readExact(client_stream, ccs_buf[0..ccs_len]) < ccs_len) return;
            continue;
        }

        log.debug("[{d}] Unexpected TLS record type after ServerHello: 0x{x:0>2}", .{ conn_id, tls_header[0] });
        return;
    }

    const payload_len = std.mem.readInt(u16, tls_header[3..5], .big);
    if (payload_len < constants.handshake_len) return;
    if (payload_len > constants.max_tls_ciphertext_size) return; // Fix #4: bounds check against buffer size

    var payload_buf: [constants.max_tls_ciphertext_size]u8 = undefined;
    if (try readExact(client_stream, payload_buf[0..payload_len]) < payload_len) return;

    const handshake: *const [constants.handshake_len]u8 = payload_buf[0..constants.handshake_len];

    // Parse obfuscation params
    const result = obfuscation.ObfuscationParams.fromHandshake(handshake, state.user_secrets) orelse {
        log.debug("[{d}] MTProto handshake failed for user {s}", .{ conn_id, v.user });
        return;
    };

    var params = result.params;
    defer params.wipe();

    log.info("[{d}] MTProto OK: user={s} dc={d} proto={any}", .{
        conn_id,
        result.user,
        params.dc_idx,
        params.proto_tag,
    });

    // Resolve DC address — use @abs() to avoid overflow when dc_idx == minInt(i16)
    const dc_idx: usize = if (params.dc_idx > 0)
        @as(usize, @intCast(params.dc_idx)) - 1
    else if (params.dc_idx < 0)
        @as(usize, @abs(params.dc_idx)) - 1
    else
        return;

    if (dc_idx >= constants.tg_datacenters_v4.len) return;

    const dc_addr = constants.tg_datacenters_v4[dc_idx];
    log.info("[{d}] Connecting to DC {d}", .{ conn_id, params.dc_idx });

    const dc_stream = net.tcpConnectToAddress(dc_addr) catch |err| {
        log.err("[{d}] DC connect failed: {any}", .{ conn_id, err });
        return;
    };
    defer dc_stream.close();

    // Generate and send obfuscated handshake to Telegram DC
    var tg_nonce = obfuscation.generateNonce();
    // Set proto tag and DC index in the nonce
    const tag_bytes = params.proto_tag.toBytes();
    @memcpy(tg_nonce[constants.proto_tag_pos..][0..4], &tag_bytes);
    std.mem.writeInt(i16, tg_nonce[constants.dc_idx_pos..][0..2], params.dc_idx, .little);

    // Derive TG crypto keys from nonce (raw key bytes, NOT SHA256)
    const tg_enc_key_iv = tg_nonce[constants.skip_len..][0 .. constants.key_len + constants.iv_len];
    var tg_enc_key: [constants.key_len]u8 = tg_enc_key_iv[0..constants.key_len].*;
    var tg_enc_iv_bytes: [constants.iv_len]u8 = tg_enc_key_iv[constants.key_len..][0..constants.iv_len].*;
    const tg_enc_iv = std.mem.readInt(u128, &tg_enc_iv_bytes, .big);

    // Decrypt direction: reversed key+IV
    var tg_dec_key_iv: [constants.key_len + constants.iv_len]u8 = undefined;
    for (0..tg_enc_key_iv.len) |i| {
        tg_dec_key_iv[i] = tg_enc_key_iv[tg_enc_key_iv.len - 1 - i];
    }
    var tg_dec_key: [constants.key_len]u8 = tg_dec_key_iv[0..constants.key_len].*;
    const tg_dec_iv = std.mem.readInt(u128, tg_dec_key_iv[constants.key_len..][0..constants.iv_len], .big);

    // Encrypt the nonce: encrypt full nonce to advance counter, but only
    // replace bytes from proto_tag_pos onwards with ciphertext
    var tg_encryptor = crypto.AesCtr.init(&tg_enc_key, tg_enc_iv);
    defer tg_encryptor.wipe();
    var encrypted_nonce: [constants.handshake_len]u8 = undefined;
    @memcpy(&encrypted_nonce, &tg_nonce);
    tg_encryptor.apply(&encrypted_nonce);
    // Build final nonce: unencrypted prefix + encrypted suffix
    var nonce_to_send: [constants.handshake_len]u8 = undefined;
    @memcpy(nonce_to_send[0..constants.proto_tag_pos], tg_nonce[0..constants.proto_tag_pos]);
    @memcpy(nonce_to_send[constants.proto_tag_pos..], encrypted_nonce[constants.proto_tag_pos..]);

    _ = try dc_stream.write(&nonce_to_send);
    // tg_encryptor counter is now at position 4 (past 64 bytes), correct for subsequent data

    var tg_decryptor = crypto.AesCtr.init(&tg_dec_key, tg_dec_iv);
    defer tg_decryptor.wipe();

    // Wipe key material from stack
    @memset(&tg_enc_key, 0);
    @memset(&tg_enc_iv_bytes, 0);
    @memset(&tg_dec_key, 0);
    @memset(&tg_dec_key_iv, 0);

    log.info("[{d}] Relaying traffic", .{conn_id});

    // Set both sockets to non-blocking to prevent deadlocks with poll().
    // The relay handlers already handle WouldBlock errors correctly.
    setNonBlocking(client_stream.handle);
    setNonBlocking(dc_stream.handle);

    // Create client-side crypto
    // client_decryptor: decrypt client→proxy traffic (C2S)
    // client_encryptor: encrypt proxy→client traffic (S2C)
    var client_decryptor = params.createDecryptor();
    var client_encryptor = params.createEncryptor();
    defer client_decryptor.wipe();
    defer client_encryptor.wipe();

    // CRITICAL: The client encrypted its 64-byte handshake with AES-CTR, advancing
    // its counter by 4 blocks (64 / 16 = 4). fromHandshake() used a temp decryptor
    // to verify the handshake then discarded it. Our fresh decryptor starts at
    // counter 0 — we must advance it by 4 to match the client's CTR state.
    client_decryptor.ctr +%= 4;

    // Fix #3: Handle pipelined data — Telegram clients send their first RPC request
    // immediately after the 64-byte handshake in the same TLS record. If we don't
    // forward these bytes, the client's first message is silently lost.
    if (payload_len > constants.handshake_len) {
        const pipelined = payload_buf[constants.handshake_len..payload_len];
        // Decrypt with client cipher, re-encrypt with DC cipher
        client_decryptor.apply(pipelined);
        tg_encryptor.apply(pipelined);
        try writeAll(dc_stream, pipelined);
    }

    relayBidirectional(
        client_stream,
        dc_stream,
        &client_decryptor,
        &client_encryptor,
        &tg_encryptor,
        &tg_decryptor,
        conn_id,
    ) catch |err| {
        log.debug("[{d}] Relay ended: {any}", .{ conn_id, err });
    };
}

/// Bidirectional relay between client (TLS + AES-CTR) and Telegram DC (AES-CTR).
///
/// Data flow:
///   C2S: TLS record → unwrap → AES-CTR decrypt (client) → AES-CTR encrypt (DC) → DC
///   S2C: DC → AES-CTR decrypt (DC) → AES-CTR encrypt (client) → TLS record wrap → client
fn relayBidirectional(
    client: net.Stream,
    dc: net.Stream,
    client_decryptor: *crypto.AesCtr,
    client_encryptor: *crypto.AesCtr,
    tg_encryptor: *crypto.AesCtr,
    tg_decryptor: *crypto.AesCtr,
    conn_id: u64,
) !void {
    _ = conn_id;

    var fds = [2]posix.pollfd{
        .{ .fd = client.handle, .events = posix.POLL.IN, .revents = 0 },
        .{ .fd = dc.handle, .events = posix.POLL.IN, .revents = 0 },
    };

    // State for reading TLS records from client
    var tls_hdr_buf: [tls_header_len]u8 = undefined;
    var tls_hdr_pos: usize = 0;
    var tls_body_buf: [max_tls_payload]u8 = undefined;
    var tls_body_pos: usize = 0;
    var tls_body_len: usize = 0;

    // Dynamic Record Sizing for S2C TLS records
    var drs = DynamicRecordSizer.init();

    // Buffer for DC → client direction
    var dc_read_buf: [constants.default_buffer_size]u8 = undefined;

    while (true) {
        const ready = try posix.poll(&fds, relay_timeout_ms);
        if (ready == 0) return error.ConnectionReset; // idle timeout — close ghost connection

        // Check for errors/hangup first
        if (fds[0].revents & (posix.POLL.ERR | posix.POLL.HUP) != 0) return;
        if (fds[1].revents & (posix.POLL.ERR | posix.POLL.HUP) != 0) return;

        // Client → DC (C2S): read TLS records, unwrap, decrypt, re-encrypt, forward
        if (fds[0].revents & posix.POLL.IN != 0) {
            try relayClientToDc(
                client,
                dc,
                client_decryptor,
                tg_encryptor,
                &tls_hdr_buf,
                &tls_hdr_pos,
                &tls_body_buf,
                &tls_body_pos,
                &tls_body_len,
            );
        }

        // DC → Client (S2C): read raw, decrypt DC, encrypt client, wrap in TLS
        if (fds[1].revents & posix.POLL.IN != 0) {
            try relayDcToClient(
                dc,
                client,
                tg_decryptor,
                client_encryptor,
                &dc_read_buf,
                &drs,
            );
        }
    }
}

/// C2S direction: Read TLS records from client, unwrap, AES-CTR decrypt, re-encrypt for DC, send.
///
/// Uses incremental state so partial reads across poll iterations are handled correctly.
/// Both CCS and Application Data records share the same body buffer to survive WouldBlock.
fn relayClientToDc(
    client: net.Stream,
    dc: net.Stream,
    client_decryptor: *crypto.AesCtr,
    tg_encryptor: *crypto.AesCtr,
    tls_hdr_buf: *[tls_header_len]u8,
    tls_hdr_pos: *usize,
    tls_body_buf: *[max_tls_payload]u8,
    tls_body_pos: *usize,
    tls_body_len: *usize,
) !void {
    // Read as much as possible in this call
    while (true) {
        if (tls_hdr_pos.* < tls_header_len) {
            // Still reading TLS header
            const nr = client.read(tls_hdr_buf[tls_hdr_pos.*..]) catch |err| {
                return if (err == error.WouldBlock) {} else err;
            };
            if (nr == 0) return error.ConnectionReset;
            tls_hdr_pos.* += nr;

            if (tls_hdr_pos.* < tls_header_len) return; // need more header bytes

            // Parse TLS record header
            const record_type = tls_hdr_buf[0];

            if (record_type == constants.tls_record_alert) {
                // Alert = peer closing
                return error.ConnectionReset;
            }

            if (record_type == constants.tls_record_change_cipher or
                record_type == constants.tls_record_application)
            {
                tls_body_len.* = std.mem.readInt(u16, tls_hdr_buf[3..5], .big);
                if (tls_body_len.* == 0 or tls_body_len.* > max_tls_payload) {
                    return error.ConnectionReset;
                }
                tls_body_pos.* = 0;
            } else {
                // Unexpected record type
                return error.ConnectionReset;
            }
        }

        // Reading TLS record body (shared path for CCS and Application Data)
        const remaining = tls_body_len.* - tls_body_pos.*;
        if (remaining == 0) {
            // Record complete, reset for next
            tls_hdr_pos.* = 0;
            tls_body_pos.* = 0;
            tls_body_len.* = 0;
            continue;
        }

        const nr = client.read(tls_body_buf[tls_body_pos.*..][0..remaining]) catch |err| {
            return if (err == error.WouldBlock) {} else err;
        };
        if (nr == 0) return error.ConnectionReset;
        tls_body_pos.* += nr;

        if (tls_body_pos.* < tls_body_len.*) return; // need more body bytes

        // Full record body received — check record type
        if (tls_hdr_buf[0] == constants.tls_record_change_cipher) {
            // CCS record fully read — discard body and reset for next record
            tls_hdr_pos.* = 0;
            tls_body_pos.* = 0;
            tls_body_len.* = 0;
            continue;
        }

        // Application Data record — decrypt, re-encrypt, forward
        const payload = tls_body_buf[0..tls_body_len.*];

        // AES-CTR decrypt (client obfuscation layer)
        client_decryptor.apply(payload);

        // AES-CTR encrypt for DC
        tg_encryptor.apply(payload);

        // Send to DC
        try writeAll(dc, payload);

        // Reset for next TLS record
        tls_hdr_pos.* = 0;
        tls_body_pos.* = 0;
        tls_body_len.* = 0;
        return; // processed one record, return to poll
    }
}

/// S2C direction: Read from DC, AES-CTR decrypt DC, AES-CTR encrypt for client, wrap in TLS, send.
/// Uses DRS (Dynamic Record Sizing) to mimic real browser TLS behavior.
fn relayDcToClient(
    dc: net.Stream,
    client: net.Stream,
    tg_decryptor: *crypto.AesCtr,
    client_encryptor: *crypto.AesCtr,
    dc_read_buf: *[constants.default_buffer_size]u8,
    drs: *DynamicRecordSizer,
) !void {
    const nr = dc.read(dc_read_buf) catch |err| {
        return if (err == error.WouldBlock) {} else err;
    };
    if (nr == 0) return error.ConnectionReset;

    const data = dc_read_buf[0..nr];

    // AES-CTR decrypt DC obfuscation
    tg_decryptor.apply(data);

    // AES-CTR encrypt for client obfuscation
    client_encryptor.apply(data);

    // Wrap in TLS Application Data record(s) using DRS-controlled sizes
    var offset: usize = 0;
    while (offset < data.len) {
        const max_chunk = drs.nextRecordSize();
        const chunk_len = @min(data.len - offset, max_chunk);

        // Build TLS record header
        var hdr: [tls_header_len]u8 = undefined;
        hdr[0] = constants.tls_record_application;
        hdr[1] = constants.tls_version[0];
        hdr[2] = constants.tls_version[1];
        std.mem.writeInt(u16, hdr[3..5], @intCast(chunk_len), .big);

        try writeAll(client, &hdr);
        try writeAll(client, data[offset..][0..chunk_len]);

        drs.recordSent(chunk_len);
        offset += chunk_len;
    }
}

/// Write all bytes to a stream, handling partial writes and backpressure.
/// On non-blocking sockets, waits for POLLOUT when the send buffer is full.
fn writeAll(stream: net.Stream, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) {
        const nw = stream.write(data[written..]) catch |err| {
            if (err == error.WouldBlock) {
                // Wait for the socket to become writable
                var fds = [1]posix.pollfd{
                    .{ .fd = stream.handle, .events = posix.POLL.OUT, .revents = 0 },
                };
                const ready = try posix.poll(&fds, relay_timeout_ms);
                if (ready == 0) return error.ConnectionReset; // write timeout
                if (fds[0].revents & (posix.POLL.ERR | posix.POLL.HUP) != 0)
                    return error.ConnectionReset;
                continue;
            }
            return err;
        };
        if (nw == 0) return error.ConnectionReset;
        written += nw;
    }
}

/// Read exactly `buf.len` bytes, returning how many were read.
fn readExact(stream: net.Stream, buf: []u8) !usize {
    var total: usize = 0;
    while (total < buf.len) {
        const nr = stream.read(buf[total..]) catch |err| {
            if (total > 0) return total;
            return err;
        };
        if (nr == 0) return total;
        total += nr;
    }
    return total;
}

/// Set a file descriptor to non-blocking mode.
fn setNonBlocking(fd: posix.fd_t) void {
    var fl_flags = posix.fcntl(fd, posix.F.GETFL, 0) catch return;
    const nonblock: @TypeOf(fl_flags) = @bitCast(@as(u64, @as(u32, @bitCast(posix.O{ .NONBLOCK = true }))));
    fl_flags |= nonblock;
    _ = posix.fcntl(fd, posix.F.SETFL, fl_flags) catch return;
}

/// Set SO_RCVTIMEO on a socket to limit blocking reads (anti-Slowloris).
fn setRecvTimeout(fd: posix.fd_t, timeout_sec: u32) void {
    const tv = posix.timeval{ .sec = @intCast(timeout_sec), .usec = 0 };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch return;
}

test "ProxyState init/deinit" {
    const allocator = std.testing.allocator;
    var users = std.StringHashMap([16]u8).init(allocator);
    const name = try allocator.dupe(u8, "test");
    try users.put(name, [_]u8{0} ** 16);

    var cfg = Config{
        .users = users,
    };

    var state = ProxyState.init(allocator, cfg);
    defer {
        state.deinit();
        cfg.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), state.user_secrets.len);
}

test "DRS starts small and ramps up" {
    var drs = DynamicRecordSizer.init();

    // Initially should use small records
    try std.testing.expectEqual(DynamicRecordSizer.initial_size, drs.nextRecordSize());

    // Send a few records — should stay small
    for (0..DynamicRecordSizer.ramp_record_threshold - 1) |_| {
        drs.recordSent(1369);
    }
    try std.testing.expectEqual(DynamicRecordSizer.initial_size, drs.nextRecordSize());

    // One more should trigger ramp-up
    drs.recordSent(1369);
    try std.testing.expectEqual(DynamicRecordSizer.full_size, drs.nextRecordSize());
}

test "DRS ramps up by byte threshold" {
    var drs = DynamicRecordSizer.init();

    // Send fewer records but enough bytes to trigger ramp
    drs.recordSent(DynamicRecordSizer.ramp_byte_threshold);
    try std.testing.expectEqual(DynamicRecordSizer.full_size, drs.nextRecordSize());
}
