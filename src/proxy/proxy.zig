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
/// Maximum connection lifetime (30 minutes). Hard cap to prevent thread
/// accumulation from long-lived connections or half-open sockets that
/// somehow survive keepalive probes.
const max_connection_lifetime_ms: i64 = 30 * 60 * 1000;
/// Send timeout (seconds). Prevents writeAll from hanging indefinitely
/// on a dead peer whose kernel buffer isn't full.
const send_timeout_sec: u32 = 30;

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
    /// COMPATIBILITY: Fixed at initial_size (1369) for iOS compatibility testing.
    /// Large records (16384) may cause issues with some clients.
    fn nextRecordSize(self: *DynamicRecordSizer) usize {
        _ = self;
        return initial_size;
    }

    /// Report that a record was sent. Ramp-up disabled for compatibility testing.
    fn recordSent(self: *DynamicRecordSizer, payload_len: usize) void {
        _ = self;
        _ = payload_len;
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
    /// Active concurrent connections (for overload protection)
    active_connections: std.atomic.Value(u32),

    /// Maximum concurrent connections before rejecting new ones.
    /// Prevents thread exhaustion under load.
    const max_connections: u32 = 8192;

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
            .active_connections = std.atomic.Value(u32).init(0),
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

            // Overload protection: reject if too many concurrent connections
            const active = self.active_connections.load(.monotonic);
            if (active >= max_connections) {
                log.warn("[{d}] Connection rejected: at capacity ({d}/{d})", .{ conn_id, active, max_connections });
                conn.stream.close();
                continue;
            }

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

    // Track active connections for overload protection
    _ = state.active_connections.fetchAdd(1, .monotonic);
    defer _ = state.active_connections.fetchSub(1, .monotonic);

    // Format peer IP for logging
    var addr_buf: [64]u8 = undefined;
    const peer_str = formatAddress(peer_addr, &addr_buf);

    handleConnectionInner(state, client_stream, peer_str, conn_id) catch |err| {
        // Idle pool closure is normal — mobile clients pre-warm connections
        // that may never send data. Don't pollute logs.
        if (err == error.IdleConnectionClosed) {
            log.debug("[{d}] ({s}) Closed idle pooled connection", .{ conn_id, peer_str });
            return;
        }
        // WouldBlock during handshake = Slowloris or extreme lag
        if (err == error.WouldBlock) {
            log.warn("[{d}] ({s}) Handshake timeout (Slowloris/lag)", .{ conn_id, peer_str });
            return;
        }
        log.err("[{d}] ({s}) Connection error: {any}", .{ conn_id, peer_str, err });
    };
}

fn handleConnectionInner(
    state: *ProxyState,
    client_stream: net.Stream,
    peer_str: []const u8,
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

    // Stage 2: data is coming — apply generous handshake timeout.
    // DON'T use the tight 10s timeout yet — iOS Telegram may delay the
    // MTProto handshake after ServerHello (pool warming, timing differences).
    // Tight timeout is applied after the full 64-byte handshake is assembled.
    const handshake_timeout_sec: u32 = 60;
    setRecvTimeout(fd, handshake_timeout_sec);

    // Read first 5 bytes to determine TLS vs direct
    var first_bytes: [5]u8 = undefined;
    const n = try readExact(client_stream, &first_bytes);
    if (n < 5) {
        log.debug("[{d}] ({s}) Short read on first 5 bytes (got {d}), dropping.", .{ conn_id, peer_str, n });
        return;
    }

    if (!tls.isTlsHandshake(&first_bytes)) {
        log.debug("[{d}] ({s}) Non-TLS connection, dropping. First bytes: {x:0>2}", .{ conn_id, peer_str, first_bytes });
        maskConnection(state, client_stream, peer_str, conn_id, &first_bytes, null);
        return;
    }

    // TLS path: read full ClientHello
    const record_len = std.mem.readInt(u16, first_bytes[3..5], .big);
    if (record_len < constants.min_tls_client_hello_size or record_len > constants.max_tls_plaintext_size) {
        log.debug("[{d}] ({s}) Invalid ClientHello size: {d}, dropping.", .{ conn_id, peer_str, record_len });
        maskConnection(state, client_stream, peer_str, conn_id, &first_bytes, null);
        return;
    }

    var client_hello_buf: [5 + constants.max_tls_plaintext_size]u8 = undefined;
    @memcpy(client_hello_buf[0..5], &first_bytes);
    const body_n = try readExact(client_stream, client_hello_buf[5..][0..record_len]);
    if (body_n < record_len) {
        log.debug("[{d}] ({s}) Short read on ClientHello body (got {d}, expected {d}), dropping.", .{ conn_id, peer_str, body_n, record_len });
        maskConnection(state, client_stream, peer_str, conn_id, client_hello_buf[0 .. 5 + body_n], null);
        return;
    }

    const client_hello = client_hello_buf[0 .. 5 + record_len];

    // Validate TLS handshake against secrets
    const validation = try tls.validateTlsHandshake(
        state.allocator,
        client_hello,
        state.user_secrets,
        false,
    );

    if (validation == null) {
        log.debug("[{d}] ({s}) TLS auth failed", .{ conn_id, peer_str });
        maskConnection(state, client_stream, peer_str, conn_id, client_hello, null);
        return;
    }

    const v = validation.?;
    log.info("[{d}] ({s}) TLS auth OK: user={s}", .{ conn_id, peer_str, v.user });

    // Send ServerHello response
    const server_hello = try tls.buildServerHello(
        state.allocator,
        &v.secret,
        &v.digest,
        v.session_id,
    );
    defer state.allocator.free(server_hello);

    try writeAll(client_stream, server_hello);

    // Assemble the 64-byte MTProto handshake from potentially multiple TLS AppData records.
    // iOS Telegram may split the handshake across records or interleave CCS records.
    // Desktop typically sends all 64 bytes in one AppData record, but we must not assume that.
    var handshake_assembly: [constants.handshake_len]u8 = undefined;
    var hs_pos: usize = 0;
    var pipelined_buf: [constants.max_tls_ciphertext_size]u8 = undefined;
    var pipelined_len: usize = 0;
    var app_records_used: u8 = 0;

    while (hs_pos < constants.handshake_len) {
        var tls_header: [5]u8 = undefined;
        if (try readExact(client_stream, &tls_header) < 5) {
            log.debug("[{d}] ({s}) Short read waiting for AppData header during handshake, dropping.", .{ conn_id, peer_str });
            return;
        }

        const record_type = tls_header[0];
        const body_len = std.mem.readInt(u16, tls_header[3..5], .big);

        switch (record_type) {
            constants.tls_record_change_cipher => {
                // Read and discard CCS body
                if (body_len > 256) return;
                var ccs_buf: [256]u8 = undefined;
                if (try readExact(client_stream, ccs_buf[0..body_len]) < body_len) {
                    log.debug("[{d}] ({s}) Short read on CCS body, dropping.", .{ conn_id, peer_str });
                    return;
                }
            },
            constants.tls_record_application => {
                if (body_len == 0 or body_len > constants.max_tls_ciphertext_size) return;
                var body_buf: [constants.max_tls_ciphertext_size]u8 = undefined;
                if (try readExact(client_stream, body_buf[0..body_len]) < body_len) {
                    log.debug("[{d}] ({s}) Short read on AppData body, dropping.", .{ conn_id, peer_str });
                    return;
                }

                app_records_used += 1;

                const need = constants.handshake_len - hs_pos;
                const take = @min(need, body_len);

                @memcpy(handshake_assembly[hs_pos..][0..take], body_buf[0..take]);
                hs_pos += take;

                // Any extra bytes beyond the 64-byte handshake are pipelined data
                if (body_len > take) {
                    const extra = body_len - take;
                    @memcpy(pipelined_buf[0..extra], body_buf[take..][0..extra]);
                    pipelined_len = extra;
                }
            },
            constants.tls_record_alert => {
                // Log alert details before bailing — helps diagnose iOS rejections
                if (body_len >= 2 and body_len <= 256) {
                    var alert_buf: [256]u8 = undefined;
                    if (try readExact(client_stream, alert_buf[0..body_len]) >= 2) {
                        log.info("[{d}] ({s}) TLS Alert during handshake: level={d} desc={d}", .{
                            conn_id, peer_str, alert_buf[0], alert_buf[1],
                        });
                    }
                }
                return;
            },
            else => {
                log.debug("[{d}] ({s}) Unexpected TLS record type after ServerHello: 0x{x:0>2}", .{ conn_id, peer_str, record_type });
                return;
            },
        }
    }

    log.debug("[{d}] ({s}) MTProto handshake assembled from {d} AppData record(s), pipelined={d}B", .{
        conn_id, peer_str, app_records_used, pipelined_len,
    });

    const handshake: *const [constants.handshake_len]u8 = &handshake_assembly;

    // Parse obfuscation params
    const result = obfuscation.ObfuscationParams.fromHandshake(handshake, state.user_secrets) orelse {
        log.debug("[{d}] ({s}) MTProto handshake failed for user {s}", .{ conn_id, peer_str, v.user });
        return;
    };

    var params = result.params;
    defer params.wipe();

    log.debug("[{d}] ({s}) MTProto OK: user={s} dc={d} proto={any}", .{
        conn_id,
        peer_str,
        result.user,
        params.dc_idx,
        params.proto_tag,
    });

    // Diagnostic: log client cipher details
    log.debug("[{d}] ({s}) Client dec_iv=0x{x:0>32} enc_iv=0x{x:0>32}", .{
        conn_id,                      peer_str,
        @as(u128, params.decrypt_iv), @as(u128, params.encrypt_iv),
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
    log.debug("[{d}] ({s}) Connecting to DC {d}", .{ conn_id, peer_str, params.dc_idx });

    const dc_stream = net.tcpConnectToAddress(dc_addr) catch |err| {
        log.err("[{d}] ({s}) DC connect failed: {any}", .{ conn_id, peer_str, err });
        return;
    };
    defer dc_stream.close();

    // Generate and send obfuscated handshake to Telegram DC
    var tg_nonce = obfuscation.generateNonce();
    
    // In FAST_MODE, embed the client's S2C key/IV into the DC nonce so the DC
    // derives direct-to-client encryption parameters, bypassing proxy S2C crypto.
    if (state.config.fast_mode) {
        var client_s2c_key_iv: [constants.key_len + constants.iv_len]u8 = undefined;
        @memcpy(client_s2c_key_iv[0..constants.key_len], &params.encrypt_key);
        std.mem.writeInt(u128, client_s2c_key_iv[constants.key_len..][0..constants.iv_len], params.encrypt_iv, .big);
        obfuscation.prepareTgNonce(&tg_nonce, params.proto_tag, &client_s2c_key_iv);
    } else {
        obfuscation.prepareTgNonce(&tg_nonce, params.proto_tag, null);
    }
    
    // DC index must be set explicitly after prepareTgNonce
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

    try writeAll(dc_stream, &nonce_to_send);
    // tg_encryptor counter is now at position 4 (past 64 bytes), correct for subsequent data

    var tg_decryptor = crypto.AesCtr.init(&tg_dec_key, tg_dec_iv);
    defer tg_decryptor.wipe();

    // Wipe key material from stack
    @memset(&tg_enc_key, 0);
    @memset(&tg_enc_iv_bytes, 0);
    @memset(&tg_dec_key, 0);
    @memset(&tg_dec_key_iv, 0);

    log.info("[{d}] ({s}) Relaying traffic", .{ conn_id, peer_str });

    // Configure both sockets for robust relay:
    // - TCP keepalive: detect dead peers (half-open connections) within ~90s
    // - SO_SNDTIMEO: prevent writeAll from hanging on dead peers
    // - Non-blocking: prevent deadlocks with poll()
    configureRelaySocket(client_stream.handle);
    configureRelaySocket(dc_stream.handle);
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

    // Fix #3: Handle pipelined data — Telegram clients may send their first RPC request
    // immediately after the 64-byte handshake in the same TLS record. If we don't
    // forward these bytes, the client's first message is silently lost.
    var initial_c2s_bytes: u64 = 0;

    if (pipelined_len > 0) {
        const pipelined = pipelined_buf[0..pipelined_len];
        log.debug("[{d}] ({s}) Pipelined {d}B after handshake", .{ conn_id, peer_str, pipelined.len });
        // Decrypt with client cipher, re-encrypt with DC cipher
        client_decryptor.apply(pipelined);
        tg_encryptor.apply(pipelined);
        try writeAll(dc_stream, pipelined);
        initial_c2s_bytes = pipelined.len;
    }

    relayBidirectional(
        client_stream,
        dc_stream,
        &client_decryptor,
        &client_encryptor,
        &tg_encryptor,
        &tg_decryptor,
        initial_c2s_bytes,
        conn_id,
        state.config.fast_mode,
    ) catch |err| {
        log.debug("[{d}] ({s}) Relay ended: {any}", .{ conn_id, peer_str, err });
    };
}

/// Relay progress tracking: distinguishes between no data available,
/// partial TLS record assembly, and fully forwarded payloads.
const RelayProgress = enum {
    /// No data was read (WouldBlock on first read)
    none,
    /// Some bytes were consumed but a full record hasn't been forwarded yet
    partial,
    /// At least one complete record was forwarded
    forwarded,
};

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
    initial_c2s_bytes: u64,
    conn_id: u64,
    fast_mode: bool,
) !void {
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

    // Byte counters for diagnostics
    var c2s_bytes: u64 = initial_c2s_bytes;
    var s2c_bytes: u64 = 0;
    var poll_iterations: u64 = 0;
    var no_progress_polls: u32 = 0;

    // Connection lifetime tracking — hard cap to prevent thread accumulation.
    // Even with TCP keepalive, a legitimate but rarely-active connection could
    // keep a thread alive indefinitely. Cap at 30 minutes.
    const start_ts = std.time.milliTimestamp();

    while (true) {
        fds[0].revents = 0;
        fds[1].revents = 0;

        const ready = try posix.poll(&fds, relay_timeout_ms);
        if (ready == 0) {
            log.debug("[{d}] Relay: idle timeout (no data for 5 min), c2s={d} s2c={d}", .{ conn_id, c2s_bytes, s2c_bytes });
            return error.ConnectionReset;
        }

        poll_iterations += 1;

        // Hard lifetime cap: force-close connections older than max_connection_lifetime_ms.
        // Prevents thread accumulation from long-lived or stuck connections.
        const elapsed = std.time.milliTimestamp() - start_ts;
        if (elapsed > max_connection_lifetime_ms) {
            log.info("[{d}] Relay: max lifetime reached ({d}ms), c2s={d} s2c={d}", .{
                conn_id, elapsed, c2s_bytes, s2c_bytes,
            });
            return error.ConnectionReset;
        }

        var progressed = false;

        const client_revents = fds[0].revents;
        const dc_revents = fds[1].revents;

        // IMPORTANT: drain readable data first. POLLIN|POLLHUP is common on Linux
        // when the peer has sent final bytes and then closed.
        if ((client_revents & posix.POLL.IN) != 0) {
            const step = relayClientToDc(
                client,
                dc,
                client_decryptor,
                tg_encryptor,
                &tls_hdr_buf,
                &tls_hdr_pos,
                &tls_body_buf,
                &tls_body_pos,
                &tls_body_len,
                &c2s_bytes,
                conn_id,
            ) catch |err| {
                log.debug("[{d}] Relay: C2S error: {any}, polls={d} c2s={d} s2c={d}", .{ conn_id, err, poll_iterations, c2s_bytes, s2c_bytes });
                return err;
            };
            if (step != .none) progressed = true;
        }

        if ((dc_revents & posix.POLL.IN) != 0) {
            const step = relayDcToClient(
                dc,
                client,
                if (fast_mode) null else tg_decryptor,
                if (fast_mode) null else client_encryptor,
                &dc_read_buf,
                &drs,
                &s2c_bytes,
            ) catch |err| {
                log.debug("[{d}] Relay: S2C error: {any}, polls={d} c2s={d} s2c={d}", .{ conn_id, err, poll_iterations, c2s_bytes, s2c_bytes });
                return err;
            };
            if (step != .none) progressed = true;
        }

        // Hard errors after draining readable data
        if ((client_revents & (posix.POLL.ERR | posix.POLL.NVAL)) != 0) {
            log.debug("[{d}] Relay: client ERR/NVAL (revents=0x{x}), polls={d} c2s={d} s2c={d}", .{
                conn_id, client_revents, poll_iterations, c2s_bytes, s2c_bytes,
            });
            return error.ConnectionReset;
        }
        if ((dc_revents & (posix.POLL.ERR | posix.POLL.NVAL)) != 0) {
            log.debug("[{d}] Relay: DC ERR/NVAL (revents=0x{x}), polls={d} c2s={d} s2c={d}", .{
                conn_id, dc_revents, poll_iterations, c2s_bytes, s2c_bytes,
            });
            return error.ConnectionReset;
        }

        // If HUP arrived without readable data, close immediately.
        // If it arrived with POLLIN, we already drained what we could above.
        if (((client_revents & posix.POLL.HUP) != 0) and ((client_revents & posix.POLL.IN) == 0)) {
            log.debug("[{d}] Relay: client HUP, polls={d} c2s={d} s2c={d}", .{
                conn_id, poll_iterations, c2s_bytes, s2c_bytes,
            });
            return error.ConnectionReset;
        }
        if (((dc_revents & posix.POLL.HUP) != 0) and ((dc_revents & posix.POLL.IN) == 0)) {
            log.debug("[{d}] Relay: DC HUP, polls={d} c2s={d} s2c={d}", .{
                conn_id, poll_iterations, c2s_bytes, s2c_bytes,
            });
            return error.ConnectionReset;
        }

        // Spin detection: track progress including partial TLS record assembly.
        // Old approach only checked byte counters, missing partial reads that
        // represent real forward progress.
        if (!progressed) {
            no_progress_polls += 1;
            if (no_progress_polls >= 32) {
                log.warn("[{d}] Relay: no-progress poll loop, client_revents=0x{x} dc_revents=0x{x} hdr={d} body_pos={d} body_len={d} c2s={d} s2c={d}", .{
                    conn_id,
                    client_revents,
                    dc_revents,
                    tls_hdr_pos,
                    tls_body_pos,
                    tls_body_len,
                    c2s_bytes,
                    s2c_bytes,
                });
                return error.ConnectionReset;
            }
        } else {
            no_progress_polls = 0;
        }
    }
}

/// C2S direction: Read TLS records from client, unwrap, AES-CTR decrypt, re-encrypt for DC, send.
///
/// Uses incremental state so partial reads across poll iterations are handled correctly.
/// Both CCS and Application Data records share the same body buffer to survive WouldBlock.
/// Returns progress indicator for spin detection in the relay loop.
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
    bytes_counter: *u64,
    conn_id: u64,
) !RelayProgress {
    var consumed_any = false;

    // Read as much as possible in this call
    while (true) {
        if (tls_hdr_pos.* < tls_header_len) {
            // Still reading TLS header
            const nr = client.read(tls_hdr_buf[tls_hdr_pos.*..]) catch |err| {
                if (err == error.WouldBlock) {
                    return if (consumed_any) .partial else .none;
                }
                return err;
            };
            if (nr == 0) return error.ConnectionReset;

            consumed_any = true;
            tls_hdr_pos.* += nr;

            if (tls_hdr_pos.* < tls_header_len) return .partial; // need more header bytes

            // Parse TLS record header
            const record_type = tls_hdr_buf[0];

            if (record_type == constants.tls_record_alert) {
                // Try to read alert body for diagnostic logging (best-effort, non-blocking)
                const alert_body_len = std.mem.readInt(u16, tls_hdr_buf[3..5], .big);
                if (alert_body_len >= 2 and alert_body_len <= 256) {
                    var alert_buf: [256]u8 = undefined;
                    const ar = client.read(alert_buf[0..alert_body_len]) catch 0;
                    if (ar >= 2) {
                        log.info("[{d}] C2S TLS Alert: level={d} desc={d}", .{ conn_id, alert_buf[0], alert_buf[1] });
                    }
                }
                return error.ConnectionReset;
            }

            switch (record_type) {
                constants.tls_record_change_cipher, constants.tls_record_application => {
                    tls_body_len.* = std.mem.readInt(u16, tls_hdr_buf[3..5], .big);
                    if (tls_body_len.* == 0 or tls_body_len.* > max_tls_payload) {
                        return error.ConnectionReset;
                    }
                    tls_body_pos.* = 0;
                },
                else => return error.ConnectionReset,
            }
        }

        // Reading TLS record body (shared path for CCS and Application Data)
        const remaining = tls_body_len.* - tls_body_pos.*;
        if (remaining == 0) {
            // Record complete, reset for next
            tls_hdr_pos.* = 0;
            tls_body_pos.* = 0;
            tls_body_len.* = 0;
            if (consumed_any) return .partial;
            continue;
        }

        const nr = client.read(tls_body_buf[tls_body_pos.*..][0..remaining]) catch |err| {
            if (err == error.WouldBlock) {
                return if (consumed_any) .partial else .none;
            }
            return err;
        };
        if (nr == 0) return error.ConnectionReset;

        consumed_any = true;
        tls_body_pos.* += nr;

        if (tls_body_pos.* < tls_body_len.*) return .partial; // need more body bytes

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
        bytes_counter.* += payload.len;

        // Reset for next TLS record
        tls_hdr_pos.* = 0;
        tls_body_pos.* = 0;
        tls_body_len.* = 0;
        return .forwarded; // processed one record, return to poll
    }
}

/// S2C direction: Read from DC, AES-CTR decrypt DC, AES-CTR encrypt for client, wrap in TLS, send.
/// Uses DRS (Dynamic Record Sizing) to mimic real browser TLS behavior.
/// Returns progress indicator for spin detection in the relay loop.
fn relayDcToClient(
    dc: net.Stream,
    client: net.Stream,
    tg_decryptor: ?*crypto.AesCtr,
    client_encryptor: ?*crypto.AesCtr,
    dc_read_buf: *[constants.default_buffer_size]u8,
    drs: *DynamicRecordSizer,
    bytes_counter: *u64,
) !RelayProgress {
    const nr = dc.read(dc_read_buf) catch |err| {
        if (err == error.WouldBlock) return .none;
        return err;
    };
    if (nr == 0) return error.ConnectionReset;

    const data = dc_read_buf[0..nr];

    // In fast mode, the DC encrypts directly for the client, so we skip these
    if (tg_decryptor) |dec| dec.apply(data);

    // AES-CTR encrypt for client obfuscation
    if (client_encryptor) |enc| enc.apply(data);

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

    bytes_counter.* += nr;
    return .forwarded;
}

/// Write all bytes to a stream, handling partial writes and backpressure.
/// On non-blocking sockets, waits for POLLOUT when the send buffer is full.
/// Includes a spin counter to prevent infinite WouldBlock loops on broken sockets.
fn writeAll(stream: net.Stream, data: []const u8) !void {
    var written: usize = 0;
    var wouldblock_spins: u8 = 0;

    while (written < data.len) {
        const nw = stream.write(data[written..]) catch |err| {
            if (err == error.WouldBlock) {
                wouldblock_spins += 1;
                if (wouldblock_spins >= 32) return error.ConnectionReset;

                // Wait for the socket to become writable
                var fds = [1]posix.pollfd{
                    .{ .fd = stream.handle, .events = posix.POLL.OUT, .revents = 0 },
                };
                const ready = try posix.poll(&fds, relay_timeout_ms);
                if (ready == 0) return error.ConnectionReset; // write timeout
                if ((fds[0].revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL)) != 0)
                    return error.ConnectionReset;
                if ((fds[0].revents & posix.POLL.OUT) == 0) continue;
                continue;
            }
            return err;
        };
        if (nw == 0) return error.ConnectionReset;
        wouldblock_spins = 0;
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

/// Format a network address as "ip:port" for logging.
fn formatAddress(addr: net.Address, buf: *[64]u8) []const u8 {
    switch (addr.any.family) {
        posix.AF.INET => {
            const bytes: *const [4]u8 = @ptrCast(&addr.in.sa.addr);
            return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{
                bytes[0],                                  bytes[1], bytes[2], bytes[3],
                std.mem.bigToNative(u16, addr.in.sa.port),
            }) catch "?";
        },
        posix.AF.INET6 => {
            return std.fmt.bufPrint(buf, "[ipv6]:{d}", .{
                std.mem.bigToNative(u16, addr.in6.sa.port),
            }) catch "?";
        },
        else => return "?",
    }
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

/// Set SO_SNDTIMEO on a socket to prevent write hangs on dead peers.
fn setSendTimeout(fd: posix.fd_t, timeout_sec: u32) void {
    const tv = posix.timeval{ .sec = @intCast(timeout_sec), .usec = 0 };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch return;
}

/// Enable TCP keepalive to detect dead peers (half-open connections).
/// Without this, a peer that disappears without sending FIN leaves our
/// thread stuck in poll() for up to relay_timeout_ms (5 minutes). With
/// keepalive, the OS probes the connection and delivers an error within
/// ~90 seconds (60s idle + 3 probes * 10s interval).
fn setTcpKeepalive(fd: posix.fd_t) void {
    // SOL.TCP = 6 (IPPROTO_TCP), not in posix.SOL — use raw value
    const sol_tcp: i32 = 6;

    // Enable SO_KEEPALIVE at the socket level
    const enable: c_int = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&enable)) catch return;

    // Start probing after 60 seconds idle
    const idle: c_int = 60;
    posix.setsockopt(fd, sol_tcp, 4, std.mem.asBytes(&idle)) catch return; // TCP_KEEPIDLE

    // Probe every 10 seconds
    const interval: c_int = 10;
    posix.setsockopt(fd, sol_tcp, 5, std.mem.asBytes(&interval)) catch return; // TCP_KEEPINTVL

    // 3 failed probes = connection dead
    const count: c_int = 3;
    posix.setsockopt(fd, sol_tcp, 6, std.mem.asBytes(&count)) catch return; // TCP_KEEPCNT
}

/// Configure a relay socket with keepalive + send timeout.
/// Applied to both client and DC sockets before entering the relay loop.
fn configureRelaySocket(fd: posix.fd_t) void {
    setTcpKeepalive(fd);
    setSendTimeout(fd, send_timeout_sec);
}

fn maskConnection(
    state: *ProxyState,
    client_stream: net.Stream,
    peer_str: []const u8,
    conn_id: u64,
    buffered_data1: []const u8,
    buffered_data2: ?[]const u8,
) void {
    if (!state.config.mask) return;

    // Connect to the real domain on port 443
    const upstream_stream = std.net.tcpConnectToHost(state.allocator, state.config.tls_domain, 443) catch {
        log.debug("[{d}] ({s}) Masking failed: cannot connect to {s}:443", .{ conn_id, peer_str, state.config.tls_domain });
        return;
    };
    defer upstream_stream.close();

    // Write any already read bytes to the upstream server
    if (buffered_data1.len > 0) {
        writeAll(upstream_stream, buffered_data1) catch return;
    }
    if (buffered_data2) |buf2| {
        if (buf2.len > 0) {
            writeAll(upstream_stream, buf2) catch return;
        }
    }

    log.debug("[{d}] ({s}) Masking active: forwarding to {s}:443", .{ conn_id, peer_str, state.config.tls_domain });

    // Bidirectional raw relay
    relayRaw(client_stream, upstream_stream, peer_str, conn_id) catch |err| {
        log.debug("[{d}] ({s}) Masking relay ended: {any}", .{ conn_id, peer_str, err });
    };
}

fn relayRaw(client: net.Stream, upstream: net.Stream, peer_str: []const u8, conn_id: u64) !void {
    _ = peer_str;
    _ = conn_id;
    var fds = [2]posix.pollfd{
        .{ .fd = client.handle, .events = posix.POLL.IN, .revents = 0 },
        .{ .fd = upstream.handle, .events = posix.POLL.IN, .revents = 0 },
    };

    var buf: [constants.default_buffer_size]u8 = undefined;

    while (true) {
        fds[0].events = posix.POLL.IN;
        fds[1].events = posix.POLL.IN;
        fds[0].revents = 0;
        fds[1].revents = 0;

        const ready = try posix.poll(&fds, 30_000); // 30s timeout
        if (ready == 0) return error.ConnectionReset;

        if (fds[0].revents & posix.POLL.IN != 0) {
            const n = try client.read(&buf);
            if (n == 0) return;
            try writeAll(upstream, buf[0..n]);
        }
        if (fds[1].revents & posix.POLL.IN != 0) {
            const n = try upstream.read(&buf);
            if (n == 0) return;
            try writeAll(client, buf[0..n]);
        }

        if (fds[0].revents & posix.POLL.HUP != 0 or fds[0].revents & posix.POLL.ERR != 0) return error.ConnectionReset;
        if (fds[1].revents & posix.POLL.HUP != 0 or fds[1].revents & posix.POLL.ERR != 0) return error.ConnectionReset;
    }
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

test "DRS always returns fixed size (compatibility mode)" {
    var drs = DynamicRecordSizer.init();

    // Should always use small records (compatibility mode)
    try std.testing.expectEqual(DynamicRecordSizer.initial_size, drs.nextRecordSize());

    // After many records, still small
    for (0..100) |_| {
        drs.recordSent(1369);
    }
    try std.testing.expectEqual(DynamicRecordSizer.initial_size, drs.nextRecordSize());
}
