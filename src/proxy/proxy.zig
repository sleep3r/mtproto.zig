//! Proxy core — single-threaded Linux epoll event loop.
//!
//! This replaces the thread-per-connection model with a pre-allocated
//! connection pool and non-blocking state machine.

const std = @import("std");
const builtin = @import("builtin");
const net = std.net;
const posix = std.posix;
const linux = std.os.linux;

const constants = @import("../protocol/constants.zig");
const crypto = @import("../crypto/crypto.zig");
const obfuscation = @import("../protocol/obfuscation.zig");
const middleproxy = @import("../protocol/middleproxy.zig");
const tls = @import("../protocol/tls.zig");
const Config = @import("../config.zig").Config;

const log = std.log.scoped(.proxy);

const tls_header_len = 5;
const event_loop_wait_ms = 37;
const accept_backoff_ms: i64 = 500;
const accept_backoff_ns: i128 = @as(i128, accept_backoff_ms) * std.time.ns_per_ms;
const stats_log_interval_s: i64 = 10;
const stats_log_interval_ns: i128 = @as(i128, stats_log_interval_s) * std.time.ns_per_s;
const nofile_fd_overhead: usize = 512;
const middle_proxy_config_url = "https://core.telegram.org/getProxyConfig";
const middle_proxy_secret_url = "https://core.telegram.org/getProxySecret";
const middle_proxy_update_period_ns: u64 = 24 * 60 * 60 * std.time.ns_per_s;
const min_nofile_soft: usize = 65535;
const client_hello_inline_size: usize = 512;
const mp_handshake_frame_buf_size: usize = 2048;
const read_buf_size: usize = 4096;

const MsgBlockClass = enum(u2) {
    tiny = 0,
    small = 1,
    standard = 2,
};

const MsgBlock = struct {
    class: MsgBlockClass,
    len: usize,
    data: [standard_block_size]u8,
};

const tiny_block_size: usize = 64;
const small_block_size: usize = 512;
const standard_block_size: usize = 2048;
const max_scatter_parts: usize = 64;

fn hasFatalEpollHangup(events: u32) bool {
    return (events & (linux.EPOLL.ERR | linux.EPOLL.HUP | linux.EPOLL.RDHUP)) != 0;
}

fn classCapacity(class: MsgBlockClass) usize {
    return switch (class) {
        .tiny => tiny_block_size,
        .small => small_block_size,
        .standard => standard_block_size,
    };
}

fn chooseClass(size: usize) MsgBlockClass {
    if (size <= tiny_block_size) return .tiny;
    if (size <= small_block_size) return .small;
    return .standard;
}

const MessageQueue = struct {
    allocator: std.mem.Allocator,
    tiny_free: std.ArrayListUnmanaged(*MsgBlock) = .{},
    small_free: std.ArrayListUnmanaged(*MsgBlock) = .{},
    std_free: std.ArrayListUnmanaged(*MsgBlock) = .{},
    blocks: std.ArrayListUnmanaged(*MsgBlock) = .{},
    head_idx: usize = 0,
    offset: usize = 0,
    total_len: usize = 0,

    fn deinit(self: *MessageQueue) void {
        self.clear();

        for (self.tiny_free.items) |blk| self.allocator.destroy(blk);
        for (self.small_free.items) |blk| self.allocator.destroy(blk);
        for (self.std_free.items) |blk| self.allocator.destroy(blk);

        self.tiny_free.deinit(self.allocator);
        self.small_free.deinit(self.allocator);
        self.std_free.deinit(self.allocator);
        self.blocks.deinit(self.allocator);
    }

    fn clear(self: *MessageQueue) void {
        for (self.blocks.items[self.head_idx..]) |blk| {
            self.recycleBlock(blk) catch {
                self.allocator.destroy(blk);
            };
        }
        self.blocks.clearRetainingCapacity();
        self.head_idx = 0;
        self.offset = 0;
        self.total_len = 0;
    }

    fn isEmpty(self: *const MessageQueue) bool {
        return self.total_len == 0;
    }

    fn appendCopy(self: *MessageQueue, data: []const u8) !void {
        if (data.len == 0) return;

        var off: usize = 0;
        while (off < data.len) {
            const rem = data.len - off;
            const class = chooseClass(rem);
            const cap = classCapacity(class);
            const take = @min(rem, cap);

            var blk = try self.acquireBlock(class);
            blk.len = take;
            @memcpy(blk.data[0..take], data[off .. off + take]);
            try self.blocks.append(self.allocator, blk);
            self.total_len += take;
            off += take;
        }
    }

    fn appendOwned(self: *MessageQueue, owned: []u8) !void {
        defer self.allocator.free(owned);
        try self.appendCopy(owned);
    }

    fn prepareIovecs(self: *const MessageQueue, out: []posix.iovec_const) usize {
        if (self.head_idx >= self.blocks.items.len) return 0;

        var count: usize = 0;
        var local_off = self.offset;
        for (self.blocks.items[self.head_idx..]) |blk| {
            if (count >= out.len) break;

            if (local_off >= blk.len) {
                local_off -= blk.len;
                continue;
            }

            out[count] = .{ .base = blk.data[local_off..blk.len].ptr, .len = blk.len - local_off };
            count += 1;
            local_off = 0;
        }
        return count;
    }

    fn consume(self: *MessageQueue, bytes: usize) !void {
        if (bytes == 0 or self.total_len == 0) return;

        var remaining = @min(bytes, self.total_len);
        self.total_len -= remaining;

        while (remaining > 0 and self.head_idx < self.blocks.items.len) {
            const blk = self.blocks.items[self.head_idx];
            const blk_left = blk.len - self.offset;

            if (remaining < blk_left) {
                self.offset += remaining;
                remaining = 0;
                break;
            }

            remaining -= blk_left;
            self.offset = 0;
            self.head_idx += 1;
            try self.recycleBlock(blk);
        }

        if (self.head_idx > 0 and (self.head_idx >= self.blocks.items.len or self.head_idx >= 64)) {
            const rem = self.blocks.items.len - self.head_idx;
            if (rem > 0) {
                std.mem.copyForwards(*MsgBlock, self.blocks.items[0..rem], self.blocks.items[self.head_idx..]);
            }
            self.blocks.shrinkRetainingCapacity(rem);
            self.head_idx = 0;
        }

        if (self.total_len == 0) {
            self.head_idx = 0;
            self.offset = 0;
        }
    }

    fn acquireBlock(self: *MessageQueue, class: MsgBlockClass) !*MsgBlock {
        const list = switch (class) {
            .tiny => &self.tiny_free,
            .small => &self.small_free,
            .standard => &self.std_free,
        };

        if (list.items.len > 0) {
            return list.pop().?;
        }

        const blk = try self.allocator.create(MsgBlock);
        blk.* = .{
            .class = class,
            .len = 0,
            .data = undefined,
        };
        return blk;
    }

    fn recycleBlock(self: *MessageQueue, blk: *MsgBlock) !void {
        blk.len = 0;
        const list = switch (blk.class) {
            .tiny => &self.tiny_free,
            .small => &self.small_free,
            .standard => &self.std_free,
        };
        try list.append(self.allocator, blk);
    }
};

const UpstreamKind = enum {
    none,
    dc,
    mask,
};

const ConnectionPhase = enum {
    idle,
    reading_tls_header,
    reading_client_hello_body,
    writing_server_hello_first,
    desync_wait,
    writing_server_hello_rest,
    reading_mtproto_tls_header,
    reading_mtproto_tls_body,
    connecting_upstream,
    writing_dc_nonce,
    middle_proxy_handshake,
    relaying,
    mask_relaying,
    closing,
};

const MiddleProxyHandshakeStep = enum {
    none,
    sending_rpc_nonce,
    waiting_rpc_nonce_response,
    sending_rpc_handshake,
    waiting_rpc_handshake_response,
    done,
};

const RelayProgress = enum {
    none,
    partial,
    forwarded,
};

const DcConnectPlan = struct {
    candidates: [16]net.Address = undefined,
    count: usize = 0,
    use_middle_proxy: bool = false,
    is_media_path: bool = false,
    direct_fallback: ?net.Address = null,
};

const DynamicRecordSizer = struct {
    current_size: usize,
    records_sent: u32,
    bytes_sent: u64,
    enabled: bool,

    const initial_size: usize = 1369;
    const full_size: usize = constants.max_tls_plaintext_size;
    const ramp_record_threshold: u32 = 8;
    const ramp_byte_threshold: u64 = 128 * 1024;

    fn init(enabled: bool) DynamicRecordSizer {
        return .{
            .current_size = initial_size,
            .records_sent = 0,
            .bytes_sent = 0,
            .enabled = enabled,
        };
    }

    fn nextRecordSize(self: *DynamicRecordSizer) usize {
        return self.current_size;
    }

    fn recordSent(self: *DynamicRecordSizer, payload_len: usize) void {
        if (!self.enabled) return;
        self.records_sent += 1;
        self.bytes_sent += @as(u64, @intCast(payload_len));
        if (self.current_size == initial_size and
            (self.records_sent >= ramp_record_threshold or self.bytes_sent >= ramp_byte_threshold))
        {
            self.current_size = full_size;
        }
    }
};

const ReplayCache = struct {
    mutex: std.Thread.Mutex = .{},
    entries: [4096][32]u8 = [_][32]u8{[_]u8{0} ** 32} ** 4096,
    idx: usize = 0,

    pub fn checkAndInsert(self: *ReplayCache, digest: *const [32]u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (&self.entries) |*cached| {
            if (std.mem.eql(u8, cached, digest)) return true;
        }

        self.entries[self.idx] = digest.*;
        self.idx = (self.idx + 1) % self.entries.len;
        return false;
    }
};

const ConnectionSlot = struct {
    index: u32 = 0,
    conn_id: u64 = 0,

    client_fd: posix.fd_t = -1,
    upstream_fd: posix.fd_t = -1,
    upstream_kind: UpstreamKind = .none,
    peer_addr: net.Address = undefined,

    phase: ConnectionPhase = .idle,
    active_reserved: bool = false,

    created_at_ms: i64 = 0,
    first_byte_at_ms: i64 = 0,
    last_activity_ms: i64 = 0,
    desync_deadline_ns: i128 = 0,

    // Initial TLS handshake reassembly
    tls_hdr_buf: [tls_header_len]u8 = undefined,
    tls_hdr_pos: u8 = 0,
    tls_body_len: u16 = 0,
    tls_body_pos: u16 = 0,
    tls_record_type: u8 = 0,

    client_hello_inline: [client_hello_inline_size]u8 = undefined,
    client_hello_heap: ?[]u8 = null,
    client_hello_len: usize = 0,

    validation_secret: [16]u8 = [_]u8{0} ** 16,
    validation_digest: [32]u8 = [_]u8{0} ** 32,
    validation_session_id: [32]u8 = [_]u8{0} ** 32,
    validation_session_id_len: u8 = 0,
    validation_user: [32]u8 = [_]u8{0} ** 32,
    validation_user_len: u8 = 0,

    server_hello: ?[]u8 = null,
    server_hello_off: usize = 0,

    // 64-byte MTProto handshake assembly from TLS appdata records
    handshake_buf: [constants.handshake_len]u8 = undefined,
    handshake_pos: u8 = 0,
    pipelined_data: ?[]u8 = null,

    // Obfuscation / relay crypto state
    obf_params: ?obfuscation.ObfuscationParams = null,
    client_encryptor: ?crypto.AesCtr = null,
    client_decryptor: ?crypto.AesCtr = null,
    tg_encryptor: ?crypto.AesCtr = null,
    tg_decryptor: ?crypto.AesCtr = null,
    middle_ctx: ?middleproxy.MiddleProxyContext = null,

    dc_idx: i16 = 0,
    dc_abs: u16 = 0,
    proto_tag: constants.ProtoTag = .intermediate,
    use_fast_mode: bool = false,
    use_middle_proxy: bool = false,
    is_media_path: bool = false,

    upstream_candidates: ?[]net.Address = null,
    upstream_candidate_next: u8 = 0,
    direct_fallback_addr: ?net.Address = null,
    direct_fallback_used: bool = false,
    current_upstream_addr: ?net.Address = null,

    // Pending initial bytes for direct DC path (promotion tag)
    dc_initial_tail: ?[]u8 = null,

    // Relay parsing state (C2S TLS records)
    relay_tls_hdr: [tls_header_len]u8 = undefined,
    relay_tls_hdr_pos: u8 = 0,
    relay_tls_body_len: u16 = 0,
    relay_tls_body_pos: u16 = 0,
    relay_record_type: u8 = 0,

    drs: DynamicRecordSizer = DynamicRecordSizer{
        .current_size = DynamicRecordSizer.initial_size,
        .records_sent = 0,
        .bytes_sent = 0,
        .enabled = false,
    },
    c2s_bytes: u64 = 0,
    s2c_bytes: u64 = 0,

    read_buf: ?[]u8 = null,

    // Non-blocking write queues (slab-like chain buffers)
    client_queue: MessageQueue = .{ .allocator = std.heap.page_allocator },
    upstream_queue: MessageQueue = .{ .allocator = std.heap.page_allocator },

    // Masking: bytes already read from client before deciding to mask
    mask_prebuffer: ?[]u8 = null,

    // Non-blocking MiddleProxy handshake state
    mp_step: MiddleProxyHandshakeStep = .none,
    mp_write_seq_no: i32 = -2,
    mp_read_seq_no: i32 = -2,
    mp_nonce: [16]u8 = [_]u8{0} ** 16,
    mp_timestamp: u32 = 0,
    mp_rpc_nonce_ans: [16]u8 = [_]u8{0} ** 16,
    mp_enc: ?crypto.AesCbc = null,
    mp_dec: ?crypto.AesCbc = null,
    mp_frame_buf: ?[]u8 = null,
    mp_frame_have: usize = 0,
    mp_frame_need: usize = 0,
    mp_frame_total_len: usize = 0,
    mp_frame_padded_len: usize = 0,
    mp_frame_encrypted: bool = false,
    mp_frame_first_decrypted: bool = false,

    // Current epoll interests
    client_interest_in: bool = false,
    client_interest_out: bool = false,
    upstream_interest_in: bool = false,
    upstream_interest_out: bool = false,

    fn hasClientPending(self: *const ConnectionSlot) bool {
        return !self.client_queue.isEmpty();
    }

    fn hasUpstreamPending(self: *const ConnectionSlot) bool {
        return !self.upstream_queue.isEmpty();
    }

    fn handshakeInProgress(self: *const ConnectionSlot) bool {
        return switch (self.phase) {
            .reading_tls_header,
            .reading_client_hello_body,
            .writing_server_hello_first,
            .desync_wait,
            .writing_server_hello_rest,
            .reading_mtproto_tls_header,
            .reading_mtproto_tls_body,
            .connecting_upstream,
            .writing_dc_nonce,
            .middle_proxy_handshake,
            => true,
            else => false,
        };
    }

    fn resetOwnedBuffers(self: *ConnectionSlot, allocator: std.mem.Allocator) void {
        self.client_queue.deinit();
        self.upstream_queue.deinit();

        if (self.client_hello_heap) |buf| allocator.free(buf);
        self.client_hello_heap = null;

        if (self.server_hello) |buf| allocator.free(buf);
        self.server_hello = null;

        if (self.pipelined_data) |buf| allocator.free(buf);
        self.pipelined_data = null;

        if (self.mask_prebuffer) |buf| allocator.free(buf);
        self.mask_prebuffer = null;

        if (self.dc_initial_tail) |buf| allocator.free(buf);
        self.dc_initial_tail = null;

        if (self.middle_ctx) |*mp| mp.deinit(allocator);
        self.middle_ctx = null;

        if (self.upstream_candidates) |buf| allocator.free(buf);
        self.upstream_candidates = null;
        self.upstream_candidate_next = 0;
        self.direct_fallback_addr = null;
        self.direct_fallback_used = false;
        self.current_upstream_addr = null;
        self.dc_abs = 0;
        self.is_media_path = false;

        if (self.read_buf) |buf| allocator.free(buf);
        self.read_buf = null;

        if (self.mp_frame_buf) |buf| allocator.free(buf);
        self.mp_frame_buf = null;

        if (self.obf_params) |*params| params.wipe();
        self.obf_params = null;

        if (self.client_encryptor) |*c| c.wipe();
        if (self.client_decryptor) |*c| c.wipe();
        if (self.tg_encryptor) |*c| c.wipe();
        if (self.tg_decryptor) |*c| c.wipe();

        self.client_encryptor = null;
        self.client_decryptor = null;
        self.tg_encryptor = null;
        self.tg_decryptor = null;
    }

    fn clientHelloBuf(self: *ConnectionSlot) []u8 {
        if (self.client_hello_heap) |buf| return buf;
        return self.client_hello_inline[0..self.client_hello_len];
    }
};

const ConnectionPool = struct {
    allocator: std.mem.Allocator,
    slots: []?*ConnectionSlot,
    free_stack: []u32,
    free_count: u32,
    allocated_hi: u32,
    fd_to_slot: std.AutoHashMapUnmanaged(posix.fd_t, u32) = .{},

    fn init(allocator: std.mem.Allocator, capacity: u32) !ConnectionPool {
        const slots = try allocator.alloc(?*ConnectionSlot, capacity);
        errdefer allocator.free(slots);

        const free_stack = try allocator.alloc(u32, capacity);
        errdefer allocator.free(free_stack);

        for (slots) |*slot| {
            slot.* = null;
        }

        var i: usize = 0;
        while (i < capacity) : (i += 1) {
            free_stack[i] = @intCast(capacity - 1 - i);
        }

        var pool = ConnectionPool{
            .allocator = allocator,
            .slots = slots,
            .free_stack = free_stack,
            .free_count = capacity,
            .allocated_hi = 0,
            .fd_to_slot = .{},
        };
        try pool.fd_to_slot.ensureTotalCapacity(allocator, @as(u32, capacity * 2));
        return pool;
    }

    fn deinit(self: *ConnectionPool) void {
        for (self.slots) |slot_opt| {
            if (slot_opt) |slot_ptr| {
                self.allocator.destroy(slot_ptr);
            }
        }
        self.fd_to_slot.deinit(self.allocator);
        self.allocator.free(self.free_stack);
        self.allocator.free(self.slots);
    }

    fn acquire(self: *ConnectionPool) ?*ConnectionSlot {
        if (self.free_count == 0) return null;
        self.free_count -= 1;
        const idx = self.free_stack[self.free_count];
        if (self.slots[idx] == null) {
            const fresh = self.allocator.create(ConnectionSlot) catch {
                self.free_stack[self.free_count] = idx;
                self.free_count += 1;
                return null;
            };
            fresh.* = .{};
            self.slots[idx] = fresh;
            const hi = idx + 1;
            if (hi > self.allocated_hi) self.allocated_hi = hi;
        }

        const slot = self.slots[idx].?;
        slot.* = .{};
        slot.index = idx;
        slot.client_queue.allocator = self.allocator;
        slot.upstream_queue.allocator = self.allocator;
        return slot;
    }

    fn release(self: *ConnectionPool, slot: *ConnectionSlot) void {
        self.free_stack[self.free_count] = slot.index;
        self.free_count += 1;
        slot.phase = .idle;
    }

    fn mapFd(self: *ConnectionPool, fd: posix.fd_t, idx: u32) !void {
        try self.fd_to_slot.put(self.allocator, fd, idx);
    }

    fn unmapFd(self: *ConnectionPool, fd: posix.fd_t) void {
        _ = self.fd_to_slot.remove(fd);
    }

    fn getByFd(self: *ConnectionPool, fd: posix.fd_t) ?*ConnectionSlot {
        const idx = self.fd_to_slot.get(fd) orelse return null;
        return self.slots[idx];
    }
};

fn slotCandidateCount(slot: *const ConnectionSlot) usize {
    if (slot.upstream_candidates) |c| return c.len;
    return 0;
}

pub const ProxyState = struct {
    allocator: std.mem.Allocator,
    config: Config,
    user_secrets: []const obfuscation.UserSecret,
    connection_count: std.atomic.Value(u64),
    active_connections: std.atomic.Value(u32),
    mask_addr: ?net.Address,
    replay_cache: ReplayCache,

    middle_proxy_lock: std.Thread.RwLock = .{},
    middle_proxy_addrs_primary: [5]net.Address,
    middle_proxy_addr_203: net.Address,
    middle_proxy_addrs_dc4: [16]net.Address,
    middle_proxy_addrs_dc4_len: usize,
    middle_proxy_addrs_203: [8]net.Address,
    middle_proxy_addrs_203_len: usize,
    middle_proxy_secret: [256]u8,
    middle_proxy_secret_len: usize,

    pub fn init(allocator: std.mem.Allocator, cfg: Config) ProxyState {
        var secrets: std.ArrayList(obfuscation.UserSecret) = .empty;
        var it = @constCast(&cfg.users).iterator();
        while (it.next()) |entry| {
            secrets.append(allocator, .{
                .name = entry.key_ptr.*,
                .secret = entry.value_ptr.*,
            }) catch continue;
        }

        var resolved_addr: ?net.Address = null;
        if (cfg.mask) {
            const mask_target = if (cfg.mask_port != 443) "127.0.0.1" else cfg.tls_domain;
            const list = net.getAddressList(allocator, mask_target, cfg.mask_port) catch |err| blk: {
                log.err("Failed to resolve mask target '{s}': {any}", .{ mask_target, err });
                break :blk null;
            };
            if (list) |al| {
                defer al.deinit();
                if (al.addrs.len > 0) {
                    resolved_addr = al.addrs[0];
                    log.info("Mask target '{s}' resolved at startup", .{mask_target});
                }
            }
        }

        var default_middle_proxy_secret = [_]u8{0} ** 256;
        @memcpy(default_middle_proxy_secret[0..middleproxy.proxy_secret.len], middleproxy.proxy_secret[0..]);

        return .{
            .allocator = allocator,
            .config = cfg,
            .user_secrets = secrets.toOwnedSlice(allocator) catch &.{},
            .connection_count = std.atomic.Value(u64).init(0),
            .active_connections = std.atomic.Value(u32).init(0),
            .mask_addr = resolved_addr,
            .replay_cache = .{},
            .middle_proxy_addrs_primary = constants.tg_middle_proxies_v4,
            .middle_proxy_addr_203 = constants.getDcAddressV4(203),
            .middle_proxy_addrs_dc4 = [_]net.Address{constants.tg_middle_proxies_v4[3]} ++ ([_]net.Address{constants.tg_middle_proxies_v4[3]} ** 15),
            .middle_proxy_addrs_dc4_len = 1,
            .middle_proxy_addrs_203 = [_]net.Address{constants.getDcAddressV4(203)} ++ ([_]net.Address{constants.getDcAddressV4(203)} ** 7),
            .middle_proxy_addrs_203_len = 1,
            .middle_proxy_secret = default_middle_proxy_secret,
            .middle_proxy_secret_len = middleproxy.proxy_secret.len,
        };
    }

    pub fn deinit(self: *ProxyState) void {
        self.allocator.free(self.user_secrets);
    }

    pub fn run(self: *ProxyState) !void {
        if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

        const address = net.Address.initIp6(
            .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            self.config.port,
            0,
            0,
        );
        var ipv6_ok = true;
        var server = address.listen(.{
            .reuse_address = true,
            .kernel_backlog = @intCast(self.config.backlog),
        }) catch |err| blk: {
            if (err == error.AddressFamilyNotSupported) {
                ipv6_ok = false;
                log.warn("IPv6 not available, falling back to IPv4 (0.0.0.0)", .{});
                const address_v4 = net.Address.initIp4(.{ 0, 0, 0, 0 }, self.config.port);
                break :blk try address_v4.listen(.{
                    .reuse_address = true,
                    .kernel_backlog = @intCast(self.config.backlog),
                });
            }
            return err;
        };
        defer server.deinit();

        if (ipv6_ok) {
            log.info("Listening on [::]:{d} (epoll, single-thread)", .{self.config.port});
        } else {
            log.info("Listening on 0.0.0.0:{d} (epoll, single-thread)", .{self.config.port});
        }

        setNonBlocking(server.stream.handle);

        if (self.config.datacenter_override == null) {
            self.refreshMiddleProxyInfo() catch |err| {
                log.warn("Initial middle-proxy refresh failed, using bundled defaults: {any}", .{err});
            };

            if (std.Thread.spawn(.{}, ProxyState.middleProxyUpdaterMain, .{self})) |updater| {
                updater.detach();
            } else |err| {
                log.warn("Middle-proxy updater thread failed to start: {any}", .{err});
            }
        }

        if (getNofileSoftLimit()) |soft| {
            const configured_max = self.config.max_connections;
            const needed_fds = requiredFdsForConnections(configured_max);
            if (soft < needed_fds) {
                const clamped = maxConnectionsForNofile(soft);
                if (clamped < configured_max) {
                    self.config.max_connections = clamped;
                    log.warn("max_connections clamped from {d} to {d} due to RLIMIT_NOFILE soft={d}", .{
                        configured_max,
                        clamped,
                        soft,
                    });
                }
            }
        }

        const effective_needed_fds = requiredFdsForConnections(self.config.max_connections);
        checkNofileLimit(@max(effective_needed_fds, min_nofile_soft), self.config.max_connections);

        var loop = try EventLoop.init(self, server.stream.handle);
        defer loop.deinit();
        try loop.run();
    }

    const MiddleProxySnapshot = struct {
        addrs_primary: [5]net.Address,
        addr_203: net.Address,
        addrs_dc4: [16]net.Address,
        addrs_dc4_len: usize,
        addrs_203: [8]net.Address,
        addrs_203_len: usize,
        secret: [256]u8,
        secret_len: usize,

        fn getForDc(self: *const MiddleProxySnapshot, dc_abs: usize) ?net.Address {
            if (dc_abs == 203) return self.addr_203;
            if (dc_abs >= 1 and dc_abs <= self.addrs_primary.len) {
                return self.addrs_primary[dc_abs - 1];
            }
            return null;
        }
    };

    fn getMiddleProxySnapshot(self: *ProxyState) MiddleProxySnapshot {
        self.middle_proxy_lock.lockShared();
        defer self.middle_proxy_lock.unlockShared();

        return .{
            .addrs_primary = self.middle_proxy_addrs_primary,
            .addr_203 = self.middle_proxy_addr_203,
            .addrs_dc4 = self.middle_proxy_addrs_dc4,
            .addrs_dc4_len = self.middle_proxy_addrs_dc4_len,
            .addrs_203 = self.middle_proxy_addrs_203,
            .addrs_203_len = self.middle_proxy_addrs_203_len,
            .secret = self.middle_proxy_secret,
            .secret_len = self.middle_proxy_secret_len,
        };
    }

    fn middleProxyUpdaterMain(self: *ProxyState) void {
        while (true) {
            std.Thread.sleep(middle_proxy_update_period_ns);
            self.refreshMiddleProxyInfo() catch |err| {
                log.warn("Middle-proxy refresh failed: {any}", .{err});
            };
        }
    }

    fn refreshMiddleProxyInfo(self: *ProxyState) !void {
        const cfg_bytes = try fetchUrlBytes(self.allocator, middle_proxy_config_url);
        defer self.allocator.free(cfg_bytes);

        var next_primary: [5]?net.Address = [_]?net.Address{null} ** 5;
        var next_dc4_candidates: [16]net.Address = undefined;
        var next_dc4_candidates_len: usize = 0;
        for (0..next_primary.len) |i| {
            var candidates: [16]net.Address = undefined;
            const count = parseMiddleProxyAddressesForDc(cfg_bytes, @as(i16, @intCast(i + 1)), &candidates);

            if (i == 3 and count > 0) {
                const dc4_n = @min(count, next_dc4_candidates.len);
                @memcpy(next_dc4_candidates[0..dc4_n], candidates[0..dc4_n]);
                next_dc4_candidates_len = dc4_n;
            }

            next_primary[i] = if (count == 0)
                null
            else if (i == 3)
                candidates[0]
            else if (trySelectReachableMiddleProxy(candidates[0..count], 1200)) |reachable|
                reachable
            else
                candidates[0];
        }

        var candidates_203: [8]net.Address = undefined;
        const count_203 = parseMiddleProxyAddressesForDc(cfg_bytes, 203, &candidates_203);
        var next_203_candidates: [8]net.Address = undefined;
        var next_203_candidates_len: usize = 0;
        if (count_203 > 0) {
            const c203_n = @min(count_203, next_203_candidates.len);
            @memcpy(next_203_candidates[0..c203_n], candidates_203[0..c203_n]);
            next_203_candidates_len = c203_n;
        }
        const next_addr_203 = if (count_203 == 0) null else candidates_203[0];

        const next_secret = try fetchUrlBytes(self.allocator, middle_proxy_secret_url);
        defer self.allocator.free(next_secret);

        if (next_secret.len < 16 or next_secret.len > self.middle_proxy_secret.len) {
            return error.BadMiddleProxySecret;
        }

        self.middle_proxy_lock.lock();
        defer self.middle_proxy_lock.unlock();

        var changed = false;

        for (0..next_primary.len) |i| {
            if (next_primary[i]) |addr| {
                if (!self.middle_proxy_addrs_primary[i].eql(addr)) {
                    self.middle_proxy_addrs_primary[i] = addr;
                    changed = true;
                }
            }
        }

        if (next_addr_203) |addr| {
            if (!self.middle_proxy_addr_203.eql(addr)) {
                self.middle_proxy_addr_203 = addr;
                changed = true;
            }
        }

        if (next_dc4_candidates_len > 0) {
            if (self.middle_proxy_addrs_dc4_len != next_dc4_candidates_len or
                !addressesEqual(self.middle_proxy_addrs_dc4[0..next_dc4_candidates_len], next_dc4_candidates[0..next_dc4_candidates_len]))
            {
                @memcpy(self.middle_proxy_addrs_dc4[0..next_dc4_candidates_len], next_dc4_candidates[0..next_dc4_candidates_len]);
                self.middle_proxy_addrs_dc4_len = next_dc4_candidates_len;
                changed = true;
            }
        }

        if (next_203_candidates_len > 0) {
            if (self.middle_proxy_addrs_203_len != next_203_candidates_len or
                !addressesEqual(self.middle_proxy_addrs_203[0..next_203_candidates_len], next_203_candidates[0..next_203_candidates_len]))
            {
                @memcpy(self.middle_proxy_addrs_203[0..next_203_candidates_len], next_203_candidates[0..next_203_candidates_len]);
                self.middle_proxy_addrs_203_len = next_203_candidates_len;
                changed = true;
            }
        }

        if (self.middle_proxy_secret_len != next_secret.len or
            !std.mem.eql(u8, self.middle_proxy_secret[0..self.middle_proxy_secret_len], next_secret))
        {
            @memset(self.middle_proxy_secret[0..], 0);
            @memcpy(self.middle_proxy_secret[0..next_secret.len], next_secret);
            self.middle_proxy_secret_len = next_secret.len;
            changed = true;
        }

        if (changed) {
            log.info("Middle-proxy cache updated: dc4={any} dc203={any} secret_len={d}", .{
                self.middle_proxy_addrs_primary[3],
                self.middle_proxy_addr_203,
                self.middle_proxy_secret_len,
            });
        }
    }
};

const EventLoop = struct {
    state: *ProxyState,
    epoll_fd: posix.fd_t,
    listen_fd: posix.fd_t,
    pool: ConnectionPool,
    accept_paused: bool,
    accept_resume_ns: i128,
    stats_next_log_ns: i128,
    accepted_since_log: u64,
    closed_since_log: u64,

    fn init(state: *ProxyState, listen_fd: posix.fd_t) !EventLoop {
        const epoll_fd = try epollCreate();
        errdefer posix.close(epoll_fd);

        var loop = EventLoop{
            .state = state,
            .epoll_fd = epoll_fd,
            .listen_fd = listen_fd,
            .pool = try ConnectionPool.init(state.allocator, state.config.max_connections),
            .accept_paused = false,
            .accept_resume_ns = 0,
            .stats_next_log_ns = std.time.nanoTimestamp() + stats_log_interval_ns,
            .accepted_since_log = 0,
            .closed_since_log = 0,
        };
        errdefer loop.pool.deinit();

        try loop.addFd(listen_fd, true, false);
        return loop;
    }

    fn deinit(self: *EventLoop) void {
        for (self.pool.slots) |slot_opt| {
            if (slot_opt) |slot| {
                if (slot.phase != .idle) {
                    self.closeSlot(slot, "shutdown");
                }
            }
        }
        self.pool.deinit();
        posix.close(self.epoll_fd);
    }

    fn run(self: *EventLoop) !void {
        var events: [256]linux.epoll_event = undefined;
        const timer_tick_ns: i128 = 5 * std.time.ns_per_ms;
        var next_timer_tick_ns: i128 = std.time.nanoTimestamp();

        while (true) {
            const rc = linux.epoll_wait(self.epoll_fd, events[0..].ptr, @intCast(events.len), event_loop_wait_ms);
            switch (posix.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                else => |err| return posix.unexpectedErrno(err),
            }

            const n: usize = @intCast(rc);
            for (events[0..n]) |ev| {
                const fd = ev.data.fd;
                const ev_flags = ev.events;
                if (fd == self.listen_fd) {
                    self.acceptNewConnections() catch |err| {
                        log.err("accept loop error: {any}", .{err});
                    };
                    continue;
                }

                const slot = self.pool.getByFd(fd) orelse continue;
                self.processSlotEvent(slot, fd, ev_flags);
            }

            const now_ns = std.time.nanoTimestamp();
            if (self.accept_paused and now_ns >= self.accept_resume_ns) {
                self.resumeAccepting();
            }
            if (now_ns >= next_timer_tick_ns) {
                self.runTimers();
                next_timer_tick_ns = now_ns + timer_tick_ns;
            }
            if (now_ns >= self.stats_next_log_ns) {
                self.logPeriodicStats(now_ns);
            }
        }
    }

    fn processSlotEvent(self: *EventLoop, slot: *ConnectionSlot, fd: posix.fd_t, events: u32) void {
        if (slot.phase == .idle) return;

        const fatal_hangup = hasFatalEpollHangup(events);

        if (fd == slot.client_fd) {
            if ((events & linux.EPOLL.OUT) != 0) {
                self.onClientWritable(slot);
            }
            if (slot.phase == .idle) return;
            if ((events & linux.EPOLL.IN) != 0) {
                self.onClientReadable(slot);
            }
        } else if (fd == slot.upstream_fd) {
            if ((events & linux.EPOLL.OUT) != 0 or (slot.phase == .connecting_upstream and fatal_hangup)) {
                self.onUpstreamWritable(slot);
            }
            if (slot.phase == .idle) return;
            if ((events & linux.EPOLL.IN) != 0) {
                self.onUpstreamReadable(slot);
            }
        }

        if (slot.phase != .idle and fatal_hangup and slot.phase != .connecting_upstream) {
            self.closeSlot(slot, "epoll hup/err");
            return;
        }

        if (slot.phase != .idle) {
            self.syncInterests(slot) catch |err| {
                log.debug("[{d}] interest sync error: {any}", .{ slot.conn_id, err });
                self.closeSlot(slot, "interest sync error");
            };
        }
    }

    fn acceptNewConnections(self: *EventLoop) !void {
        while (true) {
            var client_addr: net.Address = undefined;
            var client_len: posix.socklen_t = @sizeOf(net.Address);
            const cfd = posix.accept(self.listen_fd, &client_addr.any, &client_len, posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK) catch |err| {
                switch (err) {
                    error.WouldBlock => return,
                    error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded => {
                        self.pauseAccepting(err);
                        return;
                    },
                    else => return err,
                }
            };

            const active_before = self.state.active_connections.fetchAdd(1, .monotonic);
            if (active_before >= self.state.config.max_connections) {
                _ = self.state.active_connections.fetchSub(1, .monotonic);
                posix.close(cfd);
                continue;
            }

            const slot = self.pool.acquire() orelse {
                _ = self.state.active_connections.fetchSub(1, .monotonic);
                posix.close(cfd);
                continue;
            };

            slot.active_reserved = true;
            slot.conn_id = self.state.connection_count.fetchAdd(1, .monotonic);
            slot.client_fd = cfd;
            slot.peer_addr = client_addr;
            slot.phase = .reading_tls_header;
            slot.created_at_ms = std.time.milliTimestamp();
            slot.last_activity_ms = slot.created_at_ms;
            slot.drs = DynamicRecordSizer.init(self.state.config.drs);

            if (self.addFd(cfd, true, false)) |_| {
                self.pool.mapFd(cfd, slot.index) catch {
                    self.closeSlot(slot, "fd map failed");
                    continue;
                };
                self.accepted_since_log += 1;
            } else |_| {
                self.closeSlot(slot, "epoll add client failed");
                continue;
            }
        }
    }

    fn logPeriodicStats(self: *EventLoop, now_ns: i128) void {
        const active = self.state.active_connections.load(.monotonic);
        const accepted_total = self.state.connection_count.load(.monotonic);
        log.info("conn stats: active={d}/{d} accepted+={d} closed+={d} tracked_fds={d} total={d} accept_paused={}", .{
            active,
            self.state.config.max_connections,
            self.accepted_since_log,
            self.closed_since_log,
            self.pool.fd_to_slot.count(),
            accepted_total,
            self.accept_paused,
        });

        self.accepted_since_log = 0;
        self.closed_since_log = 0;

        while (self.stats_next_log_ns <= now_ns) {
            self.stats_next_log_ns += stats_log_interval_ns;
        }
    }

    fn pauseAccepting(self: *EventLoop, err: anyerror) void {
        self.accept_resume_ns = std.time.nanoTimestamp() + accept_backoff_ns;
        if (self.accept_paused) return;

        self.modFd(self.listen_fd, false, false) catch |mod_err| {
            log.err("failed to pause accepts after fd quota error: {any}", .{mod_err});
            return;
        };

        self.accept_paused = true;
        const needed = requiredFdsForConnections(self.state.config.max_connections);
        log.warn("fd quota reached ({any}); pausing accepts for {d}ms (recommended LimitNOFILE >= {d})", .{
            err,
            accept_backoff_ms,
            needed,
        });
    }

    fn resumeAccepting(self: *EventLoop) void {
        if (!self.accept_paused) return;

        self.modFd(self.listen_fd, true, false) catch |err| {
            self.accept_resume_ns = std.time.nanoTimestamp() + accept_backoff_ns;
            log.warn("failed to resume accepts; retry in {d}ms: {any}", .{ accept_backoff_ms, err });
            return;
        };

        self.accept_paused = false;
        self.accept_resume_ns = 0;
    }

    fn onClientReadable(self: *EventLoop, slot: *ConnectionSlot) void {
        slot.last_activity_ms = std.time.milliTimestamp();

        switch (slot.phase) {
            .reading_tls_header => self.readTlsHeader(slot),
            .reading_client_hello_body => self.readClientHelloBody(slot),
            .reading_mtproto_tls_header, .reading_mtproto_tls_body => self.readMtprotoHandshake(slot),
            .relaying => self.relayClientToUpstream(slot),
            .mask_relaying => self.relayRawClientToUpstream(slot),
            else => {},
        }
    }

    fn onClientWritable(self: *EventLoop, slot: *ConnectionSlot) void {
        const had_pending = slot.hasClientPending();
        if (flushClientPending(slot, self.state.allocator)) |progressed| {
            if (!progressed) {}
        } else |err| {
            log.debug("[{d}] client flush error: {any}", .{ slot.conn_id, err });
            self.closeSlot(slot, "client flush error");
            return;
        }
        if (had_pending and !slot.hasClientPending()) {
            slot.last_activity_ms = std.time.milliTimestamp();
        }

        switch (slot.phase) {
            .writing_server_hello_first => {
                if (!slot.hasClientPending()) {
                    slot.phase = .desync_wait;
                    slot.desync_deadline_ns = std.time.nanoTimestamp() + (3 * std.time.ns_per_ms);
                }
            },
            .writing_server_hello_rest => {
                if (!slot.hasClientPending()) {
                    if (slot.server_hello) |buf| {
                        self.state.allocator.free(buf);
                        slot.server_hello = null;
                    }
                    slot.phase = .reading_mtproto_tls_header;
                    slot.tls_hdr_pos = 0;
                    slot.tls_body_len = 0;
                    slot.tls_body_pos = 0;
                }
            },
            else => {},
        }
    }

    fn onUpstreamReadable(self: *EventLoop, slot: *ConnectionSlot) void {
        slot.last_activity_ms = std.time.milliTimestamp();

        switch (slot.phase) {
            .middle_proxy_handshake => self.middleProxyOnReadable(slot),
            .relaying => self.relayUpstreamToClient(slot),
            .mask_relaying => self.relayRawUpstreamToClient(slot),
            else => {},
        }
    }

    fn onUpstreamWritable(self: *EventLoop, slot: *ConnectionSlot) void {
        switch (slot.phase) {
            .connecting_upstream => self.onUpstreamConnectComplete(slot),
            .writing_dc_nonce, .relaying, .mask_relaying, .middle_proxy_handshake => {
                const had_pending = slot.hasUpstreamPending();
                if (flushUpstreamPending(slot, self.state.allocator)) |_| {} else |err| {
                    log.debug("[{d}] upstream flush error: {any}", .{ slot.conn_id, err });
                    self.closeSlot(slot, "upstream flush error");
                    return;
                }
                if (had_pending and !slot.hasUpstreamPending()) {
                    slot.last_activity_ms = std.time.milliTimestamp();
                }

                if (slot.phase == .writing_dc_nonce and !slot.hasUpstreamPending()) {
                    self.onDcNonceWritable(slot);
                    if (slot.phase == .idle) return;
                }

                if (slot.phase == .middle_proxy_handshake) {
                    self.middleProxyOnWritable(slot);
                }

                // If middle-proxy handshake failed and switched to fallback direct path,
                // immediately start direct DC nonce sequence on the same connected fd.
                if (slot.phase == .writing_dc_nonce and !slot.hasUpstreamPending()) {
                    self.onDcNonceWritable(slot);
                }
            },
            else => {},
        }
    }

    fn onDcNonceWritable(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.dc_initial_tail) |tail| {
            if (queueUpstream(slot, self.state.allocator, tail)) |_| {
                self.state.allocator.free(tail);
                slot.dc_initial_tail = null;
            } else |err| {
                log.debug("[{d}] dc tail write error: {any}", .{ slot.conn_id, err });
                self.closeSlot(slot, "dc tail write error");
                return;
            }
        }

        if (!slot.hasUpstreamPending() and slot.dc_initial_tail == null) {
            self.startRelay(slot);
        }
    }

    fn readTlsHeader(self: *EventLoop, slot: *ConnectionSlot) void {
        while (slot.tls_hdr_pos < tls_header_len) {
            const n = posix.read(slot.client_fd, slot.tls_hdr_buf[slot.tls_hdr_pos..]) catch |err| {
                if (err == error.WouldBlock) return;
                self.closeSlot(slot, "tls header read error");
                return;
            };
            if (n == 0) {
                self.closeSlot(slot, "client eof before tls header");
                return;
            }
            if (slot.first_byte_at_ms == 0) {
                slot.first_byte_at_ms = std.time.milliTimestamp();
            }
            slot.tls_hdr_pos += @intCast(n);
            slot.last_activity_ms = std.time.milliTimestamp();
        }

        if (!tls.isTlsHandshake(slot.tls_hdr_buf[0..])) {
            self.startMasking(slot, slot.tls_hdr_buf[0..]) catch {
                self.closeSlot(slot, "non-tls masked failed");
            };
            return;
        }

        const record_len = std.mem.readInt(u16, slot.tls_hdr_buf[3..5], .big);
        if (record_len < constants.min_tls_client_hello_size or record_len > constants.max_tls_plaintext_size) {
            self.startMasking(slot, slot.tls_hdr_buf[0..]) catch {
                self.closeSlot(slot, "bad tls length");
            };
            return;
        }

        slot.client_hello_len = tls_header_len + record_len;
        if (slot.client_hello_len > slot.client_hello_inline.len) {
            slot.client_hello_heap = self.state.allocator.alloc(u8, slot.client_hello_len) catch {
                self.closeSlot(slot, "client_hello alloc failed");
                return;
            };
        }

        const hello_buf = slot.clientHelloBuf();
        @memcpy(hello_buf[0..tls_header_len], slot.tls_hdr_buf[0..]);
        slot.tls_body_len = @intCast(record_len);
        slot.tls_body_pos = 0;
        slot.phase = .reading_client_hello_body;
    }

    fn readClientHelloBody(self: *EventLoop, slot: *ConnectionSlot) void {
        const hello_buf = slot.clientHelloBuf();

        while (slot.tls_body_pos < slot.tls_body_len) {
            const off = tls_header_len + slot.tls_body_pos;
            const end = tls_header_len + slot.tls_body_len;
            const n = posix.read(slot.client_fd, hello_buf[off..end]) catch |err| {
                if (err == error.WouldBlock) return;
                self.closeSlot(slot, "client hello body read error");
                return;
            };
            if (n == 0) {
                self.closeSlot(slot, "client eof during client hello");
                return;
            }
            slot.tls_body_pos += @intCast(n);
            slot.last_activity_ms = std.time.milliTimestamp();
        }

        const client_hello = hello_buf[0..slot.client_hello_len];

        const maybe_sni = tls.extractSni(client_hello);
        if (maybe_sni == null) {
            self.startMasking(slot, client_hello) catch {
                self.closeSlot(slot, "tls missing sni");
            };
            return;
        }

        const sni = maybe_sni.?;
        if (!std.ascii.eqlIgnoreCase(sni, self.state.config.tls_domain)) {
            self.startMasking(slot, client_hello) catch {
                self.closeSlot(slot, "tls sni mismatch");
            };
            return;
        }

        const validation = tls.validateTlsHandshake(
            self.state.allocator,
            client_hello,
            self.state.user_secrets,
            false,
        ) catch null;

        if (validation == null) {
            self.startMasking(slot, client_hello) catch {
                self.closeSlot(slot, "tls validation failed");
            };
            return;
        }

        const v = validation.?;
        if (self.state.replay_cache.checkAndInsert(&v.canonical_hmac)) {
            self.startMasking(slot, client_hello) catch {
                self.closeSlot(slot, "replay detected, masking failed");
            };
            return;
        }

        slot.validation_secret = v.secret;
        slot.validation_digest = v.digest;
        slot.validation_session_id_len = @intCast(v.session_id.len);
        @memcpy(slot.validation_session_id[0..v.session_id.len], v.session_id);
        const ulen = @min(v.user.len, slot.validation_user.len);
        slot.validation_user_len = @intCast(ulen);
        @memcpy(slot.validation_user[0..ulen], v.user[0..ulen]);

        slot.server_hello = tls.buildServerHello(
            self.state.allocator,
            &slot.validation_secret,
            &slot.validation_digest,
            slot.validation_session_id[0..slot.validation_session_id_len],
        ) catch {
            self.closeSlot(slot, "build server hello failed");
            return;
        };
        slot.server_hello_off = 0;

        if (self.state.config.desync and slot.server_hello.?.len > 1) {
            slot.phase = .writing_server_hello_first;
            const one = slot.server_hello.?[0..1];
            if (queueClient(slot, self.state.allocator, one)) |_| {} else |_| {
                self.closeSlot(slot, "queue first desync byte failed");
                return;
            }
            slot.server_hello_off = 1;
        } else {
            slot.phase = .writing_server_hello_rest;
            if (queueClient(slot, self.state.allocator, slot.server_hello.?)) |_| {} else |_| {
                self.closeSlot(slot, "queue server hello failed");
                return;
            }
            slot.server_hello_off = slot.server_hello.?.len;
        }
    }

    fn readMtprotoHandshake(self: *EventLoop, slot: *ConnectionSlot) void {
        // Phase pair: read TLS header then body, reusing tls_* fields.
        while (true) {
            if (slot.phase == .reading_mtproto_tls_header) {
                while (slot.tls_hdr_pos < tls_header_len) {
                    const n = posix.read(slot.client_fd, slot.tls_hdr_buf[slot.tls_hdr_pos..]) catch |err| {
                        if (err == error.WouldBlock) return;
                        self.closeSlot(slot, "mtproto tls hdr read error");
                        return;
                    };
                    if (n == 0) {
                        self.closeSlot(slot, "client eof waiting mtproto hdr");
                        return;
                    }
                    slot.tls_hdr_pos += @intCast(n);
                }

                slot.tls_record_type = slot.tls_hdr_buf[0];
                slot.tls_body_len = std.mem.readInt(u16, slot.tls_hdr_buf[3..5], .big);
                slot.tls_body_pos = 0;

                if (slot.tls_record_type == constants.tls_record_alert) {
                    self.closeSlot(slot, "tls alert during mtproto handshake");
                    return;
                }

                if (slot.tls_record_type != constants.tls_record_change_cipher and
                    slot.tls_record_type != constants.tls_record_application)
                {
                    self.closeSlot(slot, "unexpected tls record type in mtproto handshake");
                    return;
                }
                if (slot.tls_body_len == 0 or slot.tls_body_len > constants.max_tls_ciphertext_size) {
                    self.closeSlot(slot, "bad mtproto tls body size");
                    return;
                }

                slot.phase = .reading_mtproto_tls_body;
            }

            if (slot.phase != .reading_mtproto_tls_body) return;

            const remaining: usize = slot.tls_body_len - slot.tls_body_pos;
            if (remaining == 0) {
                slot.tls_hdr_pos = 0;
                slot.phase = .reading_mtproto_tls_header;
                if (slot.handshake_pos >= constants.handshake_len) {
                    self.finishClientHandshake(slot);
                    return;
                }
                continue;
            }

            const read_buf = ensureReadBuf(slot, self.state.allocator) catch {
                self.closeSlot(slot, "alloc read buffer failed");
                return;
            };
            const want = @min(remaining, read_buf.len);
            const n = posix.read(slot.client_fd, read_buf[0..want]) catch |err| {
                if (err == error.WouldBlock) return;
                self.closeSlot(slot, "mtproto tls body read error");
                return;
            };
            if (n == 0) {
                self.closeSlot(slot, "client eof waiting mtproto body");
                return;
            }

            slot.tls_body_pos += @intCast(n);

            if (slot.tls_record_type == constants.tls_record_change_cipher) {
                // discard body
            } else {
                var off: usize = 0;
                while (off < n) {
                    if (slot.handshake_pos < constants.handshake_len) {
                        const need = constants.handshake_len - slot.handshake_pos;
                        const take = @min(need, n - off);
                        @memcpy(slot.handshake_buf[slot.handshake_pos .. slot.handshake_pos + take], read_buf[off .. off + take]);
                        slot.handshake_pos += @intCast(take);
                        off += take;
                    } else {
                        const extra = read_buf[off..n];
                        self.appendPipelined(slot, extra) catch {
                            self.closeSlot(slot, "pipelined append failed");
                            return;
                        };
                        off = n;
                    }
                }
            }

            if (slot.tls_body_pos == slot.tls_body_len) {
                slot.tls_hdr_pos = 0;
                slot.phase = .reading_mtproto_tls_header;
                if (slot.handshake_pos >= constants.handshake_len) {
                    self.finishClientHandshake(slot);
                    return;
                }
            }
        }
    }

    fn finishClientHandshake(self: *EventLoop, slot: *ConnectionSlot) void {
        const result = obfuscation.ObfuscationParams.fromHandshake(&slot.handshake_buf, self.state.user_secrets) orelse {
            self.closeSlot(slot, "bad mtproto obfuscation handshake");
            return;
        };

        slot.obf_params = result.params;
        slot.proto_tag = result.params.proto_tag;
        slot.dc_idx = result.params.dc_idx;
        slot.client_decryptor = result.params.createDecryptor();
        slot.client_encryptor = result.params.createEncryptor();
        if (slot.client_decryptor) |*dec| dec.ctr +%= 4;

        const dc_abs: usize = if (slot.dc_idx > 0)
            @as(usize, @intCast(slot.dc_idx))
        else if (slot.dc_idx < 0)
            @as(usize, @abs(slot.dc_idx))
        else {
            self.closeSlot(slot, "invalid dc index");
            return;
        };

        const snapshot = if (self.state.config.datacenter_override == null and (self.state.config.use_middle_proxy or dc_abs == 203))
            self.state.getMiddleProxySnapshot()
        else
            null;

        const plan = buildDcConnectPlan(&self.state.config, dc_abs, slot.dc_idx, if (snapshot) |*s| s else null);
        if (plan.count == 0) {
            self.closeSlot(slot, "no upstream candidates");
            return;
        }

        slot.dc_abs = @intCast(dc_abs);
        slot.use_middle_proxy = plan.use_middle_proxy;
        slot.is_media_path = plan.is_media_path;
        slot.use_fast_mode = self.state.config.fast_mode and !slot.use_middle_proxy and (dc_abs >= 1 and dc_abs <= constants.tg_datacenters_v4.len);
        slot.direct_fallback_addr = plan.direct_fallback;
        slot.direct_fallback_used = false;

        if (slot.upstream_candidates) |old| {
            self.state.allocator.free(old);
            slot.upstream_candidates = null;
        }

        slot.upstream_candidates = self.state.allocator.alloc(net.Address, plan.count) catch {
            self.closeSlot(slot, "alloc upstream candidate list failed");
            return;
        };
        const candidates = slot.upstream_candidates.?;
        var idx: usize = 0;
        while (idx < candidates.len) : (idx += 1) {
            candidates[idx] = plan.candidates[idx];
        }
        slot.upstream_candidate_next = 1;
        slot.current_upstream_addr = candidates[0];

        self.startConnectUpstream(slot, candidates[0], .dc) catch {
            self.closeSlot(slot, "upstream connect start failed");
        };
    }

    fn startMasking(self: *EventLoop, slot: *ConnectionSlot, buffered: []const u8) !void {
        if (!self.state.config.mask) return error.MaskingDisabled;

        const addr = self.state.mask_addr orelse return error.NoMaskAddress;
        const pre = try self.state.allocator.alloc(u8, buffered.len);
        @memcpy(pre, buffered);
        slot.mask_prebuffer = pre;

        try self.startConnectUpstream(slot, addr, .mask);
    }

    fn startConnectUpstream(self: *EventLoop, slot: *ConnectionSlot, addr: net.Address, kind: UpstreamKind) !void {
        slot.current_upstream_addr = addr;

        const fd = try posix.socket(addr.any.family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP);
        slot.upstream_fd = fd;
        slot.upstream_kind = kind;
        slot.phase = .connecting_upstream;

        try self.addFd(fd, false, true);
        try self.pool.mapFd(fd, slot.index);

        posix.connect(fd, &addr.any, addr.getOsSockLen()) catch |err| {
            if (err == error.WouldBlock or err == error.ConnectionPending) {
                return;
            }

            self.pool.unmapFd(fd);
            _ = self.delFd(fd) catch {};
            posix.close(fd);
            slot.upstream_fd = -1;
            slot.upstream_kind = .none;
            slot.current_upstream_addr = null;
            return err;
        };

        self.onUpstreamConnectComplete(slot);
    }

    fn onUpstreamConnectComplete(self: *EventLoop, slot: *ConnectionSlot) void {
        if (posix.getsockoptError(slot.upstream_fd)) |_| {} else |err| {
            self.cleanupFailedUpstreamConnect(slot);

            if (slot.upstream_kind == .dc and self.tryNextDcEndpoint(slot, err)) {
                return;
            }

            log.debug("[{d}] connect completion failed: {any}", .{ slot.conn_id, err });
            self.closeSlot(slot, "connect failed");
            return;
        }

        configureRelaySocket(slot.client_fd);
        configureRelaySocket(slot.upstream_fd);

        if (slot.upstream_kind == .mask) {
            if (slot.mask_prebuffer) |pre| {
                if (queueUpstream(slot, self.state.allocator, pre)) |_| {
                    self.state.allocator.free(pre);
                    slot.mask_prebuffer = null;
                } else |err| {
                    log.debug("[{d}] queue mask prebuffer failed: {any}", .{ slot.conn_id, err });
                    self.closeSlot(slot, "mask prebuffer failed");
                    return;
                }
            }
            slot.phase = .mask_relaying;
            return;
        }

        if (slot.use_middle_proxy) {
            self.middleProxyBegin(slot);
            return;
        }

        self.sendDcNonce(slot);
    }

    fn cleanupFailedUpstreamConnect(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.upstream_fd != -1) {
            const fd = slot.upstream_fd;
            _ = self.delFd(fd) catch {};
            self.pool.unmapFd(fd);
            posix.close(fd);
            slot.upstream_fd = -1;
        }
        slot.upstream_kind = .none;
        slot.current_upstream_addr = null;
        slot.upstream_queue.clear();
    }

    fn tryNextDcEndpoint(self: *EventLoop, slot: *ConnectionSlot, err: anyerror) bool {
        const attempt_addr = slot.current_upstream_addr;
        const candidates = slot.upstream_candidates orelse return false;
        const candidate_count = slotCandidateCount(slot);

        if (slot.upstream_candidate_next < candidates.len) {
            const next_idx = slot.upstream_candidate_next;
            const next_addr = candidates[next_idx];
            slot.upstream_candidate_next += 1;
            self.startConnectUpstream(slot, next_addr, .dc) catch |next_err| {
                log.warn("[{d}] dc connect candidate {d}/{d} failed immediately: {any}", .{
                    slot.conn_id,
                    next_idx + 1,
                    candidate_count,
                    next_err,
                });
                return self.tryNextDcEndpoint(slot, next_err);
            };

            if (attempt_addr) |addr| {
                var prev_buf: [64]u8 = undefined;
                const prev_str = formatAddress(addr, &prev_buf);
                log.warn("[{d}] dc connect failed ({any}), retry candidate {d}/{d} after {s}", .{
                    slot.conn_id,
                    err,
                    next_idx + 1,
                    candidate_count,
                    prev_str,
                });
            }
            return true;
        }

        if (!slot.direct_fallback_used and slot.direct_fallback_addr != null and slot.use_middle_proxy and !slot.is_media_path) {
            slot.direct_fallback_used = true;
            slot.use_middle_proxy = false;
            const fallback = slot.direct_fallback_addr.?;
            slot.upstream_candidate_next = 1;

            if (slot.upstream_candidates) |old| {
                self.state.allocator.free(old);
                slot.upstream_candidates = null;
            }
            const one = self.state.allocator.alloc(net.Address, 1) catch {
                return false;
            };
            one[0] = fallback;
            slot.upstream_candidates = one;

            self.startConnectUpstream(slot, fallback, .dc) catch |fallback_err| {
                log.warn("[{d}] direct fallback connect failed: {any}", .{ slot.conn_id, fallback_err });
                return false;
            };

            var fb_buf: [64]u8 = undefined;
            const fb_str = formatAddress(fallback, &fb_buf);
            log.warn("[{d}] middle-proxy exhausted, fallback to direct {s}", .{ slot.conn_id, fb_str });
            return true;
        }

        if (slot.is_media_path) {
            log.warn("[{d}] media path connect failed after all candidates: {any}", .{ slot.conn_id, err });
        }
        return false;
    }

    fn sendDcNonce(self: *EventLoop, slot: *ConnectionSlot) void {
        const params = slot.obf_params orelse {
            self.closeSlot(slot, "missing obfuscation params");
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

        if (queueUpstream(slot, self.state.allocator, &nonce_to_send)) |_| {} else |err| {
            log.debug("[{d}] queue dc nonce failed: {any}", .{ slot.conn_id, err });
            self.closeSlot(slot, "queue dc nonce failed");
            return;
        }

        // Promotion tag (optional), only for primary DC1..5
        if (self.state.config.tag) |tag| {
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

                const tail = self.state.allocator.alloc(u8, packet_len) catch {
                    self.closeSlot(slot, "alloc promotion tail failed");
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

    fn startRelay(self: *EventLoop, slot: *ConnectionSlot) void {
        slot.phase = .relaying;

        if (slot.pipelined_data) |buf| {
            if (slot.client_decryptor) |*dec| dec.apply(buf);

            if (slot.middle_ctx) |*mp| {
                const out_data = mp.encapsulateC2S(buf) catch {
                    return;
                };
                if (out_data.len > 0) {
                    _ = queueUpstream(slot, self.state.allocator, out_data) catch {
                        self.closeSlot(slot, "queue pipelined middleproxy payload failed");
                        return;
                    };
                }
            } else if (slot.tg_encryptor) |*enc| {
                enc.apply(buf);
                _ = queueUpstream(slot, self.state.allocator, buf) catch {
                    self.closeSlot(slot, "queue pipelined direct payload failed");
                    return;
                };
            }

            slot.c2s_bytes += buf.len;
            self.state.allocator.free(buf);
            slot.pipelined_data = null;
        }
    }

    fn relayClientToUpstream(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasUpstreamPending()) return;

        const progress = relayClientToUpstreamStep(slot, self.state.allocator) catch {
            self.closeSlot(slot, "relay c2s failed");
            return;
        };
        if (progress == .forwarded or progress == .partial) {
            slot.last_activity_ms = std.time.milliTimestamp();
        }
    }

    fn relayUpstreamToClient(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasClientPending()) return;

        const progress = relayUpstreamToClientStep(slot, self.state.allocator) catch {
            self.closeSlot(slot, "relay s2c failed");
            return;
        };
        if (progress == .forwarded or progress == .partial) {
            slot.last_activity_ms = std.time.milliTimestamp();
        }
    }

    fn relayRawClientToUpstream(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasUpstreamPending()) return;

        const read_buf = ensureReadBuf(slot, self.state.allocator) catch {
            slot.phase = .closing;
            return;
        };

        const n = posix.read(slot.client_fd, read_buf) catch |err| {
            if (err == error.WouldBlock) return;
            slot.phase = .closing;
            return;
        };
        if (n == 0) {
            slot.phase = .closing;
            return;
        }

        _ = queueUpstream(slot, self.state.allocator, read_buf[0..n]) catch {
            slot.phase = .closing;
            return;
        };
    }

    fn relayRawUpstreamToClient(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasClientPending()) return;

        const read_buf = ensureReadBuf(slot, self.state.allocator) catch {
            slot.phase = .closing;
            return;
        };

        const n = posix.read(slot.upstream_fd, read_buf) catch |err| {
            if (err == error.WouldBlock) return;
            slot.phase = .closing;
            return;
        };
        if (n == 0) {
            slot.phase = .closing;
            return;
        }

        _ = queueClient(slot, self.state.allocator, read_buf[0..n]) catch {
            slot.phase = .closing;
            return;
        };
    }

    fn middleProxyBegin(self: *EventLoop, slot: *ConnectionSlot) void {
        slot.phase = .middle_proxy_handshake;
        slot.mp_step = .sending_rpc_nonce;
        slot.mp_write_seq_no = -2;
        slot.mp_read_seq_no = -2;
        slot.mp_frame_have = 0;
        slot.mp_frame_need = 0;
        slot.mp_enc = null;
        slot.mp_dec = null;

        crypto.randomBytes(&slot.mp_nonce);
        const ts: u32 = @intCast(@mod(std.time.timestamp(), 4294967296));
        slot.mp_timestamp = ts;

        var crypto_ts: [4]u8 = undefined;
        std.mem.writeInt(u32, &crypto_ts, ts, .little);

        var msg: [32]u8 = undefined;
        @memcpy(msg[0..4], &middleproxy.rpc_nonce_req);
        self.state.middle_proxy_lock.lockShared();
        const key_sel_len = @min(@as(usize, 4), self.state.middle_proxy_secret_len);
        @memcpy(msg[4..8], self.state.middle_proxy_secret[0..key_sel_len]);
        self.state.middle_proxy_lock.unlockShared();
        @memcpy(msg[8..12], &middleproxy.rpc_crypto_aes);
        @memcpy(msg[12..16], &crypto_ts);
        @memcpy(msg[16..32], &slot.mp_nonce);

        self.mpWriteFrame(slot, msg[0..], false) catch {
            self.closeSlot(slot, "mp send nonce failed");
            return;
        };

        if (!slot.hasUpstreamPending()) {
            slot.mp_step = .waiting_rpc_nonce_response;
            mpReadReset(slot, false);
        }
    }

    fn middleProxyOnWritable(self: *EventLoop, slot: *ConnectionSlot) void {
        _ = self;
        if (slot.hasUpstreamPending()) return;

        switch (slot.mp_step) {
            .sending_rpc_nonce => {
                slot.mp_step = .waiting_rpc_nonce_response;
                mpReadReset(slot, false);
            },
            .sending_rpc_handshake => {
                slot.mp_step = .waiting_rpc_handshake_response;
                mpReadReset(slot, true);
            },
            else => {},
        }
    }

    fn middleProxyOnReadable(self: *EventLoop, slot: *ConnectionSlot) void {
        switch (slot.mp_step) {
            .waiting_rpc_nonce_response => {
                const payload = self.mpTryReadFrame(slot, false) catch {
                    self.closeSlot(slot, "mp read nonce ans failed");
                    return;
                } orelse return;

                if (payload.len != 32) {
                    self.closeSlot(slot, "mp bad nonce ans len");
                    return;
                }
                if (!std.mem.eql(u8, payload[0..4], &middleproxy.rpc_nonce_req)) {
                    self.closeSlot(slot, "mp bad nonce ans type");
                    return;
                }

                self.state.middle_proxy_lock.lockShared();
                const key_sel = self.state.middle_proxy_secret[0..@min(@as(usize, 4), self.state.middle_proxy_secret_len)];
                const secret_slice = self.state.middle_proxy_secret[0..self.state.middle_proxy_secret_len];
                if (!std.mem.eql(u8, payload[4..8], key_sel)) {
                    self.state.middle_proxy_lock.unlockShared();
                    self.closeSlot(slot, "mp key selector mismatch");
                    return;
                }
                if (!std.mem.eql(u8, payload[8..12], &middleproxy.rpc_crypto_aes)) {
                    self.state.middle_proxy_lock.unlockShared();
                    self.closeSlot(slot, "mp crypto schema mismatch");
                    return;
                }

                slot.mp_rpc_nonce_ans = payload[16..32][0..16].*;

                var ts_arr: [4]u8 = undefined;
                std.mem.writeInt(u32, &ts_arr, slot.mp_timestamp, .little);

                var peer_addr: net.Address = undefined;
                var peer_len: posix.socklen_t = @sizeOf(net.Address);
                posix.getpeername(slot.upstream_fd, &peer_addr.any, &peer_len) catch {
                    self.state.middle_proxy_lock.unlockShared();
                    self.closeSlot(slot, "mp getpeername failed");
                    return;
                };

                var local_addr: net.Address = undefined;
                var local_len: posix.socklen_t = @sizeOf(net.Address);
                posix.getsockname(slot.upstream_fd, &local_addr.any, &local_len) catch {
                    self.state.middle_proxy_lock.unlockShared();
                    self.closeSlot(slot, "mp getsockname failed");
                    return;
                };

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
                    self.state.middle_proxy_lock.unlockShared();
                    self.closeSlot(slot, "mp unsupported addr family");
                    return;
                }

                const tg_ip_v4_ptr: ?*const [4]u8 = if (tg_ip_v4_opt) |*ip| ip else null;
                const my_ip_v4_ptr: ?*const [4]u8 = if (my_ip_v4_opt) |*ip| ip else null;
                const my_ip_v6_ptr: ?*const [16]u8 = if (my_ip_v6_opt) |*ip| ip else null;
                const tg_ip_v6_ptr: ?*const [16]u8 = if (tg_ip_v6_opt) |*ip| ip else null;

                const enc_keys = middleproxy.getAesKeyAndIv(
                    &slot.mp_rpc_nonce_ans,
                    &slot.mp_nonce,
                    &ts_arr,
                    tg_ip_v4_ptr,
                    &my_port,
                    "CLIENT",
                    my_ip_v4_ptr,
                    &tg_port,
                    secret_slice,
                    my_ip_v6_ptr,
                    tg_ip_v6_ptr,
                );

                const dec_keys = middleproxy.getAesKeyAndIv(
                    &slot.mp_rpc_nonce_ans,
                    &slot.mp_nonce,
                    &ts_arr,
                    tg_ip_v4_ptr,
                    &my_port,
                    "SERVER",
                    my_ip_v4_ptr,
                    &tg_port,
                    secret_slice,
                    my_ip_v6_ptr,
                    tg_ip_v6_ptr,
                );
                self.state.middle_proxy_lock.unlockShared();

                slot.mp_enc = crypto.AesCbc.init(&enc_keys[0], &enc_keys[1]);
                slot.mp_dec = crypto.AesCbc.init(&dec_keys[0], &dec_keys[1]);

                var hs_msg: [32]u8 = undefined;
                @memcpy(hs_msg[0..4], &middleproxy.rpc_handshake);
                @memset(hs_msg[4..8], 0);
                @memcpy(hs_msg[8..20], "IPIPPRPDTIME");
                @memcpy(hs_msg[20..32], "IPIPPRPDTIME");

                self.mpWriteFrame(slot, hs_msg[0..], true) catch {
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp send handshake failed");
                    }
                    return;
                };

                slot.mp_step = if (slot.hasUpstreamPending()) .sending_rpc_handshake else .waiting_rpc_handshake_response;
                if (!slot.hasUpstreamPending()) {
                    mpReadReset(slot, true);
                }
            },

            .waiting_rpc_handshake_response => {
                const payload = self.mpTryReadFrame(slot, true) catch {
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp read handshake ans failed");
                    }
                    return;
                } orelse return;

                if (payload.len != 32) {
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp bad handshake ans len");
                    }
                    return;
                }
                if (!std.mem.eql(u8, payload[0..4], &middleproxy.rpc_handshake)) {
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp bad handshake ans type");
                    }
                    return;
                }
                if (!std.mem.eql(u8, payload[20..32], "IPIPPRPDTIME")) {
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp bad handshake pid");
                    }
                    return;
                }

                var local_addr: net.Address = undefined;
                var local_len: posix.socklen_t = @sizeOf(net.Address);
                posix.getsockname(slot.upstream_fd, &local_addr.any, &local_len) catch {
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp getsockname failed");
                    }
                    return;
                };

                var conn_id: [8]u8 = undefined;
                crypto.randomBytes(&conn_id);

                slot.middle_ctx = middleproxy.MiddleProxyContext.initWithBuffer(
                    self.state.allocator,
                    slot.mp_enc.?,
                    slot.mp_dec.?,
                    conn_id,
                    slot.mp_write_seq_no,
                    slot.peer_addr,
                    local_addr,
                    slot.proto_tag,
                    self.state.config.tag,
                    self.state.config.middleProxyBufferBytes(),
                ) catch {
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp context init failed");
                    }
                    return;
                };

                slot.mp_step = .done;
                self.startRelay(slot);
            },
            else => {},
        }
    }

    fn fallbackFromMiddleProxyToDirect(self: *EventLoop, slot: *ConnectionSlot) bool {
        if (slot.direct_fallback_addr == null or slot.direct_fallback_used) return false;

        _ = slot.obf_params orelse return false;
        slot.direct_fallback_used = true;
        slot.use_middle_proxy = false;
        slot.mp_step = .none;
        slot.mp_enc = null;
        slot.mp_dec = null;

        slot.use_fast_mode = self.state.config.fast_mode and
            (slot.dc_abs >= 1 and slot.dc_abs <= constants.tg_datacenters_v4.len);

        // Reset nonce path state to cleanly re-send direct nonce.
        if (slot.dc_initial_tail) |tail| {
            self.state.allocator.free(tail);
            slot.dc_initial_tail = null;
        }
        if (slot.tg_encryptor) |*enc| enc.wipe();
        if (slot.tg_decryptor) |*dec| dec.wipe();
        slot.tg_encryptor = null;
        slot.tg_decryptor = null;

        // If current connected endpoint is already the direct fallback, continue inline.
        const fallback = slot.direct_fallback_addr.?;
        if (slot.current_upstream_addr) |cur| {
            if (isSameIpEndpoint(cur, fallback)) {
                self.sendDcNonce(slot);
                return true;
            }
        }

        // Otherwise reconnect to direct fallback endpoint.
        self.cleanupFailedUpstreamConnect(slot);
        slot.upstream_candidate_next = 1;

        if (slot.upstream_candidates) |old| {
            self.state.allocator.free(old);
            slot.upstream_candidates = null;
        }
        const one = self.state.allocator.alloc(net.Address, 1) catch {
            return false;
        };
        one[0] = fallback;
        slot.upstream_candidates = one;

        self.startConnectUpstream(slot, fallback, .dc) catch |err| {
            log.warn("[{d}] direct fallback connect start failed: {any}", .{ slot.conn_id, err });
            return false;
        };

        var fb_buf: [64]u8 = undefined;
        const fb_str = formatAddress(fallback, &fb_buf);
        log.warn("[{d}] middle-proxy handshake failed, reconnecting direct to {s}", .{ slot.conn_id, fb_str });
        return true;
    }

    fn mpWriteFrame(self: *EventLoop, slot: *ConnectionSlot, payload: []const u8, encrypted: bool) !void {
        var plain: [mp_handshake_frame_buf_size]u8 = undefined;
        const total_len: usize = payload.len + 12;
        if (total_len > plain.len) return error.BadMiddleProxyFrameSize;

        std.mem.writeInt(u32, plain[0..4], @intCast(total_len), .little);
        std.mem.writeInt(i32, plain[4..8], slot.mp_write_seq_no, .little);
        slot.mp_write_seq_no += 1;

        @memcpy(plain[8 .. 8 + payload.len], payload);
        const checksum = middleproxy.crc32(plain[0 .. 8 + payload.len]);
        std.mem.writeInt(u32, plain[8 + payload.len ..][0..4], checksum, .little);

        var frame_len = total_len;
        if (encrypted) {
            const pad = (16 - (frame_len % 16)) % 16;
            if (frame_len + pad > plain.len) return error.BadMiddleProxyFrameSize;
            var i: usize = 0;
            while (i < pad) : (i += 4) {
                std.mem.writeInt(u32, plain[frame_len + i ..][0..4], 4, .little);
            }
            frame_len += pad;
            try slot.mp_enc.?.encryptInPlace(plain[0..frame_len]);
        }

        _ = try queueUpstream(slot, self.state.allocator, plain[0..frame_len]);
    }

    fn mpTryReadFrame(self: *EventLoop, slot: *ConnectionSlot, encrypted: bool) !?[]const u8 {
        const frame_buf = try ensureMpFrameBuf(slot, self.state.allocator);

        while (true) {
            if (slot.mp_frame_need == 0) {
                mpReadReset(slot, encrypted);
            }

            if (slot.mp_frame_have < slot.mp_frame_need) {
                const n = posix.read(slot.upstream_fd, frame_buf[slot.mp_frame_have..slot.mp_frame_need]) catch |err| {
                    if (err == error.WouldBlock) return null;
                    return err;
                };
                if (n == 0) return error.EndOfStream;
                slot.mp_frame_have += n;
                if (slot.mp_frame_have < slot.mp_frame_need) return null;
            }

            if (!encrypted) {
                if (slot.mp_frame_total_len == 0) {
                    slot.mp_frame_total_len = std.mem.readInt(u32, frame_buf[0..4], .little);
                    if (slot.mp_frame_total_len < 12 or slot.mp_frame_total_len > frame_buf.len) {
                        return error.BadMiddleProxyFrameSize;
                    }
                    slot.mp_frame_need = slot.mp_frame_total_len;
                    continue;
                }
            } else {
                if (!slot.mp_frame_first_decrypted) {
                    try slot.mp_dec.?.decryptInPlace(frame_buf[0..16]);
                    slot.mp_frame_first_decrypted = true;
                    slot.mp_frame_total_len = std.mem.readInt(u32, frame_buf[0..4], .little);
                    if (slot.mp_frame_total_len < 12 or slot.mp_frame_total_len > (1 << 24)) {
                        return error.BadMiddleProxyFrameSize;
                    }
                    slot.mp_frame_padded_len = if (slot.mp_frame_total_len % 16 == 0)
                        slot.mp_frame_total_len
                    else
                        slot.mp_frame_total_len + (16 - (slot.mp_frame_total_len % 16));
                    if (slot.mp_frame_padded_len > frame_buf.len) return error.BadMiddleProxyFrameSize;
                    slot.mp_frame_need = slot.mp_frame_padded_len;
                    if (slot.mp_frame_have < slot.mp_frame_need) return null;
                }

                if (slot.mp_frame_padded_len > 16) {
                    try slot.mp_dec.?.decryptInPlace(frame_buf[16..slot.mp_frame_padded_len]);
                }
            }

            const frame = frame_buf[0..slot.mp_frame_total_len];
            const msg_seq = std.mem.readInt(i32, frame[4..8], .little);
            if (msg_seq != slot.mp_read_seq_no) return error.BadMiddleProxySeqNo;
            slot.mp_read_seq_no += 1;

            const expected_checksum = std.mem.readInt(u32, frame[frame.len - 4 ..][0..4], .little);
            const computed_checksum = middleproxy.crc32(frame[0 .. frame.len - 4]);
            if (expected_checksum != computed_checksum) return error.BadMiddleProxyChecksum;

            // Copy payload into front of frame_buf so caller can consume before reset.
            const payload_len = frame.len - 12;
            std.mem.copyForwards(u8, frame_buf[0..payload_len], frame[8 .. frame.len - 4]);
            const payload = frame_buf[0..payload_len];

            mpReadReset(slot, encrypted);
            return payload;
        }
    }

    fn runTimers(self: *EventLoop) void {
        const now_ms = std.time.milliTimestamp();
        const now_ns = std.time.nanoTimestamp();

        const hi: usize = @intCast(self.pool.allocated_hi);
        for (self.pool.slots[0..hi]) |slot_opt| {
            const slot = slot_opt orelse continue;
            if (slot.phase == .idle) continue;

            if (slot.phase == .desync_wait and now_ns >= slot.desync_deadline_ns) {
                slot.phase = .writing_server_hello_rest;
                if (slot.server_hello) |sh| {
                    if (slot.server_hello_off < sh.len) {
                        if (queueClient(slot, self.state.allocator, sh[slot.server_hello_off..])) |_| {} else |_| {
                            self.closeSlot(slot, "desync rest write failed");
                            continue;
                        }
                        slot.server_hello_off = sh.len;
                    }
                }
            }

            if (slot.phase == .closing) {
                self.closeSlot(slot, "closing phase");
                continue;
            }

            if (slot.handshakeInProgress()) {
                if (slot.first_byte_at_ms == 0) {
                    if (now_ms - slot.created_at_ms > secondsToMs(self.state.config.idle_timeout_sec)) {
                        self.closeSlot(slot, "idle pre-first-byte timeout");
                        continue;
                    }
                } else if (now_ms - slot.first_byte_at_ms > secondsToMs(self.state.config.handshake_timeout_sec)) {
                    self.closeSlot(slot, "handshake timeout");
                    continue;
                }
            } else if (slot.phase == .relaying or slot.phase == .mask_relaying) {
                if (now_ms - slot.last_activity_ms > secondsToMs(self.state.config.idle_timeout_sec)) {
                    self.closeSlot(slot, "relay idle timeout");
                    continue;
                }
            }

            self.syncInterests(slot) catch |err| {
                log.debug("[{d}] syncInterests error in timer tick: {any}", .{ slot.conn_id, err });
                self.closeSlot(slot, "sync interest error");
            };
        }
    }

    fn syncInterests(self: *EventLoop, slot: *ConnectionSlot) !void {
        var want_client_in = false;
        var want_client_out = slot.hasClientPending();
        var want_upstream_in = false;
        var want_upstream_out = slot.hasUpstreamPending();

        switch (slot.phase) {
            .reading_tls_header,
            .reading_client_hello_body,
            .reading_mtproto_tls_header,
            .reading_mtproto_tls_body,
            => {
                want_client_in = true;
            },

            .writing_server_hello_first,
            .writing_server_hello_rest,
            => {
                want_client_out = true;
            },

            .desync_wait => {
                // Wait for timer tick only; keeping EPOLLOUT enabled here can
                // cause a busy loop because writable sockets trigger continuously.
            },

            .connecting_upstream => {
                want_client_in = false;
                want_upstream_out = true;
            },

            .writing_dc_nonce => {
                want_client_in = false;
                want_upstream_out = true;
            },

            .middle_proxy_handshake => {
                want_upstream_out = want_upstream_out or
                    slot.mp_step == .sending_rpc_nonce or
                    slot.mp_step == .sending_rpc_handshake;
                want_upstream_in = slot.mp_step == .waiting_rpc_nonce_response or
                    slot.mp_step == .waiting_rpc_handshake_response;
            },

            .relaying => {
                want_client_in = !slot.hasUpstreamPending();
                want_upstream_in = !slot.hasClientPending();
            },

            .mask_relaying => {
                want_client_in = !slot.hasUpstreamPending();
                want_upstream_in = !slot.hasClientPending();
            },

            else => {},
        }

        if (slot.client_fd != -1) {
            if (slot.client_interest_in != want_client_in or slot.client_interest_out != want_client_out) {
                try self.modFd(slot.client_fd, want_client_in, want_client_out);
                slot.client_interest_in = want_client_in;
                slot.client_interest_out = want_client_out;
            }
        }

        if (slot.upstream_fd != -1) {
            if (slot.upstream_interest_in != want_upstream_in or slot.upstream_interest_out != want_upstream_out) {
                try self.modFd(slot.upstream_fd, want_upstream_in, want_upstream_out);
                slot.upstream_interest_in = want_upstream_in;
                slot.upstream_interest_out = want_upstream_out;
            }
        }
    }

    fn closeSlot(self: *EventLoop, slot: *ConnectionSlot, reason: []const u8) void {
        if (slot.phase == .idle) return;
        log.debug("[{d}] closing: {s}", .{ slot.conn_id, reason });

        if (slot.client_fd != -1) {
            _ = self.delFd(slot.client_fd) catch {};
            self.pool.unmapFd(slot.client_fd);
            posix.close(slot.client_fd);
            slot.client_fd = -1;
        }

        if (slot.upstream_fd != -1) {
            _ = self.delFd(slot.upstream_fd) catch {};
            self.pool.unmapFd(slot.upstream_fd);
            posix.close(slot.upstream_fd);
            slot.upstream_fd = -1;
        }

        slot.resetOwnedBuffers(self.state.allocator);

        if (slot.active_reserved) {
            _ = self.state.active_connections.fetchSub(1, .monotonic);
            slot.active_reserved = false;
            self.closed_since_log += 1;
        }

        slot.phase = .idle;
        self.pool.release(slot);
    }

    fn addFd(self: *EventLoop, fd: posix.fd_t, want_in: bool, want_out: bool) !void {
        var events: u32 = linux.EPOLL.ERR | linux.EPOLL.HUP | linux.EPOLL.RDHUP;
        if (want_in) events |= linux.EPOLL.IN;
        if (want_out) events |= linux.EPOLL.OUT;

        var ev = linux.epoll_event{ .events = events, .data = .{ .fd = fd } };
        const rc = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_ADD, fd, &ev);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    fn modFd(self: *EventLoop, fd: posix.fd_t, want_in: bool, want_out: bool) !void {
        var events: u32 = linux.EPOLL.ERR | linux.EPOLL.HUP | linux.EPOLL.RDHUP;
        if (want_in) events |= linux.EPOLL.IN;
        if (want_out) events |= linux.EPOLL.OUT;

        var ev = linux.epoll_event{ .events = events, .data = .{ .fd = fd } };
        const rc = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_MOD, fd, &ev);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    fn delFd(self: *EventLoop, fd: posix.fd_t) !void {
        const rc = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, fd, null);
        switch (posix.errno(rc)) {
            .SUCCESS, .NOENT => return,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    fn appendPipelined(self: *EventLoop, slot: *ConnectionSlot, extra: []const u8) !void {
        if (extra.len == 0) return;
        if (slot.pipelined_data == null) {
            const buf = try self.state.allocator.alloc(u8, extra.len);
            @memcpy(buf, extra);
            slot.pipelined_data = buf;
            return;
        }

        const prev = slot.pipelined_data.?;
        const next = try self.state.allocator.alloc(u8, prev.len + extra.len);
        @memcpy(next[0..prev.len], prev);
        @memcpy(next[prev.len..], extra);
        self.state.allocator.free(prev);
        slot.pipelined_data = next;
    }
};

fn relayClientToUpstreamStep(slot: *ConnectionSlot, allocator: std.mem.Allocator) !RelayProgress {
    const read_buf = try ensureReadBuf(slot, allocator);
    var consumed_any = false;

    while (true) {
        if (slot.relay_tls_hdr_pos < tls_header_len) {
            const n = posix.read(slot.client_fd, slot.relay_tls_hdr[slot.relay_tls_hdr_pos..]) catch |err| {
                if (err == error.WouldBlock) return if (consumed_any) .partial else .none;
                return err;
            };
            if (n == 0) return error.EndOfStream;
            consumed_any = true;
            slot.relay_tls_hdr_pos += @intCast(n);

            if (slot.relay_tls_hdr_pos < tls_header_len) return .partial;

            slot.relay_record_type = slot.relay_tls_hdr[0];
            slot.relay_tls_body_len = std.mem.readInt(u16, slot.relay_tls_hdr[3..5], .big);
            slot.relay_tls_body_pos = 0;

            if (slot.relay_record_type == constants.tls_record_alert) return error.ConnectionReset;
            if (slot.relay_record_type != constants.tls_record_change_cipher and
                slot.relay_record_type != constants.tls_record_application)
            {
                return error.ConnectionReset;
            }
            if (slot.relay_tls_body_len == 0 or slot.relay_tls_body_len > constants.max_tls_ciphertext_size) {
                return error.ConnectionReset;
            }
        }

        const remaining = slot.relay_tls_body_len - slot.relay_tls_body_pos;
        if (remaining == 0) {
            slot.relay_tls_hdr_pos = 0;
            slot.relay_tls_body_pos = 0;
            slot.relay_tls_body_len = 0;
            if (consumed_any) return .partial;
            continue;
        }

        const want = @min(@as(usize, remaining), read_buf.len);
        const n = posix.read(slot.client_fd, read_buf[0..want]) catch |err| {
            if (err == error.WouldBlock) return if (consumed_any) .partial else .none;
            return err;
        };
        if (n == 0) return error.EndOfStream;

        consumed_any = true;
        slot.relay_tls_body_pos += @intCast(n);

        if (slot.relay_record_type == constants.tls_record_change_cipher) {
            if (slot.relay_tls_body_pos == slot.relay_tls_body_len) {
                slot.relay_tls_hdr_pos = 0;
                slot.relay_tls_body_pos = 0;
                slot.relay_tls_body_len = 0;
            }
            return .partial;
        }

        const payload = read_buf[0..n];
        if (slot.client_decryptor) |*dec| dec.apply(payload);

        if (slot.middle_ctx) |*mp| {
            const out_data = try mp.encapsulateC2S(payload);
            if (out_data.len > 0) {
                _ = try queueUpstream(slot, allocator, out_data);
            }
        } else if (slot.tg_encryptor) |*enc| {
            enc.apply(payload);
            _ = try queueUpstream(slot, allocator, payload);
        }

        slot.c2s_bytes += payload.len;

        if (slot.relay_tls_body_pos == slot.relay_tls_body_len) {
            slot.relay_tls_hdr_pos = 0;
            slot.relay_tls_body_pos = 0;
            slot.relay_tls_body_len = 0;
            return .forwarded;
        }

        return .partial;
    }
}

fn relayUpstreamToClientStep(slot: *ConnectionSlot, allocator: std.mem.Allocator) !RelayProgress {
    const read_buf = try ensureReadBuf(slot, allocator);
    const n = posix.read(slot.upstream_fd, read_buf) catch |err| {
        if (err == error.WouldBlock) return .none;
        return err;
    };
    if (n == 0) return error.EndOfStream;

    const raw = read_buf[0..n];

    if (slot.middle_ctx) |*mp| {
        const payload = try mp.decapsulateS2C(raw);
        if (payload.len == 0) return .partial;
        if (slot.client_encryptor) |*enc| enc.apply(payload);
        try queueTlsAppRecords(slot, allocator, payload);
        slot.s2c_bytes += payload.len;
        return .forwarded;
    }

    if (!slot.use_fast_mode) {
        if (slot.tg_decryptor) |*dec| dec.apply(raw);
        if (slot.client_encryptor) |*enc| enc.apply(raw);
    }

    try queueTlsAppRecords(slot, allocator, raw);
    slot.s2c_bytes += raw.len;
    return .forwarded;
}

fn queueTlsAppRecords(slot: *ConnectionSlot, allocator: std.mem.Allocator, payload: []u8) !void {
    var off: usize = 0;
    while (off < payload.len) {
        const chunk_len = @min(payload.len - off, slot.drs.nextRecordSize());
        const frame_len = tls_header_len + chunk_len;
        var frame = try allocator.alloc(u8, frame_len);
        errdefer allocator.free(frame);

        frame[0] = constants.tls_record_application;
        frame[1] = constants.tls_version[0];
        frame[2] = constants.tls_version[1];
        std.mem.writeInt(u16, frame[3..5], @intCast(chunk_len), .big);
        @memcpy(frame[5..], payload[off .. off + chunk_len]);

        _ = try queueClientOwned(slot, allocator, frame);
        slot.drs.recordSent(chunk_len);
        off += chunk_len;
    }
}

fn epollCreate() !posix.fd_t {
    const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => |err| return posix.unexpectedErrno(err),
    }
}

fn requiredFdsForConnections(max_connections: u32) usize {
    return @as(usize, max_connections) * 2 + nofile_fd_overhead;
}

fn maxConnectionsForNofile(soft_nofile: usize) u32 {
    if (soft_nofile <= nofile_fd_overhead + 2) return 32;

    const cap = (soft_nofile - nofile_fd_overhead) / 2;
    const capped_u32: u32 = @intCast(@min(cap, @as(usize, std.math.maxInt(u32))));
    return @max(@as(u32, 32), capped_u32);
}

fn getNofileSoftLimit() ?usize {
    if (builtin.os.tag != .linux) return null;

    var lim: linux.rlimit = undefined;
    const rc = linux.getrlimit(.NOFILE, &lim);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return null,
    }

    return @intCast(lim.cur);
}

fn checkNofileLimit(required: usize, max_connections: u32) void {
    const soft = getNofileSoftLimit() orelse return;

    if (soft >= required) return;

    log.warn("RLIMIT_NOFILE soft limit is {d}, recommended >= {d} for max_connections={d}", .{
        soft,
        required,
        max_connections,
    });
}

fn setNonBlocking(fd: posix.fd_t) void {
    var fl_flags = posix.fcntl(fd, posix.F.GETFL, 0) catch return;
    const nonblock: @TypeOf(fl_flags) = @bitCast(@as(u64, @as(u32, @bitCast(posix.O{ .NONBLOCK = true }))));
    fl_flags |= nonblock;
    _ = posix.fcntl(fd, posix.F.SETFL, fl_flags) catch return;
}

fn secondsToMs(sec: u32) i64 {
    return @as(i64, @intCast(sec)) * std.time.ms_per_s;
}

fn setSendTimeout(fd: posix.fd_t, timeout_sec: u32) void {
    const tv = posix.timeval{ .sec = @intCast(timeout_sec), .usec = 0 };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch return;
}

fn setTcpKeepalive(fd: posix.fd_t) void {
    const sol_tcp: i32 = 6;

    const enable: c_int = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&enable)) catch return;

    const idle: c_int = 60;
    posix.setsockopt(fd, sol_tcp, 4, std.mem.asBytes(&idle)) catch return;

    const interval: c_int = 10;
    posix.setsockopt(fd, sol_tcp, 5, std.mem.asBytes(&interval)) catch return;

    const count: c_int = 3;
    posix.setsockopt(fd, sol_tcp, 6, std.mem.asBytes(&count)) catch return;
}

fn configureRelaySocket(fd: posix.fd_t) void {
    setTcpKeepalive(fd);
    setSendTimeout(fd, 30);
}

fn formatAddress(addr: net.Address, buf: *[64]u8) []const u8 {
    switch (addr.any.family) {
        posix.AF.INET => {
            return std.fmt.bufPrint(buf, "[ipv4]:{d}", .{
                std.mem.bigToNative(u16, addr.in.sa.port),
            }) catch "?";
        },
        posix.AF.INET6 => {
            const bytes: *const [16]u8 = @ptrCast(&addr.in6.sa.addr);
            const is_ipv4_mapped = std.mem.eql(u8, bytes[0..10], &[_]u8{0} ** 10) and
                std.mem.eql(u8, bytes[10..12], &[_]u8{ 0xff, 0xff });

            if (is_ipv4_mapped) {
                return std.fmt.bufPrint(buf, "[ipv4]:{d}", .{
                    std.mem.bigToNative(u16, addr.in6.sa.port),
                }) catch "?";
            }
            return std.fmt.bufPrint(buf, "[ipv6]:{d}", .{
                std.mem.bigToNative(u16, addr.in6.sa.port),
            }) catch "?";
        },
        else => return "?",
    }
}

fn ensureReadBuf(slot: *ConnectionSlot, allocator: std.mem.Allocator) ![]u8 {
    if (slot.read_buf) |buf| return buf;
    const buf = try allocator.alloc(u8, read_buf_size);
    slot.read_buf = buf;
    return buf;
}

fn ensureMpFrameBuf(slot: *ConnectionSlot, allocator: std.mem.Allocator) ![]u8 {
    if (slot.mp_frame_buf) |buf| return buf;
    const buf = try allocator.alloc(u8, mp_handshake_frame_buf_size);
    slot.mp_frame_buf = buf;
    return buf;
}

fn runCurl(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
    });
    defer allocator.free(result.stderr);
    errdefer allocator.free(result.stdout);

    switch (result.term) {
        .Exited => |code| if (code != 0) return error.CurlFailed,
        else => return error.CurlFailed,
    }

    return result.stdout;
}

fn fetchUrlBytes(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
    const strict_argv = [_][]const u8{ "curl", "-fsSL", "--max-time", "10", url };
    return runCurl(allocator, &strict_argv);
}

fn isSameIpEndpoint(a: net.Address, b: net.Address) bool {
    if (a.any.family != b.any.family) return false;

    if (a.any.family == posix.AF.INET) {
        return a.in.sa.addr == b.in.sa.addr and a.in.sa.port == b.in.sa.port;
    }

    if (a.any.family == posix.AF.INET6) {
        return std.mem.eql(u8, &a.in6.sa.addr, &b.in6.sa.addr) and a.in6.sa.port == b.in6.sa.port;
    }

    return false;
}

fn appendUniqueAddress(addrs: *[16]net.Address, count: *usize, addr: net.Address) void {
    if (count.* >= addrs.len) return;
    for (addrs[0..count.*]) |existing| {
        if (isSameIpEndpoint(existing, addr)) return;
    }
    addrs[count.*] = addr;
    count.* += 1;
}

fn buildDcConnectPlan(
    cfg: *const Config,
    dc_abs: usize,
    dc_idx: i16,
    snapshot: ?*const ProxyState.MiddleProxySnapshot,
) DcConnectPlan {
    var plan = DcConnectPlan{};
    plan.is_media_path = (dc_idx < 0) or (dc_abs == 203);

    if (cfg.datacenter_override) |override| {
        plan.candidates[0] = override;
        plan.count = 1;
        plan.use_middle_proxy = false;
        plan.direct_fallback = null;
        return plan;
    }

    var middle_addr: ?net.Address = null;
    if (snapshot) |snap| {
        middle_addr = snap.getForDc(dc_abs);
    }

    const force_media_middle_proxy = plan.is_media_path and middle_addr != null;
    plan.use_middle_proxy = if (force_media_middle_proxy)
        true
    else
        cfg.use_middle_proxy and middle_addr != null;

    if (!plan.use_middle_proxy) {
        plan.candidates[0] = constants.getDcAddressV4(dc_abs);
        plan.count = 1;
        plan.direct_fallback = null;
        return plan;
    }

    if (snapshot) |snap| {
        if (dc_abs == 4 and snap.addrs_dc4_len > 0) {
            var n: usize = 0;
            while (n < snap.addrs_dc4_len and plan.count < plan.candidates.len) : (n += 1) {
                appendUniqueAddress(&plan.candidates, &plan.count, snap.addrs_dc4[n]);
            }
        } else if (dc_abs == 203 and snap.addrs_203_len > 0) {
            var n: usize = 0;
            while (n < snap.addrs_203_len and plan.count < plan.candidates.len) : (n += 1) {
                appendUniqueAddress(&plan.candidates, &plan.count, snap.addrs_203[n]);
            }
        }
    }

    if (plan.count == 0 and middle_addr != null) {
        appendUniqueAddress(&plan.candidates, &plan.count, middle_addr.?);
    }

    if (plan.count == 0) {
        // Safety fallback: if cache has no middle-proxy endpoint for this DC,
        // avoid dropping valid users and go direct.
        plan.use_middle_proxy = false;
        plan.candidates[0] = constants.getDcAddressV4(dc_abs);
        plan.count = 1;
        plan.direct_fallback = null;
        return plan;
    }

    // Non-media paths may fall back to direct DC if all middle-proxy candidates fail.
    plan.direct_fallback = if (!plan.is_media_path) constants.getDcAddressV4(dc_abs) else null;
    return plan;
}

fn parseMiddleProxyAddressesForDc(config_text: []const u8, target_dc: i16, out: []net.Address) usize {
    if (out.len == 0) return 0;

    var lines = std.mem.splitScalar(u8, config_text, '\n');
    var count: usize = 0;

    while (lines.next()) |raw_line| {
        var line = std.mem.trim(u8, raw_line, &[_]u8{ ' ', '\t', '\r' });
        if (line.len == 0 or line[0] == '#') continue;
        if (line[line.len - 1] == ';') line = line[0 .. line.len - 1];

        var parts = std.mem.tokenizeAny(u8, line, " \t");
        const keyword = parts.next() orelse continue;
        if (!std.mem.eql(u8, keyword, "proxy_for")) continue;

        const dc_text = parts.next() orelse continue;
        const host_port = parts.next() orelse continue;

        const dc_idx = std.fmt.parseInt(i16, dc_text, 10) catch continue;
        if (dc_idx != target_dc and dc_idx != -target_dc) continue;

        const parsed = net.Address.parseIpAndPort(host_port) catch continue;

        var dup = false;
        for (out[0..count]) |existing| {
            if (existing.eql(parsed)) {
                dup = true;
                break;
            }
        }
        if (dup) continue;

        out[count] = parsed;
        count += 1;
        if (count == out.len) break;
    }

    return count;
}

fn trySelectReachableMiddleProxy(candidates: []const net.Address, timeout_ms: i32) ?net.Address {
    for (candidates) |addr| {
        if (isAddressReachable(addr, timeout_ms)) return addr;
    }
    return null;
}

fn addressesEqual(a: []const net.Address, b: []const net.Address) bool {
    if (a.len != b.len) return false;
    for (a, b) |lhs, rhs| {
        if (!lhs.eql(rhs)) return false;
    }
    return true;
}

fn isAddressReachable(address: net.Address, timeout_ms: i32) bool {
    const sock_flags = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
    const fd = posix.socket(address.any.family, sock_flags, posix.IPPROTO.TCP) catch return false;
    defer posix.close(fd);

    posix.connect(fd, &address.any, address.getOsSockLen()) catch |err| switch (err) {
        error.WouldBlock, error.ConnectionPending => {},
        else => return false,
    };

    var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
    const ready = posix.poll(&fds, timeout_ms) catch return false;
    if (ready == 0) return false;
    const revents = fds[0].revents;
    if ((revents & posix.POLL.OUT) == 0) return false;
    if ((revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL)) != 0) return false;
    posix.getsockoptError(fd) catch return false;
    return true;
}

fn parseMiddleProxyAddressForDc(config_text: []const u8, target_dc: i16) ?net.Address {
    var one: [1]net.Address = undefined;
    const n = parseMiddleProxyAddressesForDc(config_text, target_dc, &one);
    if (n == 0) return null;
    return one[0];
}

fn queueOrWriteMsg(fd: posix.fd_t, queue: *MessageQueue, data: []const u8) !bool {
    if (data.len == 0) return true;

    if (queue.isEmpty()) {
        const n = posix.write(fd, data) catch |err| {
            if (err == error.WouldBlock) {
                try queue.appendCopy(data);
                return false;
            }
            return err;
        };

        if (n == data.len) return true;
        try queue.appendCopy(data[n..]);
        return false;
    }

    try queue.appendCopy(data);
    return false;
}

fn queueOrWriteOwnedMsg(fd: posix.fd_t, queue: *MessageQueue, owned: []u8) !bool {
    if (owned.len == 0) {
        queue.allocator.free(owned);
        return true;
    }

    if (queue.isEmpty()) {
        const n = posix.write(fd, owned) catch |err| {
            if (err == error.WouldBlock) {
                try queue.appendOwned(owned);
                return false;
            }
            queue.allocator.free(owned);
            return err;
        };

        if (n == owned.len) {
            queue.allocator.free(owned);
            return true;
        }

        const remaining = owned[n..];
        try queue.appendCopy(remaining);
        queue.allocator.free(owned);
        return false;
    }

    try queue.appendOwned(owned);
    return false;
}

fn flushQueue(fd: posix.fd_t, queue: *MessageQueue) !bool {
    if (queue.isEmpty()) return true;

    var iovecs: [max_scatter_parts]posix.iovec_const = undefined;

    while (!queue.isEmpty()) {
        const n_iov = queue.prepareIovecs(iovecs[0..]);
        if (n_iov == 0) return true;

        const n = posix.writev(fd, iovecs[0..n_iov]) catch |err| {
            if (err == error.WouldBlock) return false;
            return err;
        };

        if (n == 0) return error.ConnectionReset;
        try queue.consume(n);

        if (n < iovecs[0].len) return false;
    }

    return true;
}

fn slotQueueClient(slot: *ConnectionSlot, allocator: std.mem.Allocator, data: []const u8) !bool {
    _ = allocator;
    return queueOrWriteMsg(slot.client_fd, &slot.client_queue, data);
}

fn slotQueueClientOwned(slot: *ConnectionSlot, allocator: std.mem.Allocator, owned: []u8) !bool {
    _ = allocator;
    return queueOrWriteOwnedMsg(slot.client_fd, &slot.client_queue, owned);
}

fn slotQueueUpstream(slot: *ConnectionSlot, allocator: std.mem.Allocator, data: []const u8) !bool {
    _ = allocator;
    return queueOrWriteMsg(slot.upstream_fd, &slot.upstream_queue, data);
}

fn slotFlushClientPending(slot: *ConnectionSlot, allocator: std.mem.Allocator) !bool {
    _ = allocator;
    return flushQueue(slot.client_fd, &slot.client_queue);
}

fn slotFlushUpstreamPending(slot: *ConnectionSlot, allocator: std.mem.Allocator) !bool {
    _ = allocator;
    return flushQueue(slot.upstream_fd, &slot.upstream_queue);
}

fn slotMpReadReset(slot: *ConnectionSlot, encrypted: bool) void {
    slot.mp_frame_have = 0;
    slot.mp_frame_total_len = 0;
    slot.mp_frame_padded_len = 0;
    slot.mp_frame_encrypted = encrypted;
    slot.mp_frame_first_decrypted = false;
    slot.mp_frame_need = if (encrypted) 16 else 4;
}

// Method forwarding helpers (keeps call sites readable)
fn queueClient(self: *ConnectionSlot, allocator: std.mem.Allocator, data: []const u8) !bool {
    return slotQueueClient(self, allocator, data);
}

fn queueClientOwned(self: *ConnectionSlot, allocator: std.mem.Allocator, data: []u8) !bool {
    return slotQueueClientOwned(self, allocator, data);
}

fn queueUpstream(self: *ConnectionSlot, allocator: std.mem.Allocator, data: []const u8) !bool {
    return slotQueueUpstream(self, allocator, data);
}

fn flushClientPending(self: *ConnectionSlot, allocator: std.mem.Allocator) !bool {
    return slotFlushClientPending(self, allocator);
}

fn flushUpstreamPending(self: *ConnectionSlot, allocator: std.mem.Allocator) !bool {
    return slotFlushUpstreamPending(self, allocator);
}

fn mpReadReset(self: *ConnectionSlot, encrypted: bool) void {
    return slotMpReadReset(self, encrypted);
}

test "parse middle proxy address for dc203" {
    const cfg =
        "# force_probability 10 10\n" ++
        "default 2;\n" ++
        "proxy_for 1 149.154.175.50:8888;\n" ++
        "proxy_for 203 91.105.192.110:443;\n" ++
        "proxy_for -203 91.105.192.110:443;\n";

    const addr = parseMiddleProxyAddressForDc(cfg, 203) orelse return error.TestExpectedEqual;
    try std.testing.expect(addr.any.family == posix.AF.INET);
    try std.testing.expectEqual(@as(u16, 443), std.mem.bigToNative(u16, addr.in.sa.port));
}

test "DRS disabled fixed size" {
    var drs = DynamicRecordSizer.init(false);
    try std.testing.expectEqual(DynamicRecordSizer.initial_size, drs.nextRecordSize());
    for (0..32) |_| drs.recordSent(1369);
    try std.testing.expectEqual(DynamicRecordSizer.initial_size, drs.nextRecordSize());
}

test "DRS enabled ramps" {
    var drs = DynamicRecordSizer.init(true);
    for (0..8) |_| drs.recordSent(1369);
    try std.testing.expectEqual(DynamicRecordSizer.full_size, drs.nextRecordSize());
}

test "message queue consume is stable" {
    var q = MessageQueue{ .allocator = std.testing.allocator };
    defer q.deinit();

    try q.appendCopy("abc");
    try q.appendCopy("defg");
    try std.testing.expectEqual(@as(usize, 7), q.total_len);

    try q.consume(2);
    try std.testing.expectEqual(@as(usize, 5), q.total_len);

    var iov: [8]posix.iovec_const = undefined;
    const n = q.prepareIovecs(iov[0..]);
    try std.testing.expect(n >= 1);
    try std.testing.expectEqual(@as(u8, 'c'), iov[0].base[0]);

    try q.consume(5);
    try std.testing.expect(q.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), q.offset);
    try std.testing.expectEqual(@as(usize, 0), q.head_idx);
}

test "epoll hangup helper" {
    try std.testing.expect(hasFatalEpollHangup(linux.EPOLL.RDHUP));
    try std.testing.expect(hasFatalEpollHangup(linux.EPOLL.HUP));
    try std.testing.expect(hasFatalEpollHangup(linux.EPOLL.ERR));
    try std.testing.expect(!hasFatalEpollHangup(linux.EPOLL.IN));
}

test "fd requirement helpers" {
    try std.testing.expectEqual(@as(usize, 131582), requiredFdsForConnections(65535));
    try std.testing.expectEqual(@as(u32, 65535), maxConnectionsForNofile(131582));
    try std.testing.expectEqual(@as(u32, 32511), maxConnectionsForNofile(65535));
}
