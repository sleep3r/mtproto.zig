//! Proxy core — single-threaded Linux epoll event loop.
//!
//! This replaces the thread-per-connection model with a pre-allocated
//! connection pool and non-blocking state machine.

const std = @import("std");
const builtin = @import("builtin");
const net = std.Io.net;
const Address = net.IpAddress;
const posix = std.posix;
const linux = std.os.linux;

const constants = @import("../protocol/constants.zig");
const crypto = @import("../crypto/crypto.zig");
const obfuscation = @import("../protocol/obfuscation.zig");
const middleproxy = @import("../protocol/middleproxy.zig");
const tls = @import("../protocol/tls.zig");
const Config = @import("../config.zig").Config;
const upstream_mod = @import("upstream.zig");
const tunnel_mod = @import("../tunnel.zig");
const socks5 = @import("socks5.zig");
const http_connect = @import("http_connect.zig");
const SubnetRateLimit = @import("subnet_rate_limit.zig").SubnetRateLimit;
const DynamicRecordSizer = @import("drs.zig").DynamicRecordSizer;
const ReplayCache = @import("replay_cache.zig").ReplayCache;
const MessageQueue = @import("message_queue.zig").MessageQueue;
const queue_io = @import("queue_io.zig");
const middle_proxy_routing = @import("middle_proxy_routing.zig");
const socket_utils = @import("socket_utils.zig");
const network_detect = @import("network_detect.zig");
const http_fetch = @import("http_fetch.zig");
const fd_limits = @import("fd_limits.zig");
const connection_phase = @import("connection_phase.zig");
const net_helpers = @import("net_helpers.zig");
const connection_pool_mod = @import("connection_pool.zig");
const relay_steps = @import("relay_steps.zig");
const middle_proxy_frames = @import("middle_proxy_frames.zig");
const middle_proxy_handshake = @import("middle_proxy_handshake.zig");
const proxy_upstream_handshake = @import("proxy_upstream_handshake.zig");
const middle_proxy_fallback = @import("middle_proxy_fallback.zig");
const dc_nonce = @import("dc_nonce.zig");
const upstream_failover = @import("upstream_failover.zig");
const runtime_log = @import("../runtime_log.zig");

test {
    // Keep extracted proxy submodule tests in the default `zig build test` run.
    _ = @import("subnet_rate_limit.zig");
    _ = @import("drs.zig");
    _ = @import("replay_cache.zig");
    _ = @import("message_queue.zig");
    _ = @import("queue_io.zig");
    _ = @import("middle_proxy_routing.zig");
    _ = @import("socket_utils.zig");
    _ = @import("network_detect.zig");
    _ = @import("http_fetch.zig");
    _ = @import("fd_limits.zig");
    _ = @import("connection_phase.zig");
    _ = @import("net_helpers.zig");
    _ = @import("connection_pool.zig");
    _ = @import("relay_steps.zig");
    _ = @import("middle_proxy_frames.zig");
    _ = @import("middle_proxy_handshake.zig");
    _ = @import("proxy_upstream_handshake.zig");
    _ = @import("middle_proxy_fallback.zig");
    _ = @import("dc_nonce.zig");
    _ = @import("upstream_failover.zig");
}

const log = std.log.scoped(.proxy);

const tls_header_len = 5;
const event_loop_wait_ms: i32 = 37;
const desync_wait_poll_ms: i32 = 3;
const accept_backoff_ms: i64 = 500;
const accept_backoff_ns: i128 = @as(i128, accept_backoff_ms) * std.time.ns_per_ms;
const accept_batch_limit: usize = 256;
const stats_log_interval_s: i64 = 10;
const stats_log_interval_ns: i128 = @as(i128, stats_log_interval_s) * std.time.ns_per_s;
const timer_scan_budget: usize = 512;
const middle_proxy_config_url = "https://core.telegram.org/getProxyConfig";
const middle_proxy_secret_url = "https://core.telegram.org/getProxySecret";
const middle_proxy_update_period_ns: u64 = 24 * 60 * 60 * std.time.ns_per_s;
const tunnel_socket_mark: u32 = 200;
const min_nofile_soft: usize = 65535;
const client_hello_inline_size: usize = 512;
const mp_handshake_frame_buf_size: usize = 2048;
const read_buf_size: usize = 32 * 1024;
const max_pipelined_handshake_bytes: usize = 128 * 1024;
const graceful_shutdown_check_ms: i32 = 100;

const upstream_candidates_inline_cap: usize = 4;

const CompatRwLock = struct {
    mutex: std.Io.Mutex = .init,

    fn io() std.Io {
        return std.Io.Threaded.global_single_threaded.io();
    }

    fn lock(self: *CompatRwLock) void {
        self.mutex.lockUncancelable(io());
    }

    fn unlock(self: *CompatRwLock) void {
        self.mutex.unlock(io());
    }

    fn lockShared(self: *CompatRwLock) void {
        self.mutex.lockUncancelable(io());
    }

    fn unlockShared(self: *CompatRwLock) void {
        self.mutex.unlock(io());
    }
};

const UpstreamKind = enum {
    none,
    dc,
    mask,
};

const MiddleProxyHandshakeStep = enum {
    none,
    sending_rpc_nonce,
    waiting_rpc_nonce_response,
    sending_rpc_handshake,
    waiting_rpc_handshake_response,
    done,
};

const DcConnectPlan = middle_proxy_routing.DcConnectPlan;
const buildDcConnectPlan = middle_proxy_routing.buildDcConnectPlan;
const parseMiddleProxyAddressesForDc = middle_proxy_routing.parseMiddleProxyAddressesForDc;
const trySelectReachableMiddleProxy = middle_proxy_routing.trySelectReachableMiddleProxy;
const addressesEqual = middle_proxy_routing.addressesEqual;

const realtimeSeconds = socket_utils.realtimeSeconds;
const nowMs = socket_utils.nowMs;
const nowNs = socket_utils.nowNs;
const sleepNs = socket_utils.sleepNs;
const closeFd = socket_utils.closeFd;
const checkSocketConnectError = socket_utils.checkSocketConnectError;
const acceptClient = socket_utils.acceptClient;
const localSocketAddress = socket_utils.localSocketAddress;
const setNonBlocking = socket_utils.setNonBlocking;
const secondsToMs = socket_utils.secondsToMs;
const setTcpNoDelay = socket_utils.setTcpNoDelay;
const configureRelaySocket = socket_utils.configureRelaySocket;
const formatAddress = socket_utils.formatAddress;

const parseIpv4Literal = network_detect.parseIpv4Literal;
const parseListenAddress = network_detect.parseListenAddress;
const isRunningInNonInitNetns = network_detect.isRunningInNonInitNetns;
const detectAwgEndpointIpv4 = network_detect.detectAwgEndpointIpv4;
const formatIpv4Bytes = network_detect.formatIpv4Bytes;
const ipv4NetworkToHostBytes = network_detect.ipv4NetworkToHostBytes;
const fetchUrlBytes = http_fetch.fetchUrlBytes;
const fetchUrlBytesViaInterface = http_fetch.fetchUrlBytesViaInterface;
const requiredFdsForConnections = fd_limits.requiredFdsForConnections;
const maxConnectionsForNofile = fd_limits.maxConnectionsForNofile;
const getNofileSoftLimit = fd_limits.getNofileSoftLimit;
const checkNofileLimit = fd_limits.checkNofileLimit;
const epollCreate = socket_utils.epollCreate;
const ConnectionPhase = connection_phase.ConnectionPhase;
const hasFatalEpollHangup = connection_phase.hasFatalEpollHangup;
const shouldCloseOnFatalHangup = connection_phase.shouldCloseOnFatalHangup;
const RelayProgress = relay_steps.RelayProgress;
const AddressList = net_helpers.AddressList;
const ip4 = net_helpers.ip4;
const ip6 = net_helpers.ip6;
const isIpv6 = net_helpers.isIpv6;
const addressEql = net_helpers.addressEql;
const getAddressList = net_helpers.getAddressList;

fn detectPublicIpv4(allocator: std.mem.Allocator) ?[4]u8 {
    return network_detect.detectPublicIpv4(allocator, fetchUrlBytes);
}

const ConnectionSlot = struct {
    index: u32 = 0,
    conn_id: u64 = 0,

    client_fd: posix.fd_t = -1,
    upstream_fd: posix.fd_t = -1,
    upstream_kind: UpstreamKind = .none,
    peer_addr: Address = undefined,

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

    upstream_candidates_inline: [upstream_candidates_inline_cap]Address = undefined,
    upstream_candidates_heap: ?[]Address = null,
    upstream_candidate_count: u8 = 0,
    upstream_candidate_next: u8 = 0,
    direct_fallback_addr: ?Address = null,
    direct_fallback_used: bool = false,
    current_upstream_addr: ?Address = null,

    // Pending initial bytes for direct DC path (promotion tag)
    dc_initial_tail: ?[]u8 = null,

    // Relay parsing state (C2S TLS records)
    relay_tls_hdr: [tls_header_len]u8 = undefined,
    relay_tls_hdr_pos: u8 = 0,
    relay_tls_body_len: u16 = 0,
    relay_tls_body_pos: u16 = 0,
    relay_record_type: u8 = 0,

    // Placeholder until `DynamicRecordSizer.init` is called with the runtime
    // config value; kept consistent with the enabled=false invariant so the
    // sizer is immediately usable even if init() is ever skipped.
    drs: DynamicRecordSizer = DynamicRecordSizer{
        .current_size = DynamicRecordSizer.full_size,
        .records_sent = 0,
        .bytes_sent = 0,
        .enabled = false,
    },
    c2s_bytes: u64 = 0,
    s2c_bytes: u64 = 0,
    traffic_client_to_upstream_counter: ?*std.atomic.Value(u64) = null,
    traffic_upstream_to_client_counter: ?*std.atomic.Value(u64) = null,
    user_metrics: ?*ProxyState.UserMetrics = null,

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

    // Non-blocking proxy handshake state (SOCKS5 / HTTP CONNECT)
    proxy_handshake_buf: [http_connect.max_response_size]u8 = undefined,
    proxy_handshake_pos: u16 = 0,
    proxy_handshake_len: u16 = 0,
    proxy_target_addr: ?Address = null,

    // Current epoll interests
    client_interest_in: bool = false,
    client_interest_out: bool = false,
    upstream_interest_in: bool = false,
    upstream_interest_out: bool = false,
    desync_wait_enqueued: bool = false,

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
            .proxy_socks5_greeting,
            .proxy_socks5_greeting_resp,
            .proxy_socks5_auth,
            .proxy_socks5_auth_resp,
            .proxy_socks5_connect,
            .proxy_socks5_connect_resp,
            .proxy_http_connect,
            .proxy_http_connect_resp,
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

        if (self.upstream_candidates_heap) |buf| allocator.free(buf);
        self.upstream_candidates_heap = null;
        self.upstream_candidate_count = 0;
        self.upstream_candidate_next = 0;
        self.direct_fallback_addr = null;
        self.direct_fallback_used = false;
        self.current_upstream_addr = null;
        self.dc_abs = 0;
        self.is_media_path = false;
        self.user_metrics = null;

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

    fn upstreamCandidates(self: *const ConnectionSlot) []const Address {
        const count: usize = self.upstream_candidate_count;
        if (count == 0) return &.{};
        if (self.upstream_candidates_heap) |buf| return buf[0..count];
        return self.upstream_candidates_inline[0..count];
    }

    fn setUpstreamCandidates(self: *ConnectionSlot, allocator: std.mem.Allocator, candidates: []const Address) !void {
        if (self.upstream_candidates_heap) |buf| {
            allocator.free(buf);
            self.upstream_candidates_heap = null;
        }

        if (candidates.len == 0) {
            self.upstream_candidate_count = 0;
            return;
        }

        if (candidates.len <= self.upstream_candidates_inline.len) {
            @memcpy(self.upstream_candidates_inline[0..candidates.len], candidates);
            self.upstream_candidate_count = @intCast(candidates.len);
            return;
        }

        const heap = try allocator.alloc(Address, candidates.len);
        errdefer allocator.free(heap);

        @memcpy(heap, candidates);
        self.upstream_candidates_heap = heap;
        self.upstream_candidate_count = @intCast(candidates.len);
    }
};

pub const BenchCandidatePath = struct {
    slot: ConnectionSlot = .{},

    pub fn deinit(self: *BenchCandidatePath, allocator: std.mem.Allocator) void {
        self.slot.resetOwnedBuffers(allocator);
    }

    pub fn apply(self: *BenchCandidatePath, allocator: std.mem.Allocator, candidates: []const Address) !usize {
        if (candidates.len == 0) return error.BenchEmptyCandidates;

        try self.slot.setUpstreamCandidates(allocator, candidates);

        const prepared = self.slot.upstreamCandidates();
        self.slot.upstream_candidate_next = 1;
        self.slot.current_upstream_addr = prepared[0];
        return prepared.len;
    }
};

const ConnectionPool = connection_pool_mod.ConnectionPool(ConnectionSlot);

const SignalController = struct {
    fd: posix.fd_t,
    old_mask: posix.sigset_t,

    fn init() !SignalController {
        var mask = posix.sigemptyset();
        posix.sigaddset(&mask, .TERM);
        posix.sigaddset(&mask, .INT);
        posix.sigaddset(&mask, .HUP);
        posix.sigaddset(&mask, .USR1);

        var old_mask: posix.sigset_t = undefined;
        posix.sigprocmask(posix.SIG.BLOCK, &mask, &old_mask);
        errdefer posix.sigprocmask(posix.SIG.SETMASK, &old_mask, null);

        const fd = try posix.signalfd(-1, &mask, linux.SFD.CLOEXEC | linux.SFD.NONBLOCK);
        return .{
            .fd = fd,
            .old_mask = old_mask,
        };
    }

    fn deinit(self: *SignalController) void {
        closeFd(self.fd);
        posix.sigprocmask(posix.SIG.SETMASK, &self.old_mask, null);
    }
};

pub const ProxyState = struct {
    pub const UserMetrics = struct {
        name: []const u8,
        connections_active: std.atomic.Value(u32),
        client_to_upstream_bytes_total: std.atomic.Value(u64),
        upstream_to_client_bytes_total: std.atomic.Value(u64),
    };

    pub const MetricsSnapshot = struct {
        start_time_seconds: i64,
        uptime_seconds: i64,
        connections_active: u32,
        connections_max: u32,
        handshakes_inflight: u32,
        connections_accepted_total: u64,
        connections_closed_total: u64,
        connections_total: u64,
        accept_paused: bool,
        saturation_paused: bool,
        drops_capacity_total: u64,
        drops_saturation_total: u64,
        drops_rate_limit_total: u64,
        drops_handshake_budget_total: u64,
        handshake_timeouts_total: u64,
        middleproxy_fallback_total: u64,
        client_to_upstream_bytes_total: u64,
        upstream_to_client_bytes_total: u64,
        config_port: u16,
        config_max_connections: u32,
        middleproxy_enabled: bool,
        fast_mode_enabled: bool,
        mask_enabled: bool,
        desync_enabled: bool,
        drs_enabled: bool,
    };

    allocator: std.mem.Allocator,
    config_path: []const u8,
    config: Config,
    user_secrets: []const obfuscation.UserSecret,
    user_metrics: []UserMetrics,
    start_time_seconds: i64,
    connection_count: std.atomic.Value(u64),
    closed_count: std.atomic.Value(u64),
    client_to_upstream_bytes_total: std.atomic.Value(u64),
    upstream_to_client_bytes_total: std.atomic.Value(u64),
    active_connections: std.atomic.Value(u32),
    handshakes_inflight: std.atomic.Value(u32),
    accept_paused: std.atomic.Value(bool),
    saturation_paused: std.atomic.Value(bool),
    mask_addr: ?Address,
    replay_cache: ReplayCache,
    tls_server_hello_template: [tls.server_hello_template_len]u8,

    // Degradation counters (monotonic totals, delta'd in stats log)
    stats_dropped_cap: std.atomic.Value(u64),
    stats_dropped_saturation: std.atomic.Value(u64),
    stats_dropped_rate_limit: std.atomic.Value(u64),
    stats_dropped_hs_budget: std.atomic.Value(u64),
    stats_hs_timeout: std.atomic.Value(u64),
    stats_mp_fallback: std.atomic.Value(u64),

    middle_proxy_lock: CompatRwLock = .{},
    // Regular (non-media) primary endpoints per DC 1..5. Matches `proxy_for N`
    // lines in Telegram's getProxyConfig.
    middle_proxy_addrs_primary: [5]Address,
    // Media primary endpoints per DC 1..5 (matches `proxy_for -N`). Telegram
    // serves large-file traffic on a dedicated MP fleet; routing a media
    // client through a regular MP causes downloads to stall.
    middle_proxy_addrs_media_primary: [5]Address,
    middle_proxy_addr_203: Address,
    middle_proxy_addrs_dc4: [16]Address,
    middle_proxy_addrs_dc4_len: usize,
    middle_proxy_addrs_media_dc4: [16]Address,
    middle_proxy_addrs_media_dc4_len: usize,
    middle_proxy_addrs_203: [8]Address,
    middle_proxy_addrs_203_len: usize,
    middle_proxy_secret: [256]u8,
    middle_proxy_secret_len: usize,
    middle_proxy_nat_ip4: ?[4]u8,
    middle_proxy_updater_shutdown: std.atomic.Value(bool),
    middle_proxy_updater_thread: ?std.Thread,
    upstream: upstream_mod.Upstream,
    tunnel_info: tunnel_mod.Tunnel,

    pub fn init(allocator: std.mem.Allocator, cfg: Config, config_path: []const u8) !ProxyState {
        if (cfg.users.count() == 0) return error.NoUsersConfigured;

        var secrets: std.ArrayList(obfuscation.UserSecret) = .empty;
        errdefer secrets.deinit(allocator);
        var user_metrics: std.ArrayList(UserMetrics) = .empty;
        errdefer user_metrics.deinit(allocator);
        var it = @constCast(&cfg.users).iterator();
        while (it.next()) |entry| {
            try secrets.append(allocator, .{
                .name = entry.key_ptr.*,
                .secret = entry.value_ptr.*,
            });
            try user_metrics.append(allocator, .{
                .name = entry.key_ptr.*,
                .connections_active = std.atomic.Value(u32).init(0),
                .client_to_upstream_bytes_total = std.atomic.Value(u64).init(0),
                .upstream_to_client_bytes_total = std.atomic.Value(u64).init(0),
            });
        }

        var resolved_addr: ?Address = null;
        if (cfg.mask) {
            const mask_target = if (cfg.mask_port == 443) cfg.tls_domain else "127.0.0.1";
            if (cfg.mask_port != 443) {
                log.info("mask_port={d} configured, using local mask target 127.0.0.1", .{cfg.mask_port});
            }
            const list = getAddressList(allocator, mask_target, cfg.mask_port) catch |err| blk: {
                log.err("Failed to resolve mask target '{s}': {any}", .{ mask_target, err });
                break :blk null;
            };
            if (list) |al| {
                defer al.deinit();
                if (al.addrs.len > 0) {
                    resolved_addr = al.addrs[0];
                    log.info("Mask target '{s}:{d}' resolved at startup", .{ mask_target, cfg.mask_port });
                }
            }
        }

        var default_middle_proxy_secret = [_]u8{0} ** 256;
        @memcpy(default_middle_proxy_secret[0..middleproxy.proxy_secret.len], middleproxy.proxy_secret[0..]);

        var detected_nat_ip4: ?[4]u8 = null;
        if (cfg.datacenter_override == null) {
            if (cfg.middle_proxy_nat_ip) |configured_nat_ip| {
                if (parseIpv4Literal(configured_nat_ip)) |parsed_ip| {
                    detected_nat_ip4 = parsed_ip;
                    var ip_buf: [16]u8 = undefined;
                    log.info("Using server.middle_proxy_nat_ip for middle-proxy NAT translation: {s}", .{formatIpv4Bytes(parsed_ip, &ip_buf)});
                } else {
                    log.info("server.middle_proxy_nat_ip='{s}' is not an IPv4 literal; falling back to AWG/public detection", .{configured_nat_ip});
                }
            }

            if (detected_nat_ip4 == null) {
                if (detectAwgEndpointIpv4(allocator)) |awg_ip| {
                    detected_nat_ip4 = awg_ip;
                    var awg_ip_buf: [16]u8 = undefined;
                    log.info("Using AWG endpoint IPv4 for middle-proxy NAT translation: {s}", .{formatIpv4Bytes(awg_ip, &awg_ip_buf)});
                }
            }

            if (detected_nat_ip4 == null) {
                if (cfg.public_ip) |configured_public_ip| {
                    if (parseIpv4Literal(configured_public_ip)) |parsed_ip| {
                        detected_nat_ip4 = parsed_ip;
                        var ip_buf: [16]u8 = undefined;
                        log.info("Using server.public_ip for middle-proxy NAT translation: {s}", .{formatIpv4Bytes(parsed_ip, &ip_buf)});
                    } else {
                        log.info("server.public_ip='{s}' is not an IPv4 literal; auto-detecting middle-proxy NAT IP", .{configured_public_ip});
                    }
                }
            }

            if (detected_nat_ip4 == null) {
                detected_nat_ip4 = detectPublicIpv4(allocator);
                if (detected_nat_ip4) |ip| {
                    var ip_buf: [16]u8 = undefined;
                    log.info("Detected public IPv4 for middle-proxy NAT translation: {s}", .{formatIpv4Bytes(ip, &ip_buf)});
                }
            }
        }

        const user_secrets = try secrets.toOwnedSlice(allocator);
        errdefer allocator.free(user_secrets);
        const user_metrics_owned = try user_metrics.toOwnedSlice(allocator);
        errdefer allocator.free(user_metrics_owned);

        const owned_config_path = try allocator.dupe(u8, config_path);
        errdefer allocator.free(owned_config_path);

        return .{
            .allocator = allocator,
            .config_path = owned_config_path,
            .config = cfg,
            .user_secrets = user_secrets,
            .user_metrics = user_metrics_owned,
            .start_time_seconds = realtimeSeconds(),
            .connection_count = std.atomic.Value(u64).init(0),
            .closed_count = std.atomic.Value(u64).init(0),
            .client_to_upstream_bytes_total = std.atomic.Value(u64).init(0),
            .upstream_to_client_bytes_total = std.atomic.Value(u64).init(0),
            .active_connections = std.atomic.Value(u32).init(0),
            .handshakes_inflight = std.atomic.Value(u32).init(0),
            .accept_paused = std.atomic.Value(bool).init(false),
            .saturation_paused = std.atomic.Value(bool).init(false),
            .mask_addr = resolved_addr,
            .replay_cache = ReplayCache.init(),
            .tls_server_hello_template = tls.buildServerHelloTemplate(null),
            .stats_dropped_cap = std.atomic.Value(u64).init(0),
            .stats_dropped_saturation = std.atomic.Value(u64).init(0),
            .stats_dropped_rate_limit = std.atomic.Value(u64).init(0),
            .stats_dropped_hs_budget = std.atomic.Value(u64).init(0),
            .stats_hs_timeout = std.atomic.Value(u64).init(0),
            .stats_mp_fallback = std.atomic.Value(u64).init(0),
            .middle_proxy_addrs_primary = constants.tg_middle_proxies_v4,
            .middle_proxy_addrs_media_primary = constants.tg_media_middle_proxies_v4,
            .middle_proxy_addr_203 = constants.getDcAddressV4(203),
            .middle_proxy_addrs_dc4 = [_]Address{constants.tg_middle_proxies_v4[3]} ++ ([_]Address{constants.tg_middle_proxies_v4[3]} ** 15),
            .middle_proxy_addrs_dc4_len = 1,
            .middle_proxy_addrs_media_dc4 = [_]Address{constants.tg_media_middle_proxies_v4[3]} ++ ([_]Address{constants.tg_media_middle_proxies_v4[3]} ** 15),
            .middle_proxy_addrs_media_dc4_len = 1,
            .middle_proxy_addrs_203 = [_]Address{constants.getDcAddressV4(203)} ++ ([_]Address{constants.getDcAddressV4(203)} ** 7),
            .middle_proxy_addrs_203_len = 1,
            .middle_proxy_secret = default_middle_proxy_secret,
            .middle_proxy_secret_len = middleproxy.proxy_secret.len,
            .middle_proxy_nat_ip4 = detected_nat_ip4,
            .middle_proxy_updater_shutdown = std.atomic.Value(bool).init(false),
            .middle_proxy_updater_thread = null,
            .upstream = upblk: {
                switch (cfg.upstream_mode) {
                    .tunnel => break :upblk upstream_mod.Upstream.initDirectWithMark(tunnel_socket_mark),
                    .socks5 => {
                        if (cfg.upstream_proxy_host) |host| {
                            if (cfg.upstream_proxy_port > 0) {
                                const proxy_list = getAddressList(allocator, host, cfg.upstream_proxy_port) catch |err| {
                                    if (cfg.allow_direct_fallback) {
                                        log.err("Failed to resolve SOCKS5 proxy host '{s}:{d}': {any}", .{ host, cfg.upstream_proxy_port, err });
                                        break :upblk upstream_mod.Upstream.initDirect();
                                    }
                                    return error.InvalidSocks5UpstreamConfig;
                                };
                                defer proxy_list.deinit();
                                if (proxy_list.addrs.len > 0) {
                                    log.info("Upstream mode: SOCKS5 via {s}:{d}", .{ host, cfg.upstream_proxy_port });
                                    break :upblk upstream_mod.Upstream.initSocks5(
                                        proxy_list.addrs[0],
                                        cfg.upstream_proxy_username,
                                        cfg.upstream_proxy_password,
                                    );
                                }
                            }
                        }
                        if (!cfg.allow_direct_fallback) return error.InvalidSocks5UpstreamConfig;
                        log.warn("upstream.type=socks5 but proxy host/port not configured; falling back to direct", .{});
                        break :upblk upstream_mod.Upstream.initDirect();
                    },
                    .http => {
                        if (cfg.upstream_proxy_host) |host| {
                            if (cfg.upstream_proxy_port > 0) {
                                const proxy_list = getAddressList(allocator, host, cfg.upstream_proxy_port) catch |err| {
                                    if (cfg.allow_direct_fallback) {
                                        log.err("Failed to resolve HTTP proxy host '{s}:{d}': {any}", .{ host, cfg.upstream_proxy_port, err });
                                        break :upblk upstream_mod.Upstream.initDirect();
                                    }
                                    return error.InvalidHttpUpstreamConfig;
                                };
                                defer proxy_list.deinit();
                                if (proxy_list.addrs.len > 0) {
                                    log.info("Upstream mode: HTTP CONNECT via {s}:{d}", .{ host, cfg.upstream_proxy_port });
                                    break :upblk upstream_mod.Upstream.initHttpConnect(
                                        proxy_list.addrs[0],
                                        cfg.upstream_proxy_username,
                                        cfg.upstream_proxy_password,
                                    );
                                }
                            }
                        }
                        if (!cfg.allow_direct_fallback) return error.InvalidHttpUpstreamConfig;
                        log.warn("upstream.type=http but proxy host/port not configured; falling back to direct", .{});
                        break :upblk upstream_mod.Upstream.initDirect();
                    },
                    .direct, .auto => break :upblk upstream_mod.Upstream.initDirect(),
                }
            },
            .tunnel_info = blk: {
                switch (cfg.upstream_mode) {
                    .direct => {
                        log.info("Upstream mode: direct (configured)", .{});
                        break :blk tunnel_mod.Tunnel{ .tag = .none };
                    },
                    .tunnel => {
                        log.info("Upstream mode: tunnel (socket policy routing via SO_MARK={d})", .{tunnel_socket_mark});
                        break :blk tunnel_mod.Tunnel{ .tag = .tunnel };
                    },
                    .socks5 => {
                        break :blk tunnel_mod.Tunnel{ .tag = .socks5 };
                    },
                    .http => {
                        break :blk tunnel_mod.Tunnel{ .tag = .http_connect };
                    },
                    .auto => {
                        if (isRunningInNonInitNetns()) {
                            log.warn("auto mode does not infer tunnel from netns; using direct egress", .{});
                        }
                        log.info("Upstream mode: direct (auto)", .{});
                        break :blk tunnel_mod.Tunnel{ .tag = .none };
                    },
                }
            },
        };
    }

    pub fn deinit(self: *ProxyState) void {
        self.middle_proxy_updater_shutdown.store(true, .release);
        if (self.middle_proxy_updater_thread) |thread| {
            thread.join();
            self.middle_proxy_updater_thread = null;
        }
        self.allocator.free(self.config_path);
        self.allocator.free(self.user_secrets);
        self.allocator.free(self.user_metrics);
    }

    pub fn findUserMetrics(self: *ProxyState, user_name: []const u8) ?*UserMetrics {
        for (self.user_metrics) |*entry| {
            if (std.mem.eql(u8, entry.name, user_name)) return entry;
        }
        return null;
    }

    pub fn getMetricsSnapshot(self: *const ProxyState) MetricsSnapshot {
        const now = realtimeSeconds();
        const accepted_total = self.connection_count.load(.monotonic);
        return .{
            .start_time_seconds = self.start_time_seconds,
            .uptime_seconds = @max(@as(i64, 0), now - self.start_time_seconds),
            .connections_active = self.active_connections.load(.monotonic),
            .connections_max = self.config.max_connections,
            .handshakes_inflight = self.handshakes_inflight.load(.monotonic),
            .connections_accepted_total = accepted_total,
            .connections_closed_total = self.closed_count.load(.monotonic),
            .connections_total = accepted_total,
            .accept_paused = self.accept_paused.load(.monotonic),
            .saturation_paused = self.saturation_paused.load(.monotonic),
            .drops_capacity_total = self.stats_dropped_cap.load(.monotonic),
            .drops_saturation_total = self.stats_dropped_saturation.load(.monotonic),
            .drops_rate_limit_total = self.stats_dropped_rate_limit.load(.monotonic),
            .drops_handshake_budget_total = self.stats_dropped_hs_budget.load(.monotonic),
            .handshake_timeouts_total = self.stats_hs_timeout.load(.monotonic),
            .middleproxy_fallback_total = self.stats_mp_fallback.load(.monotonic),
            .client_to_upstream_bytes_total = self.client_to_upstream_bytes_total.load(.monotonic),
            .upstream_to_client_bytes_total = self.upstream_to_client_bytes_total.load(.monotonic),
            .config_port = self.config.port,
            .config_max_connections = self.config.max_connections,
            .middleproxy_enabled = self.config.use_middle_proxy,
            .fast_mode_enabled = self.config.fast_mode,
            .mask_enabled = self.config.mask,
            .desync_enabled = self.config.desync,
            .drs_enabled = self.config.drs,
        };
    }

    pub fn run(self: *ProxyState) !void {
        if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
        const io_ctx = std.Io.Threaded.global_single_threaded.io();
        var signal_controller = try SignalController.init();
        defer signal_controller.deinit();

        var ipv6_ok = true;
        var server: net.Server = undefined;

        if (self.config.bind_address) |bind_str| {
            // Explicit bind address from config
            const parsed = parseListenAddress(bind_str, self.config.port) orelse {
                log.err("Invalid bind_address '{s}', cannot start", .{bind_str});
                return error.InvalidBindAddress;
            };
            ipv6_ok = isIpv6(parsed);
            server = try parsed.listen(io_ctx, .{
                .reuse_address = true,
                .kernel_backlog = @intCast(self.config.backlog),
            });
            log.info("Listening on {s}:{d} (epoll, single-thread)", .{ bind_str, self.config.port });
        } else {
            // Default: try [::] (dual-stack), fall back to 0.0.0.0
            const address = ip6(
                .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                self.config.port,
                0,
                0,
            );
            server = address.listen(io_ctx, .{
                .reuse_address = true,
                .kernel_backlog = @intCast(self.config.backlog),
            }) catch |err| blk: {
                if (err == error.AddressFamilyUnsupported) {
                    ipv6_ok = false;
                    log.warn("IPv6 not available, falling back to IPv4 (0.0.0.0)", .{});
                    const address_v4 = ip4(.{ 0, 0, 0, 0 }, self.config.port);
                    break :blk try address_v4.listen(io_ctx, .{
                        .reuse_address = true,
                        .kernel_backlog = @intCast(self.config.backlog),
                    });
                }
                return err;
            };

            if (ipv6_ok) {
                log.info("Listening on [::]:{d} (epoll, single-thread)", .{self.config.port});
            } else {
                log.info("Listening on 0.0.0.0:{d} (epoll, single-thread)", .{self.config.port});
            }
        }
        defer server.deinit(io_ctx);

        setNonBlocking(server.socket.handle);

        if (self.config.use_middle_proxy and self.config.datacenter_override == null) {
            self.refreshMiddleProxyInfo() catch |err| {
                if (isMiddleProxyRefreshNetworkError(err)) {
                    log.info("Initial middle-proxy refresh unavailable ({s}), using bundled defaults", .{@errorName(err)});
                } else {
                    log.warn("Initial middle-proxy refresh failed, using bundled defaults: {any}", .{err});
                }
            };

            self.middle_proxy_updater_shutdown.store(false, .release);
            if (std.Thread.spawn(.{}, ProxyState.middleProxyUpdaterMain, .{self})) |updater| {
                self.middle_proxy_updater_thread = updater;
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

        if (self.config.metrics.enabled) {
            try @import("../monitoring.zig").start(self);
        }

        var loop = try EventLoop.init(self, server.socket.handle, signal_controller.fd);
        defer loop.deinit();
        try loop.run();
    }

    const MiddleProxySnapshot = middle_proxy_routing.MiddleProxySnapshot;

    fn getMiddleProxySnapshot(self: *ProxyState) MiddleProxySnapshot {
        self.middle_proxy_lock.lockShared();
        defer self.middle_proxy_lock.unlockShared();

        return .{
            .addrs_primary = self.middle_proxy_addrs_primary,
            .addrs_media_primary = self.middle_proxy_addrs_media_primary,
            .addr_203 = self.middle_proxy_addr_203,
            .addrs_dc4 = self.middle_proxy_addrs_dc4,
            .addrs_dc4_len = self.middle_proxy_addrs_dc4_len,
            .addrs_media_dc4 = self.middle_proxy_addrs_media_dc4,
            .addrs_media_dc4_len = self.middle_proxy_addrs_media_dc4_len,
            .addrs_203 = self.middle_proxy_addrs_203,
            .addrs_203_len = self.middle_proxy_addrs_203_len,
            .secret = self.middle_proxy_secret,
            .secret_len = self.middle_proxy_secret_len,
        };
    }

    /// Refresh helper. Tries the default route first; on any network-class
    /// failure AND when the config selects tunnel upstream, retries via
    /// `curl --interface <tunnel>`. This is what makes the media MP cache
    /// warm up correctly on censored hosts where `core.telegram.org` is
    /// unreachable directly but reachable through the tunnel.
    fn fetchMiddleProxyAsset(self: *ProxyState, allocator: std.mem.Allocator, url: []const u8) ![]u8 {
        if (fetchUrlBytes(allocator, url)) |bytes| {
            return bytes;
        } else |direct_err| {
            const tunnel_iface = blk: {
                if (self.config.upstream_mode != .tunnel) break :blk null;
                break :blk self.config.upstream_tunnel_interface;
            };
            const iface = tunnel_iface orelse return direct_err;
            log.info(
                "Middle-proxy asset {s} unreachable directly ({s}); retrying via tunnel '{s}'",
                .{ url, @errorName(direct_err), iface },
            );
            return fetchUrlBytesViaInterface(allocator, url, iface);
        }
    }

    fn middleProxyUpdaterMain(self: *ProxyState) void {
        // Initial refresh runs before the proxy event loop starts, so on a
        // censored host it typically fails (tunnel handshake may not be up yet).
        // Do a short-cycle retry loop early, then fall back to the normal
        // 24-hour cadence. This gets media MP addresses into the cache within
        // the first few minutes of uptime instead of the next day.
        const short_retries: [5]u64 = .{
            10 * std.time.ns_per_s,
            30 * std.time.ns_per_s,
            60 * std.time.ns_per_s,
            5 * 60 * std.time.ns_per_s,
            30 * 60 * std.time.ns_per_s,
        };
        var retry_idx: usize = 0;
        while (retry_idx < short_retries.len) : (retry_idx += 1) {
            if (self.waitForUpdaterDelay(short_retries[retry_idx])) return;
            if (self.refreshMiddleProxyInfo()) |_| {
                break;
            } else |err| {
                if (isMiddleProxyRefreshNetworkError(err)) {
                    log.info("Middle-proxy early retry unavailable ({s}), will try again", .{@errorName(err)});
                } else {
                    log.warn("Middle-proxy early retry failed: {any}", .{err});
                }
            }
        }

        while (!self.middle_proxy_updater_shutdown.load(.acquire)) {
            if (self.waitForUpdaterDelay(middle_proxy_update_period_ns)) return;
            self.refreshMiddleProxyInfo() catch |err| {
                if (isMiddleProxyRefreshNetworkError(err)) {
                    log.info("Middle-proxy refresh unavailable ({s}), keeping current cache", .{@errorName(err)});
                } else {
                    log.warn("Middle-proxy refresh failed: {any}", .{err});
                }
            };
        }
    }

    fn waitForUpdaterDelay(self: *ProxyState, total_ns: u64) bool {
        const step_ns: u64 = std.time.ns_per_s;
        var remaining = total_ns;
        while (remaining > 0) {
            if (self.middle_proxy_updater_shutdown.load(.acquire)) return true;
            const chunk = @min(remaining, step_ns);
            sleepNs(chunk);
            remaining -= chunk;
        }
        return self.middle_proxy_updater_shutdown.load(.acquire);
    }

    fn isMiddleProxyRefreshNetworkError(err: anyerror) bool {
        const name = @errorName(err);
        return std.mem.eql(u8, name, "UnexpectedConnectFailure") or
            std.mem.eql(u8, name, "ConnectionRefused") or
            std.mem.eql(u8, name, "ConnectionResetByPeer") or
            std.mem.eql(u8, name, "NetworkUnreachable") or
            std.mem.eql(u8, name, "HostUnreachable") or
            std.mem.eql(u8, name, "ConnectionTimedOut") or
            std.mem.eql(u8, name, "TemporaryNameServerFailure") or
            std.mem.eql(u8, name, "NameServerFailure");
    }

    fn refreshMiddleProxyInfo(self: *ProxyState) !void {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const temp_alloc = arena.allocator();

        // Fetch config + secret. When the proxy runs inside a censored network
        // (e.g. RU), core.telegram.org is unreachable over the default route;
        // we transparently retry through the configured tunnel interface so
        // the runtime MP cache (including media endpoints) stays up to date.
        const cfg_bytes = self.fetchMiddleProxyAsset(temp_alloc, middle_proxy_config_url) catch |err| return err;
        const next_secret = self.fetchMiddleProxyAsset(temp_alloc, middle_proxy_secret_url) catch |err| return err;

        var next_primary: [5]?Address = [_]?Address{null} ** 5;
        var next_media_primary: [5]?Address = [_]?Address{null} ** 5;
        var next_dc4_candidates: [16]Address = undefined;
        var next_dc4_candidates_len: usize = 0;
        var next_media_dc4_candidates: [16]Address = undefined;
        var next_media_dc4_candidates_len: usize = 0;
        for (0..next_primary.len) |i| {
            const dc_num: i16 = @intCast(i + 1);

            // Regular (positive dc_idx) — used for non-media traffic.
            var candidates: [16]Address = undefined;
            const count = parseMiddleProxyAddressesForDc(cfg_bytes, dc_num, .positive_only, &candidates);

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

            // Media (negative dc_idx) — Telegram uses a separate MP fleet for
            // large file routing. Mixing the two causes media downloads to
            // stall (what looks like "tormozit" on photo/video load).
            var media_candidates: [16]Address = undefined;
            const media_count = parseMiddleProxyAddressesForDc(cfg_bytes, dc_num, .negative_only, &media_candidates);

            if (i == 3 and media_count > 0) {
                const m4_n = @min(media_count, next_media_dc4_candidates.len);
                @memcpy(next_media_dc4_candidates[0..m4_n], media_candidates[0..m4_n]);
                next_media_dc4_candidates_len = m4_n;
            }

            next_media_primary[i] = if (media_count == 0)
                null
            else if (i == 3)
                media_candidates[0]
            else if (trySelectReachableMiddleProxy(media_candidates[0..media_count], 1200)) |reachable|
                reachable
            else
                media_candidates[0];
        }

        var candidates_203: [8]Address = undefined;
        const count_203 = parseMiddleProxyAddressesForDc(cfg_bytes, 203, .any, &candidates_203);
        var next_203_candidates: [8]Address = undefined;
        var next_203_candidates_len: usize = 0;
        if (count_203 > 0) {
            const c203_n = @min(count_203, next_203_candidates.len);
            @memcpy(next_203_candidates[0..c203_n], candidates_203[0..c203_n]);
            next_203_candidates_len = c203_n;
        }
        const next_addr_203 = if (count_203 == 0) null else candidates_203[0];

        if (next_secret.len < 16 or next_secret.len > self.middle_proxy_secret.len) {
            return error.BadMiddleProxySecret;
        }

        self.middle_proxy_lock.lock();
        defer self.middle_proxy_lock.unlock();

        var changed = false;

        for (0..next_primary.len) |i| {
            if (next_primary[i]) |addr| {
                if (!addressEql(self.middle_proxy_addrs_primary[i], addr)) {
                    self.middle_proxy_addrs_primary[i] = addr;
                    changed = true;
                }
            }
            if (next_media_primary[i]) |addr| {
                if (!addressEql(self.middle_proxy_addrs_media_primary[i], addr)) {
                    self.middle_proxy_addrs_media_primary[i] = addr;
                    changed = true;
                }
            }
        }

        if (next_media_dc4_candidates_len > 0) {
            if (self.middle_proxy_addrs_media_dc4_len != next_media_dc4_candidates_len or
                !addressesEqual(self.middle_proxy_addrs_media_dc4[0..self.middle_proxy_addrs_media_dc4_len], next_media_dc4_candidates[0..next_media_dc4_candidates_len]))
            {
                @memcpy(self.middle_proxy_addrs_media_dc4[0..next_media_dc4_candidates_len], next_media_dc4_candidates[0..next_media_dc4_candidates_len]);
                self.middle_proxy_addrs_media_dc4_len = next_media_dc4_candidates_len;
                changed = true;
            }
        }

        if (next_addr_203) |addr| {
            if (!addressEql(self.middle_proxy_addr_203, addr)) {
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
    signal_fd: posix.fd_t,
    pool: ConnectionPool,
    accept_paused: bool,
    accept_resume_ns: i128,
    saturation_paused: bool,
    shutting_down: bool,
    shutdown_deadline_ns: i128,
    timer_scan_cursor: u32,
    stats_next_log_ns: i128,
    accepted_since_log: u64,
    closed_since_log: u64,
    subnet_limiter: SubnetRateLimit,
    // Snapshot of degradation counters for delta logging
    prev_dropped_cap: u64,
    prev_dropped_saturation: u64,
    prev_dropped_rate_limit: u64,
    prev_dropped_hs_budget: u64,
    prev_hs_timeout: u64,
    prev_mp_fallback: u64,
    shared_read_buf: [read_buf_size]u8,
    desync_wait_slots: std.ArrayListUnmanaged(u32),
    mp_c2s_scratch: ?[]u8,
    mp_s2c_scratch: ?[]u8,

    fn init(state: *ProxyState, listen_fd: posix.fd_t, signal_fd: posix.fd_t) !EventLoop {
        const epoll_fd = try epollCreate();
        errdefer closeFd(epoll_fd);

        var loop = EventLoop{
            .state = state,
            .epoll_fd = epoll_fd,
            .listen_fd = listen_fd,
            .signal_fd = signal_fd,
            .pool = try ConnectionPool.init(state.allocator, state.config.max_connections),
            .accept_paused = false,
            .accept_resume_ns = 0,
            .saturation_paused = false,
            .shutting_down = false,
            .shutdown_deadline_ns = 0,
            .timer_scan_cursor = 0,
            .stats_next_log_ns = nowNs() + stats_log_interval_ns,
            .accepted_since_log = 0,
            .closed_since_log = 0,
            .subnet_limiter = SubnetRateLimit.init(),
            .prev_dropped_cap = 0,
            .prev_dropped_saturation = 0,
            .prev_dropped_rate_limit = 0,
            .prev_dropped_hs_budget = 0,
            .prev_hs_timeout = 0,
            .prev_mp_fallback = 0,
            .shared_read_buf = undefined,
            .desync_wait_slots = .empty,
            .mp_c2s_scratch = null,
            .mp_s2c_scratch = null,
        };
        errdefer loop.pool.deinit();

        try loop.addFd(listen_fd, true, false);
        try loop.addFd(signal_fd, true, false);
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

        if (self.mp_c2s_scratch) |buf| self.state.allocator.free(buf);
        if (self.mp_s2c_scratch) |buf| self.state.allocator.free(buf);
        self.desync_wait_slots.deinit(self.state.allocator);

        self.pool.deinit();
        closeFd(self.epoll_fd);
    }

    fn run(self: *EventLoop) !void {
        var events: [256]linux.epoll_event = undefined;
        const timer_tick_ns: i128 = 5 * std.time.ns_per_ms;
        var next_timer_tick_ns: i128 = nowNs();

        while (true) {
            var current_wait_ms: i32 = event_loop_wait_ms;
            if (self.desync_wait_slots.items.len > 0) {
                current_wait_ms = @min(current_wait_ms, desync_wait_poll_ms);
            }
            if (self.shutting_down) {
                current_wait_ms = @min(current_wait_ms, graceful_shutdown_check_ms);
            }

            const rc = linux.epoll_wait(self.epoll_fd, events[0..].ptr, @intCast(events.len), current_wait_ms);
            switch (posix.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                else => |err| return posix.unexpectedErrno(err),
            }

            const n: usize = @intCast(rc);
            for (events[0..n]) |ev| {
                const fd = ev.data.fd;
                const ev_flags = ev.events;
                if (fd == self.signal_fd) {
                    self.processSignalFd();
                    continue;
                }
                if (fd == self.listen_fd) {
                    if (!self.shutting_down) {
                        self.acceptNewConnections() catch |err| {
                            log.err("accept loop error: {any}", .{err});
                        };
                    }
                    continue;
                }

                const slot = self.pool.getByFd(fd) orelse continue;
                self.processSlotEvent(slot, fd, ev_flags);
            }

            self.processDesyncWaits();

            const now_ns = nowNs();
            if (!self.shutting_down and self.accept_paused and now_ns >= self.accept_resume_ns) {
                self.resumeAccepting();
            }
            // Saturation hysteresis: resume accepting when active drops below 80%
            if (!self.shutting_down and self.saturation_paused) {
                const active = self.state.active_connections.load(.monotonic);
                const resume_threshold = (self.state.config.max_connections * 8) / 10;
                if (active <= resume_threshold) {
                    self.resumeSaturation();
                }
            }
            if (now_ns >= next_timer_tick_ns) {
                self.runTimers();
                next_timer_tick_ns = now_ns + timer_tick_ns;
            }
            if (now_ns >= self.stats_next_log_ns) {
                self.logPeriodicStats(now_ns);
            }
            if (self.shutting_down and self.maybeCompleteShutdown(now_ns)) {
                return;
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

        if (fatal_hangup and shouldCloseOnFatalHangup(slot.phase, fd, slot.upstream_fd)) {
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
        // Saturation hysteresis: if active > 90% of max, stop accepting entirely.
        // Resume only when active drops below 80% (checked in run() loop).
        const active_now = self.state.active_connections.load(.monotonic);
        const max = self.state.config.max_connections;
        if (active_now >= (max * 9) / 10) {
            if (!self.saturation_paused) {
                self.pauseSaturation();
            }
            _ = self.state.stats_dropped_saturation.fetchAdd(1, .monotonic);
            return;
        }

        var accepted_this_round: usize = 0;
        while (accepted_this_round < accept_batch_limit) {
            const accepted = acceptClient(self.listen_fd) catch |err| {
                switch (err) {
                    // TCP three-way-handshake aborts between the kernel's
                    // accept queue and our accept() call. These are benign —
                    // bubbling them up causes the whole batch to abort and
                    // (worse) starves other connections waiting in the queue.
                    error.ConnectionAborted, error.ConnectionResetByPeer => continue,

                    // Resource exhaustion: either we hit an FD limit or the
                    // kernel ran out of socket buffers (ENOBUFS). In LT epoll
                    // mode the listen socket stays readable, so returning the
                    // error here without pausing would spin the event loop at
                    // 100% CPU. Pause accepts with back-off instead.
                    error.ProcessFdQuotaExceeded,
                    error.SystemFdQuotaExceeded,
                    error.SystemResources,
                    => {
                        self.pauseAccepting(err);
                        return;
                    },
                    else => return error.UnexpectedAccept,
                }
            };
            if (accepted == null) return;
            const cfd = accepted.?.fd;
            const client_addr = accepted.?.addr;
            accepted_this_round += 1;

            // Ensure desync byte-splitting is not coalesced by Nagle during early handshake.
            setTcpNoDelay(cfd);

            // Per-/24 subnet rate limit (before we allocate any slot)
            if (!self.subnet_limiter.check(client_addr, self.state.config.rate_limit_per_subnet)) {
                _ = self.state.stats_dropped_rate_limit.fetchAdd(1, .monotonic);
                closeFd(cfd);
                continue;
            }

            const active_before = self.state.active_connections.fetchAdd(1, .monotonic);
            if (active_before >= self.state.config.max_connections) {
                _ = self.state.active_connections.fetchSub(1, .monotonic);
                _ = self.state.stats_dropped_cap.fetchAdd(1, .monotonic);
                closeFd(cfd);
                continue;
            }

            // Handshake inflight budget: cap at 30% of max_connections.
            // Prevents churn (scanners/probes) from starving established relay sessions.
            const hs_inflight = self.state.handshakes_inflight.fetchAdd(1, .monotonic);
            const hs_max = (self.state.config.max_connections * 3) / 10;
            if (hs_max > 0 and hs_inflight >= hs_max) {
                _ = self.state.handshakes_inflight.fetchSub(1, .monotonic);
                _ = self.state.active_connections.fetchSub(1, .monotonic);
                _ = self.state.stats_dropped_hs_budget.fetchAdd(1, .monotonic);
                closeFd(cfd);
                continue;
            }

            const slot = self.pool.acquire() orelse {
                _ = self.state.handshakes_inflight.fetchSub(1, .monotonic);
                _ = self.state.active_connections.fetchSub(1, .monotonic);
                closeFd(cfd);
                continue;
            };

            slot.active_reserved = true;
            slot.traffic_client_to_upstream_counter = &self.state.client_to_upstream_bytes_total;
            slot.traffic_upstream_to_client_counter = &self.state.upstream_to_client_bytes_total;
            slot.user_metrics = null;
            slot.conn_id = self.state.connection_count.fetchAdd(1, .monotonic);
            slot.client_fd = cfd;
            slot.peer_addr = client_addr;
            slot.phase = .reading_tls_header;
            slot.created_at_ms = nowMs();
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
        const hs = self.state.handshakes_inflight.load(.monotonic);
        const accepted_total = self.state.connection_count.load(.monotonic);

        // Snapshot degradation counters and compute deltas
        const cur_cap = self.state.stats_dropped_cap.load(.monotonic);
        const cur_sat = self.state.stats_dropped_saturation.load(.monotonic);
        const cur_rate = self.state.stats_dropped_rate_limit.load(.monotonic);
        const cur_hs = self.state.stats_dropped_hs_budget.load(.monotonic);
        const cur_hst = self.state.stats_hs_timeout.load(.monotonic);
        const cur_mpf = self.state.stats_mp_fallback.load(.monotonic);

        const d_cap = cur_cap - self.prev_dropped_cap;
        const d_sat = cur_sat - self.prev_dropped_saturation;
        const d_rate = cur_rate - self.prev_dropped_rate_limit;
        const d_hs = cur_hs - self.prev_dropped_hs_budget;
        const d_hst = cur_hst - self.prev_hs_timeout;
        const d_mpf = cur_mpf - self.prev_mp_fallback;

        self.prev_dropped_cap = cur_cap;
        self.prev_dropped_saturation = cur_sat;
        self.prev_dropped_rate_limit = cur_rate;
        self.prev_dropped_hs_budget = cur_hs;
        self.prev_hs_timeout = cur_hst;
        self.prev_mp_fallback = cur_mpf;

        const has_drops = d_cap + d_sat + d_rate + d_hs + d_hst + d_mpf > 0;

        // Build per-user active connection counts for dashboard parsing
        var user_buf: [1024]u8 = undefined;
        var user_pos: usize = 0;
        var users_active_total: u32 = 0;
        for (self.state.user_metrics) |*um| {
            const uactive = um.connections_active.load(.monotonic);
            users_active_total +|= uactive;
            const name = um.name;
            if (user_pos > 0 and user_pos < user_buf.len) {
                user_buf[user_pos] = ',';
                user_pos += 1;
            }
            const written = std.fmt.bufPrint(user_buf[user_pos..], "{s}={d}", .{ name, uactive }) catch break;
            user_pos += written.len;
        }
        const user_str = if (user_pos > 0) user_buf[0..user_pos] else "";
        const unassigned_active = active -| users_active_total;

        log.info("conn stats: active={d}/{d} hs_inflight={d} accepted+={d} closed+={d} tracked_fds={d} total={d} paused={}/{} users_total={d} unassigned={d} users{{{s}}}", .{
            active,
            self.state.config.max_connections,
            hs,
            self.accepted_since_log,
            self.closed_since_log,
            self.pool.fd_to_slot.count(),
            accepted_total,
            self.accept_paused,
            self.saturation_paused,
            users_active_total,
            unassigned_active,
            user_str,
        });

        if (has_drops) {
            log.info("  drops: cap+={d} sat+={d} rate+={d} hs_budget+={d} hs_timeout+={d} mp_fallback+={d}", .{
                d_cap, d_sat, d_rate, d_hs, d_hst, d_mpf,
            });
        }

        self.accepted_since_log = 0;
        self.closed_since_log = 0;

        while (self.stats_next_log_ns <= now_ns) {
            self.stats_next_log_ns += stats_log_interval_ns;
        }
    }

    fn pauseAccepting(self: *EventLoop, err: anyerror) void {
        self.accept_resume_ns = nowNs() + accept_backoff_ns;
        if (self.accept_paused) return;

        self.modFd(self.listen_fd, false, false) catch |mod_err| {
            log.err("failed to pause accepts after fd quota error: {any}", .{mod_err});
            return;
        };

        self.accept_paused = true;
        self.state.accept_paused.store(true, .monotonic);
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
            self.accept_resume_ns = nowNs() + accept_backoff_ns;
            log.warn("failed to resume accepts; retry in {d}ms: {any}", .{ accept_backoff_ms, err });
            return;
        };

        self.accept_paused = false;
        self.accept_resume_ns = 0;
        self.state.accept_paused.store(false, .monotonic);
    }

    fn pauseSaturation(self: *EventLoop) void {
        if (self.saturation_paused) return;

        self.modFd(self.listen_fd, false, false) catch |mod_err| {
            log.err("failed to pause accepts for saturation: {any}", .{mod_err});
            return;
        };

        self.saturation_paused = true;
        self.state.saturation_paused.store(true, .monotonic);
        const active = self.state.active_connections.load(.monotonic);
        const max = self.state.config.max_connections;
        log.warn(
            "connection saturation: active={d}/{d} (>{d}%); pausing new accepts. " ++
                "Will resume when active drops below {d} ({d}%). " ++
                "To handle more clients, increase max_connections or upgrade VPS RAM.",
            .{ active, max, @as(u32, 90), (max * 8) / 10, @as(u32, 80) },
        );
    }

    fn resumeSaturation(self: *EventLoop) void {
        if (!self.saturation_paused) return;

        self.modFd(self.listen_fd, true, false) catch |err| {
            log.warn("failed to resume accepts after saturation ease: {any}", .{err});
            return;
        };

        self.saturation_paused = false;
        self.state.saturation_paused.store(false, .monotonic);
        const active = self.state.active_connections.load(.monotonic);
        log.info("saturation eased: active={d}/{d}; resuming accepts", .{ active, self.state.config.max_connections });
    }

    fn processSignalFd(self: *EventLoop) void {
        while (true) {
            var info: linux.signalfd_siginfo = undefined;
            const buf = std.mem.asBytes(&info);
            const n = posix.read(self.signal_fd, buf) catch |err| switch (err) {
                error.WouldBlock => return,
                else => {
                    log.warn("signalfd read failed: {any}", .{err});
                    return;
                },
            };
            if (n == 0) return;
            if (n != buf.len) {
                log.warn("short signalfd read: got {d} bytes, expected {d}", .{ n, buf.len });
                continue;
            }
            self.onSignal(@enumFromInt(info.signo));
        }
    }

    fn onSignal(self: *EventLoop, sig: posix.SIG) void {
        switch (sig) {
            .TERM => self.beginGracefulShutdown("SIGTERM"),
            .INT => self.beginGracefulShutdown("SIGINT"),
            .HUP => self.reloadConfigFromDisk(),
            .USR1 => self.dumpSignalStats(),
            else => {},
        }
    }

    fn beginGracefulShutdown(self: *EventLoop, signal_name: []const u8) void {
        const now_ns = nowNs();
        if (self.shutting_down) {
            self.shutdown_deadline_ns = now_ns;
            log.warn("{s} received during graceful drain; forcing immediate shutdown", .{signal_name});
            return;
        }

        self.shutting_down = true;
        self.shutdown_deadline_ns = now_ns + (@as(i128, @intCast(self.state.config.graceful_shutdown_timeout_sec)) * std.time.ns_per_s);

        self.modFd(self.listen_fd, false, false) catch |err| {
            log.warn("failed to disable listen socket during shutdown: {any}", .{err});
        };
        self.accept_paused = true;
        self.saturation_paused = true;
        self.state.accept_paused.store(true, .monotonic);
        self.state.saturation_paused.store(true, .monotonic);

        const active = self.state.active_connections.load(.monotonic);
        log.warn(
            "{s} received: graceful shutdown started, active={d}, timeout={d}s",
            .{ signal_name, active, self.state.config.graceful_shutdown_timeout_sec },
        );
    }

    fn maybeCompleteShutdown(self: *EventLoop, now_ns: i128) bool {
        const active = self.state.active_connections.load(.monotonic);
        if (active == 0) {
            log.info("graceful shutdown complete: all connections drained", .{});
            return true;
        }
        if (now_ns < self.shutdown_deadline_ns) return false;

        log.warn("graceful shutdown timeout reached; forcing close of {d} active connections", .{active});
        self.forceCloseActiveSlots("shutdown timeout");
        return true;
    }

    fn forceCloseActiveSlots(self: *EventLoop, reason: []const u8) void {
        for (self.pool.slots) |slot_opt| {
            if (slot_opt) |slot| {
                if (slot.phase != .idle) {
                    self.closeSlot(slot, reason);
                }
            }
        }
    }

    fn dumpSignalStats(self: *EventLoop) void {
        const snapshot = self.state.getMetricsSnapshot();
        log.info(
            "SIGUSR1 stats: active={d}/{d} hs={d} total={d} closed={d} c2s={d} s2c={d} paused={}/{} drops(cap/sat/rate/hs)={d}/{d}/{d}/{d}",
            .{
                snapshot.connections_active,
                snapshot.connections_max,
                snapshot.handshakes_inflight,
                snapshot.connections_accepted_total,
                snapshot.connections_closed_total,
                snapshot.client_to_upstream_bytes_total,
                snapshot.upstream_to_client_bytes_total,
                snapshot.accept_paused,
                snapshot.saturation_paused,
                snapshot.drops_capacity_total,
                snapshot.drops_saturation_total,
                snapshot.drops_rate_limit_total,
                snapshot.drops_handshake_budget_total,
            },
        );
    }

    fn reloadConfigFromDisk(self: *EventLoop) void {
        var next = Config.loadFromFile(self.state.allocator, self.state.config_path) catch |err| {
            log.err("SIGHUP: failed to reload config '{s}': {any}", .{ self.state.config_path, err });
            return;
        };
        defer next.deinit(self.state.allocator);

        if (next.users.count() == 0) {
            log.err("SIGHUP: reload rejected (no users configured)", .{});
            return;
        }

        var applied: usize = 0;
        var static_changes: usize = 0;

        if (next.port != self.state.config.port) static_changes += 1;
        const bind_address_changed = blk: {
            if (next.bind_address == null and self.state.config.bind_address == null) break :blk false;
            if (next.bind_address) |new_bind| {
                if (self.state.config.bind_address) |old_bind| {
                    break :blk !std.mem.eql(u8, new_bind, old_bind);
                }
            }
            break :blk true;
        };
        if (bind_address_changed) static_changes += 1;
        if (next.backlog != self.state.config.backlog) static_changes += 1;
        if (next.use_middle_proxy != self.state.config.use_middle_proxy) static_changes += 1;
        if (next.force_media_middle_proxy != self.state.config.force_media_middle_proxy) static_changes += 1;
        if (next.middleproxy_buffer_kb != self.state.config.middleproxy_buffer_kb) static_changes += 1;
        if (next.upstream_mode != self.state.config.upstream_mode) static_changes += 1;
        if (next.allow_direct_fallback != self.state.config.allow_direct_fallback) static_changes += 1;

        if (next.idle_timeout_sec != self.state.config.idle_timeout_sec) {
            self.state.config.idle_timeout_sec = next.idle_timeout_sec;
            applied += 1;
        }
        if (next.handshake_timeout_sec != self.state.config.handshake_timeout_sec) {
            self.state.config.handshake_timeout_sec = next.handshake_timeout_sec;
            applied += 1;
        }
        if (next.graceful_shutdown_timeout_sec != self.state.config.graceful_shutdown_timeout_sec) {
            self.state.config.graceful_shutdown_timeout_sec = next.graceful_shutdown_timeout_sec;
            applied += 1;
        }
        if (next.rate_limit_per_subnet != self.state.config.rate_limit_per_subnet) {
            self.state.config.rate_limit_per_subnet = next.rate_limit_per_subnet;
            applied += 1;
        }
        if (next.log_level != self.state.config.log_level) {
            self.state.config.log_level = next.log_level;
            runtime_log.level = next.log_level;
            applied += 1;
        }
        const tls_domain_changed = !std.mem.eql(u8, next.tls_domain, self.state.config.tls_domain);
        if (next.mask != self.state.config.mask or next.mask_port != self.state.config.mask_port or tls_domain_changed) {
            const resolved_mask_addr = self.resolveMaskAddress(&next);
            if (next.mask) {
                if (resolved_mask_addr) |addr| {
                    self.state.mask_addr = addr;
                } else {
                    log.warn("SIGHUP: failed to resolve new mask target, keeping previous mask address", .{});
                }
            } else {
                self.state.mask_addr = null;
            }
            self.state.config.mask = next.mask;
            self.state.config.mask_port = next.mask_port;
            if (tls_domain_changed) {
                if (self.state.allocator.dupe(u8, next.tls_domain)) |owned_tls_domain| {
                    if (self.state.config.ownsTlsDomain()) {
                        self.state.allocator.free(self.state.config.tls_domain);
                    }
                    self.state.config.tls_domain = owned_tls_domain;
                } else |_| {
                    log.warn("SIGHUP: failed to apply new tls_domain due to allocation error", .{});
                }
            }
            applied += 1;
        }
        if (next.desync != self.state.config.desync) {
            self.state.config.desync = next.desync;
            applied += 1;
        }
        if (next.drs != self.state.config.drs) {
            self.state.config.drs = next.drs;
            applied += 1;
        }
        if (next.fast_mode != self.state.config.fast_mode) {
            self.state.config.fast_mode = next.fast_mode;
            applied += 1;
        }

        const pool_capacity: u32 = @intCast(self.pool.slots.len);
        if (next.max_connections != self.state.config.max_connections) {
            if (next.max_connections <= pool_capacity) {
                self.state.config.max_connections = next.max_connections;
                applied += 1;
            } else {
                log.warn(
                    "SIGHUP: requested max_connections={d} exceeds startup pool capacity={d}; restart required",
                    .{ next.max_connections, pool_capacity },
                );
                static_changes += 1;
            }
        }

        if (static_changes > 0) {
            log.warn("SIGHUP: {d} non-reloadable settings changed; restart required for full apply", .{static_changes});
        }
        if (applied == 0) {
            log.info("SIGHUP: config reloaded, no hot-reloadable changes detected", .{});
            return;
        }
        log.info("SIGHUP: applied {d} hot-reloadable setting(s)", .{applied});
    }

    fn resolveMaskAddress(self: *EventLoop, cfg: *const Config) ?Address {
        if (!cfg.mask) return null;
        const mask_target = if (cfg.mask_port == 443) cfg.tls_domain else "127.0.0.1";
        const list = getAddressList(self.state.allocator, mask_target, cfg.mask_port) catch |err| {
            log.warn("SIGHUP: mask target resolve failed for '{s}:{d}': {any}", .{ mask_target, cfg.mask_port, err });
            return null;
        };
        defer list.deinit();
        if (list.addrs.len == 0) return null;
        return list.addrs[0];
    }

    fn onClientReadable(self: *EventLoop, slot: *ConnectionSlot) void {
        slot.last_activity_ms = nowMs();

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
            slot.last_activity_ms = nowMs();
        }

        switch (slot.phase) {
            .writing_server_hello_first => {
                if (!slot.hasClientPending()) {
                    slot.phase = .desync_wait;
                    slot.desync_deadline_ns = nowNs() + (3 * std.time.ns_per_ms);
                    self.enqueueDesyncWait(slot) catch {
                        self.closeSlot(slot, "desync wait queue failed");
                        return;
                    };
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
        slot.last_activity_ms = nowMs();

        switch (slot.phase) {
            .proxy_socks5_greeting_resp,
            .proxy_socks5_auth_resp,
            .proxy_socks5_connect_resp,
            => self.onProxySocks5Readable(slot),
            .proxy_http_connect_resp => self.onProxyHttpConnectReadable(slot),
            .middle_proxy_handshake => self.middleProxyOnReadable(slot),
            .relaying => self.relayUpstreamToClient(slot),
            .mask_relaying => self.relayRawUpstreamToClient(slot),
            else => {},
        }
    }

    fn onUpstreamWritable(self: *EventLoop, slot: *ConnectionSlot) void {
        switch (slot.phase) {
            .connecting_upstream => self.onUpstreamConnectComplete(slot),
            .proxy_socks5_greeting,
            .proxy_socks5_auth,
            .proxy_socks5_connect,
            .proxy_http_connect,
            => {
                // Proxy handshake phases: flush pending writes.
                if (slot.hasUpstreamPending()) {
                    if (flushUpstreamPending(slot, self.state.allocator)) |_| {} else |err| {
                        log.debug("[{d}] proxy handshake flush error: {any}", .{ slot.conn_id, err });
                        self.closeSlot(slot, "proxy handshake flush error");
                        return;
                    }
                }

                if (!slot.hasUpstreamPending()) {
                    slot.last_activity_ms = nowMs();
                    // Write complete, switch to reading response
                    switch (slot.phase) {
                        .proxy_socks5_greeting => slot.phase = .proxy_socks5_greeting_resp,
                        .proxy_socks5_auth => slot.phase = .proxy_socks5_auth_resp,
                        .proxy_socks5_connect => slot.phase = .proxy_socks5_connect_resp,
                        .proxy_http_connect => slot.phase = .proxy_http_connect_resp,
                        else => {},
                    }
                    slot.proxy_handshake_pos = 0;
                }
            },
            .writing_dc_nonce, .relaying, .mask_relaying, .middle_proxy_handshake => {
                const had_pending = slot.hasUpstreamPending();
                if (flushUpstreamPending(slot, self.state.allocator)) |_| {} else |err| {
                    log.debug("[{d}] upstream flush error: {any}", .{ slot.conn_id, err });
                    self.closeSlot(slot, "upstream flush error");
                    return;
                }
                if (had_pending and !slot.hasUpstreamPending()) {
                    slot.last_activity_ms = nowMs();
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

    fn enqueueDesyncWait(self: *EventLoop, slot: *ConnectionSlot) !void {
        if (slot.desync_wait_enqueued) return;
        try self.desync_wait_slots.append(self.state.allocator, slot.index);
        slot.desync_wait_enqueued = true;
    }

    fn processDesyncWaits(self: *EventLoop) void {
        if (self.desync_wait_slots.items.len == 0) return;

        const now_ns = nowNs();
        var write_idx: usize = 0;
        var read_idx: usize = 0;

        while (read_idx < self.desync_wait_slots.items.len) : (read_idx += 1) {
            const slot_idx = self.desync_wait_slots.items[read_idx];
            const slot = self.pool.slots[slot_idx] orelse continue;

            if (slot.phase != .desync_wait) {
                slot.desync_wait_enqueued = false;
                continue;
            }

            if (now_ns < slot.desync_deadline_ns) {
                self.desync_wait_slots.items[write_idx] = slot_idx;
                write_idx += 1;
                continue;
            }

            slot.desync_wait_enqueued = false;
            slot.phase = .writing_server_hello_rest;

            if (slot.server_hello) |sh| {
                if (slot.server_hello_off < sh.len) {
                    if (queueClient(slot, self.state.allocator, sh[slot.server_hello_off..])) |_| {
                        slot.server_hello_off = sh.len;
                    } else |_| {
                        self.closeSlot(slot, "desync rest write failed");
                        continue;
                    }
                }
            }

            self.syncInterests(slot) catch |err| {
                log.debug("[{d}] desync syncInterests error: {any}", .{ slot.conn_id, err });
                self.closeSlot(slot, "desync sync interests failed");
            };
        }

        self.desync_wait_slots.shrinkRetainingCapacity(write_idx);
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
                slot.first_byte_at_ms = nowMs();
            }
            slot.tls_hdr_pos += @intCast(n);
            slot.last_activity_ms = nowMs();
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
            slot.last_activity_ms = nowMs();
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

        slot.server_hello = tls.buildServerHelloWithTemplate(
            self.state.allocator,
            self.state.tls_server_hello_template[0..],
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

            const read_buf = self.shared_read_buf[0..];
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
        // The user and their secret were already resolved during FakeTLS
        // validation (`onTlsClientHelloComplete`), so the obfuscation
        // parameters can be derived in strict O(1) instead of iterating the
        // full user list with a SHA-256 + AES-CTR per candidate. With large
        // configs (hundreds of users) this saves a significant amount of CPU
        // per handshake and shrinks the DPI-probe amplification factor.
        const known_secret = [_]obfuscation.UserSecret{.{
            .name = slot.validation_user[0..slot.validation_user_len],
            .secret = slot.validation_secret,
        }};
        const result = obfuscation.ObfuscationParams.fromHandshake(&slot.handshake_buf, &known_secret) orelse {
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

        const plan = buildDcConnectPlan(&self.state.config, dc_abs, slot.dc_idx, if (snapshot) |*s| s else null, result.user);
        if (plan.count == 0) {
            self.closeSlot(slot, "no upstream candidates");
            return;
        }

        slot.user_metrics = self.state.findUserMetrics(result.user);
        if (slot.user_metrics) |entry| {
            _ = entry.connections_active.fetchAdd(1, .monotonic);
        }

        slot.dc_abs = @intCast(dc_abs);
        slot.use_middle_proxy = plan.use_middle_proxy;
        slot.is_media_path = plan.is_media_path;
        slot.use_fast_mode = self.state.config.fast_mode and !slot.use_middle_proxy and (dc_abs >= 1 and dc_abs <= constants.tg_datacenters_v4.len);
        slot.direct_fallback_addr = plan.direct_fallback;
        slot.direct_fallback_used = false;

        // Log DC routing decisions at debug level (enable with log_level = "debug" in config)
        if (plan.is_media_path) {
            var addr_buf: [64]u8 = undefined;
            const addr_str = formatAddress(plan.candidates[0], &addr_buf);
            log.debug("[{d}] route: dc_idx={d} dc_abs={d} media={} middle_proxy={} candidates={d} -> {s}", .{
                slot.conn_id,
                slot.dc_idx,
                dc_abs,
                plan.is_media_path,
                plan.use_middle_proxy,
                plan.count,
                addr_str,
            });
        }

        slot.setUpstreamCandidates(self.state.allocator, plan.candidates[0..plan.count]) catch {
            self.closeSlot(slot, "alloc upstream candidate list failed");
            return;
        };

        const candidates = slot.upstreamCandidates();
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

    fn startConnectUpstream(self: *EventLoop, slot: *ConnectionSlot, addr: Address, kind: UpstreamKind) !void {
        const connect_result = if (kind == .mask) blk: {
            const direct = upstream_mod.Upstream.initDirect();
            break :blk try direct.connect(addr);
        } else try self.state.upstream.connect(addr);
        const fd = connect_result.fd;
        errdefer closeFd(fd);

        try self.addFd(fd, false, true);
        errdefer _ = self.delFd(fd) catch {};

        try self.pool.mapFd(fd, slot.index);
        errdefer self.pool.unmapFd(fd);

        slot.upstream_fd = fd;
        slot.upstream_kind = kind;
        slot.current_upstream_addr = addr;
        slot.phase = .connecting_upstream;

        // For proxy upstreams, stash the real target address for the proxy handshake.
        if (connect_result.proxy_handshake != .none) {
            slot.proxy_target_addr = addr;
        }

        errdefer {
            slot.upstream_fd = -1;
            slot.upstream_kind = .none;
            slot.current_upstream_addr = null;
            slot.proxy_target_addr = null;
        }

        if (!connect_result.pending) {
            self.onUpstreamConnectComplete(slot);
        }
    }

    fn onUpstreamConnectComplete(self: *EventLoop, slot: *ConnectionSlot) void {
        if (checkSocketConnectError(slot.upstream_fd)) |_| {} else |err| {
            const failed_kind = slot.upstream_kind;
            self.cleanupFailedUpstreamConnect(slot);

            if (failed_kind == .dc and self.tryNextDcEndpoint(slot, err)) {
                return;
            }

            log.debug("[{d}] connect completion failed: dc_idx={d} media={} err={any}", .{
                slot.conn_id,
                slot.dc_idx,
                slot.is_media_path,
                err,
            });
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
            // Handshake complete (mask path) — release from handshake budget
            _ = self.state.handshakes_inflight.fetchSub(1, .monotonic);
            slot.phase = .mask_relaying;
            return;
        }

        // Check if we need a proxy handshake before proceeding to DC.
        if (slot.proxy_target_addr != null) {
            switch (self.state.upstream) {
                .socks5 => {
                    self.startSocks5Handshake(slot);
                    return;
                },
                .http_connect => {
                    self.startHttpConnectHandshake(slot);
                    return;
                },
                .direct => {},
            }
        }

        if (slot.use_middle_proxy) {
            self.middleProxyBegin(slot);
            return;
        }

        self.sendDcNonce(slot);
    }

    fn startSocks5Handshake(self: *EventLoop, slot: *ConnectionSlot) void {
        return proxy_upstream_handshake.startSocks5(
            self,
            slot,
            proxyHandshakeQueueUpstream,
            proxyHandshakeCloseSlot,
        );
    }

    fn onProxySocks5Readable(self: *EventLoop, slot: *ConnectionSlot) void {
        return proxy_upstream_handshake.onSocks5Readable(
            self,
            slot,
            proxyHandshakeQueueUpstream,
            proxyHandshakeCloseSlot,
            proxyHandshakeCompleteCallback,
        );
    }

    fn startHttpConnectHandshake(self: *EventLoop, slot: *ConnectionSlot) void {
        return proxy_upstream_handshake.startHttpConnect(
            self,
            slot,
            proxyHandshakeQueueUpstream,
            proxyHandshakeCloseSlot,
        );
    }

    fn onProxyHttpConnectReadable(self: *EventLoop, slot: *ConnectionSlot) void {
        return proxy_upstream_handshake.onHttpConnectReadable(
            self,
            slot,
            proxyHandshakeCloseSlot,
            proxyHandshakeCompleteCallback,
        );
    }

    // ─── Common: proxy handshake → DC path transition ───────────

    fn proxyHandshakeComplete(self: *EventLoop, slot: *ConnectionSlot) void {
        slot.proxy_target_addr = null;

        log.debug("[{d}] proxy handshake complete, proceeding to DC path", .{slot.conn_id});

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
            closeFd(fd);
            slot.upstream_fd = -1;
        }
        slot.upstream_kind = .none;
        slot.current_upstream_addr = null;
        slot.upstream_queue.clear();
    }

    fn tryNextDcEndpoint(self: *EventLoop, slot: *ConnectionSlot, err: anyerror) bool {
        return upstream_failover.tryNextDcEndpoint(
            self,
            slot,
            err,
            startConnectUpstreamDc,
            mpFallbackSetSingleUpstreamCandidate,
        );
    }

    fn sendDcNonce(self: *EventLoop, slot: *ConnectionSlot) void {
        return dc_nonce.send(
            self,
            slot,
            proxyHandshakeQueueUpstream,
            proxyHandshakeCloseSlot,
        );
    }

    fn startRelay(self: *EventLoop, slot: *ConnectionSlot) void {
        return relay_steps.startRelay(
            self,
            slot,
            relayEnsureMpC2sScratch,
            proxyHandshakeQueueUpstream,
            proxyHandshakeCloseSlot,
        );
    }

    fn relayClientToUpstream(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasUpstreamPending()) return;

        const mp_c2s_scratch = if (slot.middle_ctx != null)
            self.ensureMpC2sScratch() catch {
                self.closeSlot(slot, "alloc middleproxy c2s scratch failed");
                return;
            }
        else
            null;

        const progress = relayClientToUpstreamStep(slot, self.state.allocator, mp_c2s_scratch, self.shared_read_buf[0..]) catch |err| {
            if (slot.is_media_path) {
                log.debug("[{d}] relay c2s error: dc_idx={d} err={any} c2s={d} s2c={d}", .{
                    slot.conn_id, slot.dc_idx, err, slot.c2s_bytes, slot.s2c_bytes,
                });
            }
            self.closeSlot(slot, "relay c2s failed");
            return;
        };
        if (progress == .forwarded or progress == .partial) {
            slot.last_activity_ms = nowMs();
        }
    }

    fn relayUpstreamToClient(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasClientPending()) return;

        const mp_s2c_scratch = if (slot.middle_ctx != null)
            self.ensureMpS2cScratch() catch {
                self.closeSlot(slot, "alloc middleproxy s2c scratch failed");
                return;
            }
        else
            null;

        const progress = relayUpstreamToClientStep(slot, self.state.allocator, mp_s2c_scratch, self.shared_read_buf[0..]) catch |err| {
            if (slot.is_media_path) {
                log.debug("[{d}] relay s2c error: dc_idx={d} err={any} c2s={d} s2c={d}", .{
                    slot.conn_id, slot.dc_idx, err, slot.c2s_bytes, slot.s2c_bytes,
                });
            }
            self.closeSlot(slot, "relay s2c failed");
            return;
        };
        if (progress == .forwarded or progress == .partial) {
            slot.last_activity_ms = nowMs();
        }
    }

    fn relayRawClientToUpstream(self: *EventLoop, slot: *ConnectionSlot) void {
        return relay_steps.relayRawClientToUpstream(
            self,
            slot,
            self.shared_read_buf[0..],
            proxyHandshakeQueueUpstream,
            proxyHandshakeCloseSlot,
        );
    }

    fn relayRawUpstreamToClient(self: *EventLoop, slot: *ConnectionSlot) void {
        return relay_steps.relayRawUpstreamToClient(
            self,
            slot,
            self.shared_read_buf[0..],
            relayQueueClient,
            proxyHandshakeCloseSlot,
        );
    }

    fn middleProxyBegin(self: *EventLoop, slot: *ConnectionSlot) void {
        return middle_proxy_handshake.begin(
            self,
            slot,
            mpHandshakeWriteFrame,
            mpLockMiddleProxyShared,
            mpUnlockMiddleProxyShared,
            mpHandshakeCloseSlot,
        );
    }

    fn middleProxyOnWritable(self: *EventLoop, slot: *ConnectionSlot) void {
        _ = self;
        return middle_proxy_handshake.onWritable(slot);
    }

    fn middleProxyOnReadable(self: *EventLoop, slot: *ConnectionSlot) void {
        return middle_proxy_handshake.onReadable(
            self,
            slot,
            mpHandshakeReadFrame,
            mpHandshakeWriteFrame,
            mpLockMiddleProxyShared,
            mpUnlockMiddleProxyShared,
            mpHandshakeStartRelay,
            mpHandshakeCloseSlot,
            mpHandshakeFallbackToDirect,
        );
    }

    fn fallbackFromMiddleProxyToDirect(self: *EventLoop, slot: *ConnectionSlot) bool {
        return middle_proxy_fallback.fallbackToDirect(
            self,
            slot,
            mpFallbackSendDcNonce,
            mpFallbackCleanupFailedUpstreamConnect,
            mpFallbackSetSingleUpstreamCandidate,
            mpFallbackStartDirectConnect,
        );
    }

    fn mpWriteFrame(self: *EventLoop, slot: *ConnectionSlot, payload: []const u8, encrypted: bool) !void {
        return middle_proxy_frames.writeFrame(
            slot,
            self.state.allocator,
            payload,
            encrypted,
            mp_handshake_frame_buf_size,
            slotQueueUpstream,
        );
    }

    fn mpTryReadFrame(self: *EventLoop, slot: *ConnectionSlot, encrypted: bool) !?[]const u8 {
        return middle_proxy_frames.tryReadFrame(
            slot,
            self.state.allocator,
            encrypted,
            mp_handshake_frame_buf_size,
        );
    }

    fn runTimers(self: *EventLoop) void {
        const now_ms = nowMs();

        const hi: usize = @intCast(self.pool.allocated_hi);
        if (hi == 0) return;

        var idx: usize = @intCast(self.timer_scan_cursor);
        if (idx >= hi) idx = 0;

        const budget = @min(hi, timer_scan_budget);
        var scanned: usize = 0;
        while (scanned < budget) : (scanned += 1) {
            const slot_opt = self.pool.slots[idx];
            idx += 1;
            if (idx >= hi) idx = 0;

            const slot = slot_opt orelse continue;
            if (slot.phase == .idle) continue;

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
                    _ = self.state.stats_hs_timeout.fetchAdd(1, .monotonic);
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

        self.timer_scan_cursor = @intCast(idx);
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

            .proxy_socks5_greeting,
            .proxy_socks5_auth,
            .proxy_socks5_connect,
            .proxy_http_connect,
            => {
                want_client_in = false;
                want_upstream_out = true;
            },

            .proxy_socks5_greeting_resp,
            .proxy_socks5_auth_resp,
            .proxy_socks5_connect_resp,
            .proxy_http_connect_resp,
            => {
                want_client_in = false;
                want_upstream_in = true;
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

    fn ensureMpC2sScratch(self: *EventLoop) ![]u8 {
        if (self.mp_c2s_scratch) |buf| return buf;

        // Worst-case RPC_PROXY_REQ expansion.
        // The smallest consumable input is a single abridged header byte with
        // len_val=0 → 0-byte payload → encrypted_len = 96 with ad_tag.
        // A pathological client pipelining 1MB of such bytes would expand to
        // ~96MB of encapsulated frames. Sizing the scratch buffer to match
        // keeps encapsulateC2S overflow-free under adversarial load and
        // prevents the spurious connection drops observed in production.
        //
        // One allocation per EventLoop (single-threaded), so the memory cost
        // is bounded regardless of connection count.
        const mp_max_expansion: usize = 96;
        const capacity = self.state.config.middleProxyBufferBytes() * mp_max_expansion + 256;
        const buf = try self.state.allocator.alloc(u8, capacity);
        self.mp_c2s_scratch = buf;
        return buf;
    }

    fn ensureMpS2cScratch(self: *EventLoop) ![]u8 {
        if (self.mp_s2c_scratch) |buf| return buf;
        const buf = try self.state.allocator.alloc(u8, self.state.config.middleProxyBufferBytes());
        self.mp_s2c_scratch = buf;
        return buf;
    }

    fn closeSlot(self: *EventLoop, slot: *ConnectionSlot, reason: []const u8) void {
        if (slot.phase == .idle) return;
        log.debug("[{d}] closing: dc_idx={d} media={} phase={s} reason={s} c2s={d} s2c={d}", .{
            slot.conn_id,
            slot.dc_idx,
            slot.is_media_path,
            @tagName(slot.phase),
            reason,
            slot.c2s_bytes,
            slot.s2c_bytes,
        });

        if (slot.client_fd != -1) {
            _ = self.delFd(slot.client_fd) catch {};
            self.pool.unmapFd(slot.client_fd);
            closeFd(slot.client_fd);
            slot.client_fd = -1;
        }

        if (slot.upstream_fd != -1) {
            _ = self.delFd(slot.upstream_fd) catch {};
            self.pool.unmapFd(slot.upstream_fd);
            closeFd(slot.upstream_fd);
            slot.upstream_fd = -1;
        }

        const user_metrics = slot.user_metrics;
        slot.resetOwnedBuffers(self.state.allocator);

        if (slot.active_reserved) {
            _ = self.state.active_connections.fetchSub(1, .monotonic);
            _ = self.state.closed_count.fetchAdd(1, .monotonic);
            if (user_metrics) |entry| {
                _ = entry.connections_active.fetchSub(1, .monotonic);
            }
            // If connection was still in handshake phase, release from handshake budget
            if (slot.handshakeInProgress()) {
                _ = self.state.handshakes_inflight.fetchSub(1, .monotonic);
            }
            slot.active_reserved = false;
            self.closed_since_log += 1;
        }

        slot.desync_wait_enqueued = false;
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

        const current_len: usize = if (slot.pipelined_data) |p| p.len else 0;
        const next_len = std.math.add(usize, current_len, extra.len) catch {
            return error.PipelinedDataTooLarge;
        };
        if (next_len > max_pipelined_handshake_bytes) {
            return error.PipelinedDataTooLarge;
        }

        if (slot.pipelined_data == null) {
            const buf = try self.state.allocator.alloc(u8, next_len);
            @memcpy(buf, extra);
            slot.pipelined_data = buf;
            return;
        }

        const prev = slot.pipelined_data.?;
        const next = try self.state.allocator.alloc(u8, next_len);
        @memcpy(next[0..prev.len], prev);
        @memcpy(next[prev.len..], extra);
        self.state.allocator.free(prev);
        slot.pipelined_data = next;
    }
};

fn relayClientToUpstreamStep(slot: *ConnectionSlot, allocator: std.mem.Allocator, mp_c2s_scratch: ?[]u8, read_buf: []u8) !RelayProgress {
    return relay_steps.relayClientToUpstreamStep(slot, allocator, mp_c2s_scratch, read_buf, queueUpstream);
}

fn relayUpstreamToClientStep(slot: *ConnectionSlot, allocator: std.mem.Allocator, mp_s2c_scratch: ?[]u8, read_buf: []u8) !RelayProgress {
    return relay_steps.relayUpstreamToClientStep(slot, allocator, mp_s2c_scratch, read_buf, queueTlsAppRecords);
}

fn queueTlsAppRecords(slot: *ConnectionSlot, allocator: std.mem.Allocator, payload: []u8) !void {
    return relay_steps.queueTlsAppRecords(slot, allocator, payload, slotQueueClientPair);
}

/// Dummy counter for slots that don't yet have traffic counters attached
/// (e.g. during mask phase or before handshake completes).  Writes are
/// silently absorbed so the data path never errors out on missing metrics.
var noop_counter = std.atomic.Value(u64).init(0);

fn slotQueueClient(slot: *ConnectionSlot, allocator: std.mem.Allocator, data: []const u8) !bool {
    _ = allocator;
    return queue_io.queueOrWriteMsg(
        slot.client_fd,
        &slot.client_queue,
        data,
        slot.traffic_upstream_to_client_counter orelse &noop_counter,
        if (slot.user_metrics) |entry| &entry.upstream_to_client_bytes_total else null,
    );
}

fn slotQueueClientPair(slot: *ConnectionSlot, allocator: std.mem.Allocator, first: []const u8, second: []const u8) !bool {
    _ = allocator;
    return queue_io.queueOrWriteMsgPair(
        slot.client_fd,
        &slot.client_queue,
        first,
        second,
        slot.traffic_upstream_to_client_counter orelse &noop_counter,
        if (slot.user_metrics) |entry| &entry.upstream_to_client_bytes_total else null,
    );
}

fn slotQueueClientOwned(slot: *ConnectionSlot, allocator: std.mem.Allocator, owned: []u8) !bool {
    _ = allocator;
    return queue_io.queueOrWriteOwnedMsg(
        slot.client_fd,
        &slot.client_queue,
        owned,
        slot.traffic_upstream_to_client_counter orelse &noop_counter,
        if (slot.user_metrics) |entry| &entry.upstream_to_client_bytes_total else null,
    );
}

fn slotQueueUpstream(slot: *ConnectionSlot, allocator: std.mem.Allocator, data: []const u8) !bool {
    _ = allocator;
    return queue_io.queueOrWriteMsg(
        slot.upstream_fd,
        &slot.upstream_queue,
        data,
        slot.traffic_client_to_upstream_counter orelse &noop_counter,
        if (slot.user_metrics) |entry| &entry.client_to_upstream_bytes_total else null,
    );
}

fn slotFlushClientPending(slot: *ConnectionSlot, allocator: std.mem.Allocator) !bool {
    _ = allocator;
    return queue_io.flushQueue(
        slot.client_fd,
        &slot.client_queue,
        slot.traffic_upstream_to_client_counter orelse &noop_counter,
        if (slot.user_metrics) |entry| &entry.upstream_to_client_bytes_total else null,
    );
}

fn slotFlushUpstreamPending(slot: *ConnectionSlot, allocator: std.mem.Allocator) !bool {
    _ = allocator;
    return queue_io.flushQueue(
        slot.upstream_fd,
        &slot.upstream_queue,
        slot.traffic_client_to_upstream_counter orelse &noop_counter,
        if (slot.user_metrics) |entry| &entry.client_to_upstream_bytes_total else null,
    );
}

fn slotMpReadReset(slot: *ConnectionSlot, encrypted: bool) void {
    return middle_proxy_frames.readReset(slot, encrypted);
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

fn proxyHandshakeQueueUpstream(loop: *EventLoop, slot: *ConnectionSlot, data: []const u8) !bool {
    return queueUpstream(slot, loop.state.allocator, data);
}

fn proxyHandshakeCloseSlot(loop: *EventLoop, slot: *ConnectionSlot, reason: []const u8) void {
    return loop.closeSlot(slot, reason);
}

fn proxyHandshakeCompleteCallback(loop: *EventLoop, slot: *ConnectionSlot) void {
    return loop.proxyHandshakeComplete(slot);
}

fn relayEnsureMpC2sScratch(loop: *EventLoop) ![]u8 {
    return loop.ensureMpC2sScratch();
}

fn relayQueueClient(loop: *EventLoop, slot: *ConnectionSlot, data: []const u8) !bool {
    return queueClient(slot, loop.state.allocator, data);
}

fn startConnectUpstreamDc(loop: *EventLoop, slot: *ConnectionSlot, addr: Address) !void {
    return loop.startConnectUpstream(slot, addr, .dc);
}

fn mpFallbackSendDcNonce(loop: *EventLoop, slot: *ConnectionSlot) void {
    return loop.sendDcNonce(slot);
}

fn mpFallbackCleanupFailedUpstreamConnect(loop: *EventLoop, slot: *ConnectionSlot) void {
    return loop.cleanupFailedUpstreamConnect(slot);
}

fn mpFallbackSetSingleUpstreamCandidate(loop: *EventLoop, slot: *ConnectionSlot, addr: Address) !void {
    var one = [_]Address{addr};
    try slot.setUpstreamCandidates(loop.state.allocator, one[0..]);
}

fn mpFallbackStartDirectConnect(loop: *EventLoop, slot: *ConnectionSlot, addr: Address) !void {
    return loop.startConnectUpstream(slot, addr, .dc);
}

fn mpHandshakeReadFrame(loop: *EventLoop, slot: *ConnectionSlot, encrypted: bool) !?[]const u8 {
    return loop.mpTryReadFrame(slot, encrypted);
}

fn mpHandshakeWriteFrame(loop: *EventLoop, slot: *ConnectionSlot, payload: []const u8, encrypted: bool) !void {
    return loop.mpWriteFrame(slot, payload, encrypted);
}

fn mpLockMiddleProxyShared(loop: *EventLoop) void {
    loop.state.middle_proxy_lock.lockShared();
}

fn mpUnlockMiddleProxyShared(loop: *EventLoop) void {
    loop.state.middle_proxy_lock.unlockShared();
}

fn mpHandshakeStartRelay(loop: *EventLoop, slot: *ConnectionSlot) void {
    return loop.startRelay(slot);
}

fn mpHandshakeCloseSlot(loop: *EventLoop, slot: *ConnectionSlot, reason: []const u8) void {
    return loop.closeSlot(slot, reason);
}

fn mpHandshakeFallbackToDirect(loop: *EventLoop, slot: *ConnectionSlot) bool {
    return loop.fallbackFromMiddleProxyToDirect(slot);
}

test "handshakeInProgress - phases" {
    var slot: ConnectionSlot = undefined;

    const hs_phases = [_]ConnectionPhase{
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
    };
    for (hs_phases) |phase| {
        slot.phase = phase;
        try std.testing.expect(slot.handshakeInProgress());
    }

    // Non-handshake phases
    slot.phase = .idle;
    try std.testing.expect(!slot.handshakeInProgress());
    slot.phase = .relaying;
    try std.testing.expect(!slot.handshakeInProgress());
    slot.phase = .mask_relaying;
    try std.testing.expect(!slot.handshakeInProgress());
    slot.phase = .closing;
    try std.testing.expect(!slot.handshakeInProgress());
}
