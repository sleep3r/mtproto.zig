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
const sd_notify = @import("sd_notify.zig");
const Config = @import("../config.zig").Config;
const upstream_mod = @import("upstream.zig");
const tunnel_mod = @import("../tunnel.zig");
const socks5 = @import("socks5.zig");
const http_connect = @import("http_connect.zig");
const SubnetRateLimit = @import("subnet_rate_limit.zig").SubnetRateLimit;
const HandshakeFloodGuard = @import("handshake_flood_guard.zig").HandshakeFloodGuard;
const DynamicRecordSizer = @import("drs.zig").DynamicRecordSizer;
const ReplayCache = @import("replay_cache.zig").ReplayCache;
const MessageQueue = @import("message_queue.zig").MessageQueue;
const queue_io = @import("queue_io.zig");
const middle_proxy_routing = @import("middle_proxy_routing.zig");
const socket_utils = @import("socket_utils.zig");
const proxy_protocol = @import("proxy_protocol.zig");
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
const middle_proxy_nat = @import("middle_proxy_nat.zig");
const dc_nonce = @import("dc_nonce.zig");
const upstream_failover = @import("upstream_failover.zig");
const runtime_log = @import("../runtime_log.zig");

test {
    // Keep extracted proxy submodule tests in the default `zig build test` run.
    _ = @import("subnet_rate_limit.zig");
    _ = @import("handshake_flood_guard.zig");
    _ = @import("drs.zig");
    _ = @import("replay_cache.zig");
    _ = @import("message_queue.zig");
    _ = @import("queue_io.zig");
    _ = @import("middle_proxy_routing.zig");
    _ = @import("socket_utils.zig");
    _ = @import("network_detect.zig");
    _ = @import("http_fetch.zig");
    _ = @import("proxy_protocol.zig");
    _ = @import("sd_notify.zig");
    _ = @import("fd_limits.zig");
    _ = @import("connection_phase.zig");
    _ = @import("net_helpers.zig");
    _ = @import("connection_pool.zig");
    _ = @import("relay_steps.zig");
    _ = @import("middle_proxy_frames.zig");
    _ = @import("middle_proxy_handshake.zig");
    _ = @import("proxy_upstream_handshake.zig");
    _ = @import("middle_proxy_fallback.zig");
    _ = @import("middle_proxy_nat.zig");
    _ = @import("dc_nonce.zig");
    _ = @import("upstream_failover.zig");
    _ = @import("socks5.zig");
    _ = @import("../monitoring.zig");
}

const log = std.log.scoped(.proxy);

const tls_header_len = 5;
/// Upper bound on SO_REUSEPORT epoll worker threads ([server].workers / 0=auto).
const max_workers = 256;
/// A worker not ticking within this window is treated as wedged: the signal owner
/// then stops petting the systemd watchdog so the unit is restarted.
const watchdog_stale_ms: i64 = 10_000;
const event_loop_wait_ms: i32 = 37;
/// How long after its first byte a non-TLS (dd) connection may take to deliver
/// the full 64-byte obfuscated handshake before we treat it as a probe and serve
/// the masking cover. Real dd clients send the whole handshake in the first
/// packet, so a few seconds is generous; keeping it well below
/// handshake_timeout_sec shrinks the active-probe timing oracle on the dd path.
const dd_handshake_decision_ms: i64 = 4000;
const desync_wait_poll_ms: i32 = 3;
const accept_backoff_ms: i64 = 500;
const accept_backoff_ns: i128 = @as(i128, accept_backoff_ms) * std.time.ns_per_ms;
const accept_batch_limit: usize = 256;
const stats_log_interval_s: i64 = 10;
const stats_log_interval_ns: i128 = @as(i128, stats_log_interval_s) * std.time.ns_per_s;
const timer_scan_budget: usize = 512;
const middle_proxy_config_url = "https://core.telegram.org/getProxyConfig";
const middle_proxy_secret_url = "https://core.telegram.org/getProxySecret";
// Telegram rotates the middleproxy DC addresses / proxy secret well within a day
// (observed ~10h in production: dc4 moved 91.108.4.139 -> .200, stalling every
// middleproxy handshake until restart). A 24h cadence let the cache go stale, so
// refresh hourly to stay ahead of the rotation. The fetch is cheap and best-effort
// (keeps the current cache on failure), so the extra polls cost ~nothing.
const middle_proxy_update_period_ns: u64 = 60 * 60 * std.time.ns_per_s;
// Minimum gap between *reactive* middleproxy refreshes (those triggered by stalled
// handshakes rather than the periodic timer), so a flood of failing handshakes — or a
// genuine middleproxy-side outage that fresh metadata can't fix — can't spin the
// updater into a refresh storm.
const middle_proxy_reactive_cooldown_ns: u64 = 60 * std.time.ns_per_s;
const tunnel_socket_mark: u32 = 200;
const tunnel_route_table: u32 = 200;
const tunnel_pool_state_path = "/run/mtproto-proxy/tunnel-pool.state";
const min_nofile_soft: usize = 65535;
const client_hello_inline_size: usize = 512;
const mp_handshake_frame_buf_size: usize = 2048;
const read_buf_size: usize = 32 * 1024;
const max_pipelined_handshake_bytes: usize = 128 * 1024;
const graceful_shutdown_check_ms: i32 = 100;

const upstream_candidates_inline_cap: usize = 4;

fn floodGuardSettings(cfg: *const Config) HandshakeFloodGuard.Settings {
    return HandshakeFloodGuard.settings(
        cfg.handshake_flood_guard_enabled,
        cfg.handshake_flood_guard_threshold,
        cfg.handshake_flood_guard_window_sec,
        cfg.handshake_flood_guard_block_sec,
    );
}

fn formatFloodGuardTop(entries: []const HandshakeFloodGuard.TopEntry, buf: *[1024]u8) []const u8 {
    const now_s = @divTrunc(nowMs(), std.time.ms_per_s);
    var pos: usize = 0;

    for (entries) |entry| {
        var ip_buf: [64]u8 = undefined;
        const ip = HandshakeFloodGuard.formatKey(entry.key, &ip_buf);
        const blocked_for = if (entry.blocked_until_s > now_s) entry.blocked_until_s - now_s else 0;

        if (pos > 0 and pos < buf.len) {
            buf[pos] = ',';
            pos += 1;
        }
        const written = std.fmt.bufPrint(
            buf[pos..],
            "{s}=total:{d}/rate:{d}/budget:{d}/timeout:{d}/blocked:{d}s",
            .{
                ip,
                entry.total,
                entry.rate_limit,
                entry.handshake_budget,
                entry.handshake_timeout,
                blocked_for,
            },
        ) catch break;
        pos += written.len;
    }

    return buf[0..pos];
}

fn optionalStringEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a) |av| {
        if (b) |bv| return std.mem.eql(u8, av, bv);
        return false;
    }
    return b == null;
}

// Lock around the shared middle-proxy snapshot. Zig 0.16 has no std.Thread.Mutex
// / std.Thread.RwLock, so this wraps std.Io.Mutex — a real cross-thread futex
// mutex (atomic CAS fast path + futex park/wake via the Io) driven by the global
// single-threaded Io (which disables only async task spawning, NOT mutual
// exclusion). Cross-thread correctness matters because the middle-proxy updater
// runs on its own thread AND, under the SO_REUSEPORT multi-worker model, N worker
// threads read the snapshot concurrently. Readers serialize (no real RwLock
// available), which is fine — the snapshot is read once per connection at routing
// time, not on the per-byte relay path.
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

const ClientTransport = enum {
    fake_tls,
    direct_obfuscated,
};

const MiddleProxyHandshakeStep = enum {
    none,
    sending_rpc_nonce,
    waiting_rpc_nonce_response,
    sending_rpc_handshake,
    waiting_rpc_handshake_response,
    done,

    /// True while the RPC handshake with the middleproxy is in flight. A slot stuck
    /// here is waiting on the middleproxy (its DC address / secret), so a timeout
    /// here is evidence the cached metadata may have gone stale.
    fn awaitingMiddleProxy(self: MiddleProxyHandshakeStep) bool {
        return switch (self) {
            .sending_rpc_nonce, .waiting_rpc_nonce_response, .sending_rpc_handshake, .waiting_rpc_handshake_response => true,
            .none, .done => false,
        };
    }
};

const MiddleProxyFetchRoute = enum {
    direct,
    tunnel,
    socks5,
    http_connect,
};

fn middleProxyFetchRouteForConfig(cfg: *const Config) MiddleProxyFetchRoute {
    return switch (cfg.upstream_mode) {
        .socks5 => .socks5,
        .http => .http_connect,
        .tunnel => .tunnel,
        .auto, .direct => .direct,
    };
}

test "middle-proxy refresh selects proxy route for explicit socks5 and http upstreams" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
    };
    defer cfg.deinit(std.testing.allocator);

    cfg.upstream_mode = .socks5;
    try std.testing.expectEqual(MiddleProxyFetchRoute.socks5, middleProxyFetchRouteForConfig(&cfg));

    cfg.upstream_mode = .http;
    try std.testing.expectEqual(MiddleProxyFetchRoute.http_connect, middleProxyFetchRouteForConfig(&cfg));

    cfg.upstream_mode = .tunnel;
    try std.testing.expectEqual(MiddleProxyFetchRoute.tunnel, middleProxyFetchRouteForConfig(&cfg));
}

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
const setLingerReset = socket_utils.setLingerReset;
const setNonBlocking = socket_utils.setNonBlocking;
const secondsToMs = socket_utils.secondsToMs;

/// Per-connection idle timeout in ms with ±jitter_pct random jitter, so a constant
/// idle timeout isn't a behavioral fingerprint. `seed` varies per connection. Floored
/// to half the base (and >= 5s) so jitter never makes the timeout pathologically short.
fn jitteredIdleTimeoutMs(base_sec: u32, jitter_pct: u8, seed: u64) i64 {
    const base_ms = secondsToMs(base_sec);
    if (jitter_pct == 0) return base_ms;
    const pct: i64 = @min(@as(i64, jitter_pct), 100);
    const range = @divTrunc(base_ms * pct, 100);
    if (range <= 0) return base_ms;
    const span: u64 = @intCast(2 * range + 1);
    const offset = @as(i64, @intCast(seed % span)) - range;
    const floor_ms = @max(secondsToMs(5), @divTrunc(base_ms, 2));
    return @max(floor_ms, base_ms + offset);
}
const setTcpNoDelay = socket_utils.setTcpNoDelay;
const configureRelaySocket = socket_utils.configureRelaySocket;
const formatAddress = socket_utils.formatAddress;

const parseListenAddress = network_detect.parseListenAddress;
const isRunningInNonInitNetns = network_detect.isRunningInNonInitNetns;
const detectAwgEndpointIpv4 = network_detect.detectAwgEndpointIpv4;
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
const isClientDrivenHandshakePhase = connection_phase.isClientDrivenHandshakePhase;
const RelayProgress = relay_steps.RelayProgress;
const AddressList = net_helpers.AddressList;
const ip4 = net_helpers.ip4;
const ip6 = net_helpers.ip6;
const isIpv6 = net_helpers.isIpv6;
const addressEql = net_helpers.addressEql;
const getAddressList = net_helpers.getAddressList;

/// A safelisted SNI the masking backend may front to that domain's own server.
pub const MaskSafelistEntry = struct {
    /// Lower-cased domain (points into the owned Config; matched case-insensitively).
    domain: []const u8,
    /// Resolved address (port 443) of that domain's real server.
    addr: Address,
};

/// Fetch a public-IP echo service through the SAME egress middle-proxy traffic uses, so
/// the IP we feed into the MP key derivation matches what Telegram's MiddleProxy observes.
/// A plain direct probe returns the HOST's IP even when egress is socks5/http/tunnel — the
/// long-standing "socks + ad-tag doesn't work out of the box, you must set
/// middle_proxy_nat_ip by hand" trap. Routing the probe through the upstream removes it.
fn fetchPublicIpProbe(allocator: std.mem.Allocator, cfg: *const Config, url: []const u8) ![]u8 {
    switch (cfg.upstream_mode) {
        .socks5, .http => {
            const host = cfg.upstream_proxy_host orelse return error.InvalidProxyUpstreamConfig;
            if (cfg.upstream_proxy_port == 0) return error.InvalidProxyUpstreamConfig;
            return http_fetch.fetchUrlBytesViaProxy(allocator, url, .{
                .kind = if (cfg.upstream_mode == .socks5) .socks5 else .http_connect,
                .host = host,
                .port = cfg.upstream_proxy_port,
                .username = cfg.upstream_proxy_username,
                .password = cfg.upstream_proxy_password,
            });
        },
        .tunnel => {
            const iface = cfg.tunnelCandidateAt(0) orelse cfg.upstream_tunnel_interface orelse "awg0";
            return fetchUrlBytesViaInterface(allocator, url, iface);
        },
        .auto, .direct => return fetchUrlBytes(allocator, url),
    }
}

/// Detect the public IPv4 as seen from the configured egress (see fetchPublicIpProbe).
fn detectPublicIpv4ViaEgress(allocator: std.mem.Allocator, cfg: *const Config) ?[4]u8 {
    const services = [_][]const u8{
        "https://api.ipify.org",
        "https://ifconfig.me",
        "https://ipv4.icanhazip.com",
    };
    for (services) |url| {
        const bytes = fetchPublicIpProbe(allocator, cfg, url) catch continue;
        defer allocator.free(bytes);
        const trimmed = std.mem.trim(u8, bytes, &[_]u8{ ' ', '\t', '\r', '\n' });
        if (network_detect.parseIpv4Literal(trimmed)) |ip| return ip;
    }
    return null;
}

fn runSmallCommand(allocator: std.mem.Allocator, argv: []const []const u8) ?[]u8 {
    var io_instance: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer io_instance.deinit();

    const result = std.process.run(allocator, io_instance.io(), .{
        .argv = argv,
        .stdout_limit = std.Io.Limit.limited(512),
        .stderr_limit = std.Io.Limit.limited(512),
    }) catch return null;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code != 0) return null,
        else => return null,
    }

    const trimmed = std.mem.trim(u8, result.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (trimmed.len == 0) return null;
    return allocator.dupe(u8, trimmed) catch null;
}

/// Fetch the `Date:` header from an HTTPS URL (via curl HEAD) and return the offset
/// (seconds) to add to the local clock so it matches, clamped to ±1 day. Used to correct
/// a skewed VPS clock that would otherwise fail the handshake time-skew check for everyone.
fn fetchClockOffsetSeconds(allocator: std.mem.Allocator, url: []const u8) ?i64 {
    // `-w %header{date}` prints ONLY the Date header value (tiny, always within the small
    // runSmallCommand stdout cap), unlike full `-I` headers where Date could be truncated.
    const out = runSmallCommand(allocator, &.{ "curl", "-sS", "-o", "/dev/null", "--max-time", "8", "-w", "%header{date}", url }) orelse return null;
    defer allocator.free(out);
    const http_epoch = http_fetch.parseHttpDate(out) orelse return null;
    const off = http_epoch - realtimeSeconds();
    return @max(@as(i64, -86400), @min(@as(i64, 86400), off));
}

fn detectActiveTunnelInterface(allocator: std.mem.Allocator) ?[]u8 {
    var table_buf: [16]u8 = undefined;
    const table = std.fmt.bufPrint(&table_buf, "{d}", .{tunnel_route_table}) catch "200";
    const argv = [_][]const u8{
        "sh",
        "-c",
        "ip -4 route show table \"$1\" default 2>/dev/null | awk '/default/ { for (i=1;i<=NF;i++) if ($i==\"dev\") { print $(i+1); exit } }'",
        "sh",
        table,
    };
    return runSmallCommand(allocator, &argv);
}

fn readTunnelPoolStateValue(allocator: std.mem.Allocator, key: []const u8) ?[]u8 {
    const io_instance = std.Io.Threaded.global_single_threaded.io();
    const content = std.Io.Dir.cwd().readFileAlloc(
        io_instance,
        tunnel_pool_state_path,
        allocator,
        .limited(4096),
    ) catch return null;
    defer allocator.free(content);

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const raw_key = std.mem.trim(u8, line[0..eq], &[_]u8{ ' ', '\t', '\r' });
        if (!std.mem.eql(u8, raw_key, key)) continue;
        const value = std.mem.trim(u8, line[eq + 1 ..], &[_]u8{ ' ', '\t', '\r' });
        if (value.len == 0) return null;
        return allocator.dupe(u8, value) catch null;
    }

    return null;
}

fn tryFetchMiddleProxyViaInterface(
    allocator: std.mem.Allocator,
    url: []const u8,
    iface: []const u8,
    direct_err: anyerror,
) ![]u8 {
    const trimmed = std.mem.trim(u8, iface, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (trimmed.len == 0) return error.UnexpectedConnectFailure;
    log.info(
        "Middle-proxy asset {s} unreachable directly ({s}); retrying via tunnel '{s}'",
        .{ url, @errorName(direct_err), trimmed },
    );
    return fetchUrlBytesViaInterface(allocator, url, trimmed);
}

const ConnectionSlot = struct {
    index: u32 = 0,
    conn_id: u64 = 0,

    client_fd: posix.fd_t = -1,
    upstream_fd: posix.fd_t = -1,
    upstream_kind: UpstreamKind = .none,
    client_transport: ClientTransport = .fake_tls,
    peer_addr: Address = undefined,

    phase: ConnectionPhase = .idle,
    active_reserved: bool = false,
    /// True while this connection occupies a handshake-inflight budget slot.
    /// Counted at FIRST BYTE (not accept), so silent/pre-first-byte TCP sessions
    /// (mobile pre-warmed sockets, zero-byte slow-loris) never hold the budget.
    hs_counted: bool = false,

    created_at_ms: i64 = 0,
    first_byte_at_ms: i64 = 0,
    /// When the current upstream connect() was initiated (phase .connecting_upstream).
    /// Reset on every endpoint attempt so dc_connect_timeout_sec is per-endpoint, not
    /// cumulative across failover. 0 when not connecting upstream.
    upstream_connect_started_ms: i64 = 0,
    last_activity_ms: i64 = 0,
    /// Last time client->server payload was relayed (0 until the client first speaks while
    /// relaying), and last time server->client payload was relayed. When the server spoke more
    /// recently than the client (last_server_byte_ms > last_client_byte_ms) the client has an
    /// unanswered reply — the iOS bad_salt "Updating" wedge. Drives client_silence_close_sec.
    last_client_byte_ms: i64 = 0,
    last_server_byte_ms: i64 = 0,
    /// Per-connection idle timeout in ms, with random jitter applied once at setup
    /// so a constant idle timeout isn't itself a behavioral fingerprint. 0 until set.
    idle_timeout_ms: i64 = 0,
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
    /// One-shot override for the next startMasking (SNI-following safelist hit).
    /// Consumed (read + cleared) inside startMasking so it never leaks to a reused slot.
    mask_addr_override: ?Address = null,
    /// Expect a HAProxy PROXY-protocol header before the TLS ClientHello (set at accept
    /// when accept_proxy_protocol is on; cleared once the header is consumed).
    expect_proxy_header: bool = false,

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
    /// Relay half-close drain: one peer gracefully closed (RDHUP, no HUP/ERR) while data
    /// was still queued for the other peer. The hung-up fd is detached from epoll and the
    /// surviving direction is flushed before the slot is torn down, so backpressured s2c/
    /// c2s data isn't silently truncated. `*_detached` marks which fd left epoll.
    relay_half_closed: bool = false,
    client_detached: bool = false,
    upstream_detached: bool = false,

    fn hasClientPending(self: *const ConnectionSlot) bool {
        return !self.client_queue.isEmpty();
    }

    fn hasUpstreamPending(self: *const ConnectionSlot) bool {
        return !self.upstream_queue.isEmpty();
    }

    fn handshakeInProgress(self: *const ConnectionSlot) bool {
        return switch (self.phase) {
            .reading_tls_header,
            .reading_direct_obfuscated_handshake,
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

/// Bounded, low-cardinality classification of why a connection closed. The first
/// five buckets are the evasion/probe signals a circumvention operator needs to
/// SEE a censor start blocking (a spike in tls_validation_failed / replay /
/// handshake_timeout vs baseline). Exported as mtproto_connection_close_reason_total{reason}.
pub const CloseReason = enum(u8) {
    tls_validation_failed,
    sni_mismatch,
    replay_detected,
    handshake_budget,
    handshake_timeout,
    idle_timeout,
    bad_handshake,
    client_eof,
    client_error,
    upstream_error,
    epoll_error,
    internal_error,
    shutdown,
    other,

    pub const count = @typeInfo(CloseReason).@"enum".fields.len;

    /// Bucket a free-text closeSlot reason. Evasion signals matched precisely first.
    pub fn classify(reason: []const u8) CloseReason {
        const has = struct {
            fn f(h: []const u8, n: []const u8) bool {
                return std.mem.indexOf(u8, h, n) != null;
            }
        }.f;
        if (has(reason, "tls validation failed")) return .tls_validation_failed;
        if (has(reason, "sni")) return .sni_mismatch; // mismatch + missing sni
        if (has(reason, "replay")) return .replay_detected;
        if (has(reason, "budget")) return .handshake_budget;
        if (has(reason, "idle")) return .idle_timeout;
        if (has(reason, "timeout")) return .handshake_timeout;
        if (has(reason, "shutdown") or has(reason, "closing")) return .shutdown;
        if (has(reason, "bad ") or has(reason, "invalid") or has(reason, "unexpected") or has(reason, "alert")) return .bad_handshake;
        // Upstream-side markers FIRST: "s2c" (server→client reads) and the dd-relay's
        // "direct obfuscated s2c …" reasons are upstream reads, so they must bucket as
        // upstream_error rather than falling through to the generic eof/read-error
        // (client) buckets below.
        if (has(reason, "connect") or has(reason, "upstream") or has(reason, "candidate") or has(reason, "relay ") or has(reason, "dc tail") or has(reason, "middleproxy") or has(reason, "s2c")) return .upstream_error;
        if (has(reason, "eof")) return .client_eof;
        if (has(reason, "epoll") or has(reason, "interest") or has(reason, "desync") or has(reason, "fd map")) return .epoll_error;
        if (has(reason, "read error")) return .client_error;
        // Only reasons that actually signal an error map to internal_error; any
        // other unmatched (benign/uncategorized) close lands in .other so the
        // internal_error counter stays meaningful for operators.
        if (has(reason, "error") or has(reason, "fail")) return .internal_error;
        return .other;
    }
};

test "CloseReason.classify buckets the evasion signals precisely" {
    try std.testing.expectEqual(CloseReason.tls_validation_failed, CloseReason.classify("tls validation failed"));
    try std.testing.expectEqual(CloseReason.sni_mismatch, CloseReason.classify("tls sni mismatch"));
    try std.testing.expectEqual(CloseReason.sni_mismatch, CloseReason.classify("tls missing sni"));
    try std.testing.expectEqual(CloseReason.replay_detected, CloseReason.classify("replay detected, masking failed"));
    try std.testing.expectEqual(CloseReason.handshake_budget, CloseReason.classify("handshake budget exhausted"));
    try std.testing.expectEqual(CloseReason.handshake_timeout, CloseReason.classify("handshake timeout"));
    try std.testing.expectEqual(CloseReason.handshake_timeout, CloseReason.classify("dd handshake decision timeout"));
    try std.testing.expectEqual(CloseReason.idle_timeout, CloseReason.classify("idle pre-first-byte timeout"));
    try std.testing.expectEqual(CloseReason.bad_handshake, CloseReason.classify("bad tls length"));
    try std.testing.expectEqual(CloseReason.client_eof, CloseReason.classify("client eof before tls header"));
    try std.testing.expectEqual(CloseReason.upstream_error, CloseReason.classify("connect failed"));
    try std.testing.expectEqual(CloseReason.shutdown, CloseReason.classify("shutdown"));
    // Genuine errors → internal_error; benign/uncategorized reasons → other.
    try std.testing.expectEqual(CloseReason.internal_error, CloseReason.classify("config parse failure"));
    try std.testing.expectEqual(CloseReason.other, CloseReason.classify("graceful drain"));
}

test "MiddleProxyHandshakeStep.awaitingMiddleProxy gates the reactive refresh" {
    // Only the in-flight RPC-handshake steps should trigger a reactive refresh; a
    // timeout in .none/.done is not a middleproxy-staleness signal.
    try std.testing.expect(!MiddleProxyHandshakeStep.none.awaitingMiddleProxy());
    try std.testing.expect(!MiddleProxyHandshakeStep.done.awaitingMiddleProxy());
    try std.testing.expect(MiddleProxyHandshakeStep.sending_rpc_nonce.awaitingMiddleProxy());
    try std.testing.expect(MiddleProxyHandshakeStep.waiting_rpc_nonce_response.awaitingMiddleProxy());
    try std.testing.expect(MiddleProxyHandshakeStep.sending_rpc_handshake.awaitingMiddleProxy());
    try std.testing.expect(MiddleProxyHandshakeStep.waiting_rpc_handshake_response.awaitingMiddleProxy());
}

test "jitteredIdleTimeoutMs stays within bounds and respects the floor" {
    const base_sec: u32 = 120;
    const base_ms = secondsToMs(base_sec);
    // jitter 0 → exactly the base timeout
    try std.testing.expectEqual(base_ms, jitteredIdleTimeoutMs(base_sec, 0, 0xdeadbeef));
    // jitter 15% → within [base/2, base + 15%] and never below 5s, across many seeds
    const max_ms = base_ms + @divTrunc(base_ms * 15, 100);
    var i: u64 = 0;
    while (i < 2000) : (i += 1) {
        const v = jitteredIdleTimeoutMs(base_sec, 15, i *% 2654435761);
        try std.testing.expect(v >= @divTrunc(base_ms, 2));
        try std.testing.expect(v >= secondsToMs(5));
        try std.testing.expect(v <= max_ms);
    }
    // not every connection gets the same value (jitter actually varies)
    try std.testing.expect(jitteredIdleTimeoutMs(base_sec, 15, 1) != jitteredIdleTimeoutMs(base_sec, 15, 2));
}

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
        drops_flood_guard_total: u64,
        drops_handshake_budget_total: u64,
        handshake_timeouts_total: u64,
        middleproxy_fallback_total: u64,
        drops_pool_total: u64,
        replay_hits_total: u64,
        unknown_sni_total: u64,
        close_reasons: [CloseReason.count]u64,
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

    fn buildUserSecrets(allocator: std.mem.Allocator, cfg: *const Config) ![]const obfuscation.UserSecret {
        var secrets: std.ArrayList(obfuscation.UserSecret) = .empty;
        errdefer secrets.deinit(allocator);

        var it = @constCast(&cfg.users).iterator();
        while (it.next()) |entry| {
            try secrets.append(allocator, .{
                .name = entry.key_ptr.*,
                .secret = entry.value_ptr.*,
            });
        }

        return try secrets.toOwnedSlice(allocator);
    }

    fn createUserMetrics(allocator: std.mem.Allocator, user_name: []const u8) !*UserMetrics {
        const entry = try allocator.create(UserMetrics);
        errdefer allocator.destroy(entry);

        entry.* = .{
            .name = try allocator.dupe(u8, user_name),
            .connections_active = std.atomic.Value(u32).init(0),
            .client_to_upstream_bytes_total = std.atomic.Value(u64).init(0),
            .upstream_to_client_bytes_total = std.atomic.Value(u64).init(0),
        };
        return entry;
    }

    fn destroyUserMetrics(allocator: std.mem.Allocator, entry: *UserMetrics) void {
        allocator.free(entry.name);
        allocator.destroy(entry);
    }

    fn freeUserMetricsSlice(allocator: std.mem.Allocator, entries: []*UserMetrics) void {
        for (entries) |entry| {
            destroyUserMetrics(allocator, entry);
        }
        allocator.free(entries);
    }

    fn buildInitialUserMetrics(allocator: std.mem.Allocator, cfg: *const Config) ![]*UserMetrics {
        var metrics: std.ArrayList(*UserMetrics) = .empty;
        errdefer {
            for (metrics.items) |entry| {
                destroyUserMetrics(allocator, entry);
            }
            metrics.deinit(allocator);
        }

        var it = @constCast(&cfg.users).iterator();
        while (it.next()) |entry| {
            const metric = try createUserMetrics(allocator, entry.key_ptr.*);
            errdefer destroyUserMetrics(allocator, metric);
            try metrics.append(allocator, metric);
        }

        return try metrics.toOwnedSlice(allocator);
    }

    fn findMetricInSlice(entries: []*UserMetrics, user_name: []const u8) ?*UserMetrics {
        for (entries) |entry| {
            if (std.mem.eql(u8, entry.name, user_name)) return entry;
        }
        return null;
    }

    fn collectRetiredUserMetrics(self: *ProxyState) void {
        var idx: usize = 0;
        while (idx < self.retired_user_metrics.items.len) {
            const entry = self.retired_user_metrics.items[idx];
            if (entry.connections_active.load(.monotonic) == 0) {
                _ = self.retired_user_metrics.swapRemove(idx);
                destroyUserMetrics(self.allocator, entry);
                continue;
            }
            idx += 1;
        }
    }

    fn retireOrDestroyUserMetrics(self: *ProxyState, entry: *UserMetrics) void {
        if (entry.connections_active.load(.monotonic) == 0) {
            destroyUserMetrics(self.allocator, entry);
            return;
        }
        self.retired_user_metrics.appendAssumeCapacity(entry);
    }

    fn deinitAccessMaps(allocator: std.mem.Allocator, cfg: *Config) void {
        var users = &cfg.users;
        var user_it = users.iterator();
        while (user_it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        users.deinit();

        var direct_users = &cfg.direct_users;
        var direct_it = direct_users.iterator();
        while (direct_it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        direct_users.deinit();
    }

    fn moveAccessMapsFrom(self: *ProxyState, next: *Config) void {
        deinitAccessMaps(self.allocator, &self.config);
        self.config.users = next.users;
        self.config.direct_users = next.direct_users;
        next.users = std.StringHashMap([16]u8).init(self.allocator);
        next.direct_users = std.StringHashMap(void).init(self.allocator);
    }

    fn accessMapsEqual(current: *const Config, next: *const Config) bool {
        if (current.users.count() != next.users.count()) return false;
        if (current.direct_users.count() != next.direct_users.count()) return false;

        var user_it = @constCast(&current.users).iterator();
        while (user_it.next()) |entry| {
            const next_secret = next.users.get(entry.key_ptr.*) orelse return false;
            if (!std.mem.eql(u8, entry.value_ptr.*[0..], next_secret[0..])) return false;
        }

        var direct_it = @constCast(&current.direct_users).iterator();
        while (direct_it.next()) |entry| {
            if (!next.direct_users.contains(entry.key_ptr.*)) return false;
        }

        return true;
    }

    fn reloadAccessUsers(self: *ProxyState, next: *Config) !usize {
        if (accessMapsEqual(&self.config, next)) return 0;

        const new_user_secrets = try buildUserSecrets(self.allocator, next);
        errdefer self.allocator.free(new_user_secrets);

        const new_metrics_slice = blk: {
            var new_metrics: std.ArrayList(*UserMetrics) = .empty;
            errdefer {
                for (new_metrics.items) |entry| {
                    if (findMetricInSlice(self.user_metrics, entry.name) == null) {
                        destroyUserMetrics(self.allocator, entry);
                    }
                }
                new_metrics.deinit(self.allocator);
            }

            var next_it = next.users.iterator();
            while (next_it.next()) |entry| {
                const user_name = entry.key_ptr.*;
                if (findMetricInSlice(self.user_metrics, user_name)) |metrics| {
                    try new_metrics.append(self.allocator, metrics);
                } else {
                    const metrics = try createUserMetrics(self.allocator, user_name);
                    errdefer destroyUserMetrics(self.allocator, metrics);
                    try new_metrics.append(self.allocator, metrics);
                }
            }

            break :blk try new_metrics.toOwnedSlice(self.allocator);
        };
        errdefer self.allocator.free(new_metrics_slice);

        var retired_metrics_needed: usize = 0;
        for (self.user_metrics) |entry| {
            if (findMetricInSlice(new_metrics_slice, entry.name) == null and entry.connections_active.load(.monotonic) != 0) {
                retired_metrics_needed += 1;
            }
        }
        try self.retired_user_metrics.ensureUnusedCapacity(self.allocator, retired_metrics_needed);

        const old_user_secrets = self.user_secrets;
        const old_user_metrics = self.user_metrics;

        self.user_metrics_lock.lock();
        defer self.user_metrics_lock.unlock();

        self.user_secrets = new_user_secrets;
        self.user_metrics = new_metrics_slice;
        self.moveAccessMapsFrom(next);

        self.allocator.free(old_user_secrets);
        for (old_user_metrics) |entry| {
            if (findMetricInSlice(self.user_metrics, entry.name) == null) {
                self.retireOrDestroyUserMetrics(entry);
            }
        }
        self.allocator.free(old_user_metrics);
        self.collectRetiredUserMetrics();
        return 1;
    }

    pub fn reloadAccessUsersForTest(self: *ProxyState, next: *Config) !void {
        _ = try self.reloadAccessUsers(next);
    }

    pub fn collectRetiredUserMetricsForTest(self: *ProxyState) void {
        self.collectRetiredUserMetrics();
    }

    pub fn lockUserMetricsForRead(self: *ProxyState) void {
        self.user_metrics_lock.lockShared();
    }

    pub fn unlockUserMetricsForRead(self: *ProxyState) void {
        self.user_metrics_lock.unlockShared();
    }

    pub fn lockUserMetricsForReadForTest(self: *ProxyState) void {
        self.lockUserMetricsForRead();
    }

    pub fn unlockUserMetricsForReadForTest(self: *ProxyState) void {
        self.unlockUserMetricsForRead();
    }

    allocator: std.mem.Allocator,
    config_path: []const u8,
    config: Config,
    user_secrets: []const obfuscation.UserSecret,
    user_metrics_lock: CompatRwLock = .{},
    user_metrics: []*UserMetrics,
    retired_user_metrics: std.ArrayList(*UserMetrics),
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
    /// Opt-in SNI-following mask targets (config.mask_sni_safelist), resolved at boot.
    mask_safelist: []const MaskSafelistEntry,
    /// Startup HTTP-Date clock correction (seconds); 0 if disabled or unavailable.
    clock_offset_seconds: i64,
    replay_cache: ReplayCache,
    /// FakeTLS ServerHello template (heap; size varies with fake_cert_size).
    tls_server_hello_template: []const u8,

    // Degradation counters (monotonic totals, delta'd in stats log)
    stats_dropped_cap: std.atomic.Value(u64),
    stats_dropped_saturation: std.atomic.Value(u64),
    stats_dropped_rate_limit: std.atomic.Value(u64),
    stats_dropped_flood_guard: std.atomic.Value(u64),
    stats_dropped_hs_budget: std.atomic.Value(u64),
    stats_hs_timeout: std.atomic.Value(u64),
    stats_mp_fallback: std.atomic.Value(u64),
    /// Replay-cache hits: a valid handshake whose canonical HMAC was already seen
    /// (active replay probing). Distinct from a fresh accept.
    stats_replay_hits: std.atomic.Value(u64),
    /// ClientHello whose SNI did not match tls_domain (active probing / scanners /
    /// borrowed-link misuse) — handled per unknown_sni_action.
    stats_unknown_sni: std.atomic.Value(u64),
    /// Per-worker connection pool exhausted while the global cap still had room
    /// (SO_REUSEPORT hashes connections to workers, so one pool can fill first).
    stats_dropped_pool: std.atomic.Value(u64),
    /// Per-reason connection close counters (RED errors + evasion signals).
    close_reasons: [CloseReason.count]std.atomic.Value(u64),
    /// Per-worker monotonic-ms liveness heartbeat (index = worker_id). /healthz and
    /// the watchdog require EVERY active worker to be fresh, so a wedged non-owner
    /// SO_REUSEPORT shard is detected (not masked by worker 0 staying alive). 0 until
    /// a worker starts ticking.
    worker_heartbeats: [max_workers]std.atomic.Value(i64),
    /// Anti-flood + per-subnet rate guards are SHARED across workers (behind
    /// guard_lock) so an IP/subnet spread across SO_REUSEPORT shards is still limited
    /// globally, not ~N×threshold. Touched only on the accept/handshake path.
    subnet_limiter: SubnetRateLimit,
    flood_guard: *HandshakeFloodGuard,
    guard_lock: CompatRwLock = .{},
    /// True once graceful shutdown/drain has begun — drives /readyz.
    shutting_down: std.atomic.Value(bool),
    /// $NOTIFY_SOCKET (set by systemd Type=notify); null when not run under
    /// systemd. Borrowed from the process environ (lives for process lifetime).
    notify_socket: ?[]const u8 = null,
    /// $WATCHDOG_USEC (systemd WatchdogSec); 0 disables watchdog pings.
    watchdog_usec: u64 = 0,
    /// Diagnostic budget: log the first N incoming ClientHello fingerprints (what a
    /// real client offers) at info, then go quiet. Lets an operator capture the
    /// real client shape on deploy (connect once) without ongoing log spam.
    clienthello_fp_budget: std.atomic.Value(u32) = std.atomic.Value(u32).init(16),
    /// Resolved SO_REUSEPORT worker count (1 = single-threaded). Set in run().
    /// Gates SIGHUP config reload: a live reload mutates shared config string
    /// slices (e.g. tls_domain) and frees the old ones, which would race the N
    /// worker threads reading them on the handshake path — so with >1 worker the
    /// reload is refused and a restart is required to apply config changes.
    effective_workers: usize = 1,

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
    // Set by the data plane when a middleproxy handshake stalls; the updater thread
    // consumes it to refresh ahead of the periodic timer (debounced by the cooldown).
    middle_proxy_refresh_requested: std.atomic.Value(bool),
    middle_proxy_updater_thread: ?std.Thread,
    upstream: upstream_mod.Upstream,
    tunnel_info: tunnel_mod.Tunnel,

    pub fn init(allocator: std.mem.Allocator, cfg: Config, config_path: []const u8) !ProxyState {
        if (cfg.users.count() == 0) return error.NoUsersConfigured;

        const user_secrets = try buildUserSecrets(allocator, &cfg);
        errdefer allocator.free(user_secrets);

        const user_metrics_owned = try buildInitialUserMetrics(allocator, &cfg);
        errdefer freeUserMetricsSlice(allocator, user_metrics_owned);

        var resolved_addr: ?Address = null;
        if (cfg.mask) {
            const mask_target = cfg.effectiveMaskTarget();
            if (cfg.mask_target) |configured_target| {
                log.info("mask_target={s} configured, using mask target {s}:{d}", .{ configured_target, mask_target, cfg.mask_port });
            } else if (cfg.mask_port != 443) {
                log.info("mask_port={d} configured, using local mask target {s}", .{ cfg.mask_port, mask_target });
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

        // Resolve the opt-in SNI-following mask safelist (each domain → its own server,
        // port 443). Failed resolutions are skipped, not fatal.
        var mask_safelist_buf: std.ArrayListUnmanaged(MaskSafelistEntry) = .empty;
        errdefer mask_safelist_buf.deinit(allocator);
        if (cfg.mask and cfg.mask_sni_safelist.len > 0) {
            for (cfg.mask_sni_safelist) |domain| {
                const sl = getAddressList(allocator, domain, 443) catch {
                    log.warn("mask_sni_safelist: could not resolve '{s}', skipping", .{domain});
                    continue;
                };
                defer sl.deinit();
                if (sl.addrs.len > 0) {
                    mask_safelist_buf.append(allocator, .{ .domain = domain, .addr = sl.addrs[0] }) catch continue;
                    log.info("mask_sni_safelist: fronting '{s}' enabled", .{domain});
                }
            }
        }
        const mask_safelist = mask_safelist_buf.toOwnedSlice(allocator) catch &.{};

        // Optional startup clock correction from an HTTPS Date header.
        var clock_offset_seconds: i64 = 0;
        if (cfg.clock_sync_url) |url| {
            if (fetchClockOffsetSeconds(allocator, url)) |off| {
                clock_offset_seconds = off;
                log.info("clock_sync: applied {d}s server-clock correction from {s}", .{ off, url });
            } else {
                log.warn("clock_sync: could not read a Date header from {s}", .{url});
            }
        }

        // FakeTLS ServerHello template, sized to a profile-matched fake-cert record when
        // fake_cert_size is set (else the default ~2878). Falls back to the default size
        // if the configured value can't be built.
        const fake_cert_size: usize = if (cfg.fake_cert_size == 0)
            tls.default_fake_cert_size
        else
            std.math.clamp(@as(usize, cfg.fake_cert_size), tls.min_fake_cert_size, tls.max_fake_cert_size);
        const tls_template = tls.buildServerHelloTemplateAlloc(allocator, fake_cert_size) catch
            try tls.buildServerHelloTemplateAlloc(allocator, tls.default_fake_cert_size);
        errdefer allocator.free(tls_template);

        var default_middle_proxy_secret = [_]u8{0} ** 256;
        @memcpy(default_middle_proxy_secret[0..middleproxy.proxy_secret.len], middleproxy.proxy_secret[0..]);

        const detected_nat_ip4 = if (cfg.datacenter_override == null)
            middle_proxy_nat.detectIpv4(allocator, &cfg, detectAwgEndpointIpv4, detectPublicIpv4ViaEgress)
        else
            null;

        // The ad-tag and non-Premium media both require a working MiddleProxy handshake,
        // which needs the egress public IP. If MiddleProxy is wanted but we couldn't learn
        // that IP, say so loudly — otherwise the proxy silently falls back to direct DC
        // (no ad-tag) and operators never notice.
        if (detected_nat_ip4 == null and (cfg.use_middle_proxy or cfg.force_media_middle_proxy or cfg.tag != null)) {
            log.warn("MiddleProxy/ad-tag is enabled but the egress public IP could not be detected; " ++
                "the ad-tag (and non-Premium media via ME) may not work. Set [server].middle_proxy_nat_ip " ++
                "to the IP Telegram sees for this server's egress (the SOCKS/tunnel exit IP when egress isn't direct).", .{});
        }

        const owned_config_path = try allocator.dupe(u8, config_path);
        errdefer allocator.free(owned_config_path);

        return .{
            .allocator = allocator,
            .config_path = owned_config_path,
            .config = cfg,
            .user_secrets = user_secrets,
            .user_metrics = user_metrics_owned,
            .retired_user_metrics = .empty,
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
            .mask_safelist = mask_safelist,
            .clock_offset_seconds = clock_offset_seconds,
            .replay_cache = ReplayCache.init(),
            .tls_server_hello_template = tls_template,
            .stats_dropped_cap = std.atomic.Value(u64).init(0),
            .stats_dropped_saturation = std.atomic.Value(u64).init(0),
            .stats_dropped_rate_limit = std.atomic.Value(u64).init(0),
            .stats_dropped_flood_guard = std.atomic.Value(u64).init(0),
            .stats_dropped_hs_budget = std.atomic.Value(u64).init(0),
            .stats_hs_timeout = std.atomic.Value(u64).init(0),
            .stats_dropped_pool = std.atomic.Value(u64).init(0),
            .close_reasons = [_]std.atomic.Value(u64){std.atomic.Value(u64).init(0)} ** CloseReason.count,
            .stats_mp_fallback = std.atomic.Value(u64).init(0),
            .stats_replay_hits = std.atomic.Value(u64).init(0),
            .stats_unknown_sni = std.atomic.Value(u64).init(0),
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
            .middle_proxy_refresh_requested = std.atomic.Value(bool).init(false),
            .worker_heartbeats = [_]std.atomic.Value(i64){std.atomic.Value(i64).init(0)} ** max_workers,
            .subnet_limiter = SubnetRateLimit.init(),
            .flood_guard = try HandshakeFloodGuard.create(allocator),
            .shutting_down = std.atomic.Value(bool).init(false),
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
        self.flood_guard.destroy(self.allocator);
        self.allocator.free(self.mask_safelist);
        self.allocator.free(self.tls_server_hello_template);
        self.allocator.free(self.config_path);
        self.allocator.free(self.user_secrets);
        freeUserMetricsSlice(self.allocator, self.user_metrics);
        for (self.retired_user_metrics.items) |entry| {
            destroyUserMetrics(self.allocator, entry);
        }
        self.retired_user_metrics.deinit(self.allocator);
        self.config.deinit(self.allocator);
    }

    pub fn findUserMetrics(self: *ProxyState, user_name: []const u8) ?*UserMetrics {
        for (self.user_metrics) |entry| {
            if (std.mem.eql(u8, entry.name, user_name)) return entry;
        }
        return null;
    }

    /// Liveness: have ALL active workers iterated within threshold_ms? Returns
    /// false if ANY started worker has stalled, so a wedged non-owner SO_REUSEPORT
    /// shard is surfaced (not masked by worker 0 staying alive). Lenient before a
    /// worker first ticks (heartbeat 0) so /healthz doesn't fail during startup.
    pub fn loopAlive(self: *const ProxyState, threshold_ms: i64) bool {
        const now = nowMs();
        const n = @min(self.effective_workers, max_workers);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const hb = self.worker_heartbeats[i].load(.monotonic);
            if (hb == 0) continue; // not started ticking yet
            if (now - hb >= threshold_ms) return false; // this worker stalled
        }
        return true;
    }

    /// Readiness: serving and not draining. (Not gated on middleproxy — it runs
    /// on bundled defaults and may never refresh on a censored host.)
    pub fn isReady(self: *const ProxyState) bool {
        return !self.shutting_down.load(.acquire);
    }

    // ── Shared anti-flood / subnet-rate guards (global across workers) ──
    // Each call holds guard_lock so the shared tables stay consistent under N
    // worker threads. Only on the accept/handshake path, so contention is bounded.

    fn floodIsBlocked(self: *ProxyState, addr: Address, cfg: HandshakeFloodGuard.Settings) bool {
        self.guard_lock.lock();
        defer self.guard_lock.unlock();
        return self.flood_guard.isBlocked(addr, cfg);
    }

    fn floodRecord(self: *ProxyState, addr: Address, event: HandshakeFloodGuard.Event, cfg: HandshakeFloodGuard.Settings) bool {
        self.guard_lock.lock();
        defer self.guard_lock.unlock();
        return self.flood_guard.record(addr, event, cfg);
    }

    fn floodTop(self: *ProxyState, cfg: HandshakeFloodGuard.Settings, out: []HandshakeFloodGuard.TopEntry) usize {
        self.guard_lock.lock();
        defer self.guard_lock.unlock();
        return self.flood_guard.top(cfg, out);
    }

    fn subnetCheck(self: *ProxyState, addr: Address, max_per_sec: u8) bool {
        self.guard_lock.lock();
        defer self.guard_lock.unlock();
        return self.subnet_limiter.check(addr, max_per_sec);
    }

    pub fn getMetricsSnapshot(self: *const ProxyState) MetricsSnapshot {
        const now = realtimeSeconds();
        const accepted_total = self.connection_count.load(.monotonic);
        var close_reasons: [CloseReason.count]u64 = undefined;
        for (&self.close_reasons, 0..) |*c, idx| close_reasons[idx] = c.load(.monotonic);
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
            .drops_flood_guard_total = self.stats_dropped_flood_guard.load(.monotonic),
            .drops_handshake_budget_total = self.stats_dropped_hs_budget.load(.monotonic),
            .handshake_timeouts_total = self.stats_hs_timeout.load(.monotonic),
            .middleproxy_fallback_total = self.stats_mp_fallback.load(.monotonic),
            .drops_pool_total = self.stats_dropped_pool.load(.monotonic),
            .replay_hits_total = self.stats_replay_hits.load(.monotonic),
            .unknown_sni_total = self.stats_unknown_sni.load(.monotonic),
            .close_reasons = close_reasons,
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
        // The address `server` is bound to, captured so additional SO_REUSEPORT
        // worker listeners can be created on the same addr:port.
        var listen_addr: Address = undefined;

        if (self.config.bind_address) |bind_str| {
            // Explicit bind address from config
            const parsed = parseListenAddress(bind_str, self.config.port) orelse {
                log.err("Invalid bind_address '{s}', cannot start", .{bind_str});
                return error.InvalidBindAddress;
            };
            ipv6_ok = isIpv6(parsed);
            listen_addr = parsed;
            server = try parsed.listen(io_ctx, .{
                .reuse_address = true,
                .kernel_backlog = @intCast(self.config.backlog),
            });
            log.info("Listening on {s}:{d} (epoll)", .{ bind_str, self.config.port });
        } else {
            // Default: try [::] (dual-stack), fall back to 0.0.0.0
            const address = ip6(
                .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                self.config.port,
                0,
                0,
            );
            listen_addr = address;
            server = address.listen(io_ctx, .{
                .reuse_address = true,
                .kernel_backlog = @intCast(self.config.backlog),
            }) catch |err| blk: {
                if (err == error.AddressFamilyUnsupported) {
                    ipv6_ok = false;
                    log.warn("IPv6 not available, falling back to IPv4 (0.0.0.0)", .{});
                    const address_v4 = ip4(.{ 0, 0, 0, 0 }, self.config.port);
                    listen_addr = address_v4;
                    break :blk try address_v4.listen(io_ctx, .{
                        .reuse_address = true,
                        .kernel_backlog = @intCast(self.config.backlog),
                    });
                }
                return err;
            };

            if (ipv6_ok) {
                log.info("Listening on [::]:{d} (epoll)", .{self.config.port});
            } else {
                log.info("Listening on 0.0.0.0:{d} (epoll)", .{self.config.port});
            }
        }
        defer server.deinit(io_ctx);

        setNonBlocking(server.socket.handle);

        // Resolve the worker count: 1 = classic single loop (default, unchanged),
        // 0 = auto (one per CPU), clamped to [1, max_workers]. Published on the
        // shared state so SIGHUP reload can refuse a racy live-reload under >1.
        var worker_count: usize = self.config.workers;
        if (worker_count == 0) worker_count = std.Thread.getCpuCount() catch 1;
        worker_count = std.math.clamp(worker_count, 1, max_workers);
        self.effective_workers = worker_count;

        if (self.config.use_middle_proxy and self.config.datacenter_override == null) {
            // The INITIAL middle-proxy metadata refresh now runs inside the
            // updater thread (see middleProxyUpdaterMain), NOT synchronously
            // here, so a blocked/stalled core.telegram.org fetch on a censored
            // host cannot delay the event loop from accepting connections (the
            // std.http fetch has no read timeout). The proxy serves immediately
            // on bundled fallback addresses and upgrades the cache in the
            // background as soon as the network allows.
            self.middle_proxy_updater_shutdown.store(false, .release);
            if (std.Thread.spawn(.{}, ProxyState.middleProxyUpdaterMain, .{self})) |updater| {
                self.middle_proxy_updater_thread = updater;
            } else |err| {
                log.warn("Middle-proxy updater thread failed to start: {any}", .{err});
                // No background thread: best-effort synchronous refresh so
                // metadata is still populated (bounded by the OS connect timeout).
                self.refreshMiddleProxyInfo() catch {};
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

        // Connection fds stay bounded by the GLOBAL saturation cap (not N×max),
        // but each worker adds its own listener + epoll fd — account for that 2×N
        // overhead so the RLIMIT warning is accurate under the multi-worker model.
        const effective_needed_fds = requiredFdsForConnections(self.config.max_connections) + 2 * worker_count;
        checkNofileLimit(@max(effective_needed_fds, min_nofile_soft), self.config.max_connections);

        if (self.config.metrics.enabled) {
            try @import("../monitoring.zig").start(self);
        }

        if (worker_count <= 1) {
            // Classic single-threaded path — byte-for-byte the previous behavior.
            var loop = try EventLoop.init(self, server.socket.handle, signal_controller.fd, 0, self.config.max_connections);
            defer loop.deinit();
            // Listener bound, epoll + metrics up: tell systemd we're ready
            // (Type=notify gate). No-op when not under systemd ($NOTIFY_SOCKET unset).
            sd_notify.ready(self.notify_socket);
            try loop.run();
            return;
        }

        // Split the global connection budget across workers so total slot memory
        // (and the RAM estimate) stays ~constant regardless of worker count; the
        // global saturation cap still bounds total active connections. Floor at 64.
        const per_worker_pool: u32 = @max(@as(u32, 64), self.config.max_connections / @as(u32, @intCast(worker_count)));

        // Multi-worker (SO_REUSEPORT): worker 0 runs on this (main) thread and owns
        // the signalfd; workers 1..N-1 are spawned threads, each with its OWN
        // SO_REUSEPORT listener and no signalfd. The kernel load-balances incoming
        // connections across the N listeners. Shared ProxyState (atomic counters,
        // mutex-guarded replay cache + middle-proxy snapshot) is read/written by all.
        log.info("Starting {d} SO_REUSEPORT epoll workers", .{worker_count});

        var extra_servers: [max_workers]net.Server = undefined;
        var extra_count: usize = 0;
        var threads: [max_workers]std.Thread = undefined;
        var thread_count: usize = 0;
        // Order matters (defers run LIFO): join all worker threads FIRST, then tear
        // down the listener sockets whose fds those threads were using.
        defer for (extra_servers[0..extra_count]) |*s| s.deinit(io_ctx);
        defer for (threads[0..thread_count]) |t| t.join();

        var i: usize = 1;
        while (i < worker_count) : (i += 1) {
            const extra = listen_addr.listen(io_ctx, .{
                .reuse_address = true,
                .kernel_backlog = @intCast(self.config.backlog),
            }) catch |err| {
                log.err("worker {d} listener failed ({any}); continuing with {d} workers", .{ i, err, i });
                break;
            };
            setNonBlocking(extra.socket.handle);
            // Spawn FIRST; only retain the listener (in extra_servers) once its
            // worker exists. Otherwise a spawn failure would leave a listenerless
            // socket in the SO_REUSEPORT group that the kernel still routes
            // connections to but nobody accepts (they would hang).
            const t = std.Thread.spawn(.{}, ProxyState.eventLoopWorkerMain, .{ self, extra.socket.handle, i, per_worker_pool }) catch |err| {
                log.err("worker {d} thread spawn failed ({any}); continuing with {d} workers", .{ i, err, extra_count });
                var dead = extra;
                dead.deinit(io_ctx); // remove the listenerless socket from the reuseport group
                break;
            };
            extra_servers[extra_count] = extra;
            extra_count += 1;
            threads[thread_count] = t;
            thread_count += 1;
        }

        // Worker 0 on the main thread owns the signalfd (signal handling + watchdog).
        // On init failure, signal the already-spawned workers to drain before propagating
        // — otherwise the LIFO defers above join() workers that never observe shutdown and
        // the process hangs with worker 0's listener still in the SO_REUSEPORT group.
        var loop0 = EventLoop.init(self, server.socket.handle, signal_controller.fd, 0, per_worker_pool) catch |err| {
            self.shutting_down.store(true, .release);
            return err;
        };
        defer loop0.deinit();
        sd_notify.ready(self.notify_socket);
        loop0.run() catch |err| {
            log.err("worker 0 event loop error: {any}", .{err});
            // Make the other workers drain and exit so we don't leave a half-dead set.
            self.shutting_down.store(true, .release);
        };
    }

    /// Worker thread entry: run a non-signal-owning EventLoop on its own
    /// SO_REUSEPORT listener. On any failure it sets the shared shutdown flag so
    /// the rest of the fleet drains rather than running degraded.
    fn eventLoopWorkerMain(self: *ProxyState, listen_fd: posix.fd_t, worker_id: usize, pool_capacity: u32) void {
        var loop = EventLoop.init(self, listen_fd, -1, worker_id, pool_capacity) catch |err| {
            log.err("worker {d} EventLoop.init failed: {any}", .{ worker_id, err });
            self.shutting_down.store(true, .release);
            return;
        };
        defer loop.deinit();
        loop.run() catch |err| {
            log.err("worker {d} event loop error: {any}", .{ worker_id, err });
            self.shutting_down.store(true, .release);
        };
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
    /// failure AND when the config selects tunnel upstream, retries via the
    /// active tunnel route (`table 200`), pool state, then configured tunnel
    /// candidates. This keeps the media MP cache warm after tunnel failover.
    fn fetchMiddleProxyAsset(self: *ProxyState, allocator: std.mem.Allocator, url: []const u8) ![]u8 {
        switch (middleProxyFetchRouteForConfig(&self.config)) {
            .socks5, .http_connect => {
                if (self.fetchMiddleProxyAssetViaConfiguredProxy(allocator, url)) |bytes| {
                    return bytes;
                } else |proxy_err| {
                    if (!self.config.allow_direct_fallback) return proxy_err;
                    log.warn("Middle-proxy asset {s} unavailable through configured upstream ({s}); trying direct fallback", .{
                        url,
                        @errorName(proxy_err),
                    });
                    return fetchUrlBytes(allocator, url) catch proxy_err;
                }
            },
            .tunnel => {
                if (fetchUrlBytes(allocator, url)) |bytes| {
                    return bytes;
                } else |direct_err| {
                    return self.fetchMiddleProxyAssetViaTunnelPool(allocator, url, direct_err);
                }
            },
            .direct => return fetchUrlBytes(allocator, url),
        }
    }

    fn fetchMiddleProxyAssetViaConfiguredProxy(
        self: *ProxyState,
        allocator: std.mem.Allocator,
        url: []const u8,
    ) ![]u8 {
        const host = self.config.upstream_proxy_host orelse return error.InvalidProxyUpstreamConfig;
        if (self.config.upstream_proxy_port == 0) return error.InvalidProxyUpstreamConfig;

        const kind: http_fetch.ProxyKind = switch (self.config.upstream_mode) {
            .socks5 => .socks5,
            .http => .http_connect,
            else => return error.InvalidProxyUpstreamConfig,
        };

        log.info("Fetching middle-proxy asset {s} through configured {s} upstream", .{
            url,
            if (kind == .socks5) "SOCKS5" else "HTTP CONNECT",
        });
        return http_fetch.fetchUrlBytesViaProxy(allocator, url, .{
            .kind = kind,
            .host = host,
            .port = self.config.upstream_proxy_port,
            .username = self.config.upstream_proxy_username,
            .password = self.config.upstream_proxy_password,
        });
    }

    fn fetchMiddleProxyAssetViaTunnelPool(
        self: *ProxyState,
        allocator: std.mem.Allocator,
        url: []const u8,
        direct_err: anyerror,
    ) ![]u8 {
        var last_err: anyerror = direct_err;

        if (detectActiveTunnelInterface(allocator)) |iface| {
            defer allocator.free(iface);
            if (tryFetchMiddleProxyViaInterface(allocator, url, iface, direct_err)) |bytes| {
                return bytes;
            } else |err| {
                last_err = err;
            }
        }

        if (readTunnelPoolStateValue(allocator, "active")) |iface| {
            defer allocator.free(iface);
            if (tryFetchMiddleProxyViaInterface(allocator, url, iface, direct_err)) |bytes| {
                return bytes;
            } else |err| {
                last_err = err;
            }
        }

        var idx: usize = 0;
        while (self.config.tunnelCandidateAt(idx)) |iface| : (idx += 1) {
            if (tryFetchMiddleProxyViaInterface(allocator, url, iface, direct_err)) |bytes| {
                return bytes;
            } else |err| {
                last_err = err;
            }
        }

        return last_err;
    }

    fn middleProxyUpdaterMain(self: *ProxyState) void {
        // The INITIAL refresh happens here (in this background thread) so it
        // never blocks the boot path. On a censored host it may fail (tunnel
        // handshake may not be up yet), so on failure run a short-cycle retry
        // loop before falling back to the normal 24-hour cadence. This gets
        // media MP addresses into the cache within the first few minutes of
        // uptime instead of the next day, all without delaying startup.
        var initial_ok = false;
        if (self.refreshMiddleProxyInfo()) |_| {
            initial_ok = true;
        } else |err| {
            if (isMiddleProxyRefreshNetworkError(err)) {
                log.info("Initial middle-proxy refresh unavailable ({s}), using bundled defaults", .{@errorName(err)});
            } else {
                log.warn("Initial middle-proxy refresh failed, using bundled defaults: {any}", .{err});
            }
        }
        if (self.middle_proxy_updater_shutdown.load(.acquire)) return;

        const short_retries: [5]u64 = .{
            10 * std.time.ns_per_s,
            30 * std.time.ns_per_s,
            60 * std.time.ns_per_s,
            5 * 60 * std.time.ns_per_s,
            30 * 60 * std.time.ns_per_s,
        };
        var retry_idx: usize = 0;
        while (!initial_ok and retry_idx < short_retries.len) : (retry_idx += 1) {
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

    /// Ask the background updater to refresh middleproxy metadata ahead of the
    /// periodic timer — called from the data plane when a middleproxy handshake
    /// stalls (a sign the cached DC/secret went stale). Idempotent and lock-free;
    /// the updater debounces it via `middle_proxy_reactive_cooldown_ns`.
    pub fn requestMiddleProxyRefresh(self: *ProxyState) void {
        self.middle_proxy_refresh_requested.store(true, .release);
    }

    /// Sleep up to `total_ns`, returning early (false) once a reactive refresh has
    /// been requested AND at least the cooldown has elapsed since this wait began
    /// (i.e. since the last refresh). Requests arriving inside the cooldown are left
    /// pending and honored as soon as it expires. Returns true on shutdown.
    fn waitForUpdaterDelay(self: *ProxyState, total_ns: u64) bool {
        const step_ns: u64 = std.time.ns_per_s;
        var elapsed: u64 = 0;
        while (elapsed < total_ns) {
            if (self.middle_proxy_updater_shutdown.load(.acquire)) return true;
            if (elapsed >= middle_proxy_reactive_cooldown_ns and
                self.middle_proxy_refresh_requested.swap(false, .acq_rel))
            {
                log.info("Middle-proxy reactive refresh: stalled handshake(s) suggest stale metadata", .{});
                return false;
            }
            const chunk = @min(total_ns - elapsed, step_ns);
            sleepNs(chunk);
            elapsed += chunk;
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
    /// 0..N-1; worker 0 owns the signalfd + systemd watchdog. Indexes the shared
    /// per-worker heartbeat slot.
    worker_id: usize,
    pool: ConnectionPool,
    accept_paused: bool,
    accept_resume_ns: i128,
    saturation_paused: bool,
    shutting_down: bool,
    shutdown_deadline_ns: i128,
    /// Monotonic ms of the last systemd WATCHDOG=1 ping (0 = never).
    last_watchdog_ms: i64 = 0,
    timer_scan_cursor: u32,
    stats_next_log_ns: i128,
    accepted_since_log: u64,
    closed_since_log: u64,
    // Snapshot of degradation counters for delta logging
    prev_dropped_cap: u64,
    prev_dropped_saturation: u64,
    prev_dropped_rate_limit: u64,
    prev_dropped_flood_guard: u64,
    prev_dropped_hs_budget: u64,
    prev_hs_timeout: u64,
    prev_mp_fallback: u64,
    prev_dropped_pool: u64,
    shared_read_buf: [read_buf_size]u8,
    desync_wait_slots: std.ArrayListUnmanaged(u32),
    mp_c2s_scratch: ?[]u8,
    mp_s2c_scratch: ?[]u8,
    /// Fds whose slot was closed during the current epoll batch. closeSlot unmaps them
    /// from fd_to_slot immediately (so stale events in the same batch miss) but defers the
    /// actual close() until the batch finishes — otherwise the kernel could hand a
    /// just-freed fd number to an accept()/connect() later in the SAME batch, and a stale
    /// hangup event for the old fd would then be misattributed to the new connection.
    pending_close_fds: std.ArrayListUnmanaged(posix.fd_t),

    fn init(state: *ProxyState, listen_fd: posix.fd_t, signal_fd: posix.fd_t, worker_id: usize, pool_capacity: u32) !EventLoop {
        const epoll_fd = try epollCreate();
        errdefer closeFd(epoll_fd);

        var loop = EventLoop{
            .state = state,
            .epoll_fd = epoll_fd,
            .listen_fd = listen_fd,
            .signal_fd = signal_fd,
            .worker_id = worker_id,
            .pool = try ConnectionPool.init(state.allocator, pool_capacity),
            .accept_paused = false,
            .accept_resume_ns = 0,
            .saturation_paused = false,
            .shutting_down = false,
            .shutdown_deadline_ns = 0,
            .timer_scan_cursor = 0,
            .stats_next_log_ns = nowNs() + stats_log_interval_ns,
            .accepted_since_log = 0,
            .closed_since_log = 0,
            .prev_dropped_cap = 0,
            .prev_dropped_saturation = 0,
            .prev_dropped_rate_limit = 0,
            .prev_dropped_flood_guard = 0,
            .prev_dropped_hs_budget = 0,
            .prev_hs_timeout = 0,
            .prev_mp_fallback = 0,
            .prev_dropped_pool = 0,
            .shared_read_buf = undefined,
            .desync_wait_slots = .empty,
            .pending_close_fds = .empty,
            .mp_c2s_scratch = null,
            .mp_s2c_scratch = null,
        };
        errdefer loop.pool.deinit();

        try loop.addFd(listen_fd, true, false);
        // Only the signal-owning worker has a real signalfd; other SO_REUSEPORT
        // workers pass -1 and learn about shutdown via state.shutting_down.
        if (signal_fd >= 0) try loop.addFd(signal_fd, true, false);
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

        self.drainPendingCloses();
        self.pending_close_fds.deinit(self.state.allocator);

        if (self.mp_c2s_scratch) |buf| self.state.allocator.free(buf);
        if (self.mp_s2c_scratch) |buf| self.state.allocator.free(buf);
        self.desync_wait_slots.deinit(self.state.allocator);

        self.pool.deinit();
        closeFd(self.epoll_fd);
    }

    /// Defer closing `fd` until the end of the current epoll batch (see pending_close_fds).
    /// Falls back to an immediate close only if the bookkeeping allocation fails.
    fn deferClose(self: *EventLoop, fd: posix.fd_t) void {
        self.pending_close_fds.append(self.state.allocator, fd) catch {
            closeFd(fd);
        };
    }

    fn drainPendingCloses(self: *EventLoop) void {
        for (self.pending_close_fds.items) |fd| closeFd(fd);
        self.pending_close_fds.clearRetainingCapacity();
    }

    fn run(self: *EventLoop) !void {
        var events: [256]linux.epoll_event = undefined;
        const timer_tick_ns: i128 = 5 * std.time.ns_per_ms;
        var next_timer_tick_ns: i128 = nowNs();

        while (true) {
            // Close fds whose slots were torn down in the previous batch (and by timers /
            // desync processing). Doing it here — before this iteration's accept()/connect()
            // calls — guarantees a freed fd number is never recycled within the batch that
            // still has queued events for it. See pending_close_fds.
            self.drainPendingCloses();

            // Per-worker liveness heartbeat (this worker's slot), and pet the
            // systemd watchdog at half the configured interval — ONLY from the
            // signal owner AND only while EVERY worker is alive, so a wedged
            // non-owner shard stops the watchdog and triggers a restart.
            const tick_ms = nowMs();
            self.state.worker_heartbeats[@min(self.worker_id, max_workers - 1)].store(tick_ms, .monotonic);
            if (self.signal_fd >= 0 and self.state.watchdog_usec > 0 and
                tick_ms - self.last_watchdog_ms >= @as(i64, @intCast(self.state.watchdog_usec / 2000)) and
                self.state.loopAlive(watchdog_stale_ms))
            {
                sd_notify.watchdog(self.state.notify_socket);
                self.last_watchdog_ms = tick_ms;
            }
            // Non-owner SO_REUSEPORT workers learn about shutdown via the shared
            // flag the signal owner sets, so they also stop accepting and drain.
            if (!self.shutting_down and self.state.shutting_down.load(.acquire)) {
                self.beginGracefulShutdown("peer shutdown");
            }
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

        // A handler above may have replaced upstream_fd: DC failover
        // (cleanupFailedUpstreamConnect -> tryNextDcEndpoint -> startConnectUpstream) and
        // middleproxy->direct fallback both connect() a NEW socket. The original event fd
        // then belongs to a now-closed connection, and shouldCloseOnFatalHangup's
        // connecting-phase exemption only matches the *current* upstream_fd — so a stale
        // hangup for the old fd would tear down the freshly started replacement. Drop any
        // event whose fd no longer belongs to this slot before applying the close.
        if (fd != slot.client_fd and fd != slot.upstream_fd) return;

        if (fatal_hangup and shouldCloseOnFatalHangup(slot.phase, fd, slot.upstream_fd)) {
            // During an active relay a *graceful* half-close (RDHUP with no HUP/ERR) on one
            // peer must not discard data already queued for the other peer. Detach the
            // hung-up fd from epoll and flush the surviving direction before tearing down;
            // a hard error (HUP/ERR) or an empty opposite queue still closes immediately.
            const graceful = (events & (linux.EPOLL.HUP | linux.EPOLL.ERR)) == 0;
            const relaying = slot.phase == .relaying or slot.phase == .mask_relaying;
            const opposite_pending = if (fd == slot.client_fd) slot.hasUpstreamPending() else slot.hasClientPending();
            if (graceful and relaying and opposite_pending and !slot.relay_half_closed) {
                self.beginRelayHalfClose(slot, fd);
                return;
            }
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
            // No connection is dropped here — the backlog is retained and served after the
            // 80% resume. Count only the transition INTO pause so the counter measures
            // saturation-pause events rather than every accept attempt while paused.
            if (!self.saturation_paused) {
                self.pauseSaturation();
                _ = self.state.stats_dropped_saturation.fetchAdd(1, .monotonic);
            }
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

            // Behind a PROXY-protocol LB, the accepted address is the load balancer's, not
            // the client's, so per-IP flood/subnet checks here are meaningless (they'd rate
            // the LB). They run on the real client address once the PROXY header is parsed
            // (peer_addr) via the per-handshake flood machinery.
            const proxy_proto = self.state.config.accept_proxy_protocol;
            const flood_cfg = floodGuardSettings(&self.state.config);
            if (!proxy_proto and self.state.floodIsBlocked(client_addr, flood_cfg)) {
                _ = self.state.stats_dropped_flood_guard.fetchAdd(1, .monotonic);
                closeFd(cfd);
                continue;
            }

            // Ensure desync byte-splitting is not coalesced by Nagle during early handshake.
            setTcpNoDelay(cfd);

            // Per-/24 subnet rate limit (before we allocate any slot)
            if (!proxy_proto and !self.state.subnetCheck(client_addr, self.state.config.rate_limit_per_subnet)) {
                _ = self.state.stats_dropped_rate_limit.fetchAdd(1, .monotonic);
                _ = self.state.floodRecord(client_addr, .rate_limit, flood_cfg);
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

            // NOTE: the handshake-inflight budget is charged at FIRST BYTE
            // (reserveHandshakeBudget in readTlsHeader), not here at accept, so
            // a flood of silent/zero-byte TCP sessions can no longer exhaust the
            // budget and starve real handshakes. accept() is still bounded by the
            // flood guard, per-/24 subnet rate limit, and the active_connections
            // cap above.

            const slot = self.pool.acquire() orelse {
                // Per-worker pool is full even though the global active count was under
                // max_connections (SO_REUSEPORT can skew connections onto one worker).
                // Count it distinctly from the global cap so the drop isn't invisible.
                _ = self.state.active_connections.fetchSub(1, .monotonic);
                _ = self.state.stats_dropped_pool.fetchAdd(1, .monotonic);
                closeFd(cfd);
                continue;
            };

            slot.active_reserved = true;
            slot.hs_counted = false;
            slot.traffic_client_to_upstream_counter = &self.state.client_to_upstream_bytes_total;
            slot.traffic_upstream_to_client_counter = &self.state.upstream_to_client_bytes_total;
            slot.user_metrics = null;
            slot.conn_id = self.state.connection_count.fetchAdd(1, .monotonic);
            slot.client_fd = cfd;
            slot.peer_addr = client_addr;
            slot.expect_proxy_header = proxy_proto;
            slot.client_transport = .fake_tls;
            slot.phase = .reading_tls_header;
            slot.handshake_pos = 0;
            slot.created_at_ms = nowMs();
            slot.last_activity_ms = slot.created_at_ms;
            slot.last_client_byte_ms = 0;
            slot.last_server_byte_ms = 0;
            slot.idle_timeout_ms = jitteredIdleTimeoutMs(
                self.state.config.idle_timeout_sec,
                self.state.config.idle_timeout_jitter_pct,
                slot.conn_id ^ @as(u64, @bitCast(slot.created_at_ms)),
            );
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
        const cur_flood = self.state.stats_dropped_flood_guard.load(.monotonic);
        const cur_hs = self.state.stats_dropped_hs_budget.load(.monotonic);
        const cur_hst = self.state.stats_hs_timeout.load(.monotonic);
        const cur_mpf = self.state.stats_mp_fallback.load(.monotonic);
        const cur_pool = self.state.stats_dropped_pool.load(.monotonic);

        const d_cap = cur_cap - self.prev_dropped_cap;
        const d_sat = cur_sat - self.prev_dropped_saturation;
        const d_rate = cur_rate - self.prev_dropped_rate_limit;
        const d_flood = cur_flood - self.prev_dropped_flood_guard;
        const d_hs = cur_hs - self.prev_dropped_hs_budget;
        const d_hst = cur_hst - self.prev_hs_timeout;
        const d_mpf = cur_mpf - self.prev_mp_fallback;
        const d_pool = cur_pool - self.prev_dropped_pool;

        self.prev_dropped_cap = cur_cap;
        self.prev_dropped_saturation = cur_sat;
        self.prev_dropped_rate_limit = cur_rate;
        self.prev_dropped_flood_guard = cur_flood;
        self.prev_dropped_hs_budget = cur_hs;
        self.prev_hs_timeout = cur_hst;
        self.prev_mp_fallback = cur_mpf;
        self.prev_dropped_pool = cur_pool;

        const has_drops = d_cap + d_sat + d_rate + d_flood + d_hs + d_hst + d_mpf + d_pool > 0;

        // Build per-user active connection counts for dashboard parsing
        var user_buf: [1024]u8 = undefined;
        var user_pos: usize = 0;
        var users_active_total: u32 = 0;
        for (self.state.user_metrics) |um| {
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
            log.info("  drops: cap+={d} sat+={d} rate+={d} flood_guard+={d} hs_budget+={d} hs_timeout+={d} mp_fallback+={d} pool+={d}", .{
                d_cap, d_sat, d_rate, d_flood, d_hs, d_hst, d_mpf, d_pool,
            });
        }

        // A run of MiddleProxy->direct fallbacks means the ad-tag (and non-Premium media via
        // ME) is silently NOT applied for those connections. Surface it instead of letting it
        // pass unnoticed — the usual cause is a wrong/undetected egress NAT IP.
        if (d_mpf > 0 and (self.state.config.use_middle_proxy or self.state.config.tag != null)) {
            log.warn("ad-tag likely inactive: {d} middle-proxy handshake(s) fell back to direct this interval — those connections carry no ad-tag/ME media. Check egress reachability and [server].middle_proxy_nat_ip.", .{d_mpf});
        }

        var top_entries: [5]HandshakeFloodGuard.TopEntry = undefined;
        const flood_cfg = floodGuardSettings(&self.state.config);
        const top_len = self.state.floodTop(flood_cfg, top_entries[0..]);
        if (top_len > 0 and (d_flood + d_rate + d_hs + d_hst > 0 or hs > 0)) {
            var top_buf: [1024]u8 = undefined;
            const top = formatFloodGuardTop(top_entries[0..top_len], &top_buf);
            if (top.len > 0) {
                log.info("  flood_guard: blocked+={d} top{{{s}}}", .{ d_flood, top });
            }
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
        self.state.shutting_down.store(true, .release); // flip /readyz to draining
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
            "SIGUSR1 stats: active={d}/{d} hs={d} total={d} closed={d} c2s={d} s2c={d} paused={}/{} drops(cap/sat/rate/flood/hs)={d}/{d}/{d}/{d}/{d}",
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
                snapshot.drops_flood_guard_total,
                snapshot.drops_handshake_budget_total,
            },
        );
    }

    fn reloadConfigFromDisk(self: *EventLoop) void {
        // With multiple SO_REUSEPORT workers, a live reload would swap and FREE
        // shared config string slices (tls_domain, mask_target, …) that the other
        // worker threads read on the handshake hot path — a torn-pointer /
        // use-after-free data race. Refuse the reload and require a restart.
        if (self.state.effective_workers > 1) {
            log.warn("SIGHUP: config reload is not supported with [server].workers>1 ({d} workers); restart to apply changes", .{self.state.effective_workers});
            return;
        }
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

        const access_applied = self.state.reloadAccessUsers(&next) catch |err| {
            log.err("SIGHUP: failed to apply access users: {any}", .{err});
            return;
        };
        if (access_applied > 0) {
            log.info(
                "SIGHUP: access users reloaded users={d} direct_users={d} retired_metrics={d}",
                .{ self.state.user_secrets.len, self.state.config.direct_users.count(), self.state.retired_user_metrics.items.len },
            );
            applied += access_applied;
        }

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
        if (next.handshake_flood_guard_enabled != self.state.config.handshake_flood_guard_enabled) {
            self.state.config.handshake_flood_guard_enabled = next.handshake_flood_guard_enabled;
            applied += 1;
        }
        if (next.handshake_flood_guard_threshold != self.state.config.handshake_flood_guard_threshold) {
            self.state.config.handshake_flood_guard_threshold = next.handshake_flood_guard_threshold;
            applied += 1;
        }
        if (next.handshake_flood_guard_window_sec != self.state.config.handshake_flood_guard_window_sec) {
            self.state.config.handshake_flood_guard_window_sec = next.handshake_flood_guard_window_sec;
            applied += 1;
        }
        if (next.handshake_flood_guard_block_sec != self.state.config.handshake_flood_guard_block_sec) {
            self.state.config.handshake_flood_guard_block_sec = next.handshake_flood_guard_block_sec;
            applied += 1;
        }
        if (next.log_level != self.state.config.log_level) {
            self.state.config.log_level = next.log_level;
            runtime_log.level = next.log_level;
            applied += 1;
        }
        const tls_domain_changed = !std.mem.eql(u8, next.tls_domain, self.state.config.tls_domain);
        const mask_target_changed = !optionalStringEql(next.mask_target, self.state.config.mask_target);
        if (next.mask != self.state.config.mask or next.mask_port != self.state.config.mask_port or tls_domain_changed or mask_target_changed) {
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
            if (mask_target_changed) {
                if (next.mask_target) |target| {
                    if (self.state.allocator.dupe(u8, target)) |owned_mask_target| {
                        if (self.state.config.ownsMaskTarget()) {
                            self.state.allocator.free(self.state.config.mask_target.?);
                        }
                        self.state.config.mask_target = owned_mask_target;
                    } else |_| {
                        log.warn("SIGHUP: failed to apply new mask_target due to allocation error", .{});
                    }
                } else {
                    if (self.state.config.ownsMaskTarget()) {
                        self.state.allocator.free(self.state.config.mask_target.?);
                    }
                    self.state.config.mask_target = null;
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
        const mask_target = cfg.effectiveMaskTarget();
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
            .reading_direct_obfuscated_handshake => self.readDirectObfuscatedHandshake(slot),
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

        // Relay half-close: upstream gracefully closed and we were draining its already-read
        // s2c data to a slow client. Once that queue empties, the connection is done.
        if (slot.upstream_detached and !slot.hasClientPending()) {
            self.closeSlot(slot, "relay drained after peer half-close");
            return;
        }

        switch (slot.phase) {
            .writing_server_hello_first => {
                if (!slot.hasClientPending()) {
                    slot.phase = .desync_wait;
                    slot.desync_deadline_ns = self.desyncSplitDeadlineNs(slot);
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

                // Relay half-close: client gracefully closed and we were draining its
                // already-read c2s data to upstream. Once that queue empties, we're done.
                if (slot.client_detached and !slot.hasUpstreamPending()) {
                    self.closeSlot(slot, "relay drained after peer half-close");
                    return;
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

    /// Deadline for the desync first-byte→rest split: a configurable base plus a cheap
    /// per-connection jitter. A *fixed* gap is itself a passive timing fingerprint; the
    /// jitter (derived from conn_id, no CSPRNG on the hot path) varies it per connection.
    fn desyncSplitDeadlineNs(self: *EventLoop, slot: *const ConnectionSlot) i128 {
        const cfg = &self.state.config;
        var delay_ms: u64 = cfg.desync_split_delay_ms;
        if (cfg.desync_split_jitter_ms > 0) {
            const mix = slot.conn_id *% 0x9E3779B97F4A7C15;
            delay_ms += (mix >> 33) % (@as(u64, cfg.desync_split_jitter_ms) + 1);
        }
        return nowNs() + @as(i128, delay_ms) * std.time.ns_per_ms;
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

    /// Charge a connection against the handshake-inflight budget once it has
    /// sent its first byte. Returns false (and reverts) if the budget is
    /// exhausted, in which case the caller must close the slot. The budget caps
    /// concurrent in-flight handshakes at 30% of max_connections so churn
    /// (scanners/probes that actually handshake) cannot starve established
    /// relays. Pre-first-byte sessions are deliberately NOT counted.
    fn reserveHandshakeBudget(self: *EventLoop, slot: *ConnectionSlot) bool {
        if (slot.hs_counted) return true;
        const hs_inflight = self.state.handshakes_inflight.fetchAdd(1, .monotonic);
        const hs_max = (self.state.config.max_connections * 3) / 10;
        if (hs_max > 0 and hs_inflight >= hs_max) {
            _ = self.state.handshakes_inflight.fetchSub(1, .monotonic);
            _ = self.state.stats_dropped_hs_budget.fetchAdd(1, .monotonic);
            return false;
        }
        slot.hs_counted = true;
        return true;
    }

    /// Release a connection's handshake-budget slot exactly once (idempotent).
    fn releaseHandshakeBudget(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hs_counted) {
            _ = self.state.handshakes_inflight.fetchSub(1, .monotonic);
            slot.hs_counted = false;
        }
    }

    const ProxyHeaderStep = enum { done, wait, closed };

    /// MSG_PEEK the connection's first bytes, parse a HAProxy PROXY-protocol header, and
    /// drain exactly its bytes (leaving the TLS ClientHello untouched in the socket buffer)
    /// so peer_addr reflects the real client behind a load balancer.
    fn tryConsumeProxyHeader(self: *EventLoop, slot: *ConnectionSlot) ProxyHeaderStep {
        var peek: [256]u8 = undefined;
        const msg_peek: u32 = 0x2; // MSG_PEEK (Linux)
        const rc = posix.system.recvfrom(slot.client_fd, &peek, peek.len, msg_peek, null, null);
        const n: usize = switch (posix.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN, .INTR => return .wait,
            else => {
                self.closeSlot(slot, "proxy header read error");
                return .closed;
            },
        };
        if (n == 0) {
            self.closeSlot(slot, "client eof before proxy header");
            return .closed;
        }
        switch (proxy_protocol.parse(peek[0..n])) {
            .incomplete => {
                if (n >= peek.len) {
                    self.closeSlot(slot, "proxy header too long");
                    return .closed;
                }
                return .wait;
            },
            .invalid => {
                self.closeSlot(slot, "invalid proxy header");
                return .closed;
            },
            .ok => |res| {
                var drain: [256]u8 = undefined;
                var left: usize = res.consumed;
                while (left > 0) {
                    const got = posix.read(slot.client_fd, drain[0..@min(left, drain.len)]) catch {
                        self.closeSlot(slot, "proxy header drain error");
                        return .closed;
                    };
                    if (got == 0) {
                        self.closeSlot(slot, "client eof draining proxy header");
                        return .closed;
                    }
                    left -= got;
                }
                if (res.src) |real| slot.peer_addr = real;
                slot.expect_proxy_header = false;
                slot.last_activity_ms = nowMs();
                return .done;
            },
        }
    }

    fn readTlsHeader(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.expect_proxy_header) {
            switch (self.tryConsumeProxyHeader(slot)) {
                .done => {},
                .wait => return,
                .closed => return,
            }
        }
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
                // First byte arrived → the connection is now actually
                // handshaking. Charge it against the handshake-inflight budget
                // here (not at accept) so pre-first-byte silent sessions never
                // occupied a budget slot. Covers both FakeTLS and the dd path,
                // which is entered from this function after the TLS sniff.
                if (!self.reserveHandshakeBudget(slot)) {
                    // Feed the flood guard so a client that repeatedly burns the budget
                    // accrues a score (and the per-IP handshake_budget column is no longer
                    // dead telemetry). This is a client-driven, first-byte event.
                    _ = self.state.floodRecord(slot.peer_addr, .handshake_budget, floodGuardSettings(&self.state.config));
                    self.closeSlot(slot, "handshake budget exhausted");
                    return;
                }
            }
            slot.tls_hdr_pos += @intCast(n);
            slot.last_activity_ms = nowMs();
        }

        if (!tls.isTlsHandshake(slot.tls_hdr_buf[0..])) {
            if (self.state.config.fake_tls_only) {
                // Strict FakeTLS-only: never accept the non-TLS "direct
                // obfuscated" (dd) transport. Mask the bytes immediately so a
                // non-TLS active probe gets the masking cover (matching the old
                // behavior) instead of being read up to 64 bytes — no dd
                // transport and no dd active-probe distinguisher.
                self.startMasking(slot, slot.tls_hdr_buf[0..]) catch {
                    self.closeSlot(slot, "non-tls masked failed");
                };
                return;
            }
            slot.client_transport = .direct_obfuscated;
            @memcpy(slot.handshake_buf[0..tls_header_len], slot.tls_hdr_buf[0..]);
            slot.handshake_pos = tls_header_len;
            slot.phase = .reading_direct_obfuscated_handshake;
            self.readDirectObfuscatedHandshake(slot);
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

    fn readDirectObfuscatedHandshake(self: *EventLoop, slot: *ConnectionSlot) void {
        while (slot.handshake_pos < constants.handshake_len) {
            const n = posix.read(slot.client_fd, slot.handshake_buf[slot.handshake_pos..]) catch |err| {
                if (err == error.WouldBlock) return;
                self.closeSlot(slot, "direct obfuscated handshake read error");
                return;
            };
            if (n == 0) {
                // A real dd client sends all 64 obfuscation bytes; a short
                // non-TLS payload followed by EOF is a probe shape. Serve the
                // masking cover for whatever was buffered instead of a bare
                // silent close, so the response matches the masking target
                // rather than fingerprinting the proxy.
                self.startMasking(slot, slot.handshake_buf[0..slot.handshake_pos]) catch {
                    self.closeSlot(slot, "client eof during direct obfuscated handshake");
                };
                return;
            }
            slot.handshake_pos += @intCast(n);
            slot.last_activity_ms = nowMs();
        }

        const result = obfuscation.ObfuscationParams.fromHandshake(&slot.handshake_buf, self.state.user_secrets) orelse {
            self.startMasking(slot, slot.handshake_buf[0..]) catch {
                self.closeSlot(slot, "bad direct obfuscated handshake");
            };
            return;
        };

        self.finishParsedClientHandshake(slot, result);
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
            self.handleInvalidSni(slot, client_hello, null, "tls missing sni");
            return;
        }

        const sni = maybe_sni.?;
        if (!std.ascii.eqlIgnoreCase(sni, self.state.config.tls_domain)) {
            self.handleInvalidSni(slot, client_hello, sni, "tls sni mismatch");
            return;
        }

        const validation = tls.validateTlsHandshake(
            self.state.allocator,
            client_hello,
            self.state.user_secrets,
            false,
            self.state.clock_offset_seconds,
        ) catch null;

        if (validation == null) {
            self.startMasking(slot, client_hello) catch {
                self.closeSlot(slot, "tls validation failed");
            };
            return;
        }

        const v = validation.?;
        if (self.state.replay_cache.checkAndInsert(&v.canonical_hmac)) {
            _ = self.state.stats_replay_hits.fetchAdd(1, .monotonic);
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

        // Echo a client-offered cipher in the ServerHello (naturalistic, matches
        // how a real server negotiates) instead of a constant. Falls back to the
        // template default when the client offered no parseable TLS 1.3 suite.
        const client_hello_bytes = slot.clientHelloBuf()[0..slot.client_hello_len];

        // Diagnostic: log the first few real ClientHello fingerprints so an operator
        // can see what their client actually offers (e.g. whether it presents
        // X25519MLKEM768) before we match the ServerHello to it. Quiets after the budget.
        // Saturating decrement: only consume a slot while the budget is > 0, via
        // cmpxchg, so two SO_REUSEPORT workers racing at value 1 can't both fetchSub
        // and wrap the u32 past zero (which would keep the counter non-zero forever).
        const fp_consumed = blk: {
            var cur = self.state.clienthello_fp_budget.load(.monotonic);
            while (cur != 0) {
                if (self.state.clienthello_fp_budget.cmpxchgWeak(cur, cur - 1, .monotonic, .monotonic)) |actual| {
                    cur = actual; // lost the race — retry with the observed value
                } else {
                    break :blk true; // decremented from a positive value
                }
            }
            break :blk false;
        };
        // A PQ-offering client (X25519MLKEM768 0x11ec) must be answered with a 0x11ec
        // key_share, else we emit a passive group-downgrade tell.
        const offers_pq = tls.clientOffersPqKeyShare(client_hello_bytes);
        if (fp_consumed) {
            var fp_buf: [256]u8 = undefined;
            if (tls.formatClientHelloFingerprint(client_hello_bytes, &fp_buf)) |fp| {
                log.info("client ClientHello [{s}] (we serve: cipher echoes client, key_share={s})", .{
                    fp,
                    if (offers_pq) "X25519MLKEM768 0x11ec" else "x25519 0x001d",
                });
            }
        }

        const echoed_cipher = tls.extractFirstTls13Cipher(client_hello_bytes);
        const session_id = slot.validation_session_id[0..slot.validation_session_id_len];
        slot.server_hello = (if (offers_pq)
            tls.buildServerHelloPq(
                self.state.allocator,
                &slot.validation_secret,
                &slot.validation_digest,
                session_id,
                echoed_cipher,
                self.state.tls_server_hello_template.len - tls.server_hello_prefix_len,
            )
        else
            tls.buildServerHelloWithTemplate(
                self.state.allocator,
                self.state.tls_server_hello_template[0..],
                &slot.validation_secret,
                &slot.validation_digest,
                session_id,
                echoed_cipher,
            )) catch {
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

        self.finishParsedClientHandshake(slot, result);
    }

    fn finishParsedClientHandshake(self: *EventLoop, slot: *ConnectionSlot, result: anytype) void {
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

        // Per-user limits (read at startup; changing them needs a restart). Checked
        // BEFORE assigning slot.user_metrics so a rejected connection never touches
        // the active-connection counter (closeSlot decrements only when it's set).
        if (self.state.config.user_expirations) |exps| {
            if (exps.get(result.user)) |expiry_ts| {
                if (realtimeSeconds() >= expiry_ts) {
                    self.closeSlot(slot, "user expired");
                    return;
                }
            }
        }
        if (self.state.findUserMetrics(result.user)) |entry| {
            // Optimistic atomic admission: increment first, then roll back + reject if
            // we exceeded the per-user cap. Avoids a load-then-add TOCTOU where two
            // SO_REUSEPORT workers both pass a non-atomic check and overshoot the cap.
            const prev = entry.connections_active.fetchAdd(1, .monotonic);
            if (self.state.config.user_max_conns) |maxc| {
                if (maxc.get(result.user)) |cap| {
                    if (prev >= cap) {
                        _ = entry.connections_active.fetchSub(1, .monotonic);
                        self.closeSlot(slot, "user connection limit");
                        return;
                    }
                }
            }
            slot.user_metrics = entry;
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

    /// Handle a ClientHello whose SNI is missing or doesn't match tls_domain,
    /// per `unknown_sni_action`: `mask` forwards to the masking backend (default,
    /// active-probe defense), `reject` emits a fatal `handshake_failure` (40) TLS alert
    /// like nginx ssl_reject_handshake and closes, `drop` closes silently. Validation-failed /
    /// replay cases (SNI matched) keep masking — they're not handled here.
    fn handleInvalidSni(self: *EventLoop, slot: *ConnectionSlot, client_hello: []const u8, sni: ?[]const u8, reason: []const u8) void {
        _ = self.state.stats_unknown_sni.fetchAdd(1, .monotonic);
        switch (self.state.config.unknown_sni_action) {
            .mask => {
                // SNI-following: if the probed SNI is safelisted, front to that domain's
                // own server so the on-wire conversation matches the SNI the prober claimed.
                if (sni) |s| {
                    for (self.state.mask_safelist) |entry| {
                        if (std.ascii.eqlIgnoreCase(s, entry.domain)) {
                            slot.mask_addr_override = entry.addr;
                            break;
                        }
                    }
                }
                self.startMasking(slot, client_hello) catch self.closeSlot(slot, reason);
            },
            .reject => {
                if (self.state.config.reject_rst) {
                    // Mirror a server/middlebox that resets a bad handshake: no alert,
                    // force an RST on the (deferred) close via SO_LINGER{0}.
                    setLingerReset(slot.client_fd);
                } else {
                    // Best-effort raw write of the 7-byte fatal alert before close (mirrors
                    // queue_io's syscall use); a partial/EAGAIN write is fine here.
                    const alert: []const u8 = &tls.reject_handshake_alert;
                    _ = posix.system.write(slot.client_fd, alert.ptr, alert.len);
                }
                self.closeSlot(slot, reason);
            },
            .drop => self.closeSlot(slot, reason),
        }
    }

    fn startMasking(self: *EventLoop, slot: *ConnectionSlot, buffered: []const u8) !void {
        if (!self.state.config.mask) return error.MaskingDisabled;

        // Consume a one-shot SNI-following override if set; otherwise the default target.
        const addr = blk: {
            if (slot.mask_addr_override) |override| {
                slot.mask_addr_override = null;
                break :blk override;
            }
            break :blk self.state.mask_addr orelse return error.NoMaskAddress;
        };
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
        // Stamp the per-endpoint connect deadline base. tryNextDcEndpoint re-enters here
        // for each endpoint, so this resets per attempt (see dc_connect_timeout_sec).
        slot.upstream_connect_started_ms = nowMs();

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
            self.releaseHandshakeBudget(slot);
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
        if (slot.client_transport == .direct_obfuscated) {
            self.relayObfuscatedClientToUpstream(slot);
            return;
        }

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
            slot.last_client_byte_ms = slot.last_activity_ms;
        }
    }

    fn relayUpstreamToClient(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasClientPending()) return;
        if (slot.client_transport == .direct_obfuscated) {
            self.relayObfuscatedUpstreamToClient(slot);
            return;
        }

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
            slot.last_server_byte_ms = slot.last_activity_ms;
        }
    }

    fn relayObfuscatedClientToUpstream(self: *EventLoop, slot: *ConnectionSlot) void {
        const n = posix.read(slot.client_fd, self.shared_read_buf[0..]) catch |err| {
            if (err == error.WouldBlock) return;
            self.closeSlot(slot, "direct obfuscated c2s read error");
            return;
        };
        if (n == 0) {
            self.closeSlot(slot, "direct obfuscated c2s eof");
            return;
        }

        const payload = self.shared_read_buf[0..n];
        if (slot.client_decryptor) |*dec| dec.apply(payload);

        if (slot.middle_ctx) |*mp| {
            const scratch = self.ensureMpC2sScratch() catch {
                self.closeSlot(slot, "alloc middleproxy c2s scratch failed");
                return;
            };
            const out_data = mp.encapsulateC2S(payload, scratch) catch {
                self.closeSlot(slot, "direct obfuscated middleproxy c2s failed");
                return;
            };
            if (out_data.len > 0) {
                _ = proxyHandshakeQueueUpstream(self, slot, out_data) catch {
                    self.closeSlot(slot, "direct obfuscated c2s queue failed");
                    return;
                };
            }
        } else if (slot.tg_encryptor) |*enc| {
            enc.apply(payload);
            _ = proxyHandshakeQueueUpstream(self, slot, payload) catch {
                self.closeSlot(slot, "direct obfuscated c2s queue failed");
                return;
            };
        } else {
            // No encapsulation/encryptor wired up: forwarding here would silently
            // black-hole decrypted client data while still counting it. The dd
            // path only reaches .relaying after dc_nonce/middleProxyBegin set one
            // of these, so this is unreachable today — fail loudly if it changes.
            self.closeSlot(slot, "direct obfuscated c2s missing encryptor/middle_ctx");
            return;
        }

        slot.c2s_bytes += payload.len;
        slot.last_activity_ms = nowMs();
        slot.last_client_byte_ms = slot.last_activity_ms;
    }

    fn relayObfuscatedUpstreamToClient(self: *EventLoop, slot: *ConnectionSlot) void {
        const n = posix.read(slot.upstream_fd, self.shared_read_buf[0..]) catch |err| {
            if (err == error.WouldBlock) return;
            self.closeSlot(slot, "direct obfuscated s2c read error");
            return;
        };
        if (n == 0) {
            self.closeSlot(slot, "direct obfuscated s2c eof");
            return;
        }

        const raw = self.shared_read_buf[0..n];
        if (slot.middle_ctx) |*mp| {
            const scratch = self.ensureMpS2cScratch() catch {
                self.closeSlot(slot, "alloc middleproxy s2c scratch failed");
                return;
            };
            const payload = mp.decapsulateS2C(raw, scratch) catch {
                self.closeSlot(slot, "direct obfuscated middleproxy s2c failed");
                return;
            };
            if (payload.len == 0) return;
            if (slot.client_encryptor) |*enc| enc.apply(payload);
            _ = relayQueueClient(self, slot, payload) catch {
                self.closeSlot(slot, "direct obfuscated s2c queue failed");
                return;
            };
            slot.s2c_bytes += payload.len;
        } else {
            if (!slot.use_fast_mode) {
                if (slot.tg_decryptor) |*dec| dec.apply(raw);
                if (slot.client_encryptor) |*enc| enc.apply(raw);
            }
            _ = relayQueueClient(self, slot, raw) catch {
                self.closeSlot(slot, "direct obfuscated s2c queue failed");
                return;
            };
            slot.s2c_bytes += raw.len;
        }

        slot.last_activity_ms = nowMs();
        slot.last_server_byte_ms = slot.last_activity_ms;
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

            // Per-endpoint upstream connect deadline. Fires only while a connect() is still
            // in flight; lets failover advance to the next DC endpoint quickly instead of
            // burning the whole (global) handshake_timeout_sec on one black-holed endpoint.
            if (slot.phase == .connecting_upstream and self.state.config.dc_connect_timeout_sec > 0 and
                slot.upstream_connect_started_ms > 0 and
                now_ms - slot.upstream_connect_started_ms > secondsToMs(self.state.config.dc_connect_timeout_sec))
            {
                const failed_kind = slot.upstream_kind;
                self.cleanupFailedUpstreamConnect(slot);
                // Mirror onUpstreamConnectComplete's failure path: DC endpoints fail over to
                // the next candidate; any other upstream kind (mask/proxy/middle) just closes.
                if (failed_kind == .dc and self.tryNextDcEndpoint(slot, error.ConnectTimedOut)) continue;
                self.closeSlot(slot, "dc connect timeout");
                continue;
            }

            if (slot.handshakeInProgress()) {
                if (slot.first_byte_at_ms == 0) {
                    if (now_ms - slot.created_at_ms > (if (slot.idle_timeout_ms > 0) slot.idle_timeout_ms else secondsToMs(self.state.config.idle_timeout_sec))) {
                        self.closeSlot(slot, "idle pre-first-byte timeout");
                        continue;
                    }
                } else if (slot.phase == .reading_direct_obfuscated_handshake and
                    now_ms - slot.first_byte_at_ms > dd_handshake_decision_ms)
                {
                    // A non-TLS (dd) connection that hasn't completed its 64-byte
                    // handshake shortly after the first byte is almost certainly a
                    // probe. Serve the masking cover now instead of waiting out the
                    // full handshake_timeout and then closing silently — this makes
                    // the response match the masking target and shrinks the active-
                    // probe timing oracle. Falls back to close if masking is off.
                    self.startMasking(slot, slot.handshake_buf[0..slot.handshake_pos]) catch {
                        self.closeSlot(slot, "dd handshake decision timeout");
                    };
                    continue;
                } else if (now_ms - slot.first_byte_at_ms > secondsToMs(self.state.config.handshake_timeout_sec)) {
                    _ = self.state.stats_hs_timeout.fetchAdd(1, .monotonic);
                    // Only blame the client's IP when the stall is client-driven. An
                    // upstream-side timeout (DC unreachable, slow upstream proxy, stale
                    // middleproxy secret) is not the client's fault, and feeding it to the
                    // flood guard would block legit secret-holders behind a shared NAT
                    // during an upstream outage.
                    if (isClientDrivenHandshakePhase(slot.phase) and !slot.mp_step.awaitingMiddleProxy()) {
                        _ = self.state.floodRecord(slot.peer_addr, .handshake_timeout, floodGuardSettings(&self.state.config));
                    }
                    // A timeout while still waiting on the middleproxy RPC handshake
                    // means the cached DC/secret likely went stale (Telegram rotates
                    // them) — ask the updater to refresh ahead of its periodic timer.
                    if (slot.mp_step.awaitingMiddleProxy()) self.state.requestMiddleProxyRefresh();
                    self.closeSlot(slot, "handshake timeout");
                    continue;
                }
            } else if (slot.phase == .relaying or slot.phase == .mask_relaying) {
                // Break an iOS MtProtoKit bad_salt wedge. After a stale-salt rejection the
                // client discards the server-supplied salt, gets stuck in
                // AwaitingTimeFixAndSalts and stops sending entirely (even queued pings/acks
                // never go out), so "Updating" hangs ~90-120s until the DC closes the socket.
                // We detect the wedge precisely (not by plain idle, which a healthy connection
                // does for ~45-60s between pings): the last relayed payload was server->client
                // and the client has not answered for the threshold. A healthy client confirms
                // any incoming message immediately (MtProtoKit schedules the ack + requests a
                // transaction on receipt), so an unanswered server reply past the threshold is a
                // wedge; a healthy connection whose last word was its own ping/ack
                // (last_client_byte_ms >= last_server_byte_ms) is never touched, however long it
                // idles. The threshold must exceed the slowest legitimate server response time
                // (a big getDifference) or it would tear down slow-but-healthy requests. A
                // graceful close triggers a ~450ms clean reconnect. Gated on
                // last_client_byte_ms>0 so a fresh/never-spoke connection is never touched.
                if (slot.phase == .relaying and self.state.config.client_silence_close_sec > 0 and
                    slot.last_client_byte_ms > 0 and
                    slot.last_server_byte_ms > slot.last_client_byte_ms and
                    now_ms - slot.last_server_byte_ms > secondsToMs(self.state.config.client_silence_close_sec))
                {
                    log.info("[{d}] closing relay: server reply unanswered {d}s (iOS bad_salt wedge breaker)", .{ slot.conn_id, self.state.config.client_silence_close_sec });
                    self.closeSlot(slot, "client silence wedge breaker");
                    continue;
                }
                if (slot.phase == .mask_relaying and self.state.config.mask_relay_max_secs > 0 and
                    now_ms - slot.created_at_ms > secondsToMs(self.state.config.mask_relay_max_secs))
                {
                    self.closeSlot(slot, "mask relay max duration");
                    continue;
                }
                if (now_ms - slot.last_activity_ms > (if (slot.idle_timeout_ms > 0) slot.idle_timeout_ms else secondsToMs(self.state.config.idle_timeout_sec))) {
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
            .reading_direct_obfuscated_handshake,
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

            .relaying, .mask_relaying => {
                if (slot.relay_half_closed) {
                    // One side gracefully closed; only drain the surviving direction's
                    // queued data (want_*_out already reflects hasXPending). Don't read
                    // from either peer — c2s has nowhere to go and the closed side is gone.
                    want_client_in = false;
                    want_upstream_in = false;
                } else {
                    want_client_in = !slot.hasUpstreamPending();
                    want_upstream_in = !slot.hasClientPending();
                }
            },

            else => {},
        }

        // A detached fd (relay half-close) has left epoll — never modFd it.
        if (slot.client_fd != -1 and !slot.client_detached) {
            if (slot.client_interest_in != want_client_in or slot.client_interest_out != want_client_out) {
                try self.modFd(slot.client_fd, want_client_in, want_client_out);
                slot.client_interest_in = want_client_in;
                slot.client_interest_out = want_client_out;
            }
        }

        if (slot.upstream_fd != -1 and !slot.upstream_detached) {
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

    /// Begin a relay half-close drain: the peer on `hung_fd` gracefully closed while data
    /// was still queued for the other peer. Detach `hung_fd` from epoll (it stays open so
    /// closeSlot still closes it) and let the surviving direction flush; the writable
    /// handler closes the slot once its queue drains, with the relay idle timer as backstop.
    fn beginRelayHalfClose(self: *EventLoop, slot: *ConnectionSlot, hung_fd: posix.fd_t) void {
        _ = self.delFd(hung_fd) catch {};
        if (hung_fd == slot.client_fd) {
            slot.client_detached = true;
            slot.client_interest_in = false;
            slot.client_interest_out = false;
        } else {
            slot.upstream_detached = true;
            slot.upstream_interest_in = false;
            slot.upstream_interest_out = false;
        }
        slot.relay_half_closed = true;
        slot.last_activity_ms = nowMs();
        self.syncInterests(slot) catch {
            self.closeSlot(slot, "half-close sync failed");
            return;
        };
        // If the surviving direction had nothing buffered after all, close now.
        if (slot.upstream_detached and !slot.hasClientPending()) {
            self.closeSlot(slot, "relay drained after peer half-close");
        } else if (slot.client_detached and !slot.hasUpstreamPending()) {
            self.closeSlot(slot, "relay drained after peer half-close");
        }
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

        // Unmap from fd_to_slot immediately so any later stale event in this batch misses,
        // but defer the actual close() to batch end so the fd number can't be recycled by
        // an accept()/connect() mid-batch and then misattributed (see pending_close_fds).
        if (slot.client_fd != -1) {
            _ = self.delFd(slot.client_fd) catch {};
            self.pool.unmapFd(slot.client_fd);
            self.deferClose(slot.client_fd);
            slot.client_fd = -1;
        }

        if (slot.upstream_fd != -1) {
            _ = self.delFd(slot.upstream_fd) catch {};
            self.pool.unmapFd(slot.upstream_fd);
            self.deferClose(slot.upstream_fd);
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
            // RED errors + evasion signal: bucket the close reason once per slot.
            _ = self.state.close_reasons[@intFromEnum(CloseReason.classify(reason))].fetchAdd(1, .monotonic);
            slot.active_reserved = false;
            self.closed_since_log += 1;
        }
        // Release the handshake-budget slot exactly once, keyed on hs_counted
        // (set at first byte). Pre-first-byte sessions were never counted, and
        // relay/mask completion already released, so this is a no-op in those
        // cases and avoids both leaks and underflow.
        self.releaseHandshakeBudget(slot);
        // Reclaim retired user-metrics whose connections have now drained (#302).
        self.state.collectRetiredUserMetrics();

        slot.desync_wait_enqueued = false;
        slot.relay_half_closed = false;
        slot.client_detached = false;
        slot.upstream_detached = false;
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

test "ProxyState access reload keeps active metrics safe" {
    const allocator = std.testing.allocator;

    const initial_cfg = try Config.parse(allocator,
        \\[server]
        \\port = 443
        \\
        \\[access.users]
        \\alice = "00000000000000000000000000000001"
        \\removed = "00000000000000000000000000000002"
        \\
        \\[access.direct_users]
        \\removed = true
    );
    var state = try ProxyState.init(allocator, initial_cfg, "/tmp/mtproto-test.toml");
    defer state.deinit();

    const alice_metrics = state.findUserMetrics("alice") orelse return error.TestExpectedEqual;
    const removed_metrics = state.findUserMetrics("removed") orelse return error.TestExpectedEqual;
    _ = removed_metrics.connections_active.fetchAdd(1, .monotonic);

    var next_cfg = try Config.parse(allocator,
        \\[server]
        \\port = 443
        \\
        \\[access.users]
        \\alice = "0000000000000000000000000000000a"
        \\bob = "0000000000000000000000000000000b"
        \\
        \\[access.direct_users]
        \\alice = true
    );
    defer next_cfg.deinit(allocator);

    try state.reloadAccessUsersForTest(&next_cfg);

    try std.testing.expectEqual(@as(usize, 2), state.user_secrets.len);
    try std.testing.expect(state.config.userBypassesMiddleProxy("alice"));
    try std.testing.expect(!state.config.userBypassesMiddleProxy("removed"));
    try std.testing.expect(alice_metrics == state.findUserMetrics("alice").?);
    try std.testing.expect(state.findUserMetrics("bob") != null);
    try std.testing.expect(state.findUserMetrics("removed") == null);
    try std.testing.expectEqual(@as(u32, 1), removed_metrics.connections_active.load(.monotonic));

    _ = removed_metrics.connections_active.fetchSub(1, .monotonic);
    state.collectRetiredUserMetricsForTest();
    try std.testing.expectEqual(@as(usize, 0), state.retired_user_metrics.items.len);

    var saw_alice_new_secret = false;
    for (state.user_secrets) |entry| {
        if (std.mem.eql(u8, entry.name, "alice")) {
            saw_alice_new_secret = entry.secret[15] == 0x0a;
        }
    }
    try std.testing.expect(saw_alice_new_secret);
}

fn reloadAccessUsersInThread(
    state: *ProxyState,
    next_cfg: *Config,
    done: *std.atomic.Value(bool),
    failed: *std.atomic.Value(bool),
) void {
    state.reloadAccessUsersForTest(next_cfg) catch {
        failed.store(true, .release);
    };
    done.store(true, .release);
}

test "ProxyState access reload waits for metrics readers" {
    const allocator = std.testing.allocator;

    const initial_cfg = try Config.parse(allocator,
        \\[server]
        \\port = 443
        \\
        \\[access.users]
        \\alice = "00000000000000000000000000000001"
    );
    var state = try ProxyState.init(allocator, initial_cfg, "/tmp/mtproto-test.toml");
    defer state.deinit();

    var next_cfg = try Config.parse(allocator,
        \\[server]
        \\port = 443
        \\
        \\[access.users]
        \\alice = "0000000000000000000000000000000a"
        \\bob = "0000000000000000000000000000000b"
    );
    defer next_cfg.deinit(allocator);

    state.lockUserMetricsForReadForTest();

    var done = std.atomic.Value(bool).init(false);
    var failed = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, reloadAccessUsersInThread, .{ &state, &next_cfg, &done, &failed });

    sleepNs(20 * std.time.ns_per_ms);
    const completed_while_reader_locked = done.load(.acquire);

    state.unlockUserMetricsForReadForTest();
    thread.join();

    try std.testing.expect(!completed_while_reader_locked);
    try std.testing.expect(!failed.load(.acquire));
    try std.testing.expect(done.load(.acquire));
    try std.testing.expect(state.findUserMetrics("bob") != null);
}
