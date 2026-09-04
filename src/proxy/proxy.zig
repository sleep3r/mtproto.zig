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
const dns_cache = @import("dns_cache.zig");
const connection_pool_mod = @import("connection_pool.zig");
const relay_steps = @import("relay_steps.zig");
const middle_proxy_frames = @import("middle_proxy_frames.zig");
const middle_proxy_handshake = @import("middle_proxy_handshake.zig");
const proxy_upstream_handshake = @import("proxy_upstream_handshake.zig");
const middle_proxy_fallback = @import("middle_proxy_fallback.zig");
const middle_proxy_nat = @import("middle_proxy_nat.zig");
const dc_nonce = @import("dc_nonce.zig");
const upstream_failover = @import("upstream_failover.zig");
const trusted_peers = @import("trusted_peers.zig");
pub const UserIpLimit = @import("user_ip_limit.zig").UserIpLimit;
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
    _ = @import("trusted_peers.zig");
    _ = @import("user_ip_limit.zig");
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

fn configValueEqual(comptime T: type, a: T, b: T) bool {
    return switch (@typeInfo(T)) {
        .optional => |o| if (a) |v| (if (b) |w| configValueEqual(o.child, v, w) else false) else b == null,
        .pointer => |p| blk: {
            if (p.size != .slice) break :blk a == b;
            if (a.len != b.len) break :blk false;
            for (a, b) |v, w| if (!configValueEqual(p.child, v, w)) break :blk false;
            break :blk true;
        },
        .@"struct" => blk: {
            if (@hasDecl(T, "iterator") and @hasDecl(T, "get") and @hasDecl(T, "count")) {
                if (a.count() != b.count()) break :blk false;
                var iter = a.iterator();
                while (iter.next()) |entry| {
                    const other = b.get(entry.key_ptr.*) orelse break :blk false;
                    if (!configValueEqual(@TypeOf(other), entry.value_ptr.*, other)) break :blk false;
                }
            } else {
                inline for (std.meta.fields(T)) |f| {
                    if (!configValueEqual(f.type, @field(a, f.name), @field(b, f.name))) break :blk false;
                }
            }
            break :blk true;
        },
        else => std.meta.eql(a, b),
    };
}

fn isHotConfigField(comptime name: []const u8) bool {
    for ([_][]const u8{ "users", "direct_users", "idle_timeout_sec", "handshake_timeout_sec", "graceful_shutdown_timeout_sec", "rate_limit_per_subnet", "handshake_flood_guard_enabled", "handshake_flood_guard_threshold", "handshake_flood_guard_window_sec", "handshake_flood_guard_block_sec", "log_level", "mask", "mask_port", "mask_target", "desync", "drs", "fast_mode", "max_connections" }) |hot| {
        if (std.mem.eql(u8, name, hot)) return true;
    }
    return false;
}

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
const client_hello_inline_size: usize = 512;
const mp_handshake_frame_buf_size: usize = 2048;
const read_buf_size: usize = Config.relay_read_buffer_size;
const max_pipelined_handshake_bytes: usize = 128 * 1024;
const graceful_shutdown_check_ms: i32 = 25;

const upstream_candidates_inline_cap: usize = 4;

/// Inputs to the "does this peer get an MTProto responder at all?" decision.
pub const AcceptanceGate = struct {
    /// `[web].only` and `[web].enabled` together (`Config.Web.onlyActive`).
    web_only: bool,
    /// `[censorship].fake_tls_only`.
    fake_tls_only: bool,
    /// Whether the first bytes looked like a TLS handshake record.
    transport_is_tls: bool,
    /// Decided at accept() from the kernel-reported address, never from `peer_addr` —
    /// the PROXY-protocol path overwrites that with something the client supplied.
    trusted_peer: bool,
};

/// True when the connection must be handed to the masking backend instead of served.
///
/// Two gates, one shape. `fake_tls_only` (the default) refuses the non-TLS `dd`
/// transport to the public so there is no `dd` responder to fingerprint. `[web].only`
/// widens that to *every* transport: under WEB-only the relay is the only party that
/// gets an MTProto responder, and a real client holding a valid `ee` link is masked
/// exactly the way a wrong secret is — which is the point, because that is what makes a
/// WEB-only proxy indistinguishable from the site it fronts.
///
/// The relay is exempt from both, and it has to be: it dials this proxy on loopback for
/// every logical stream (`[web].backend`), so a blanket refusal would take the WEB proxy
/// down with the direct one.
pub fn masksInsteadOfServing(gate: AcceptanceGate) bool {
    if (gate.trusted_peer) return false;
    if (gate.web_only) return true;
    return !gate.transport_is_tls and gate.fake_tls_only;
}

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
        var redacted = entry.key;
        if (redacted.family == .ip4) redacted.bytes[3] = 0 else @memset(redacted.bytes[8..], 0);
        const ip = HandshakeFloodGuard.formatKey(redacted, &ip_buf);
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

// Shared snapshots use a real reader/writer lock: concurrent readers, exclusive updates.
const CompatRwLock = struct {
    mutex: std.Io.RwLock = .init,

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
        self.mutex.lockSharedUncancelable(io());
    }

    fn unlockShared(self: *CompatRwLock) void {
        self.mutex.unlockShared(io());
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

/// Whether it is safe to trust trySelectReachableMiddleProxy's verdict.
/// isAddressReachable opens a plain, unmarked, unproxied TCP socket, so it
/// measures reachability on the host's DEFAULT route — on a tunnel/socks5/http
/// upstream that (a) leaks a direct probe to Telegram MP IPs on exactly the
/// network path the egress choice exists to hide this traffic from, and (b)
/// can pick a candidate that is "reachable" on the wrong path but unreachable
/// through the real egress. Only `.direct` (no configured egress to bypass)
/// makes the probe meaningful.
fn middleProxyProbeAllowed(cfg: *const Config) bool {
    return middleProxyFetchRouteForConfig(cfg) == .direct;
}

test "middle-proxy reachability probe is skipped on any non-direct egress" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
    };
    defer cfg.deinit(std.testing.allocator);

    cfg.upstream_mode = .direct;
    try std.testing.expect(middleProxyProbeAllowed(&cfg));

    cfg.upstream_mode = .auto;
    try std.testing.expect(middleProxyProbeAllowed(&cfg));

    // Tunnel/socks5/http: a bare socket() probe would bypass the configured
    // egress entirely, so it must not be trusted.
    cfg.upstream_mode = .tunnel;
    try std.testing.expect(!middleProxyProbeAllowed(&cfg));

    cfg.upstream_mode = .socks5;
    try std.testing.expect(!middleProxyProbeAllowed(&cfg));

    cfg.upstream_mode = .http;
    try std.testing.expect(!middleProxyProbeAllowed(&cfg));
}

/// Whether ANY connection this process serves could take a middle-proxy route,
/// i.e. whether the background metadata updater thread is worth running at all.
/// Same three-way predicate as the NAT-IP warning in ProxyState.init: regular
/// traffic (use_middle_proxy), media/CDN traffic (force_media_middle_proxy,
/// default true even with use_middle_proxy=false), and the ad-tag RPC (tag),
/// which only takes effect over a middleproxy handshake.
fn middleProxyUpdaterNeeded(cfg: *const Config) bool {
    return cfg.use_middle_proxy or cfg.force_media_middle_proxy or cfg.tag != null;
}

/// Whether a specific connection's buildDcConnectPlan call should be handed a
/// live middle-proxy snapshot. DC203 (CDN) has no direct address at all and
/// always needs one; every other DC only needs one when regular MiddleProxy
/// routing is on, or when force_media_middle_proxy could route ITS media path
/// through MiddleProxy (buildDcConnectPlan itself gates that on dc_idx < 0, so
/// handing a snapshot to a regular connection here is harmless — it's simply
/// unused).
fn middleProxySnapshotWanted(cfg: *const Config, dc_abs: usize) bool {
    return cfg.use_middle_proxy or cfg.force_media_middle_proxy or dc_abs == 203;
}

test "middle-proxy updater runs whenever any MP route is reachable, not just use_middle_proxy" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
    };
    defer cfg.deinit(std.testing.allocator);

    // Shipped defaults: use_middle_proxy=false, force_media_middle_proxy=true.
    // The updater must still run, or DC203/media snapshots never refresh.
    cfg.use_middle_proxy = false;
    cfg.force_media_middle_proxy = true;
    try std.testing.expect(middleProxyUpdaterNeeded(&cfg));
    try std.testing.expect(middleProxySnapshotWanted(&cfg, 1));
    try std.testing.expect(middleProxySnapshotWanted(&cfg, 203));

    // Everything off: no route can ever use MiddleProxy, so no updater and no
    // snapshot for a regular DC — except CDN 203, which has no direct address.
    cfg.force_media_middle_proxy = false;
    cfg.tag = null;
    try std.testing.expect(!middleProxyUpdaterNeeded(&cfg));
    try std.testing.expect(!middleProxySnapshotWanted(&cfg, 1));
    try std.testing.expect(middleProxySnapshotWanted(&cfg, 203));

    // An ad-tag alone (no use_middle_proxy, no force_media) still needs the
    // updater — the promotion RPC only takes effect over a MiddleProxy handshake.
    cfg.tag = [_]u8{0} ** 16;
    try std.testing.expect(middleProxyUpdaterNeeded(&cfg));
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
    dns_id: usize,
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

    const result = @import("child_process").run(allocator, io_instance.io(), .{
        .argv = argv,
        .expand_arg0 = .expand,
        .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } },
        .stdout_limit = std.Io.Limit.limited(32 * 1024),
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
    if (!std.mem.startsWith(u8, url, "https://")) return null;
    const out = runSmallCommand(allocator, &.{ "curl", "-sSI", "--proto", "=https", "--proto-redir", "=https", "--max-time", "8", "--", url }) orelse return null;
    defer allocator.free(out);
    const http_epoch = http_fetch.parseHttpDate(out) orelse return null;
    return validatedClockOffset(http_epoch, realtimeSeconds());
}

fn validatedClockOffset(http_epoch: i64, local_epoch: i64) ?i64 {
    const off = std.math.sub(i64, http_epoch, local_epoch) catch return null;
    if (off < constants.time_skew_min or off > constants.time_skew_max) {
        log.warn("clock_sync: refusing offset {d}s outside handshake skew window; fix the host clock", .{off});
        return null;
    }
    return off;
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

    return parseTunnelPoolStateValue(allocator, content, key);
}

fn parseTunnelPoolStateValue(allocator: std.mem.Allocator, content: []const u8, key: []const u8) ?[]u8 {
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

test "clock correction and tunnel state parsing are bounded" {
    try std.testing.expectEqual(@as(?i64, 0), validatedClockOffset(1000, 1000));
    try std.testing.expectEqual(@as(?i64, 42), validatedClockOffset(1042, 1000));
    try std.testing.expect(validatedClockOffset(std.math.maxInt(i64), -1) == null);
    try std.testing.expect(validatedClockOffset(100000, 0) == null);
    const value = parseTunnelPoolStateValue(std.testing.allocator, "bad\nactive_old=wrong\n active = awg1 \r\n", "active").?;
    defer std.testing.allocator.free(value);
    try std.testing.expectEqualStrings("awg1", value);
    try std.testing.expect(parseTunnelPoolStateValue(std.testing.allocator, "active=\n", "active") == null);
    try std.testing.expect(parseTunnelPoolStateValue(std.testing.allocator, "other=x\n", "active") == null);
    var state: ProxyState = undefined;
    state.middle_proxy_updater_shutdown = .init(true);
    try std.testing.expect(state.waitForUpdaterDelay(std.time.ns_per_hour));
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
    /// Decided once, at accept, from the address the kernel reported — and never
    /// revisited. It must NOT be recomputed from `peer_addr`, which a PROXY-protocol
    /// header overwrites with an address the client chose: gating on that would let
    /// anyone claim to be loopback and unlock the direct-obfuscated responder.
    ///
    /// True means the peer is the WEB proxy relay (see trusted_peers.zig): it may use
    /// the direct-obfuscated transport under `fake_tls_only`, may announce a real client
    /// address, and is exempt from the per-IP guards that would otherwise see every
    /// relayed user as one address.
    trusted_peer: bool = false,

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
    validation_user: []const u8 = "",
    validation_user_len: usize = 0,

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
    mp_secret: [256]u8 = undefined,
    mp_secret_len: usize = 0,

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
    proxy_candidate_index: u8 = 0,
    mask_candidate_next: u8 = 0,
    resolved_candidates: ?*net_helpers.AddressCandidates = null,
    mask_dns_override: ?usize = null,

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
    /// The [access.user_max_ips] table key this connection holds, when the user has a
    /// quota. Captured at admission and released verbatim on close: peer_addr must NOT
    /// be re-keyed later, or a PROXY-protocol/forwarded-for rewrite would release a
    /// different slot than the one that was taken.
    user_ip_key: ?[16]u8 = null,

    // Non-blocking write queues (slab-like chain buffers)
    client_queue: MessageQueue = .{ .allocator = std.heap.page_allocator },
    upstream_queue: MessageQueue = .{ .allocator = std.heap.page_allocator },

    // Masking: bytes already read from client before deciding to mask
    mask_prebuffer: ?[]u8 = null,
    /// One-shot override for the next startMasking (SNI-following safelist hit, or the
    /// WEB relay's own domain). Consumed (read + cleared) inside startMasking so it never
    /// leaks to a reused slot.
    mask_addr_override: ?Address = null,
    /// Prefix the masked connection with a PROXY-protocol header carrying this client's
    /// address. Set only for the WEB relay's domain, whose terminator expects one — the
    /// masking hop is otherwise a raw pipe and the relay would see 127.0.0.1 for
    /// everybody. One-shot, like mask_addr_override.
    mask_send_proxy_header: bool = false,
    /// Expect a HAProxy PROXY-protocol header before the TLS ClientHello (set at accept
    /// when accept_proxy_protocol is on; cleared once the header is consumed).
    expect_proxy_header: bool = false,
    /// The header is welcome but not required — set for trusted relay peers so an
    /// ordinary local connection (a health probe, a curl) is not rejected just because
    /// the WEB relay is enabled.
    proxy_header_optional: bool = false,
    /// Bytes seen by the last PROXY-header peek. MSG_PEEK consumes nothing, so a peer
    /// that sends a partial header and stops would otherwise keep the socket readable
    /// forever and spin this level-triggered loop; growth is what proves progress.
    proxy_header_peeked: u16 = 0,
    /// Client read interest stays disarmed until this monotonic deadline. Used to back
    /// off a stalled PROXY header instead of re-peeking the same bytes at full speed;
    /// the timer scan re-arms it. 0 = not paused.
    client_read_pause_until_ms: i64 = 0,

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
    mp_frame_first_decrypted: bool = false,

    // Non-blocking proxy handshake state (SOCKS5 / HTTP CONNECT)
    proxy_handshake_buf: ?*[http_connect.max_response_size]u8 = null,
    proxy_handshake_pos: u16 = 0,
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
    client_read_eof: bool = false,
    upstream_read_eof: bool = false,
    client_write_shutdown: bool = false,
    upstream_write_shutdown: bool = false,

    /// Record what we just armed on the client fd in epoll. The cache MUST describe the
    /// live kernel registration: syncInterests only issues an EPOLL_CTL_MOD when the two
    /// differ, so a cache that under-reports (the zeroed slot vs. the EPOLLIN armed at
    /// accept) silently skips the *disarm* — the fd stays level-readable with bytes
    /// nobody consumes in .connecting_upstream and the worker spins at 100% CPU.
    fn noteClientRegistered(self: *ConnectionSlot, want_in: bool, want_out: bool) void {
        self.client_interest_in = want_in;
        self.client_interest_out = want_out;
    }

    /// Same invariant for the upstream fd (see noteClientRegistered).
    fn noteUpstreamRegistered(self: *ConnectionSlot, want_in: bool, want_out: bool) void {
        self.upstream_interest_in = want_in;
        self.upstream_interest_out = want_out;
    }

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

    fn freezeResolvedCandidates(self: *ConnectionSlot, allocator: std.mem.Allocator, candidates: net_helpers.AddressCandidates) !void {
        if (self.resolved_candidates == null) self.resolved_candidates = try allocator.create(net_helpers.AddressCandidates);
        self.resolved_candidates.?.* = candidates;
    }

    fn resetOwnedBuffers(self: *ConnectionSlot, allocator: std.mem.Allocator) void {
        if (self.validation_user.len > 0) allocator.free(self.validation_user);
        self.validation_user = "";
        self.validation_user_len = 0;
        if (self.proxy_handshake_buf) |buf| allocator.destroy(buf);
        self.proxy_handshake_buf = null;
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
        if (self.resolved_candidates) |candidates| allocator.destroy(candidates);
        self.resolved_candidates = null;
        self.mask_dns_override = null;

        if (self.dc_initial_tail) |buf| allocator.free(buf);
        self.dc_initial_tail = null;

        if (self.middle_ctx) |*mp| mp.deinit(allocator);
        self.middle_ctx = null;
        if (self.mp_enc) |*cipher| cipher.wipe();
        if (self.mp_dec) |*cipher| cipher.wipe();
        self.mp_enc = null;
        self.mp_dec = null;
        std.crypto.secureZero(u8, &self.mp_secret);
        self.mp_secret_len = 0;

        if (self.upstream_candidates_heap) |buf| allocator.free(buf);
        self.upstream_candidates_heap = null;
        self.upstream_candidate_count = 0;
        self.upstream_candidate_next = 0;
        self.direct_fallback_addr = null;
        self.direct_fallback_used = false;
        self.current_upstream_addr = null;
        self.proxy_candidate_index = 0;
        self.mask_candidate_next = 0;
        self.dc_abs = 0;
        self.is_media_path = false;
        self.user_metrics = null;
        self.user_ip_key = null;

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

/// The epoll interest pair each fd of a slot should hold in its current phase.
const SlotInterests = struct {
    client_in: bool,
    client_out: bool,
    upstream_in: bool,
    upstream_out: bool,
};

/// Pure half of `syncInterests`: what the slot's phase asks for, independent of what
/// the kernel currently holds. Split out so the cache-vs-wanted comparison — the thing
/// that decides whether an EPOLL_CTL_MOD is issued at all — is unit-testable without
/// an epoll fd.
fn wantedInterests(slot: *const ConnectionSlot, now_ms: i64) SlotInterests {
    var want = SlotInterests{
        .client_in = false,
        .client_out = slot.hasClientPending(),
        .upstream_in = false,
        .upstream_out = slot.hasUpstreamPending(),
    };

    switch (slot.phase) {
        .reading_tls_header,
        .reading_direct_obfuscated_handshake,
        .reading_client_hello_body,
        .reading_mtproto_tls_header,
        .reading_mtproto_tls_body,
        => {
            want.client_in = slot.client_read_pause_until_ms == 0 or
                now_ms >= slot.client_read_pause_until_ms;
        },

        .writing_server_hello_first,
        .writing_server_hello_rest,
        => {
            want.client_out = true;
        },

        .desync_wait => {
            // Wait for timer tick only; keeping EPOLLOUT enabled here can
            // cause a busy loop because writable sockets trigger continuously.
        },

        .connecting_upstream => {
            want.client_in = false;
            want.upstream_out = true;
        },

        .proxy_socks5_greeting,
        .proxy_socks5_auth,
        .proxy_socks5_connect,
        .proxy_http_connect,
        => {
            want.client_in = false;
            want.upstream_out = true;
        },

        .proxy_socks5_greeting_resp,
        .proxy_socks5_auth_resp,
        .proxy_socks5_connect_resp,
        .proxy_http_connect_resp,
        => {
            want.client_in = false;
            want.upstream_in = true;
        },

        .writing_dc_nonce => {
            want.client_in = false;
            want.upstream_out = true;
        },

        .middle_proxy_handshake => {
            want.upstream_out = want.upstream_out or
                slot.mp_step == .sending_rpc_nonce or
                slot.mp_step == .sending_rpc_handshake;
            want.upstream_in = slot.mp_step == .waiting_rpc_nonce_response or
                slot.mp_step == .waiting_rpc_handshake_response;
        },

        .relaying, .mask_relaying => {
            want.client_in = !slot.client_read_eof and !slot.hasUpstreamPending();
            want.upstream_in = !slot.upstream_read_eof and !slot.hasClientPending();
        },

        else => {},
    }

    return want;
}

test "epoll interest cache must be seeded at registration or the disarm is skipped" {
    var slot: ConnectionSlot = .{};
    slot.client_queue.allocator = std.testing.allocator;
    slot.upstream_queue.allocator = std.testing.allocator;
    defer slot.resetOwnedBuffers(std.testing.allocator);

    // What acceptNewConnections registers with the kernel, recorded on the slot.
    slot.client_fd = 3;
    slot.noteClientRegistered(true, false);
    try std.testing.expect(slot.client_interest_in);

    // First client event ends in .connecting_upstream (a non-TLS byte under
    // fake_tls_only → startMasking, or the trusted dd path). That phase wants the
    // client fd disarmed; with an unseeded cache the pair would compare equal to the
    // zeroed (false,false) and syncInterests would skip the EPOLL_CTL_MOD, leaving
    // unread client bytes to spin the level-triggered loop at 100% CPU.
    slot.phase = .connecting_upstream;
    const want = wantedInterests(&slot, 0);
    try std.testing.expect(!want.client_in);
    try std.testing.expect(slot.client_interest_in != want.client_in);

    // The upstream registration is seeded the same way: EPOLLOUT while the connect
    // is in flight, which is exactly what .connecting_upstream wants — no redundant
    // MOD on the first upstream event.
    slot.upstream_fd = 4;
    slot.noteUpstreamRegistered(false, true);
    try std.testing.expect(!want.upstream_in and want.upstream_out);
    try std.testing.expectEqual(slot.upstream_interest_in, want.upstream_in);
    try std.testing.expectEqual(slot.upstream_interest_out, want.upstream_out);
}

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
const EndpointPenalties = @import("endpoint_penalties.zig").EndpointPenalties;
const WorkerHeartbeat = struct {
    value: std.atomic.Value(i64) = .init(0),
    tracked_fds: std.atomic.Value(u32) = .init(0),
    padding: [52]u8 = undefined,
    fn load(self: *const WorkerHeartbeat, comptime order: std.builtin.AtomicOrder) i64 {
        return self.value.load(order);
    }
    fn store(self: *WorkerHeartbeat, value: i64, comptime order: std.builtin.AtomicOrder) void {
        self.value.store(value, order);
    }
};

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
        if (has(reason, "connect timeout") or has(reason, "wedge")) return .upstream_error;
        if (has(reason, "half-close")) return .client_eof;
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

/// Parse a WEB masking `host:port` without resolving DNS.
fn parseHostPort(spec: []const u8) ?struct { host: []const u8, port: u16 } {
    const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return null;
    const host = std.mem.trim(u8, spec[0..colon], "[] ");
    if (host.len == 0) return null;
    const port = std.fmt.parseInt(u16, spec[colon + 1 ..], 10) catch return null;
    if (port == 0) return null;
    return .{ .host = host, .port = port };
}

pub const ProxyState = struct {
    pub const UserMetrics = struct {
        name: []const u8,
        connections_active: std.atomic.Value(u32),
        client_to_upstream_bytes_total: std.atomic.Value(u64),
        upstream_to_client_bytes_total: std.atomic.Value(u64),
        /// [access.user_max_ips] quota, present only for users that configure one.
        /// Lives here because it must survive a SIGHUP that keeps the user (the
        /// entry is matched by name and reused), exactly like connections_active.
        ip_limit: ?UserIpLimit = null,
        /// Connections refused because the user's unique-IP quota was full. Without
        /// this the feature's whole failure mode ("my client stopped connecting") is
        /// invisible: the refusal only reaches a debug log, and a full quota is also
        /// the intended steady state, so the gauge alone cannot tell the two apart.
        ip_limit_refused_total: std.atomic.Value(u64) = .init(0),
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
        web_only_masked_total: u64,
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

    fn createUserMetrics(allocator: std.mem.Allocator, user_name: []const u8, max_ips: ?u32) !*UserMetrics {
        const entry = try allocator.create(UserMetrics);
        errdefer allocator.destroy(entry);

        const name = try allocator.dupe(u8, user_name);
        errdefer allocator.free(name);

        entry.* = .{
            .name = name,
            .connections_active = std.atomic.Value(u32).init(0),
            .client_to_upstream_bytes_total = std.atomic.Value(u64).init(0),
            .upstream_to_client_bytes_total = std.atomic.Value(u64).init(0),
            .ip_limit = if (max_ips) |cap| try UserIpLimit.init(allocator, cap) else null,
            .ip_limit_refused_total = .init(0),
        };
        return entry;
    }

    /// The per-user unique-IP cap for `user_name`, or null when the user has none.
    /// Always read from the STARTUP config: a SIGHUP reload only swaps user secrets
    /// (see moveAccessMapsFrom), so the caps a running process enforces are the ones
    /// it booted with — the same rule user_max_conns and user_expirations follow.
    fn userMaxIps(cfg: *const Config, user_name: []const u8) ?u32 {
        const map = cfg.user_max_ips orelse return null;
        return map.get(user_name);
    }

    fn destroyUserMetrics(allocator: std.mem.Allocator, entry: *UserMetrics) void {
        if (entry.ip_limit) |*limit| limit.deinit(allocator);
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
            const metric = try createUserMetrics(allocator, entry.key_ptr.*, userMaxIps(cfg, entry.key_ptr.*));
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

    /// Reclaim retired entries whose connections have drained. This mutates an
    /// unsynchronised ArrayList from every worker's closeSlot, which is safe ONLY
    /// because reloadConfigFromDisk refuses to reload with workers > 1 — so the list
    /// stays permanently empty in the multi-threaded configuration and retirement is
    /// single-threaded. Anyone relaxing that refusal must lock this list first: it frees
    /// UserMetrics, and with it the user_max_ips table a concurrent release() touches.
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
                    const metrics = try createUserMetrics(self.allocator, user_name, userMaxIps(&self.config, user_name));
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
    metrics_config_mutex: CompatRwLock = .{},
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
    mask_candidates: net_helpers.AddressCandidates = .{},
    dns: *dns_cache.Cache,
    mask_dns_id: ?usize = null,
    web_dns_id: ?usize = null,
    proxy_dns_id: ?usize = null,
    /// Opt-in SNI-following mask targets (config.mask_sni_safelist), resolved at boot.
    mask_safelist: []const MaskSafelistEntry,
    /// Peers allowed to speak the direct-obfuscated transport under `fake_tls_only`
    /// (the WEB proxy relay), resolved from `[web]` at boot.
    trusted: trusted_peers.TrustedPeers,
    /// `[web].only`: serve the relay and nobody else. Resolved once at boot (like the
    /// trusted set it is paired with) — `[web]` is not part of the SIGHUP reload set.
    web_only: bool,
    /// Masking target for connections whose SNI is the WEB relay's domain — a terminator
    /// that accepts a PROXY-protocol header, so the real client address survives the
    /// masking hop. Null keeps the ordinary mask target for them.
    web_mask_addr: ?Address,
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
    /// Connections refused because `[web].only` is on and the peer is not the relay.
    /// These are masked, not dropped, so they are otherwise indistinguishable from a
    /// wrong-secret probe — this counter is the only way to see them.
    stats_web_only_masked: std.atomic.Value(u64),
    /// Per-worker connection pool exhausted while the global cap still had room
    /// (SO_REUSEPORT hashes connections to workers, so one pool can fill first).
    stats_dropped_pool: std.atomic.Value(u64),
    /// Per-reason connection close counters (RED errors + evasion signals).
    close_reasons: [CloseReason.count]std.atomic.Value(u64),
    /// Per-worker monotonic-ms liveness heartbeat (index = worker_id). /healthz and
    /// the watchdog require EVERY active worker to be fresh, so a wedged non-owner
    /// SO_REUSEPORT shard is detected (not masked by worker 0 staying alive). 0 until
    /// a worker starts ticking.
    worker_heartbeats: [max_workers]WorkerHeartbeat,
    accepted_since_log: std.atomic.Value(u64) = .init(0),
    closed_since_log: std.atomic.Value(u64) = .init(0),
    /// Anti-flood + per-subnet rate guards are SHARED across workers (behind
    /// guard_lock) so an IP/subnet spread across SO_REUSEPORT shards is still limited
    /// globally, not ~N×threshold. Touched only on the accept/handshake path.
    subnet_limiter: ?*SubnetRateLimit = null,
    flood_guard: ?*HandshakeFloodGuard = null,
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
    middle_proxy_spawn_retry_ms: i64 = 0,
    upstream: upstream_mod.Upstream,
    tunnel_info: tunnel_mod.Tunnel,

    pub fn init(allocator: std.mem.Allocator, cfg: Config, config_path: []const u8) !ProxyState {
        if (cfg.users.count() == 0) return error.NoUsersConfigured;
        const dns = try dns_cache.Cache.create(allocator);
        errdefer dns.destroy();
        var mask_dns_id: ?usize = null;
        var web_dns_id: ?usize = null;
        var proxy_dns_id: ?usize = null;

        const user_secrets = try buildUserSecrets(allocator, &cfg);
        errdefer allocator.free(user_secrets);

        const user_metrics_owned = try buildInitialUserMetrics(allocator, &cfg);
        errdefer freeUserMetricsSlice(allocator, user_metrics_owned);

        var resolved_addr: ?Address = null;
        var mask_candidates: net_helpers.AddressCandidates = .{};
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
                    mask_candidates = .init(al.addrs);
                    log.info("Mask target '{s}:{d}': retained {d} DNS addresses", .{ mask_target, cfg.mask_port, mask_candidates.len });
                }
            }
            mask_dns_id = try dns.add(mask_target, cfg.mask_port, mask_candidates);
        }

        // Resolve the opt-in SNI-following mask safelist (each domain → its own server,
        // port 443). Failed resolutions stay registered for background recovery.
        var mask_safelist_buf: std.ArrayListUnmanaged(MaskSafelistEntry) = .empty;
        errdefer mask_safelist_buf.deinit(allocator);
        if (cfg.mask and cfg.mask_sni_safelist.len > 0) {
            for (cfg.mask_sni_safelist) |domain| {
                const sl = getAddressList(allocator, domain, 443) catch blk: {
                    log.warn("mask_sni_safelist: could not resolve '{s}', retrying in background", .{domain});
                    break :blk null;
                };
                defer if (sl) |list| list.deinit();
                const candidates: net_helpers.AddressCandidates = if (sl) |list| .init(list.addrs) else .{};
                const id = try dns.add(domain, 443, candidates);
                try mask_safelist_buf.append(allocator, .{ .domain = domain, .addr = if (candidates.len > 0) candidates.addresses[0] else ip4(.{ 0, 0, 0, 0 }, 443), .dns_id = id });
                log.info("mask_sni_safelist: fronting '{s}' enabled", .{domain});
            }
        }
        const mask_safelist = try mask_safelist_buf.toOwnedSlice(allocator);
        errdefer allocator.free(mask_safelist);

        // Peers allowed to bypass `fake_tls_only` with the direct-obfuscated transport.
        // Loopback is implied by [web].enabled; anything else must be named explicitly.
        const relay_extra = trusted_peers.parseSources(allocator, cfg.web.relay_sources, struct {
            fn warn(text: []const u8) void {
                log.warn("[web].relay_sources: '{s}' is not an IP literal, ignoring", .{text});
            }
        }.warn) catch &.{};
        errdefer allocator.free(relay_extra);
        // Masking target for the relay's own domain. Resolved here so the hot path only
        // compares an SNI string.
        var web_mask_addr: ?Address = null;
        if (cfg.web.enabled and cfg.web.domain != null) {
            if (cfg.web.mask_backend) |spec| {
                if (parseHostPort(spec)) |target| {
                    const addresses = getAddressList(allocator, target.host, target.port) catch null;
                    defer if (addresses) |list| list.deinit();
                    const candidates: net_helpers.AddressCandidates = if (addresses) |list| .init(list.addrs) else .{};
                    if (candidates.len > 0) {
                        const addr = candidates.addresses[0];
                        if (trusted_peers.isLoopback(addr) and addr.getPort() == cfg.port) return error.MaskBackendLoopsToProxy;
                    }
                    // The marker is never used for a connection: startMasking consumes
                    // the cache snapshot, rejecting an empty snapshot until DNS recovers.
                    web_mask_addr = if (candidates.len > 0) candidates.addresses[0] else ip4(.{ 0, 0, 0, 0 }, target.port);
                    web_dns_id = try dns.add(target.host, target.port, candidates);
                    log.info("[web] masked connections for '{s}' are fronted with a PROXY header", .{cfg.web.domain.?});
                } else {
                    log.warn("[web].mask_backend '{s}' is not a usable host:port; ignoring", .{spec});
                }
            }
        }
        const trusted = trusted_peers.TrustedPeers{ .enabled = cfg.web.enabled, .extra = relay_extra };
        if (trusted.enabled) {
            log.info("web relay trust: loopback + {d} explicit source(s) may use the direct-obfuscated transport", .{relay_extra.len});
        }
        if (cfg.web.onlyActive()) {
            log.info("[web].only: direct MTProto is masked for everyone but the relay — only tg://webproxy links work", .{});
        }

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
            2400 + crypto.randomRange(usize, 1201)
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

        var result: ProxyState = .{
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
            .dns = dns,
            .mask_dns_id = mask_dns_id,
            .web_dns_id = web_dns_id,
            .mask_candidates = mask_candidates,
            .mask_safelist = mask_safelist,
            .trusted = trusted,
            .web_only = cfg.web.onlyActive(),
            .web_mask_addr = web_mask_addr,
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
            .stats_web_only_masked = std.atomic.Value(u64).init(0),
            .middle_proxy_addrs_primary = constants.tg_middle_proxies_v4,
            .middle_proxy_addrs_media_primary = constants.tg_media_middle_proxies_v4,
            .middle_proxy_addr_203 = constants.getDcAddressV4(203).?,
            .middle_proxy_addrs_dc4 = [_]Address{constants.tg_middle_proxies_v4[3]} ++ ([_]Address{constants.tg_middle_proxies_v4[3]} ** 15),
            .middle_proxy_addrs_dc4_len = 1,
            .middle_proxy_addrs_media_dc4 = [_]Address{constants.tg_media_middle_proxies_v4[3]} ++ ([_]Address{constants.tg_media_middle_proxies_v4[3]} ** 15),
            .middle_proxy_addrs_media_dc4_len = 1,
            .middle_proxy_addrs_203 = [_]Address{constants.getDcAddressV4(203).?} ++ ([_]Address{constants.getDcAddressV4(203).?} ** 7),
            .middle_proxy_addrs_203_len = 1,
            .middle_proxy_secret = default_middle_proxy_secret,
            .middle_proxy_secret_len = middleproxy.proxy_secret.len,
            .middle_proxy_nat_ip4 = detected_nat_ip4,
            .middle_proxy_updater_shutdown = std.atomic.Value(bool).init(false),
            .middle_proxy_refresh_requested = std.atomic.Value(bool).init(false),
            .worker_heartbeats = [_]WorkerHeartbeat{.{}} ** max_workers,
            .subnet_limiter = null,
            .flood_guard = null,
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
                                    proxy_dns_id = try dns.add(host, cfg.upstream_proxy_port, .init(proxy_list.addrs));
                                    break :upblk upstream_mod.Upstream.initSocks5Candidates(
                                        proxy_list.addrs,
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
                                    proxy_dns_id = try dns.add(host, cfg.upstream_proxy_port, .init(proxy_list.addrs));
                                    break :upblk upstream_mod.Upstream.initHttpConnectCandidates(
                                        proxy_list.addrs,
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
        result.proxy_dns_id = proxy_dns_id;
        return result;
    }

    pub fn deinit(self: *ProxyState) void {
        self.dns.destroy();
        self.middle_proxy_updater_shutdown.store(true, .release);
        if (self.middle_proxy_updater_thread) |thread| {
            thread.join();
            self.middle_proxy_updater_thread = null;
        }
        if (self.flood_guard) |guard| guard.destroy(self.allocator);
        if (self.subnet_limiter) |limiter| self.allocator.destroy(limiter);
        self.allocator.free(self.mask_safelist);
        if (self.trusted.extra.len > 0) self.allocator.free(self.trusted.extra);
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
        if (!cfg.enabled) return false;
        self.guard_lock.lock();
        defer self.guard_lock.unlock();
        const guard = self.flood_guard orelse return false;
        return guard.isBlocked(addr, cfg);
    }

    fn floodRecord(self: *ProxyState, addr: Address, event: HandshakeFloodGuard.Event, cfg: HandshakeFloodGuard.Settings) bool {
        if (!cfg.enabled) return false;
        self.guard_lock.lock();
        defer self.guard_lock.unlock();
        if (self.flood_guard == null) self.flood_guard = HandshakeFloodGuard.create(self.allocator) catch return true;
        return self.flood_guard.?.record(addr, event, cfg);
    }

    fn floodTop(self: *ProxyState, cfg: HandshakeFloodGuard.Settings, out: []HandshakeFloodGuard.TopEntry) usize {
        if (!cfg.enabled) return 0;
        self.guard_lock.lock();
        defer self.guard_lock.unlock();
        const guard = self.flood_guard orelse return 0;
        return guard.top(cfg, out);
    }

    fn subnetCheck(self: *ProxyState, addr: Address, max_per_sec: u8) bool {
        if (max_per_sec == 0) return true;
        self.guard_lock.lock();
        defer self.guard_lock.unlock();
        if (self.subnet_limiter == null) {
            const limiter = self.allocator.create(SubnetRateLimit) catch return false;
            limiter.* = SubnetRateLimit.init();
            self.subnet_limiter = limiter;
        }
        return self.subnet_limiter.?.check(addr, max_per_sec);
    }

    pub fn getMetricsSnapshot(self: *const ProxyState) MetricsSnapshot {
        const config_mutex = @constCast(&self.metrics_config_mutex);
        config_mutex.lock();
        defer config_mutex.unlock();
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
            .web_only_masked_total = self.stats_web_only_masked.load(.monotonic),
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
        log.info("Effective egress: {s}", .{self.tunnel_info.name()});
        if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
        const io_ctx = std.Io.Threaded.global_single_threaded.io();
        var signal_controller = try SignalController.init();
        defer signal_controller.deinit();
        // Resolver inherits the blocked service-signal mask like all workers.
        try self.dns.start();

        // Resolve the worker count: 1 = classic single loop (default, unchanged),
        // 0 = auto (one per CPU), clamped to [1, max_workers]. Published on the
        // shared state so SIGHUP reload can refuse a racy live-reload under >1.
        var worker_count: usize = self.config.workers;
        if (worker_count == 0) worker_count = std.Thread.getCpuCount() catch 1;
        worker_count = std.math.clamp(worker_count, 1, max_workers);
        self.effective_workers = worker_count;

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
            listen_addr = parsed;
            server = try net_helpers.listen(parsed, @intCast(self.config.backlog), worker_count > 1);
            var listen_buf: [64]u8 = undefined;
            log.info("Listening on {s} (epoll)", .{formatAddress(parsed, &listen_buf)});
        } else {
            // Default: try [::] (dual-stack), fall back to 0.0.0.0
            const address = ip6(
                .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                self.config.port,
                0,
                0,
            );
            listen_addr = address;
            server = net_helpers.listen(address, @intCast(self.config.backlog), worker_count > 1) catch |err| blk: {
                if (err == error.AddressFamilyUnsupported) {
                    ipv6_ok = false;
                    log.warn("IPv6 not available, falling back to IPv4 (0.0.0.0)", .{});
                    const address_v4 = ip4(.{ 0, 0, 0, 0 }, self.config.port);
                    listen_addr = address_v4;
                    break :blk try net_helpers.listen(address_v4, @intCast(self.config.backlog), worker_count > 1);
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
        log.warn("Telegram DC routes require IPv4 egress; IPv6-only hosts need a configured SOCKS/HTTP or tunnel egress that reaches IPv4", .{});

        setNonBlocking(server.socket.handle);

        // Any of these three can route a connection through MiddleProxy (same
        // predicate as the NAT-IP warning above): use_middle_proxy for regular
        // traffic, force_media_middle_proxy (default true) for media/CDN even
        // with use_middle_proxy=false, and tag for the ad-tag RPC that only
        // takes effect over a middleproxy handshake. Gating the updater on
        // use_middle_proxy alone left DC203's snapshot (always consulted for
        // CDN media, see buildDcConnectPlan's dc_abs==203 case) frozen on the
        // bundled constants for the life of the process under the shipped
        // defaults, since Telegram rotates MP addresses within hours.
        if (middleProxyUpdaterNeeded(&self.config) and self.config.datacenter_override == null) {
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
                self.middle_proxy_spawn_retry_ms = nowMs() + 10_000;
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
        checkNofileLimit(effective_needed_fds, self.config.max_connections);

        const metrics: ?@import("../monitoring.zig").Handle = if (self.config.metrics.enabled)
            @import("../monitoring.zig").start(self) catch |err| blk: {
                log.warn("metrics endpoint unavailable: {any}", .{err});
                break :blk null;
            }
        else
            null;
        defer if (metrics) |handle| handle.stop();

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
            const extra = net_helpers.listen(listen_addr, @intCast(self.config.backlog), worker_count > 1) catch |err| {
                log.err("worker {d} listener failed: {any}", .{ i, err });
                self.shutting_down.store(true, .release);
                return err;
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
                self.shutting_down.store(true, .release);
                return err;
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
        };
    }

    /// Refresh helper. When the config selects a configured egress (tunnel,
    /// socks5, http), tries THAT route first — a host that chose non-direct
    /// egress chose it to keep this exact traffic (fetching Telegram MP
    /// metadata) off the local uplink, so trying direct first would emit the
    /// SYNs the operator configured egress specifically to avoid, and on a
    /// SYN-blackholing network could block the updater for the full kernel
    /// connect timeout before ever trying the configured route. Falls back to
    /// direct only when `allow_direct_fallback` allows it (fail-closed
    /// otherwise, matching the socks5/http_connect branch below).
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
                if (self.fetchMiddleProxyAssetViaTunnelPool(allocator, url, error.TunnelRouteUnavailable)) |bytes| {
                    return bytes;
                } else |tunnel_err| {
                    if (!self.config.allow_direct_fallback) return tunnel_err;
                    log.warn("Middle-proxy asset {s} unavailable through the tunnel ({s}); trying direct fallback", .{
                        url,
                        @errorName(tunnel_err),
                    });
                    return fetchUrlBytes(allocator, url) catch tunnel_err;
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

        if (self.middle_proxy_updater_shutdown.load(.acquire)) return error.ShuttingDown;
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
            if (self.middle_proxy_updater_shutdown.load(.acquire)) return error.ShuttingDown;
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
        // loop before falling back to the normal hourly cadence. This gets
        // media MP addresses into the cache within the first few minutes of
        // uptime instead of the next hour, all without delaying startup.
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

    fn selectReachableUntilShutdown(self: *ProxyState, candidates: []const Address, timeout: i32) ?Address {
        for (candidates) |candidate| {
            if (self.middle_proxy_updater_shutdown.load(.acquire)) return null;
            if (trySelectReachableMiddleProxy(&.{candidate}, timeout)) |addr| return addr;
        }
        return null;
    }

    fn refreshMiddleProxyInfo(self: *ProxyState) !void {
        if (self.middle_proxy_updater_shutdown.load(.acquire)) return error.ShuttingDown;
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const temp_alloc = arena.allocator();

        // Fetch config + secret. When the proxy runs inside a censored network
        // (e.g. RU), core.telegram.org is unreachable over the default route;
        // we transparently retry through the configured tunnel interface so
        // the runtime MP cache (including media endpoints) stays up to date.
        const cfg_bytes = self.fetchMiddleProxyAsset(temp_alloc, middle_proxy_config_url) catch |err| return err;
        if (self.middle_proxy_updater_shutdown.load(.acquire)) return error.ShuttingDown;
        const next_secret = self.fetchMiddleProxyAsset(temp_alloc, middle_proxy_secret_url) catch |err| return err;

        try self.mergeMiddleProxyAssets(cfg_bytes, next_secret, middleProxyProbeAllowed(&self.config));
    }

    /// Apply one fetched snapshot atomically. Kept separate from network fetches
    /// so partial config responses and secret rotation can be tested directly.
    fn mergeMiddleProxyAssets(self: *ProxyState, cfg_bytes: []const u8, next_secret: []const u8, probe_reachability: bool) !void {
        // Reject the entire snapshot before probing or mutating cached routes.
        if (next_secret.len < 16 or next_secret.len > self.middle_proxy_secret.len) {
            return error.BadMiddleProxySecret;
        }

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
            else if (i == 3 or !probe_reachability)
                candidates[0]
            else if (self.selectReachableUntilShutdown(candidates[0..count], 1200)) |reachable|
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
            else if (i == 3 or !probe_reachability)
                media_candidates[0]
            else if (self.selectReachableUntilShutdown(media_candidates[0..media_count], 1200)) |reachable|
                reachable
            else
                media_candidates[0];
        }

        var candidates_203: [8]Address = undefined;
        var count_203 = parseMiddleProxyAddressesForDc(cfg_bytes, 203, .negative_only, &candidates_203);
        if (count_203 == 0) count_203 = parseMiddleProxyAddressesForDc(cfg_bytes, 203, .positive_only, &candidates_203);
        var next_203_candidates: [8]Address = undefined;
        var next_203_candidates_len: usize = 0;
        if (count_203 > 0) {
            const c203_n = @min(count_203, next_203_candidates.len);
            @memcpy(next_203_candidates[0..c203_n], candidates_203[0..c203_n]);
            next_203_candidates_len = c203_n;
        }
        const next_addr_203 = if (count_203 == 0) null else candidates_203[0];

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
    traffic_c2s_pending: std.atomic.Value(u64) = .init(0),
    traffic_s2c_pending: std.atomic.Value(u64) = .init(0),
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
    server_hello_scratch: [65535 + 2048]u8 = undefined,
    desync_wait_slots: std.ArrayListUnmanaged(u32),
    desync_next_ns: i128 = 0,
    endpoint_penalties: EndpointPenalties = .{},
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
        defer self.flushTrafficCounters();
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
        defer self.flushTrafficCounters();
        var events: [256]linux.epoll_event = undefined;
        const timer_tick_ns: i128 = 5 * std.time.ns_per_ms;
        var next_timer_tick_ns: i128 = nowNs();

        while (true) {
            // Close fds whose slots were torn down in the previous batch (and by timers /
            // desync processing). Doing it here — before this iteration's accept()/connect()
            // calls — guarantees a freed fd number is never recycled within the batch that
            // still has queued events for it. See pending_close_fds.
            self.drainPendingCloses();
            self.flushTrafficCounters();

            // Per-worker liveness heartbeat (this worker's slot), and pet the
            // systemd watchdog at half the configured interval — ONLY from the
            // signal owner AND only while EVERY worker is alive, so a wedged
            // non-owner shard stops the watchdog and triggers a restart.
            const tick_ms = nowMs();
            self.state.worker_heartbeats[@min(self.worker_id, max_workers - 1)].store(tick_ms, .monotonic);
            if (self.worker_id == 0 and !self.shutting_down and self.state.middle_proxy_updater_thread == null and self.state.middle_proxy_spawn_retry_ms != 0 and tick_ms >= self.state.middle_proxy_spawn_retry_ms) {
                self.state.middle_proxy_spawn_retry_ms = tick_ms + 10_000;
                if (std.Thread.spawn(.{}, ProxyState.middleProxyUpdaterMain, .{self.state})) |thread| {
                    self.state.middle_proxy_updater_thread = thread;
                    self.state.middle_proxy_spawn_retry_ms = 0;
                } else |err| log.warn("Middle-proxy updater spawn retry failed: {any}", .{err});
            }
            self.state.worker_heartbeats[@min(self.worker_id, max_workers - 1)].tracked_fds.store(@intCast(self.pool.fd_to_slot.count()), .monotonic);
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
            if ((events & (linux.EPOLL.IN | linux.EPOLL.RDHUP | linux.EPOLL.HUP)) != 0 and !slot.client_read_eof) {
                self.onClientReadable(slot);
            }
        } else if (fd == slot.upstream_fd) {
            if ((events & linux.EPOLL.OUT) != 0 or (slot.phase == .connecting_upstream and fatal_hangup)) {
                self.onUpstreamWritable(slot);
            }
            if (slot.phase == .idle) return;
            if ((events & (linux.EPOLL.IN | linux.EPOLL.RDHUP | linux.EPOLL.HUP)) != 0 and !slot.upstream_read_eof) {
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
            const graceful = (events & linux.EPOLL.ERR) == 0;
            const relaying = slot.phase == .relaying or slot.phase == .mask_relaying;
            const masking_connect = slot.phase == .connecting_upstream and slot.upstream_kind == .mask and fd == slot.client_fd;
            if (!graceful or (!relaying and !masking_connect)) {
                self.closeSlot(slot, "epoll hup/err");
                return;
            }
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
        var active_now = self.state.active_connections.load(.monotonic);
        const max = self.state.config.max_connections;
        if (active_now >= (max * 8) / 10) {
            // Reclaim silent unauthenticated sockets before pausing the listener.
            // Existing authenticated users must not compete with idle probes.
            for (self.pool.slots[0..self.pool.allocated_hi]) |candidate| {
                const slot = candidate orelse continue;
                if (slot.phase != .idle and slot.handshakeInProgress() and slot.first_byte_at_ms == 0) {
                    self.closeSlot(slot, "silent connection capacity eviction");
                    active_now = self.state.active_connections.load(.monotonic);
                    if (active_now < (max * 8) / 10) break;
                }
            }
        }
        if (active_now >= (max * 9) / 10) {
            // No connection is dropped here — the backlog is retained and served after the
            // 80% resume. Count only the transition INTO pause so the counter measures
            // saturation-pause events rather than every accept attempt while paused.
            if (!self.saturation_paused) {
                if (self.pauseSaturation()) _ = self.state.stats_dropped_saturation.fetchAdd(1, .monotonic);
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
            // The WEB relay multiplexes every one of its users onto one source address,
            // so the per-IP guards below would rate the relay rather than its clients —
            // one flaky user would block all of them. The real client address arrives in
            // the relay's PROXY header and is judged by the per-handshake machinery.
            const relay_peer = self.state.trusted.contains(client_addr);
            const flood_cfg = floodGuardSettings(&self.state.config);
            if (!proxy_proto and !relay_peer and self.state.floodIsBlocked(client_addr, flood_cfg)) {
                _ = self.state.stats_dropped_flood_guard.fetchAdd(1, .monotonic);
                closeFd(cfd);
                continue;
            }

            // Ensure desync byte-splitting is not coalesced by Nagle during early handshake.
            setTcpNoDelay(cfd);

            // Per-/24 subnet rate limit (before we allocate any slot)
            if (!proxy_proto and !relay_peer and !self.state.subnetCheck(client_addr, self.state.config.rate_limit_per_subnet)) {
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
            slot.client_queue.allocator = self.state.allocator;
            slot.upstream_queue.allocator = self.state.allocator;
            slot.hs_counted = false;
            slot.traffic_client_to_upstream_counter = &self.traffic_c2s_pending;
            slot.traffic_upstream_to_client_counter = &self.traffic_s2c_pending;
            slot.user_metrics = null;
            slot.user_ip_key = null;
            slot.conn_id = self.state.connection_count.fetchAdd(1, .monotonic);
            slot.client_fd = cfd;
            slot.peer_addr = client_addr;
            slot.trusted_peer = relay_peer;
            slot.expect_proxy_header = proxy_proto or relay_peer;
            slot.proxy_header_optional = relay_peer and !proxy_proto;
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

            if (self.addClientFd(slot, cfd, true, false)) |_| {
                self.pool.mapFd(cfd, slot.index) catch {
                    self.closeSlot(slot, "fd map failed");
                    continue;
                };
                _ = self.state.accepted_since_log.fetchAdd(1, .monotonic);
            } else |_| {
                self.closeSlot(slot, "epoll add client failed");
                continue;
            }
        }
    }

    fn logPeriodicStats(self: *EventLoop, now_ns: i128) void {
        if (self.worker_id != 0) return;
        var tracked_fds: u64 = 0;
        for (&self.state.worker_heartbeats) |*heartbeat| tracked_fds += heartbeat.tracked_fds.load(.monotonic);
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
            self.state.accepted_since_log.swap(0, .monotonic),
            self.state.closed_since_log.swap(0, .monotonic),
            tracked_fds,
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
            log.warn("middle-proxy degraded: {d} middle-proxy handshake(s) fell back to direct this interval — those connections lose middle-proxy media routing (direct promo tags remain). Check egress reachability and [server].middle_proxy_nat_ip.", .{d_mpf});
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

        while (self.stats_next_log_ns <= now_ns) {
            self.stats_next_log_ns += stats_log_interval_ns;
        }
    }

    fn flushTrafficCounters(self: *EventLoop) void {
        const c2s = self.traffic_c2s_pending.swap(0, .monotonic);
        const s2c = self.traffic_s2c_pending.swap(0, .monotonic);
        if (c2s != 0) _ = self.state.client_to_upstream_bytes_total.fetchAdd(c2s, .monotonic);
        if (s2c != 0) _ = self.state.upstream_to_client_bytes_total.fetchAdd(s2c, .monotonic);
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

    fn pauseSaturation(self: *EventLoop) bool {
        if (self.saturation_paused) return true;

        self.modFd(self.listen_fd, false, false) catch |mod_err| {
            log.err("failed to pause accepts for saturation: {any}", .{mod_err});
            self.state.shutting_down.store(true, .release);
            return false;
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
        return true;
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
        @setEvalBranchQuota(100000);
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
        self.state.metrics_config_mutex.lock();
        defer self.state.metrics_config_mutex.unlock();

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
                "SIGHUP: access users reloaded users={d} direct_users={d} retired_metrics={d} " ++
                    "(per-user max_conns / expirations / max_ips are NOT reloaded — restart to change them)",
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
        // `[web]` is resolved once at boot — the trusted-peer set, the mask backend and
        // the WEB-only gate all with it. Count a change so SIGHUP says "restart
        // required" instead of leaving the operator to believe it took effect.
        if (next.web.onlyActive() != self.state.web_only) static_changes += 1;
        if (next.web.enabled != self.state.config.web.enabled) static_changes += 1;
        if (next.allow_direct_fallback != self.state.config.allow_direct_fallback) static_changes += 1;
        // Every non-hot field, including nested sections and per-user limits,
        // must report restart-required. New configuration fields are covered too.
        inline for (std.meta.fields(Config)) |field| {
            if (comptime !isHotConfigField(field.name)) {
                if (!configValueEqual(field.type, @field(next, field.name), @field(self.state.config, field.name))) {
                    static_changes += 1;
                    log.warn("SIGHUP: {s} changed; restart required", .{field.name});
                }
            }
        }

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
            runtime_log.level.store(next.log_level, .monotonic);
            applied += 1;
        }
        const tls_domain_changed = !std.mem.eql(u8, next.tls_domain, self.state.config.tls_domain);
        const mask_target_changed = !optionalStringEql(next.mask_target, self.state.config.mask_target);
        if (tls_domain_changed) {
            static_changes += 1;
            log.err("SIGHUP: tls_domain change requires restart and redistribution of every ee link; keeping current domain", .{});
        }
        if (!tls_domain_changed and (next.mask != self.state.config.mask or next.mask_port != self.state.config.mask_port or mask_target_changed)) {
            const same_host = std.mem.eql(u8, next.effectiveMaskTarget(), self.state.config.effectiveMaskTarget());
            if (!same_host or (next.mask and self.state.mask_addr == null)) {
                static_changes += 1;
                log.warn("SIGHUP: mask target change requires restart; DNS is never resolved on the event loop", .{});
            } else {
                if (self.state.mask_addr) |*addr| addr.setPort(next.mask_port);
                for (self.state.mask_candidates.addresses[0..self.state.mask_candidates.len]) |*addr| addr.setPort(next.mask_port);
                self.state.config.mask = next.mask;
                self.state.config.mask_port = next.mask_port;
                applied += 1;
            }
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
        self.finishRelayHalfClose(slot);
        if (slot.phase == .idle) return;

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
                self.finishRelayHalfClose(slot);
                if (slot.phase == .idle) return;

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
        if (self.desync_next_ns == 0 or slot.desync_deadline_ns < self.desync_next_ns) self.desync_next_ns = slot.desync_deadline_ns;
        slot.desync_wait_enqueued = true;
    }

    fn processDesyncWaits(self: *EventLoop) void {
        if (self.desync_wait_slots.items.len == 0) return;

        const now_ns = nowNs();
        if (now_ns < self.desync_next_ns) return;
        self.desync_next_ns = 0;
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
                if (self.desync_next_ns == 0 or slot.desync_deadline_ns < self.desync_next_ns) self.desync_next_ns = slot.desync_deadline_ns;
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

    /// How long client reads stay disarmed after a PROXY-header peek made no progress.
    const proxy_header_stall_backoff_ms: i64 = 25;

    const ProxyHeaderStep = enum { done, wait, closed };

    /// MSG_PEEK the connection's first bytes, parse a HAProxy PROXY-protocol header, and
    /// drain exactly its bytes (leaving the TLS ClientHello untouched in the socket buffer)
    /// so peer_addr reflects the real client behind a load balancer.
    fn tryConsumeProxyHeader(self: *EventLoop, slot: *ConnectionSlot) ProxyHeaderStep {
        var peek: [4096]u8 = undefined;
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
        // A peeked byte is still a first byte: without this the handshake clock never
        // starts and a stalled header would sit for the whole idle timeout.
        if (slot.first_byte_at_ms == 0 and n > 0) slot.first_byte_at_ms = nowMs();
        switch (proxy_protocol.parse(peek[0..n])) {
            .incomplete => {
                if (n >= peek.len) {
                    self.closeSlot(slot, "proxy header too long");
                    return .closed;
                }
                const seen: u16 = @intCast(@min(n, std.math.maxInt(u16)));
                if (seen <= slot.proxy_header_peeked) {
                    // No progress since the last look. MSG_PEEK leaves the bytes in the
                    // socket, so the fd stays readable and re-peeking at loop speed would
                    // pin a core until the handshake timeout. Back off and let the timer
                    // scan re-arm the read interest.
                    slot.client_read_pause_until_ms = nowMs() + proxy_header_stall_backoff_ms;
                } else {
                    slot.proxy_header_peeked = seen;
                    slot.client_read_pause_until_ms = 0;
                }
                return .wait;
            },
            .invalid => {
                // A trusted relay peer is *allowed* to prefix a PROXY header, not
                // required to: an ordinary local connection (health probe, curl) must
                // still work once the WEB relay is enabled. Fall through to the normal
                // path with the observed address intact.
                if (slot.proxy_header_optional) {
                    slot.expect_proxy_header = false;
                    slot.proxy_header_optional = false;
                    slot.proxy_header_peeked = 0;
                    slot.client_read_pause_until_ms = 0;
                    return .done;
                }
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
                if (res.src) |real| {
                    slot.peer_addr = real;
                    if (!slot.trusted_peer or !trusted_peers.isLoopback(real)) {
                        const flood_cfg = floodGuardSettings(&self.state.config);
                        if (self.state.floodIsBlocked(real, flood_cfg)) {
                            _ = self.state.stats_dropped_flood_guard.fetchAdd(1, .monotonic);
                            self.closeSlot(slot, "proxy client flood blocked");
                            return .closed;
                        }
                        if (!self.state.subnetCheck(real, self.state.config.rate_limit_per_subnet)) {
                            _ = self.state.stats_dropped_rate_limit.fetchAdd(1, .monotonic);
                            _ = self.state.floodRecord(real, .rate_limit, flood_cfg);
                            self.closeSlot(slot, "proxy client rate limited");
                            return .closed;
                        }
                    }
                }
                slot.expect_proxy_header = false;
                slot.proxy_header_optional = false;
                slot.proxy_header_peeked = 0;
                slot.client_read_pause_until_ms = 0;
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
            if (slot.first_byte_at_ms == 0) slot.first_byte_at_ms = nowMs();
            // First byte arrived → the connection is now actually handshaking.
            // Charge it against the handshake-inflight budget here (not at accept)
            // so pre-first-byte silent sessions never occupied a budget slot. Covers
            // both FakeTLS and the dd path, which is entered from this function after
            // the TLS sniff. Keyed on hs_counted, NOT on first_byte_at_ms: the
            // PROXY-protocol peek already stamps the first byte, and a connection that
            // arrived behind such a header must still pay for its handshake.
            if (!slot.hs_counted) {
                if (!self.reserveHandshakeBudget(slot)) {
                    // Feed the flood guard so a client that repeatedly burns the budget
                    // accrues a score (and the per-IP handshake_budget column is no longer
                    // dead telemetry). This is a client-driven, first-byte event.
                    if (!slot.trusted_peer or !trusted_peers.isLoopback(slot.peer_addr)) {
                        _ = self.state.floodRecord(slot.peer_addr, .handshake_budget, floodGuardSettings(&self.state.config));
                    }
                    self.closeSlot(slot, "handshake budget exhausted");
                    return;
                }
            }
            slot.tls_hdr_pos += @intCast(n);
            slot.last_activity_ms = nowMs();
        }

        if (!tls.isTlsHandshake(slot.tls_hdr_buf[0..])) {
            // The WEB proxy relay carries the client's own MTProxy stream verbatim, and
            // Telegram Desktop refuses `ee` (FakeTLS) secrets for WEB proxies — so a
            // relayed connection is always direct-obfuscated. Trust is judged on the
            // accepted address, which no PROXY header can rewrite.
            if (masksInsteadOfServing(.{
                .web_only = self.state.web_only,
                .fake_tls_only = self.state.config.fake_tls_only,
                .transport_is_tls = false,
                .trusted_peer = slot.trusted_peer,
            })) {
                // Strict FakeTLS-only: never accept the non-TLS "direct
                // obfuscated" (dd) transport. Mask the bytes immediately so a
                // non-TLS active probe gets the masking cover (matching the old
                // behavior) instead of being read up to 64 bytes — no dd
                // transport and no dd active-probe distinguisher.
                // Counted only where WEB-only is what made the difference. With
                // fake_tls_only on — the default — this dd connection would have been
                // masked anyway, and attributing it to the new gate would overstate it.
                if (self.state.web_only and !self.state.config.fake_tls_only) {
                    _ = self.state.stats_web_only_masked.fetchAdd(1, .monotonic);
                }
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
                slot.client_read_eof = true;
                slot.relay_half_closed = true;
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

        if (!slot.trusted_peer) {
            const digest = crypto.sha256(slot.handshake_buf[8..56]);
            if (self.state.replay_cache.checkAndInsert(&digest)) {
                self.startMasking(slot, &slot.handshake_buf) catch self.closeSlot(slot, "dd replay masking failed");
                return;
            }
        }

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

        // `[web].only`: the SNI is ours and the secret may well be valid, but this peer
        // is not the relay — so we answer the way we answer a wrong secret, by masking
        // the ClientHello. Byte-identical to the path twenty lines below, deliberately:
        // a WEB-only proxy must not become distinguishable from an ordinary one.
        //
        // It has to sit HERE rather than in readTlsHeader. In `--mode mask` the browser
        // that fetches the bridge arrives on this same :443 with the relay's domain as
        // its SNI, and reaches the relay only through handleInvalidSni's web_mask_addr
        // branch — a gate before SNI extraction would take the WEB proxy down with it.
        if (masksInsteadOfServing(.{
            .web_only = self.state.web_only,
            .fake_tls_only = self.state.config.fake_tls_only,
            .transport_is_tls = true,
            .trusted_peer = slot.trusted_peer,
        })) {
            _ = self.state.stats_web_only_masked.fetchAdd(1, .monotonic);
            self.startMasking(slot, client_hello) catch {
                self.closeSlot(slot, "web-only, masking failed");
            };
            return;
        }

        const validation = tls.validateTlsHandshake(
            client_hello,
            self.state.user_secrets,
            false,
            self.state.clock_offset_seconds,
        ) catch |err| blk: {
            if (err == error.ClockSkew) log.warn("valid FakeTLS authentication rejected for clock skew; check host time synchronization", .{});
            break :blk null;
        };

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
        slot.validation_user = self.state.allocator.dupe(u8, v.user) catch {
            self.closeSlot(slot, "username allocation failed");
            return;
        };
        slot.validation_user_len = v.user.len;

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
        if (!offers_pq and !tls.clientOffersX25519KeyShare(client_hello_bytes)) {
            self.startMasking(slot, client_hello_bytes) catch self.closeSlot(slot, "unsupported TLS key share");
            return;
        }
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
        if (!self.state.config.desync) {
            const response = (if (offers_pq)
                tls.buildServerHelloPqInto(&self.server_hello_scratch, &slot.validation_secret, &slot.validation_digest, session_id, echoed_cipher, self.state.tls_server_hello_template.len - tls.server_hello_prefix_len)
            else
                tls.buildServerHelloWithTemplateInto(&self.server_hello_scratch, self.state.tls_server_hello_template, &slot.validation_secret, &slot.validation_digest, session_id, echoed_cipher)) catch {
                self.closeSlot(slot, "build server hello failed");
                return;
            };
            slot.phase = .writing_server_hello_rest;
            _ = queueClient(slot, self.state.allocator, response) catch {
                self.closeSlot(slot, "queue server hello failed");
                return;
            };
            return;
        }
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
        if (slot.validation_user.len == 0) {
            slot.validation_user = self.state.allocator.dupe(u8, result.user) catch {
                self.closeSlot(slot, "username allocation failed");
                return;
            };
            slot.validation_user_len = result.user.len;
        }
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

        // force_media_middle_proxy (default true) must see a snapshot for every
        // media path (dc_idx < 0), not just DC203 — otherwise buildDcConnectPlan's
        // `middle_addr != null` guard always fails for DC1..5 media under the
        // shipped use_middle_proxy=false default, silently sending media direct
        // and making the flag dead code for anything but CDN.
        const snapshot = if (self.state.config.datacenter_override == null and middleProxySnapshotWanted(&self.state.config, dc_abs))
            self.state.getMiddleProxySnapshot()
        else
            null;

        var plan = buildDcConnectPlan(&self.state.config, dc_abs, slot.dc_idx, if (snapshot) |*s| s else null, result.user);
        self.endpoint_penalties.prioritize(plan.candidates[0..plan.count], nowMs());
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
            // Published BEFORE the unique-IP acquire below, so the pair can never
            // desynchronise in the direction that leaks: closeSlot releases the IP
            // reference only when user_metrics is set, and a leaked reference is
            // permanent (nothing sweeps the table). The refusal path below unwinds
            // both together.
            slot.user_metrics = entry;

            // [access.user_max_ips]: how many distinct client networks may hold this
            // user's link at once. peer_addr is final here — the PROXY-protocol /
            // forwarded-for rewrite happens before the handshake completes.
            //
            // A relay connection still sitting on loopback is exempt, for the same
            // reason relay peers are already exempt from the per-IP flood guard and the
            // /24 limiter: without a PROXY-protocol terminator in front of it the WEB
            // relay hands us every browser as 127.0.0.1 (it announces its own peer, so
            // "did a header arrive" cannot tell the two apart — the ADDRESS can), and
            // every browser behind it would collapse onto one key. Counting that would
            // crowd out the user's real devices while limiting nothing. With a terminator
            // (`[web].mask_backend`) peer_addr is the browser's own address, not
            // loopback, and the quota applies as usual.
            if (entry.ip_limit) |*limit| {
                const relay_hid_the_client = slot.trusted_peer and trusted_peers.isLoopback(slot.peer_addr);
                if (!relay_hid_the_client) {
                    const ip_key = UserIpLimit.addrKey(slot.peer_addr);
                    if (!limit.acquire(ip_key)) {
                        _ = entry.ip_limit_refused_total.fetchAdd(1, .monotonic);
                        _ = entry.connections_active.fetchSub(1, .monotonic);
                        slot.user_metrics = null;
                        self.closeSlot(slot, "user ip limit");
                        return;
                    }
                    slot.user_ip_key = ip_key;
                }
            }
        }

        slot.dc_abs = @intCast(dc_abs);
        slot.use_middle_proxy = plan.use_middle_proxy;
        slot.is_media_path = plan.is_media_path;
        slot.use_fast_mode = self.state.config.fast_mode and !slot.use_middle_proxy and (dc_abs >= 1 and dc_abs <= constants.tg_datacenters_v4.len);
        slot.direct_fallback_addr = plan.direct_fallback;
        slot.direct_fallback_used = false;

        // Log DC routing decisions at debug level (enable with log_level = "debug" in config)
        {
            var addr_buf: [64]u8 = undefined;
            const addr_str = formatAddress(plan.candidates[0], &addr_buf);
            log.debug("[{d}] route: user={s} dc_idx={d} dc_abs={d} media={} middle_proxy={} candidates={d} -> {s}", .{
                slot.conn_id,
                slot.validation_user[0..slot.validation_user_len],
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

        self.startConnectUpstream(slot, candidates[0], .dc) catch |err| {
            if (!self.tryNextDcEndpoint(slot, err)) self.closeSlot(slot, "upstream connect start failed");
        };
    }

    /// Handle a ClientHello whose SNI is missing or doesn't match tls_domain,
    /// per `unknown_sni_action`: `mask` forwards to the masking backend (default,
    /// active-probe defense), `reject` emits a fatal `handshake_failure` (40) TLS alert
    /// like nginx ssl_reject_handshake and closes, `drop` closes silently. Validation-failed /
    /// replay cases (SNI matched) keep masking — they're not handled here.
    fn handleInvalidSni(self: *EventLoop, slot: *ConnectionSlot, client_hello: []const u8, sni: ?[]const u8, reason: []const u8) void {
        // The configured WEB domain is a legitimate carrier, not an unknown SNI.
        if (sni) |name| {
            if (self.state.web_mask_addr) |addr| {
                if (self.state.config.web.domain) |domain| {
                    if (std.ascii.eqlIgnoreCase(name, domain)) {
                        slot.mask_addr_override = addr;
                        slot.mask_dns_override = self.state.web_dns_id;
                        slot.mask_send_proxy_header = true;
                        self.startMasking(slot, client_hello) catch self.closeSlot(slot, reason);
                        return;
                    }
                }
            }
        }
        _ = self.state.stats_unknown_sni.fetchAdd(1, .monotonic);
        switch (self.state.config.unknown_sni_action) {
            .mask => {
                // SNI-following: if the probed SNI is safelisted, front to that domain's
                // own server so the on-wire conversation matches the SNI the prober claimed.
                if (sni) |s| {
                    // The WEB relay's own domain is not a probe: it is a real browser
                    // fetching the bridge. Front it through the terminator that accepts a
                    // PROXY header so the relay — and Telegram beyond it — see the actual
                    // client instead of loopback.
                    if (self.state.web_mask_addr) |web_addr| {
                        if (self.state.config.web.domain) |domain| {
                            if (std.ascii.eqlIgnoreCase(s, domain)) {
                                slot.mask_addr_override = web_addr;
                                slot.mask_dns_override = self.state.web_dns_id;
                                slot.mask_send_proxy_header = true;
                            }
                        }
                    }
                    if (!slot.mask_send_proxy_header) {
                        for (self.state.mask_safelist) |entry| {
                            if (std.ascii.eqlIgnoreCase(s, entry.domain)) {
                                slot.mask_addr_override = entry.addr;
                                slot.mask_dns_override = entry.dns_id;
                                break;
                            }
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
        const candidates = blk: {
            if (slot.mask_addr_override) |override| {
                slot.mask_addr_override = null;
                const id = slot.mask_dns_override;
                slot.mask_dns_override = null;
                break :blk if (id) |value| self.state.dns.snapshot(value) else net_helpers.AddressCandidates.init(&.{override});
            }
            var current = if (self.state.mask_dns_id) |id| self.state.dns.snapshot(id) else self.state.mask_candidates;
            for (current.addresses[0..current.len]) |*address| address.setPort(self.state.config.mask_port);
            break :blk current;
        };
        if (candidates.len == 0) return error.NoMaskAddress;
        try slot.freezeResolvedCandidates(self.state.allocator, candidates);
        slot.mask_candidate_next = 1;
        var addr = candidates.addresses[0];
        // Reject a cover target that routes back into this listener, including the
        // public ingress address (not just the configured loopback address).
        while (addr.getPort() == self.state.config.port) {
            const local = try socket_utils.localSocketAddress(slot.client_fd);
            if (!addressEql(addr, local) and !trusted_peers.isLoopback(addr)) break;
            if (slot.mask_candidate_next >= candidates.len) return error.MaskBackendLoopsToProxy;
            addr = candidates.addresses[slot.mask_candidate_next];
            slot.mask_candidate_next += 1;
        }
        // Build any PROXY header only after a backend connects, so a DNS retry
        // across address families uses the actual destination and header length.
        slot.mask_prebuffer = try self.state.allocator.dupe(u8, buffered);

        self.startConnectUpstream(slot, addr, .mask) catch |err| {
            if (!self.tryNextResolvedEndpoint(slot, .mask, addr)) return err;
        };
    }

    fn startConnectUpstream(self: *EventLoop, slot: *ConnectionSlot, addr: Address, kind: UpstreamKind) !void {
        const connect_result = if (kind == .mask) blk: {
            const direct = if (self.state.config.upstream_mode == .tunnel) upstream_mod.Upstream.initDirectWithMark(tunnel_socket_mark) else upstream_mod.Upstream.initDirect();
            break :blk try direct.connect(addr);
        } else blk: {
            if (slot.resolved_candidates == null) {
                if (self.state.proxy_dns_id) |id| {
                    const candidates = self.state.dns.snapshot(id);
                    if (candidates.len == 0) return error.NoProxyAddress;
                    try slot.freezeResolvedCandidates(self.state.allocator, candidates);
                }
            }
            while (true) {
                const connector = if (slot.resolved_candidates) |candidates| self.state.upstream.withProxyAddress(candidates.addresses[slot.proxy_candidate_index]) else self.state.upstream.withProxyCandidate(slot.proxy_candidate_index);
                break :blk connector.connect(addr) catch |err| {
                    const count = if (slot.resolved_candidates) |candidates| candidates.len else self.state.upstream.proxyCandidateCount();
                    if (slot.proxy_candidate_index + 1 >= count) return err;
                    slot.proxy_candidate_index += 1;
                    continue;
                };
            }
        };
        const fd = connect_result.fd;
        errdefer closeFd(fd);

        try self.addUpstreamFd(slot, fd, false, true);
        errdefer _ = self.delFd(fd) catch {};

        try self.pool.mapFd(fd, slot.index);

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

        if (!connect_result.pending) {
            self.onUpstreamConnectComplete(slot);
        }
    }

    fn onUpstreamConnectComplete(self: *EventLoop, slot: *ConnectionSlot) void {
        if (checkSocketConnectError(slot.upstream_fd)) |_| {} else |err| {
            const failed_kind = slot.upstream_kind;
            const failed_target = slot.current_upstream_addr;
            self.cleanupFailedUpstreamConnect(slot);

            if (self.tryNextResolvedEndpoint(slot, failed_kind, failed_target)) return;

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
        if (slot.upstream_kind == .dc) if (slot.current_upstream_addr) |addr| self.endpoint_penalties.succeeded(addr);

        if (slot.upstream_kind == .mask) {
            if (slot.mask_send_proxy_header) {
                var header_buf: [64]u8 = undefined;
                const header = proxy_protocol.buildV2(&header_buf, slot.peer_addr, slot.current_upstream_addr.?);
                _ = queueUpstream(slot, self.state.allocator, header) catch {
                    self.closeSlot(slot, "mask PROXY header failed");
                    return;
                };
                slot.mask_send_proxy_header = false;
            }
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
            self.finishRelayHalfClose(slot);
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
            self.deferClose(fd);
            slot.upstream_fd = -1;
            // The fd left epoll: keep the cache describing the kernel, so the next
            // endpoint's registration starts from a truthful (false,false).
            slot.noteUpstreamRegistered(false, false);
        }
        slot.upstream_kind = .none;
        slot.current_upstream_addr = null;
        slot.upstream_queue.clear();
    }

    fn tryNextResolvedEndpoint(self: *EventLoop, slot: *ConnectionSlot, kind: UpstreamKind, target: ?Address) bool {
        if (kind == .mask) {
            const candidates = slot.resolved_candidates orelse return false;
            while (slot.mask_candidate_next > 0 and slot.mask_candidate_next < candidates.len) {
                const addr = candidates.addresses[slot.mask_candidate_next];
                slot.mask_candidate_next += 1;
                if (addr.getPort() == self.state.config.port) {
                    const local = socket_utils.localSocketAddress(slot.client_fd) catch return false;
                    if (addressEql(addr, local) or trusted_peers.isLoopback(addr)) continue;
                }
                self.startConnectUpstream(slot, addr, .mask) catch continue;
                return true;
            }
            return false;
        }
        if (kind != .dc or self.state.upstream == .direct) return false;
        const addr = target orelse return false;
        const count = if (slot.resolved_candidates) |candidates| candidates.len else self.state.upstream.proxyCandidateCount();
        if (slot.proxy_candidate_index + 1 >= count) return false;
        slot.proxy_candidate_index += 1;
        self.startConnectUpstream(slot, addr, kind) catch return false;
        return true;
    }

    fn tryNextDcEndpoint(self: *EventLoop, slot: *ConnectionSlot, err: anyerror) bool {
        slot.proxy_candidate_index = 0;
        const candidates = slot.upstreamCandidates();
        if (candidates.len > 0) self.endpoint_penalties.failed(slot.current_upstream_addr orelse candidates[@min(slot.upstream_candidate_next -| 1, candidates.len - 1)], nowMs());
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
            if (err == error.EndOfStream) {
                self.beginRelayHalfClose(slot, slot.client_fd);
                return;
            }
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
            if (err == error.EndOfStream) {
                self.beginRelayHalfClose(slot, slot.upstream_fd);
                return;
            }
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
            self.beginRelayHalfClose(slot, slot.client_fd);
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
            self.beginRelayHalfClose(slot, slot.upstream_fd);
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
            beginRelayHalfClose,
        );
    }

    fn relayRawUpstreamToClient(self: *EventLoop, slot: *ConnectionSlot) void {
        return relay_steps.relayRawUpstreamToClient(
            self,
            slot,
            self.shared_read_buf[0..],
            relayQueueClient,
            proxyHandshakeCloseSlot,
            beginRelayHalfClose,
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
            mpHandshakeFallbackToDirect,
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

        const budget = hi; // Visit every deadline this tick; inactive slots are cheap pointer checks.
        var scanned: usize = 0;
        while (scanned < budget) : (scanned += 1) {
            const slot_opt = self.pool.slots[idx];
            idx += 1;
            if (idx >= hi) idx = 0;

            const slot = slot_opt orelse continue;
            if (slot.phase == .idle) continue;

            // Per-endpoint upstream connect deadline. Fires only while a connect() is still
            // in flight; lets failover advance to the next DC endpoint quickly instead of
            // burning the whole (global) handshake_timeout_sec on one black-holed endpoint.
            if (slot.phase == .connecting_upstream and self.state.config.dc_connect_timeout_sec > 0 and
                slot.upstream_connect_started_ms > 0 and
                now_ms - slot.upstream_connect_started_ms > secondsToMs(self.state.config.dc_connect_timeout_sec))
            {
                const failed_kind = slot.upstream_kind;
                const failed_target = slot.current_upstream_addr;
                self.cleanupFailedUpstreamConnect(slot);
                if (self.tryNextResolvedEndpoint(slot, failed_kind, failed_target)) continue;
                // Mirror onUpstreamConnectComplete's failure path: DC endpoints fail over to
                // the next candidate; any other upstream kind (mask/proxy/middle) just closes.
                if (failed_kind == .dc and self.tryNextDcEndpoint(slot, error.ConnectTimedOut)) continue;
                self.closeSlot(slot, "dc connect timeout");
                continue;
            }

            if (slot.handshakeInProgress()) {
                if (slot.first_byte_at_ms == 0) {
                    if (now_ms - slot.created_at_ms > jitteredIdleTimeoutMs(self.state.config.handshake_timeout_sec, self.state.config.idle_timeout_jitter_pct, slot.conn_id ^ @as(u64, @bitCast(slot.created_at_ms)))) {
                        _ = self.state.stats_hs_timeout.fetchAdd(1, .monotonic);
                        if (!slot.trusted_peer and !self.state.config.accept_proxy_protocol)
                            _ = self.state.floodRecord(slot.peer_addr, .handshake_timeout, floodGuardSettings(&self.state.config));
                        self.closeSlot(slot, "silent handshake timeout");
                        continue;
                    }
                } else if (slot.phase == .reading_direct_obfuscated_handshake and
                    !slot.trusted_peer and
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
                } else if (now_ms - slot.first_byte_at_ms > jitteredIdleTimeoutMs(self.state.config.handshake_timeout_sec, self.state.config.idle_timeout_jitter_pct, slot.conn_id ^ @as(u64, @bitCast(slot.created_at_ms)))) {
                    _ = self.state.stats_hs_timeout.fetchAdd(1, .monotonic);
                    // Only blame the client's IP when the stall is client-driven. An
                    // upstream-side timeout (DC unreachable, slow upstream proxy, stale
                    // middleproxy secret) is not the client's fault, and feeding it to the
                    // flood guard would block legit secret-holders behind a shared NAT
                    // during an upstream outage.
                    if (isClientDrivenHandshakePhase(slot.phase) and !slot.mp_step.awaitingMiddleProxy() and (!slot.trusted_peer or !trusted_peers.isLoopback(slot.peer_addr))) {
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
                if (slot.phase == .mask_relaying and !slot.mask_send_proxy_header and self.state.config.mask_relay_max_secs > 0 and
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
        const want = wantedInterests(slot, nowMs());
        const relaying = slot.phase == .relaying or slot.phase == .mask_relaying;
        if (relaying and slot.client_fd != -1) {
            if (!want.client_in and !want.client_out and !slot.client_detached) {
                try self.delFd(slot.client_fd);
                slot.client_detached = true;
                slot.noteClientRegistered(false, false);
            } else if ((want.client_in or want.client_out) and slot.client_detached) {
                try self.addClientFd(slot, slot.client_fd, want.client_in, want.client_out);
                slot.client_detached = false;
            }
        }
        if (relaying and slot.upstream_fd != -1) {
            if (!want.upstream_in and !want.upstream_out and !slot.upstream_detached) {
                try self.delFd(slot.upstream_fd);
                slot.upstream_detached = true;
                slot.noteUpstreamRegistered(false, false);
            } else if ((want.upstream_in or want.upstream_out) and slot.upstream_detached) {
                try self.addUpstreamFd(slot, slot.upstream_fd, want.upstream_in, want.upstream_out);
                slot.upstream_detached = false;
            }
        }

        // A detached fd (relay half-close) has left epoll — never modFd it.
        if (slot.client_fd != -1 and !slot.client_detached) {
            if (slot.client_interest_in != want.client_in or slot.client_interest_out != want.client_out) {
                try self.modFd(slot.client_fd, want.client_in, want.client_out);
                slot.client_interest_in = want.client_in;
                slot.client_interest_out = want.client_out;
            }
        }

        if (slot.upstream_fd != -1 and !slot.upstream_detached) {
            if (slot.upstream_interest_in != want.upstream_in or slot.upstream_interest_out != want.upstream_out) {
                try self.modFd(slot.upstream_fd, want.upstream_in, want.upstream_out);
                slot.upstream_interest_in = want.upstream_in;
                slot.upstream_interest_out = want.upstream_out;
            }
        }
    }

    fn ensureMpC2sScratch(self: *EventLoop) ![]u8 {
        if (self.mp_c2s_scratch) |buf| return buf;

        // At most one prior buffered frame plus the current bounded read can
        // complete here. Charge worst-case framing overhead per new input byte.
        const capacity = self.state.config.middleProxyC2sScratchBytes();
        const buf = try self.state.allocator.alloc(u8, capacity);
        self.mp_c2s_scratch = buf;
        return buf;
    }

    fn ensureMpS2cScratch(self: *EventLoop) ![]u8 {
        if (self.mp_s2c_scratch) |buf| return buf;
        const buf = try self.state.allocator.alloc(u8, self.state.config.middleProxyBufferBytes() + read_buf_size + 16);
        self.mp_s2c_scratch = buf;
        return buf;
    }

    /// EOF is only recorded after read() returns zero, never from RDHUP alone.
    fn beginRelayHalfClose(self: *EventLoop, slot: *ConnectionSlot, hung_fd: posix.fd_t) void {
        if (hung_fd == slot.client_fd) slot.client_read_eof = true else slot.upstream_read_eof = true;
        slot.relay_half_closed = true;
        self.finishRelayHalfClose(slot);
    }

    fn finishRelayHalfClose(self: *EventLoop, slot: *ConnectionSlot) void {
        if (!slot.relay_half_closed) return;
        if (slot.client_read_eof and !slot.hasUpstreamPending() and !slot.upstream_write_shutdown) {
            _ = linux.shutdown(slot.upstream_fd, linux.SHUT.WR);
            slot.upstream_write_shutdown = true;
        }
        if (slot.upstream_read_eof and !slot.hasClientPending() and !slot.client_write_shutdown) {
            _ = linux.shutdown(slot.client_fd, linux.SHUT.WR);
            slot.client_write_shutdown = true;
        }
        if (slot.client_read_eof and slot.upstream_read_eof and !slot.hasClientPending() and !slot.hasUpstreamPending())
            self.closeSlot(slot, "relay drained after peer half-close");
    }

    fn closeSlot(self: *EventLoop, slot: *ConnectionSlot, reason: []const u8) void {
        if (slot.phase == .idle) return;
        std.crypto.secureZero(u8, &slot.mp_secret);
        slot.mp_secret_len = 0;
        // s2c counts payload handed to the client queue, so a large `qlen` here means we
        // decapsulated the bytes but never got them onto the socket.
        log.debug("[{d}] closing: user={s} dc_idx={d} media={} phase={s} reason={s} c2s={d} s2c={d} qlen={d} relay={}", .{
            slot.conn_id,
            slot.validation_user[0..slot.validation_user_len],
            slot.dc_idx,
            slot.is_media_path,
            @tagName(slot.phase),
            reason,
            slot.c2s_bytes,
            slot.s2c_bytes,
            slot.client_queue.total_len,
            slot.trusted_peer,
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
        const user_ip_key = slot.user_ip_key;
        slot.resetOwnedBuffers(self.state.allocator);

        if (slot.active_reserved) {
            _ = self.state.active_connections.fetchSub(1, .monotonic);
            _ = self.state.closed_count.fetchAdd(1, .monotonic);
            if (user_metrics) |entry| {
                // Release the unique-IP slot BEFORE dropping connections_active: a
                // retired entry is reclaimed the moment that counter reaches zero
                // (collectRetiredUserMetrics), so touching ip_limit afterwards would
                // race a free.
                if (user_ip_key) |ip_key| {
                    if (entry.ip_limit) |*limit| limit.release(ip_key);
                }
                _ = entry.connections_active.fetchSub(1, .monotonic);
            }
            // RED errors + evasion signal: bucket the close reason once per slot.
            _ = self.state.close_reasons[@intFromEnum(CloseReason.classify(reason))].fetchAdd(1, .monotonic);
            slot.active_reserved = false;
            _ = self.state.closed_since_log.fetchAdd(1, .monotonic);
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

    /// Register a slot's client fd and record the registration in one step. Slot fds must
    /// go through this (never bare addFd): the interest cache is what syncInterests
    /// compares against, so a registration it never saw makes a later disarm a no-op.
    fn addClientFd(self: *EventLoop, slot: *ConnectionSlot, fd: posix.fd_t, want_in: bool, want_out: bool) !void {
        try self.addFd(fd, want_in, want_out);
        slot.noteClientRegistered(want_in, want_out);
    }

    /// Register a slot's upstream fd and record the registration (see addClientFd).
    fn addUpstreamFd(self: *EventLoop, slot: *ConnectionSlot, fd: posix.fd_t, want_in: bool, want_out: bool) !void {
        try self.addFd(fd, want_in, want_out);
        slot.noteUpstreamRegistered(want_in, want_out);
    }

    /// Low-level epoll registration. Only for fds with no slot behind them (the
    /// listener, the signalfd) — everything else uses addClientFd/addUpstreamFd.
    fn addFd(self: *EventLoop, fd: posix.fd_t, want_in: bool, want_out: bool) !void {
        var events: u32 = linux.EPOLL.ERR | linux.EPOLL.HUP;
        if (want_in) events |= linux.EPOLL.IN | linux.EPOLL.RDHUP;
        if (want_out) events |= linux.EPOLL.OUT;

        var ev = linux.epoll_event{ .events = events, .data = .{ .fd = fd } };
        const rc = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_ADD, fd, &ev);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    fn modFd(self: *EventLoop, fd: posix.fd_t, want_in: bool, want_out: bool) !void {
        var events: u32 = linux.EPOLL.ERR | linux.EPOLL.HUP;
        if (want_in) events |= linux.EPOLL.IN | linux.EPOLL.RDHUP;
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
        const next = try self.state.allocator.realloc(prev, next_len);
        @memcpy(next[prev.len..], extra);
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
    return relay_steps.queueTlsAppRecords(slot, allocator, payload, slotQueueClientParts);
}

fn slotQueueClientParts(slot: *ConnectionSlot, _: std.mem.Allocator, parts: []const []const u8) !bool {
    return queue_io.queueOrWriteParts(slot.client_fd, &slot.client_queue, parts, slot.traffic_upstream_to_client_counter orelse &noop_counter, if (slot.user_metrics) |entry| &entry.upstream_to_client_bytes_total else null);
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
    if (std.mem.eql(u8, reason, "socks5 connect rejected") or std.mem.eql(u8, reason, "http connect rejected")) {
        loop.cleanupFailedUpstreamConnect(slot);
        if (loop.tryNextDcEndpoint(slot, error.ConnectionRefused)) return;
    }
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

test "worker traffic counters batch global writes without losing bytes" {
    var state: ProxyState = undefined;
    state.client_to_upstream_bytes_total = .init(100);
    state.upstream_to_client_bytes_total = .init(200);
    var loop: EventLoop = undefined;
    loop.state = &state;
    loop.traffic_c2s_pending = .init(7);
    loop.traffic_s2c_pending = .init(11);
    loop.flushTrafficCounters();
    loop.flushTrafficCounters();
    try std.testing.expectEqual(@as(u64, 107), state.client_to_upstream_bytes_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 211), state.upstream_to_client_bytes_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), loop.traffic_c2s_pending.load(.monotonic));
}

test "handshakeInProgress - phases" {
    var slot: ConnectionSlot = undefined;

    inline for (@typeInfo(ConnectionPhase).@"enum".fields) |field| {
        slot.phase = @enumFromInt(field.value);
        const expected = switch (slot.phase) {
            .idle, .relaying, .mask_relaying => false,
            else => true,
        };
        try std.testing.expectEqual(expected, slot.handshakeInProgress());
    }
}

test "resolved retry exhaustion and overrides preserve masking prebuffer" {
    const addr = ip4(.{ 192, 0, 2, 1 }, 443);
    var state: ProxyState = undefined;
    state.mask_candidates = .init(&.{addr});
    state.upstream = upstream_mod.Upstream.initSocks5Candidates(&.{addr}, "user", "pass");
    var loop: EventLoop = undefined;
    loop.state = &state;
    var pre = [_]u8{ 1, 2, 3 };
    var slot = ConnectionSlot{ .mask_prebuffer = &pre, .mask_candidate_next = 0 };
    try std.testing.expect(!loop.tryNextResolvedEndpoint(&slot, .mask, addr)); // An override never falls back to default.
    slot.mask_candidate_next = 1;
    try std.testing.expect(!loop.tryNextResolvedEndpoint(&slot, .mask, addr));
    try std.testing.expect(!loop.tryNextResolvedEndpoint(&slot, .dc, addr));
    try std.testing.expectEqualSlices(u8, &pre, slot.mask_prebuffer.?);
    try std.testing.expectEqual(@as(u8, 0), slot.proxy_candidate_index);
}

test "connection DNS candidates are frozen copies and retain every override address" {
    const allocator = std.testing.allocator;
    var slot: ConnectionSlot = .{};
    defer slot.resetOwnedBuffers(allocator);
    const first = ip4(.{ 192, 0, 2, 1 }, 443);
    const second = ip4(.{ 192, 0, 2, 2 }, 443);
    var source = net_helpers.AddressCandidates.init(&.{ first, second });
    try slot.freezeResolvedCandidates(allocator, source);
    source = .init(&.{second});
    try std.testing.expectEqual(@as(usize, 2), slot.resolved_candidates.?.len);
    try std.testing.expect(addressEql(first, slot.resolved_candidates.?.addresses[0]));
    try std.testing.expect(addressEql(second, slot.resolved_candidates.?.addresses[1]));
    // A future connection receives the new snapshot; an in-flight retry does not.
    var next: ConnectionSlot = .{};
    defer next.resetOwnedBuffers(allocator);
    try next.freezeResolvedCandidates(allocator, source);
    try std.testing.expectEqual(@as(usize, 1), next.resolved_candidates.?.len);
}

test "relay FIN drains more than one read buffer and preserves reverse traffic" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    for ([_]bool{ false, true }) |from_upstream| {
        var client: [2]i32 = undefined;
        var upstream_pair: [2]i32 = undefined;
        try std.testing.expectEqual(posix.E.SUCCESS, linux.errno(linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0, &client)));
        defer for (client) |fd| closeFd(fd);
        try std.testing.expectEqual(posix.E.SUCCESS, linux.errno(linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0, &upstream_pair)));
        defer for (upstream_pair) |fd| closeFd(fd);
        var state: ProxyState = undefined;
        state.allocator = std.testing.allocator;
        var loop: EventLoop = undefined;
        loop.state = &state;
        loop.epoll_fd = try epollCreate();
        defer closeFd(loop.epoll_fd);
        var slot = ConnectionSlot{ .phase = .mask_relaying, .client_fd = client[0], .upstream_fd = upstream_pair[0] };
        slot.client_queue.allocator = std.testing.allocator;
        slot.upstream_queue.allocator = std.testing.allocator;
        defer slot.client_queue.deinit();
        defer slot.upstream_queue.deinit();
        try loop.addClientFd(&slot, slot.client_fd, true, false);
        try loop.addUpstreamFd(&slot, slot.upstream_fd, true, false);
        const sender = if (from_upstream) upstream_pair[1] else client[1];
        const receiver = if (from_upstream) client[1] else upstream_pair[1];
        const source_fd = if (from_upstream) slot.upstream_fd else slot.client_fd;
        const reverse_fd = if (from_upstream) slot.client_fd else slot.upstream_fd;
        const send_buffer: u32 = 4096;
        try posix.setsockopt(reverse_fd, posix.SOL.SOCKET, linux.SO.SNDBUF, std.mem.asBytes(&send_buffer));
        const payload = [_]u8{0x5a} ** (read_buf_size * 2 + 17);
        try std.testing.expectEqual(payload.len, linux.write(sender, &payload, payload.len));
        try std.testing.expectEqual(posix.E.SUCCESS, linux.errno(linux.shutdown(sender, linux.SHUT.WR)));
        var received: usize = 0;
        var buffer: [read_buf_size]u8 = undefined;
        var reached_eof = false;
        for (0..16) |_| {
            loop.processSlotEvent(&slot, source_fd, linux.EPOLL.IN | linux.EPOLL.RDHUP);
            loop.processSlotEvent(&slot, reverse_fd, linux.EPOLL.OUT);
            while (true) {
                const n = posix.read(receiver, &buffer) catch |err| switch (err) {
                    error.WouldBlock => break,
                    else => return err,
                };
                if (n == 0) {
                    reached_eof = true;
                    break;
                }
                try std.testing.expect(std.mem.allEqual(u8, buffer[0..n], 0x5a));
                received += n;
            }
            if (reached_eof) break;
        }
        try std.testing.expectEqual(payload.len, received);
        try std.testing.expect(reached_eof);
        try std.testing.expectEqual(ConnectionPhase.mask_relaying, slot.phase);
        try std.testing.expectEqual(@as(usize, 5), linux.write(receiver, "reply", 5));
        loop.processSlotEvent(&slot, reverse_fd, linux.EPOLL.IN);
        const reply_len = try posix.read(sender, &buffer);
        try std.testing.expectEqualStrings("reply", buffer[0..reply_len]);
    }
}

test "middle proxy response rejection falls back without starting relay" {
    const Harness = struct {
        state: *ProxyState,
        payload: [32]u8 = @splat(0),
        response_len: usize = 32,
        fallbacks: usize = 0,
        closed: bool = false,
        started: bool = false,
        fn read(self: *@This(), _: *ConnectionSlot, _: bool) !?[]const u8 {
            return self.payload[0..self.response_len];
        }
        fn write(_: *@This(), _: *ConnectionSlot, _: []const u8, _: bool) !void {}
        fn lock(_: *@This()) void {}
        fn start(self: *@This(), _: *ConnectionSlot) void {
            self.started = true;
        }
        fn close(self: *@This(), _: *ConnectionSlot, _: []const u8) void {
            self.closed = true;
        }
        fn fallback(self: *@This(), _: *ConnectionSlot) bool {
            self.fallbacks += 1;
            return true;
        }
    };
    var state: ProxyState = undefined;
    var harness = Harness{ .state = &state };
    var slot = ConnectionSlot{};
    for ([_]MiddleProxyHandshakeStep{ .waiting_rpc_nonce_response, .waiting_rpc_handshake_response }) |step| {
        for ([_]usize{ 0, 31, 32 }) |len| {
            slot.mp_step = step;
            harness.response_len = len;
            middle_proxy_handshake.onReadable(&harness, &slot, Harness.read, Harness.write, Harness.lock, Harness.lock, Harness.start, Harness.close, Harness.fallback);
        }
    }
    try std.testing.expectEqual(@as(usize, 6), harness.fallbacks);
    try std.testing.expect(!harness.closed);
    try std.testing.expect(!harness.started);
    if (builtin.os.tag == .linux) {
        // A SOCKS transport may be IPv6 while the logical MP endpoint is IPv4.
        // The announced NAT address must follow the latter, not getsockname.
        const fd_result = linux.socket(posix.AF.INET6, posix.SOCK.STREAM, 0);
        try std.testing.expectEqual(posix.E.SUCCESS, linux.errno(fd_result));
        const fd: i32 = @intCast(fd_result);
        defer closeFd(fd);
        state.allocator = std.testing.allocator;
        state.config = .{ .users = std.StringHashMap([16]u8).init(std.testing.allocator), .direct_users = std.StringHashMap(void).init(std.testing.allocator) };
        state.middle_proxy_nat_ip4 = .{ 203, 0, 113, 7 };
        slot.upstream_fd = fd;
        slot.current_upstream_addr = ip4(.{ 149, 154, 167, 50 }, 443);
        slot.peer_addr = ip4(.{ 192, 0, 2, 8 }, 1234);
        slot.mp_secret_len = 32;
        @memset(slot.mp_secret[0..32], 0x42);
        slot.mp_nonce = @splat(0x11);
        slot.mp_timestamp = 0x12345678;
        slot.mp_step = .waiting_rpc_nonce_response;
        @memcpy(harness.payload[0..4], &middleproxy.rpc_nonce_req);
        @memcpy(harness.payload[4..8], slot.mp_secret[0..4]);
        @memcpy(harness.payload[8..12], &middleproxy.rpc_crypto_aes);
        @memset(harness.payload[16..32], 0x22);
        middle_proxy_handshake.onReadable(&harness, &slot, Harness.read, Harness.write, Harness.lock, Harness.lock, Harness.start, Harness.close, Harness.fallback);
        try std.testing.expectEqual(MiddleProxyHandshakeStep.waiting_rpc_handshake_response, slot.mp_step);
        try std.testing.expectEqual(@as(usize, 6), harness.fallbacks);
        const expected_enc = try middleproxy.getAesKeyAndIv(&([_]u8{0x22} ** 16), &slot.mp_nonce, &.{ 0x78, 0x56, 0x34, 0x12 }, &.{ 50, 167, 154, 149 }, &.{ 0, 0 }, "CLIENT", &.{ 7, 113, 0, 203 }, &.{ 0xbb, 1 }, slot.mp_secret[0..32], null, null);
        const expected_dec = try middleproxy.getAesKeyAndIv(&([_]u8{0x22} ** 16), &slot.mp_nonce, &.{ 0x78, 0x56, 0x34, 0x12 }, &.{ 50, 167, 154, 149 }, &.{ 0, 0 }, "SERVER", &.{ 7, 113, 0, 203 }, &.{ 0xbb, 1 }, slot.mp_secret[0..32], null, null);
        try std.testing.expectEqualSlices(u8, &expected_enc[0], &slot.mp_enc.?.key);
        try std.testing.expectEqualSlices(u8, &expected_enc[1], &slot.mp_enc.?.iv);
        try std.testing.expectEqualSlices(u8, &expected_dec[0], &slot.mp_dec.?.key);
        try std.testing.expectEqualSlices(u8, &expected_dec[1], &slot.mp_dec.?.iv);
        @memcpy(harness.payload[0..4], &middleproxy.rpc_handshake);
        @memcpy(harness.payload[20..32], "IPIPPRPDTIME");
        middle_proxy_handshake.onReadable(&harness, &slot, Harness.read, Harness.write, Harness.lock, Harness.lock, Harness.start, Harness.close, Harness.fallback);
        try std.testing.expect(harness.started);
        try std.testing.expectEqual(MiddleProxyHandshakeStep.done, slot.mp_step);
        defer slot.middle_ctx.?.deinit(std.testing.allocator);
        try std.testing.expectEqualSlices(u8, &.{ 203, 0, 113, 7 }, slot.middle_ctx.?.our_ip_port[12..16]);
    }
}

test "multicore handshake budget is bounded and released exactly once" {
    var state: ProxyState = undefined;
    state.config = .{ .users = std.StringHashMap([16]u8).init(std.testing.allocator), .direct_users = std.StringHashMap(void).init(std.testing.allocator) };
    state.config.max_connections = 10;
    state.handshakes_inflight = .init(0);
    state.stats_dropped_hs_budget = .init(0);
    var loop: EventLoop = undefined;
    loop.state = &state;
    var slots = [_]ConnectionSlot{.{}} ** 8;
    const Worker = struct {
        fn run(shared: *EventLoop, slot: *ConnectionSlot) void {
            if (shared.reserveHandshakeBudget(slot)) {
                std.debug.assert(shared.reserveHandshakeBudget(slot));
            }
        }
    };
    var threads: [8]std.Thread = undefined;
    for (&threads, &slots) |*thread, *slot| thread.* = try std.Thread.spawn(.{}, Worker.run, .{ &loop, slot });
    for (threads) |thread| thread.join();
    try std.testing.expectEqual(@as(u64, 3), state.handshakes_inflight.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 5), state.stats_dropped_hs_budget.load(.monotonic));
    for (&slots) |*slot| {
        loop.releaseHandshakeBudget(slot);
        loop.releaseHandshakeBudget(slot);
    }
    try std.testing.expectEqual(@as(u64, 0), state.handshakes_inflight.load(.monotonic));
    // Refusal must happen before touching config_path or allocator.
    state.effective_workers = 2;
    loop.reloadConfigFromDisk();
    try std.testing.expectEqual(@as(u32, 10), state.config.max_connections);
}

test "SOCKS response state machine authenticates and connects logical destination" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const Harness = struct {
        state: *ProxyState,
        closed: bool = false,
        complete: bool = false,
        message: [512]u8 = undefined,
        message_len: usize = 0,
        fn queue(self: *@This(), _: *ConnectionSlot, bytes: []const u8) !bool {
            @memcpy(self.message[0..bytes.len], bytes);
            self.message_len = bytes.len;
            return true;
        }
        fn close(self: *@This(), _: *ConnectionSlot, _: []const u8) void {
            self.closed = true;
        }
        fn done(self: *@This(), _: *ConnectionSlot) void {
            self.complete = true;
        }
    };
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(posix.E.SUCCESS, linux.errno(linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0, &fds)));
    defer for (fds) |fd| closeFd(fd);
    var state: ProxyState = undefined;
    state.allocator = std.testing.allocator;
    state.upstream = upstream_mod.Upstream.initSocks5(ip4(.{ 127, 0, 0, 1 }, 1080), "user", "pass");
    var harness = Harness{ .state = &state };
    var slot = ConnectionSlot{ .upstream_fd = fds[0], .proxy_target_addr = ip4(.{ 149, 154, 167, 50 }, 443) };
    defer if (slot.proxy_handshake_buf) |buf| std.testing.allocator.destroy(buf);
    proxy_upstream_handshake.startSocks5(&harness, &slot, Harness.queue, Harness.close);
    try std.testing.expectEqual(ConnectionPhase.proxy_socks5_greeting_resp, slot.phase);
    // Split the greeting across readable events; no premature phase advance.
    try std.testing.expectEqual(@as(usize, 1), linux.write(fds[1], &.{5}, 1));
    proxy_upstream_handshake.onSocks5Readable(&harness, &slot, Harness.queue, Harness.close, Harness.done);
    try std.testing.expectEqual(ConnectionPhase.proxy_socks5_greeting_resp, slot.phase);
    try std.testing.expectEqual(@as(usize, 1), linux.write(fds[1], &.{2}, 1));
    proxy_upstream_handshake.onSocks5Readable(&harness, &slot, Harness.queue, Harness.close, Harness.done);
    try std.testing.expectEqual(ConnectionPhase.proxy_socks5_auth_resp, slot.phase);
    try std.testing.expectEqualSlices(u8, &.{ 1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's' }, harness.message[0..harness.message_len]);
    try std.testing.expectEqual(@as(usize, 2), linux.write(fds[1], &.{ 1, 0 }, 2));
    proxy_upstream_handshake.onSocks5Readable(&harness, &slot, Harness.queue, Harness.close, Harness.done);
    try std.testing.expectEqual(ConnectionPhase.proxy_socks5_connect_resp, slot.phase);
    try std.testing.expectEqualSlices(u8, &.{ 149, 154, 167, 50 }, harness.message[4..8]);
    try std.testing.expectEqual(@as(usize, 10), linux.write(fds[1], &.{ 5, 0, 0, 1, 127, 0, 0, 1, 0, 80 }, 10));
    proxy_upstream_handshake.onSocks5Readable(&harness, &slot, Harness.queue, Harness.close, Harness.done);
    try std.testing.expect(harness.complete);
    try std.testing.expect(!harness.closed);
    state.upstream = upstream_mod.Upstream.initHttpConnect(ip4(.{ 127, 0, 0, 1 }, 8080), "user", "pass");
    harness.complete = false;
    proxy_upstream_handshake.startHttpConnect(&harness, &slot, Harness.queue, Harness.close);
    try std.testing.expectEqual(ConnectionPhase.proxy_http_connect_resp, slot.phase);
    const prefix = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nX-Padding: ";
    try std.testing.expectEqual(prefix.len, linux.write(fds[1], prefix, prefix.len));
    proxy_upstream_handshake.onHttpConnectReadable(&harness, &slot, Harness.close, Harness.done);
    try std.testing.expect(!harness.complete);
    const padding = [_]u8{'x'} ** 5000;
    try std.testing.expectEqual(padding.len, linux.write(fds[1], &padding, padding.len));
    proxy_upstream_handshake.onHttpConnectReadable(&harness, &slot, Harness.close, Harness.done);
    try std.testing.expect(!harness.complete);
    try std.testing.expectEqual(@as(usize, 4), linux.write(fds[1], "\r\n\r\n", 4));
    proxy_upstream_handshake.onHttpConnectReadable(&harness, &slot, Harness.close, Harness.done);
    try std.testing.expect(harness.complete);
    try std.testing.expect(!harness.closed);
}

test "middle proxy fetched snapshot merges partial routes and rotates secret atomically" {
    const cfg = try Config.parse(std.testing.allocator, "[server]\nport=443\nmax_connections=32\nmiddle_proxy_nat_ip=\"192.0.2.1\"\n[censorship]\nmask=false\n[access.users]\nalice=\"00000000000000000000000000000001\"\n");
    var state = try ProxyState.init(std.testing.allocator, cfg, "/tmp/mtproto-snapshot-test.toml");
    defer state.deinit();
    const before = state.getMiddleProxySnapshot();
    const secret = [_]u8{0xa5} ** 32;
    const partial =
        "proxy_for 1 192.0.2.11:443;\n" ++
        "proxy_for 4 192.0.2.41:443;\n" ++
        "proxy_for 4 192.0.2.42:8443;\n" ++
        "proxy_for -4 192.0.2.44:443;\n" ++
        "proxy_for 203 192.0.2.203:443;\n" ++
        "proxy_for -203 192.0.2.204:443;\n";
    try state.mergeMiddleProxyAssets(partial, &secret, false);
    const after = state.getMiddleProxySnapshot();
    try std.testing.expect(addressEql(after.addrs_primary[0], try Address.parse("192.0.2.11", 443)));
    for ([_]usize{ 1, 2, 4 }) |i| {
        try std.testing.expect(addressEql(before.addrs_primary[i], after.addrs_primary[i]));
    }
    for ([_]usize{ 0, 1, 2, 4 }) |i| {
        try std.testing.expect(addressEql(before.addrs_media_primary[i], after.addrs_media_primary[i]));
    }
    try std.testing.expectEqual(@as(usize, 2), after.addrs_dc4_len);
    try std.testing.expect(addressEql(after.addrs_dc4[0], after.addrs_primary[3]));
    try std.testing.expect(addressEql(after.addrs_dc4[1], try Address.parse("192.0.2.42", 8443)));
    try std.testing.expectEqual(@as(usize, 1), after.addrs_media_dc4_len);
    try std.testing.expect(addressEql(after.addrs_media_dc4[0], after.addrs_media_primary[3]));
    try std.testing.expectEqual(@as(usize, 1), after.addrs_203_len);
    try std.testing.expect(addressEql(after.addrs_203[0], try Address.parse("192.0.2.204", 443)));
    try std.testing.expect(addressEql(after.addr_203, after.addrs_203[0]));
    try std.testing.expectEqualSlices(u8, &secret, state.middle_proxy_secret[0..state.middle_proxy_secret_len]);

    // Empty route data preserves the last good snapshot while a shorter secret
    // replaces the old one and wipes its now-unused tail.
    const shorter_secret = [_]u8{0x5a} ** 16;
    try state.mergeMiddleProxyAssets("", &shorter_secret, false);
    const retained = state.getMiddleProxySnapshot();
    try std.testing.expect(addressesEqual(&after.addrs_primary, &retained.addrs_primary));
    try std.testing.expect(addressesEqual(&after.addrs_media_primary, &retained.addrs_media_primary));
    try std.testing.expect(addressesEqual(after.addrs_dc4[0..after.addrs_dc4_len], retained.addrs_dc4[0..retained.addrs_dc4_len]));
    try std.testing.expect(addressesEqual(after.addrs_media_dc4[0..after.addrs_media_dc4_len], retained.addrs_media_dc4[0..retained.addrs_media_dc4_len]));
    try std.testing.expect(addressesEqual(after.addrs_203[0..after.addrs_203_len], retained.addrs_203[0..retained.addrs_203_len]));
    try std.testing.expect(addressEql(after.addr_203, retained.addr_203));
    try std.testing.expectEqualSlices(u8, &shorter_secret, state.middle_proxy_secret[0..state.middle_proxy_secret_len]);
    for (state.middle_proxy_secret[shorter_secret.len..]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    // Invalid secrets reject otherwise valid changed routes without a partial
    // commit of endpoints or destruction of the previous usable secret.
    const changed_routes = "proxy_for 1 192.0.2.99:443;\n";
    const oversized = [_]u8{1} ** 257;
    for ([_][]const u8{ "short", &oversized }) |bad_secret| {
        try std.testing.expectError(error.BadMiddleProxySecret, state.mergeMiddleProxyAssets(changed_routes, bad_secret, false));
        const rejected = state.getMiddleProxySnapshot();
        try std.testing.expect(addressesEqual(&retained.addrs_primary, &rejected.addrs_primary));
        try std.testing.expectEqualSlices(u8, &shorter_secret, state.middle_proxy_secret[0..state.middle_proxy_secret_len]);
    }
}

test "disk reload applies hot settings without replacing startup capacity" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/config.toml", .{tmp.sub_path});
    const initial = "[server]\nport=443\nmax_connections=64\nmiddle_proxy_nat_ip=\"192.0.2.1\"\n[censorship]\nmask=false\n[access.users]\nalice=\"00000000000000000000000000000001\"\n";
    const cfg = try Config.parse(allocator, initial);
    var state = try ProxyState.init(allocator, cfg, path);
    defer state.deinit();
    state.effective_workers = 1;
    var loop: EventLoop = undefined;
    loop.state = &state;
    loop.pool = try ConnectionPool.init(allocator, 64);
    defer loop.pool.deinit();
    const next = "[server]\nport=8443\nmax_connections=128\nidle_timeout_sec=123\nmiddle_proxy_nat_ip=\"192.0.2.1\"\n[censorship]\nmask=false\n[access.users]\nalice=\"00000000000000000000000000000002\"\n";
    try tmp.dir.writeFile(io, .{ .sub_path = "config.toml", .data = next });
    loop.reloadConfigFromDisk();
    try std.testing.expectEqual(@as(u16, 443), state.config.port);
    try std.testing.expectEqual(@as(u32, 64), state.config.max_connections);
    try std.testing.expectEqual(@as(u32, 123), state.config.idle_timeout_sec);
    try std.testing.expectEqual(@as(u8, 2), state.user_secrets[0].secret[15]);
    try tmp.dir.writeFile(io, .{ .sub_path = "config.toml", .data = "[server]\nmax_connections=32\n[censorship]\nmask=false\n[access.users]\nalice=\"00000000000000000000000000000002\"\n" });
    loop.reloadConfigFromDisk();
    try std.testing.expectEqual(@as(u32, 32), state.config.max_connections);
    try std.testing.expectEqual(@as(usize, 64), loop.pool.slots.len);
}

test "ProxyState access reload keeps active metrics safe" {
    const allocator = std.testing.allocator;

    const initial_cfg = try Config.parse(allocator,
        \\[censorship]
        \\mask = false
        \\[server]
        \\middle_proxy_nat_ip = "192.0.2.1"
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

test "ProxyState per-user unique-IP quota is allocated per config and survives reload" {
    const allocator = std.testing.allocator;

    // `later` has a cap but no secret yet: it is added by the reload below, which
    // proves the quota comes from the STARTUP config rather than from the reloaded one.
    const initial_cfg = try Config.parse(allocator,
        \\[censorship]
        \\mask = false
        \\[server]
        \\middle_proxy_nat_ip = "192.0.2.1"
        \\port = 443
        \\
        \\[access.users]
        \\alice = "00000000000000000000000000000001"
        \\bob = "00000000000000000000000000000002"
        \\
        \\[access.user_max_ips]
        \\alice = 2
        \\later = 1
    );
    var state = try ProxyState.init(allocator, initial_cfg, "/tmp/mtproto-test.toml");
    defer state.deinit();

    const alice = state.findUserMetrics("alice") orelse return error.TestExpectedEqual;
    const bob = state.findUserMetrics("bob") orelse return error.TestExpectedEqual;

    try std.testing.expect(bob.ip_limit == null); // no cap configured → untracked
    if (alice.ip_limit == null) return error.TestExpectedEqual;
    const alice_limit = &alice.ip_limit.?;
    try std.testing.expectEqual(@as(usize, 2), alice_limit.slots.len);

    const home = UserIpLimit.addrKey(.{ .ip4 = .{ .bytes = .{ 203, 0, 113, 1 }, .port = 443 } });
    const office = UserIpLimit.addrKey(.{ .ip4 = .{ .bytes = .{ 198, 51, 100, 1 }, .port = 443 } });
    const cafe = UserIpLimit.addrKey(.{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 443 } });

    try std.testing.expect(alice_limit.acquire(home));
    try std.testing.expect(alice_limit.acquire(office));
    try std.testing.expect(!alice_limit.acquire(cafe));

    var next_cfg = try Config.parse(allocator,
        \\[server]
        \\port = 443
        \\
        \\[access.users]
        \\alice = "00000000000000000000000000000001"
        \\later = "00000000000000000000000000000003"
    );
    defer next_cfg.deinit(allocator);
    try state.reloadAccessUsersForTest(&next_cfg);

    // Alice keeps the very same entry, so the networks she already holds keep
    // their slots across the reload instead of silently resetting the quota.
    try std.testing.expect(alice == state.findUserMetrics("alice").?);
    try std.testing.expectEqual(@as(u32, 2), alice_limit.activeCount());
    try std.testing.expect(!alice_limit.acquire(cafe));

    const later = state.findUserMetrics("later") orelse return error.TestExpectedEqual;
    if (later.ip_limit == null) return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(usize, 1), later.ip_limit.?.slots.len);

    alice_limit.release(home);
    alice_limit.release(office);
    try std.testing.expectEqual(@as(u32, 0), alice_limit.activeCount());
}

fn reloadAccessUsersInThread(
    state: *ProxyState,
    next_cfg: *Config,
    started: *std.atomic.Value(bool),
    done: *std.atomic.Value(bool),
    failed: *std.atomic.Value(bool),
) void {
    started.store(true, .release);
    state.reloadAccessUsersForTest(next_cfg) catch {
        failed.store(true, .release);
    };
    done.store(true, .release);
}

test "ProxyState access reload waits for metrics readers" {
    const allocator = std.testing.allocator;

    const initial_cfg = try Config.parse(allocator,
        \\[censorship]
        \\mask = false
        \\[server]
        \\middle_proxy_nat_ip = "192.0.2.1"
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

    var started = std.atomic.Value(bool).init(false);
    var done = std.atomic.Value(bool).init(false);
    var failed = std.atomic.Value(bool).init(false);
    const thread = try std.Thread.spawn(.{}, reloadAccessUsersInThread, .{ &state, &next_cfg, &started, &done, &failed });

    while (!started.load(.acquire)) std.atomic.spinLoopHint();
    sleepNs(20 * std.time.ns_per_ms);
    const completed_while_reader_locked = done.load(.acquire);

    state.unlockUserMetricsForReadForTest();
    thread.join();

    try std.testing.expect(!completed_while_reader_locked);
    try std.testing.expect(!failed.load(.acquire));
    try std.testing.expect(done.load(.acquire));
    try std.testing.expect(state.findUserMetrics("bob") != null);
}

test "acceptance gate: [web].only serves the relay and masks everyone else" {
    const G = AcceptanceGate;

    // Today's behaviour, unchanged: FakeTLS is served, dd is masked for the public.
    try std.testing.expect(!masksInsteadOfServing(G{ .web_only = false, .fake_tls_only = true, .transport_is_tls = true, .trusted_peer = false }));
    try std.testing.expect(masksInsteadOfServing(G{ .web_only = false, .fake_tls_only = true, .transport_is_tls = false, .trusted_peer = false }));
    // dd deliberately re-enabled: the public gets a dd responder again.
    try std.testing.expect(!masksInsteadOfServing(G{ .web_only = false, .fake_tls_only = false, .transport_is_tls = false, .trusted_peer = false }));

    // WEB-only: neither transport is served to the public, whatever fake_tls_only says.
    // A valid `ee` link from a real Telegram client lands here too — that is the point.
    try std.testing.expect(masksInsteadOfServing(G{ .web_only = true, .fake_tls_only = true, .transport_is_tls = true, .trusted_peer = false }));
    try std.testing.expect(masksInsteadOfServing(G{ .web_only = true, .fake_tls_only = true, .transport_is_tls = false, .trusted_peer = false }));
    try std.testing.expect(masksInsteadOfServing(G{ .web_only = true, .fake_tls_only = false, .transport_is_tls = false, .trusted_peer = false }));
    try std.testing.expect(masksInsteadOfServing(G{ .web_only = true, .fake_tls_only = false, .transport_is_tls = true, .trusted_peer = false }));

    // The relay is never masked. It dials this proxy on loopback for every logical
    // stream, so a gate that caught it would take the WEB proxy down with the direct
    // one — the single way this feature can break the thing it exists to protect.
    for ([_]bool{ true, false }) |web_only| {
        for ([_]bool{ true, false }) |fake_tls_only| {
            for ([_]bool{ true, false }) |is_tls| {
                try std.testing.expect(!masksInsteadOfServing(G{
                    .web_only = web_only,
                    .fake_tls_only = fake_tls_only,
                    .transport_is_tls = is_tls,
                    .trusted_peer = true,
                }));
            }
        }
    }
}

test "[web].only reaches the data plane only together with [web].enabled" {
    // ProxyState resolves the gate once at boot from `onlyActive()`, so a config with
    // `only` but no `enabled` must leave the data plane exactly as it was. Without this
    // the trusted set would be empty (it is keyed on `enabled`) while the gate was on —
    // every connection masked, the relay's included.
    var cfg_on = try Config.parse(std.testing.allocator,
        \\[server]
        \\port = 4443
        \\[censorship]
        \\tls_domain = "example.com"
        \\[web]
        \\enabled = true
        \\only = true
        \\domain = "relay.example.com"
        \\[access.users]
        \\user1 = "00112233445566778899aabbccddeeff"
    );
    defer cfg_on.deinit(std.testing.allocator);
    try std.testing.expect(cfg_on.web.onlyActive());

    var cfg_off = try Config.parse(std.testing.allocator,
        \\[server]
        \\port = 4443
        \\[censorship]
        \\tls_domain = "example.com"
        \\[web]
        \\enabled = false
        \\only = true
        \\[access.users]
        \\user1 = "00112233445566778899aabbccddeeff"
    );
    defer cfg_off.deinit(std.testing.allocator);
    try std.testing.expect(!cfg_off.web.onlyActive());
}
