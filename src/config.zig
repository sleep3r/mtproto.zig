//! Configuration loading for MTProto proxy.
//!
//! Parses a simplified TOML config with user secrets and server settings.
//! Format is compatible with the Rust telemt config.toml.

const std = @import("std");
const net = std.Io.net;
const default_tls_domain = "google.com";
const default_local_mask_target = "127.0.0.1";

pub const UpstreamMode = enum {
    /// Automatic egress mode (default).
    /// Uses direct routing without socket policy marks.
    auto,
    /// Explicit direct egress.
    direct,
    /// VPN tunnel egress via socket policy routing (SO_MARK/fwmask).
    /// The specific VPN type is an mtbuddy/installer concern.
    tunnel,
    /// SOCKS5 proxy upstream.
    socks5,
    /// HTTP CONNECT proxy upstream.
    http,
};

/// Action for a TLS ClientHello whose SNI doesn't match tls_domain.
pub const UnknownSniAction = enum {
    /// Forward to the masking backend (current default; no wire change).
    mask,
    /// Emit a fatal `handshake_failure` (40) TLS alert (like nginx ssl_reject_handshake),
    /// then close. (Not `unrecognized_name`/112 — see tls.zig reject_handshake_alert.)
    reject,
    /// Close silently with no response.
    drop,
};

fn parseUnknownSniAction(value: []const u8) ?UnknownSniAction {
    if (std.mem.eql(u8, value, "mask")) return .mask;
    if (std.mem.eql(u8, value, "reject")) return .reject;
    if (std.mem.eql(u8, value, "drop")) return .drop;
    return null;
}

/// Parse "YYYY-MM-DD" into the Unix-seconds instant the user EXPIRES — i.e. 00:00 UTC
/// of the day AFTER the named date, so the user stays valid through the whole named
/// UTC date (end-of-day inclusive). Returns null on any malformed / impossible date.
/// (Hinnant's days_from_civil.)
fn parseExpiryToUnix(value: []const u8) ?i64 {
    if (value.len != 10 or value[4] != '-' or value[7] != '-') return null;
    // Digits only — std.fmt.parseInt would otherwise accept '+'/'-' signs.
    for ([_][]const u8{ value[0..4], value[5..7], value[8..10] }) |field| {
        for (field) |c| if (c < '0' or c > '9') return null;
    }
    const y = std.fmt.parseInt(i64, value[0..4], 10) catch return null;
    const m = std.fmt.parseInt(i64, value[5..7], 10) catch return null;
    const d = std.fmt.parseInt(i64, value[8..10], 10) catch return null;
    if (y < 1970 or y > 9999 or m < 1 or m > 12) return null;
    // Reject impossible days (e.g. Feb 31) instead of silently rolling them forward.
    const leap = (@mod(y, 4) == 0 and @mod(y, 100) != 0) or @mod(y, 400) == 0;
    const month_days = [_]i64{ 31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (d < 1 or d > month_days[@intCast(m - 1)]) return null;
    const ym = y - @as(i64, @intFromBool(m <= 2));
    const era = @divFloor(if (ym >= 0) ym else ym - 399, 400);
    const yoe = ym - era * 400;
    const mp: i64 = if (m > 2) m - 3 else m + 9;
    const doy = @divTrunc(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divTrunc(yoe, 4) - @divTrunc(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    return (days + 1) * 86400; // +1 day → expiry at 00:00 UTC the following day
}

fn parseUpstreamMode(value: []const u8) ?UpstreamMode {
    if (std.mem.eql(u8, value, "auto")) return .auto;
    if (std.mem.eql(u8, value, "direct") or std.mem.eql(u8, value, "none")) return .direct;
    if (std.mem.eql(u8, value, "tunnel")) return .tunnel;
    // Backward compatibility: old config values map to .tunnel
    if (std.mem.eql(u8, value, "amnezia_wg") or std.mem.eql(u8, value, "amneziawg")) return .tunnel;
    if (std.mem.eql(u8, value, "wireguard") or std.mem.eql(u8, value, "wg")) return .tunnel;
    if (std.mem.eql(u8, value, "socks5") or std.mem.eql(u8, value, "socks")) return .socks5;
    if (std.mem.eql(u8, value, "http") or std.mem.eql(u8, value, "http_connect")) return .http;
    return null;
}

/// Parse a TOML-ish boolean leniently: true/1/yes/on (and false/0/no/off), case-insensitive.
/// Previously every [server]/[censorship]/etc. bool used `eql(value, "true")`, so `mask = yes`,
/// `mask = 1`, or `fake_tls_only = True` silently became false — a footgun that turned OFF
/// active-probe masking or turned ON the DPI-fingerprintable dd transport. Matches the
/// lenient parsing [access.direct_users] already used.
fn parseBool(value: []const u8) bool {
    return std.ascii.eqlIgnoreCase(value, "true") or
        std.mem.eql(u8, value, "1") or
        std.ascii.eqlIgnoreCase(value, "yes") or
        std.ascii.eqlIgnoreCase(value, "on");
}

fn stripInlineComment(value: []const u8) []const u8 {
    var in_quotes = false;
    var escaped = false;
    var i: usize = 0;

    while (i < value.len) : (i += 1) {
        const ch = value[i];

        if (escaped) {
            escaped = false;
            continue;
        }

        if (in_quotes and ch == '\\') {
            escaped = true;
            continue;
        }

        if (ch == '"') {
            in_quotes = !in_quotes;
            continue;
        }

        if (!in_quotes and (ch == '#' or ch == ';')) {
            return std.mem.trim(u8, value[0..i], &[_]u8{ ' ', '\t' });
        }
    }

    return std.mem.trim(u8, value, &[_]u8{ ' ', '\t' });
}

fn parseStringArrayValue(allocator: std.mem.Allocator, value: []const u8) ![]const []const u8 {
    const trimmed = std.mem.trim(u8, value, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (trimmed.len < 2 or trimmed[0] != '[' or trimmed[trimmed.len - 1] != ']') {
        return error.InvalidStringArray;
    }

    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit(allocator);
    }

    var i: usize = 1;
    while (i + 1 < trimmed.len) {
        while (i + 1 < trimmed.len and (trimmed[i] == ' ' or trimmed[i] == '\t' or trimmed[i] == ',')) : (i += 1) {}
        if (i + 1 >= trimmed.len or trimmed[i] == ']') break;

        if (trimmed[i] == '"') {
            i += 1;
            const start = i;
            var escaped = false;
            while (i < trimmed.len) : (i += 1) {
                if (escaped) {
                    escaped = false;
                    continue;
                }
                if (trimmed[i] == '\\') {
                    escaped = true;
                    continue;
                }
                if (trimmed[i] == '"') break;
            }
            if (i >= trimmed.len or trimmed[i] != '"') return error.InvalidStringArray;
            const item = trimmed[start..i];
            if (item.len > 0) try list.append(allocator, try allocator.dupe(u8, item));
            i += 1;
            continue;
        }

        const start = i;
        while (i < trimmed.len and trimmed[i] != ',' and trimmed[i] != ']') : (i += 1) {}
        const item = std.mem.trim(u8, trimmed[start..i], &[_]u8{ ' ', '\t', '\r', '\n' });
        if (item.len > 0) try list.append(allocator, try allocator.dupe(u8, item));
    }

    if (list.items.len == 0) {
        list.deinit(allocator);
        return &.{};
    }

    return try list.toOwnedSlice(allocator);
}

fn freeStringSlice(allocator: std.mem.Allocator, values: []const []const u8) void {
    if (values.len == 0) return;
    for (values) |value| allocator.free(value);
    allocator.free(values);
}

pub const Config = struct {
    pub const UserSecret = struct { name: []const u8, secret: [16]u8 };
    pub const Metrics = struct {
        enabled: bool = false,
        host: ?[]const u8 = null,
        port: u16 = 9400,

        /// Return bound host, falling back to localhost.
        pub fn effectiveHost(self: *const Metrics) []const u8 {
            return self.host orelse "127.0.0.1";
        }
    };

    /// Route regular DC traffic via Telegram MiddleProxy transport.
    /// Mirrors telemt's [general].use_middle_proxy behavior.
    use_middle_proxy: bool = false,
    /// Force media-path traffic (DC203 / negative dc_idx) through MiddleProxy,
    /// even when use_middle_proxy is false.
    force_media_middle_proxy: bool = true,
    port: u16 = 443,
    /// Bind address for the listen socket.  When null the proxy listens on
    /// all interfaces ([::]  with IPv4 fallback to 0.0.0.0).
    /// Set to a specific IP when sharing the host with other services.
    bind_address: ?[]const u8 = null,
    /// Explicit public IP address. If set, bypasses detection via external services.
    public_ip: ?[]const u8 = null,
    /// Explicit public port shown in generated Telegram client links.
    /// Useful when the proxy listens on an internal HAProxy/backend port.
    public_port: ?u16 = null,
    /// Explicit IPv4 to use in Telegram MiddleProxy AES key derivation.
    /// Useful when `public_ip` is a domain name or when tunnel egress differs
    /// from generic "what is my IP" services.
    middle_proxy_nat_ip: ?[]const u8 = null,
    /// TCP listen(2) backlog for client-facing sockets
    backlog: u32 = 4096,
    /// Hard cap for concurrently handled client connections
    /// Default tuned for 1 vCPU / 1 GB VPS profile.
    max_connections: u32 = 512,
    /// Number of SO_REUSEPORT epoll worker threads. 1 (default) = the classic
    /// single-threaded loop, behavior identical to before. 0 = auto (one per CPU,
    /// clamped). >1 spreads the relay/crypto load across cores; the kernel
    /// load-balances connections across workers. max_connections stays the global
    /// total (workers share it, bounded by the saturation cap).
    workers: u16 = 1,
    /// Pre-handshake idle timeout: wait for first client byte
    idle_timeout_sec: u32 = 120,
    /// Per-connection random jitter (± percent, 0-100) applied to the effective idle
    /// timeout, so a constant timeout isn't itself a behavioral fingerprint. Computed
    /// once per slot. 0 disables jitter.
    idle_timeout_jitter_pct: u8 = 15,
    /// Handshake read timeout after first byte arrives
    handshake_timeout_sec: u32 = 15,
    /// Graceful shutdown drain timeout on SIGTERM.
    /// The proxy stops accepting new clients and drains active relays
    /// for this many seconds before forced close.
    graceful_shutdown_timeout_sec: u32 = 15,
    tag: ?[16]u8 = null,
    /// FakeTLS fronting domain (the SNI clients present).
    ///
    /// ⚠️ IMMUTABLE once links are distributed: the `ee` secret embeds this domain
    /// as hex, so the tg:// link is a function of (secret, tls_domain). Changing
    /// tls_domain changes EVERY user's link — never do it on a live deployment.
    ///
    /// Mimicry note: our 3-record FakeTLS emits ONE ServerHello with an x25519
    /// key_share and cannot replicate a HelloRetryRequest. Pick a domain whose
    /// genuine TLS 1.3 negotiates **x25519 in a single round** (most big sites:
    /// rutube.ru, ozon.ru, vk.com, yandex.ru, dzen.ru). Domains that prefer
    /// secp521r1 / reject x25519 and HRR (e.g. wb.ru, mail.ru) produce a passive
    /// ServerHello mismatch that cannot be fixed without changing tls_domain —
    /// which the immutability rule above forbids. So choose well at install time.
    /// See ARCHITECTURE.md "FakeTLS fronting & domain selection".
    tls_domain: []const u8 = default_tls_domain,
    users: std.StringHashMap([16]u8),
    /// Users that always bypass MiddleProxy and connect to DC directly.
    /// Section: [access.direct_users] (alias: [access.admins])
    direct_users: std.StringHashMap(void),
    /// Optional per-user concurrent-connection caps. Section [access.user_max_conns]
    /// (name = N). null/absent = no cap. Read at startup; changing it needs a restart
    /// (a SIGHUP reload does not pick it up).
    user_max_conns: ?std.StringHashMap(u32) = null,
    /// Optional per-user expiry. Section [access.user_expirations] (name = "YYYY-MM-DD",
    /// end-of-day inclusive). null/absent = never expires. Read at startup; changing it
    /// needs a restart.
    user_expirations: ?std.StringHashMap(i64) = null,
    /// Whether to mask bad clients (forward to tls_domain)
    mask: bool = true,
    /// Optional backend host for masked clients. When unset, mask_port=443 uses
    /// tls_domain and non-443 mask ports use the local Nginx target.
    mask_target: ?[]const u8 = null,
    /// Port used by the masking backend.
    mask_port: u16 = 443,
    /// Reject the non-TLS "direct obfuscated" (dd / secure) transport. When true
    /// (the default), only FakeTLS (ee) clients are accepted and any non-TLS
    /// first bytes are masked immediately — eliminating the dd active-probe
    /// distinguisher. This is the secure default for a TLS-camouflage proxy: dd
    /// is plain, DPI-fingerprintable MTProto. Set to false ONLY if you need to
    /// hand out dd links (lower-DPI / compatibility scenarios).
    fake_tls_only: bool = true,
    /// What to do with a TLS ClientHello whose SNI doesn't match tls_domain:
    /// `mask` (default — forward to the masking backend, current behavior),
    /// `reject` (emit a fatal `handshake_failure` TLS alert like nginx
    /// ssl_reject_handshake, then close), or `drop` (silent close). Default keeps the wire unchanged.
    unknown_sni_action: UnknownSniAction = .mask,
    /// When `unknown_sni_action = reject`, reset the connection (TCP RST via
    /// SO_LINGER{0}) instead of sending a fatal alert + FIN. Some fronted CDNs /
    /// middleboxes RST a bad handshake where nginx `ssl_reject_handshake` sends a
    /// fatal alert; pick whichever your masked domain actually does. Default off.
    reject_rst: bool = false,
    /// TCP desync: split ServerHello into 1-byte + rest to evade DPI
    desync: bool = true,
    /// Base delay (ms) between the 1-byte desync split and the rest of the ServerHello.
    desync_split_delay_ms: u32 = 3,
    /// Random extra delay (0..jitter ms) added to desync_split_delay_ms per connection.
    /// A *fixed* split gap is itself a passive timing fingerprint; jitter removes it.
    desync_split_jitter_ms: u32 = 3,
    /// Dynamic Record Sizing: ramp TLS records from 1369→16384 bytes
    drs: bool = false,
    /// Fast mode: skip S2C encryption by passing client keys to DC directly
    fast_mode: bool = false,
    /// MiddleProxy stream buffer size in KiB.
    /// In current design, each connection keeps 2 such buffers and EventLoop
    /// keeps 2 shared scratch buffers.
    /// Must exceed the largest single RPC_PROXY_ANS frame. A max download part is 1 MiB
    /// of payload plus MTProto + RPC framing, so a 1024 KiB buffer is just too small and
    /// truncates 1 MiB-part media downloads (Stories, video messages). Default 2048 gives
    /// headroom; oversized frames now close the connection cleanly rather than stalling.
    middleproxy_buffer_kb: u32 = 2048,
    /// Runtime log level: "debug", "info" (default), "warn", "err"
    log_level: std.log.Level = .info,
    /// Max new connections per second per /24 (IPv4) or /48 (IPv6) subnet
    /// (0 = disabled, the default). Disabled by default because the target
    /// audience sits behind heavy carrier-grade NAT where many legitimate users
    /// share one subnet — a per-subnet new-connection cap false-positives on
    /// exactly those users, which for a censorship-circumvention tool is worse
    /// than the flood it prevents. Access is already gated by the per-user
    /// secret, the global handshake-inflight budget, and max_connections. Set a
    /// value (e.g. 30) to re-enable for single-tenant / non-NAT deployments.
    rate_limit_per_subnet: u8 = 0,
    /// Exact-IP handshake flood guard: temporarily denies clients that repeatedly hit
    /// handshake timeouts, subnet rate limits, or the handshake budget. Off by default
    /// — like rate_limit_per_subnet it false-positives on carrier-NAT / VPN-egress /
    /// shared IPs, where many legitimate clients share one source IP and get blocked
    /// together. Access is already gated by the per-user secret, the handshake-inflight
    /// budget, and max_connections. Set true (and tune threshold/window/block) on a
    /// single-tenant / non-NAT host under real abuse.
    handshake_flood_guard_enabled: bool = false,
    handshake_flood_guard_threshold: u16 = 20,
    handshake_flood_guard_window_sec: u16 = 30,
    handshake_flood_guard_block_sec: u16 = 120,
    /// When true, disables auto-clamping of max_connections to the RAM-safe estimate.
    /// Use only if you know your host has enough memory for the configured limits.
    unsafe_override_limits: bool = false,
    /// Test-only hook to redirect upstream connections locally
    datacenter_override: ?net.IpAddress = null,
    /// Upstream egress mode. Parsed from [upstream].type.
    /// Supported values: auto | direct | tunnel | socks5 | http.
    upstream_mode: UpstreamMode = .auto,
    /// Allow fallback to direct egress when explicit upstream mode
    /// (socks5/http) is misconfigured or unavailable.
    allow_direct_fallback: bool = false,
    /// Proxy server host for socks5/http upstream modes.
    /// Parsed from [upstream.socks5].host or [upstream.http].host.
    upstream_proxy_host: ?[]const u8 = null,
    /// Proxy server port for socks5/http upstream modes.
    upstream_proxy_port: u16 = 0,
    /// Proxy authentication username (empty string = no auth).
    upstream_proxy_username: ?[]const u8 = null,
    /// Proxy authentication password.
    upstream_proxy_password: ?[]const u8 = null,
    /// VPN tunnel interface name (e.g. "awg0", "wg0").
    /// Parsed from [upstream.tunnel].interface.
    upstream_tunnel_interface: ?[]const u8 = null,
    /// Ordered VPN tunnel pool. Parsed from [upstream.tunnel].interfaces.
    upstream_tunnel_interfaces: []const []const u8 = &.{},
    /// Optional manually preferred tunnel from the pool.
    /// Parsed from [upstream.tunnel].pinned_interface.
    upstream_tunnel_pinned_interface: ?[]const u8 = null,
    metrics: Metrics = .{},

    pub fn middleProxyBufferBytes(self: *const Config) usize {
        return @as(usize, self.middleproxy_buffer_kb) * 1024;
    }

    pub fn ownsTlsDomain(self: *const Config) bool {
        return self.tls_domain.ptr != default_tls_domain.ptr;
    }

    pub fn ownsMaskTarget(self: *const Config) bool {
        return self.mask_target != null;
    }

    pub fn effectiveMaskTarget(self: *const Config) []const u8 {
        if (self.mask_target) |target| return target;
        if (self.mask_port == 443) return self.tls_domain;
        return default_local_mask_target;
    }

    pub fn maskTargetIsLocal(self: *const Config) bool {
        const target = self.effectiveMaskTarget();
        return std.mem.eql(u8, target, default_local_mask_target) or
            std.mem.eql(u8, target, "localhost") or
            std.mem.eql(u8, target, "::1");
    }

    /// Port to advertise in generated client links.
    pub fn publicLinkPort(self: *const Config) u16 {
        return self.public_port orelse self.port;
    }

    pub fn userBypassesMiddleProxy(self: *const Config, user_name: []const u8) bool {
        return self.direct_users.contains(user_name);
    }

    pub fn tunnelInterfaceCount(self: *const Config) usize {
        if (self.upstream_tunnel_interfaces.len > 0) return self.upstream_tunnel_interfaces.len;
        return 1;
    }

    pub fn tunnelInterfaceAt(self: *const Config, index: usize) ?[]const u8 {
        if (self.upstream_tunnel_interfaces.len > 0) {
            if (index >= self.upstream_tunnel_interfaces.len) return null;
            return self.upstream_tunnel_interfaces[index];
        }
        if (index == 0) return self.upstream_tunnel_interface orelse "awg0";
        return null;
    }

    pub fn tunnelCandidateCount(self: *const Config) usize {
        const base = self.tunnelInterfaceCount();
        const pinned = self.upstream_tunnel_pinned_interface orelse return base;
        var found = false;
        var i: usize = 0;
        while (self.tunnelInterfaceAt(i)) |iface| : (i += 1) {
            if (std.mem.eql(u8, iface, pinned)) {
                found = true;
                break;
            }
        }
        return if (found) base else base + 1;
    }

    pub fn tunnelCandidateAt(self: *const Config, index: usize) ?[]const u8 {
        if (self.upstream_tunnel_pinned_interface) |pinned| {
            if (index == 0) return pinned;
            var candidate_idx: usize = 1;
            var i: usize = 0;
            while (self.tunnelInterfaceAt(i)) |iface| : (i += 1) {
                if (std.mem.eql(u8, iface, pinned)) continue;
                if (candidate_idx == index) return iface;
                candidate_idx += 1;
            }
            return null;
        }
        return self.tunnelInterfaceAt(index);
    }

    /// Port collision exists only when masking points to a local endpoint.
    /// With mask_port=443, masking targets tls_domain:443 (remote), so no local bind clash.
    pub fn hasLocalMaskPortCollision(self: *const Config) bool {
        return self.mask and self.maskTargetIsLocal() and self.port == self.mask_port;
    }

    /// Emit startup warnings for configuration values known to cause issues.
    pub fn emitWarnings(self: *const Config) void {
        if (self.hasLocalMaskPortCollision()) {
            const log = std.log.scoped(.config);
            log.err(
                "proxy port ({d}) equals mask_port ({d}). The proxy listen socket " ++
                    "will collide with the local masking server (Nginx). " ++
                    "Change [server].port or [censorship].mask_port so they differ.",
                .{ self.port, self.mask_port },
            );
        }
        if (self.use_middle_proxy and self.middleproxy_buffer_kb < 1024) {
            const log = std.log.scoped(.config);
            log.warn(
                "middleproxy_buffer_kb={d} is below recommended minimum (1024). " ++
                    "This may cause MiddleProxyBufferOverflow errors on media-heavy " ++
                    "traffic (Stories, video downloads). Consider increasing to 1024+.",
                .{self.middleproxy_buffer_kb},
            );
        }
        if (self.use_middle_proxy and self.max_connections > 2000) {
            const log = std.log.scoped(.config);
            const mem_per_conn_mb = (self.middleProxyBufferBytes() * 2) / (1024 * 1024);
            const shared_mb = (self.middleProxyBufferBytes() * 2) / (1024 * 1024);
            log.warn(
                "max_connections={d} with middleproxy_buffer_kb={d} may require " ++
                    "up to {d} MB + {d} MB shared RAM at full capacity. Ensure your VPS has sufficient memory.",
                .{ self.max_connections, self.middleproxy_buffer_kb, mem_per_conn_mb * self.max_connections, shared_mb },
            );
        }

        if (self.direct_users.count() > 0) {
            const log = std.log.scoped(.config);
            var it = @constCast(&self.direct_users).iterator();
            while (it.next()) |entry| {
                if (!self.users.contains(entry.key_ptr.*)) {
                    log.warn(
                        "access.direct_users contains unknown user '{s}' (missing in [access.users]); entry will be ignored",
                        .{entry.key_ptr.*},
                    );
                }
            }
        }
    }

    pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !Config {
        const io = std.Io.Threaded.global_single_threaded.io();
        const content = try std.Io.Dir.cwd().readFileAlloc(
            io,
            path,
            allocator,
            .limited(1024 * 1024),
        );
        defer allocator.free(content);
        return parse(allocator, content);
    }

    pub fn parse(allocator: std.mem.Allocator, content: []const u8) !Config {
        var cfg = Config{
            .users = std.StringHashMap([16]u8).init(allocator),
            .direct_users = std.StringHashMap(void).init(allocator),
        };
        errdefer cfg.deinit(allocator);

        var lines = std.mem.splitScalar(u8, content, '\n');
        var in_users_section = false;
        var in_direct_users_section = false;
        var in_user_max_conns_section = false;
        var in_user_expirations_section = false;
        var in_censorship_section = false;
        var in_server_section = false;
        var in_general_section = false;
        var in_metrics_section = false;
        var in_upstream_section = false;
        var in_upstream_socks5_section = false;
        var in_upstream_http_section = false;
        var in_upstream_tunnel_section = false;
        var server_tag_set = false;

        while (lines.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, &[_]u8{ ' ', '\t', '\r' });

            // Skip empty lines and comments
            if (line.len == 0 or line[0] == '#') continue;

            // Section headers
            if (line[0] == '[') {
                // Strip a trailing inline comment ("[server] # main settings") and spaces
                // before matching — otherwise a TOML-legal commented header matches no
                // section and every key until the next header is silently dropped (e.g.
                // [access.users] # mine → zero users).
                var header = line;
                if (std.mem.indexOfScalar(u8, header, '#')) |h| header = header[0..h];
                header = std.mem.trim(u8, header, &[_]u8{ ' ', '\t', '\r' });
                in_users_section = std.mem.eql(u8, header, "[access.users]");
                in_direct_users_section = std.mem.eql(u8, header, "[access.direct_users]") or std.mem.eql(u8, header, "[access.admins]");
                in_user_max_conns_section = std.mem.eql(u8, header, "[access.user_max_conns]");
                in_user_expirations_section = std.mem.eql(u8, header, "[access.user_expirations]");
                in_censorship_section = std.mem.eql(u8, header, "[censorship]");
                in_server_section = std.mem.eql(u8, header, "[server]");
                in_general_section = std.mem.eql(u8, header, "[general]");
                in_metrics_section = std.mem.eql(u8, header, "[metrics]");
                in_upstream_section = std.mem.eql(u8, header, "[upstream]");
                in_upstream_socks5_section = std.mem.eql(u8, header, "[upstream.socks5]");
                in_upstream_http_section = std.mem.eql(u8, header, "[upstream.http]");
                in_upstream_tunnel_section = std.mem.eql(u8, header, "[upstream.tunnel]");
                // Sub-sections are also part of the upstream family;
                // entering a sub-section should not reset the parent.
                if (in_upstream_socks5_section or in_upstream_http_section or in_upstream_tunnel_section) {
                    in_upstream_section = false;
                }
                continue;
            }

            // Key = value parsing
            if (std.mem.indexOfScalar(u8, line, '=')) |eq_pos| {
                const key = std.mem.trim(u8, line[0..eq_pos], &[_]u8{ ' ', '\t' });
                var value = std.mem.trim(u8, line[eq_pos + 1 ..], &[_]u8{ ' ', '\t' });
                value = stripInlineComment(value);
                if (value.len == 0) continue;

                // Strip quotes from value
                if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                    value = value[1 .. value.len - 1];
                }

                if (in_users_section) {
                    // Parse user secret (32 hex chars = 16 bytes)
                    if (value.len != 32) return error.InvalidUserSecretLength;
                    var secret: [16]u8 = undefined;
                    _ = std.fmt.hexToBytes(&secret, value) catch return error.InvalidUserSecretHex;
                    // On a duplicate user name, update the value in place and keep
                    // the already-owned key (put with an existing key does not
                    // retain the passed key), so we don't leak a fresh dupe.
                    if (cfg.users.contains(key)) {
                        try cfg.users.put(key, secret);
                    } else {
                        const name = try allocator.dupe(u8, key);
                        try cfg.users.put(name, secret);
                    }
                } else if (in_direct_users_section) {
                    if (!parseBool(value)) continue;
                    if (!cfg.direct_users.contains(key)) {
                        const name = try allocator.dupe(u8, key);
                        try cfg.direct_users.put(name, {});
                    }
                } else if (in_user_max_conns_section) {
                    const cap = std.fmt.parseInt(u32, value, 10) catch continue;
                    if (cap == 0) continue; // 0 == no limit
                    if (cfg.user_max_conns == null) cfg.user_max_conns = std.StringHashMap(u32).init(allocator);
                    if (cfg.user_max_conns.?.getKey(key)) |_| {
                        try cfg.user_max_conns.?.put(key, cap);
                    } else {
                        try cfg.user_max_conns.?.put(try allocator.dupe(u8, key), cap);
                    }
                } else if (in_user_expirations_section) {
                    const ts = parseExpiryToUnix(value) orelse continue;
                    if (cfg.user_expirations == null) cfg.user_expirations = std.StringHashMap(i64).init(allocator);
                    if (cfg.user_expirations.?.getKey(key)) |_| {
                        try cfg.user_expirations.?.put(key, ts);
                    } else {
                        try cfg.user_expirations.?.put(try allocator.dupe(u8, key), ts);
                    }
                } else if (in_general_section) {
                    if (std.mem.eql(u8, key, "use_middle_proxy")) {
                        cfg.use_middle_proxy = parseBool(value);
                    } else if (std.mem.eql(u8, key, "force_media_middle_proxy")) {
                        cfg.force_media_middle_proxy = parseBool(value);
                    } else if (std.mem.eql(u8, key, "fast_mode")) {
                        // telemt compatibility: [general].fast_mode
                        cfg.fast_mode = parseBool(value);
                    } else if (std.mem.eql(u8, key, "ad_tag")) {
                        // telemt compatibility: [general].ad_tag
                        // If [server].tag is present and valid, it has priority.
                        if (!server_tag_set and value.len == 32) {
                            var tag: [16]u8 = undefined;
                            if (std.fmt.hexToBytes(&tag, value)) |_| {
                                cfg.tag = tag;
                            } else |_| {}
                        }
                    }
                } else if (in_server_section) {
                    if (std.mem.eql(u8, key, "port")) {
                        cfg.port = std.fmt.parseInt(u16, value, 10) catch blk: {
                            std.log.scoped(.config).warn("invalid server.port \"{s}\"; falling back to 443", .{value});
                            break :blk 443;
                        };
                    } else if (std.mem.eql(u8, key, "bind_address")) {
                        if (cfg.bind_address) |prev| allocator.free(prev);
                        cfg.bind_address = try allocator.dupe(u8, value);
                    } else if (std.mem.eql(u8, key, "backlog")) {
                        cfg.backlog = std.fmt.parseInt(u32, value, 10) catch 4096;
                    } else if (std.mem.eql(u8, key, "max_connections")) {
                        const parsed = std.fmt.parseInt(u32, value, 10) catch cfg.max_connections;
                        cfg.max_connections = @max(@as(u32, 32), parsed);
                    } else if (std.mem.eql(u8, key, "workers")) {
                        cfg.workers = std.fmt.parseInt(u16, value, 10) catch cfg.workers;
                    } else if (std.mem.eql(u8, key, "idle_timeout_sec")) {
                        const parsed = std.fmt.parseInt(u32, value, 10) catch cfg.idle_timeout_sec;
                        cfg.idle_timeout_sec = @max(@as(u32, 5), parsed);
                    } else if (std.mem.eql(u8, key, "handshake_timeout_sec")) {
                        const parsed = std.fmt.parseInt(u32, value, 10) catch cfg.handshake_timeout_sec;
                        cfg.handshake_timeout_sec = @max(@as(u32, 5), parsed);
                    } else if (std.mem.eql(u8, key, "graceful_shutdown_timeout_sec")) {
                        const parsed = std.fmt.parseInt(u32, value, 10) catch cfg.graceful_shutdown_timeout_sec;
                        cfg.graceful_shutdown_timeout_sec = @max(@as(u32, 1), parsed);
                    } else if (std.mem.eql(u8, key, "tag")) {
                        if (value.len == 32) {
                            var tag: [16]u8 = undefined;
                            if (std.fmt.hexToBytes(&tag, value)) |_| {
                                cfg.tag = tag;
                                server_tag_set = true;
                            } else |_| {}
                        }
                    } else if (std.mem.eql(u8, key, "public_ip")) {
                        if (cfg.public_ip) |prev| allocator.free(prev);
                        cfg.public_ip = try allocator.dupe(u8, value);
                    } else if (std.mem.eql(u8, key, "public_port")) {
                        const parsed = std.fmt.parseInt(u16, value, 10) catch 0;
                        if (parsed > 0) cfg.public_port = parsed;
                    } else if (std.mem.eql(u8, key, "middle_proxy_nat_ip")) {
                        if (cfg.middle_proxy_nat_ip) |prev| allocator.free(prev);
                        cfg.middle_proxy_nat_ip = try allocator.dupe(u8, value);
                    } else if (std.mem.eql(u8, key, "fast_mode")) {
                        cfg.fast_mode = parseBool(value);
                    } else if (std.mem.eql(u8, key, "middleproxy_buffer_kb")) {
                        const parsed = std.fmt.parseInt(u32, value, 10) catch cfg.middleproxy_buffer_kb;
                        cfg.middleproxy_buffer_kb = @max(@as(u32, 64), parsed);
                    } else if (std.mem.eql(u8, key, "log_level")) {
                        if (std.mem.eql(u8, value, "debug")) {
                            cfg.log_level = .debug;
                        } else if (std.mem.eql(u8, value, "info")) {
                            cfg.log_level = .info;
                        } else if (std.mem.eql(u8, value, "warn")) {
                            cfg.log_level = .warn;
                        } else if (std.mem.eql(u8, value, "err")) {
                            cfg.log_level = .err;
                        }
                    } else if (std.mem.eql(u8, key, "rate_limit_per_subnet")) {
                        cfg.rate_limit_per_subnet = std.fmt.parseInt(u8, value, 10) catch cfg.rate_limit_per_subnet;
                    } else if (std.mem.eql(u8, key, "handshake_flood_guard_enabled")) {
                        cfg.handshake_flood_guard_enabled = parseBool(value);
                    } else if (std.mem.eql(u8, key, "handshake_flood_guard_threshold")) {
                        const parsed = std.fmt.parseInt(u16, value, 10) catch cfg.handshake_flood_guard_threshold;
                        cfg.handshake_flood_guard_threshold = @max(@as(u16, 1), parsed);
                    } else if (std.mem.eql(u8, key, "handshake_flood_guard_window_sec")) {
                        const parsed = std.fmt.parseInt(u16, value, 10) catch cfg.handshake_flood_guard_window_sec;
                        cfg.handshake_flood_guard_window_sec = @max(@as(u16, 1), parsed);
                    } else if (std.mem.eql(u8, key, "handshake_flood_guard_block_sec")) {
                        const parsed = std.fmt.parseInt(u16, value, 10) catch cfg.handshake_flood_guard_block_sec;
                        cfg.handshake_flood_guard_block_sec = @max(@as(u16, 1), parsed);
                    } else if (std.mem.eql(u8, key, "idle_timeout_jitter_pct")) {
                        const parsed = std.fmt.parseInt(u8, value, 10) catch cfg.idle_timeout_jitter_pct;
                        cfg.idle_timeout_jitter_pct = @min(@as(u8, 100), parsed);
                    } else if (std.mem.eql(u8, key, "unsafe_override_limits")) {
                        cfg.unsafe_override_limits = parseBool(value);
                    }
                } else if (in_censorship_section) {
                    if (std.mem.eql(u8, key, "tls_domain")) {
                        // The top-level empty-value guard runs BEFORE quote
                        // stripping, so `tls_domain = ""` reaches here as an empty
                        // string. An empty FakeTLS domain silently breaks SNI
                        // matching and masking — reject it loudly instead.
                        if (value.len == 0) return error.EmptyTlsDomain;
                        // Free the previous heap dupe (but never the compile-time
                        // default) before overwriting, so a duplicate tls_domain
                        // key does not leak.
                        if (cfg.tls_domain.ptr != default_tls_domain.ptr) allocator.free(cfg.tls_domain);
                        cfg.tls_domain = try allocator.dupe(u8, value);
                    } else if (std.mem.eql(u8, key, "mask")) {
                        cfg.mask = parseBool(value);
                    } else if (std.mem.eql(u8, key, "mask_target")) {
                        if (cfg.mask_target) |target| allocator.free(target);
                        cfg.mask_target = if (value.len > 0) try allocator.dupe(u8, value) else null;
                    } else if (std.mem.eql(u8, key, "mask_port")) {
                        cfg.mask_port = std.fmt.parseInt(u16, value, 10) catch 443;
                    } else if (std.mem.eql(u8, key, "desync")) {
                        cfg.desync = parseBool(value);
                    } else if (std.mem.eql(u8, key, "desync_split_delay_ms")) {
                        cfg.desync_split_delay_ms = std.fmt.parseInt(u32, value, 10) catch cfg.desync_split_delay_ms;
                    } else if (std.mem.eql(u8, key, "desync_split_jitter_ms")) {
                        cfg.desync_split_jitter_ms = std.fmt.parseInt(u32, value, 10) catch cfg.desync_split_jitter_ms;
                    } else if (std.mem.eql(u8, key, "fake_tls_only")) {
                        cfg.fake_tls_only = parseBool(value);
                    } else if (std.mem.eql(u8, key, "drs")) {
                        cfg.drs = parseBool(value);
                    } else if (std.mem.eql(u8, key, "fast_mode")) {
                        cfg.fast_mode = parseBool(value);
                    } else if (std.mem.eql(u8, key, "unknown_sni_action")) {
                        if (parseUnknownSniAction(value)) |action| cfg.unknown_sni_action = action;
                    } else if (std.mem.eql(u8, key, "reject_rst")) {
                        cfg.reject_rst = parseBool(value);
                    }
                } else if (in_metrics_section) {
                    if (std.mem.eql(u8, key, "enabled")) {
                        cfg.metrics.enabled = parseBool(value);
                    } else if (std.mem.eql(u8, key, "host")) {
                        if (cfg.metrics.host) |prev| allocator.free(prev);
                        cfg.metrics.host = try allocator.dupe(u8, value);
                    } else if (std.mem.eql(u8, key, "port")) {
                        cfg.metrics.port = std.fmt.parseInt(u16, value, 10) catch cfg.metrics.port;
                    }
                } else if (in_upstream_section) {
                    if (std.mem.eql(u8, key, "type")) {
                        if (parseUpstreamMode(value)) |mode| {
                            cfg.upstream_mode = mode;
                        }
                    } else if (std.mem.eql(u8, key, "allow_direct_fallback")) {
                        cfg.allow_direct_fallback = parseBool(value);
                    }
                } else if (in_upstream_socks5_section or in_upstream_http_section) {
                    if (std.mem.eql(u8, key, "host")) {
                        if (cfg.upstream_proxy_host) |h| allocator.free(h);
                        cfg.upstream_proxy_host = try allocator.dupe(u8, value);
                    } else if (std.mem.eql(u8, key, "port")) {
                        cfg.upstream_proxy_port = std.fmt.parseInt(u16, value, 10) catch 0;
                    } else if (std.mem.eql(u8, key, "username")) {
                        if (cfg.upstream_proxy_username) |u| allocator.free(u);
                        cfg.upstream_proxy_username = try allocator.dupe(u8, value);
                    } else if (std.mem.eql(u8, key, "password")) {
                        if (cfg.upstream_proxy_password) |p| allocator.free(p);
                        cfg.upstream_proxy_password = try allocator.dupe(u8, value);
                    }
                } else if (in_upstream_tunnel_section) {
                    if (std.mem.eql(u8, key, "interface")) {
                        if (cfg.upstream_tunnel_interface) |prev| allocator.free(prev);
                        cfg.upstream_tunnel_interface = try allocator.dupe(u8, value);
                    } else if (std.mem.eql(u8, key, "interfaces")) {
                        freeStringSlice(allocator, cfg.upstream_tunnel_interfaces);
                        cfg.upstream_tunnel_interfaces = parseStringArrayValue(allocator, value) catch &.{};
                    } else if (std.mem.eql(u8, key, "pinned_interface")) {
                        if (cfg.upstream_tunnel_pinned_interface) |iface| allocator.free(iface);
                        cfg.upstream_tunnel_pinned_interface = if (value.len > 0) try allocator.dupe(u8, value) else null;
                    }
                }
            }
        }

        return cfg;
    }

    pub fn deinit(self: *const Config, allocator: std.mem.Allocator) void {
        var users = @constCast(&self.users);
        var it = users.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        users.deinit();

        var direct_users = @constCast(&self.direct_users);
        var direct_it = direct_users.iterator();
        while (direct_it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        direct_users.deinit();

        if (self.user_max_conns) |maxc| {
            var m = @constCast(&maxc);
            var mit = m.iterator();
            while (mit.next()) |entry| allocator.free(entry.key_ptr.*);
            m.deinit();
        }
        if (self.user_expirations) |exps| {
            var e = @constCast(&exps);
            var eit = e.iterator();
            while (eit.next()) |entry| allocator.free(entry.key_ptr.*);
            e.deinit();
        }

        // Free tls_domain only when it does not point to the compile-time default.
        if (self.tls_domain.ptr != default_tls_domain.ptr) {
            allocator.free(self.tls_domain);
        }
        if (self.mask_target) |target| {
            allocator.free(target);
        }
        if (self.public_ip) |ip| {
            allocator.free(ip);
        }
        if (self.middle_proxy_nat_ip) |ip| {
            allocator.free(ip);
        }
        if (self.upstream_proxy_host) |h| {
            allocator.free(h);
        }
        if (self.upstream_proxy_username) |u| {
            allocator.free(u);
        }
        if (self.upstream_proxy_password) |p| {
            allocator.free(p);
        }
        if (self.upstream_tunnel_interface) |iface| {
            allocator.free(iface);
        }
        freeStringSlice(allocator, self.upstream_tunnel_interfaces);
        if (self.upstream_tunnel_pinned_interface) |iface| {
            allocator.free(iface);
        }
        if (self.bind_address) |ba| {
            allocator.free(ba);
        }
        if (self.metrics.host) |h| {
            allocator.free(h);
        }
    }

    /// Get user secrets as a flat slice for handshake validation.
    pub fn getUserSecrets(self: *const Config, allocator: std.mem.Allocator) ![]const UserSecret {
        var list: std.ArrayList(UserSecret) = .empty;
        var it = @constCast(&self.users).iterator();
        while (it.next()) |entry| {
            try list.append(allocator, .{
                .name = entry.key_ptr.*,
                .secret = entry.value_ptr.*,
            });
        }
        return try list.toOwnedSlice(allocator);
    }
};

// ============= Tests =============

test "parse config - valid complete" {
    const content =
        \\[general]
        \\use_middle_proxy = true
        \\
        \\[server]
        \\port = 8443
        \\public_port = 443
        \\backlog = 8192
        \\max_connections = 6000
        \\idle_timeout_sec = 180
        \\handshake_timeout_sec = 30
        \\fast_mode = true
        \\
        \\[censorship]
        \\tls_domain = "example.com"
        \\mask = true
        \\desync = true
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
        \\bob = "ffeeddccbbaa99887766554433221100"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 8443), cfg.port);
    try std.testing.expectEqual(@as(u16, 443), cfg.public_port.?);
    try std.testing.expectEqual(@as(u16, 443), cfg.publicLinkPort());
    try std.testing.expectEqual(@as(u32, 8192), cfg.backlog);
    try std.testing.expectEqual(@as(u32, 6000), cfg.max_connections);
    try std.testing.expectEqual(@as(u32, 180), cfg.idle_timeout_sec);
    try std.testing.expectEqual(@as(u32, 30), cfg.handshake_timeout_sec);
    try std.testing.expectEqualStrings("example.com", cfg.tls_domain);
    try std.testing.expect(cfg.use_middle_proxy);
    try std.testing.expect(cfg.mask);
    try std.testing.expect(cfg.desync);
    try std.testing.expect(cfg.fast_mode);
    try std.testing.expectEqual(@as(usize, 2), cfg.users.count());

    const alice_secret = cfg.users.get("alice").?;
    try std.testing.expectEqual([_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, alice_secret);
}

test "parse config - missing fields defaults" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 443), cfg.port);
    try std.testing.expect(cfg.public_port == null);
    try std.testing.expectEqual(@as(u16, 443), cfg.publicLinkPort());
    try std.testing.expectEqual(@as(u32, 4096), cfg.backlog); // Default is 4096
    try std.testing.expectEqual(@as(u32, 512), cfg.max_connections);
    try std.testing.expectEqual(@as(u32, 120), cfg.idle_timeout_sec);
    try std.testing.expectEqual(@as(u32, 15), cfg.handshake_timeout_sec);
    try std.testing.expectEqual(@as(u32, 15), cfg.graceful_shutdown_timeout_sec);
    try std.testing.expectEqualStrings("google.com", cfg.tls_domain);
    try std.testing.expect(cfg.mask_target == null);
    try std.testing.expect(!cfg.use_middle_proxy); // Default is false
    try std.testing.expect(cfg.mask); // Default is true
    try std.testing.expect(cfg.desync); // Default is true
    try std.testing.expect(!cfg.fast_mode); // Default is false
    try std.testing.expect(cfg.fake_tls_only); // Default is true (secure: dd off)
    try std.testing.expectEqual(@as(u32, 2048), cfg.middleproxy_buffer_kb);
    try std.testing.expectEqual(@as(usize, 2048 * 1024), cfg.middleProxyBufferBytes());
    try std.testing.expectEqual(@as(u8, 0), cfg.rate_limit_per_subnet); // Default 0 (disabled)
    try std.testing.expect(!cfg.handshake_flood_guard_enabled);
    try std.testing.expectEqual(@as(u16, 20), cfg.handshake_flood_guard_threshold);
    try std.testing.expectEqual(@as(u16, 30), cfg.handshake_flood_guard_window_sec);
    try std.testing.expectEqual(@as(u16, 120), cfg.handshake_flood_guard_block_sec);
    try std.testing.expect(!cfg.unsafe_override_limits);
    try std.testing.expect(!cfg.metrics.enabled);
    try std.testing.expect(cfg.metrics.host == null);
    try std.testing.expectEqual(@as(u16, 9400), cfg.metrics.port);
    try std.testing.expectEqual(@as(usize, 1), cfg.users.count());
    try std.testing.expectEqual(@as(usize, 0), cfg.direct_users.count());
}

test "parse config - custom mask target" {
    const content =
        \\[censorship]
        \\tls_domain = "example.com"
        \\mask = true
        \\mask_target = "host.docker.internal"
        \\mask_port = 4443
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("host.docker.internal", cfg.mask_target.?);
    try std.testing.expectEqualStrings("host.docker.internal", cfg.effectiveMaskTarget());
    try std.testing.expectEqual(@as(u16, 4443), cfg.mask_port);
}

test "parse config - metrics section" {
    const content =
        \\[metrics]
        \\enabled = true
        \\host = "0.0.0.0"
        \\port = 9200
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.metrics.enabled);
    try std.testing.expectEqualStrings("0.0.0.0", cfg.metrics.host.?);
    try std.testing.expectEqual(@as(u16, 9200), cfg.metrics.port);
}

test "local mask collision check ignores default remote masking port" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .mask = true,
        .port = 443,
        .mask_port = 443,
    };
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expect(!cfg.hasLocalMaskPortCollision());
}

test "local mask collision check detects local nginx clash" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .mask = true,
        .port = 8443,
        .mask_port = 8443,
    };
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expect(cfg.hasLocalMaskPortCollision());
}

test "local mask collision check ignores custom non-local target" {
    const target = try std.testing.allocator.dupe(u8, "host.docker.internal");
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .mask = true,
        .port = 8443,
        .mask_target = target,
        .mask_port = 8443,
    };
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expect(!cfg.hasLocalMaskPortCollision());
}

test "parse config - direct users allowlist" {
    const content =
        \\[access.users]
        \\admin = "00112233445566778899aabbccddeeff"
        \\regular = "aabbccddeeff00112233445566778899"
        \\[access.direct_users]
        \\admin = true
        \\regular = false
        \\ghost = true
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), cfg.direct_users.count());
    try std.testing.expect(cfg.userBypassesMiddleProxy("admin"));
    try std.testing.expect(!cfg.userBypassesMiddleProxy("regular"));
    try std.testing.expect(cfg.userBypassesMiddleProxy("ghost"));
}

test "parse config - access admins alias" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
        \\[access.admins]
        \\alice = true
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.userBypassesMiddleProxy("alice"));
}

test "parse config - middleproxy buffer size" {
    const content =
        \\[server]
        \\middleproxy_buffer_kb = 192
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 192), cfg.middleproxy_buffer_kb);
    try std.testing.expectEqual(@as(usize, 192 * 1024), cfg.middleProxyBufferBytes());
}

test "parse config - middleproxy buffer lower bound" {
    const content =
        \\[server]
        \\middleproxy_buffer_kb = 16
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 64), cfg.middleproxy_buffer_kb);
}

test "parse config - log_level debug" {
    const content =
        \\[server]
        \\log_level = "debug"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(std.log.Level.debug, cfg.log_level);
}

test "parse config - log_level warn" {
    const content =
        \\[server]
        \\log_level = "warn"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(std.log.Level.warn, cfg.log_level);
}

test "parse config - log_level default is info" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(std.log.Level.info, cfg.log_level);
}

test "parse config - server runtime tunables lower bounds" {
    const content =
        \\[server]
        \\max_connections = 1
        \\idle_timeout_sec = 1
        \\handshake_timeout_sec = 1
        \\graceful_shutdown_timeout_sec = 0
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 32), cfg.max_connections);
    try std.testing.expectEqual(@as(u32, 5), cfg.idle_timeout_sec);
    try std.testing.expectEqual(@as(u32, 5), cfg.handshake_timeout_sec);
    try std.testing.expectEqual(@as(u32, 1), cfg.graceful_shutdown_timeout_sec);
}

test "parse config - spaces and tabs" {
    const content =
        \\[server]
        \\  port   =   9999   
        \\[censorship]
        \\  tls_domain= "test.com"  
        \\[access.users]
        \\  user  = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 9999), cfg.port);
    try std.testing.expectEqualStrings("test.com", cfg.tls_domain);
    try std.testing.expect(cfg.users.contains("user"));
}

test "parse config - invalid user secret fails fast" {
    const content =
        \\[access.users]
        \\valid = "00112233445566778899aabbccddeeff"
        \\invalid_len = "001122"
        \\invalid_hex = "zz112233445566778899aabbccddeeff"
    ;
    try std.testing.expectError(error.InvalidUserSecretLength, Config.parse(std.testing.allocator, content));
}

test "parse config - getUserSecrets" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;
    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    const secrets = try cfg.getUserSecrets(std.testing.allocator);
    defer std.testing.allocator.free(secrets);

    try std.testing.expectEqual(@as(usize, 1), secrets.len);
    try std.testing.expectEqualStrings("alice", secrets[0].name);
}

test "parse config - tag parsing" {
    const content =
        \\[server]
        \\port = 443
        \\tag = 1234567890abcdef1234567890abcdef
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.tag != null);
    const expected_tag = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    try std.testing.expectEqual(expected_tag, cfg.tag.?);
}

test "parse config - inline comment after tag" {
    const content =
        \\[server]
        \\tag = "1234567890abcdef1234567890abcdef" # production tag
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.tag != null);
    const expected_tag = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    try std.testing.expectEqual(expected_tag, cfg.tag.?);
}

test "parse config - quoted hash preserved" {
    const content =
        \\[censorship]
        \\tls_domain = "exa#mple.com" # inline comment
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("exa#mple.com", cfg.tls_domain);
}

test "parse config - tag default null" {
    const content =
        \\[server]
        \\port = 443
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.tag == null);
}

test "parse config - invalid tag ignored" {
    const content =
        \\[server]
        \\tag = tooshort
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.tag == null);
}

test "parse config - general ad_tag alias" {
    const content =
        \\[general]
        \\ad_tag = "1234567890abcdef1234567890abcdef"
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.tag != null);
    const expected_tag = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    try std.testing.expectEqual(expected_tag, cfg.tag.?);
}

test "parse config - server tag overrides general ad_tag" {
    const content =
        \\[general]
        \\ad_tag = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        \\
        \\[server]
        \\tag = "1234567890abcdef1234567890abcdef"
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.tag != null);
    const expected_tag = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    try std.testing.expectEqual(expected_tag, cfg.tag.?);
}

test "parse config - rate_limit_per_subnet custom" {
    const content =
        \\[server]
        \\rate_limit_per_subnet = 20
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 20), cfg.rate_limit_per_subnet);
}

test "parse config - bind_address" {
    const content =
        \\[server]
        \\bind_address = "127.0.0.1"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("127.0.0.1", cfg.bind_address.?);
}

test "parse config - rate_limit_per_subnet disabled" {
    const content =
        \\[server]
        \\rate_limit_per_subnet = 0
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 0), cfg.rate_limit_per_subnet);
}

test "parse config - handshake flood guard defaults disabled" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(!cfg.handshake_flood_guard_enabled);
    try std.testing.expectEqual(@as(u16, 20), cfg.handshake_flood_guard_threshold);
    try std.testing.expectEqual(@as(u16, 30), cfg.handshake_flood_guard_window_sec);
    try std.testing.expectEqual(@as(u16, 120), cfg.handshake_flood_guard_block_sec);
}

test "parse config - evasion/UX knobs (sni action, idle jitter, per-user limits)" {
    const content =
        \\[server]
        \\idle_timeout_jitter_pct = 25
        \\[censorship]
        \\unknown_sni_action = reject
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
        \\[access.user_max_conns]
        \\alice = 3
        \\bob = 0
        \\[access.user_expirations]
        \\alice = "2026-12-31"
    ;
    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 25), cfg.idle_timeout_jitter_pct);
    try std.testing.expectEqual(UnknownSniAction.reject, cfg.unknown_sni_action);
    try std.testing.expectEqual(@as(u32, 3), cfg.user_max_conns.?.get("alice").?);
    // 0 == "no limit" → not stored
    try std.testing.expect(cfg.user_max_conns.?.get("bob") == null);
    try std.testing.expect(cfg.user_expirations.?.get("alice").? > 0);
}

test "parse config - defaults for new knobs" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;
    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 15), cfg.idle_timeout_jitter_pct);
    try std.testing.expectEqual(UnknownSniAction.mask, cfg.unknown_sni_action);
    try std.testing.expect(cfg.user_max_conns == null);
    try std.testing.expect(cfg.user_expirations == null);
}

test "parseExpiryToUnix" {
    // End-of-day inclusive: expiry is 00:00 UTC of the FOLLOWING day.
    try std.testing.expectEqual(@as(i64, 1609545600), parseExpiryToUnix("2021-01-01").?); // → 2021-01-02 00:00 UTC
    try std.testing.expectEqual(@as(i64, 1640995200), parseExpiryToUnix("2021-12-31").?); // → 2022-01-01 00:00 UTC
    try std.testing.expectEqual(@as(i64, 1583020800), parseExpiryToUnix("2020-02-29").?); // leap day valid
    try std.testing.expect(parseExpiryToUnix("not-a-date") == null);
    try std.testing.expect(parseExpiryToUnix("2021-13-01") == null); // bad month
    try std.testing.expect(parseExpiryToUnix("2021-02-29") == null); // 2021 not a leap year
    try std.testing.expect(parseExpiryToUnix("2021-04-31") == null); // April has 30 days
    try std.testing.expect(parseExpiryToUnix("2021--1-01") == null); // signed field rejected
    try std.testing.expect(parseExpiryToUnix("2021-1-1") == null); // wrong length
}

test "parse config - handshake flood guard custom values" {
    const content =
        \\[server]
        \\handshake_flood_guard_enabled = false
        \\handshake_flood_guard_threshold = 9
        \\handshake_flood_guard_window_sec = 17
        \\handshake_flood_guard_block_sec = 45
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(!cfg.handshake_flood_guard_enabled);
    try std.testing.expectEqual(@as(u16, 9), cfg.handshake_flood_guard_threshold);
    try std.testing.expectEqual(@as(u16, 17), cfg.handshake_flood_guard_window_sec);
    try std.testing.expectEqual(@as(u16, 45), cfg.handshake_flood_guard_block_sec);
}

test "parse config - unsafe_override_limits true" {
    const content =
        \\[server]
        \\unsafe_override_limits = true
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.unsafe_override_limits);
}

test "parse config - unsafe_override_limits default false" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(!cfg.unsafe_override_limits);
}

test "parse config - full production-like config" {
    const content =
        \\[general]
        \\use_middle_proxy = true
        \\
        \\[server]
        \\port = 443
        \\tag = 9649114fbafd6fe2ae98ca635c4e4007
        \\middleproxy_buffer_kb = 1024
        \\max_connections = 512
        \\idle_timeout_sec = 120
        \\handshake_timeout_sec = 15
        \\backlog = 8192
        \\log_level = "info"
        \\rate_limit_per_subnet = 30
        \\
        \\[censorship]
        \\tls_domain = "wb.ru"
        \\mask = true
        \\fast_mode = true
        \\mask_port = 8443
        \\drs = true
        \\
        \\[access.users]
        \\alexander = "0b513f6e83524354984a8835939fa9af"
        \\debug_user = "c8f31d0a8b7f4d2c91e6a5b3d4f8e102"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.use_middle_proxy);
    try std.testing.expectEqual(@as(u16, 443), cfg.port);
    try std.testing.expect(cfg.tag != null);
    try std.testing.expectEqual(@as(u32, 1024), cfg.middleproxy_buffer_kb);
    try std.testing.expectEqual(@as(u32, 512), cfg.max_connections);
    try std.testing.expectEqual(@as(u32, 120), cfg.idle_timeout_sec);
    try std.testing.expectEqual(@as(u32, 15), cfg.handshake_timeout_sec);
    try std.testing.expectEqual(@as(u32, 8192), cfg.backlog);
    try std.testing.expectEqual(std.log.Level.info, cfg.log_level);
    try std.testing.expectEqual(@as(u8, 30), cfg.rate_limit_per_subnet);
    try std.testing.expect(!cfg.unsafe_override_limits);
    try std.testing.expectEqualStrings("wb.ru", cfg.tls_domain);
    try std.testing.expect(cfg.mask);
    try std.testing.expect(cfg.fast_mode);
    try std.testing.expectEqual(@as(u16, 8443), cfg.mask_port);
    try std.testing.expect(cfg.drs);
    try std.testing.expectEqual(@as(usize, 2), cfg.users.count());
    try std.testing.expect(cfg.users.contains("alexander"));
    try std.testing.expect(cfg.users.contains("debug_user"));
}

test "parse config - log_level err" {
    const content =
        \\[server]
        \\log_level = "err"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(std.log.Level.err, cfg.log_level);
}

test "parse config - invalid log_level keeps default" {
    const content =
        \\[server]
        \\log_level = "banana"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(std.log.Level.info, cfg.log_level);
}

test "parse config - invalid rate_limit keeps default" {
    const content =
        \\[server]
        \\rate_limit_per_subnet = notanumber
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 0), cfg.rate_limit_per_subnet);
}

test "parse config - censorship section booleans" {
    const content =
        \\[censorship]
        \\mask = false
        \\desync = false
        \\drs = true
        \\fast_mode = true
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(!cfg.mask);
    try std.testing.expect(!cfg.desync);
    try std.testing.expect(cfg.drs);
    try std.testing.expect(cfg.fast_mode);
}

test "parse config - multiple users" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
        \\bob = "aabbccddeeff00112233445566778899"
        \\charlie = "ffeeddccbbaa99887766554433221100"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 3), cfg.users.count());
    try std.testing.expect(cfg.users.contains("alice"));
    try std.testing.expect(cfg.users.contains("bob"));
    try std.testing.expect(cfg.users.contains("charlie"));

    // Verify secret bytes are correct
    const alice_secret = cfg.users.get("alice").?;
    try std.testing.expectEqual(@as(u8, 0x00), alice_secret[0]);
    try std.testing.expectEqual(@as(u8, 0xff), alice_secret[15]);
}

test "parse config - upstream type amnezia_wg backward compat" {
    const content =
        \\[upstream]
        \\type = "amnezia_wg"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    // amnezia_wg maps to .tunnel for backward compatibility
    try std.testing.expectEqual(UpstreamMode.tunnel, cfg.upstream_mode);
}

test "parse config - upstream type tunnel explicit" {
    const content =
        \\[upstream]
        \\type = "tunnel"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(UpstreamMode.tunnel, cfg.upstream_mode);
}

test "parse config - upstream type default auto" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(UpstreamMode.auto, cfg.upstream_mode);
}

test "parse config - upstream type direct explicit" {
    const content =
        \\[upstream]
        \\type = "direct"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(UpstreamMode.direct, cfg.upstream_mode);
}

test "parse config - upstream type invalid keeps default auto" {
    const content =
        \\[upstream]
        \\type = "banana"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(UpstreamMode.auto, cfg.upstream_mode);
}

test "parse config - legacy tunnel section ignored" {
    const content =
        \\[tunnel]
        \\type = "amnezia_wg"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(UpstreamMode.auto, cfg.upstream_mode);
}

test "parse config - upstream type wireguard backward compat" {
    const content =
        \\[upstream]
        \\type = "wireguard"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(UpstreamMode.tunnel, cfg.upstream_mode);
}

test "parse config - upstream tunnel legacy interface only" {
    const content =
        \\[upstream]
        \\type = "tunnel"
        \\[upstream.tunnel]
        \\interface = "wg0"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), cfg.tunnelInterfaceCount());
    try std.testing.expectEqualStrings("wg0", cfg.tunnelInterfaceAt(0).?);
    try std.testing.expectEqualStrings("wg0", cfg.tunnelCandidateAt(0).?);
    try std.testing.expect(cfg.tunnelCandidateAt(1) == null);
}

test "parse config - upstream tunnel interface pool" {
    const content =
        \\[upstream]
        \\type = "tunnel"
        \\[upstream.tunnel]
        \\interface = "awg0"
        \\interfaces = ["awg0", "awg1"]
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), cfg.tunnelInterfaceCount());
    try std.testing.expectEqualStrings("awg0", cfg.tunnelInterfaceAt(0).?);
    try std.testing.expectEqualStrings("awg1", cfg.tunnelInterfaceAt(1).?);
    try std.testing.expectEqualStrings("awg0", cfg.tunnelCandidateAt(0).?);
    try std.testing.expectEqualStrings("awg1", cfg.tunnelCandidateAt(1).?);
}

test "parse config - upstream tunnel pinned interface candidate order" {
    const content =
        \\[upstream]
        \\type = "tunnel"
        \\[upstream.tunnel]
        \\interfaces = ["awg0", "awg1", "awg2"]
        \\pinned_interface = "awg1"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("awg1", cfg.upstream_tunnel_pinned_interface.?);
    try std.testing.expectEqual(@as(usize, 3), cfg.tunnelCandidateCount());
    try std.testing.expectEqualStrings("awg1", cfg.tunnelCandidateAt(0).?);
    try std.testing.expectEqualStrings("awg0", cfg.tunnelCandidateAt(1).?);
    try std.testing.expectEqualStrings("awg2", cfg.tunnelCandidateAt(2).?);
    try std.testing.expect(cfg.tunnelCandidateAt(3) == null);
}

test "parse config - upstream tunnel pinned interface outside pool" {
    const content =
        \\[upstream]
        \\type = "tunnel"
        \\[upstream.tunnel]
        \\interfaces = ["awg0", "awg1"]
        \\pinned_interface = "awg9"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 3), cfg.tunnelCandidateCount());
    try std.testing.expectEqualStrings("awg9", cfg.tunnelCandidateAt(0).?);
    try std.testing.expectEqualStrings("awg0", cfg.tunnelCandidateAt(1).?);
    try std.testing.expectEqualStrings("awg1", cfg.tunnelCandidateAt(2).?);
}

test "parse config - upstream socks5 with credentials" {
    const content =
        \\[upstream]
        \\type = "socks5"
        \\[upstream.socks5]
        \\host = "38.180.236.207"
        \\port = 1080
        \\username = "admin"
        \\password = "fr6CgjUvxFEAn5vs"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(UpstreamMode.socks5, cfg.upstream_mode);
    try std.testing.expectEqualStrings("38.180.236.207", cfg.upstream_proxy_host.?);
    try std.testing.expectEqual(@as(u16, 1080), cfg.upstream_proxy_port);
    try std.testing.expectEqualStrings("admin", cfg.upstream_proxy_username.?);
    try std.testing.expectEqualStrings("fr6CgjUvxFEAn5vs", cfg.upstream_proxy_password.?);
}

test "parse config - upstream http with credentials" {
    const content =
        \\[upstream]
        \\type = "http"
        \\[upstream.http]
        \\host = "38.180.236.207"
        \\port = 8080
        \\username = "admin"
        \\password = "secret123"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(UpstreamMode.http, cfg.upstream_mode);
    try std.testing.expectEqualStrings("38.180.236.207", cfg.upstream_proxy_host.?);
    try std.testing.expectEqual(@as(u16, 8080), cfg.upstream_proxy_port);
    try std.testing.expectEqualStrings("admin", cfg.upstream_proxy_username.?);
    try std.testing.expectEqualStrings("secret123", cfg.upstream_proxy_password.?);
}

test "parse config - upstream socks5 no credentials" {
    const content =
        \\[upstream]
        \\type = "socks5"
        \\[upstream.socks5]
        \\host = "127.0.0.1"
        \\port = 1080
        \\username = ""
        \\password = ""
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(UpstreamMode.socks5, cfg.upstream_mode);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.upstream_proxy_host.?);
    try std.testing.expectEqual(@as(u16, 1080), cfg.upstream_proxy_port);
    // Empty string credentials are preserved
    try std.testing.expectEqualStrings("", cfg.upstream_proxy_username.?);
    try std.testing.expectEqualStrings("", cfg.upstream_proxy_password.?);
}

test "parse config - upstream http_connect alias" {
    const content =
        \\[upstream]
        \\type = "http_connect"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(UpstreamMode.http, cfg.upstream_mode);
}

test "parse config - upstream socks alias" {
    const content =
        \\[upstream]
        \\type = "socks"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(UpstreamMode.socks5, cfg.upstream_mode);
}

test "parse config - duplicate upstream proxy fields" {
    const content =
        \\[upstream]
        \\type = "socks5"
        \\[upstream.socks5]
        \\host = "10.0.0.1"
        \\host = "10.0.0.2"
        \\port = 1080
        \\username = "first"
        \\username = "second"
        \\password = "one"
        \\password = "two"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("10.0.0.2", cfg.upstream_proxy_host.?);
    try std.testing.expectEqualStrings("second", cfg.upstream_proxy_username.?);
    try std.testing.expectEqualStrings("two", cfg.upstream_proxy_password.?);
}

test "parse config - fake_tls_only defaults true (secure) and parses false" {
    var default_cfg = try Config.parse(std.testing.allocator,
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    );
    defer default_cfg.deinit(std.testing.allocator);
    try std.testing.expect(default_cfg.fake_tls_only);

    var cfg = try Config.parse(std.testing.allocator,
        \\[censorship]
        \\fake_tls_only = false
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    );
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expect(!cfg.fake_tls_only);
}

test "parse config - rate_limit_per_subnet defaults to 0 (disabled)" {
    var cfg = try Config.parse(std.testing.allocator,
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    );
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0), cfg.rate_limit_per_subnet);
}

test "parse config - workers defaults to 1 (single-threaded) and parses" {
    var cfg_default = try Config.parse(std.testing.allocator,
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    );
    defer cfg_default.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 1), cfg_default.workers);

    var cfg_multi = try Config.parse(std.testing.allocator,
        \\[server]
        \\workers = 4
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    );
    defer cfg_multi.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 4), cfg_multi.workers);
}

test "parse config - duplicate user key does not leak (last value wins)" {
    // std.testing.allocator fails the test on any leak, so this also guards the
    // getOrPut-style dedup that replaced the leaking put().
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
        \\alice = "ffeeddccbbaa99887766554433221100"
    ;
    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), cfg.users.count());
    const secret = cfg.users.get("alice").?;
    try std.testing.expectEqual(@as(u8, 0xff), secret[0]);
}

test "parse config - empty tls_domain is rejected" {
    const content =
        \\[censorship]
        \\tls_domain = ""
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;
    try std.testing.expectError(error.EmptyTlsDomain, Config.parse(std.testing.allocator, content));
}

test "parse config - fuzz malformed/random content" {
    var prng = std.Random.DefaultPrng.init(0xC01F16F2);
    const random = prng.random();

    var buf: [1400]u8 = undefined;
    for (0..1200) |_| {
        const len: usize = @as(usize, random.int(u16)) % buf.len;
        random.bytes(buf[0..len]);

        // Keep bytes text-like to exercise parser state transitions rather than UTF noise only.
        for (buf[0..len]) |*b| {
            const v = b.*;
            b.* = switch (v % 7) {
                0 => '\n',
                1 => '=',
                2 => '[',
                3 => ']',
                4 => '#',
                else => 32 + (v % 95),
            };
        }

        var parsed = Config.parse(std.testing.allocator, buf[0..len]) catch continue;
        parsed.deinit(std.testing.allocator);
    }
}

test "parseBool accepts true/1/yes/on case-insensitively, rejects others" {
    try std.testing.expect(parseBool("true"));
    try std.testing.expect(parseBool("True"));
    try std.testing.expect(parseBool("TRUE"));
    try std.testing.expect(parseBool("1"));
    try std.testing.expect(parseBool("yes"));
    try std.testing.expect(parseBool("on"));
    try std.testing.expect(!parseBool("false"));
    try std.testing.expect(!parseBool("0"));
    try std.testing.expect(!parseBool("no"));
    try std.testing.expect(!parseBool(""));
    try std.testing.expect(!parseBool("tru"));
}

test "section header with an inline comment still selects the section" {
    const toml =
        \\[server] # main settings
        \\port = 9999
        \\[censorship]   # masking knobs
        \\mask = yes
    ;
    var cfg = try Config.parse(std.testing.allocator, toml);
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 9999), cfg.port);
    try std.testing.expect(cfg.mask); // `mask = yes` now parses (parseBool) under a commented header
}
