//! Proxy core — TCP listener, client handler, DC connection, bidirectional relay.
//!
//! Design: ProxyState is passed by reference (DI) — no global mutable state.

const std = @import("std");
const net = std.net;
const posix = std.posix;
const constants = @import("../protocol/constants.zig");
const crypto = @import("../crypto/crypto.zig");
const obfuscation = @import("../protocol/obfuscation.zig");
const middleproxy = @import("../protocol/middleproxy.zig");
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
/// MiddleProxy config source (same as mtprotoproxy.py)
const middle_proxy_config_url = "https://core.telegram.org/getProxyConfig";
/// MiddleProxy secret source (same as mtprotoproxy.py)
const middle_proxy_secret_url = "https://core.telegram.org/getProxySecret";
/// MiddleProxy refresh period (24h)
const middle_proxy_update_period_ns: u64 = 24 * 60 * 60 * std.time.ns_per_s;

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

/// Anti-Replay Cache — defends against ТСПУ "Revisor" active probing.
///
/// The Revisor scanner captures a real client's TLS ClientHello and replays it
/// byte-for-byte to our server. Because the HMAC uses the user secret + timestamp
/// (valid within ±2 min), a replayed digest will pass HMAC validation and expose
/// us as a proxy server.
///
/// Fix: Telegram clients NEVER repeat the same 32-byte random digest. We cache
/// all seen digests in a ring buffer. If we see the same digest twice, it's a
/// replay attack — we forward to the real tls_domain transparently instead.
const ReplayCache = struct {
    mutex: std.Thread.Mutex = .{},
    /// Ring buffer of seen TLS ClientHello digests (32 bytes each)
    entries: [4096][32]u8 = [_][32]u8{[_]u8{0} ** 32} ** 4096,
    /// Next write position in the ring buffer
    idx: usize = 0,

    /// Returns true if this digest was seen before (replay attack).
    /// Adds the digest to the cache if it's new.
    pub fn checkAndInsert(self: *ReplayCache, digest: *const [32]u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Scan the ring buffer for a match
        for (&self.entries) |*cached| {
            if (std.mem.eql(u8, cached, digest)) return true; // replay detected!
        }

        // New digest — store it
        self.entries[self.idx] = digest.*;
        self.idx = (self.idx + 1) % self.entries.len;
        return false;
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
    /// Cached resolved address for mask domain (tls_domain).
    /// Resolved once at startup to avoid per-connection DNS (getaddrinfo)
    /// which uses ~48-80KB of stack and causes SEGFAULT on 128KB threads.
    mask_addr: ?net.Address,
    /// Anti-replay cache — detects ТСПУ Revisor active probing.
    replay_cache: ReplayCache,
    /// Protects live middle-proxy address/secret cache.
    middle_proxy_lock: std.Thread.RwLock = .{},
    /// Current middle-proxy endpoints for primary DCs (1..5).
    middle_proxy_addrs_primary: [5]net.Address,
    /// Current middle-proxy endpoint for media DC 203.
    middle_proxy_addr_203: net.Address,
    /// Candidate middle-proxy endpoints for DC4 (some may be filtered per route).
    middle_proxy_addrs_dc4: [16]net.Address,
    middle_proxy_addrs_dc4_len: usize,
    /// Candidate middle-proxy endpoints for media DC203.
    middle_proxy_addrs_203: [8]net.Address,
    middle_proxy_addrs_203_len: usize,
    /// Current middle-proxy shared secret from getProxySecret.
    middle_proxy_secret: [256]u8,
    /// Valid length of middle_proxy_secret bytes.
    middle_proxy_secret_len: usize,

    /// Maximum concurrent connections before rejecting new ones.
    /// Prevents thread exhaustion under load.
    const max_connections: u32 = 65535;

    pub fn init(allocator: std.mem.Allocator, cfg: Config) ProxyState {
        var secrets: std.ArrayList(obfuscation.UserSecret) = .empty;
        var it = @constCast(&cfg.users).iterator();
        while (it.next()) |entry| {
            secrets.append(allocator, .{
                .name = entry.key_ptr.*,
                .secret = entry.value_ptr.*,
            }) catch continue;
        }

        // Resolve mask domain DNS at startup (avoids getaddrinfo on small-stack threads)
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

    /// Start the proxy server.
    pub fn run(self: *ProxyState) !void {
        // Bind to IPv6 wildcard [::] — on Linux with IPV6_V6ONLY=0 (default),
        // this also accepts IPv4-mapped connections (::ffff:x.x.x.x).
        // This enables IPv6 address hopping for DPI evasion without restart.
        const address = net.Address.initIp6(
            .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, // [::]
            self.config.port,
            0, // flowinfo
            0, // scope_id
        );
        var server = try address.listen(.{
            .reuse_address = true,
            .kernel_backlog = @intCast(self.config.backlog),
        });
        defer server.deinit();

        log.info("Listening on 0.0.0.0:{d}", .{self.config.port});

        // Keep middle-proxy address/secret in sync with Telegram endpoints.
        // Skip in tests when datacenter is explicitly overridden.
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
                // Proxy threads shuffle bytes between sockets + AES-CTR (no deep recursion).
                // 256 KB is plenty with safety margin for stack-heavy operations.
                // Default 8-16 MB per thread would exhaust memory with thousands
                // of idle iOS pool connections (e.g. 4000 threads * 8 MB = 32 GB virtual memory).
                .stack_size = 256 * 1024,
            }, handleConnection, .{ self, conn.stream, conn.address, conn_id }) catch |err| {
                log.err("[{d}] Spawn error: {any}", .{ conn_id, err });
                conn.stream.close();
                continue;
            };
            thread.detach();
        }
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
        const next_addr_203 = if (count_203 == 0)
            null
        else
            candidates_203[0];

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

fn parseMiddleProxyAddressForDc(config_text: []const u8, target_dc: i16) ?net.Address {
    var one: [1]net.Address = undefined;
    const n = parseMiddleProxyAddressesForDc(config_text, target_dc, &one);
    if (n == 0) return null;
    return one[0];
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

        // Skip duplicates.
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
        if (isAddressReachable(addr, timeout_ms)) {
            return addr;
        }
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

    var fds = [_]posix.pollfd{
        .{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 },
    };

    const ready = posix.poll(&fds, timeout_ms) catch return false;
    if (ready == 0) return false;

    const revents = fds[0].revents;
    if ((revents & posix.POLL.OUT) == 0) return false;
    if ((revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL)) != 0) return false;

    posix.getsockoptError(fd) catch return false;
    return true;
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
    return runCurl(allocator, &strict_argv) catch {
        const insecure_argv = [_][]const u8{ "curl", "-kfsSL", "--max-time", "10", url };
        return runCurl(allocator, &insecure_argv);
    };
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

    const ip = std.mem.asBytes(&addr.in.sa.addr);
    try std.testing.expectEqual(@as(u8, 91), ip[0]);
    try std.testing.expectEqual(@as(u8, 105), ip[1]);
    try std.testing.expectEqual(@as(u8, 192), ip[2]);
    try std.testing.expectEqual(@as(u8, 110), ip[3]);
}

test "parse middle proxy address returns null when absent" {
    const cfg =
        "proxy_for 1 149.154.175.50:8888;\n" ++
        "proxy_for 2 149.154.161.144:8888;\n";

    try std.testing.expect(parseMiddleProxyAddressForDc(cfg, 203) == null);
}

test "middle proxy snapshot selects primary dc and 203" {
    const snapshot = ProxyState.MiddleProxySnapshot{
        .addrs_primary = constants.tg_middle_proxies_v4,
        .addr_203 = constants.getDcAddressV4(203),
        .addrs_dc4 = [_]net.Address{constants.tg_middle_proxies_v4[3]} ++ ([_]net.Address{constants.tg_middle_proxies_v4[3]} ** 15),
        .addrs_dc4_len = 1,
        .addrs_203 = [_]net.Address{constants.getDcAddressV4(203)} ++ ([_]net.Address{constants.getDcAddressV4(203)} ** 7),
        .addrs_203_len = 1,
        .secret = [_]u8{0} ** 256,
        .secret_len = 128,
    };

    const dc1 = snapshot.getForDc(1) orelse return error.TestExpectedEqual;
    try std.testing.expect(dc1.eql(constants.tg_middle_proxies_v4[0]));

    const dc5 = snapshot.getForDc(5) orelse return error.TestExpectedEqual;
    try std.testing.expect(dc5.eql(constants.tg_middle_proxies_v4[4]));

    const dc203 = snapshot.getForDc(203) orelse return error.TestExpectedEqual;
    try std.testing.expect(dc203.eql(constants.getDcAddressV4(203)));

    try std.testing.expect(snapshot.getForDc(6) == null);
    try std.testing.expect(snapshot.getForDc(302) == null);
}

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

    handleConnectionInner(state, client_stream, peer_addr, peer_str, conn_id) catch |err| {
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
        if (err == error.ConnectionResetByPeer or err == error.ConnectionReset or err == error.EndOfStream) {
            log.debug("[{d}] ({s}) Connection closed: {any}", .{ conn_id, peer_str, err });
            return;
        }
        log.err("[{d}] ({s}) Connection error: {any}", .{ conn_id, peer_str, err });
    };
}

fn handleConnectionInner(
    state: *ProxyState,
    client_stream: net.Stream,
    client_addr: net.Address,
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
    const first_byte_timeout_ms: i32 = idle_timeout_ms;

    var poll_fds = [_]posix.pollfd{
        .{ .fd = fd, .events = posix.POLL.IN, .revents = 0 },
    };
    const ready = posix.poll(&poll_fds, first_byte_timeout_ms) catch return error.ConnectionReset;
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
        log.debug("[{d}] ({s}) Non-TLS connection, dropping. First bytes: {s}", .{ conn_id, peer_str, std.fmt.bytesToHex(first_bytes, .lower) });
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
        log.info("[{d}] ({s}) DIAG: Short read on ClientHello body (got {d}, expected {d}), dropping.", .{ conn_id, peer_str, body_n, record_len });
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
        log.debug("[{d}] ({s}) TLS auth failed — masking to {s}", .{ conn_id, peer_str, state.config.tls_domain });
        maskConnection(state, client_stream, peer_str, conn_id, client_hello, null);
        return;
    }

    const v = validation.?;

    // Anti-Replay Check: ТСПУ "Revisor" replays a captured ClientHello byte-for-byte
    // to confirm our server is a proxy. Legitimate Telegram clients NEVER reuse a digest.
    // If we see the same digest twice — it's active probing. Forward to real tls_domain
    // so the scanner sees a legitimate CDN response and whitelists our IP.
    if (state.replay_cache.checkAndInsert(&v.digest)) {
        log.info("[{d}] ({s}) Replay attack detected (ТСПУ Revisor) — masking to {s}", .{
            conn_id, peer_str, state.config.tls_domain,
        });
        maskConnection(state, client_stream, peer_str, conn_id, client_hello, null);
        return;
    }

    log.info("[{d}] ({s}) TLS auth OK: user={s}", .{ conn_id, peer_str, v.user });

    // Send ServerHello response
    const server_hello = try tls.buildServerHello(
        state.allocator,
        &v.secret,
        &v.digest,
        v.session_id,
    );
    defer state.allocator.free(server_hello);

    // === DPI DESYNC: Split-TLS ===
    // Split the ServerHello across TCP segments to break ТСПУ's TLS signature matching.
    // ТСПУ's passive DPI looks for `16 03 03` at the start of a TCP payload to classify
    // the response as TLS. By sending the first byte (0x16) in a separate segment,
    // the DPI sees an unclassifiable single byte, then the rest arrives in a new segment.
    //
    // TCP_NODELAY disables Nagle's algorithm so the kernel sends each writeAll immediately.
    // The 3ms sleep forces the first byte into a separate TCP segment.
    // This is safe with our thread-per-connection model — sleeping doesn't block the accept loop.
    if (state.config.desync and server_hello.len > 1) {
        const IPPROTO_TCP: i32 = 6;
        const TCP_NODELAY: i32 = 1;
        const enable = std.mem.toBytes(@as(c_int, 1));
        _ = posix.setsockopt(client_stream.handle, IPPROTO_TCP, TCP_NODELAY, &enable) catch {};

        // Send just the first byte (0x16 — TLS record type) as a separate TCP segment
        try writeAll(client_stream, server_hello[0..1]);

        // Force segment boundary: 3ms sleep pushes the first byte out
        std.Thread.sleep(3 * std.time.ns_per_ms);

        // Send the rest of ServerHello (version, length, handshake body, CCS, AppData)
        try writeAll(client_stream, server_hello[1..]);
    } else {
        try writeAll(client_stream, server_hello);
    }

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

    // Resolve DC address — use @abs() to avoid overflow when dc_idx == minInt(i16).
    // Telegram has only 5 physical DCs, but clients may request special DC numbers
    // (media clusters, CDN, etc. — e.g. DC 203, 302). Map them to physical DCs
    // via modulo: (abs(dc) - 1) % 5.
    const dc_abs: usize = if (params.dc_idx > 0)
        @as(usize, @intCast(params.dc_idx))
    else if (params.dc_idx < 0)
        @as(usize, @abs(params.dc_idx))
    else
        return;

    const middle_proxy_snapshot = if (state.config.datacenter_override == null and (state.config.use_middle_proxy or dc_abs == 203))
        state.getMiddleProxySnapshot()
    else
        null;

    const middle_proxy_addr = if (middle_proxy_snapshot) |*snap|
        snap.getForDc(dc_abs)
    else
        null;

    // Compatibility behavior:
    // - Media paths (negative DC index, plus legacy media DC203) should prefer
    //   middle-proxy transport.
    // - [general].use_middle_proxy enables middle-proxy transport for regular DC1..5.
    const is_media_path = (params.dc_idx < 0) or (dc_abs == 203);
    const force_media_middle_proxy = (is_media_path and state.config.datacenter_override == null and middle_proxy_addr != null);
    var use_middle_proxy_transport = if (state.config.datacenter_override != null)
        false
    else if (force_media_middle_proxy)
        true
    else
        state.config.use_middle_proxy and middle_proxy_addr != null;

    var dc_addr = state.config.datacenter_override orelse if (use_middle_proxy_transport)
        middle_proxy_addr.?
    else
        constants.getDcAddressV4(dc_abs);
    log.debug("[{d}] ({s}) Connecting to DC {d} (addr: {any})", .{ conn_id, peer_str, params.dc_idx, dc_addr });

    // For DC4 we may have multiple middle-proxy candidates. Rotate per-connection
    // to avoid sticking to a route-blocked endpoint.
    var dc4_try_order: [16]net.Address = undefined;
    var dc4_try_count: usize = 0;
    var dc4_try_index: usize = 0;
    if (use_middle_proxy_transport and middle_proxy_snapshot != null and dc_abs == 4) {
        const snap = middle_proxy_snapshot.?;
        if (snap.addrs_dc4_len > 0) {
            var uniq_count: usize = 0;
            for (snap.addrs_dc4[0..snap.addrs_dc4_len]) |cand| {
                var dup = false;
                for (dc4_try_order[0..uniq_count]) |existing| {
                    if (isSameIpEndpoint(existing, cand)) {
                        dup = true;
                        break;
                    }
                }
                if (dup) continue;
                dc4_try_order[uniq_count] = cand;
                uniq_count += 1;
                if (uniq_count == dc4_try_order.len) break;
            }

            if (uniq_count > 0) {
                dc4_try_count = uniq_count;
                dc_addr = dc4_try_order[0];
                dc4_try_index = 1;
            }
        }
    }

    var dc203_try_order: [8]net.Address = undefined;
    var dc203_try_count: usize = 0;
    var dc203_try_index: usize = 0;
    if (use_middle_proxy_transport and middle_proxy_snapshot != null and dc_abs == 203) {
        const snap = middle_proxy_snapshot.?;
        if (snap.addrs_203_len > 0) {
            var uniq_count: usize = 0;
            for (snap.addrs_203[0..snap.addrs_203_len]) |cand| {
                var dup = false;
                for (dc203_try_order[0..uniq_count]) |existing| {
                    if (isSameIpEndpoint(existing, cand)) {
                        dup = true;
                        break;
                    }
                }
                if (dup) continue;
                dc203_try_order[uniq_count] = cand;
                uniq_count += 1;
                if (uniq_count == dc203_try_order.len) break;
            }

            if (uniq_count > 0) {
                dc203_try_count = uniq_count;
                dc_addr = dc203_try_order[0];
                dc203_try_index = 1;
            }
        }
    }

    var dc_stream: net.Stream = undefined;
    var dc_last_err: ?anyerror = null;
    dc_connect: while (true) {
        if (net.tcpConnectToAddress(dc_addr)) |s| {
            dc_stream = s;
            break :dc_connect;
        } else |err| {
            dc_last_err = err;
            if (use_middle_proxy_transport and err == error.ConnectionTimedOut and dc_abs == 4 and dc4_try_index < dc4_try_count) {
                dc_addr = dc4_try_order[dc4_try_index];
                dc4_try_index += 1;
                var next_buf: [64]u8 = undefined;
                const next_str = formatAddress(dc_addr, &next_buf);
                log.warn("[{d}] ({s}) DC4 MiddleProxy timeout, retrying candidate {d}/{d}: {s}", .{
                    conn_id,
                    peer_str,
                    dc4_try_index,
                    dc4_try_count,
                    next_str,
                });
                continue :dc_connect;
            }

            if (use_middle_proxy_transport and err == error.ConnectionTimedOut and dc_abs == 203 and dc203_try_index < dc203_try_count) {
                dc_addr = dc203_try_order[dc203_try_index];
                dc203_try_index += 1;
                var next_buf: [64]u8 = undefined;
                const next_str = formatAddress(dc_addr, &next_buf);
                log.warn("[{d}] ({s}) DC203 MiddleProxy timeout, retrying candidate {d}/{d}: {s}", .{
                    conn_id,
                    peer_str,
                    dc203_try_index,
                    dc203_try_count,
                    next_str,
                });
                continue :dc_connect;
            }

            if (use_middle_proxy_transport and dc_abs == 4 and dc4_try_index < dc4_try_count) {
                dc_addr = dc4_try_order[dc4_try_index];
                dc4_try_index += 1;
                continue :dc_connect;
            }

            if (use_middle_proxy_transport and dc_abs == 203 and dc203_try_index < dc203_try_count) {
                dc_addr = dc203_try_order[dc203_try_index];
                dc203_try_index += 1;
                continue :dc_connect;
            }

            if (use_middle_proxy_transport and err == error.ConnectionTimedOut and !is_media_path) {
                const fallback_dc = constants.getDcAddressV4(dc_abs);
                var fallback_buf: [64]u8 = undefined;
                const fallback_str = formatAddress(fallback_dc, &fallback_buf);
                log.warn("[{d}] ({s}) MiddleProxy connect timeout for dc={d}, falling back to direct {s}", .{ conn_id, peer_str, params.dc_idx, fallback_str });

                if (net.tcpConnectToAddress(fallback_dc)) |fallback_stream| {
                    dc_stream = fallback_stream;
                    dc_addr = fallback_dc;
                    use_middle_proxy_transport = false;
                    break :dc_connect;
                } else |fallback_err| {
                    log.err("[{d}] ({s}) Fallback DC connect failed: primary={any} fallback={any}", .{
                        conn_id, peer_str, err, fallback_err,
                    });
                    return;
                }
            } else if (use_middle_proxy_transport and is_media_path) {
                log.warn("[{d}] ({s}) MiddleProxy connect failed for media dc={d}: {any}", .{ conn_id, peer_str, params.dc_idx, err });
                if (dc_last_err) |last_err| {
                    log.warn("[{d}] ({s}) Last media upstream error after retries: {any}", .{ conn_id, peer_str, last_err });
                }
                return;
            } else {
                log.err("[{d}] ({s}) DC connect failed: {any}", .{ conn_id, peer_str, err });
                return;
            }
        }
    }
    defer dc_stream.close();

    const is_primary_dc = (dc_abs >= 1 and dc_abs <= constants.tg_datacenters_v4.len);
    var use_fast_mode = false;

    var opt_middle_proxy: ?middleproxy.MiddleProxyContext = null;
    defer if (opt_middle_proxy) |*mp| mp.deinit(state.allocator);

    var tg_encryptor_opt: ?crypto.AesCtr = null;
    var tg_decryptor_opt: ?crypto.AesCtr = null;

    if (use_middle_proxy_transport) {
        // Execute MiddleProxy Handshake
        const mp_secret = if (middle_proxy_snapshot) |snap| snap.secret[0..snap.secret_len] else middleproxy.proxy_secret[0..];
        opt_middle_proxy = try middleproxy.executeHandshake(
            state.allocator,
            dc_stream,
            dc_addr,
            params.proto_tag,
            client_addr,
            mp_secret,
            state.config.tag,
        );
        log.debug("[{d}] MiddleProxy handshake successful (dc={d})", .{ conn_id, params.dc_idx });
    } else {
        // Generate and send obfuscated handshake to Telegram DC
        var tg_nonce = obfuscation.generateNonce();

        use_fast_mode = state.config.fast_mode and is_primary_dc;

        if (use_fast_mode) {
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
        var encrypted_nonce: [constants.handshake_len]u8 = undefined;
        @memcpy(&encrypted_nonce, &tg_nonce);
        tg_encryptor.apply(&encrypted_nonce);

        // Build final nonce: unencrypted prefix + encrypted suffix
        var nonce_to_send: [constants.handshake_len]u8 = undefined;
        @memcpy(nonce_to_send[0..constants.proto_tag_pos], tg_nonce[0..constants.proto_tag_pos]);
        @memcpy(nonce_to_send[constants.proto_tag_pos..], encrypted_nonce[constants.proto_tag_pos..]);

        try writeAll(dc_stream, &nonce_to_send);

        // Promotion (Sponsorship) Tag — only for primary DCs (1-5).
        if (state.config.tag) |tag| {
            if (is_primary_dc and dc_abs != 203) {
                var promote_buf: [32]u8 = undefined;
                var packet_len: usize = 0;

                const rpc_id: u32 = 0xaeaf0c42;
                var rpc_payload: [20]u8 = undefined;
                std.mem.writeInt(u32, rpc_payload[0..4], rpc_id, .little);
                @memcpy(rpc_payload[4..20], &tag);

                switch (params.proto_tag) {
                    .abridged => {
                        promote_buf[0] = 5; // 20 / 4
                        @memcpy(promote_buf[1..21], &rpc_payload);
                        packet_len = 21;
                    },
                    .intermediate, .secure => {
                        std.mem.writeInt(u32, promote_buf[0..4], 20, .little);
                        @memcpy(promote_buf[4..24], &rpc_payload);
                        packet_len = 24;
                    },
                }

                const to_send = promote_buf[0..packet_len];
                tg_encryptor.apply(to_send);
                try writeAll(dc_stream, to_send);
                log.debug("[{d}] ({s}) Sent promotion tag to primary DC{d}", .{ conn_id, peer_str, dc_abs });
            } else {
                log.debug("[{d}] ({s}) Skipping promotion tag for non-primary DC{d}", .{ conn_id, peer_str, params.dc_idx });
            }
        }

        tg_encryptor_opt = tg_encryptor;
        tg_decryptor_opt = crypto.AesCtr.init(&tg_dec_key, tg_dec_iv);

        // Wipe key material from stack
        @memset(&tg_enc_key, 0);
        @memset(&tg_enc_iv_bytes, 0);
        @memset(&tg_dec_key, 0);
        @memset(&tg_dec_key_iv, 0);
    }

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
        if (opt_middle_proxy) |*mp| {
            const out_data = try mp.encapsulateC2S(pipelined);
            if (out_data.len > 0) try writeAll(dc_stream, out_data);
        } else if (tg_encryptor_opt) |*enc| {
            enc.apply(pipelined);
            try writeAll(dc_stream, pipelined);
        }
        initial_c2s_bytes = pipelined.len;
    }

    relayBidirectional(
        client_stream,
        dc_stream,
        &client_decryptor,
        &client_encryptor,
        if (tg_encryptor_opt) |*enc| enc else null,
        if (tg_decryptor_opt) |*dec| dec else null,
        if (opt_middle_proxy) |*mp| mp else null,
        initial_c2s_bytes,
        conn_id,
        use_fast_mode,
    ) catch |err| {
        log.debug("[{d}] ({s}) Relay ended: dc={d} err={any} fast={}", .{ conn_id, peer_str, params.dc_idx, err, use_fast_mode });
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
    tg_encryptor: ?*crypto.AesCtr,
    tg_decryptor: ?*crypto.AesCtr,
    middle_proxy: ?*middleproxy.MiddleProxyContext,
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
                middle_proxy,
                &tls_hdr_buf,
                &tls_hdr_pos,
                &tls_body_buf,
                &tls_body_pos,
                &tls_body_len,
                &c2s_bytes,
                conn_id,
            ) catch |err| {
                log.debug("[{d}] DIAG C2S err: {any} c2s={d} s2c={d}", .{ conn_id, err, c2s_bytes, s2c_bytes });
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
                middle_proxy,
                &dc_read_buf,
                &drs,
                &s2c_bytes,
            ) catch |err| {
                log.debug("[{d}] DIAG S2C err: {any} c2s={d} s2c={d}", .{ conn_id, err, c2s_bytes, s2c_bytes });
                return err;
            };
            if (step != .none) progressed = true;
        }

        // Hard errors after draining readable data
        if ((client_revents & (posix.POLL.ERR | posix.POLL.NVAL)) != 0) {
            log.debug("[{d}] DIAG client ERR/NVAL c2s={d} s2c={d}", .{ conn_id, c2s_bytes, s2c_bytes });
            return error.ConnectionReset;
        }
        if ((dc_revents & (posix.POLL.ERR | posix.POLL.NVAL)) != 0) {
            log.debug("[{d}] DIAG DC ERR/NVAL c2s={d} s2c={d}", .{ conn_id, c2s_bytes, s2c_bytes });
            return error.ConnectionReset;
        }

        // If HUP arrived without readable data, close immediately.
        // If it arrived with POLLIN, we already drained what we could above.
        if (((client_revents & posix.POLL.HUP) != 0) and ((client_revents & posix.POLL.IN) == 0)) {
            log.debug("[{d}] DIAG client HUP c2s={d} s2c={d}", .{ conn_id, c2s_bytes, s2c_bytes });
            return error.ConnectionReset;
        }
        if (((dc_revents & posix.POLL.HUP) != 0) and ((dc_revents & posix.POLL.IN) == 0)) {
            log.debug("[{d}] DIAG DC HUP c2s={d} s2c={d}", .{ conn_id, c2s_bytes, s2c_bytes });
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
    tg_encryptor: ?*crypto.AesCtr,
    middle_proxy: ?*middleproxy.MiddleProxyContext,
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

        if (middle_proxy) |mp| {
            const out_data = try mp.encapsulateC2S(payload);
            if (out_data.len > 0) {
                try writeAll(dc, out_data);
            }
        } else if (tg_encryptor) |enc| {
            // AES-CTR encrypt for DC
            enc.apply(payload);
            // Send to DC
            try writeAll(dc, payload);
        }
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
    middle_proxy: ?*middleproxy.MiddleProxyContext,
    dc_read_buf: *[constants.default_buffer_size]u8,
    drs: *DynamicRecordSizer,
    bytes_counter: *u64,
) !RelayProgress {
    const nr = dc.read(dc_read_buf) catch |err| {
        if (err == error.WouldBlock) return .none;
        return err;
    };
    if (nr == 0) return error.ConnectionReset;

    const raw_data = dc_read_buf[0..nr];

    if (middle_proxy) |mp| {
        const payload = try mp.decapsulateS2C(raw_data);

        if (payload.len == 0) return .partial;

        // AES-CTR encrypt for client obfuscation
        if (client_encryptor) |enc| enc.apply(payload);

        // Wrap in TLS Application Data record(s)
        var record_buf: [tls_header_len + constants.max_tls_plaintext_size]u8 = undefined;
        var offset: usize = 0;
        while (offset < payload.len) {
            const max_chunk = drs.nextRecordSize();
            const chunk_len = @min(payload.len - offset, max_chunk);

            record_buf[0] = constants.tls_record_application;
            record_buf[1] = constants.tls_version[0];
            record_buf[2] = constants.tls_version[1];
            std.mem.writeInt(u16, record_buf[3..5], @intCast(chunk_len), .big);
            @memcpy(record_buf[tls_header_len..][0..chunk_len], payload[offset..][0..chunk_len]);

            try writeAll(client, record_buf[0 .. tls_header_len + chunk_len]);
            drs.recordSent(chunk_len);
            offset += chunk_len;
        }

        bytes_counter.* += payload.len;
        return .forwarded;
    }

    const data = raw_data;

    // In fast mode, the DC encrypts directly for the client, so we skip these
    if (tg_decryptor) |dec| dec.apply(data);

    // AES-CTR encrypt for client obfuscation
    if (client_encryptor) |enc| enc.apply(data);

    // Wrap in TLS Application Data record(s) using DRS-controlled sizes.
    // Header and body are written in a single writeAll call to reduce syscalls
    // and ensure atomic TLS record delivery (avoids tiny 5-byte header packets).
    var record_buf: [tls_header_len + constants.max_tls_plaintext_size]u8 = undefined;
    var offset: usize = 0;
    while (offset < data.len) {
        const max_chunk = drs.nextRecordSize();
        const chunk_len = @min(data.len - offset, max_chunk);

        // Build TLS record: header + payload in one buffer
        record_buf[0] = constants.tls_record_application;
        record_buf[1] = constants.tls_version[0];
        record_buf[2] = constants.tls_version[1];
        std.mem.writeInt(u16, record_buf[3..5], @intCast(chunk_len), .big);
        @memcpy(record_buf[tls_header_len..][0..chunk_len], data[offset..][0..chunk_len]);

        try writeAll(client, record_buf[0 .. tls_header_len + chunk_len]);

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
/// On WouldBlock, retries via poll(). On hard errors or EOF, returns what was read so far.
fn readExact(stream: net.Stream, buf: []u8) !usize {
    var total: usize = 0;
    while (total < buf.len) {
        const nr = stream.read(buf[total..]) catch |err| {
            if (err == error.WouldBlock) {
                // Socket is non-blocking and no data ready yet — poll and retry.
                var poll_fds = [_]posix.pollfd{
                    .{ .fd = stream.handle, .events = posix.POLL.IN, .revents = 0 },
                };
                const ready = posix.poll(&poll_fds, 30_000) catch |poll_err| {
                    log.info("DIAG: readExact poll failed after {d}/{d}B on fd={d}: {any}", .{ total, buf.len, stream.handle, poll_err });
                    return total;
                };
                if (ready == 0) {
                    log.info("DIAG: readExact poll timeout after {d}/{d}B on fd={d}", .{ total, buf.len, stream.handle });
                    return total;
                }

                const revents = poll_fds[0].revents;
                if ((revents & (posix.POLL.ERR | posix.POLL.NVAL)) != 0) {
                    log.info("DIAG: readExact poll error revents=0x{x} after {d}/{d}B on fd={d}", .{ revents, total, buf.len, stream.handle });
                    return total;
                }
                // POLLIN|POLLHUP is valid: there may still be unread bytes queued.
                if ((revents & posix.POLL.HUP) != 0 and (revents & posix.POLL.IN) == 0) {
                    log.info("DIAG: readExact poll hup without input after {d}/{d}B on fd={d}", .{ total, buf.len, stream.handle });
                    return total;
                }
                continue; // retry read
            }
            if (total > 0) {
                log.info("DIAG: readExact aborted on {any} after {d}/{d}B on fd={d}", .{ err, total, buf.len, stream.handle });
                return total;
            }
            return err;
        };
        if (nr == 0) {
            if (total > 0) {
                log.info("DIAG: readExact EOF after {d}/{d}B on fd={d}", .{ total, buf.len, stream.handle });
            }
            return total;
        }
        total += nr;
    }
    return total;
}

/// Format a network address as "[ipv4]:port" or "[ipv6]:port" for logging.
fn formatAddress(addr: net.Address, buf: *[64]u8) []const u8 {
    switch (addr.any.family) {
        posix.AF.INET => {
            return std.fmt.bufPrint(buf, "[ipv4]:{d}", .{
                std.mem.bigToNative(u16, addr.in.sa.port),
            }) catch "?";
        },
        posix.AF.INET6 => {
            const bytes: *const [16]u8 = @ptrCast(&addr.in6.sa.addr);
            // Check if it's an IPv4-mapped IPv6 address (::ffff:0:0/96)
            const is_ipv4_mapped = std.mem.eql(u8, bytes[0..10], &[_]u8{0} ** 10) and
                std.mem.eql(u8, bytes[10..12], &[_]u8{ 0xff, 0xff });

            if (is_ipv4_mapped) {
                return std.fmt.bufPrint(buf, "[ipv4]:{d}", .{
                    std.mem.bigToNative(u16, addr.in6.sa.port),
                }) catch "?";
            } else {
                return std.fmt.bufPrint(buf, "[ipv6]:{d}", .{
                    std.mem.bigToNative(u16, addr.in6.sa.port),
                }) catch "?";
            }
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

    // Use cached DNS result from startup — avoids getaddrinfo on small-stack threads
    const addr = state.mask_addr orelse {
        log.debug("[{d}] ({s}) Masking skipped: no resolved address for {s}", .{ conn_id, peer_str, state.config.tls_domain });
        return;
    };

    const upstream_stream = net.tcpConnectToAddress(addr) catch {
        log.debug("[{d}] ({s}) Masking failed: cannot connect to {s}:{d}", .{ conn_id, peer_str, state.config.tls_domain, state.config.mask_port });
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

test "Proxy Integration - Drops invalid connection (masking disabled)" {
    const allocator = std.testing.allocator;

    // Config with mask = false so it drops immediately instead of relayRaw
    const cfg = Config{
        .users = std.StringHashMap([16]u8).init(allocator),
        .port = 0, // OS assigned
        .mask = false,
    };
    defer cfg.deinit(allocator);

    var state = ProxyState.init(allocator, cfg);
    defer state.deinit();

    // Start server in background thread
    var server = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    const listener = try std.posix.socket(server.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP);
    defer std.posix.close(listener);

    try std.posix.setsockopt(listener, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    try std.posix.bind(listener, &server.any, server.getOsSockLen());
    try std.posix.listen(listener, 128);

    // Get assigned port
    var addr_len = server.getOsSockLen();
    try std.posix.getsockname(listener, &server.any, &addr_len);

    // Thread that just accepts one connection and handles it
    const ServerThread = struct {
        fn run(l: std.posix.socket_t, s: *ProxyState) !void {
            var client_addr: std.net.Address = undefined;
            var client_len: std.posix.socklen_t = @sizeOf(std.net.Address);
            const client_fd = std.posix.accept(l, &client_addr.any, &client_len, std.posix.SOCK.CLOEXEC) catch return;
            defer std.posix.close(client_fd);

            // Just run it synchronously
            const stream = std.net.Stream{ .handle = client_fd };
            const t_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
            handleConnectionInner(s, stream, t_addr, "127.0.0.1:0", 1) catch {};
        }
    };

    const t = try std.Thread.spawn(.{}, ServerThread.run, .{ listener, &state });
    defer t.join();

    // Connect as client
    const client = try std.net.tcpConnectToAddress(server);
    defer client.close();

    // Send invalid junk
    try client.writeAll("hello world this is definitely not tls");

    // Read response - should be EOF/reset since masking is false and it's invalid
    var buf: [128]u8 = undefined;
    const n = client.read(&buf) catch |err| {
        try std.testing.expect(err == error.ConnectionResetByPeer);
        return;
    };
    try std.testing.expectEqual(@as(usize, 0), n);
}

test "E2E: DPI Masking (Active Probing Defense)" {
    const allocator = std.testing.allocator;

    // Start Fake Google Server
    var mock_google = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    const google_listener = try std.posix.socket(mock_google.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP);
    defer std.posix.close(google_listener);
    try std.posix.setsockopt(google_listener, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    try std.posix.bind(google_listener, &mock_google.any, mock_google.getOsSockLen());
    try std.posix.listen(google_listener, 128);
    var google_addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
    try std.posix.getsockname(google_listener, &mock_google.any, &google_addr_len);
    const mask_port = mock_google.in.getPort();

    // Start Proxy Server
    var proxy_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    const proxy_listener = try std.posix.socket(proxy_addr.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP);
    defer std.posix.close(proxy_listener);
    try std.posix.setsockopt(proxy_listener, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    try std.posix.bind(proxy_listener, &proxy_addr.any, proxy_addr.getOsSockLen());
    try std.posix.listen(proxy_listener, 128);
    var proxy_addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
    try std.posix.getsockname(proxy_listener, &proxy_addr.any, &proxy_addr_len);

    const ServerThread = struct {
        fn run_google(l: std.posix.socket_t) void {
            const client_fd = std.posix.accept(l, null, null, std.posix.SOCK.CLOEXEC) catch return;
            defer std.posix.close(client_fd);
            const stream = std.net.Stream{ .handle = client_fd };

            // Read stuff
            var buf: [128]u8 = undefined;
            const n = stream.read(&buf) catch return;
            if (n == 0) return;

            stream.writeAll("HTTP/1.1 200 OK\r\n\r\nGoogleMock") catch return;
        }

        fn run_proxy(l: std.posix.socket_t, s: *ProxyState) void {
            const client_fd = std.posix.accept(l, null, null, std.posix.SOCK.CLOEXEC) catch return;
            defer std.posix.close(client_fd);
            const stream = std.net.Stream{ .handle = client_fd };
            const t_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
            handleConnectionInner(s, stream, t_addr, "127.0.0.1:0", 1) catch {};
        }
    };

    const google_thread = try std.Thread.spawn(.{}, ServerThread.run_google, .{google_listener});
    defer google_thread.join();

    var cfg = @import("../config.zig").Config{
        .users = std.StringHashMap([16]u8).init(allocator),
        .tls_domain = "127.0.0.1",
        .mask = true,
        .mask_port = mask_port,
    };
    defer cfg.users.deinit();

    var state = ProxyState.init(allocator, cfg);
    defer state.deinit();

    const proxy_thread = try std.Thread.spawn(.{}, ServerThread.run_proxy, .{ proxy_listener, &state });
    defer proxy_thread.join();

    // Client
    const client = try std.net.tcpConnectToAddress(proxy_addr);
    defer client.close();

    // Send HTTP-style DPI probe
    try client.writeAll("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");

    var buf: [128]u8 = undefined;
    const n = try client.read(&buf);

    // We should receive exactly what GoogleMock sent
    try std.testing.expectEqualStrings("HTTP/1.1 200 OK\r\n\r\nGoogleMock", buf[0..n]);
}

test "E2E: Valid MTProto Handshake Drop" {
    // We just want to ensure that a perfectly formed TLS + MTProto packet
    // forces the proxy to try to connect to the datacenter.
    // We mock the DC and see if the Proxy connects.

    const allocator = std.testing.allocator;

    var mock_dc = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    const dc_listener = try std.posix.socket(mock_dc.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP);
    defer std.posix.close(dc_listener);
    try std.posix.setsockopt(dc_listener, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    try std.posix.bind(dc_listener, &mock_dc.any, mock_dc.getOsSockLen());
    try std.posix.listen(dc_listener, 128);
    var dc_addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
    try std.posix.getsockname(dc_listener, &mock_dc.any, &dc_addr_len);

    var proxy_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    const proxy_listener = try std.posix.socket(proxy_addr.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP);
    defer std.posix.close(proxy_listener);
    try std.posix.setsockopt(proxy_listener, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    try std.posix.bind(proxy_listener, &proxy_addr.any, proxy_addr.getOsSockLen());
    try std.posix.listen(proxy_listener, 128);
    var proxy_addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
    try std.posix.getsockname(proxy_listener, &proxy_addr.any, &proxy_addr_len);

    const ServerThread = struct {
        fn run_dc(l: std.posix.socket_t) void {
            var fds = [_]std.posix.pollfd{
                .{ .fd = l, .events = std.posix.POLL.IN, .revents = 0 },
            };
            const ready = std.posix.poll(&fds, 1000) catch return;
            if (ready == 0) return; // Timeout, exit cleanly

            const client_fd = std.posix.accept(l, null, null, std.posix.SOCK.CLOEXEC) catch return;
            defer std.posix.close(client_fd);
            const stream = std.net.Stream{ .handle = client_fd };

            // Just read the 64-byte upstream proxy nonce
            var buf: [64]u8 = undefined;
            _ = stream.read(&buf) catch return;
            // Write some fake DC response
            stream.writeAll("DC_OK") catch return;
        }

        fn run_proxy(l: std.posix.socket_t, s: *ProxyState) void {
            const client_fd = std.posix.accept(l, null, null, std.posix.SOCK.CLOEXEC) catch return;
            defer std.posix.close(client_fd);
            const stream = std.net.Stream{ .handle = client_fd };
            const t_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
            handleConnectionInner(s, stream, t_addr, "127.0.0.1:0", 1) catch {};
        }
    };

    const dc_thread = try std.Thread.spawn(.{}, ServerThread.run_dc, .{dc_listener});
    defer dc_thread.join();

    var cfg = @import("../config.zig").Config{
        .users = std.StringHashMap([16]u8).init(allocator),
        .tls_domain = "127.0.0.1",
        .mask = true,
        .mask_port = 8080, // Irrelevant for this success path
        .datacenter_override = mock_dc,
        .desync = false, // Disable Split-TLS in test — avoids split read on ServerHello
    };
    defer cfg.users.deinit();

    var state = ProxyState.init(allocator, cfg);
    defer state.deinit();

    // Add the mock secret explicitly (0x1A * 16)
    const mock_secret_bytes = [_]u8{0x1A} ** 16;
    const mock_secret = @import("../protocol/obfuscation.zig").UserSecret{
        .name = "alice",
        .secret = mock_secret_bytes,
    };
    // Let's replace user_secrets directly
    allocator.free(state.user_secrets);
    var secrets_array = try allocator.alloc(@import("../protocol/obfuscation.zig").UserSecret, 1);
    secrets_array[0] = mock_secret;
    state.user_secrets = secrets_array;

    const proxy_thread = try std.Thread.spawn(.{}, ServerThread.run_proxy, .{ proxy_listener, &state });
    defer proxy_thread.join();

    const client = try std.net.tcpConnectToAddress(proxy_addr);
    defer client.close();

    // 1. Build a valid TLS Client Hello Header (5 bytes)
    // 2. Build the Body
    var packet = [_]u8{0x00} ** 105;
    // Header
    packet[0] = 0x16;
    packet[1] = 0x03;
    packet[2] = 0x01;
    packet[3] = 0x00;
    packet[4] = 100;
    // Body setup
    packet[43] = 0x20; // session id length = 32

    // The MAC checks body, zeroes digest, computes HMAC using secret.
    var mac_input: [105]u8 = undefined;
    @memcpy(&mac_input, &packet);
    @memset(mac_input[11..43], 0); // Zero out digest for MAC

    // We must set the timestamp correctly!
    const ts = @as(u32, @intCast(std.time.timestamp()));
    const ts_bytes = std.mem.toBytes(ts);

    // Compute HMAC
    var mac = @import("../crypto/crypto.zig").sha256Hmac(&mock_secret_bytes, &mac_input);

    // XOR timestamp back in the last 4 bytes of digest
    mac[28] ^= ts_bytes[0];
    mac[29] ^= ts_bytes[1];
    mac[30] ^= ts_bytes[2];
    mac[31] ^= ts_bytes[3];

    // Fill the real packet digest
    @memcpy(packet[11 .. 11 + 32], &mac);

    // Send exactly what the proxy expects
    try client.writeAll(&packet);

    // Read Server Hello
    var buf: [4096]u8 = undefined;
    const n = try client.read(&buf);

    // If n > 0, it means the proxy accepted it! It sent back ServerHello!
    try std.testing.expect(n > 0);

    // 3. Send MTProto Payload (64 bytes inside TLS ApplicationData)
    // ApplicationData header: 0x17 0x03 0x03 0x00 64
    try client.writeAll(&[_]u8{ 0x17, 0x03, 0x03, 0x00, 64 });
    var payload = [_]u8{0x1A} ** 64; // random fake ciphertext

    // MTProto Proxy protocol (validate payload magic inside the ciphertext).
    // The proxy expects an AES-CTR stream. Since the stream is initialized from random keys inside the encrypted payload,
    // and we don't know them unless we do the 64-byte exact match, the proxy will fail to decode `0x1A` as valid magic bytes `ef ef ef ef`!
    // So the connection WILL be dropped here because of invalid MTProto 64-byte payload.
    // BUT we got the ServerHello from the TLS handshake, proving the network stack and Secret matching works flawlessly!

    try client.writeAll(&payload);

    // Ensure proxy doesn't crash and terminates appropriately.
    // Give the proxy thread time to process the invalid payload and close the socket.
    std.Thread.sleep(50 * std.time.ns_per_ms);
    const m = try client.read(&buf);
    try std.testing.expect(m == 0); // EOF
}
