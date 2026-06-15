//! Config diagnostics commands for mtbuddy.
//!
//! Provides:
//! - mtbuddy config validate
//! - mtbuddy config doctor
//! - mtbuddy config print-effective

const std = @import("std");
const tui_mod = @import("tui.zig");
const sys = @import("sys.zig");
const fronting_domain = @import("fronting_domain.zig");
const Config = @import("proxy_config").Config;
const http_fetch = @import("proxy_http_fetch");
const net_helpers = @import("proxy_net_helpers");

const Tui = tui_mod.Tui;
const posix = std.posix;

const installed_config_path = "/opt/mtproto-proxy/config.toml";
const local_config_path = "config.toml";
const middle_proxy_config_url = "https://core.telegram.org/getProxyConfig";

const ConfigCmdOpts = struct {
    path: []const u8,
    network: bool = false,
};

pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    const sub = args.next() orelse {
        ui.fail("Usage: mtbuddy config <validate|doctor|print-effective> [--config <path>] [--network]");
        return;
    };
    const opts = parseConfigOpts(args);

    if (std.mem.eql(u8, sub, "validate")) {
        try validate(ui, allocator, opts.path);
        return;
    }
    if (std.mem.eql(u8, sub, "doctor")) {
        try doctor(ui, allocator, opts.path, opts.network);
        return;
    }
    if (std.mem.eql(u8, sub, "print-effective") or std.mem.eql(u8, sub, "print_effective")) {
        try printEffective(ui, allocator, opts.path);
        return;
    }

    ui.fail("Unknown config subcommand");
    ui.hint("Available: validate, doctor, print-effective");
}

fn isNetworkFlag(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--network");
}

fn parseConfigOpts(args: *std.process.Args.Iterator) ConfigCmdOpts {
    var path: ?[]const u8 = null;
    var network = false;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--config") or std.mem.eql(u8, arg, "-c")) {
            path = args.next() orelse path;
            continue;
        }
        if (isNetworkFlag(arg)) {
            network = true;
            continue;
        }
        if (arg.len > 0 and arg[0] != '-') {
            path = arg;
        }
    }
    return .{ .path = path orelse defaultConfigPath(), .network = network };
}

test "config command recognizes network doctor flag" {
    try std.testing.expect(isNetworkFlag("--network"));
    try std.testing.expect(!isNetworkFlag("--config"));
}

test "doctor - classifyDcVerdict maps reachability to verdict" {
    try std.testing.expectEqual(DcVerdict.reachable, classifyDcVerdict(2, 2));
    try std.testing.expectEqual(DcVerdict.partial, classifyDcVerdict(1, 2));
    try std.testing.expectEqual(DcVerdict.blackholed, classifyDcVerdict(0, 2));
    // Defensive edge: an empty probe set is treated as a blackhole, not "all up".
    try std.testing.expectEqual(DcVerdict.blackholed, classifyDcVerdict(0, 0));
}

test "doctor - parsePingRttMs extracts truncated milliseconds" {
    const line = "64 bytes from 149.154.175.50: icmp_seq=1 ttl=53 time=42.7 ms";
    try std.testing.expectEqual(@as(?u32, 42), parsePingRttMs(line));
    // Integer time= (BusyBox-style) and no trailing space before unit.
    try std.testing.expectEqual(@as(?u32, 7), parsePingRttMs("... time=7ms"));
    // No time= token (host unreachable / ping blocked) -> null.
    try std.testing.expectEqual(@as(?u32, null), parsePingRttMs("100% packet loss"));
    try std.testing.expectEqual(@as(?u32, null), parsePingRttMs("time="));
}

test "doctor - isSafeInterfaceName rejects shell metacharacters" {
    try std.testing.expect(isSafeInterfaceName("awg0"));
    try std.testing.expect(isSafeInterfaceName("wg0"));
    try std.testing.expect(isSafeInterfaceName("eth0.100"));
    try std.testing.expect(!isSafeInterfaceName(""));
    try std.testing.expect(!isSafeInterfaceName("awg0; rm -rf /"));
    try std.testing.expect(!isSafeInterfaceName("$(reboot)"));
    try std.testing.expect(!isSafeInterfaceName("a b"));
}

fn defaultConfigPath() []const u8 {
    if (sys.fileExists(installed_config_path)) return installed_config_path;
    return local_config_path;
}

fn loadConfig(ui: *Tui, allocator: std.mem.Allocator, path: []const u8) !Config {
    return Config.loadFromFile(allocator, path) catch |err| {
        ui.print("  failed to load {s}: {any}\n", .{ path, err });
        return error.ConfigLoadFailed;
    };
}

fn validate(ui: *Tui, allocator: std.mem.Allocator, path: []const u8) !void {
    var cfg = try loadConfig(ui, allocator, path);
    defer cfg.deinit(allocator);

    var errors: usize = 0;
    if (cfg.users.count() == 0) {
        ui.fail("[access.users] is empty");
        errors += 1;
    }
    if (cfg.hasLocalMaskPortCollision()) {
        ui.fail("server.port collides with local censorship.mask_port (local Nginx clash)");
        errors += 1;
    }
    switch (cfg.upstream_mode) {
        .socks5, .http => {
            if (cfg.upstream_proxy_host == null or cfg.upstream_proxy_port == 0) {
                if (cfg.allow_direct_fallback) {
                    ui.warn("upstream proxy host/port missing, but allow_direct_fallback=true");
                } else {
                    ui.fail("upstream proxy host/port missing and allow_direct_fallback=false");
                    errors += 1;
                }
            }
        },
        else => {},
    }

    if (errors > 0) return error.ConfigValidationFailed;
    ui.ok("Config is valid");
    ui.hint(path);
}

fn doctor(ui: *Tui, allocator: std.mem.Allocator, path: []const u8, network: bool) !void {
    var cfg = try loadConfig(ui, allocator, path);
    defer cfg.deinit(allocator);

    ui.section("Config doctor");
    ui.info(path);

    var errors: usize = 0;
    var warnings: usize = 0;

    if (cfg.users.count() == 0) {
        ui.fail("[access.users] is empty");
        errors += 1;
    } else {
        ui.ok("users configured");
    }

    if (cfg.hasLocalMaskPortCollision()) {
        ui.fail("server.port == censorship.mask_port in local masking mode");
        errors += 1;
    } else if (cfg.mask and cfg.mask_target != null) {
        ui.ok("masking uses custom mask_target");
    } else if (cfg.mask and cfg.mask_port == 443) {
        ui.ok("masking uses remote tls_domain:443 (no local bind collision)");
    }

    switch (cfg.upstream_mode) {
        .socks5, .http => {
            if (cfg.upstream_proxy_host == null or cfg.upstream_proxy_port == 0) {
                if (cfg.allow_direct_fallback) {
                    ui.warn("upstream proxy host/port missing, direct fallback is enabled");
                    warnings += 1;
                } else {
                    ui.fail("upstream proxy host/port missing with fail-closed mode");
                    errors += 1;
                }
            } else {
                ui.ok("upstream proxy endpoint configured");
            }
        },
        else => {},
    }

    if (cfg.use_middle_proxy and cfg.middleproxy_buffer_kb < 1024) {
        ui.warn("middleproxy_buffer_kb < 1024 may break media downloads");
        warnings += 1;
    }
    if (cfg.use_middle_proxy and cfg.max_connections > 2000) {
        ui.warn("high max_connections with middle proxy can require large RAM");
        warnings += 1;
    }
    if (cfg.unsafe_override_limits) {
        ui.warn("unsafe_override_limits=true disables RAM safety clamp");
        warnings += 1;
    }

    if (cfg.metrics.enabled) {
        const host = cfg.metrics.effectiveHost();
        if (!isLoopbackHost(host)) {
            ui.warn("metrics endpoint is not loopback-bound");
            warnings += 1;
        } else {
            ui.ok("metrics endpoint is loopback-bound");
        }
    }

    var unknown_direct_users: usize = 0;
    var direct_it = cfg.direct_users.iterator();
    while (direct_it.next()) |entry| {
        if (!cfg.users.contains(entry.key_ptr.*)) {
            unknown_direct_users += 1;
        }
    }
    if (unknown_direct_users > 0) {
        ui.warn("access.direct_users contains unknown users");
        warnings += 1;
    }

    if (network) {
        runNetworkDoctor(ui, allocator, &cfg, &errors, &warnings);
    } else {
        ui.hint("Run `mtbuddy config doctor --network` to test Telegram/upstream reachability.");
    }

    ui.print("  Summary: errors={d}, warnings={d}\n", .{ errors, warnings });
    if (errors > 0) return error.ConfigDoctorFailed;
}

/// Well-known primary Telegram DC IPs (DC2 Amsterdam, DC4 Amsterdam). A
/// non-blocking SYN to :443 either connects (path works) or times out (the
/// route is an L3 blackhole, the shape of the current RU IP block). Picking two
/// independent DCs avoids a single-DC maintenance window reading as "blocked".
const telegram_dc_probes = [_]struct { label: []const u8, ip: []const u8 }{
    .{ .label = "DC2", .ip = "149.154.167.50" },
    .{ .label = "DC4", .ip = "149.154.175.50" },
};

/// Verdict for the direct-reachability probe. `classifyDcVerdict` maps the
/// per-DC connect results to one of these so the messaging is a pure,
/// unit-testable function of "how many DCs answered".
const DcVerdict = enum { reachable, partial, blackholed };

/// Classify direct DC reachability from connect results. Pure helper so the
/// verdict wording can be tested without touching the network.
///   all DCs up        -> reachable  ("DCs reachable directly")
///   some up, some down -> partial   (asymmetric block / one DC in maintenance)
///   none up           -> blackholed (SYN timeout on every DC == IP blackhole)
fn classifyDcVerdict(reachable_count: usize, total: usize) DcVerdict {
    if (total == 0 or reachable_count == 0) return .blackholed;
    if (reachable_count == total) return .reachable;
    return .partial;
}

/// Parse the round-trip time (in whole milliseconds, truncated) out of a line
/// of `ping` output, e.g. "... time=42.5 ms" or "... time=42 ms". Returns null
/// when no `time=` token is present (host unreachable, ping blocked, etc.).
/// Pure helper, unit-tested against real ping wording.
fn parsePingRttMs(output: []const u8) ?u32 {
    const marker = "time=";
    const idx = std.mem.indexOf(u8, output, marker) orelse return null;
    var rest = output[idx + marker.len ..];
    // Number runs up to the first non [0-9.] character (space before "ms").
    var end: usize = 0;
    while (end < rest.len) : (end += 1) {
        const c = rest[end];
        if (!((c >= '0' and c <= '9') or c == '.')) break;
    }
    if (end == 0) return null;
    rest = rest[0..end];
    const rtt_f = std.fmt.parseFloat(f64, rest) catch return null;
    // Reject out-of-range values so @intFromFloat can't panic on a garbage RTT.
    if (rtt_f < 0 or rtt_f > @as(f64, std.math.maxInt(u32))) return null;
    return @intFromFloat(rtt_f);
}

/// Linux interface names are short and restricted; reject anything outside that
/// set defensively so a config value can never smuggle arguments into the
/// `ping`/`curl` argv (even though we never go through a shell).
fn isSafeInterfaceName(iface: []const u8) bool {
    if (iface.len == 0 or iface.len > 32) return false;
    for (iface) |c| {
        const ok_char = (c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or
            c == '_' or c == '-' or c == '.' or c == '@' or c == ':';
        if (!ok_char) return false;
    }
    return true;
}

/// Scratch buffer for one-off "prefix + value" status lines. The doctor is
/// single-threaded and every message is consumed by ui.ok/ui.warn before the
/// next joinMsg call, so a shared static buffer is safe and avoids per-line
/// allocations (and the leaks that `ui.ok(allocPrint(...) catch ...)` invites).
var join_msg_buf: [160]u8 = undefined;

/// Format "prefix"++"value" into the shared scratch buffer for a status line.
fn joinMsg(prefix: []const u8, value: []const u8) []const u8 {
    return std.fmt.bufPrint(&join_msg_buf, "{s}{s}", .{ prefix, value }) catch prefix;
}

fn runNetworkDoctor(
    ui: *Tui,
    allocator: std.mem.Allocator,
    cfg: *const Config,
    errors: *usize,
    warnings: *usize,
) void {
    ui.writeRaw("\n");
    ui.section("Network probes");

    if (fronting_domain.warnIfPoorFrontingDomain(ui, allocator, cfg.tls_domain) == .mismatch) {
        warnings.* += 1;
    }

    switch (cfg.upstream_mode) {
        .socks5, .http => runNetworkDoctorProxy(ui, allocator, cfg, errors, warnings),
        .tunnel => runNetworkDoctorTunnel(ui, allocator, cfg, errors, warnings),
        .auto, .direct => runNetworkDoctorDirect(ui, allocator, cfg, errors, warnings),
    }

    // Cheap, always-useful: confirm a client link can actually be generated.
    runNetworkDoctorLink(ui, cfg, warnings);
}

fn runNetworkDoctorProxy(
    ui: *Tui,
    allocator: std.mem.Allocator,
    cfg: *const Config,
    errors: *usize,
    warnings: *usize,
) void {
    _ = warnings;
    const host = cfg.upstream_proxy_host orelse {
        ui.fail("upstream proxy host is missing");
        errors.* += 1;
        return;
    };
    if (cfg.upstream_proxy_port == 0) {
        ui.fail("upstream proxy port is missing");
        errors.* += 1;
        return;
    }

    if (probeTcpEndpoint(allocator, host, cfg.upstream_proxy_port, 3000)) {
        ui.ok("upstream proxy TCP endpoint is reachable");
    } else {
        ui.fail("upstream proxy TCP endpoint is not reachable");
        errors.* += 1;
    }

    const kind: http_fetch.ProxyKind = if (cfg.upstream_mode == .socks5) .socks5 else .http_connect;
    const bytes = http_fetch.fetchUrlBytesViaProxy(allocator, middle_proxy_config_url, .{
        .kind = kind,
        .host = host,
        .port = cfg.upstream_proxy_port,
        .username = cfg.upstream_proxy_username,
        .password = cfg.upstream_proxy_password,
    }) catch null;
    if (bytes) |body| {
        allocator.free(body);
        ui.ok("Telegram metadata fetch works through configured upstream");
    } else {
        ui.fail("Telegram metadata fetch through configured upstream failed");
        errors.* += 1;
    }
}

/// "Am I blocked?" probe for direct/auto egress. Hits a couple of well-known DC
/// IPs and prints a single clear verdict so an operator can tell an L3 blackhole
/// (the current RU block: SYN times out) from a working path.
fn runNetworkDoctorDirect(
    ui: *Tui,
    allocator: std.mem.Allocator,
    cfg: *const Config,
    errors: *usize,
    warnings: *usize,
) void {
    _ = cfg; // direct probe uses fixed DC IPs; config is irrelevant here.
    ui.hint("Probing well-known Telegram DC IPs on :443 (SYN timeout vs connect)...");

    var reachable_count: usize = 0;
    for (telegram_dc_probes) |dc| {
        if (probeTcpEndpoint(allocator, dc.ip, 443, 3000)) {
            reachable_count += 1;
            ui.ok(joinMsg("reached ", dc.ip));
        } else {
            ui.warn(joinMsg("no SYN-ACK from ", dc.ip));
        }
    }

    var blackholed = false;
    switch (classifyDcVerdict(reachable_count, telegram_dc_probes.len)) {
        .reachable => ui.ok("Telegram DCs reachable directly"),
        .partial => {
            ui.warn("Some Telegram DCs reachable, some not (asymmetric block or DC maintenance)");
            warnings.* += 1;
        },
        .blackholed => {
            // A SYN timeout on every DC IP is *suggestive* of an L3 blackhole, but it
            // also fires on IPv6-only paths, a local firewall, or transient loss — so
            // don't hard-fail here. Warn, and let the metadata fetch below arbitrate
            // (only escalate to an error if that fails too).
            ui.warn("No SYN-ACK from any probed DC IP (possible L3 blackhole, IPv6-only path, or local firewall)");
            ui.hint("If the metadata fetch below also fails, egress via a tunnel/clean IP (upstream=tunnel/socks5).");
            warnings.* += 1;
            blackholed = true;
        },
    }

    // Confirm the full DC handshake, not just TCP: on a censored route this can
    // block on the OS connect timeout, so warn the operator before it runs.
    ui.hint("Fetching Telegram metadata directly (may take up to the OS connect timeout on a censored route)...");
    const bytes = http_fetch.fetchUrlBytes(allocator, middle_proxy_config_url) catch null;
    if (bytes) |body| {
        allocator.free(body);
        ui.ok("Telegram metadata fetch works directly");
    } else if (blackholed) {
        ui.fail("DC IPs unreachable (SYN timeout) AND metadata fetch failed - egress via a tunnel/clean IP");
        errors.* += 1;
    } else {
        ui.warn("Telegram metadata fetch failed directly (DPI/TLS interference or DNS)");
        warnings.* += 1;
    }
}

/// "Am I blocked?" probe for tunnel egress. Confirms a DC is reachable *through*
/// the tunnel interface and reports the bound-interface RTT, so an operator can
/// see the tunnel is actually carrying traffic (not just that it exists).
fn runNetworkDoctorTunnel(
    ui: *Tui,
    allocator: std.mem.Allocator,
    cfg: *const Config,
    errors: *usize,
    warnings: *usize,
) void {
    _ = errors;
    ui.hint("Probing a Telegram DC through the tunnel interface...");

    const dc_ip = telegram_dc_probes[telegram_dc_probes.len - 1].ip; // 149.154.175.50

    var idx: usize = 0;
    var probed: usize = 0;
    var any_reachable = false;
    while (cfg.tunnelCandidateAt(idx)) |iface| : (idx += 1) {
        if (!isSafeInterfaceName(iface)) {
            ui.warn(joinMsg("skipping interface with unexpected name: ", iface));
            warnings.* += 1;
            continue;
        }
        probed += 1;

        // L7 check: does a DC metadata fetch egress through this interface?
        const reachable = blk: {
            const bytes = http_fetch.fetchUrlBytesViaInterface(allocator, middle_proxy_config_url, iface) catch break :blk false;
            allocator.free(bytes);
            break :blk true;
        };

        if (reachable) {
            any_reachable = true;
            if (probeTunnelRtt(allocator, iface, dc_ip)) |rtt| {
                var buf: [128]u8 = undefined;
                const msg = std.fmt.bufPrint(
                    &buf,
                    "reachable via tunnel {s} (RTT {d}ms)",
                    .{ iface, rtt },
                ) catch joinMsg("reachable via tunnel ", iface);
                ui.ok(msg);
            } else {
                ui.ok(joinMsg("reachable via tunnel ", iface));
                ui.hint("RTT unavailable (ICMP/ping blocked on this interface).");
            }
            break;
        } else {
            ui.warn(joinMsg("no Telegram egress via tunnel ", iface));
        }
    }

    // NOTE: rely on `probed`, not `idx`. A `break` on the first reachable interface
    // skips the `: (idx += 1)` continuation, so idx stays 0 on the happy path — using
    // it here would print a bogus "no interface" warning exactly when it worked.
    if (probed == 0) {
        ui.warn("No tunnel interface configured to probe");
        warnings.* += 1;
    } else if (!any_reachable) {
        // Glyph matches the counter: a tunnel that can't reach Telegram is a warning
        // (the proxy may still reach DCs another way), not a hard error.
        ui.warn("Telegram unreachable via tunnel (check the tunnel is up and routes Telegram)");
        warnings.* += 1;
    }
}

/// Report whether a client tg:// link can be produced from this config. Mirrors
/// the inputs `links.zig` needs (a server host + at least one user + tls_domain)
/// rather than re-deriving the secret encoding, which lives in links.zig. Skips
/// gracefully when the link-building inputs are absent.
fn runNetworkDoctorLink(ui: *Tui, cfg: *const Config, warnings: *usize) void {
    if (cfg.users.count() == 0) {
        ui.warn("No users configured - no tg:// link to generate");
        warnings.* += 1;
        return;
    }
    if (cfg.public_ip == null) {
        ui.hint("public_ip not set; links will use the auto-detected egress IP at print time.");
    }

    var buf: [96]u8 = undefined;
    const msg = std.fmt.bufPrint(
        &buf,
        "tg:// links available for {d} user(s) on port {d} (`mtbuddy links`)",
        .{ cfg.users.count(), cfg.publicLinkPort() },
    ) catch "tg:// links available (`mtbuddy links`)";
    ui.ok(msg);
}

/// Measure RTT to `host` bound to `iface` via `ping`, returning whole ms or
/// null on failure/timeout/blocked ICMP. Uses an argv array (no shell) so the
/// interface name can never be interpreted as additional arguments.
fn probeTunnelRtt(allocator: std.mem.Allocator, iface: []const u8, host: []const u8) ?u32 {
    const result = sys.exec(allocator, &.{
        "ping", "-I", iface, "-c", "1", "-W", "2", host,
    }) catch return null;
    defer result.deinit();
    return parsePingRttMs(result.stdout);
}

fn probeTcpEndpoint(allocator: std.mem.Allocator, host: []const u8, port: u16, timeout_ms: i32) bool {
    const list = net_helpers.getAddressList(allocator, host, port) catch return false;
    defer list.deinit();

    for (list.addrs) |addr| {
        if (isAddressReachable(addr, timeout_ms)) return true;
    }
    return false;
}

fn closeFd(fd: posix.fd_t) void {
    while (true) switch (posix.errno(posix.system.close(fd))) {
        .SUCCESS => return,
        .INTR => continue,
        else => return,
    };
}

fn connectSockaddr(fd: posix.fd_t, addr: *const posix.sockaddr, addr_len: posix.socklen_t) !void {
    while (true) switch (posix.errno(posix.system.connect(fd, addr, addr_len))) {
        .SUCCESS => return,
        .INTR => continue,
        .ADDRNOTAVAIL => return error.AddressUnavailable,
        .AFNOSUPPORT => return error.AddressFamilyUnsupported,
        .AGAIN, .INPROGRESS => return error.WouldBlock,
        .ALREADY => return error.ConnectionPending,
        .CONNREFUSED => return error.ConnectionRefused,
        .CONNRESET => return error.ConnectionResetByPeer,
        .HOSTUNREACH => return error.HostUnreachable,
        .NETUNREACH => return error.NetworkUnreachable,
        .TIMEDOUT => return error.Timeout,
        else => |err| return posix.unexpectedErrno(err),
    };
}

fn isAddressReachable(address: net_helpers.Address, timeout_ms: i32) bool {
    const sock_flags = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
    const family: posix.sa_family_t = switch (address) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
    const fd = fd: {
        const rc = posix.system.socket(family, sock_flags, posix.IPPROTO.TCP);
        if (posix.errno(rc) != .SUCCESS) return false;
        break :fd @as(posix.fd_t, @intCast(rc));
    };
    defer closeFd(fd);

    switch (address) {
        .ip4 => |ip4_addr| {
            var sa: posix.sockaddr.in = .{
                .family = posix.AF.INET,
                .port = std.mem.nativeToBig(u16, ip4_addr.port),
                .addr = @bitCast(ip4_addr.bytes),
            };
            connectSockaddr(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in)) catch |err| switch (err) {
                error.WouldBlock, error.ConnectionPending => {},
                else => return false,
            };
        },
        .ip6 => |ip6_addr| {
            var sa: posix.sockaddr.in6 = .{
                .family = posix.AF.INET6,
                .port = std.mem.nativeToBig(u16, ip6_addr.port),
                .flowinfo = ip6_addr.flow,
                .addr = ip6_addr.bytes,
                .scope_id = ip6_addr.interface.index,
            };
            connectSockaddr(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in6)) catch |err| switch (err) {
                error.WouldBlock, error.ConnectionPending => {},
                else => return false,
            };
        },
    }

    var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
    const ready = posix.poll(&fds, timeout_ms) catch return false;
    if (ready == 0) return false;
    const revents = fds[0].revents;
    if ((revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL)) != 0) return false;
    return (revents & posix.POLL.OUT) != 0;
}

fn printEffective(ui: *Tui, allocator: std.mem.Allocator, path: []const u8) !void {
    var cfg = try loadConfig(ui, allocator, path);
    defer cfg.deinit(allocator);

    ui.section("Effective config");
    ui.info(path);
    ui.writeRaw("\n");

    ui.writeRaw("[general]\n");
    ui.print("use_middle_proxy = {}\n", .{cfg.use_middle_proxy});
    ui.print("force_media_middle_proxy = {}\n", .{cfg.force_media_middle_proxy});
    ui.writeRaw("\n");

    ui.writeRaw("[server]\n");
    ui.print("port = {d}\n", .{cfg.port});
    if (cfg.bind_address) |bind| {
        ui.print("bind_address = \"{s}\"\n", .{bind});
    } else {
        ui.writeRaw("bind_address = <all interfaces>\n");
    }
    if (cfg.public_ip) |public_ip| {
        ui.print("public_ip = \"{s}\"\n", .{public_ip});
    }
    if (cfg.public_port) |public_port| {
        ui.print("public_port = {d}\n", .{public_port});
    }
    if (cfg.middle_proxy_nat_ip) |middle_proxy_nat_ip| {
        ui.print("middle_proxy_nat_ip = \"{s}\"\n", .{middle_proxy_nat_ip});
    }
    ui.print("backlog = {d}\n", .{cfg.backlog});
    ui.print("max_connections = {d}\n", .{cfg.max_connections});
    ui.print("idle_timeout_sec = {d}\n", .{cfg.idle_timeout_sec});
    ui.print("handshake_timeout_sec = {d}\n", .{cfg.handshake_timeout_sec});
    ui.print("dc_connect_timeout_sec = {d}\n", .{cfg.dc_connect_timeout_sec});
    ui.print("graceful_shutdown_timeout_sec = {d}\n", .{cfg.graceful_shutdown_timeout_sec});
    ui.print("middleproxy_buffer_kb = {d}\n", .{cfg.middleproxy_buffer_kb});
    ui.print("log_level = \"{s}\"\n", .{@tagName(cfg.log_level)});
    ui.print("rate_limit_per_subnet = {d}\n", .{cfg.rate_limit_per_subnet});
    ui.print("handshake_flood_guard_enabled = {}\n", .{cfg.handshake_flood_guard_enabled});
    ui.print("handshake_flood_guard_threshold = {d}\n", .{cfg.handshake_flood_guard_threshold});
    ui.print("handshake_flood_guard_window_sec = {d}\n", .{cfg.handshake_flood_guard_window_sec});
    ui.print("handshake_flood_guard_block_sec = {d}\n", .{cfg.handshake_flood_guard_block_sec});
    ui.print("unsafe_override_limits = {}\n", .{cfg.unsafe_override_limits});
    ui.writeRaw("\n");

    ui.writeRaw("[upstream]\n");
    ui.print("type = \"{s}\"\n", .{@tagName(cfg.upstream_mode)});
    ui.print("allow_direct_fallback = {}\n", .{cfg.allow_direct_fallback});
    if (cfg.upstream_proxy_host) |host| {
        ui.print("proxy_host = \"{s}\"\n", .{host});
    }
    if (cfg.upstream_proxy_port > 0) {
        ui.print("proxy_port = {d}\n", .{cfg.upstream_proxy_port});
    }
    if (cfg.upstream_tunnel_interface) |iface| {
        ui.print("tunnel_interface = \"{s}\"\n", .{iface});
    }
    if (cfg.upstream_tunnel_interfaces.len > 0) {
        ui.writeRaw("tunnel_interfaces = [");
        for (cfg.upstream_tunnel_interfaces, 0..) |iface, idx| {
            if (idx > 0) ui.writeRaw(", ");
            ui.print("\"{s}\"", .{iface});
        }
        ui.writeRaw("]\n");
    }
    if (cfg.upstream_tunnel_pinned_interface) |iface| {
        ui.print("tunnel_pinned_interface = \"{s}\"\n", .{iface});
    }
    ui.writeRaw("\n");

    ui.writeRaw("[censorship]\n");
    ui.print("tls_domain = \"{s}\"\n", .{cfg.tls_domain});
    ui.print("mask = {}\n", .{cfg.mask});
    if (cfg.mask_target) |target| {
        ui.print("mask_target = \"{s}\"\n", .{target});
    }
    ui.print("mask_port = {d}\n", .{cfg.mask_port});
    ui.print("desync = {}\n", .{cfg.desync});
    ui.print("drs = {}\n", .{cfg.drs});
    ui.print("fast_mode = {}\n", .{cfg.fast_mode});
    ui.writeRaw("\n");

    ui.writeRaw("[metrics]\n");
    ui.print("enabled = {}\n", .{cfg.metrics.enabled});
    ui.print("host = \"{s}\"\n", .{cfg.metrics.effectiveHost()});
    ui.print("port = {d}\n", .{cfg.metrics.port});
    ui.writeRaw("\n");

    ui.print("[access.users] count = {d}\n", .{cfg.users.count()});
    ui.print("[access.direct_users] count = {d}\n", .{cfg.direct_users.count()});
}

fn isLoopbackHost(host: []const u8) bool {
    return std.mem.eql(u8, host, "127.0.0.1") or
        std.mem.eql(u8, host, "::1") or
        std.mem.eql(u8, host, "localhost");
}
