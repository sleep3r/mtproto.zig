//! Config diagnostics commands for mtbuddy.
//!
//! Provides:
//! - mtbuddy config validate
//! - mtbuddy config doctor
//! - mtbuddy config print-effective

const std = @import("std");
const tui_mod = @import("tui.zig");
const sys = @import("sys.zig");
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

fn runNetworkDoctor(
    ui: *Tui,
    allocator: std.mem.Allocator,
    cfg: *const Config,
    errors: *usize,
    warnings: *usize,
) void {
    ui.writeRaw("\n");
    ui.section("Network probes");

    switch (cfg.upstream_mode) {
        .socks5, .http => {
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
        },
        .tunnel => {
            if (probeTunnelMetadata(allocator, cfg)) {
                ui.ok("Telegram metadata fetch works through configured tunnel interface");
            } else {
                ui.warn("Telegram metadata fetch through tunnel interface failed");
                warnings.* += 1;
            }
        },
        .auto, .direct => {
            if (probeTcpEndpoint(allocator, "149.154.175.50", 443, 3000)) {
                ui.ok("Telegram DC1 TCP endpoint is reachable");
            } else {
                ui.fail("Telegram DC1 TCP endpoint is not reachable");
                errors.* += 1;
            }

            // The direct std.http fetch has no explicit timeout; on a blackholed
            // route it blocks on the OS TCP connect timeout (up to ~2 min). Warn
            // the operator so a slow probe doesn't look like a hang.
            ui.hint("Probing core.telegram.org directly (may take up to the OS connect timeout on a censored route)...");
            const bytes = http_fetch.fetchUrlBytes(allocator, middle_proxy_config_url) catch null;
            if (bytes) |body| {
                allocator.free(body);
                ui.ok("Telegram metadata fetch works directly");
            } else {
                ui.warn("Telegram metadata fetch failed directly");
                warnings.* += 1;
            }
        },
    }
}

fn probeTunnelMetadata(allocator: std.mem.Allocator, cfg: *const Config) bool {
    var idx: usize = 0;
    while (cfg.tunnelCandidateAt(idx)) |iface| : (idx += 1) {
        const bytes = http_fetch.fetchUrlBytesViaInterface(allocator, middle_proxy_config_url, iface) catch continue;
        allocator.free(bytes);
        return true;
    }
    return false;
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
