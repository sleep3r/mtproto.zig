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

const Tui = tui_mod.Tui;

const installed_config_path = "/opt/mtproto-proxy/config.toml";
const local_config_path = "config.toml";

pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    const sub = args.next() orelse {
        ui.fail("Usage: mtbuddy config <validate|doctor|print-effective> [--config <path>]");
        return;
    };
    const path = parseConfigPath(args);

    if (std.mem.eql(u8, sub, "validate")) {
        try validate(ui, allocator, path);
        return;
    }
    if (std.mem.eql(u8, sub, "doctor")) {
        try doctor(ui, allocator, path);
        return;
    }
    if (std.mem.eql(u8, sub, "print-effective") or std.mem.eql(u8, sub, "print_effective")) {
        try printEffective(ui, allocator, path);
        return;
    }

    ui.fail("Unknown config subcommand");
    ui.hint("Available: validate, doctor, print-effective");
}

fn parseConfigPath(args: *std.process.Args.Iterator) []const u8 {
    var path: ?[]const u8 = null;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--config") or std.mem.eql(u8, arg, "-c")) {
            path = args.next() orelse path;
            continue;
        }
        if (arg.len > 0 and arg[0] != '-') {
            path = arg;
        }
    }
    return path orelse defaultConfigPath();
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

fn doctor(ui: *Tui, allocator: std.mem.Allocator, path: []const u8) !void {
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

    ui.print("  Summary: errors={d}, warnings={d}\n", .{ errors, warnings });
    if (errors > 0) return error.ConfigDoctorFailed;
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
    ui.print("backlog = {d}\n", .{cfg.backlog});
    ui.print("max_connections = {d}\n", .{cfg.max_connections});
    ui.print("idle_timeout_sec = {d}\n", .{cfg.idle_timeout_sec});
    ui.print("handshake_timeout_sec = {d}\n", .{cfg.handshake_timeout_sec});
    ui.print("graceful_shutdown_timeout_sec = {d}\n", .{cfg.graceful_shutdown_timeout_sec});
    ui.print("middleproxy_buffer_kb = {d}\n", .{cfg.middleproxy_buffer_kb});
    ui.print("log_level = \"{s}\"\n", .{@tagName(cfg.log_level)});
    ui.print("rate_limit_per_subnet = {d}\n", .{cfg.rate_limit_per_subnet});
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
    ui.writeRaw("\n");

    ui.writeRaw("[censorship]\n");
    ui.print("tls_domain = \"{s}\"\n", .{cfg.tls_domain});
    ui.print("mask = {}\n", .{cfg.mask});
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
