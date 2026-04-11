//! mtbuddy — interactive installer & control panel for mtproto.zig
//!
//! Replaces the collection of bash scripts in deploy/ with a single
//! Zig binary. Supports both interactive TUI mode (--interactive)
//! and non-interactive CLI with flags.
//!
//! One-liner install:
//!   sudo mtbuddy install --port 443 --domain wb.ru --yes
//!   sudo mtbuddy install --port 443 --domain wb.ru --secret <hex> --user myuser --yes
//!
//! Interactive wizard:
//!   sudo mtbuddy --interactive

const std = @import("std");
const i18n = @import("i18n.zig");
const tui_mod = @import("tui.zig");
const install = @import("install.zig");
const update = @import("update.zig");
const masking = @import("masking.zig");
const nfqws = @import("nfqws.zig");
const tunnel = @import("tunnel.zig");
const recovery = @import("recovery.zig");
const dashboard = @import("dashboard.zig");
const ipv6hop = @import("ipv6hop.zig");
const uninstall = @import("uninstall.zig");

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;

const version = "0.16.0"; // x-release-please-version

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // skip program name

    // ── Parse global flags ──
    var lang: ?i18n.Lang = null;
    var interactive = false;
    var command: ?[]const u8 = null;
    var remaining_args = args;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--interactive") or std.mem.eql(u8, arg, "-i")) {
            interactive = true;
        } else if (std.mem.eql(u8, arg, "--lang")) {
            if (args.next()) |lang_val| {
                lang = if (std.mem.eql(u8, lang_val, "ru")) .ru else .en;
            }
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printHelp();
            return;
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            printVersion();
            return;
        } else {
            command = arg;
            remaining_args = args;
            break;
        }
    }

    const resolved_lang = lang orelse i18n.Lang.fromEnv();
    var ui = Tui.init(resolved_lang);

    // ── Interactive mode ──
    if (interactive) {
        ui.banner(version);

        if (lang == null) {
            const lang_choice = try ui.menu(
                i18n.get(.en, .select_language),
                &.{
                    i18n.get(.en, .lang_english),
                    i18n.get(.en, .lang_russian),
                },
            );
            ui.lang = if (lang_choice == 1) .ru else .en;
        }

        try interactiveMain(&ui, allocator);
        return;
    }

    // ── CLI dispatch ──
    if (command) |cmd| {
        if (std.mem.eql(u8, cmd, "install")) {
            return install.run(&ui, allocator, &remaining_args);
        } else if (std.mem.eql(u8, cmd, "uninstall")) {
            return uninstall.run(&ui, allocator, &remaining_args);
        } else if (std.mem.eql(u8, cmd, "update")) {
            return update.run(&ui, allocator, &remaining_args);
        } else if (std.mem.eql(u8, cmd, "setup")) {
            if (remaining_args.next()) |sub| {
                if (std.mem.eql(u8, sub, "masking")) {
                    return masking.run(&ui, allocator, &remaining_args);
                } else if (std.mem.eql(u8, sub, "nfqws")) {
                    return nfqws.run(&ui, allocator, &remaining_args);
                } else if (std.mem.eql(u8, sub, "tunnel")) {
                    return tunnel.run(&ui, allocator, &remaining_args);
                } else if (std.mem.eql(u8, sub, "recovery")) {
                    return recovery.run(&ui, allocator, &remaining_args);
                } else if (std.mem.eql(u8, sub, "dashboard")) {
                    return dashboard.run(&ui, allocator, &remaining_args);
                } else {
                    ui.print("\n  {s}Unknown setup subcommand:{s} {s}\n", .{ Color.err, Color.reset, sub });
                    ui.hint("Available: masking, nfqws, tunnel, recovery, dashboard");
                    return;
                }
            } else {
                ui.fail("Usage: mtbuddy setup <masking|nfqws|tunnel|recovery|dashboard>");
                return;
            }
        } else if (std.mem.eql(u8, cmd, "ipv6-hop")) {
            return ipv6hop.run(&ui, allocator, &remaining_args);
        } else if (std.mem.eql(u8, cmd, "update-dns")) {
            return ipv6hop.updateDnsA(&ui, allocator, &remaining_args);
        } else if (std.mem.eql(u8, cmd, "status")) {
            showStatus(&ui, allocator);
            return;
        } else {
            ui.print("\n  {s}Unknown command:{s} {s}\n\n", .{ Color.err, Color.reset, cmd });
            printHelp();
            return;
        }
    }

    // No command — show help
    printHelp();
}

const Action = enum {
    install,
    update,
    masking,
    tunnel,
    recovery,
    dashboard,
    ipv6hop,
    status,
    restart,
    uninstall,
    exit,
};

fn interactiveMain(ui: *Tui, allocator: std.mem.Allocator) !void {
    while (true) {
        const sys = @import("sys.zig");
        const is_installed = sys.fileExists("/opt/mtproto-proxy");

        var items: std.ArrayList([]const u8) = .empty;
        defer items.deinit(allocator);
        var actions: std.ArrayList(Action) = .empty;
        defer actions.deinit(allocator);

        if (!is_installed) {
            try items.append(allocator, i18n.get(ui.lang, .menu_install));
            try actions.append(allocator, .install);
        }

        if (is_installed) {
            try items.append(allocator, i18n.get(ui.lang, .menu_update));
            try actions.append(allocator, .update);
            try items.append(allocator, i18n.get(ui.lang, .menu_setup_masking));
            try actions.append(allocator, .masking);
            try items.append(allocator, i18n.get(ui.lang, .menu_setup_tunnel));
            try actions.append(allocator, .tunnel);

            const has_dashboard = sys.isServiceActive("proxy-monitor");
            const has_recovery = sys.isServiceActive("mtproto-mask-health.timer");

            if (!has_dashboard) {
                try items.append(allocator, i18n.get(ui.lang, .menu_setup_dashboard));
                try actions.append(allocator, .dashboard);
            }
            if (!has_recovery) {
                try items.append(allocator, i18n.get(ui.lang, .menu_setup_recovery));
                try actions.append(allocator, .recovery);
            }
            try items.append(allocator, i18n.get(ui.lang, .menu_ipv6_hop));
            try actions.append(allocator, .ipv6hop);
            try items.append(allocator, i18n.get(ui.lang, .menu_status));
            try actions.append(allocator, .status);
            try items.append(allocator, i18n.get(ui.lang, .menu_restart));
            try actions.append(allocator, .restart);
            try items.append(allocator, i18n.get(ui.lang, .menu_uninstall));
            try actions.append(allocator, .uninstall);
        }

        try items.append(allocator, i18n.get(ui.lang, .menu_exit));
        try actions.append(allocator, .exit);

        const choice_idx = try ui.menu(i18n.get(ui.lang, .menu_title), items.items);
        const action = actions.items[choice_idx];

        switch (action) {
            .install => try install.runInteractive(ui, allocator),
            .update => try update.runInteractive(ui, allocator),
            .masking => try masking.runInteractive(ui, allocator),
            .tunnel => try tunnel.runInteractive(ui, allocator),
            .dashboard => try dashboard.runInteractive(ui, allocator),
            .recovery => try recovery.runInteractive(ui, allocator),
            .ipv6hop => try ipv6hop.runInteractive(ui, allocator),
            .status => showStatus(ui, allocator),
            .restart => restartProxy(ui, allocator),
            .uninstall => try uninstall.runInteractive(ui, allocator),
            .exit => return,
        }
    }
}

fn restartProxy(ui: *Tui, allocator: std.mem.Allocator) void {
    var sp = ui.spinner("Restarting...");
    sp.start();
    _ = @import("sys.zig").exec(allocator, &.{ "systemctl", "restart", "mtproto-proxy" }) catch {};
    _ = @import("sys.zig").exec(allocator, &.{ "systemctl", "restart", "nfqws-mtproto" }) catch {};
    sp.stop(true, i18n.get(ui.lang, .restart_success));
}

fn showStatus(ui: *Tui, allocator: std.mem.Allocator) void {
    ui.section(i18n.get(ui.lang, .menu_status));

    const sys = @import("sys.zig");

    const svc_active = sys.isServiceActive("mtproto-proxy");
    if (svc_active) {
        ui.ok("mtproto-proxy is running");
    } else {
        ui.fail("mtproto-proxy is not running");
    }

    const nginx_active = sys.isServiceActive("nginx");
    if (nginx_active) {
        ui.ok("nginx is running");
    } else {
        ui.info("nginx is not running (masking may be disabled)");
    }

    const nfqws_active = sys.isServiceActive("nfqws-mtproto");
    if (nfqws_active) {
        ui.ok("nfqws-mtproto is running");
    } else {
        ui.info("nfqws-mtproto is not running (TCP desync disabled)");
    }

    const timer_active = sys.isServiceActive("mtproto-mask-health.timer");
    if (timer_active) {
        ui.ok("DPI auto-recovery is active");
    } else {
        ui.info("DPI auto-recovery is not installed");
    }

    const dashboard_active = sys.isServiceActive("proxy-monitor");
    if (dashboard_active) {
        ui.ok("monitoring dashboard is running");
        ui.summaryBox("Dashboard", &.{
            .{ .label = "Status:", .value = "active", .style = .label_value },
            .{ .label = "Port:", .value = "61208", .style = .label_value },
            .{ .label = "Service:", .value = "systemctl status proxy-monitor", .style = .label_value },
            .{ .label = "", .value = "", .style = .blank },
            .{ .label = "Access via SSH tunnel:", .value = "", .style = .highlight },
            .{ .label = "Command:", .value = "ssh -L 61208:localhost:61208 root@<ip>", .style = .label_value },
            .{ .label = "Open:", .value = "http://localhost:61208", .style = .label_value },
        });
    } else {
        ui.info("monitoring dashboard is not installed (mtbuddy setup dashboard)");
    }

    const result = @import("sys.zig").exec(allocator, &.{
        "systemctl", "status", "mtproto-proxy", "--no-pager", "-l",
    }) catch return;
    defer result.deinit();

    if (result.stdout.len > 0) {
        ui.writeRaw("\n");
        ui.print("  {s}", .{Color.dim});
        var lines = std.mem.splitScalar(u8, result.stdout, '\n');
        var count: usize = 0;
        while (lines.next()) |line| {
            if (count >= 15) break;
            ui.print("  {s}\n", .{line});
            count += 1;
        }
        ui.print("{s}\n", .{Color.reset});
    }
}

fn printHelp() void {
    var ui = Tui.init(i18n.Lang.fromEnv());

    ui.writeRaw("\n");
    ui.print("  {s}⚡ mtbuddy{s} {s}v{s}{s}  —  MTProto Proxy installer & control panel\n\n", .{
        Color.header, Color.reset,
        Color.dim,    version,
        Color.reset,
    });

    // ── One-liner examples ──
    ui.print("  {s}Quick install (one-liner):{s}\n\n", .{ Color.accent, Color.reset });
    ui.print("    {s}# Minimal — auto-generates secret:{s}\n", .{ Color.gray, Color.reset });
    ui.print("    {s}sudo mtbuddy install --port 443 --domain wb.ru --yes{s}\n\n", .{ Color.bright_yellow, Color.reset });
    ui.print("    {s}# Full control — bring your own secret and username:{s}\n", .{ Color.gray, Color.reset });
    ui.print("    {s}sudo mtbuddy install --port 443 --domain wb.ru \\\n", .{Color.bright_yellow});
    ui.print("    {s}  --secret <32-hex> --user alice --yes{s}\n\n", .{ Color.bright_yellow, Color.reset });
    ui.print("    {s}# No DPI bypass (bare install):{s}\n", .{ Color.gray, Color.reset });
    ui.print("    {s}sudo mtbuddy install --port 443 --domain wb.ru --no-dpi --yes{s}\n\n", .{ Color.bright_yellow, Color.reset });

    ui.print("  {s}Interactive wizard:{s}\n\n", .{ Color.accent, Color.reset });
    ui.print("    {s}sudo mtbuddy --interactive{s}\n\n", .{ Color.bright_yellow, Color.reset });

    // ── Commands ──
    ui.print("  {s}Commands:{s}\n\n", .{ Color.accent, Color.reset });
    printCmd(&ui, "install", "Install mtproto-proxy from release");
    printCmd(&ui, "uninstall", "Uninstall mtproto-proxy completely");
    printCmd(&ui, "update", "Update to latest GitHub release");
    printCmd(&ui, "setup masking", "Setup local Nginx DPI masking");
    printCmd(&ui, "setup nfqws", "Setup nfqws TCP desync (Zapret)");
    printCmd(&ui, "setup tunnel <conf>", "Setup VPN tunnel (AmneziaWG, WireGuard, ...)");
    printCmd(&ui, "setup dashboard", "Install web monitoring dashboard");
    printCmd(&ui, "setup recovery", "Install DPI auto-recovery");
    printCmd(&ui, "ipv6-hop", "IPv6 address rotation");
    printCmd(&ui, "update-dns <ip>", "Update Cloudflare DNS A record");
    printCmd(&ui, "status", "Show service status");
    ui.writeRaw("\n");

    // ── Install options ──
    ui.print("  {s}Install options:{s}\n\n", .{ Color.accent, Color.reset });
    printOpt(&ui, "--port,   -p <port>", "Proxy port (default: 443)");
    printOpt(&ui, "--domain, -d <domain>", "TLS masking domain (default: wb.ru)");
    printOpt(&ui, "--secret, -s <hex32>", "User secret (32 hex chars, auto-generated if omitted)");
    printOpt(&ui, "--user,   -u <name>", "Username in config.toml (default: user)");
    printOpt(&ui, "--config, -c <path>", "Use existing config.toml file");
    printOpt(&ui, "--yes,    -y", "Skip confirmation prompt (non-interactive)");
    printOpt(&ui, "--max-connections <N>", "Max proxy connections (default: 512)");
    printOpt(&ui, "--no-masking", "Disable Nginx DPI masking");
    printOpt(&ui, "--no-nfqws", "Disable nfqws TCP desync");
    printOpt(&ui, "--no-tcpmss", "Disable TCPMSS=88 clamping");
    printOpt(&ui, "--no-dpi", "Disable all DPI bypass modules");
    printOpt(&ui, "--ipv6-hop", "Enable IPv6 auto-hopping");
    printOpt(&ui, "--version, -v <tag>", "Release version to install (default: latest)");
    ui.writeRaw("\n");

    // ── Update options ──
    ui.print("  {s}Update options:{s}\n\n", .{ Color.accent, Color.reset });
    printOpt(&ui, "--version, -v <tag>", "Pin to specific release tag");
    printOpt(&ui, "--force-service", "Force systemd unit update");
    ui.writeRaw("\n");

    // ── Setup options ──
    ui.print("  {s}Setup options:{s}\n\n", .{ Color.accent, Color.reset });
    printOpt(&ui, "--domain <domain>", "TLS masking domain");
    printOpt(&ui, "--ttl <N>", "nfqws fake packet TTL (default: 6)");
    printOpt(&ui, "--remove", "Remove nfqws installation");
    ui.writeRaw("\n");

    // ── IPv6 options ──
    ui.print("  {s}IPv6 options:{s}\n\n", .{ Color.accent, Color.reset });
    printOpt(&ui, "--check", "Show current IPv6 rotation status");
    printOpt(&ui, "--auto", "Auto-rotate on ban detection");
    printOpt(&ui, "--prefix <prefix>", "IPv6 /64 prefix");
    printOpt(&ui, "--threshold <N>", "Ban detection threshold (default: 10)");
    ui.writeRaw("\n");

    // ── Global options ──
    ui.print("  {s}Global options:{s}\n\n", .{ Color.accent, Color.reset });
    printOpt(&ui, "-i, --interactive", "Interactive TUI wizard");
    printOpt(&ui, "--lang <en|ru>", "Language (default: auto-detect)");
    printOpt(&ui, "-h, --help", "Show this help");
    printOpt(&ui, "--version", "Show version");
    ui.writeRaw("\n");
}

fn printCmd(ui: *Tui, cmd: []const u8, desc: []const u8) void {
    const col = 28;
    const pad = if (cmd.len < col) col - cmd.len else 1;
    var buf: [32]u8 = undefined;
    @memset(buf[0..@min(pad, buf.len)], ' ');
    ui.print("    {s}{s}{s}{s}{s}{s}\n", .{
        Color.bright_yellow,        cmd,       Color.reset,
        buf[0..@min(pad, buf.len)], Color.dim, desc,
    });
    ui.writeRaw(Color.reset);
}

fn printOpt(ui: *Tui, flag: []const u8, desc: []const u8) void {
    const col = 30;
    const pad = if (flag.len < col) col - flag.len else 1;
    var buf: [32]u8 = undefined;
    @memset(buf[0..@min(pad, buf.len)], ' ');
    ui.print("    {s}{s}{s}{s}{s}{s}\n", .{
        Color.info,                 flag,      Color.reset,
        buf[0..@min(pad, buf.len)], Color.dim, desc,
    });
    ui.writeRaw(Color.reset);
}

fn printVersion() void {
    _ = std.posix.write(std.posix.STDOUT_FILENO, "mtbuddy v" ++ version ++ "\n") catch {};
}
