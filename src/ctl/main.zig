//! mtproto-ctl — interactive installer & control panel for mtproto.zig
//!
//! Replaces the collection of bash scripts in deploy/ with a single
//! Zig binary. Supports both interactive TUI mode (--interactive)
//! and non-interactive CLI with flags.
//!
//! Usage:
//!   mtproto-ctl --interactive              Interactive TUI wizard
//!   mtproto-ctl install [options]           Install from source
//!   mtproto-ctl update [options]            Update from GitHub release
//!   mtproto-ctl setup masking [options]     Setup local Nginx DPI masking
//!   mtproto-ctl setup nfqws [options]       Setup nfqws TCP desync
//!   mtproto-ctl setup tunnel <conf> [opts]  Setup AmneziaWG tunnel
//!   mtproto-ctl setup monitor              Install masking health monitor
//!   mtproto-ctl ipv6-hop [--auto|--check]  IPv6 rotation
//!   mtproto-ctl update-dns <ip>            Update Cloudflare DNS
//!   mtproto-ctl --help                     Show help
//!   mtproto-ctl --version                  Show version

const std = @import("std");
const i18n = @import("i18n.zig");
const tui_mod = @import("tui.zig");
const install = @import("install.zig");
const update = @import("update.zig");
const masking = @import("masking.zig");
const nfqws = @import("nfqws.zig");
const tunnel = @import("tunnel.zig");
const monitor = @import("monitor.zig");
const ipv6hop = @import("ipv6hop.zig");

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;

const version = "0.12.0-dev"; // x-release-please-version

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

    // Collect global flags and find command
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--interactive") or std.mem.eql(u8, arg, "-i")) {
            interactive = true;
        } else if (std.mem.eql(u8, arg, "--lang")) {
            if (args.next()) |lang_val| {
                if (std.mem.eql(u8, lang_val, "ru")) {
                    lang = .ru;
                } else {
                    lang = .en;
                }
            }
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printHelp();
            return;
        } else if (std.mem.eql(u8, arg, "--version")) {
            printVersion();
            return;
        } else {
            command = arg;
            remaining_args = args;
            break;
        }
    }

    // Default language from environment
    const resolved_lang = lang orelse i18n.Lang.fromEnv();
    var ui = Tui.init(resolved_lang);

    // ── Interactive mode ──
    if (interactive) {
        ui.banner(version);

        // If language not explicitly set, ask interactively
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
        } else if (std.mem.eql(u8, cmd, "update")) {
            return update.run(&ui, allocator, &remaining_args);
        } else if (std.mem.eql(u8, cmd, "setup")) {
            // setup <subcommand>
            if (remaining_args.next()) |sub| {
                if (std.mem.eql(u8, sub, "masking")) {
                    return masking.run(&ui, allocator, &remaining_args);
                } else if (std.mem.eql(u8, sub, "nfqws")) {
                    return nfqws.run(&ui, allocator, &remaining_args);
                } else if (std.mem.eql(u8, sub, "tunnel")) {
                    return tunnel.run(&ui, allocator, &remaining_args);
                } else if (std.mem.eql(u8, sub, "monitor")) {
                    return monitor.run(&ui, allocator, &remaining_args);
                } else {
                    ui.print("  {s}Unknown setup command: {s}{s}\n", .{ Color.err, sub, Color.reset });
                    ui.info("Available: masking, nfqws, tunnel, monitor");
                    return;
                }
            } else {
                ui.fail("Usage: mtproto-ctl setup <masking|nfqws|tunnel|monitor>");
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
            ui.print("  {s}Unknown command: {s}{s}\n\n", .{ Color.err, cmd, Color.reset });
            printHelp();
            return;
        }
    }

    // No command — show help
    printHelp();
}

fn interactiveMain(ui: *Tui, allocator: std.mem.Allocator) !void {
    while (true) {
        const choice = try ui.menu(i18n.get(ui.lang, .menu_title), &.{
            i18n.get(ui.lang, .menu_install),
            i18n.get(ui.lang, .menu_update),
            i18n.get(ui.lang, .menu_setup_masking),
            i18n.get(ui.lang, .menu_setup_tunnel),
            i18n.get(ui.lang, .menu_setup_monitor),
            i18n.get(ui.lang, .menu_ipv6_hop),
            i18n.get(ui.lang, .menu_status),
            i18n.get(ui.lang, .menu_exit),
        });

        switch (choice) {
            0 => try install.runInteractive(ui, allocator),
            1 => try update.runInteractive(ui, allocator),
            2 => try masking.runInteractive(ui, allocator),
            3 => try tunnel.runInteractive(ui, allocator),
            4 => try monitor.runInteractive(ui, allocator),
            5 => try ipv6hop.runInteractive(ui, allocator),
            6 => showStatus(ui, allocator),
            7 => return, // exit
            else => return,
        }
    }
}

fn showStatus(ui: *Tui, allocator: std.mem.Allocator) void {
    ui.section(i18n.get(ui.lang, .menu_status));

    // Check service status
    const svc_active = @import("sys.zig").isServiceActive("mtproto-proxy");
    if (svc_active) {
        ui.ok("mtproto-proxy is running");
    } else {
        ui.fail("mtproto-proxy is not running");
    }

    // Check nginx
    const nginx_active = @import("sys.zig").isServiceActive("nginx");
    if (nginx_active) {
        ui.ok("nginx is running");
    } else {
        ui.info("nginx is not running (masking may be disabled)");
    }

    // Check nfqws
    const nfqws_active = @import("sys.zig").isServiceActive("nfqws-mtproto");
    if (nfqws_active) {
        ui.ok("nfqws-mtproto is running");
    } else {
        ui.info("nfqws-mtproto is not running (TCP desync may be disabled)");
    }

    // Check mask health timer
    const timer_active = @import("sys.zig").isServiceActive("mtproto-mask-health.timer");
    if (timer_active) {
        ui.ok("masking health monitor is active");
    } else {
        ui.info("masking health monitor is not active");
    }

    // Show brief service output
    const result = @import("sys.zig").exec(allocator, &.{
        "systemctl", "status", "mtproto-proxy", "--no-pager", "-l",
    }) catch return;
    defer result.deinit();

    if (result.stdout.len > 0) {
        ui.writeRaw("\n");
        ui.print("  {s}", .{Color.dim});
        // Print first 15 lines
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
    const help =
        Color.header ++ "  ⚡ mtproto-ctl" ++ Color.reset ++ " — MTProto Proxy installer & control panel\n" ++
        "\n" ++
        Color.accent ++ "  Usage:" ++ Color.reset ++ "\n" ++
        "    mtproto-ctl [command] [options]\n" ++
        "    mtproto-ctl --interactive       Start interactive TUI\n" ++
        "\n" ++
        Color.accent ++ "  Commands:" ++ Color.reset ++ "\n" ++
        "    install              Install mtproto-proxy from source\n" ++
        "    update               Update to latest release\n" ++
        "    setup masking        Setup local Nginx DPI masking\n" ++
        "    setup nfqws          Setup nfqws TCP desync (Zapret)\n" ++
        "    setup tunnel <conf>  Setup AmneziaWG tunnel\n" ++
        "    setup monitor        Install masking health monitor\n" ++
        "    ipv6-hop             IPv6 address rotation\n" ++
        "    update-dns <ip>      Update Cloudflare DNS A record\n" ++
        "    status               Show service status\n" ++
        "\n" ++
        Color.accent ++ "  Setup options:" ++ Color.reset ++ "\n" ++
        "    --domain <domain>    TLS masking domain (default: wb.ru)\n" ++
        "    --ttl <N>            nfqws fake packet TTL (default: 6)\n" ++
        "    --mode <mode>        Tunnel mode: direct|preserve|middleproxy\n" ++
        "    --remove             Remove nfqws installation\n" ++
        "\n" ++
        Color.accent ++ "  IPv6 options:" ++ Color.reset ++ "\n" ++
        "    --check              Show current IPv6 status\n" ++
        "    --auto               Auto-rotate on ban detection\n" ++
        "    --prefix <prefix>    IPv6 /64 prefix\n" ++
        "    --threshold <N>      Ban detection threshold (default: 10)\n" ++
        "\n" ++
        Color.accent ++ "  Global options:" ++ Color.reset ++ "\n" ++
        "    -i, --interactive    Interactive TUI mode\n" ++
        "    --lang <en|ru>       Language (default: auto-detect)\n" ++
        "    --help, -h           Show this help\n" ++
        "    --version            Show version\n" ++
        "\n";

    _ = std.posix.write(std.posix.STDOUT_FILENO, help) catch {};
}

fn printVersion() void {
    _ = std.posix.write(std.posix.STDOUT_FILENO, "mtproto-ctl v" ++ version ++ "\n") catch {};
}
