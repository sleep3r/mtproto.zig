//! Setup tunnel command for mtbuddy.
//!
//! Configures AmneziaWG on the host and enables socket policy routing
//! for mtproto-proxy (`SO_MARK=200 -> table 200`) without network namespaces.

const std = @import("std");
const tui_mod = @import("tui.zig");
const i18n = @import("i18n.zig");
const sys = @import("sys.zig");
const toml = @import("toml.zig");
const release = @import("release.zig");
const Tunnel = @import("tunnel").Tunnel;

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;

const INSTALL_DIR = "/opt/mtproto-proxy";
const AWG_CONF_DIR = "/etc/amnezia/amneziawg";
const AWG_IFACE_CONF_PATH = "/etc/amnezia/awg0.conf";
const TUNNEL_SCRIPT = "/usr/local/bin/setup_tunnel.sh";
const TUNNEL_POOL_SERVICE = "/etc/systemd/system/mtproto-tunnel-pool.service";
const TUNNEL_POOL_TIMER = "/etc/systemd/system/mtproto-tunnel-pool.timer";
const TUNNEL_POOL_STATE = "/run/mtproto-proxy/tunnel-pool.state";
const SERVICE_FILE = "/etc/systemd/system/mtproto-proxy.service";
const TUNNEL_MARK: u32 = 200;
const TUNNEL_TABLE: u32 = 200;

fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn readFileAllocCwd(allocator: std.mem.Allocator, path: []const u8, limit: usize) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io(), path, allocator, .limited(limit));
}

pub const TunnelOpts = struct {
    awg_source: []const u8 = "",
    iface: []const u8 = "",
};

const AwgConfigKind = enum {
    native_conf,
    amnezia_vpn_link,
};

const AwgQuickValidation = enum {
    ok,
    missing_binary,
    invalid_config,
};

const InteractiveTunnelSelection = struct {
    iface: []const u8,
    action: InteractiveTunnelAction,
};

const InteractiveTunnelAction = enum {
    create,
    replace,
    delete,
};

/// Run in CLI mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    var opts = TunnelOpts{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--mode") or std.mem.eql(u8, arg, "-m")) {
            _ = args.next();
            ui.warn("--mode is deprecated and ignored; use [general].use_middle_proxy in config.toml");
            continue;
        }

        if (std.mem.eql(u8, arg, "--iface")) {
            opts.iface = args.next() orelse "";
            continue;
        }

        if (arg.len > 0 and arg[0] != '-') {
            opts.awg_source = arg;
        }
    }

    if (opts.awg_source.len == 0) {
        ui.fail("Usage: mtbuddy setup tunnel [--iface awgN] <conf-path-or-vpn-link>");
        return;
    }

    try execute(ui, allocator, opts);
}

/// Set up a tunnel directly from a WireGuard/AmneziaWG `.conf` path — same flow as
/// `setup tunnel <conf>`. Used by the egress provider after it converts a
/// wireguard:// share-link into a `.conf`.
pub fn setupFromConf(ui: *Tui, allocator: std.mem.Allocator, conf_path: []const u8) !void {
    try execute(ui, allocator, .{ .awg_source = conf_path });
}

/// Run in interactive mode.
pub fn runInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    ui.section(i18n.get(ui.lang, .menu_setup_tunnel));

    const selection = chooseInteractiveTunnelTarget(ui, allocator) catch |err| {
        switch (err) {
            error.InvalidInterfaceName => ui.fail("Invalid tunnel interface name. Use names like awg0, awg1, wg0."),
            error.NoFreeInterface => ui.fail("No free awgN interface name found"),
            else => ui.fail("Failed to prepare tunnel pool selection"),
        }
        return;
    };
    defer allocator.free(selection.iface);

    if (selection.action == .delete) {
        try deleteTunnelInteractive(ui, allocator, selection.iface);
        return;
    }

    try chooseInteractiveVpnType(ui);

    if (selection.action == .replace) {
        ui.warn(i18n.get(ui.lang, .tunnel_pool_replace_warn));
    }
    ui.stepOk(i18n.get(ui.lang, .tunnel_pool_selected_iface), selection.iface);

    var conf_buf: [16 * 1024]u8 = undefined;
    const conf_source = try ui.input(
        i18n.get(ui.lang, .tunnel_conf_prompt),
        i18n.get(ui.lang, .tunnel_conf_help),
        null,
        &conf_buf,
    );

    if (!try ui.confirm(i18n.get(ui.lang, .confirm_proceed), true)) {
        ui.info(i18n.get(ui.lang, .aborting));
        return;
    }

    try execute(ui, allocator, .{ .awg_source = conf_source, .iface = selection.iface });
}

fn tr(lang: i18n.Lang, en: []const u8, ru: []const u8) []const u8 {
    return if (lang == .ru) ru else en;
}

fn chooseInteractiveVpnType(ui: *Tui) !void {
    const items = [_][]const u8{
        i18n.get(ui.lang, .tunnel_vpn_amneziawg),
    };
    _ = try ui.menu(i18n.get(ui.lang, .tunnel_vpn_type_prompt), &items);
    ui.stepOk(i18n.get(ui.lang, .tunnel_vpn_type_prompt), i18n.get(ui.lang, .tunnel_vpn_amneziawg));
}

fn chooseInteractiveTunnelTarget(ui: *Tui, allocator: std.mem.Allocator) !InteractiveTunnelSelection {
    const pool = try loadConfiguredTunnelPool(allocator);
    defer freeOwnedStringSlice(allocator, pool);
    const known = try loadKnownTunnelInterfaces(allocator);
    defer freeOwnedStringSlice(allocator, known);

    if (known.len == 0) {
        ui.info(i18n.get(ui.lang, .tunnel_pool_empty));
    } else {
        ui.info(i18n.get(ui.lang, .tunnel_pool_current));
        printTunnelPoolRuntimeStatus(ui, allocator, known, pool);
    }

    const next_iface = try selectTunnelInterface(allocator, "");
    defer allocator.free(next_iface);

    var items: std.ArrayList([]const u8) = .empty;
    defer {
        for (items.items) |item| allocator.free(item);
        items.deinit(allocator);
    }

    try items.append(
        allocator,
        try std.fmt.allocPrint(
            allocator,
            "{s} ({s})",
            .{ i18n.get(ui.lang, .tunnel_pool_action_create), next_iface },
        ),
    );

    for (known) |iface| {
        try items.append(
            allocator,
            try std.fmt.allocPrint(
                allocator,
                "{s}: {s}",
                .{ i18n.get(ui.lang, .tunnel_pool_action_replace), iface },
            ),
        );
    }

    for (known) |iface| {
        try items.append(
            allocator,
            try std.fmt.allocPrint(
                allocator,
                "{s}: {s}",
                .{ tr(ui.lang, "Delete tunnel", "Удалить туннель"), iface },
            ),
        );
    }

    const selected = try ui.menu(i18n.get(ui.lang, .tunnel_pool_action_prompt), items.items);
    if (selected == 0) {
        return .{
            .iface = try allocator.dupe(u8, next_iface),
            .action = .create,
        };
    }

    if (selected <= known.len) {
        return .{
            .iface = try allocator.dupe(u8, known[selected - 1]),
            .action = .replace,
        };
    }

    return .{
        .iface = try allocator.dupe(u8, known[selected - known.len - 1]),
        .action = .delete,
    };
}

fn tunnelShowTool(iface: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, iface, "wg") and sys.commandExists("wg")) return "wg";
    if (sys.commandExists("awg")) return "awg";
    if (sys.commandExists("wg")) return "wg";
    return null;
}

fn quickToolForInterface(iface: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, iface, "wg") and sys.commandExists("wg-quick")) return "wg-quick";
    if (sys.commandExists("awg-quick")) return "awg-quick";
    if (sys.commandExists("wg-quick")) return "wg-quick";
    return null;
}

fn hasValidHandshakeFromShow(out: []const u8) bool {
    var lines = std.mem.splitScalar(u8, out, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r' });
        if (!std.mem.startsWith(u8, trimmed, "latest handshake:")) continue;
        const value = std.mem.trim(u8, trimmed["latest handshake:".len..], &[_]u8{ ' ', '\t', '\r' });
        if (value.len == 0) return false;
        if (std.ascii.eqlIgnoreCase(value, "0")) return false;
        if (std.ascii.eqlIgnoreCase(value, "none")) return false;
        if (std.ascii.eqlIgnoreCase(value, "none (idle)")) return false;
        return true;
    }
    return false;
}

fn hasEndpointFromShow(out: []const u8) bool {
    var lines = std.mem.splitScalar(u8, out, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r' });
        if (std.mem.startsWith(u8, trimmed, "endpoint:")) return true;
    }
    return false;
}

fn tunnelRuntimeStatus(allocator: std.mem.Allocator, iface: []const u8) []const u8 {
    const link = sys.exec(allocator, &.{ "ip", "link", "show", "dev", iface }) catch return "unknown";
    defer link.deinit();
    if (link.exit_code != 0) return "down";

    const tool = tunnelShowTool(iface) orelse return "up, no tool";
    const show = sys.exec(allocator, &.{ tool, "show", iface }) catch return "up, show failed";
    defer show.deinit();
    if (show.exit_code != 0) return "up, show failed";
    if (hasValidHandshakeFromShow(show.stdout)) return "active";
    if (hasEndpointFromShow(show.stdout)) return "up, no handshake";
    return "up, no endpoint";
}

fn printTunnelPoolRuntimeStatus(ui: *Tui, allocator: std.mem.Allocator, interfaces: []const []const u8, pool: []const []const u8) void {
    for (interfaces, 0..) |iface, idx| {
        const status = tunnelRuntimeStatus(allocator, iface);
        const source = if (containsInterface(pool, iface)) "pool" else "config";
        const status_color = if (std.mem.eql(u8, status, "active"))
            Color.ok
        else if (std.mem.startsWith(u8, status, "up"))
            Color.bright_yellow
        else
            Color.err;
        ui.print("     {d}. {s}  {s}{s}{s}  {s}{s}{s}\n", .{ idx + 1, iface, status_color, status, Color.reset, Color.dim, source, Color.reset });
    }
}

const TunnelDeleteResult = struct {
    removed_last: bool,
    remaining_count: usize,
};

fn deleteTunnelInteractive(ui: *Tui, allocator: std.mem.Allocator, iface: []const u8) !void {
    if (!sys.isRoot()) {
        ui.fail(i18n.get(ui.lang, .error_not_root));
        return;
    }

    var prompt_buf: [256]u8 = undefined;
    const prompt = std.fmt.bufPrint(
        &prompt_buf,
        "{s} {s}? {s}",
        .{
            tr(ui.lang, "Delete tunnel", "Удалить туннель"),
            iface,
            tr(ui.lang, "Config file and pool entry will be removed.", "Конфиг и запись в пуле будут удалены."),
        },
    ) catch "Delete tunnel?";

    if (!try ui.confirm(prompt, false)) {
        ui.info(i18n.get(ui.lang, .aborting));
        return;
    }

    ui.step(tr(ui.lang, "Deleting tunnel", "Удаление туннеля"));
    const result = deleteTunnelPoolMember(allocator, iface) catch |err| {
        switch (err) {
            error.InvalidInterfaceName => ui.fail("Invalid tunnel interface name"),
            error.TunnelNotInPool => ui.fail("Tunnel interface is not in configured pool"),
            error.ConfigSourceNotFound => ui.fail("Config file not found"),
            else => ui.fail("Failed to delete tunnel"),
        }
        return;
    };

    ui.stepOk(tr(ui.lang, "Tunnel deleted", "Туннель удален"), iface);
    if (result.removed_last) {
        ui.warn(tr(
            ui.lang,
            "No tunnels left; upstream switched to auto and tunnel policy routing was disabled.",
            "Туннелей не осталось; upstream переключен в auto, policy routing выключен.",
        ));
    } else {
        var msg_buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(
            &msg_buf,
            "{d} {s}",
            .{ result.remaining_count, tr(ui.lang, "tunnel(s) remain; pool controller refreshed.", "туннелей осталось; контроллер пула обновлен.") },
        ) catch "Tunnel pool refreshed.";
        ui.ok(msg);
    }
}

fn deleteTunnelPoolMember(allocator: std.mem.Allocator, iface: []const u8) !TunnelDeleteResult {
    if (!isValidTunnelInterfaceName(iface)) return error.InvalidInterfaceName;

    const known_before = try loadKnownTunnelInterfaces(allocator);
    defer freeOwnedStringSlice(allocator, known_before);

    var doc = toml.TomlDoc.load(allocator, INSTALL_DIR ++ "/config.toml") catch return error.ConfigSourceNotFound;
    defer doc.deinit();

    const config_result = try removeTunnelFromDoc(allocator, &doc, iface);
    defer freeOwnedStringSlice(allocator, config_result.remaining_pool);
    if (!config_result.removed and !tunnelConfigExists(iface)) return error.TunnelNotInPool;

    const stale_last = !config_result.removed and config_result.remaining_pool.len == 0 and known_before.len <= 1;
    if (stale_last) {
        try clearTunnelConfigInDoc(&doc);
    }

    const removed_last = config_result.removed_last or stale_last;
    const remaining_count = config_result.remaining_pool.len;
    if (config_result.removed or stale_last) {
        try doc.save(INSTALL_DIR ++ "/config.toml");
    }

    stopTunnelInterface(allocator, iface);
    deleteTunnelConfigFiles(allocator, iface);

    if (removed_last) {
        disableTunnelPoolRuntime(allocator);
        release.writeServiceFile();
        _ = sys.exec(allocator, &.{ "systemctl", "daemon-reload" }) catch null;
    } else {
        refreshTunnelPoolRuntime(allocator);
    }

    _ = sys.exec(allocator, &.{ "systemctl", "restart", "mtproto-proxy" }) catch null;

    return .{
        .removed_last = removed_last,
        .remaining_count = remaining_count,
    };
}

fn stopTunnelInterface(allocator: std.mem.Allocator, iface: []const u8) void {
    const quick = quickToolForInterface(iface);

    var awg_buf: [256]u8 = undefined;
    const awg_path = awgConfigPath(&awg_buf, iface) catch "";
    var wg_buf: [256]u8 = undefined;
    const wg_path = std.fmt.bufPrint(&wg_buf, "/etc/wireguard/{s}.conf", .{iface}) catch "";

    if (quick) |tool| {
        if (awg_path.len > 0 and sys.fileExists(awg_path)) sys.execSilent(allocator, &.{ tool, "down", awg_path });
        if (wg_path.len > 0 and sys.fileExists(wg_path)) sys.execSilent(allocator, &.{ tool, "down", wg_path });
        sys.execSilent(allocator, &.{ tool, "down", iface });
    }
    sys.execSilent(allocator, &.{ "ip", "link", "delete", "dev", iface });
}

fn tunnelConfigExists(iface: []const u8) bool {
    var awg_buf: [256]u8 = undefined;
    const awg_path = awgConfigPath(&awg_buf, iface) catch "";
    var wg_buf: [256]u8 = undefined;
    const wg_path = std.fmt.bufPrint(&wg_buf, "/etc/wireguard/{s}.conf", .{iface}) catch "";

    if (awg_path.len > 0 and sys.fileExists(awg_path)) return true;
    if (wg_path.len > 0 and sys.fileExists(wg_path)) return true;
    if (std.mem.eql(u8, iface, "awg0") and sys.fileExists(AWG_IFACE_CONF_PATH)) return true;
    return false;
}

fn deleteTunnelConfigFiles(allocator: std.mem.Allocator, iface: []const u8) void {
    var awg_buf: [256]u8 = undefined;
    const awg_path = awgConfigPath(&awg_buf, iface) catch "";
    var wg_buf: [256]u8 = undefined;
    const wg_path = std.fmt.bufPrint(&wg_buf, "/etc/wireguard/{s}.conf", .{iface}) catch "";

    if (awg_path.len > 0) sys.execSilent(allocator, &.{ "rm", "-f", awg_path });
    if (wg_path.len > 0) sys.execSilent(allocator, &.{ "rm", "-f", wg_path });
    if (std.mem.eql(u8, iface, "awg0")) {
        sys.execSilent(allocator, &.{ "rm", "-f", AWG_IFACE_CONF_PATH });
    }
}

fn disableTunnelPoolRuntime(allocator: std.mem.Allocator) void {
    sys.execSilent(allocator, &.{ "systemctl", "disable", "--now", "mtproto-tunnel-pool.timer" });
    sys.execSilent(allocator, &.{ "systemctl", "stop", "mtproto-tunnel-pool.service" });
    sys.execSilent(allocator, &.{ "sh", "-c", "while ip -4 rule del priority 1200 fwmark 200 table 200 2>/dev/null; do :; done; while ip -4 rule del fwmark 200 table 200 2>/dev/null; do :; done; ip -4 route flush table 200 2>/dev/null || true" });
    sys.execSilent(allocator, &.{ "rm", "-f", TUNNEL_SCRIPT, TUNNEL_POOL_STATE, TUNNEL_POOL_SERVICE, TUNNEL_POOL_TIMER });
}

fn refreshTunnelPoolRuntime(allocator: std.mem.Allocator) void {
    if (!sys.fileExists(TUNNEL_SCRIPT)) return;
    sys.execSilent(allocator, &.{TUNNEL_SCRIPT});
}

fn execute(ui: *Tui, allocator: std.mem.Allocator, opts: TunnelOpts) !void {
    if (!sys.isRoot()) {
        ui.fail(i18n.get(ui.lang, .error_not_root));
        return;
    }

    const awg_source = std.mem.trim(u8, opts.awg_source, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (awg_source.len == 0) {
        ui.fail("VPN config source is empty");
        return;
    }
    if (!sys.fileExists(INSTALL_DIR ++ "/mtproto-proxy")) {
        ui.fail("mtproto-proxy not installed. Run install first.");
        return;
    }

    // A sing-box egress (`setup egress`) and this WG tunnel pool both own fwmark 200 /
    // table 200 — retire the sing-box egress so the two don't fight over the route.
    if (sys.fileExists("/etc/systemd/system/mtproto-singbox-egress.service")) {
        ui.warn("Retiring the existing sing-box egress — it can't share table 200 with a WG tunnel.");
        sys.execSilent(allocator, &.{ "systemctl", "disable", "--now", "mtproto-singbox-egress.service" });
        sys.execSilent(allocator, &.{ "rm", "-f", "/etc/systemd/system/mtproto-singbox-egress.service", "/etc/mtproto-proxy/singbox-egress.json", "/usr/local/bin/mtproto-singbox-route.sh", "/etc/systemd/system/mtproto-proxy.service.d/egress.conf" });
        sys.execSilent(allocator, &.{ "systemctl", "daemon-reload" });
    }

    // ── Install AmneziaWG ──
    if (sys.commandExists("awg") and sys.commandExists("awg-quick")) {
        ui.ok("AmneziaWG already installed");
    } else {
        if (sys.commandExists("awg") != sys.commandExists("awg-quick")) {
            ui.warn("Detected partial AmneziaWG installation; repairing package setup");
        }
        ui.step("Installing AmneziaWG...");
        if (!ensureAmneziaWgInstalled(ui, allocator)) {
            return;
        }
        ui.ok("AmneziaWG installed");
    }

    const iface = selectTunnelInterface(allocator, opts.iface) catch |err| {
        switch (err) {
            error.InvalidInterfaceName => ui.fail("Invalid tunnel interface name. Use names like awg0, awg1, wg0."),
            error.NoFreeInterface => ui.fail("No free awgN interface name found"),
            else => ui.fail("Failed to select tunnel interface"),
        }
        return;
    };
    defer allocator.free(iface);

    var config_path_buf: [256]u8 = undefined;
    const awg_config_path = awgConfigPath(&config_path_buf, iface) catch {
        ui.fail("Tunnel interface name is too long");
        return;
    };

    // ── Copy AWG config ──
    ui.step("Installing AmneziaWG config...");
    _ = sys.exec(allocator, &.{ "mkdir", "-p", "/etc/amnezia" }) catch {};
    _ = sys.exec(allocator, &.{ "mkdir", "-p", AWG_CONF_DIR }) catch {};

    const config_kind = installAwgConfigSource(allocator, awg_source, awg_config_path) catch |err| {
        switch (err) {
            error.ConfigSourceNotFound => ui.fail("Config file not found"),
            error.UnsupportedConfigFormat => ui.fail("Unsupported VPN config format. Use a WireGuard/AmneziaWG .conf file, or an Amnezia vpn:// share link."),
            error.InvalidAmneziaVpnLink => ui.fail("Invalid Amnezia vpn:// link. Export/share an AmneziaWG configuration again and retry."),
            error.AwgConfigNotFound => ui.fail("Amnezia vpn:// link does not contain an AmneziaWG configuration."),
            else => ui.fail("Failed to prepare AmneziaWG config"),
        }
        return;
    };
    if (config_kind == .amnezia_vpn_link) {
        ui.warn("Converted Amnezia vpn:// link to AmneziaWG config");
    }
    if (std.mem.eql(u8, iface, "awg0")) {
        _ = sys.execForward(&.{ "ln", "-sfn", awg_config_path, AWG_IFACE_CONF_PATH }) catch {};
    }

    const dns_removed = stripAwgDnsLines(allocator, awg_config_path) catch false;
    if (dns_removed) {
        ui.warn("Removed DNS from tunnel config (host resolver will be used)");
    }

    const empty_removed = stripAwgEmptyAssignments(allocator, awg_config_path) catch false;
    if (empty_removed) {
        ui.warn("Removed empty AmneziaWG parameters from tunnel config");
    }

    const table_off_added = ensureAwgTableOff(allocator, awg_config_path) catch false;
    if (table_off_added) {
        ui.warn("Added Table = off to [Interface] in tunnel config");
    }

    switch (validateAwgQuickConfig(allocator, awg_config_path)) {
        .ok => {},
        .missing_binary => {
            ui.fail("AmneziaWG tools are not available (`awg-quick` was not found). Install amneziawg-tools and retry.");
            return;
        },
        .invalid_config => {
            ui.fail("AmneziaWG config is not accepted by awg-quick. Check that the input is an AWG/WG client config.");
            return;
        },
    }

    ui.stepOk("Config installed", awg_config_path);

    // ── Create tunnel policy script ──
    ui.step("Creating tunnel policy routing script...");

    const tunnel_script = renderTunnelPoolScript(allocator) catch {
        ui.fail("Failed to render tunnel setup script");
        return;
    };
    defer allocator.free(tunnel_script);

    sys.writeFileMode(TUNNEL_SCRIPT, tunnel_script, 0o755) catch {
        ui.fail("Failed to write tunnel setup script");
        return;
    };
    ui.ok("Created " ++ TUNNEL_SCRIPT);

    // ── Patch systemd service ──
    ui.step("Patching systemd service for tunnel policy routing...");
    const svc_content =
        \\[Unit]
        \\Description=MTProto Proxy (Zig) via Tunnel Policy Routing
        \\Documentation=https://github.com/sleep3r/mtproto.zig
        \\After=network-online.target
        \\Wants=network-online.target
        \\
        \\[Service]
        \\# Type=simple (not notify): containerized systemd (Docker/LXC) often fails to
        \\# deliver the sd_notify datagram, which would restart-loop a healthy proxy.
        \\# simple is robust everywhere; Restart=always still recovers crashes.
        \\Type=simple
        \\User=mtproto
        \\Group=mtproto
        \\WorkingDirectory=/opt/mtproto-proxy
        \\# Routing/policy setup needs root; the '+' prefix runs ONLY this command
        \\# with full privileges while the proxy itself drops to User=mtproto.
        \\ExecStartPre=+/usr/local/bin/setup_tunnel.sh
        \\ExecStart=/opt/mtproto-proxy/mtproto-proxy /opt/mtproto-proxy/config.toml
        \\ExecReload=/bin/kill -HUP $MAINPID
        \\KillSignal=SIGTERM
        \\TimeoutStopSec=25
        \\Restart=on-failure
        \\RestartSec=5
        \\
        \\# Security hardening — mirrors the default unit so tunnel mode does NOT
        \\# silently run the internet-facing proxy as unsandboxed root. CAP_NET_ADMIN
        \\# is added (on top of CAP_NET_BIND_SERVICE) for the SO_MARK policy routing
        \\# the tunnel data path uses. Only the device/netlink-safe subset of the
        \\# default unit's syscall hardening is applied: ExecStartPre runs ip/wg
        \\# setup (netlink, possibly modprobe) that an aggressive SystemCallFilter /
        \\# RestrictAddressFamilies / PrivateDevices would break.
        \\NoNewPrivileges=yes
        \\ProtectSystem=strict
        \\ProtectHome=yes
        \\PrivateTmp=yes
        \\ReadOnlyPaths=/opt/mtproto-proxy
        \\LockPersonality=yes
        \\RestrictRealtime=yes
        \\RestrictSUIDSGID=yes
        \\ProtectClock=yes
        \\ProtectHostname=yes
        \\ProtectKernelLogs=yes
        \\UMask=0077
        \\AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
        \\CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
        \\LimitNOFILE=131582
        \\TasksMax=65535
        \\
        \\[Install]
        \\WantedBy=multi-user.target
    ;

    sys.writeFile(SERVICE_FILE, svc_content) catch {
        ui.fail("Failed to write systemd service");
        return;
    };

    _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};
    ui.ok("Systemd service patched for tunnel policy routing");

    installTunnelPoolUnits(ui, allocator);

    // ── Configure proxy egress mode ──
    setTunnelPoolConfig(allocator, iface);
    ui.stepOk("Set [upstream].type", "tunnel");
    ui.stepOk("Added tunnel pool interface", iface);
    ui.stepOk("Preserved [general].use_middle_proxy", "unchanged");

    // ── Inject public IP (preserve existing custom value) ──
    var doc = toml.TomlDoc.load(allocator, INSTALL_DIR ++ "/config.toml") catch null;
    if (doc) |*d| {
        defer d.deinit();

        var should_inject = true;
        if (d.get("server", "public_ip")) |configured_public_ip| {
            const configured = std.mem.trim(u8, configured_public_ip, &[_]u8{ ' ', '\t' });
            if (configured.len > 0 and !std.mem.eql(u8, configured, "<SERVER_IP>")) {
                should_inject = false;
                ui.stepOk("Keeping configured public IP", configured);
            }
        }

        if (should_inject) {
            const public_ip = sys.detectPublicIp(allocator) orelse "";
            if (public_ip.len > 0) {
                var quoted_buf: [64]u8 = undefined;
                const quoted = std.fmt.bufPrint(&quoted_buf, "\"{s}\"", .{public_ip}) catch "";
                if (quoted.len > 0) {
                    d.set("server", "public_ip", quoted) catch {};
                    d.save(INSTALL_DIR ++ "/config.toml") catch {};
                    ui.stepOk("Injected public IP", public_ip);
                }
            }
        }
    }

    // ── Preserve promotion tag from env.sh ──
    if (sys.readEnvFile(allocator, INSTALL_DIR ++ "/env.sh", "TAG")) |tag| {
        defer allocator.free(tag);

        var doc2 = toml.TomlDoc.load(allocator, INSTALL_DIR ++ "/config.toml") catch null;
        if (doc2) |*d| {
            defer d.deinit();
            var tag_buf: [128]u8 = undefined;
            const quoted_tag = std.fmt.bufPrint(&tag_buf, "\"{s}\"", .{tag}) catch "";
            if (quoted_tag.len > 0) {
                d.set("server", "tag", quoted_tag) catch {};
                d.save(INSTALL_DIR ++ "/config.toml") catch {};
            }
        }
        ui.stepOk("Preserved promotion tag", tag);
    }

    // ── Cleanup legacy netns nginx listen directives ──
    const nginx_cleaned = cleanupNetnsNginxListen(allocator);
    if (nginx_cleaned) {
        ui.ok("Removed legacy netns listen directives from nginx masking config");
        _ = sys.execForward(&.{ "systemctl", "try-reload-or-restart", "nginx" }) catch {};
    }

    // ── Apply masking monitor (if recovery is already installed) ──
    if (sys.isServiceActive("mtproto-mask-health.timer") or sys.fileExists("/usr/local/bin/mtproto-mask-health.sh")) {
        const recovery = @import("recovery.zig");
        recovery.execute(ui, allocator, .{ .quiet = true }) catch {};
    }

    // ── Restart proxy ──
    ui.step("Restarting proxy...");
    _ = sys.execForward(&.{ "systemctl", "restart", "mtproto-proxy" }) catch {};

    if (sys.isServiceActive("mtproto-proxy")) {
        ui.ok("Proxy running with tunnel policy routing");
    } else {
        ui.fail("Proxy failed to start. Check: journalctl -u mtproto-proxy -n 30");
        return;
    }

    // ── Validate tunnel routing ──
    ui.step("Validating policy routing to Telegram DCs...");

    _ = sys.execForward(&.{TUNNEL_SCRIPT}) catch {};

    const awg_status = sys.exec(allocator, &.{ "awg", "show", iface }) catch null;
    if (awg_status) |result| {
        defer result.deinit();
        if (result.exit_code == 0) {
            ui.stepOk("Tunnel interface active", iface);
        } else {
            ui.warn("Tunnel interface is not active (check AWG config and endpoint)");
        }
    }

    const dc_ips = [_][]const u8{
        "149.154.175.50", "149.154.167.50", "149.154.175.100",
        "149.154.167.91", "91.108.56.100",
    };

    for (dc_ips) |dc_ip| {
        const r = sys.exec(allocator, &.{
            "ip", "-4", "route", "get", dc_ip, "mark", "200",
        }) catch null;

        if (r) |route_result| {
            defer route_result.deinit();
            if (route_result.exit_code == 0 and std.mem.indexOf(u8, route_result.stdout, "dev ") != null) {
                ui.stepOk("Policy route via tunnel pool", dc_ip);
            } else {
                var warn_buf: [96]u8 = undefined;
                const warn_msg = std.fmt.bufPrint(&warn_buf, "Policy route check failed for {s}", .{dc_ip}) catch "Policy route check failed";
                ui.warn(warn_msg);
            }
        }
    }

    // ── Summary ──
    ui.summaryBox("VPN Tunnel Configured", &.{
        .{ .label = "Status:", .value = "systemctl status mtproto-proxy" },
        .{ .label = "Logs:", .value = "journalctl -u mtproto-proxy -f" },
        .{ .label = "Tunnel:", .value = "awg show <iface>" },
        .{ .label = "Pool:", .value = "systemctl status mtproto-tunnel-pool.timer" },
        .{ .label = "Policy:", .value = "ip -4 rule show | grep fwmark" },
        .{ .label = "Mark:", .value = "SO_MARK=200 -> table 200" },
        .{ .label = "", .style = .blank },
        .{ .label = "Proxy runs in host network namespace", .style = .success },
        .{ .label = "Tunnel pool failover is socket-level and explicit", .style = .success },
        .{ .label = "SOCKS5/HTTP upstream stay orthogonal", .style = .success },
    });
}

fn isAmneziaVpnLinkSource(source: []const u8) bool {
    const trimmed = std.mem.trim(u8, source, &[_]u8{ ' ', '\t', '\r', '\n' });
    return std.mem.startsWith(u8, trimmed, "vpn://");
}

fn installAwgConfigSource(allocator: std.mem.Allocator, source: []const u8, dest_path: []const u8) !AwgConfigKind {
    const trimmed = std.mem.trim(u8, source, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (trimmed.len == 0) return error.ConfigSourceNotFound;

    if (isAmneziaVpnLinkSource(trimmed)) {
        try sys.writeFileMode(dest_path, trimmed, 0o600);
    } else {
        const content = readFileAllocCwd(allocator, trimmed, 1024 * 1024) catch |err| switch (err) {
            error.FileNotFound => return error.ConfigSourceNotFound,
            else => return err,
        };
        defer allocator.free(content);

        try sys.writeFileMode(dest_path, content, 0o600);
    }

    return normalizeAwgConfig(allocator, dest_path);
}

fn normalizeAwgConfig(allocator: std.mem.Allocator, path: []const u8) !AwgConfigKind {
    const content = try readFileAllocCwd(allocator, path, 1024 * 1024);
    defer allocator.free(content);

    const trimmed = std.mem.trim(u8, content, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (std.mem.startsWith(u8, trimmed, "vpn://")) {
        const converted = convertAmneziaVpnLink(allocator, trimmed) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.AwgConfigNotFound => return error.AwgConfigNotFound,
            else => return error.InvalidAmneziaVpnLink,
        };
        defer allocator.free(converted);

        try sys.writeFileMode(path, converted, 0o600);
        return .amnezia_vpn_link;
    }

    if (!looksLikeAwgConfig(trimmed)) return error.UnsupportedConfigFormat;
    return .native_conf;
}

fn convertAmneziaVpnLink(allocator: std.mem.Allocator, link: []const u8) ![]u8 {
    const encoded = std.mem.trim(u8, link["vpn://".len..], &[_]u8{ ' ', '\t', '\r', '\n' });
    if (encoded.len == 0) return error.InvalidAmneziaVpnLink;

    const decoded = decodeVpnBase64(allocator, encoded) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidAmneziaVpnLink,
    };
    defer allocator.free(decoded);
    if (decoded.len <= 4) return error.InvalidAmneziaVpnLink;

    var compressed_reader: std.Io.Reader = .fixed(decoded[4..]);
    var json_writer: std.Io.Writer.Allocating = .init(allocator);
    defer json_writer.deinit();

    var decompress_buffer: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor: std.compress.flate.Decompress = .init(&compressed_reader, .zlib, &decompress_buffer);
    _ = decompressor.reader.streamRemaining(&json_writer.writer) catch return error.InvalidAmneziaVpnLink;

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_writer.written(), .{}) catch return error.InvalidAmneziaVpnLink;
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidAmneziaVpnLink,
    };

    const containers_value = root.get("containers") orelse return error.AwgConfigNotFound;
    const containers = switch (containers_value) {
        .array => |array| array,
        else => return error.AwgConfigNotFound,
    };

    const dns1 = jsonObjectString(root, "dns1") orelse "";
    const dns2 = jsonObjectString(root, "dns2") orelse "";

    for (containers.items) |container| {
        const container_obj = switch (container) {
            .object => |obj| obj,
            else => continue,
        };
        const awg_value = container_obj.get("awg") orelse continue;
        const awg_obj = switch (awg_value) {
            .object => |obj| obj,
            else => continue,
        };

        const last_config = jsonObjectString(awg_obj, "last_config") orelse continue;
        return convertAmneziaLastConfig(allocator, last_config, dns1, dns2);
    }

    return error.AwgConfigNotFound;
}

fn decodeVpnBase64(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const padding_len = (4 - (encoded.len % 4)) % 4;
    const padded = try allocator.alloc(u8, encoded.len + padding_len);
    defer allocator.free(padded);

    @memcpy(padded[0..encoded.len], encoded);
    @memset(padded[encoded.len..], '=');

    const decoded_len = std.base64.url_safe.Decoder.calcSizeForSlice(padded) catch return error.InvalidAmneziaVpnLink;
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(decoded);

    std.base64.url_safe.Decoder.decode(decoded, padded) catch return error.InvalidAmneziaVpnLink;
    return decoded;
}

fn convertAmneziaLastConfig(
    allocator: std.mem.Allocator,
    last_config_json: []const u8,
    dns1: []const u8,
    dns2: []const u8,
) ![]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, last_config_json, .{}) catch return error.InvalidAmneziaVpnLink;
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidAmneziaVpnLink,
    };

    const config = jsonObjectString(root, "config") orelse return error.AwgConfigNotFound;

    const primary_replaced = try std.mem.replaceOwned(u8, allocator, config, "$PRIMARY_DNS", dns1);
    defer allocator.free(primary_replaced);

    var prepared = try std.mem.replaceOwned(u8, allocator, primary_replaced, "$SECONDARY_DNS", dns2);
    errdefer allocator.free(prepared);

    var value_buf: [64]u8 = undefined;
    if (jsonObjectText(root, "mtu", &value_buf)) |mtu| {
        const updated = try setInterfaceKeyInContent(allocator, prepared, "MTU", mtu);
        allocator.free(prepared);
        prepared = updated;
    }

    var port_buf: [64]u8 = undefined;
    if (jsonObjectText(root, "port", &port_buf)) |port| {
        const updated = try setInterfaceKeyInContent(allocator, prepared, "ListenPort", port);
        allocator.free(prepared);
        prepared = updated;
    }

    return prepared;
}

fn jsonObjectString(object: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = object.get(key) orelse return null;
    return switch (value) {
        .string => |s| s,
        else => null,
    };
}

fn jsonObjectText(object: std.json.ObjectMap, key: []const u8, buf: *[64]u8) ?[]const u8 {
    const value = object.get(key) orelse return null;
    return switch (value) {
        .string => |s| s,
        .number_string => |s| s,
        .integer => |i| std.fmt.bufPrint(buf, "{d}", .{i}) catch null,
        .float => |f| std.fmt.bufPrint(buf, "{d}", .{f}) catch null,
        else => null,
    };
}

fn setInterfaceKeyInContent(
    allocator: std.mem.Allocator,
    content: []const u8,
    key: []const u8,
    value: []const u8,
) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    var in_interface = false;
    var saw_interface = false;
    var key_written = false;
    var wrote_any = false;

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r' });
        const is_section = trimmed.len >= 2 and trimmed[0] == '[' and trimmed[trimmed.len - 1] == ']';

        if (is_section and in_interface and !key_written) {
            try appendConfigLine(allocator, &output, &wrote_any, key, value);
            key_written = true;
        }

        if (is_section) {
            in_interface = std.ascii.eqlIgnoreCase(trimmed, "[Interface]");
            if (in_interface) saw_interface = true;
            try appendOriginalLine(allocator, &output, &wrote_any, line);
            continue;
        }

        if (in_interface and trimmed.len > 0 and trimmed[0] != '#' and trimmed[0] != ';') {
            if (std.mem.indexOfScalar(u8, trimmed, '=')) |eq_pos| {
                const existing_key = std.mem.trim(u8, trimmed[0..eq_pos], &[_]u8{ ' ', '\t' });
                if (std.ascii.eqlIgnoreCase(existing_key, key)) {
                    try appendConfigLine(allocator, &output, &wrote_any, key, value);
                    key_written = true;
                    continue;
                }
            }
        }

        try appendOriginalLine(allocator, &output, &wrote_any, line);
    }

    if (!saw_interface) return error.UnsupportedConfigFormat;
    if (in_interface and !key_written) {
        try appendConfigLine(allocator, &output, &wrote_any, key, value);
    }

    return try output.toOwnedSlice(allocator);
}

fn appendOriginalLine(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u8),
    wrote_any: *bool,
    line: []const u8,
) !void {
    if (wrote_any.*) try output.append(allocator, '\n');
    try output.appendSlice(allocator, line);
    wrote_any.* = true;
}

fn appendConfigLine(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u8),
    wrote_any: *bool,
    key: []const u8,
    value: []const u8,
) !void {
    if (wrote_any.*) try output.append(allocator, '\n');
    try output.appendSlice(allocator, key);
    try output.appendSlice(allocator, " = ");
    try output.appendSlice(allocator, value);
    wrote_any.* = true;
}

fn looksLikeAwgConfig(content: []const u8) bool {
    var has_interface = false;
    var has_peer = false;

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r' });
        if (std.ascii.eqlIgnoreCase(trimmed, "[Interface]")) {
            has_interface = true;
        } else if (std.ascii.eqlIgnoreCase(trimmed, "[Peer]")) {
            has_peer = true;
        }
    }

    return has_interface and has_peer;
}

fn ensureAmneziaWgInstalled(ui: *Tui, allocator: std.mem.Allocator) bool {
    if (!runCommandChecked(
        ui,
        allocator,
        &.{ "apt-get", "-o", "DPkg::Lock::Timeout=600", "-o", "APT::Update::Error-Mode=any", "update", "-qq" },
        "Failed to refresh apt package index",
    )) return false;

    if (!runCommandChecked(
        ui,
        allocator,
        &.{ "apt-get", "-o", "DPkg::Lock::Timeout=600", "install", "-y", "software-properties-common" },
        "Failed to install software-properties-common",
    )) return false;

    if (!runCommandChecked(
        ui,
        allocator,
        &.{ "add-apt-repository", "-y", "ppa:amnezia/ppa" },
        "Failed to add Amnezia PPA",
    )) return false;

    if (!runCommandChecked(
        ui,
        allocator,
        &.{ "apt-get", "-o", "DPkg::Lock::Timeout=600", "-o", "APT::Update::Error-Mode=any", "update", "-qq" },
        "Failed to refresh apt index after adding Amnezia PPA",
    )) return false;

    if (!runCommandChecked(
        ui,
        allocator,
        &.{ "apt-get", "-o", "DPkg::Lock::Timeout=600", "install", "-y", "amneziawg-tools" },
        "Failed to install amneziawg-tools",
    )) return false;

    if (!sys.commandExists("awg") or !sys.commandExists("awg-quick")) {
        ui.fail("amneziawg-tools installation finished but awg/awg-quick were not found in PATH");
        ui.warn("Run `apt-cache policy amneziawg-tools` and verify package availability for your distro.");
        return false;
    }

    return true;
}

fn runCommandChecked(
    ui: *Tui,
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    fail_summary: []const u8,
) bool {
    const result = sys.exec(allocator, argv) catch {
        ui.fail(fail_summary);
        ui.warn("Failed to execute system command.");
        return false;
    };
    defer result.deinit();

    if (result.exit_code != 0) {
        ui.fail(fail_summary);

        if (firstDiagnosticLine(result.stderr)) |line| {
            ui.warn(line);
        } else if (firstDiagnosticLine(result.stdout)) |line| {
            ui.warn(line);
        }

        if (looksLikeLaunchpadPpaIssue(result.stdout) or looksLikeLaunchpadPpaIssue(result.stderr)) {
            ui.warn("Detected Launchpad PPA outage/block (ppa.launchpadcontent.net). This is usually temporary.");
            ui.warn("Retry later or install `amneziawg-tools` from a reachable mirror, then rerun `mtbuddy setup tunnel`.");
        }

        return false;
    }

    return true;
}

fn looksLikeLaunchpadPpaIssue(output: []const u8) bool {
    if (std.mem.indexOf(u8, output, "ppa.launchpadcontent.net") == null) return false;

    return std.mem.indexOf(u8, output, "Failed to fetch") != null or
        std.mem.indexOf(u8, output, "Could not resolve") != null or
        std.mem.indexOf(u8, output, "Temporary failure") != null or
        std.mem.indexOf(u8, output, "Connection timed out") != null or
        std.mem.indexOf(u8, output, "Network is unreachable") != null;
}

fn firstDiagnosticLine(output: []const u8) ?[]const u8 {
    var first_non_empty: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r' });
        if (trimmed.len == 0) continue;
        if (first_non_empty == null) first_non_empty = trimmed;

        if (std.mem.startsWith(u8, trimmed, "E:") or
            std.mem.startsWith(u8, trimmed, "Err:") or
            std.mem.startsWith(u8, trimmed, "W:"))
        {
            return trimmed;
        }
    }

    return first_non_empty;
}

fn validateAwgQuickConfig(allocator: std.mem.Allocator, path: []const u8) AwgQuickValidation {
    if (!sys.commandExists("awg-quick")) return .missing_binary;

    const result = sys.exec(allocator, &.{ "awg-quick", "strip", path }) catch return .missing_binary;
    defer result.deinit();
    return if (result.exit_code == 0) .ok else .invalid_config;
}

fn awgConfigPath(buf: []u8, iface: []const u8) ![]const u8 {
    return try std.fmt.bufPrint(buf, "{s}/{s}.conf", .{ AWG_CONF_DIR, iface });
}

fn isValidTunnelInterfaceName(iface: []const u8) bool {
    if (iface.len == 0 or iface.len > 32) return false;
    for (iface) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '-' or ch == '.') continue;
        return false;
    }
    return true;
}

fn freeOwnedStringSlice(allocator: std.mem.Allocator, values: []const []const u8) void {
    if (values.len == 0) return;
    for (values) |value| allocator.free(value);
    allocator.free(values);
}

fn parseTunnelInterfaceArray(allocator: std.mem.Allocator, value: []const u8) ![]const []const u8 {
    const trimmed = std.mem.trim(u8, value, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (trimmed.len < 2 or trimmed[0] != '[' or trimmed[trimmed.len - 1] != ']') {
        return error.InvalidInterfaceArray;
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

        const quoted = trimmed[i] == '"';
        const start: usize = if (quoted) blk: {
            i += 1;
            break :blk i;
        } else i;
        while (i < trimmed.len and ((quoted and trimmed[i] != '"') or (!quoted and trimmed[i] != ',' and trimmed[i] != ']'))) : (i += 1) {}
        const item = std.mem.trim(u8, trimmed[start..i], &[_]u8{ ' ', '\t', '\r', '\n' });
        if (quoted and i < trimmed.len and trimmed[i] == '"') i += 1;
        if (item.len > 0 and isValidTunnelInterfaceName(item)) {
            try list.append(allocator, try allocator.dupe(u8, item));
        }
    }

    if (list.items.len == 0) {
        list.deinit(allocator);
        return &.{};
    }
    return try list.toOwnedSlice(allocator);
}

fn loadTunnelPoolFromDoc(allocator: std.mem.Allocator, doc: *toml.TomlDoc) ![]const []const u8 {
    if (doc.get("upstream.tunnel", "interfaces")) |raw_interfaces| {
        const parsed = parseTunnelInterfaceArray(allocator, raw_interfaces) catch &.{};
        if (parsed.len > 0) return parsed;
    }

    if (doc.get("upstream.tunnel", "interface")) |legacy_iface| {
        const trimmed = std.mem.trim(u8, legacy_iface, &[_]u8{ ' ', '\t', '\r', '\n' });
        if (isValidTunnelInterfaceName(trimmed)) {
            const values = try allocator.alloc([]const u8, 1);
            values[0] = try allocator.dupe(u8, trimmed);
            return values;
        }
    }

    return &.{};
}

fn loadConfiguredTunnelPool(allocator: std.mem.Allocator) ![]const []const u8 {
    var doc = toml.TomlDoc.load(allocator, INSTALL_DIR ++ "/config.toml") catch return &.{};
    defer doc.deinit();

    return try loadTunnelPoolFromDoc(allocator, &doc);
}

fn loadKnownTunnelInterfaces(allocator: std.mem.Allocator) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit(allocator);
    }

    const pool = try loadConfiguredTunnelPool(allocator);
    defer freeOwnedStringSlice(allocator, pool);
    for (pool) |iface| {
        if (!containsInterface(list.items, iface)) {
            try list.append(allocator, try allocator.dupe(u8, iface));
        }
    }

    const found = sys.exec(allocator, &.{
        "find",
        "/etc/amnezia/amneziawg",
        "/etc/wireguard",
        "-maxdepth",
        "1",
        "-type",
        "f",
        "-name",
        "*.conf",
        "-printf",
        "%f\n",
    }) catch null;
    if (found) |result| {
        defer result.deinit();
        var lines = std.mem.splitScalar(u8, result.stdout, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r', '\n' });
            if (!std.mem.endsWith(u8, trimmed, ".conf")) continue;
            const iface = trimmed[0 .. trimmed.len - ".conf".len];
            if (!isValidTunnelInterfaceName(iface)) continue;
            if (!containsInterface(list.items, iface)) {
                try list.append(allocator, try allocator.dupe(u8, iface));
            }
        }
    }

    if (list.items.len == 0) {
        list.deinit(allocator);
        return &.{};
    }
    return try list.toOwnedSlice(allocator);
}

fn containsInterface(values: []const []const u8, iface: []const u8) bool {
    for (values) |value| {
        if (std.mem.eql(u8, value, iface)) return true;
    }
    return false;
}

fn appendInterfaceIfMissing(allocator: std.mem.Allocator, values: []const []const u8, iface: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |value| allocator.free(value);
        out.deinit(allocator);
    }

    for (values) |value| {
        try out.append(allocator, try allocator.dupe(u8, value));
    }
    if (!containsInterface(values, iface)) {
        try out.append(allocator, try allocator.dupe(u8, iface));
    }
    if (out.items.len == 0) {
        out.deinit(allocator);
        return &.{};
    }
    return try out.toOwnedSlice(allocator);
}

const TunnelRemovalConfigResult = struct {
    removed: bool,
    removed_last: bool,
    remaining_pool: []const []const u8,
};

fn removeInterfaceFromPool(allocator: std.mem.Allocator, values: []const []const u8, iface: []const u8) !TunnelRemovalConfigResult {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |value| allocator.free(value);
        out.deinit(allocator);
    }

    var removed = false;
    for (values) |value| {
        if (std.mem.eql(u8, value, iface)) {
            removed = true;
            continue;
        }
        try out.append(allocator, try allocator.dupe(u8, value));
    }

    return .{
        .removed = removed,
        .removed_last = removed and out.items.len == 0,
        .remaining_pool = try out.toOwnedSlice(allocator),
    };
}

fn removeTunnelFromDoc(allocator: std.mem.Allocator, doc: *toml.TomlDoc, iface: []const u8) !TunnelRemovalConfigResult {
    const existing = try loadTunnelPoolFromDoc(allocator, doc);
    defer freeOwnedStringSlice(allocator, existing);

    const result = try removeInterfaceFromPool(allocator, existing, iface);
    errdefer freeOwnedStringSlice(allocator, result.remaining_pool);

    if (!result.removed) return result;

    if (result.remaining_pool.len > 0) {
        var first_buf: [64]u8 = undefined;
        const first = try std.fmt.bufPrint(&first_buf, "\"{s}\"", .{result.remaining_pool[0]});
        try doc.set("upstream.tunnel", "interface", first);
    } else {
        try clearTunnelConfigInDoc(doc);
    }

    const array_literal = try formatInterfaceArrayLiteral(allocator, result.remaining_pool);
    defer allocator.free(array_literal);
    try doc.set("upstream.tunnel", "interfaces", array_literal);

    const pinned = doc.get("upstream.tunnel", "pinned_interface") orelse "";
    if (std.mem.eql(u8, pinned, iface) or result.remaining_pool.len == 0) {
        try doc.set("upstream.tunnel", "pinned_interface", "\"\"");
    }

    return result;
}

fn clearTunnelConfigInDoc(doc: *toml.TomlDoc) !void {
    try doc.set("upstream", "type", "\"auto\"");
    try doc.set("upstream.tunnel", "interface", "\"\"");
    try doc.set("upstream.tunnel", "interfaces", "[]");
    try doc.set("upstream.tunnel", "pinned_interface", "\"\"");
}

fn nextAwgInterfaceNameFromPool(allocator: std.mem.Allocator, used: []const []const u8) ![]const u8 {
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        var buf: [16]u8 = undefined;
        const candidate = try std.fmt.bufPrint(&buf, "awg{d}", .{i});
        if (!containsInterface(used, candidate)) return try allocator.dupe(u8, candidate);
    }
    return error.NoFreeInterface;
}

fn selectTunnelInterface(allocator: std.mem.Allocator, requested: []const u8) ![]u8 {
    const trimmed_requested = std.mem.trim(u8, requested, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (trimmed_requested.len > 0) {
        if (!isValidTunnelInterfaceName(trimmed_requested)) return error.InvalidInterfaceName;
        return try allocator.dupe(u8, trimmed_requested);
    }

    var doc = toml.TomlDoc.load(allocator, INSTALL_DIR ++ "/config.toml") catch {
        return try allocator.dupe(u8, "awg0");
    };
    defer doc.deinit();

    const pool = try loadTunnelPoolFromDoc(allocator, &doc);
    defer freeOwnedStringSlice(allocator, pool);

    var i: usize = 0;
    while (i < 64) : (i += 1) {
        var name_buf: [16]u8 = undefined;
        const candidate = try std.fmt.bufPrint(&name_buf, "awg{d}", .{i});
        var path_buf: [256]u8 = undefined;
        const path = awgConfigPath(&path_buf, candidate) catch continue;
        if (!containsInterface(pool, candidate) and !sys.fileExists(path)) {
            return try allocator.dupe(u8, candidate);
        }
    }

    return error.NoFreeInterface;
}

fn formatInterfaceArrayLiteral(allocator: std.mem.Allocator, values: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.append(allocator, '[');
    for (values, 0..) |value, idx| {
        if (idx > 0) try out.appendSlice(allocator, ", ");
        try out.append(allocator, '"');
        try out.appendSlice(allocator, value);
        try out.append(allocator, '"');
    }
    try out.append(allocator, ']');
    return try out.toOwnedSlice(allocator);
}

fn setTunnelPoolConfig(allocator: std.mem.Allocator, iface: []const u8) void {
    var doc = toml.TomlDoc.load(allocator, INSTALL_DIR ++ "/config.toml") catch return;
    defer doc.deinit();

    doc.set("upstream", "type", "\"tunnel\"") catch return;

    const existing = loadTunnelPoolFromDoc(allocator, &doc) catch &.{};
    defer freeOwnedStringSlice(allocator, existing);

    const pool = appendInterfaceIfMissing(allocator, existing, iface) catch return;
    defer freeOwnedStringSlice(allocator, pool);

    if (pool.len > 0) {
        var first_buf: [64]u8 = undefined;
        const first = std.fmt.bufPrint(&first_buf, "\"{s}\"", .{pool[0]}) catch return;
        doc.set("upstream.tunnel", "interface", first) catch return;
    }

    const array_literal = formatInterfaceArrayLiteral(allocator, pool) catch return;
    defer allocator.free(array_literal);
    doc.set("upstream.tunnel", "interfaces", array_literal) catch return;

    doc.save(INSTALL_DIR ++ "/config.toml") catch {};
}

fn installTunnelPoolUnits(ui: *Tui, allocator: std.mem.Allocator) void {
    const service =
        \\[Unit]
        \\Description=MTProto tunnel pool failover
        \\Documentation=https://github.com/sleep3r/mtproto.zig
        \\After=network-online.target
        \\Wants=network-online.target
        \\
        \\[Service]
        \\Type=oneshot
        \\ExecStart=/usr/local/bin/setup_tunnel.sh
        \\AmbientCapabilities=CAP_NET_ADMIN
    ;

    const timer =
        \\[Unit]
        \\Description=Run MTProto tunnel pool failover checks
        \\
        \\[Timer]
        \\OnBootSec=30s
        \\OnUnitInactiveSec=30s
        \\RandomizedDelaySec=5s
        \\Persistent=true
        \\
        \\[Install]
        \\WantedBy=timers.target
    ;

    sys.writeFile(TUNNEL_POOL_SERVICE, service) catch {
        ui.warn("Failed to write mtproto-tunnel-pool.service");
        return;
    };
    sys.writeFile(TUNNEL_POOL_TIMER, timer) catch {
        ui.warn("Failed to write mtproto-tunnel-pool.timer");
        return;
    };

    _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};
    _ = sys.exec(allocator, &.{ "systemctl", "enable", "--now", "mtproto-tunnel-pool.timer" }) catch {};
    ui.ok("Tunnel pool failover timer installed");
}

fn renderTunnelPoolScript(allocator: std.mem.Allocator) ![]const u8 {
    return try allocator.dupe(u8,
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\
        \\CONFIG_FILE="/opt/mtproto-proxy/config.toml"
        \\CONF_DIR="/etc/amnezia/amneziawg"
        \\STATE_DIR="/run/mtproto-proxy"
        \\STATE_FILE="$STATE_DIR/tunnel-pool.state"
        \\MARK=200
        \\TABLE=200
        \\RULE_PRIORITY=1200
        \\PROBE_URL="https://core.telegram.org/getProxyConfig"
        \\
        \\mkdir -p "$STATE_DIR"
        \\
        \\log() {
        \\    logger -t mtproto-tunnel-pool "$*" 2>/dev/null || true
        \\}
        \\
        \\read_tunnel_key() {
        \\    local want_key="$1"
        \\    [[ -f "$CONFIG_FILE" ]] || return 1
        \\    awk -v want_key="$want_key" '
        \\        BEGIN { in_section=0; value="" }
        \\        /^[[:space:]]*\[upstream\.tunnel\][[:space:]]*$/ { in_section=1; next }
        \\        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ { in_section=0; next }
        \\        in_section {
        \\            line=$0
        \\            sub(/[;#].*/, "", line)
        \\            if (line ~ "^[[:space:]]*" want_key "[[:space:]]*=") {
        \\                sub(/^[^=]*=/, "", line)
        \\                gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        \\                gsub(/^"|"$/, "", line)
        \\                value=line
        \\            }
        \\        }
        \\        END { if (value != "") print value }
        \\    ' "$CONFIG_FILE"
        \\}
        \\
        \\trim() {
        \\    local v="$1"
        \\    v="${v#"${v%%[![:space:]]*}"}"
        \\    v="${v%"${v##*[![:space:]]}"}"
        \\    printf '%s\n' "$v"
        \\}
        \\
        \\parse_interfaces() {
        \\    local raw="$1"
        \\    raw="${raw#[}"
        \\    raw="${raw%]}"
        \\    raw="${raw//\"/}"
        \\    local old_ifs="$IFS"
        \\    IFS=','
        \\    read -r -a parts <<< "$raw"
        \\    IFS="$old_ifs"
        \\    for item in "${parts[@]}"; do
        \\        item="$(trim "$item")"
        \\        [[ -n "$item" ]] && printf '%s\n' "$item"
        \\    done
        \\}
        \\
        \\add_unique() {
        \\    local item="$1"
        \\    [[ -n "$item" ]] || return 0
        \\    local existing
        \\    for existing in "${candidates[@]}"; do
        \\        [[ "$existing" == "$item" ]] && return 0
        \\    done
        \\    candidates+=("$item")
        \\}
        \\
        \\conf_path_for() {
        \\    local iface="$1"
        \\    if [[ -f "$CONF_DIR/${iface}.conf" ]]; then
        \\        printf '%s/%s.conf\n' "$CONF_DIR" "$iface"
        \\    elif [[ -f "/etc/wireguard/${iface}.conf" ]]; then
        \\        printf '/etc/wireguard/%s.conf\n' "$iface"
        \\    else
        \\        printf '%s/%s.conf\n' "$CONF_DIR" "$iface"
        \\    fi
        \\}
        \\
        \\quick_tool_for() {
        \\    local iface="$1"
        \\    if [[ "$iface" == wg* ]] && command -v wg-quick >/dev/null 2>&1; then
        \\        printf 'wg-quick\n'
        \\        return
        \\    fi
        \\    if command -v awg-quick >/dev/null 2>&1; then
        \\        printf 'awg-quick\n'
        \\        return
        \\    fi
        \\    if command -v wg-quick >/dev/null 2>&1; then
        \\        printf 'wg-quick\n'
        \\        return
        \\    fi
        \\    return 1
        \\}
        \\
        \\show_tool_for() {
        \\    local iface="$1"
        \\    if [[ "$iface" == wg* ]] && command -v wg >/dev/null 2>&1; then
        \\        printf 'wg\n'
        \\        return
        \\    fi
        \\    if command -v awg >/dev/null 2>&1; then
        \\        printf 'awg\n'
        \\        return
        \\    fi
        \\    if command -v wg >/dev/null 2>&1; then
        \\        printf 'wg\n'
        \\        return
        \\    fi
        \\    return 1
        \\}
        \\
        \\ensure_iface_up() {
        \\    local iface="$1"
        \\    ip link show dev "$iface" >/dev/null 2>&1 && return 0
        \\    local quick conf
        \\    quick="$(quick_tool_for "$iface")" || return 1
        \\    conf="$(conf_path_for "$iface")"
        \\    [[ -f "$conf" ]] || return 1
        \\    "$quick" up "$conf" >/dev/null 2>&1
        \\}
        \\
        \\policy_rule_exists() {
        \\    local mark_hex
        \\    mark_hex="$(printf '0x%x' "$MARK")"
        \\    ip -4 rule show | awk -v mark="$MARK" -v mark_hex="$mark_hex" -v table="$TABLE" '
        \\        (($0 ~ "fwmark " mark || $0 ~ "fwmark " mark_hex) && ($0 ~ "lookup " table || $0 ~ "table " table)) { found = 1 }
        \\        END { exit found ? 0 : 1 }
        \\    '
        \\}
        \\
        \\ensure_policy_rule() {
        \\    while ip -4 rule del priority "$RULE_PRIORITY" fwmark "$MARK" table "$TABLE" 2>/dev/null; do :; done
        \\    while ip -4 rule del fwmark "$MARK" table "$TABLE" 2>/dev/null; do :; done
        \\    ip -4 rule add fwmark "$MARK" table "$TABLE" priority "$RULE_PRIORITY" 2>/dev/null || true
        \\    policy_rule_exists
        \\}
        \\
        \\route_table_to_iface() {
        \\    local iface="$1"
        \\    ip -4 route flush table "$TABLE" 2>/dev/null || true
        \\    ip -4 route replace default dev "$iface" table "$TABLE"
        \\}
        \\
        \\policy_route_matches_iface() {
        \\    local iface="$1" target="${2:-149.154.175.50}"
        \\    ip -4 route get "$target" mark "$MARK" 2>/dev/null |
        \\        awk -v iface="$iface" '
        \\            { for (i = 1; i < NF; i++) if ($i == "dev" && $(i + 1) == iface) found = 1 }
        \\            END { exit found ? 0 : 1 }
        \\        '
        \\}
        \\
        \\telegram_probe_iface() {
        \\    local iface="$1"
        \\    command -v curl >/dev/null 2>&1 || return 2
        \\    curl --interface "$iface" -fsS --connect-timeout 3 --max-time 5 "$PROBE_URL" >/dev/null 2>&1
        \\}
        \\
        \\probe_iface() {
        \\    local iface="$1"
        \\    reason=""
        \\    ensure_iface_up "$iface" || { reason="failed to bring interface up"; return 1; }
        \\    ip link show dev "$iface" >/dev/null 2>&1 || { reason="interface missing"; return 1; }
        \\    local show_tool
        \\    show_tool="$(show_tool_for "$iface")" || { reason="awg/wg show tool missing"; return 1; }
        \\    "$show_tool" show "$iface" >/dev/null 2>&1 || { reason="tunnel show failed"; return 1; }
        \\    route_table_to_iface "$iface" || { reason="failed to install policy route"; return 1; }
        \\    policy_route_matches_iface "$iface" || { reason="policy route check failed"; return 1; }
        \\    if telegram_probe_iface "$iface"; then
        \\        reason="healthy"
        \\        return 0
        \\    fi
        \\    # Usable (up + policy route installed) but can't reach Telegram through it.
        \\    # Return 2 ("degraded-usable") so pool selection PREFERS a tunnel that can
        \\    # actually reach Telegram, and only falls back to this one if none can.
        \\    reason="up; Telegram probe failed"
        \\    return 2
        \\}
        \\
        \\state_value() {
        \\    local key="$1"
        \\    [[ -f "$STATE_FILE" ]] || return 0
        \\    awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$STATE_FILE"
        \\}
        \\
        \\write_state() {
        \\    local active="$1" status="$2" reason="$3"
        \\    local prev_active prev_last now last_switch
        \\    prev_active="$(state_value active || true)"
        \\    prev_last="$(state_value last_switch || true)"
        \\    now="$(date -Is)"
        \\    last_switch="${prev_last:-$now}"
        \\    [[ "$active" != "$prev_active" ]] && last_switch="$now"
        \\    {
        \\        printf 'active=%s\n' "$active"
        \\        printf 'status=%s\n' "$status"
        \\        printf 'reason=%s\n' "$reason"
        \\        printf 'pinned=%s\n' "$pinned"
        \\        printf 'pool=%s\n' "${pool[*]}"
        \\        printf 'last_switch=%s\n' "$last_switch"
        \\        printf 'checked_at=%s\n' "$now"
        \\    } > "$STATE_FILE"
        \\}
        \\
        \\mapfile -t pool < <(
        \\    raw_interfaces="$(read_tunnel_key interfaces || true)"
        \\    if [[ -n "${raw_interfaces:-}" ]]; then
        \\        parse_interfaces "$raw_interfaces"
        \\    else
        \\        legacy="$(read_tunnel_key interface || true)"
        \\        printf '%s\n' "${legacy:-awg0}"
        \\    fi
        \\)
        \\
        \\previous="$(ip -4 route show table "$TABLE" default 2>/dev/null | awk '/default/ { for (i=1;i<=NF;i++) if ($i=="dev") { print $(i+1); exit } }' || true)"
        \\pinned="$(read_tunnel_key pinned_interface || true)"
        \\candidates=()
        \\add_unique "$pinned"
        \\# Sticky: after the pin, prefer the currently-active tunnel if it's still in the
        \\# pool, so a healthy active tunnel isn't dropped for an earlier-listed one — that
        \\# would flap (reset every connection) whenever the first pool entry is reachable.
        \\for iface in "${pool[@]}"; do
        \\    [[ "$iface" == "$previous" ]] && add_unique "$previous"
        \\done
        \\for iface in "${pool[@]}"; do
        \\    add_unique "$iface"
        \\done
        \\
        \\ensure_policy_rule || {
        \\    write_state "" "degraded" "failed to install policy rule"
        \\    echo "Failed to install tunnel policy rule: fwmark=$MARK table=$TABLE" >&2
        \\    exit 1
        \\}
        \\
        \\selected=""
        \\selected_reason=""
        \\selected_status="healthy"
        \\fallback=""
        \\fallback_reason=""
        \\for iface in "${candidates[@]}"; do
        \\    if probe_iface "$iface"; then rc=0; else rc=$?; fi
        \\    if [[ "$rc" -eq 0 ]]; then
        \\        selected="$iface"
        \\        selected_reason="$reason"
        \\        break
        \\    elif [[ "$rc" -eq 2 && -z "$fallback" ]]; then
        \\        # Up but can't reach Telegram — remember it as a last resort, but keep
        \\        # looking for one that actually reaches Telegram. This is the pool
        \\        # failover: a dead-but-up active tunnel is now skipped over.
        \\        fallback="$iface"
        \\        fallback_reason="$reason"
        \\        log "tunnel $iface up but Telegram probe failed; trying others"
        \\    else
        \\        log "tunnel $iface unhealthy: $reason"
        \\    fi
        \\done
        \\
        \\if [[ -z "$selected" && -n "$fallback" ]]; then
        \\    # No tunnel reached Telegram (the probe may be globally blocked/flaky) — fall
        \\    # back to the first usable one so a single-tunnel deploy doesn't go dark.
        \\    selected="$fallback"
        \\    selected_reason="$fallback_reason (fallback)"
        \\    selected_status="degraded"
        \\    log "no Telegram-reachable tunnel; falling back to $selected"
        \\fi
        \\
        \\if [[ -z "$selected" ]]; then
        \\    write_state "" "degraded" "no usable tunnel"
        \\    echo "No usable tunnel in pool: ${candidates[*]}" >&2
        \\    exit 1
        \\fi
        \\
        \\route_table_to_iface "$selected"
        \\write_state "$selected" "$selected_status" "$selected_reason"
        \\
        \\if [[ "$previous" != "$selected" ]]; then
        \\    log "selected tunnel $selected (previous: ${previous:-none})"
        \\fi
        \\echo "Tunnel routing ready: fwmark=$MARK -> table $TABLE via $selected"
    );
}

fn stripAwgDnsLines(allocator: std.mem.Allocator, path: []const u8) !bool {
    const content = try readFileAllocCwd(allocator, path, 1024 * 1024);
    defer allocator.free(content);

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    var removed_any = false;
    var wrote_any = false;

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r' });

        var skip = false;
        if (trimmed.len > 0 and trimmed[0] != '#') {
            if (std.mem.indexOfScalar(u8, trimmed, '=')) |eq_pos| {
                const key = std.mem.trim(u8, trimmed[0..eq_pos], &[_]u8{ ' ', '\t' });
                if (std.ascii.eqlIgnoreCase(key, "DNS")) {
                    skip = true;
                }
            }
        }

        if (skip) {
            removed_any = true;
            continue;
        }

        if (wrote_any) try output.append(allocator, '\n');
        try output.appendSlice(allocator, line);
        wrote_any = true;
    }

    if (!removed_any) return false;

    const sanitized = try output.toOwnedSlice(allocator);
    defer allocator.free(sanitized);

    try sys.writeFileMode(path, sanitized, 0o600);
    return true;
}

fn stripAwgEmptyAssignments(allocator: std.mem.Allocator, path: []const u8) !bool {
    const content = try readFileAllocCwd(allocator, path, 1024 * 1024);
    defer allocator.free(content);

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    var removed_any = false;
    var wrote_any = false;

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r' });

        var skip = false;
        if (trimmed.len > 0 and trimmed[0] != '#' and trimmed[0] != ';') {
            if (std.mem.indexOfScalar(u8, trimmed, '=')) |eq_pos| {
                const key = std.mem.trim(u8, trimmed[0..eq_pos], &[_]u8{ ' ', '\t' });
                const value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], &[_]u8{ ' ', '\t' });
                if (key.len > 0 and value.len == 0) {
                    skip = true;
                }
            }
        }

        if (skip) {
            removed_any = true;
            continue;
        }

        if (wrote_any) try output.append(allocator, '\n');
        try output.appendSlice(allocator, line);
        wrote_any = true;
    }

    if (!removed_any) return false;

    const sanitized = try output.toOwnedSlice(allocator);
    defer allocator.free(sanitized);

    try sys.writeFileMode(path, sanitized, 0o600);
    return true;
}

fn ensureAwgTableOff(allocator: std.mem.Allocator, path: []const u8) !bool {
    const content = try readFileAllocCwd(allocator, path, 1024 * 1024);
    defer allocator.free(content);

    var in_interface = false;
    var has_interface = false;
    var has_table = false;
    var interface_header_idx: ?usize = null;

    var idx: usize = 0;
    var lines_scan = std.mem.splitScalar(u8, content, '\n');
    while (lines_scan.next()) |line| : (idx += 1) {
        const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r' });

        if (trimmed.len >= 2 and trimmed[0] == '[' and trimmed[trimmed.len - 1] == ']') {
            in_interface = std.ascii.eqlIgnoreCase(trimmed, "[Interface]");
            if (in_interface) {
                has_interface = true;
                if (interface_header_idx == null) interface_header_idx = idx;
            }
            continue;
        }

        if (!in_interface) continue;
        if (trimmed.len == 0 or trimmed[0] == '#' or trimmed[0] == ';') continue;

        if (std.mem.indexOfScalar(u8, trimmed, '=')) |eq_pos| {
            const key = std.mem.trim(u8, trimmed[0..eq_pos], &[_]u8{ ' ', '\t' });
            if (std.ascii.eqlIgnoreCase(key, "Table")) {
                has_table = true;
                break;
            }
        }
    }

    if (!has_interface or has_table or interface_header_idx == null) return false;

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    var out_idx: usize = 0;
    var wrote_any = false;
    var lines_write = std.mem.splitScalar(u8, content, '\n');
    while (lines_write.next()) |line| : (out_idx += 1) {
        if (wrote_any) try out.append(allocator, '\n');
        try out.appendSlice(allocator, line);
        wrote_any = true;

        if (out_idx == interface_header_idx.?) {
            try out.appendSlice(allocator, "\nTable = off");
        }
    }

    const sanitized = try out.toOwnedSlice(allocator);
    defer allocator.free(sanitized);

    try sys.writeFileMode(path, sanitized, 0o600);
    return true;
}

const NGINX_MASKING_CONF = "/etc/nginx/sites-available/mtproto-masking";

/// Strip legacy netns listen directives (e.g. `listen 10.200.200.1:8443 ssl;`)
/// from the nginx masking config. Returns true if any lines were removed.
fn cleanupNetnsNginxListen(allocator: std.mem.Allocator) bool {
    const content = readFileAllocCwd(allocator, NGINX_MASKING_CONF, 256 * 1024) catch return false;
    defer allocator.free(content);

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    var removed_any = false;
    var wrote_any = false;

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r' });

        // Match directives like: listen 10.200.200.1:8443 ssl;
        if (std.mem.startsWith(u8, trimmed, "listen ") and
            std.mem.indexOf(u8, trimmed, "10.200.200.") != null)
        {
            removed_any = true;
            continue;
        }

        if (wrote_any) output.append(allocator, '\n') catch return false;
        output.appendSlice(allocator, line) catch return false;
        wrote_any = true;
    }

    if (!removed_any) return false;

    const sanitized = output.toOwnedSlice(allocator) catch return false;
    defer allocator.free(sanitized);

    sys.writeFile(NGINX_MASKING_CONF, sanitized) catch return false;
    return true;
}

/// Detect the currently active tunnel by inspecting runtime state.
/// Returns the `Tunnel.Tag` corresponding to the detected tunnel,
/// or `.none` if no known tunnel is active.
pub fn detectActiveTunnel(allocator: std.mem.Allocator) Tunnel.Tag {
    const route_result = sys.exec(allocator, &.{ "ip", "-4", "route", "show", "table", "200", "default" }) catch null;
    if (route_result) |r| {
        defer r.deinit();
        if (r.exit_code == 0 and std.mem.indexOf(u8, r.stdout, " dev ") != null) return .tunnel;
    }

    const awg_result = sys.exec(allocator, &.{ "awg", "show", "awg0" }) catch null;
    if (awg_result) |r| {
        defer r.deinit();
        if (r.exit_code == 0) return .tunnel;
    }

    const wg_result = sys.exec(allocator, &.{ "wg", "show", "wg0" }) catch null;
    if (wg_result) |r| {
        defer r.deinit();
        if (r.exit_code == 0) return .tunnel;
    }

    return .none;
}

const test_amnezia_vpn_link =
    "vpn://AAABPXicLY9Ra8IwFIX_Srn4WGoSHZSCD6I-lDEX9Gm0IrG5jkKbliSdG6X_fTdWTiA53wn3JCNo4zhkwJOnIA5AEEiTpwhUnfGqNmgdZMUI6vEN2QiNcv5K0b0mC2MJ87mELCqhyI1He1cVXsrSbLW26Fy0iThLgsRyJYhLW_8oj-_4R1FPhtj-eCazkKf8Y3v6upKNo8X5sPs87l-eLuUi2tBGq5CINnTI4dbU1WvUcAutTdM9UOcyFM-9bMkoOBjdd7XxhPFXtX2DSdW12Xq9CjMhpve3fpg_wkXKZtR31gf2xlPBJpimy_QPWglhtw";

test "tunnel pool - next awg interface skips used names" {
    const used = [_][]const u8{ "awg0", "awg1" };
    const next = try nextAwgInterfaceNameFromPool(std.testing.allocator, &used);
    defer std.testing.allocator.free(next);
    try std.testing.expectEqualStrings("awg2", next);
}

test "tunnel pool - append interface avoids duplicates" {
    const existing = [_][]const u8{ "awg0", "awg1" };

    const same = try appendInterfaceIfMissing(std.testing.allocator, &existing, "awg1");
    defer freeOwnedStringSlice(std.testing.allocator, same);
    try std.testing.expectEqual(@as(usize, 2), same.len);
    try std.testing.expectEqualStrings("awg0", same[0]);
    try std.testing.expectEqualStrings("awg1", same[1]);

    const added = try appendInterfaceIfMissing(std.testing.allocator, &existing, "awg2");
    defer freeOwnedStringSlice(std.testing.allocator, added);
    try std.testing.expectEqual(@as(usize, 3), added.len);
    try std.testing.expectEqualStrings("awg2", added[2]);
}

test "tunnel pool - script renders failover (prefer reachable, fall back to usable)" {
    const script = try renderTunnelPoolScript(std.testing.allocator);
    defer std.testing.allocator.free(script);

    try std.testing.expect(std.mem.indexOf(u8, script, "route_table_to_iface \"$selected\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "policy_route_matches_iface \"$iface\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "route show table \"$TABLE\" default 2>/dev/null") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "https://core.telegram.org/getProxyConfig") != null);
    // probe_iface returns 2 (up but Telegram-unreachable) so the pool can skip a
    // dead-but-up tunnel and fail over to a healthy one.
    try std.testing.expect(std.mem.indexOf(u8, script, "return 2") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "trying others") != null);
    // ...but a single tunnel whose probe fails is still used (fallback), not dropped.
    try std.testing.expect(std.mem.indexOf(u8, script, "falling back to $selected") != null);
    // set -e safety: probe's non-zero exit is captured, not fatal.
    try std.testing.expect(std.mem.indexOf(u8, script, "if probe_iface \"$iface\"; then rc=0; else rc=$?; fi") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "pinned_interface") != null);
}

test "tunnel pool timer repeats after oneshot service exits" {
    const source = @embedFile("tunnel.zig");
    const needle = "OnUnitInactiveSec" ++ "=30s";
    try std.testing.expect(std.mem.indexOf(u8, source, needle) != null);
}

test "tunnel pool - parses interface array" {
    const pool = try parseTunnelInterfaceArray(std.testing.allocator, "[\"awg0\", \"awg1\"]");
    defer freeOwnedStringSlice(std.testing.allocator, pool);

    try std.testing.expectEqual(@as(usize, 2), pool.len);
    try std.testing.expectEqualStrings("awg0", pool[0]);
    try std.testing.expectEqualStrings("awg1", pool[1]);
}

test "tunnel pool - remove interface from doc clears matching pin" {
    var doc = toml.TomlDoc.initEmpty(std.testing.allocator);
    defer doc.deinit();

    try doc.addSection("upstream");
    try doc.addKvStr("type", "tunnel");
    try doc.addSection("upstream.tunnel");
    try doc.addKvStr("interface", "awg0");
    try doc.addKv("interfaces", "[\"awg0\", \"awg1\", \"awg2\"]");
    try doc.addKvStr("pinned_interface", "awg1");

    const result = try removeTunnelFromDoc(std.testing.allocator, &doc, "awg1");
    defer freeOwnedStringSlice(std.testing.allocator, result.remaining_pool);

    try std.testing.expect(result.removed);
    try std.testing.expect(!result.removed_last);
    try std.testing.expectEqual(@as(usize, 2), result.remaining_pool.len);
    try std.testing.expectEqualStrings("awg0", result.remaining_pool[0]);
    try std.testing.expectEqualStrings("awg2", result.remaining_pool[1]);
    try std.testing.expectEqualStrings("tunnel", doc.get("upstream", "type").?);
    try std.testing.expectEqualStrings("awg0", doc.get("upstream.tunnel", "interface").?);
    try std.testing.expectEqualStrings("[\"awg0\", \"awg2\"]", doc.get("upstream.tunnel", "interfaces").?);
    try std.testing.expectEqualStrings("", doc.get("upstream.tunnel", "pinned_interface").?);
}

test "tunnel pool - remove last interface disables tunnel upstream" {
    var doc = toml.TomlDoc.initEmpty(std.testing.allocator);
    defer doc.deinit();

    try doc.addSection("upstream");
    try doc.addKvStr("type", "tunnel");
    try doc.addSection("upstream.tunnel");
    try doc.addKvStr("interface", "awg0");
    try doc.addKv("interfaces", "[\"awg0\"]");
    try doc.addKvStr("pinned_interface", "awg0");

    const result = try removeTunnelFromDoc(std.testing.allocator, &doc, "awg0");
    defer freeOwnedStringSlice(std.testing.allocator, result.remaining_pool);

    try std.testing.expect(result.removed);
    try std.testing.expect(result.removed_last);
    try std.testing.expectEqual(@as(usize, 0), result.remaining_pool.len);
    try std.testing.expectEqualStrings("auto", doc.get("upstream", "type").?);
    try std.testing.expectEqualStrings("", doc.get("upstream.tunnel", "interface").?);
    try std.testing.expectEqualStrings("[]", doc.get("upstream.tunnel", "interfaces").?);
    try std.testing.expectEqualStrings("", doc.get("upstream.tunnel", "pinned_interface").?);
}

test "tunnel - converts Amnezia vpn link to AWG config" {
    const conf = try convertAmneziaVpnLink(std.testing.allocator, test_amnezia_vpn_link);
    defer std.testing.allocator.free(conf);

    try std.testing.expect(std.mem.indexOf(u8, conf, "[Interface]") != null);
    try std.testing.expect(std.mem.indexOf(u8, conf, "[Peer]") != null);
    try std.testing.expect(std.mem.indexOf(u8, conf, "DNS = 1.1.1.1, 8.8.8.8") != null);
    try std.testing.expect(std.mem.indexOf(u8, conf, "MTU = 1280") != null);
    try std.testing.expect(std.mem.indexOf(u8, conf, "ListenPort = 51820") != null);
}

test "tunnel - installs Amnezia vpn link source directly" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dest_path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/awg0.conf", .{tmp.sub_path});

    const kind = try installAwgConfigSource(std.testing.allocator, " \n" ++ test_amnezia_vpn_link ++ "\n", dest_path);
    try std.testing.expectEqual(AwgConfigKind.amnezia_vpn_link, kind);

    const installed = try std.Io.Dir.cwd().readFileAlloc(io(), dest_path, std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(installed);

    try std.testing.expect(std.mem.indexOf(u8, installed, "vpn://") == null);
    try std.testing.expect(std.mem.indexOf(u8, installed, "[Interface]") != null);
    try std.testing.expect(std.mem.indexOf(u8, installed, "[Peer]") != null);
}

test "tunnel - strips empty AWG assignments" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const name = "awg0.conf";
    try tmp.dir.writeFile(io(), .{
        .sub_path = name,
        .data =
        \\[Interface]
        \\PrivateKey = key
        \\I2 =
        \\I3 =
        \\Jc = 6
        \\
        \\[Peer]
        \\PublicKey = peer
        \\
        ,
    });

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, name });

    try std.testing.expect(try stripAwgEmptyAssignments(std.testing.allocator, path));

    const sanitized = try tmp.dir.readFileAlloc(io(), name, std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(sanitized);

    try std.testing.expect(std.mem.indexOf(u8, sanitized, "I2") == null);
    try std.testing.expect(std.mem.indexOf(u8, sanitized, "I3") == null);
    try std.testing.expect(std.mem.indexOf(u8, sanitized, "Jc = 6") != null);
}
