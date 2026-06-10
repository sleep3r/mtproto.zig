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
const tunnel_wg = @import("tunnel_wg.zig");
const Tunnel = @import("tunnel").Tunnel;

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;

const INSTALL_DIR = "/opt/mtproto-proxy";
const AWG_IFACE_CONF_PATH = "/etc/amnezia/awg0.conf";
const TUNNEL_SCRIPT = "/usr/local/bin/setup_tunnel.sh";
const TUNNEL_POOL_SERVICE = "/etc/systemd/system/mtproto-tunnel-pool.service";
const TUNNEL_POOL_TIMER = "/etc/systemd/system/mtproto-tunnel-pool.timer";
const TUNNEL_POOL_STATE = "/run/mtproto-proxy/tunnel-pool.state";

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
    var opts = tunnel_wg.TunnelOpts{};

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

        if (std.mem.eql(u8, arg, "--deps-only")) {
            opts.deps_only = true;
            continue;
        }

        if (arg.len > 0 and arg[0] != '-') {
            opts.awg_source = arg;
        }
    }

    if (!opts.deps_only and opts.awg_source.len == 0) {
        ui.fail("Usage: mtbuddy setup tunnel [--deps-only] [--iface awgN] <conf-path-or-vpn-link>");
        return;
    }

    try tunnel_wg.execute(ui, allocator, opts);
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

    // VPN type was already chosen in the interactive menu (AmneziaWG vs share-link); this
    // path is the AmneziaWG flow.
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

    try tunnel_wg.execute(ui, allocator, .{ .awg_source = conf_source, .iface = selection.iface });
}

fn tr(lang: i18n.Lang, en: []const u8, ru: []const u8) []const u8 {
    return if (lang == .ru) ru else en;
}

fn chooseInteractiveTunnelTarget(ui: *Tui, allocator: std.mem.Allocator) !InteractiveTunnelSelection {
    const pool = try loadConfiguredTunnelPool(allocator);
    defer tunnel_wg.freeOwnedStringSlice(allocator, pool);
    const known = try loadKnownTunnelInterfaces(allocator);
    defer tunnel_wg.freeOwnedStringSlice(allocator, known);

    if (known.len == 0) {
        ui.info(i18n.get(ui.lang, .tunnel_pool_empty));
    } else {
        ui.info(i18n.get(ui.lang, .tunnel_pool_current));
        printTunnelPoolRuntimeStatus(ui, allocator, known, pool);
    }

    const next_iface = try tunnel_wg.selectTunnelInterface(allocator, "");
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
        const source = if (tunnel_wg.containsInterface(pool, iface)) "pool" else "config";
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
    if (!tunnel_wg.isValidTunnelInterfaceName(iface)) return error.InvalidInterfaceName;

    const known_before = try loadKnownTunnelInterfaces(allocator);
    defer tunnel_wg.freeOwnedStringSlice(allocator, known_before);

    var doc = toml.TomlDoc.load(allocator, INSTALL_DIR ++ "/config.toml") catch return error.ConfigSourceNotFound;
    defer doc.deinit();

    const config_result = try removeTunnelFromDoc(allocator, &doc, iface);
    defer tunnel_wg.freeOwnedStringSlice(allocator, config_result.remaining_pool);
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
    const awg_path = tunnel_wg.awgConfigPath(&awg_buf, iface) catch "";
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
    const awg_path = tunnel_wg.awgConfigPath(&awg_buf, iface) catch "";
    var wg_buf: [256]u8 = undefined;
    const wg_path = std.fmt.bufPrint(&wg_buf, "/etc/wireguard/{s}.conf", .{iface}) catch "";

    if (awg_path.len > 0 and sys.fileExists(awg_path)) return true;
    if (wg_path.len > 0 and sys.fileExists(wg_path)) return true;
    if (std.mem.eql(u8, iface, "awg0") and sys.fileExists(AWG_IFACE_CONF_PATH)) return true;
    return false;
}

fn deleteTunnelConfigFiles(allocator: std.mem.Allocator, iface: []const u8) void {
    var awg_buf: [256]u8 = undefined;
    const awg_path = tunnel_wg.awgConfigPath(&awg_buf, iface) catch "";
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

fn loadConfiguredTunnelPool(allocator: std.mem.Allocator) ![]const []const u8 {
    var doc = toml.TomlDoc.load(allocator, INSTALL_DIR ++ "/config.toml") catch return &.{};
    defer doc.deinit();

    return try tunnel_wg.loadTunnelPoolFromDoc(allocator, &doc);
}

fn loadKnownTunnelInterfaces(allocator: std.mem.Allocator) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit(allocator);
    }

    const pool = try loadConfiguredTunnelPool(allocator);
    defer tunnel_wg.freeOwnedStringSlice(allocator, pool);
    for (pool) |iface| {
        if (!tunnel_wg.containsInterface(list.items, iface)) {
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
            if (!tunnel_wg.isValidTunnelInterfaceName(iface)) continue;
            if (!tunnel_wg.containsInterface(list.items, iface)) {
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
    const existing = try tunnel_wg.loadTunnelPoolFromDoc(allocator, doc);
    defer tunnel_wg.freeOwnedStringSlice(allocator, existing);

    const result = try removeInterfaceFromPool(allocator, existing, iface);
    errdefer tunnel_wg.freeOwnedStringSlice(allocator, result.remaining_pool);

    if (!result.removed) return result;

    if (result.remaining_pool.len > 0) {
        var first_buf: [64]u8 = undefined;
        const first = try std.fmt.bufPrint(&first_buf, "\"{s}\"", .{result.remaining_pool[0]});
        try doc.set("upstream.tunnel", "interface", first);
    } else {
        try clearTunnelConfigInDoc(doc);
    }

    const array_literal = try tunnel_wg.formatInterfaceArrayLiteral(allocator, result.remaining_pool);
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
        if (!tunnel_wg.containsInterface(used, candidate)) return try allocator.dupe(u8, candidate);
    }
    return error.NoFreeInterface;
}

/// Strip legacy netns listen directives (e.g. `listen 10.200.200.1:8443 ssl;`)
/// from the nginx masking config. Returns true if any lines were removed.
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

test "tunnel pool - next awg interface skips used names" {
    const used = [_][]const u8{ "awg0", "awg1" };
    const next = try nextAwgInterfaceNameFromPool(std.testing.allocator, &used);
    defer std.testing.allocator.free(next);
    try std.testing.expectEqualStrings("awg2", next);
}

test "tunnel pool - append interface avoids duplicates" {
    const existing = [_][]const u8{ "awg0", "awg1" };

    const same = try tunnel_wg.appendInterfaceIfMissing(std.testing.allocator, &existing, "awg1");
    defer tunnel_wg.freeOwnedStringSlice(std.testing.allocator, same);
    try std.testing.expectEqual(@as(usize, 2), same.len);
    try std.testing.expectEqualStrings("awg0", same[0]);
    try std.testing.expectEqualStrings("awg1", same[1]);

    const added = try tunnel_wg.appendInterfaceIfMissing(std.testing.allocator, &existing, "awg2");
    defer tunnel_wg.freeOwnedStringSlice(std.testing.allocator, added);
    try std.testing.expectEqual(@as(usize, 3), added.len);
    try std.testing.expectEqualStrings("awg2", added[2]);
}

test "tunnel pool - parses interface array" {
    const pool = try tunnel_wg.parseTunnelInterfaceArray(std.testing.allocator, "[\"awg0\", \"awg1\"]");
    defer tunnel_wg.freeOwnedStringSlice(std.testing.allocator, pool);

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
    defer tunnel_wg.freeOwnedStringSlice(std.testing.allocator, result.remaining_pool);

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
    defer tunnel_wg.freeOwnedStringSlice(std.testing.allocator, result.remaining_pool);

    try std.testing.expect(result.removed);
    try std.testing.expect(result.removed_last);
    try std.testing.expectEqual(@as(usize, 0), result.remaining_pool.len);
    try std.testing.expectEqualStrings("auto", doc.get("upstream", "type").?);
    try std.testing.expectEqualStrings("", doc.get("upstream.tunnel", "interface").?);
    try std.testing.expectEqualStrings("[]", doc.get("upstream.tunnel", "interfaces").?);
    try std.testing.expectEqualStrings("", doc.get("upstream.tunnel", "pinned_interface").?);
}
