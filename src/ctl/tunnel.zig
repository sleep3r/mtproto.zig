//! Setup tunnel command for mtbuddy.
//!
//! Configures AmneziaWG on the host and enables socket policy routing
//! for mtproto-proxy (`SO_MARK=200 -> table 200`) without network namespaces.

const std = @import("std");
const tui_mod = @import("tui.zig");
const i18n = @import("i18n.zig");
const sys = @import("sys.zig");
const toml = @import("toml.zig");
const Tunnel = @import("tunnel").Tunnel;

const Tui = tui_mod.Tui;

const INSTALL_DIR = "/opt/mtproto-proxy";
const AWG_CONF_DIR = "/etc/amnezia/amneziawg";
const TUNNEL_SCRIPT = "/usr/local/bin/setup_tunnel.sh";
const SERVICE_FILE = "/etc/systemd/system/mtproto-proxy.service";
const AWG_CONFIG_PATH = AWG_CONF_DIR ++ "/awg0.conf";
const TUNNEL_MARK: u32 = 200;
const TUNNEL_TABLE: u32 = 200;

pub const TunnelOpts = struct {
    awg_conf: []const u8 = "",
};

/// Run in CLI mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.ArgIterator) !void {
    var opts = TunnelOpts{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--mode") or std.mem.eql(u8, arg, "-m")) {
            _ = args.next();
            ui.warn("--mode is deprecated and ignored; use [general].use_middle_proxy in config.toml");
            continue;
        }

        if (arg.len > 0 and arg[0] != '-') {
            opts.awg_conf = arg;
        }
    }

    if (opts.awg_conf.len == 0) {
        ui.fail("Usage: mtbuddy setup tunnel <vpn-config.conf>");
        return;
    }

    try execute(ui, allocator, opts);
}

/// Run in interactive mode.
pub fn runInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    ui.section(i18n.get(ui.lang, .menu_setup_tunnel));

    var conf_buf: [512]u8 = undefined;
    const conf_path = try ui.input(
        i18n.get(ui.lang, .tunnel_conf_prompt),
        i18n.get(ui.lang, .tunnel_conf_help),
        null,
        &conf_buf,
    );

    if (!try ui.confirm(i18n.get(ui.lang, .confirm_proceed), true)) {
        ui.info(i18n.get(ui.lang, .aborting));
        return;
    }

    try execute(ui, allocator, .{ .awg_conf = conf_path });
}

fn execute(ui: *Tui, allocator: std.mem.Allocator, opts: TunnelOpts) !void {
    if (!sys.isRoot()) {
        ui.fail(i18n.get(ui.lang, .error_not_root));
        return;
    }

    if (!sys.fileExists(opts.awg_conf)) {
        ui.fail("Config file not found");
        return;
    }
    if (!sys.fileExists(INSTALL_DIR ++ "/mtproto-proxy")) {
        ui.fail("mtproto-proxy not installed. Run install first.");
        return;
    }

    // ── Install AmneziaWG ──
    if (sys.commandExists("awg")) {
        ui.ok("AmneziaWG already installed");
    } else {
        ui.step("Installing AmneziaWG...");
        _ = sys.execForward(&.{ "apt-get", "update", "-qq" }) catch {};
        _ = sys.execForward(&.{ "apt-get", "install", "-y", "software-properties-common" }) catch {};
        _ = sys.execForward(&.{ "add-apt-repository", "-y", "ppa:amnezia/ppa" }) catch {};
        _ = sys.execForward(&.{ "apt-get", "update", "-qq" }) catch {};
        _ = sys.execForward(&.{ "apt-get", "install", "-y", "amneziawg-tools" }) catch {};
        ui.ok("AmneziaWG installed");
    }

    // ── Copy AWG config ──
    ui.step("Installing AmneziaWG config...");
    _ = sys.exec(allocator, &.{ "mkdir", "-p", AWG_CONF_DIR }) catch {};
    _ = sys.execForward(&.{ "cp", opts.awg_conf, AWG_CONFIG_PATH }) catch {};
    _ = sys.exec(allocator, &.{ "chmod", "600", AWG_CONFIG_PATH }) catch {};

    const dns_removed = stripAwgDnsLines(allocator, AWG_CONFIG_PATH) catch false;
    if (dns_removed) {
        ui.warn("Removed DNS from awg0.conf (host resolver will be used)");
    }

    const table_off_added = ensureAwgTableOff(allocator, AWG_CONFIG_PATH) catch false;
    if (table_off_added) {
        ui.warn("Added Table = off to [Interface] in awg0.conf");
    }

    ui.ok("Config installed to " ++ AWG_CONFIG_PATH);

    // ── Create tunnel policy script ──
    ui.step("Creating tunnel policy routing script...");

    var tunnel_script_buf: [2048]u8 = undefined;
    const tunnel_script = std.fmt.bufPrint(&tunnel_script_buf,
        \\#!/bin/bash
        \\set -euo pipefail
        \\CONF="{[awg_conf]s}"
        \\IFACE="awg0"
        \\MARK={[mark]d}
        \\TABLE={[table]d}
        \\
        \\awg-quick down "$CONF" 2>/dev/null || true
        \\awg-quick up "$CONF"
        \\
        \\ip -4 route flush table "$TABLE" 2>/dev/null || true
        \\ip -4 route add default dev "$IFACE" table "$TABLE"
        \\ip -4 rule del fwmark "$MARK" table "$TABLE" 2>/dev/null || true
        \\ip -4 rule add fwmark "$MARK" table "$TABLE" priority 1200
        \\
        \\echo "Tunnel routing ready: fwmark=$MARK -> table $TABLE via $IFACE"
    , .{ .awg_conf = AWG_CONFIG_PATH, .mark = TUNNEL_MARK, .table = TUNNEL_TABLE }) catch "";

    if (tunnel_script.len == 0) {
        ui.fail("Failed to render tunnel setup script");
        return;
    }

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
        \\Type=simple
        \\ExecStartPre=/usr/local/bin/setup_tunnel.sh
        \\ExecStart=/opt/mtproto-proxy/mtproto-proxy /opt/mtproto-proxy/config.toml
        \\Restart=on-failure
        \\RestartSec=5
        \\AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
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

    // ── Configure proxy egress mode ──
    setUpstreamType(allocator, "tunnel");
    ui.stepOk("Set [upstream].type", "tunnel");
    ui.stepOk("Set [upstream.tunnel].interface", "awg0");
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

    const awg_status = sys.exec(allocator, &.{ "awg", "show", "awg0" }) catch null;
    if (awg_status) |result| {
        defer result.deinit();
        if (result.exit_code == 0) {
            ui.stepOk("Tunnel interface active", "awg0");
        } else {
            ui.warn("awg0 is not active (check AWG config and endpoint)");
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
            if (route_result.exit_code == 0 and std.mem.indexOf(u8, route_result.stdout, "dev awg0") != null) {
                ui.stepOk("Policy route via awg0", dc_ip);
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
        .{ .label = "Tunnel:", .value = "awg show awg0" },
        .{ .label = "Policy:", .value = "ip -4 rule show | grep fwmark" },
        .{ .label = "Mark:", .value = "SO_MARK=200 -> table 200" },
        .{ .label = "", .style = .blank },
        .{ .label = "Proxy runs in host network namespace", .style = .success },
        .{ .label = "Tunnel routing is socket-level and explicit", .style = .success },
        .{ .label = "SOCKS5/HTTP upstream stay orthogonal", .style = .success },
    });
}

fn setUpstreamType(allocator: std.mem.Allocator, value: []const u8) void {
    var doc = toml.TomlDoc.load(allocator, INSTALL_DIR ++ "/config.toml") catch return;
    defer doc.deinit();

    var quoted_buf: [64]u8 = undefined;
    const quoted = std.fmt.bufPrint(&quoted_buf, "\"{s}\"", .{value}) catch return;
    doc.set("upstream", "type", quoted) catch return;

    // Default to AmneziaWG interface when setting up tunnel via this script
    doc.set("upstream.tunnel", "interface", "\"awg0\"") catch return;

    doc.save(INSTALL_DIR ++ "/config.toml") catch {};
}

fn stripAwgDnsLines(allocator: std.mem.Allocator, path: []const u8) !bool {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 1024 * 1024);
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

fn ensureAwgTableOff(allocator: std.mem.Allocator, path: []const u8) !bool {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 1024 * 1024);
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

/// Detect the currently active tunnel by inspecting runtime state.
/// Returns the `Tunnel.Tag` corresponding to the detected tunnel,
/// or `.none` if no known tunnel is active.
pub fn detectActiveTunnel(allocator: std.mem.Allocator) Tunnel.Tag {
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
