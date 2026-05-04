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
const AWG_IFACE_CONF_PATH = "/etc/amnezia/awg0.conf";
const TUNNEL_SCRIPT = "/usr/local/bin/setup_tunnel.sh";
const SERVICE_FILE = "/etc/systemd/system/mtproto-proxy.service";
const AWG_CONFIG_PATH = AWG_CONF_DIR ++ "/awg0.conf";
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

/// Run in CLI mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    var opts = TunnelOpts{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--mode") or std.mem.eql(u8, arg, "-m")) {
            _ = args.next();
            ui.warn("--mode is deprecated and ignored; use [general].use_middle_proxy in config.toml");
            continue;
        }

        if (arg.len > 0 and arg[0] != '-') {
            opts.awg_source = arg;
        }
    }

    if (opts.awg_source.len == 0) {
        ui.fail("Usage: mtbuddy setup tunnel <conf-path-or-vpn-link>");
        return;
    }

    try execute(ui, allocator, opts);
}

/// Run in interactive mode.
pub fn runInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    ui.section(i18n.get(ui.lang, .menu_setup_tunnel));

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

    try execute(ui, allocator, .{ .awg_source = conf_source });
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

    // ── Copy AWG config ──
    ui.step("Installing AmneziaWG config...");
    _ = sys.exec(allocator, &.{ "mkdir", "-p", "/etc/amnezia" }) catch {};
    _ = sys.exec(allocator, &.{ "mkdir", "-p", AWG_CONF_DIR }) catch {};

    const config_kind = installAwgConfigSource(allocator, awg_source, AWG_CONFIG_PATH) catch |err| {
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
    _ = sys.execForward(&.{ "ln", "-sfn", AWG_CONFIG_PATH, AWG_IFACE_CONF_PATH }) catch {};

    const dns_removed = stripAwgDnsLines(allocator, AWG_CONFIG_PATH) catch false;
    if (dns_removed) {
        ui.warn("Removed DNS from awg0.conf (host resolver will be used)");
    }

    const empty_removed = stripAwgEmptyAssignments(allocator, AWG_CONFIG_PATH) catch false;
    if (empty_removed) {
        ui.warn("Removed empty AmneziaWG parameters from awg0.conf");
    }

    const table_off_added = ensureAwgTableOff(allocator, AWG_CONFIG_PATH) catch false;
    if (table_off_added) {
        ui.warn("Added Table = off to [Interface] in awg0.conf");
    }

    switch (validateAwgQuickConfig(allocator)) {
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

    ui.ok("Config installed to " ++ AWG_CONFIG_PATH);

    // ── Create tunnel policy script ──
    ui.step("Creating tunnel policy routing script...");

    var tunnel_script_buf: [2048]u8 = undefined;
    const tunnel_script = std.fmt.bufPrint(&tunnel_script_buf,
        \\#!/bin/bash
        \\set -euo pipefail
        \\IFACE="awg0"
        \\MARK={[mark]d}
        \\TABLE={[table]d}
        \\
        \\awg-quick down "$IFACE" 2>/dev/null || true
        \\awg-quick up "$IFACE"
        \\
        \\ip -4 route flush table "$TABLE" 2>/dev/null || true
        \\ip -4 route add default dev "$IFACE" table "$TABLE"
        \\ip -4 rule del fwmark "$MARK" table "$TABLE" 2>/dev/null || true
        \\ip -4 rule add fwmark "$MARK" table "$TABLE" priority 1200
        \\
        \\echo "Tunnel routing ready: fwmark=$MARK -> table $TABLE via $IFACE"
    , .{ .mark = TUNNEL_MARK, .table = TUNNEL_TABLE }) catch "";

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
        &.{ "apt-get", "-o", "APT::Update::Error-Mode=any", "update", "-qq" },
        "Failed to refresh apt package index",
    )) return false;

    if (!runCommandChecked(
        ui,
        allocator,
        &.{ "apt-get", "install", "-y", "software-properties-common" },
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
        &.{ "apt-get", "-o", "APT::Update::Error-Mode=any", "update", "-qq" },
        "Failed to refresh apt index after adding Amnezia PPA",
    )) return false;

    if (!runCommandChecked(
        ui,
        allocator,
        &.{ "apt-get", "install", "-y", "amneziawg-tools" },
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

fn validateAwgQuickConfig(allocator: std.mem.Allocator) AwgQuickValidation {
    if (!sys.commandExists("awg-quick")) return .missing_binary;

    const result = sys.exec(allocator, &.{ "awg-quick", "strip", AWG_CONFIG_PATH }) catch return .missing_binary;
    defer result.deinit();
    return if (result.exit_code == 0) .ok else .invalid_config;
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
    try tmp.dir.writeFile(.{
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

    const sanitized = try tmp.dir.readFileAlloc(std.testing.allocator, name, 4096);
    defer std.testing.allocator.free(sanitized);

    try std.testing.expect(std.mem.indexOf(u8, sanitized, "I2") == null);
    try std.testing.expect(std.mem.indexOf(u8, sanitized, "I3") == null);
    try std.testing.expect(std.mem.indexOf(u8, sanitized, "Jc = 6") != null);
}
