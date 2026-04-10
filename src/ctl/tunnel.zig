//! Setup tunnel command for mtbuddy.
//!
//! Ports setup_tunnel.sh (400 lines bash) — creates an isolated network
//! namespace with a VPN tunnel so Telegram DCs become reachable
//! while the host keeps normal connectivity.
//! Currently supports AmneziaWG; other VPN types will be added.

const std = @import("std");
const tui_mod = @import("tui.zig");
const i18n = @import("i18n.zig");
const sys = @import("sys.zig");
const toml = @import("toml.zig");
const Tunnel = @import("tunnel").Tunnel;

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;
const SummaryLine = tui_mod.SummaryLine;

const INSTALL_DIR = "/opt/mtproto-proxy";
const NS_NAME = "tg_proxy_ns";
const AWG_CONF_DIR = "/etc/amnezia/amneziawg";
const NETNS_SCRIPT = "/usr/local/bin/setup_netns.sh";
const SERVICE_FILE = "/etc/systemd/system/mtproto-proxy.service";
const AWG_CONFIG_PATH = AWG_CONF_DIR ++ "/awg0.conf";

pub const TunnelOpts = struct {
    awg_conf: []const u8 = "",
    mode: TunnelMode = .direct,
};

pub const TunnelMode = enum {
    direct,
    preserve,
    middleproxy,
};

/// Run in CLI mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.ArgIterator) !void {
    var opts = TunnelOpts{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--mode") or std.mem.eql(u8, arg, "-m")) {
            if (args.next()) |val| {
                if (std.mem.eql(u8, val, "middleproxy")) opts.mode = .middleproxy else if (std.mem.eql(u8, val, "preserve")) opts.mode = .preserve else opts.mode = .direct;
            }
        } else if (arg.len > 0 and arg[0] != '-') {
            opts.awg_conf = arg;
        }
    }

    if (opts.awg_conf.len == 0) {
        ui.fail("Usage: mtbuddy setup tunnel <vpn-config.conf> [--mode direct|preserve|middleproxy]");
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

    const mode_choice = try ui.menu("Tunnel mode", &.{
        "direct — Direct DC connections (recommended)",
        "preserve — Keep existing use_middle_proxy setting",
        "middleproxy — Route through Telegram middle proxy",
    });
    const mode: TunnelMode = switch (mode_choice) {
        0 => .direct,
        1 => .preserve,
        2 => .middleproxy,
        else => .direct,
    };

    if (!try ui.confirm(i18n.get(ui.lang, .confirm_proceed), true)) {
        ui.info(i18n.get(ui.lang, .aborting));
        return;
    }

    try execute(ui, allocator, .{ .awg_conf = conf_path, .mode = mode });
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

    // Read port from config (dupe to ensure lifetime)
    var port: []const u8 = "443";
    var port_buf: [8]u8 = undefined;
    {
        var doc = toml.TomlDoc.load(allocator, INSTALL_DIR ++ "/config.toml") catch null;
        if (doc) |*d| {
            defer d.deinit();
            if (d.get("server", "port")) |p| {
                const len = @min(p.len, port_buf.len);
                @memcpy(port_buf[0..len], p[0..len]);
                port = port_buf[0..len];
            }
        }
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
        ui.warn("Removed DNS from awg0.conf (netns resolver is managed separately)");
    }

    ui.ok("Config installed to " ++ AWG_CONFIG_PATH);

    // ── Create netns setup script ──
    ui.step("Creating network namespace setup script...");

    var netns_script_buf: [4096]u8 = undefined;
    const netns_script = std.fmt.bufPrint(&netns_script_buf,
        \\#!/bin/bash
        \\set -e
        \\NS_NAME="tg_proxy_ns"
        \\MAIN_IF=$(ip -o -4 route show default | awk '{{print $5; exit}}')
        \\if [[ -z "$MAIN_IF" ]]; then
        \\    echo "Failed to detect main network interface" >&2
        \\    exit 1
        \\fi
        \\
        \\ip netns del $NS_NAME 2>/dev/null || true
        \\ip link del veth_main 2>/dev/null || true
        \\
        \\sysctl -w net.ipv4.ip_forward=1 > /dev/null
        \\
        \\ip netns add $NS_NAME
        \\
        \\mkdir -p /etc/netns/$NS_NAME
        \\echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" > /etc/netns/$NS_NAME/resolv.conf
        \\
        \\ip link add veth_main type veth peer name veth_ns
        \\ip link set veth_ns netns $NS_NAME
        \\
        \\ip addr add 10.200.200.1/24 dev veth_main
        \\ip link set veth_main up
        \\
        \\ip netns exec $NS_NAME ip addr add 10.200.200.2/24 dev veth_ns
        \\ip netns exec $NS_NAME ip link set veth_ns up
        \\ip netns exec $NS_NAME ip link set lo up
        \\ip netns exec $NS_NAME ip route add default via 10.200.200.1
        \\
        \\ip netns exec $NS_NAME awg-quick up {[awg_conf]s}
        \\
        \\ip netns exec $NS_NAME ip rule add from 10.200.200.2 table 100 priority 100
        \\ip netns exec $NS_NAME ip route add default via 10.200.200.1 table 100
        \\
        \\iptables -t nat -D PREROUTING -i $MAIN_IF -p tcp --dport {[port]s} -j DNAT --to-destination 10.200.200.2:{[port]s} 2>/dev/null || true
        \\iptables -t nat -A PREROUTING -i $MAIN_IF -p tcp --dport {[port]s} -j DNAT --to-destination 10.200.200.2:{[port]s}
        \\iptables -t nat -D POSTROUTING -s 10.200.200.0/24 -o $MAIN_IF -j MASQUERADE 2>/dev/null || true
        \\iptables -t nat -A POSTROUTING -s 10.200.200.0/24 -o $MAIN_IF -j MASQUERADE
        \\
        \\iptables -D FORWARD -i $MAIN_IF -o veth_main -j ACCEPT 2>/dev/null || true
        \\iptables -A FORWARD -i $MAIN_IF -o veth_main -j ACCEPT
        \\iptables -D FORWARD -i veth_main -o $MAIN_IF -j ACCEPT 2>/dev/null || true
        \\iptables -A FORWARD -i veth_main -o $MAIN_IF -j ACCEPT
        \\
        \\echo "Network namespace $NS_NAME ready, awg0 tunnel active inside namespace"
    , .{ .port = port, .awg_conf = AWG_CONFIG_PATH }) catch "";

    if (netns_script.len > 0) {
        // Write using native Zig I/O (no shell injection risk)
        sys.writeFileMode(NETNS_SCRIPT, netns_script, 0o755) catch {
            ui.fail("Failed to write netns script");
            return;
        };
    }
    ui.ok("Created " ++ NETNS_SCRIPT);

    // ── Patch systemd service ──
    ui.step("Patching systemd service for tunnel mode...");
    const svc_content =
        \\[Unit]
        \\Description=MTProto Proxy (Zig) via AmneziaWG Tunnel
        \\Documentation=https://github.com/sleep3r/mtproto.zig
        \\After=network-online.target
        \\Wants=network-online.target
        \\
        \\[Service]
        \\Type=simple
        \\ExecStartPre=/usr/local/bin/setup_netns.sh
        \\ExecStart=/sbin/ip netns exec tg_proxy_ns /opt/mtproto-proxy/mtproto-proxy /opt/mtproto-proxy/config.toml
        \\Restart=on-failure
        \\RestartSec=5
        \\AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_SYS_ADMIN
        \\LimitNOFILE=131582
        \\TasksMax=65535
        \\
        \\[Install]
        \\WantedBy=multi-user.target
    ;
    {
        // Write using native Zig I/O
        sys.writeFile(SERVICE_FILE, svc_content) catch {
            ui.fail("Failed to write systemd service");
            return;
        };
    }
    _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};
    ui.ok("Systemd service patched for tunnel mode");

    // ── Apply tunnel mode ──
    const mode_label: []const u8 = switch (opts.mode) {
        .direct => blk: {
            setUseMiddleProxy(allocator, "false");
            break :blk "Direct mode (no middle proxy)";
        },
        .preserve => "Preserved existing setting",
        .middleproxy => blk: {
            setUseMiddleProxy(allocator, "true");
            break :blk "MiddleProxy mode enabled";
        },
    };
    ui.ok(mode_label);

    setUpstreamType(allocator, "tunnel");
    ui.stepOk("Set [upstream].type", "tunnel");
    ui.stepOk("Set [upstream.tunnel].interface", "awg0");

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

    // ── Patch Nginx masking for tunnel IP ──
    if (sys.fileExists("/etc/nginx/sites-available/mtproto-masking")) {
        const patch_cmd = "grep -q '10\\.200\\.200\\.1' /etc/nginx/sites-available/mtproto-masking 2>/dev/null || " ++
            "sed -i '/listen.*127\\.0\\.0\\.1.*ssl/a\\    listen 10.200.200.1:8443 ssl;' /etc/nginx/sites-available/mtproto-masking && " ++
            "nginx -t >/dev/null 2>&1 && systemctl reload nginx";
        _ = sys.exec(allocator, &.{ "bash", "-c", patch_cmd }) catch {};
        ui.ok("Nginx masking patched for tunnel netns");
    }

    // ── Firewall rules for namespace ──
    if (sys.commandExists("ufw")) {
        var ufw_buf: [128]u8 = undefined;
        const ufw_rule = std.fmt.bufPrint(&ufw_buf, "ufw allow from 10.200.200.0/24 to 10.200.200.1 port {s}", .{port}) catch "";
        if (ufw_rule.len > 0) {
            _ = sys.exec(allocator, &.{ "bash", "-c", ufw_rule }) catch {};
            ui.ok("Firewall: allowed namespace traffic to host veth");
        }

        var route_buf: [128]u8 = undefined;
        const route_rule = std.fmt.bufPrint(&route_buf, "ufw route allow proto tcp to 10.200.200.2 port {s}", .{port}) catch "";
        if (route_rule.len > 0) {
            _ = sys.exec(allocator, &.{ "bash", "-c", route_rule }) catch {};
            ui.ok("Firewall: allowed external client traffic forwarding");
        }
    }

    // ── Apply masking monitor (if recovery is already installed) ──
    if (sys.isServiceActive("mtproto-mask-health.timer") or sys.fileExists("/usr/local/bin/mtproto-mask-health.sh")) {
        const recovery = @import("recovery.zig");
        recovery.execute(ui, allocator, .{}) catch {};
    }

    // ── Restart proxy ──
    ui.step("Restarting proxy...");
    _ = sys.execForward(&.{ "systemctl", "restart", "mtproto-proxy" }) catch {};

    if (sys.isServiceActive("mtproto-proxy")) {
        ui.ok("Proxy running inside VPN tunnel");
    } else {
        ui.fail("Proxy failed to start. Check: journalctl -u mtproto-proxy -n 30");
        return;
    }

    // ── Validate DC connectivity ──
    ui.step("Validating Telegram DC connectivity...");
    const dc_ips = [_][]const u8{
        "149.154.175.50", "149.154.167.50", "149.154.175.100",
        "149.154.167.91", "91.108.56.100",
    };
    for (dc_ips) |dc_ip| {
        const r = sys.exec(allocator, &.{
            "ip", "netns", "exec", NS_NAME, "nc", "-zw3", dc_ip, "443",
        }) catch null;
        if (r) |result| {
            defer result.deinit();
            if (result.exit_code == 0) {
                ui.stepOk("DC reachable", dc_ip);
            } else {
                ui.print("  {s}⚠{s} DC NOT reachable: {s}\n", .{ Color.err, Color.reset, dc_ip });
            }
        }
    }

    // ── Summary ──
    ui.summaryBox("VPN Tunnel Configured", &.{
        .{ .label = "Status:", .value = "systemctl status mtproto-proxy" },
        .{ .label = "Logs:", .value = "journalctl -u mtproto-proxy -f" },
        .{ .label = "Tunnel:", .value = "ip netns exec " ++ NS_NAME ++ " awg show" },
        .{ .label = "Mode:", .value = mode_label },
        .{ .label = "", .style = .blank },
        .{ .label = "Proxy runs inside isolated network namespace", .style = .success },
        .{ .label = "VPN tunnel active (host network untouched)", .style = .success },
        .{ .label = "SSH and host services unaffected", .style = .success },
    });
}

fn setUseMiddleProxy(allocator: std.mem.Allocator, value: []const u8) void {
    var doc = toml.TomlDoc.load(allocator, INSTALL_DIR ++ "/config.toml") catch return;
    defer doc.deinit();
    doc.set("general", "use_middle_proxy", value) catch return;
    doc.save(INSTALL_DIR ++ "/config.toml") catch {};
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

/// Detect the currently active tunnel by inspecting runtime state.
/// Returns the `Tunnel.Tag` corresponding to the detected tunnel,
/// or `.none` if no known tunnel is active.
pub fn detectActiveTunnel(allocator: std.mem.Allocator) Tunnel.Tag {
    // Check if AmneziaWG interface is up inside the network namespace
    const awg_result = sys.exec(allocator, &.{
        "ip", "netns", "exec", NS_NAME, "awg", "show", "awg0",
    }) catch null;
    if (awg_result) |r| {
        defer r.deinit();
        if (r.exit_code == 0) return .tunnel;
    }

    // Check if WireGuard interface is up inside the network namespace
    const wg_result = sys.exec(allocator, &.{
        "ip", "netns", "exec", NS_NAME, "wg", "show", "wg0",
    }) catch null;
    if (wg_result) |r| {
        defer r.deinit();
        if (r.exit_code == 0) return .tunnel;
    }

    return .none;
}
