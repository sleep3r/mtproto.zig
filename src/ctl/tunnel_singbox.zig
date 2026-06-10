//! tunnel_singbox.zig — `mtbuddy setup egress <share-link>...`
//!
//! The sing-box tunnel backend + the share-link egress command. Provisions an upstream
//! egress for the proxy from VPN share-links, dispatching by URI scheme onto the
//! `type = tunnel` egress shape (transparent L3, policy-routed — the same abstraction as
//! AmneziaWG):
//!
//!   wireguard://                         -> native kernel WG/AmneziaWG tunnel (reuses
//!                                           tunnel_wg.zig: policy routing + pool)
//!   vless:// vmess:// trojan:// ss://     -> a local sing-box client in TUN mode (sbx0);
//!                                           the proxy's SO_MARK'd DC traffic is policy-
//!                                           routed through it (fwmark 200 -> table 200 ->
//!                                           sbx0). >1 link -> a sing-box urltest failover
//!                                           pool. VLESS-Reality camouflages the hop as TLS.
//!
//! The proxy relay is unchanged (it just SO_MARKs, as for any tunnel). The two providers
//! are mutually exclusive on table 200 — setting one up retires the other. Share-link
//! parsing lives in sharelink.zig; the native WG bring-up lives in tunnel_wg.zig.

const std = @import("std");
const builtin = @import("builtin");
const sys = @import("sys.zig");
const toml = @import("toml.zig");
const tunnel_wg = @import("tunnel_wg.zig");
const sharelink = @import("sharelink.zig");
const tui_mod = @import("tui.zig");
const Tui = tui_mod.Tui;

// Share-link parsing/transforms live in sharelink.zig; alias them so the bodies below
// (and their existing references) compile unchanged.
const XrayLink = sharelink.XrayLink;
const Scheme = sharelink.Scheme;
const detectScheme = sharelink.detectScheme;
const parseXrayLink = sharelink.parseXrayLink;
const schemeFamily = sharelink.schemeFamily;
const Family = sharelink.Family;
const validateLink = sharelink.validateLink;
const convertWireguardLink = sharelink.convertWireguardLink;

const INSTALL_DIR = "/opt/mtproto-proxy";
const CONFIG_PATH = INSTALL_DIR ++ "/config.toml";
const SB_CONFIG_DIR = "/etc/mtproto-proxy";
const SB_CONFIG_PATH = SB_CONFIG_DIR ++ "/singbox-egress.json";
const SB_SERVICE_NAME = "mtproto-singbox-egress.service";
const SB_SERVICE_PATH = "/etc/systemd/system/" ++ SB_SERVICE_NAME;
const SB_ROUTE_SCRIPT = "/usr/local/bin/mtproto-singbox-route.sh";
const SB_BIN = "/usr/local/bin/sing-box";
const TUN_IFACE = "sbx0"; // sing-box tun interface; mirrors awg0 as a tunnel egress
const TUN_ADDR = "172.19.0.1/30";
const TUN_TABLE = "200"; // same policy-routing table the AmneziaWG tunnel uses
const TUN_FWMARK = "200"; // proxy SO_MARK for tunnel egress

// ── Xray client config generation ───────────────────────────────────────────────

/// JSON-escape + quote a string (returns including the surrounding quotes). Control
/// characters below 0x20 are emitted as \u00XX — a raw control byte (reachable via a
/// percent-decoded link field) would otherwise produce JSON sing-box rejects.
fn js(a: std.mem.Allocator, s: []const u8) []const u8 {
    var buf = a.alloc(u8, s.len * 6 + 2) catch return "\"\"";
    var w: usize = 0;
    buf[w] = '"';
    w += 1;
    const hex = "0123456789abcdef";
    for (s) |c| switch (c) {
        '"', '\\' => {
            buf[w] = '\\';
            buf[w + 1] = c;
            w += 2;
        },
        '\n' => {
            buf[w] = '\\';
            buf[w + 1] = 'n';
            w += 2;
        },
        '\r' => {
            buf[w] = '\\';
            buf[w + 1] = 'r';
            w += 2;
        },
        '\t' => {
            buf[w] = '\\';
            buf[w + 1] = 't';
            w += 2;
        },
        0...8, 11, 12, 14...31 => {
            buf[w + 0] = '\\';
            buf[w + 1] = 'u';
            buf[w + 2] = '0';
            buf[w + 3] = '0';
            buf[w + 4] = hex[c >> 4];
            buf[w + 5] = hex[c & 0xf];
            w += 6;
        },
        else => {
            buf[w] = c;
            w += 1;
        },
    };
    buf[w] = '"';
    w += 1;
    return buf[0..w];
}

fn sbTls(a: std.mem.Allocator, l: XrayLink) ![]const u8 {
    const sni = l.sni orelse l.host orelse l.address;
    const fp = l.fingerprint orelse "chrome";
    if (std.mem.eql(u8, l.security, "reality")) {
        return std.fmt.allocPrint(a, ",\"tls\":{{\"enabled\":true,\"server_name\":{s},\"utls\":{{\"enabled\":true,\"fingerprint\":{s}}},\"reality\":{{\"enabled\":true,\"public_key\":{s},\"short_id\":{s}}}}}", .{ js(a, sni), js(a, fp), js(a, l.public_key orelse ""), js(a, l.short_id orelse "") });
    } else if (std.mem.eql(u8, l.security, "tls")) {
        return std.fmt.allocPrint(a, ",\"tls\":{{\"enabled\":true,\"server_name\":{s},\"utls\":{{\"enabled\":true,\"fingerprint\":{s}}}}}", .{ js(a, sni), js(a, fp) });
    }
    return "";
}

fn sbTransport(a: std.mem.Allocator, l: XrayLink) ![]const u8 {
    const sni = l.sni orelse l.host orelse l.address;
    if (std.mem.eql(u8, l.network, "ws")) {
        return std.fmt.allocPrint(a, ",\"transport\":{{\"type\":\"ws\",\"path\":{s},\"headers\":{{\"Host\":{s}}}}}", .{ js(a, l.path orelse "/"), js(a, l.host orelse sni) });
    } else if (std.mem.eql(u8, l.network, "grpc")) {
        return std.fmt.allocPrint(a, ",\"transport\":{{\"type\":\"grpc\",\"service_name\":{s}}}", .{js(a, l.path orelse "")});
    }
    return "";
}

fn sbOutbound(a: std.mem.Allocator, l: XrayLink, tag: []const u8) ![]const u8 {
    const tls = try sbTls(a, l);
    const tr = try sbTransport(a, l);
    return switch (l.scheme) {
        .vless => blk: {
            const flow = if (l.flow) |f| try std.fmt.allocPrint(a, ",\"flow\":{s}", .{js(a, f)}) else "";
            break :blk std.fmt.allocPrint(a, "{{\"type\":\"vless\",\"tag\":{s},\"server\":{s},\"server_port\":{d},\"uuid\":{s}{s}{s}{s}}}", .{ js(a, tag), js(a, l.address), l.port, js(a, l.id.?), flow, tls, tr });
        },
        .vmess => std.fmt.allocPrint(a, "{{\"type\":\"vmess\",\"tag\":{s},\"server\":{s},\"server_port\":{d},\"uuid\":{s},\"alter_id\":{d},\"security\":{s}{s}{s}}}", .{ js(a, tag), js(a, l.address), l.port, js(a, l.id.?), l.alter_id, js(a, l.cipher), tls, tr }),
        .trojan => std.fmt.allocPrint(a, "{{\"type\":\"trojan\",\"tag\":{s},\"server\":{s},\"server_port\":{d},\"password\":{s}{s}{s}}}", .{ js(a, tag), js(a, l.address), l.port, js(a, l.password.?), tls, tr }),
        .shadowsocks => std.fmt.allocPrint(a, "{{\"type\":\"shadowsocks\",\"tag\":{s},\"server\":{s},\"server_port\":{d},\"method\":{s},\"password\":{s}}}", .{ js(a, tag), js(a, l.address), l.port, js(a, l.method.?), js(a, l.password.?) }),
        else => error.UnsupportedScheme,
    };
}

/// Build a sing-box config: a TUN inbound (`sbx0`; auto_route off — only the proxy's
/// SO_MARK'd traffic is policy-routed into it, so the rest of the host is untouched) and
/// one outbound per link. >1 link adds a `urltest` selector (health-based failover — the
/// analogue of the tunnel pool). VLESS-Reality camouflages the egress hop as real TLS.
pub fn genSingboxConfig(a: std.mem.Allocator, links: []const XrayLink) ![]const u8 {
    var outs: std.ArrayListUnmanaged(u8) = .empty;
    for (links, 0..) |l, i| {
        const tag = try std.fmt.allocPrint(a, "egress-{d}", .{i});
        if (i != 0) try outs.append(a, ',');
        try outs.appendSlice(a, try sbOutbound(a, l, tag));
    }
    var final_tag: []const u8 = "egress-0";
    var selector: []const u8 = "";
    if (links.len > 1) {
        var tags: std.ArrayListUnmanaged(u8) = .empty;
        for (0..links.len) |i| {
            if (i != 0) try tags.append(a, ',');
            try tags.appendSlice(a, try std.fmt.allocPrint(a, "\"egress-{d}\"", .{i}));
        }
        selector = try std.fmt.allocPrint(a, ",{{\"type\":\"urltest\",\"tag\":\"egress\",\"outbounds\":[{s}],\"url\":\"https://www.gstatic.com/generate_204\",\"interval\":\"10s\"}}", .{tags.items});
        final_tag = "egress";
    }
    return std.fmt.allocPrint(a, "{{\"log\":{{\"level\":\"warn\"}},\"inbounds\":[{{\"type\":\"tun\",\"tag\":\"tun-in\",\"interface_name\":\"{s}\",\"address\":[\"{s}\"],\"auto_route\":false,\"stack\":\"system\"}}],\"outbounds\":[{s},{{\"type\":\"direct\",\"tag\":\"direct\"}}{s}],\"route\":{{\"auto_detect_interface\":true,\"final\":\"{s}\"}}}}", .{ TUN_IFACE, TUN_ADDR, outs.items, selector, final_tag });
}

// ── CLI + provisioning ──────────────────────────────────────────────────────────

fn trL(ui: *Tui, en: []const u8, ru: []const u8) []const u8 {
    return if (ui.lang == .ru) ru else en;
}

/// Validate the links are one provider family, then dispatch: wireguard:// -> native WG
/// tunnel, everything else -> the sing-box TUN tunnel. Shared by `run` and `runInteractive`.
fn dispatchLinks(ui: *Tui, allocator: std.mem.Allocator, link_list: []const []const u8) !void {
    // One egress = one provider family. Reject a mix of wireguard:// and Xray links.
    const fam0 = schemeFamily(detectScheme(link_list[0]));
    for (link_list) |l| {
        const s = detectScheme(l);
        if (s == .unknown) {
            ui.fail("Unrecognized share-link scheme (want vless/vmess/trojan/ss/wireguard)");
            return;
        }
        if (schemeFamily(s) != fam0) {
            ui.fail("Don't mix wireguard:// and Xray links in one egress — set them up separately");
            return;
        }
    }
    if (fam0 == .wireguard) {
        return setupWireguard(ui, allocator, link_list);
    }
    return setupSingboxTunnel(ui, allocator, link_list);
}

pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    var links: std.ArrayListUnmanaged([]const u8) = .empty;
    defer links.deinit(allocator);
    var deps_only = false;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--deps-only")) {
            deps_only = true;
            continue;
        }
        if (arg.len > 0 and arg[0] != '-') links.append(allocator, arg) catch {};
    }
    if (deps_only) {
        ui.step("Checking sing-box dependency...");
        if (!ensureSingboxInstalled(ui, allocator)) return;
        ui.ok("sing-box dependency available");
        return;
    }
    if (links.items.len == 0) {
        ui.fail("Usage: mtbuddy setup egress [--deps-only] <share-link> [<share-link>...]");
        ui.hint("vless:// vmess:// trojan:// ss://  ->  sing-box TUN tunnel (upstream.type=tunnel)");
        ui.hint("wireguard://                       ->  native kernel WG tunnel");
        return;
    }
    return dispatchLinks(ui, allocator, links.items);
}

/// Interactive entry: prompt for a share-link (or several, for a failover pool), then run
/// the same dispatch as `run`. Reached from the interactive "Setup tunnel" VPN-type chooser.
pub fn runInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    ui.info(trL(ui, "VPN share-link egress — paste a link. Several links (space/newline/comma-separated) form a failover pool.", "Egress из VPN-ссылки — вставь ссылку. Несколько ссылок (через пробел/перенос/запятую) образуют failover-пул."));
    var buf: [16 * 1024]u8 = undefined;
    const input = ui.input(
        trL(ui, "Share-link(s)", "Ссылка(и)"),
        trL(ui, "vless:// vmess:// trojan:// ss://  (sing-box tunnel)  |  wireguard://  (native tunnel)", "vless:// vmess:// trojan:// ss://  (sing-box-туннель)  |  wireguard://  (нативный туннель)"),
        null,
        &buf,
    ) catch return;

    var links: std.ArrayListUnmanaged([]const u8) = .empty;
    defer links.deinit(allocator);
    var it = std.mem.tokenizeAny(u8, input, " \t\r\n,");
    while (it.next()) |tok| links.append(allocator, tok) catch {};
    if (links.items.len == 0) {
        ui.fail(trL(ui, "No share-link provided.", "Ссылка не введена."));
        return;
    }
    if (!(ui.confirm(trL(ui, "Proceed?", "Продолжить?"), true) catch false)) {
        ui.info(trL(ui, "Aborting.", "Отмена."));
        return;
    }
    return dispatchLinks(ui, allocator, links.items);
}

/// wireguard:// links -> native L3 tunnel. Convert each link to a WG/AmneziaWG .conf
/// (sharelink.zig owns the URI parsing) and hand it to tunnel_wg.zig's existing setup,
/// which brings up the interface + policy routing and, for >1 link, builds the tunnel pool.
fn setupWireguard(ui: *Tui, allocator: std.mem.Allocator, links: []const []const u8) !void {
    for (links, 0..) |link, idx| {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const conf = convertWireguardLink(a, link) catch {
            ui.fail("Failed to parse a wireguard:// link");
            return;
        };
        // Stage the .conf (which contains the WG PRIVATE KEY) in a ROOT-OWNED dir, not
        // world-writable /tmp. writeFileMode follows symlinks and only sets 0600 on create,
        // so a predictable /tmp/mtbuddy-wg-<idx>.conf let a local user pre-create a symlink
        // and have root's write land on an arbitrary file (CWE-59 overwrite-as-root). /etc
        // and /etc/amnezia are root-owned, so no unprivileged user can plant a symlink here.
        _ = sys.exec(allocator, &.{ "mkdir", "-p", "/etc/amnezia" }) catch {};
        const tmp = try std.fmt.allocPrint(a, "/etc/amnezia/.mtbuddy-stage-{d}.conf", .{idx});
        sys.writeFileMode(tmp, conf, 0o600) catch {
            ui.fail("Failed to stage the WireGuard config");
            return;
        };
        try tunnel_wg.setupFromConf(ui, allocator, tmp);
        _ = sys.exec(allocator, &.{ "rm", "-f", tmp }) catch {};
    }
}

fn setupSingboxTunnel(ui: *Tui, allocator: std.mem.Allocator, link_texts: []const []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = try a.alloc(XrayLink, link_texts.len);
    for (link_texts, 0..) |t, i| {
        parsed[i] = parseXrayLink(a, t) catch {
            ui.fail("Failed to parse a share-link");
            return;
        };
        var vbuf: [256]u8 = undefined;
        if (validateLink(parsed[i], &vbuf)) |msg| {
            ui.fail(msg);
            return;
        }
        ui.stepOk("Parsed egress", parsed[i].address);
    }

    // A sing-box tunnel and the AmneziaWG tunnel pool both own fwmark 200 / table 200 —
    // the pool's 30s timer does `ip route flush table 200` and would silently steal the
    // route from sbx0. They must be mutually exclusive, so retire any existing pool first.
    if (sys.fileExists("/etc/systemd/system/mtproto-tunnel-pool.timer")) {
        ui.warn("Retiring the existing AmneziaWG tunnel pool — it can't share table 200 with the sing-box egress.");
        _ = sys.exec(allocator, &.{ "systemctl", "disable", "--now", "mtproto-tunnel-pool.timer" }) catch {};
        _ = sys.exec(allocator, &.{ "systemctl", "stop", "mtproto-tunnel-pool.service" }) catch {};
        _ = sys.exec(allocator, &.{ "rm", "-f", "/etc/systemd/system/mtproto-tunnel-pool.timer", "/etc/systemd/system/mtproto-tunnel-pool.service", "/usr/local/bin/setup_tunnel.sh", "/run/mtproto-proxy/tunnel-pool.state" }) catch {};
        _ = sys.exec(allocator, &.{ "systemctl", "daemon-reload" }) catch {};
    }

    if (!ensureSingboxInstalled(ui, allocator)) return;
    const sb_bin: []const u8 = if (sys.fileExists(SB_BIN)) SB_BIN else "sing-box";

    const cfg = genSingboxConfig(a, parsed) catch {
        ui.fail("Failed to generate sing-box config");
        return;
    };
    _ = sys.exec(allocator, &.{ "mkdir", "-p", SB_CONFIG_DIR }) catch {};
    sys.writeFileMode(SB_CONFIG_PATH, cfg, 0o600) catch {
        ui.fail("Failed to write " ++ SB_CONFIG_PATH);
        return;
    };

    // Policy-routing helper: wait for the tun, then route the proxy's SO_MARK'd egress
    // (fwmark 200 → table 200 → sbx0) — the same mechanism the AmneziaWG tunnel uses.
    const route_script = "#!/bin/bash\n" ++
        "for i in $(seq 1 60); do ip link show " ++ TUN_IFACE ++ " >/dev/null 2>&1 && break; sleep 0.25; done\n" ++
        "ip link show " ++ TUN_IFACE ++ " >/dev/null 2>&1 || { echo 'mtproto egress: " ++ TUN_IFACE ++ " never appeared (sing-box failed to start the tun?)' >&2; exit 1; }\n" ++
        "ip rule add fwmark " ++ TUN_FWMARK ++ " lookup " ++ TUN_TABLE ++ " 2>/dev/null || true\n" ++
        "ip route replace default dev " ++ TUN_IFACE ++ " table " ++ TUN_TABLE ++ "\n";
    sys.writeFileMode(SB_ROUTE_SCRIPT, route_script, 0o755) catch {
        ui.fail("Failed to write the routing helper");
        return;
    };

    const unit = try std.fmt.allocPrint(a,
        \\[Unit]
        \\Description=mtproto-proxy sing-box tunnel egress
        \\After=network-online.target
        \\Wants=network-online.target
        \\
        \\[Service]
        \\ExecStart={s} run -c {s}
        \\ExecStartPost=+{s}
        \\Restart=on-failure
        \\RestartSec=3
        \\AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
        \\
        \\[Install]
        \\WantedBy=multi-user.target
        \\
    , .{ sb_bin, SB_CONFIG_PATH, SB_ROUTE_SCRIPT });
    sys.writeFile(SB_SERVICE_PATH, unit) catch {
        ui.fail("Failed to write the systemd unit");
        return;
    };
    _ = sys.exec(allocator, &.{ "systemctl", "daemon-reload" }) catch {};
    _ = sys.exec(allocator, &.{ "systemctl", "enable", "--now", SB_SERVICE_NAME }) catch {};
    ui.ok("sing-box tunnel egress up (tun " ++ TUN_IFACE ++ ")");

    if (sys.fileExists(CONFIG_PATH)) {
        // Order mtproto-proxy after the egress so sbx0 + its route exist before the proxy
        // marks DC sockets — otherwise a reboot races and DC connects fail until retry.
        _ = sys.exec(allocator, &.{ "mkdir", "-p", "/etc/systemd/system/mtproto-proxy.service.d" }) catch {};
        sys.writeFile("/etc/systemd/system/mtproto-proxy.service.d/egress.conf", "[Unit]\nAfter=" ++ SB_SERVICE_NAME ++ "\nWants=" ++ SB_SERVICE_NAME ++ "\n") catch {};
        _ = sys.exec(allocator, &.{ "systemctl", "daemon-reload" }) catch {};
        wireUpstreamTunnel(allocator, link_texts) catch {
            ui.warn("tunnel is up, but updating config.toml failed — set [upstream] type=tunnel, [upstream.tunnel] interface=" ++ TUN_IFACE ++ " manually");
            return;
        };
        _ = sys.exec(allocator, &.{ "systemctl", "restart", "mtproto-proxy" }) catch {};
        ui.ok("upstream set to tunnel via " ++ TUN_IFACE ++ "; mtproto-proxy restarted");
    } else {
        ui.warn("mtproto-proxy not installed here — the sing-box tunnel is up on " ++ TUN_IFACE ++ "; set [upstream] type=tunnel, [upstream.tunnel] interface=" ++ TUN_IFACE);
    }
}

fn wireUpstreamTunnel(allocator: std.mem.Allocator, link_texts: []const []const u8) !void {
    var doc = try toml.TomlDoc.load(allocator, CONFIG_PATH);
    defer doc.deinit();
    try doc.set("upstream", "type", "tunnel");
    // Point both the plural pool list (which the proxy reads first) and the singular key
    // at sbx0, and clear any pinned awg interface, so no stale awg name shadows sbx0.
    try doc.set("upstream.tunnel", "interfaces", "[\"" ++ TUN_IFACE ++ "\"]");
    try doc.set("upstream.tunnel", "pinned_interface", "");
    try doc.set("upstream.tunnel", "interface", TUN_IFACE);
    // Persist the links so a reinstall reproduces the egress (config is 0600).
    var arr: std.ArrayListUnmanaged(u8) = .empty;
    defer arr.deinit(allocator);
    try arr.append(allocator, '[');
    for (link_texts, 0..) |t, i| {
        if (i != 0) try arr.append(allocator, ',');
        try arr.append(allocator, '"');
        try arr.appendSlice(allocator, t);
        try arr.append(allocator, '"');
    }
    try arr.append(allocator, ']');
    try doc.set("upstream.xray", "links", arr.items);
    try doc.save(CONFIG_PATH);
}

fn ensureSingboxInstalled(ui: *Tui, allocator: std.mem.Allocator) bool {
    if (sys.commandExists("sing-box") or sys.fileExists(SB_BIN)) return true;

    ui.step("Installing sing-box...");
    if (!installSingbox(allocator)) {
        ui.fail("Failed to install sing-box (download/extract). Check network and retry.");
        return false;
    }
    ui.ok("sing-box installed");
    return true;
}

/// Download + install the static sing-box binary for this arch. The release asset name
/// carries the version, so resolve the latest tag from the API first. Private temp dir.
fn installSingbox(allocator: std.mem.Allocator) bool {
    const arch: []const u8 = switch (builtin.cpu.arch) {
        .x86_64 => "amd64",
        .aarch64 => "arm64",
        else => return false,
    };
    if (!sys.commandExists("curl") or !sys.commandExists("tar")) {
        _ = sys.exec(allocator, &.{ "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", "DPkg::Lock::Timeout=600", "update", "-qq" }) catch {};
        _ = sys.exec(allocator, &.{ "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "--no-install-recommends", "curl", "tar" }) catch {};
    }
    const ver = blk: {
        const r = sys.exec(allocator, &.{ "curl", "-fsSL", "--connect-timeout", "30", "https://api.github.com/repos/SagerNet/sing-box/releases/latest" }) catch return false;
        defer r.deinit();
        if (r.exit_code != 0) break :blk null;
        // Tolerate whitespace + the optional leading 'v': `"tag_name": "v1.13.13"`.
        const key = "\"tag_name\"";
        const ki = std.mem.indexOf(u8, r.stdout, key) orelse break :blk null;
        const after = r.stdout[ki + key.len ..];
        const q1 = std.mem.indexOfScalar(u8, after, '"') orelse break :blk null;
        var vstart = q1 + 1;
        if (vstart < after.len and after[vstart] == 'v') vstart += 1;
        const q2 = std.mem.indexOfScalarPos(u8, after, vstart, '"') orelse break :blk null;
        break :blk allocator.dupe(u8, after[vstart..q2]) catch null;
    } orelse return false;
    defer allocator.free(ver);
    const td = blk: {
        const r = sys.exec(allocator, &.{ "mktemp", "-d", "/tmp/mtbuddy-singbox.XXXXXX" }) catch return false;
        defer r.deinit();
        if (r.exit_code != 0) break :blk null;
        const t = std.mem.trim(u8, r.stdout, " \t\r\n");
        if (t.len == 0) break :blk null;
        break :blk allocator.dupe(u8, t) catch null;
    } orelse return false;
    defer {
        _ = sys.exec(allocator, &.{ "rm", "-rf", td }) catch {};
        allocator.free(td);
    }
    const url = std.fmt.allocPrint(allocator, "https://github.com/SagerNet/sing-box/releases/download/v{s}/sing-box-{s}-linux-{s}.tar.gz", .{ ver, ver, arch }) catch return false;
    defer allocator.free(url);
    const tgz = std.fmt.allocPrint(allocator, "{s}/sb.tar.gz", .{td}) catch return false;
    defer allocator.free(tgz);
    {
        const r = sys.exec(allocator, &.{ "curl", "-fsSL", "--retry", "3", "--connect-timeout", "30", "-o", tgz, url }) catch return false;
        defer r.deinit();
        if (r.exit_code != 0) return false;
    }
    {
        const r = sys.exec(allocator, &.{ "tar", "xzf", tgz, "-C", td, "--no-same-owner" }) catch return false;
        defer r.deinit();
        if (r.exit_code != 0) return false;
    }
    const extracted = std.fmt.allocPrint(allocator, "{s}/sing-box-{s}-linux-{s}/sing-box", .{ td, ver, arch }) catch return false;
    defer allocator.free(extracted);
    // Verify the downloaded artifact actually runs as sing-box before installing it. The
    // transport is TLS (authenticity); this catches a corrupt/truncated download or a
    // wrong-arch binary. sing-box publishes no checksums/signatures to verify against.
    {
        const r = sys.exec(allocator, &.{ extracted, "version" }) catch return false;
        defer r.deinit();
        if (r.exit_code != 0 or std.mem.indexOf(u8, r.stdout, "sing-box") == null) return false;
    }
    {
        const r = sys.exec(allocator, &.{ "install", "-m", "0755", extracted, SB_BIN }) catch return false;
        defer r.deinit();
        if (r.exit_code != 0) return false;
    }
    return sys.fileExists(SB_BIN);
}

test "genSingboxConfig is valid JSON; urltest only for a pool" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const vless = try parseXrayLink(a, "vless://95e0edb9-4a0b-4312-a71f-1d4b8b6db79b@154.59.110.32:443?type=tcp&security=reality&pbk=PBK&sni=www.microsoft.com&sid=SID&flow=xtls-rprx-vision#v");
    const ss = try parseXrayLink(a, "ss://YWVzLTI1Ni1nY206ZzdaR000c0JwNUZ1elBndktRZ1lnQQ==@154.59.110.32:9443#s");

    const one = try genSingboxConfig(a, &.{vless});
    _ = try std.json.parseFromSlice(std.json.Value, a, one, .{}); // well-formed JSON
    try std.testing.expect(std.mem.indexOf(u8, one, "\"reality\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, one, "\"type\":\"tun\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, one, "\"sbx0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, one, "xtls-rprx-vision") != null);
    try std.testing.expect(std.mem.indexOf(u8, one, "\"urltest\"") == null);

    const pool = try genSingboxConfig(a, &.{ vless, ss });
    _ = try std.json.parseFromSlice(std.json.Value, a, pool, .{});
    try std.testing.expect(std.mem.indexOf(u8, pool, "\"urltest\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pool, "egress-0") != null);
    try std.testing.expect(std.mem.indexOf(u8, pool, "egress-1") != null);
    try std.testing.expect(std.mem.indexOf(u8, pool, "shadowsocks") != null);
}

test "vmess scy maps to cipher and is emitted" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json = "{\"v\":\"2\",\"ps\":\"x\",\"add\":\"1.2.3.4\",\"port\":\"443\",\"id\":\"95e0edb9-4a0b-4312-a71f-1d4b8b6db79b\",\"aid\":\"0\",\"net\":\"tcp\",\"scy\":\"zero\",\"tls\":\"\"}";
    var b64: [512]u8 = undefined;
    const enc = std.base64.standard.Encoder.encode(&b64, json);
    const link = try std.fmt.allocPrint(a, "vmess://{s}", .{enc});
    const l = try parseXrayLink(a, link);
    try std.testing.expectEqualStrings("zero", l.cipher);
    const cfg = try genSingboxConfig(a, &.{l});
    try std.testing.expect(std.mem.indexOf(u8, cfg, "\"security\":\"zero\"") != null);
}
