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
//!   hysteria2:// (hy2://)                    the proxy's SO_MARK'd DC traffic is policy-
//!                                           routed through it (fwmark 200 -> table 200 ->
//!                                           sbx0). >1 link -> a sing-box urltest failover
//!                                           pool. VLESS-Reality camouflages the hop as TLS.
//!
//! hysteria2 is QUIC, i.e. the ONLY scheme here whose egress leg is UDP. That matters on
//! the hosts this command exists for: providers that block the Telegram DCs commonly also
//! police UDP hard (measured: WireGuard capped near 1.5 Mbit/s on any port), and the
//! failure looks like a healthy tunnel moving no bytes. Measure the path before choosing
//! it. Note also that its headline congestion control (Brutal) needs a bandwidth the
//! share-link grammar deliberately does not carry, so a link-provisioned hysteria2 egress
//! runs BBR — the same algorithm the TCP schemes already get.
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
/// Where a generated config waits while `sing-box check` judges it — see setupSingboxTunnel.
const SB_CANDIDATE_PATH = SB_CONFIG_PATH ++ ".new";
const SB_SERVICE_NAME = "mtproto-singbox-egress.service";
const SB_SERVICE_PATH = "/etc/systemd/system/" ++ SB_SERVICE_NAME;
const SB_ROUTE_SCRIPT = "/usr/local/bin/mtproto-singbox-route.sh";
const SB_BIN = "/usr/local/bin/sing-box";
const TUN_IFACE = "sbx0"; // sing-box tun interface; mirrors awg0 as a tunnel egress
/// /32, NOT /30 — a one-bit difference that decides whether the host can resolve DNS.
///
/// sing-tun's NativeTun.start() calls setSearchDomainForSystemdResolved() unconditionally
/// (tun_linux.go:357 — the only AutoRoute guard next to it is Android-only, so
/// auto_route:false does not stop it). With no explicit DNS servers it synthesises one:
///
///     if len(t.options.Inet4Address) > 0 && HasNextAddress(t.options.Inet4Address[0], 1) {
///         dnsServer = append(dnsServer, t.options.Inet4Address[0].Addr().Next())
///     }
///     if len(dnsServer) == 0 { return }
///     go func() { resolvectl domain <tun> "~."; resolvectl default-route <tun> true;
///                 resolvectl dns <tun> <dnsServer> }()
///
/// Under /30 the next address (172.19.0.2) is inside the prefix, so it becomes sbx0's DNS
/// server — and `~.` is a route-only domain matching every name, which outranks eth0's
/// scope in resolved, so EVERY query goes to 172.19.0.2:53 where nothing listens. Total
/// DNS failure on any host that has resolvectl and systemd-resolved. Under /32 the next
/// address is outside the prefix, there is no Inet6Address, so dnsServer stays empty and
/// the function returns before running a single resolvectl command.
///
/// The knob that would disable it directly (EXP_DisableDNSHijack) is library-only and has
/// no JSON tag, so the address IS the lever. Reverting it afterwards from the route helper
/// would race the detached goroutine above.
///
/// Nothing here needs the /30: auto_route is off so sing-tun adds no routes and never
/// consults the gateway address, and our default route is installed by SB_ROUTE_SCRIPT as
/// a `dev sbx0` route, which takes no nexthop.
const TUN_ADDR = "172.19.0.1/32";
/// An unset `mtu` leaves a Linux TUN at 65535 (sing-box protocol/tun/inbound.go; 9000 is
/// the Android branch, and was the global default only through v1.11.x). This is NOT an
/// on-wire size — with a TUN inbound sing-box terminates the TCP flow in its own netstack
/// and re-dials the outbound on an ordinary kernel socket, so nothing here is
/// encapsulated and no headroom for the outer TLS transport is involved. It is the
/// kernel<->netstack framing size, i.e. the MSS the local kernel negotiates on a DC
/// connection routed via sbx0. Leave it at the default and the handshake and DC connect
/// (small) sail through while every bulk transfer is silently dropped: the egress comes
/// up "healthy" and then moves 0 B/s, which reads as a dead upstream rather than a
/// link-layer problem. Measured on a live host, `"stack": "gvisor"` + `"mtu": 1400` is
/// the pair that actually passes bulk traffic, so they ship together.
///
/// The pair is also what turns on sing-box's TUN GSO offload, which the default misses:
///   enableGSO := C.IsLinux && options.Stack == "gvisor" && platformInterface == nil &&
///                tunMTU > 0 && tunMTU < 49152
/// and upstream's own tun_bench has gvisor at or above the system stack at every MTU, so
/// the stack choice costs no throughput.
///
/// Both values are pinned by a test: sing-box validates `stack` only at Start(), so
/// `sing-box check` exits 0 on a bogus one and a typo would ship silently.
const TUN_MTU = "1400";
const TUN_STACK = "gvisor";

/// Drop-in laid over mtproto-proxy.service once the sing-box egress is up.
///
/// `After=`/`Wants=` keep sbx0 and its route present before the proxy starts marking DC
/// sockets, so a reboot does not race into failing DC connects.
///
/// The empty `ExecStartPre=` resets the list, dropping the AmneziaWG unit's
/// `ExecStartPre=+/usr/local/bin/setup_tunnel.sh`. That line is left behind on any host
/// that ran `setup tunnel` first, and it breaks two different ways:
///   * the pool-retire path in `setupSingbox` deletes setup_tunnel.sh, so systemd fails
///     the unit with 203/EXEC and restart-loops a proxy that is otherwise healthy;
///   * a single-tunnel host keeps the script, which then re-points table 200 at awg0 on
///     every proxy start and steals the route from sbx0.
/// sbx0's own routing is installed by the sing-box unit's ExecStartPost, and the default
/// (non-tunnel) unit has no ExecStartPre at all, so the reset is a no-op everywhere else.
/// CAP_NET_ADMIN is the other half, and without it `setup egress` produces a proxy that
/// accepts clients and fails EVERY DC connection. Wiring the egress sets
/// `[upstream] type = tunnel`, so the proxy starts SO_MARKing its DC sockets — and
/// SO_MARK needs CAP_NET_ADMIN. Only the AmneziaWG unit ever granted it, so a host that
/// went straight to `setup egress` without ever running `setup tunnel` ran under the
/// default unit's CAP_NET_BIND_SERVICE alone and every connect failed with EPERM
/// ("upstream connect start failed"), while setup still printed "egress up". Reproduced
/// and fixed on a live host. systemd MERGES these two directives across drop-ins, so the
/// unit's own CAP_NET_BIND_SERVICE is kept rather than replaced.
///
/// It lives in the drop-in because that is what survives: a hand-added line is wiped by
/// the next `setup egress`.
const PROXY_EGRESS_DROPIN = "[Unit]\nAfter=" ++ SB_SERVICE_NAME ++ "\nWants=" ++ SB_SERVICE_NAME ++ "\n" ++
    "\n[Service]\nExecStartPre=\n" ++
    "AmbientCapabilities=CAP_NET_ADMIN\nCapabilityBoundingSet=CAP_NET_ADMIN\n";
const TUN_TABLE = "200"; // same policy-routing table the AmneziaWG tunnel uses
const TUN_FWMARK = "200"; // proxy SO_MARK for tunnel egress

/// Policy-routing helper: the sing-box unit runs it after start (`ExecStartPost`) and,
/// with `down`, after stop (`ExecStopPost`).
///
/// It fails CLOSED, and that is the whole point of the blackhole. A policy rule that
/// matches but resolves nothing does NOT drop the packet — the kernel walks on to the next
/// rule — so an EMPTY table 200 sends the proxy's SO_MARK'd DC sockets out of the host's
/// real uplink: the origin the egress exists to hide, leaked with no log line, no metric
/// and no user-visible symptom. sbx0's route is `dev`-bound, so the kernel purges it the
/// instant sing-box stops or crashes. The blackhole is therefore installed BEFORE we wait
/// for the tun and restored when the unit stops; `ip route replace default dev sbx0`
/// simply overwrites it while the tun is up. The AmneziaWG pool script fails closed the
/// same way (tunnel_wg.zig, "Fail CLOSED").
const SB_ROUTE_SCRIPT_BODY = "#!/bin/bash\n" ++
    "blackhole() {\n" ++
    "    ip route replace blackhole default table " ++ TUN_TABLE ++ " 2>/dev/null || true\n" ++
    "    ip -6 route replace blackhole default table " ++ TUN_TABLE ++ " 2>/dev/null || true\n" ++
    "}\n" ++
    // `down` only restores the blackhole: re-adding the rule on every stop would stack
    // duplicate `fwmark 200 lookup 200` entries for the life of the boot.
    "if [ \"${1:-up}\" = \"down\" ]; then blackhole; exit 0; fi\n" ++
    "for family in -4 -6; do\n" ++
    "  while ip $family rule del fwmark " ++ TUN_FWMARK ++ " lookup " ++ TUN_TABLE ++ " 2>/dev/null; do :; done\n" ++
    "  ip $family rule add fwmark " ++ TUN_FWMARK ++ " lookup " ++ TUN_TABLE ++ " || exit 1\n" ++
    "done\n" ++
    "blackhole\n" ++
    "for i in $(seq 1 60); do ip link show " ++ TUN_IFACE ++ " >/dev/null 2>&1 && break; sleep 0.25; done\n" ++
    "ip link show " ++ TUN_IFACE ++ " >/dev/null 2>&1 || { echo 'mtproto egress: " ++ TUN_IFACE ++ " never appeared (sing-box failed to start the tun?)' >&2; exit 1; }\n" ++
    "ip route replace default dev " ++ TUN_IFACE ++ " table " ++ TUN_TABLE ++ "\n";

/// The sing-box unit. Rendered rather than a const because ExecStart names the binary we
/// actually found; `refreshFailClosedRouting` re-renders it to add the ExecStopPost that a
/// pre-fail-closed host is missing.
fn renderEgressUnit(a: std.mem.Allocator, sb_bin: []const u8) ![]const u8 {
    if (!std.fs.path.isAbsolute(sb_bin)) return error.InvalidBinaryPath;
    return std.fmt.allocPrint(a,
        \\[Unit]
        \\Description=mtproto-proxy sing-box tunnel egress
        \\After=network-online.target
        \\Wants=network-online.target
        \\
        \\[Service]
        \\ExecStart={s} run -c {s}
        \\ExecStartPost=+{s}
        \\ExecStopPost=+{s} down
        \\Restart=on-failure
        \\RestartSec=3
        \\AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
        \\
        \\[Install]
        \\WantedBy=multi-user.target
        \\
    , .{ sb_bin, SB_CONFIG_PATH, SB_ROUTE_SCRIPT, SB_ROUTE_SCRIPT });
}

fn sleepSeconds(seconds: u64) void {
    const req: std.posix.timespec = .{ .sec = @intCast(seconds), .nsec = 0 };
    _ = std.os.linux.nanosleep(&req, null);
}

// ── Xray client config generation ───────────────────────────────────────────────

/// JSON-escape + quote a string (returns including the surrounding quotes). Control
/// characters below 0x20 are emitted as \u00XX — a raw control byte (reachable via a
/// percent-decoded link field) would otherwise produce JSON sing-box rejects.
fn js(a: std.mem.Allocator, s: []const u8) ![]const u8 {
    if (!std.unicode.utf8ValidateSlice(s)) return error.InvalidUtf8;
    var buf = try a.alloc(u8, s.len * 6 + 2);
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

test "egress generation rejects missing links and invalid JSON text" {
    try std.testing.expectError(error.NoLinks, genSingboxConfig(std.testing.allocator, &.{}));
    try std.testing.expectError(error.InvalidUtf8, js(std.testing.allocator, "\xff"));
}

test "endpoint comparison distinguishes port prefixes" {
    try std.testing.expect(!sameEgressEndpoints("{\"server\":\"host\",\"server_port\":44,\"uuid\":\"x\"}", "{\"server\":\"host\",\"server_port\":443,\"uuid\":\"x\"}"));
}

fn sbTls(a: std.mem.Allocator, l: XrayLink) ![]const u8 {
    const sni = l.sni orelse l.host orelse l.address;
    const fp = l.fingerprint orelse "chrome";
    if (std.mem.eql(u8, l.security, "reality")) {
        return std.fmt.allocPrint(a, ",\"tls\":{{\"enabled\":true,\"server_name\":{s},\"utls\":{{\"enabled\":true,\"fingerprint\":{s}}},\"reality\":{{\"enabled\":true,\"public_key\":{s},\"short_id\":{s}}}}}", .{ try js(a, sni), try js(a, fp), try js(a, l.public_key orelse ""), try js(a, l.short_id orelse "") });
    } else if (std.mem.eql(u8, l.security, "tls")) {
        // `allowInsecure=1` rides through as sing-box's `insecure`, and ONLY when the link
        // asked for it. Dropped, a self-signed 3x-ui endpoint got an outbound that verifies
        // strictly: `sing-box check` passes, the unit starts, and every dial dies on x509.
        const insecure = if (l.insecure) ",\"insecure\":true" else "";
        return std.fmt.allocPrint(a, ",\"tls\":{{\"enabled\":true,\"server_name\":{s}{s},\"utls\":{{\"enabled\":true,\"fingerprint\":{s}}}}}", .{ try js(a, sni), insecure, try js(a, fp) });
    }
    return "";
}

/// TLS block for hysteria2. Separate from sbTls on purpose, and the separation is
/// load-bearing twice over:
///   * a hy2 link carries no `security=` param, so l.security would leave sbTls returning
///     "" — and sing-box's hysteria2 outbound refuses to load without TLS at all;
///   * both of sbTls's branches emit `"utls"`, which cannot work over QUIC — sing-box's
///     uTLS client has no STDConfig, so sing-quic fails every connection with
///     "unsupported usage for uTLS". And `sing-box check` PASSES, the unit starts, the
///     ok line prints: a green deploy on a 100%-dead egress.
/// A test pins the absence of "utls" so a future refactor cannot merge these back.
fn sbTlsHy2(a: std.mem.Allocator, l: XrayLink) ![]const u8 {
    const sni = l.sni orelse l.address;
    return std.fmt.allocPrint(
        a,
        ",\"tls\":{{\"enabled\":true,\"server_name\":{s},\"insecure\":{s}}}",
        .{ try js(a, sni), if (l.insecure) "true" else "false" },
    );
}

fn sbTransport(a: std.mem.Allocator, l: XrayLink) ![]const u8 {
    const sni = l.sni orelse l.host orelse l.address;
    if (std.mem.eql(u8, l.network, "ws")) {
        return std.fmt.allocPrint(a, ",\"transport\":{{\"type\":\"ws\",\"path\":{s},\"headers\":{{\"Host\":{s}}}}}", .{ try js(a, l.path orelse "/"), try js(a, l.host orelse sni) });
    } else if (std.mem.eql(u8, l.network, "grpc")) {
        return std.fmt.allocPrint(a, ",\"transport\":{{\"type\":\"grpc\",\"service_name\":{s}}}", .{try js(a, l.path orelse "")});
    }
    return "";
}

fn sbOutbound(a: std.mem.Allocator, l: XrayLink, tag: []const u8) ![]const u8 {
    // The Xray-family TLS/transport blocks. The hysteria2 arm below uses neither — it
    // builds its own TLS and has no transport concept.
    const uses_xray_transport = l.scheme == .vless or l.scheme == .vmess or l.scheme == .trojan;
    const tls = if (uses_xray_transport) try sbTls(a, l) else "";
    const tr = if (uses_xray_transport) try sbTransport(a, l) else "";
    return switch (l.scheme) {
        .vless => blk: {
            const flow = if (l.flow) |f| try std.fmt.allocPrint(a, ",\"flow\":{s}", .{try js(a, f)}) else "";
            break :blk std.fmt.allocPrint(a, "{{\"type\":\"vless\",\"tag\":{s},\"server\":{s},\"server_port\":{d},\"uuid\":{s}{s}{s}{s}}}", .{ try js(a, tag), try js(a, l.address), l.port, try js(a, l.id.?), flow, tls, tr });
        },
        .vmess => std.fmt.allocPrint(a, "{{\"type\":\"vmess\",\"tag\":{s},\"server\":{s},\"server_port\":{d},\"uuid\":{s},\"alter_id\":{d},\"security\":{s}{s}{s}}}", .{ try js(a, tag), try js(a, l.address), l.port, try js(a, l.id.?), l.alter_id, try js(a, l.cipher), tls, tr }),
        .trojan => std.fmt.allocPrint(a, "{{\"type\":\"trojan\",\"tag\":{s},\"server\":{s},\"server_port\":{d},\"password\":{s}{s}{s}}}", .{ try js(a, tag), try js(a, l.address), l.port, try js(a, l.password.?), tls, tr }),
        .shadowsocks => std.fmt.allocPrint(a, "{{\"type\":\"shadowsocks\",\"tag\":{s},\"server\":{s},\"server_port\":{d},\"method\":{s},\"password\":{s}}}", .{ try js(a, tag), try js(a, l.address), l.port, try js(a, l.method.?), try js(a, l.password.?) }),
        .hysteria2 => blk: {
            // No `tr`: hysteria2 is QUIC end to end, it has no ws/grpc transport to carry.
            const hy_tls = try sbTlsHy2(a, l);
            const pw = if (l.password) |p| try std.fmt.allocPrint(a, ",\"password\":{s}", .{try js(a, p)}) else "";
            const obfs = if (l.obfs) |o|
                try std.fmt.allocPrint(a, ",\"obfs\":{{\"type\":{s},\"password\":{s}}}", .{ try js(a, o), try js(a, l.obfs_password orelse "") })
            else
                "";
            break :blk std.fmt.allocPrint(a, "{{\"type\":\"hysteria2\",\"tag\":{s},\"server\":{s},\"server_port\":{d}{s}{s}{s}}}", .{ try js(a, tag), try js(a, l.address), l.port, pw, obfs, hy_tls });
        },
        else => error.UnsupportedScheme,
    };
}

/// Build a sing-box config: a TUN inbound (`sbx0`; auto_route off — only the proxy's
/// SO_MARK'd traffic is policy-routed into it, so the rest of the host is untouched) and
/// one outbound per link. >1 link adds a `urltest` selector (health-based failover — the
/// analogue of the tunnel pool). VLESS-Reality camouflages the egress hop as real TLS.
pub fn genSingboxConfig(a: std.mem.Allocator, links: []const XrayLink) ![]const u8 {
    if (links.len == 0) return error.NoLinks;
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
        selector = try std.fmt.allocPrint(a, ",{{\"type\":\"urltest\",\"tag\":\"egress\",\"outbounds\":[{s}],\"url\":\"https://www.gstatic.com/generate_204\",\"interval\":\"60s\",\"tolerance\":50}}", .{tags.items});
        final_tag = "egress";
    }
    return std.fmt.allocPrint(a, "{{\"log\":{{\"level\":\"warn\"}},\"inbounds\":[{{\"type\":\"tun\",\"tag\":\"tun-in\",\"interface_name\":\"{s}\",\"address\":[\"{s}\"],\"auto_route\":false,\"stack\":\"{s}\",\"mtu\":{s}}}],\"outbounds\":[{s},{{\"type\":\"direct\",\"tag\":\"direct\"}}{s}],\"route\":{{\"auto_detect_interface\":true,\"final\":\"{s}\"}}}}", .{ TUN_IFACE, TUN_ADDR, TUN_STACK, TUN_MTU, outs.items, selector, final_tag });
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
        // Before anything else: the pasted text is recorded verbatim in the root-owned
        // config.toml (`[upstream.xray] links`), so a newline in it injects TOML the proxy
        // then honours — e.g. an extra [access.users] entry. See sharelink.linkTextIsSafe.
        if (!sharelink.linkTextIsSafe(l)) {
            ui.fail("Refusing a share-link containing a newline, control byte or quote — it would inject config into config.toml");
            return;
        }
        const s = detectScheme(l);
        if (s == .unknown) {
            ui.fail("Unrecognized share-link scheme (want vless/vmess/trojan/ss/hysteria2/wireguard)");
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
        if (arg.len > 0 and arg[0] != '-') {
            try links.append(allocator, arg);
        } else {
            return error.UnknownOption;
        }
    }
    if (deps_only) {
        ui.step("Checking sing-box dependency...");
        if (!ensureSingboxInstalled(ui, allocator)) return;
        ui.ok("sing-box dependency available");
        return;
    }
    if (links.items.len == 0) {
        ui.fail("Usage: mtbuddy setup egress [--deps-only] <share-link> [<share-link>...]");
        ui.hint("vless:// vmess:// trojan:// ss:// hysteria2://  ->  sing-box TUN tunnel (upstream.type=tunnel)");
        ui.hint("wireguard://                       ->  native kernel WG tunnel");
        return;
    }
    return dispatchLinks(ui, allocator, links.items);
}

/// Interactive entry: prompt for a share-link (or several, for a failover pool), then run
/// the same dispatch as `run`. Reached from the interactive "Setup tunnel" VPN-type chooser.
pub fn runInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    // Header names the chosen type so this reads consistently with the Amnezia create flow.
    ui.section(trL(ui, "3x-ui", "3x-ui"));
    ui.info(trL(ui, "Paste a share-link. Several links (space/newline/comma-separated) form a failover pool.", "Вставь ссылку. Несколько ссылок (через пробел/перенос/запятую) образуют failover-пул."));

    var buf: [16 * 1024]u8 = undefined;
    var links: std.ArrayListUnmanaged([]const u8) = .empty;
    defer links.deinit(allocator);

    var step: usize = 0;
    while (true) switch (step) {
        0 => {
            const input = ui.input(
                trL(ui, "Share-link(s)", "Ссылка(и)"),
                trL(ui, "vless:// vmess:// trojan:// ss:// hysteria2://  (sing-box tunnel)  |  wireguard://  (native tunnel)", "vless:// vmess:// trojan:// ss:// hysteria2://  (sing-box-туннель)  |  wireguard://  (нативный туннель)"),
                null,
                &buf,
            ) catch |e| {
                if (e == error.GoBack) return error.GoBack; // back to the type choice
                return; // EOF / no input — abort
            };
            links.clearRetainingCapacity();
            var it = std.mem.tokenizeAny(u8, input, " \t\r\n,");
            while (it.next()) |tok| links.append(allocator, tok) catch {};
            if (links.items.len == 0) {
                ui.fail(trL(ui, "No share-link provided.", "Ссылка не введена."));
                continue; // re-prompt
            }
            step = 1;
        },
        1 => {
            const ok = ui.confirm(trL(ui, "Proceed?", "Продолжить?"), true) catch |e| {
                if (e == error.GoBack) {
                    step = 0;
                    continue; // step back to the link prompt
                }
                return;
            };
            if (!ok) {
                ui.info(trL(ui, "Aborting.", "Отмена."));
                return;
            }
            step = 2;
        },
        else => return dispatchLinks(ui, allocator, links.items),
    };
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
        try std.Io.Dir.cwd().createDirPath(std.Io.Threaded.global_single_threaded.io(), "/etc/amnezia");
        const tmp = try std.fmt.allocPrint(a, "/etc/amnezia/.mtbuddy-stage-{d}.conf", .{idx});
        sys.writeFileMode(tmp, conf, 0o600) catch {
            ui.fail("Failed to stage the WireGuard config");
            return;
        };
        defer std.Io.Dir.deleteFileAbsolute(std.Io.Threaded.global_single_threaded.io(), tmp) catch {
            ui.warn("Failed to remove staged WireGuard credentials");
        };
        try tunnel_wg.setupFromConf(ui, allocator, tmp);
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
        if (parsed[i].insecure) {
            // Faithful to the link, but never silent: the egress hop is then unauthenticated.
            ui.warn("Certificate verification is DISABLED for this endpoint (the link carries allowInsecure=1)");
        }
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
    const sb_bin = resolveSingboxBinary(allocator) catch {
        ui.fail("Unable to resolve an absolute sing-box executable path");
        return;
    };
    defer allocator.free(sb_bin);

    const cfg = genSingboxConfig(a, parsed) catch {
        ui.fail("Failed to generate sing-box config");
        return;
    };
    try std.Io.Dir.cwd().createDirPath(std.Io.Threaded.global_single_threaded.io(), SB_CONFIG_DIR);

    // Check the CANDIDATE, then rename it into place. Writing first and checking after
    // destroyed a working config the moment this sing-box rejected the new one: the
    // running egress kept serving from memory, so nothing looked broken until the next
    // reboot, when the unit failed, sbx0 never appeared and table 200 stayed empty.
    sys.writeFileMode(SB_CANDIDATE_PATH, cfg, 0o600) catch {
        ui.fail("Failed to write " ++ SB_CANDIDATE_PATH);
        return;
    };
    if (!singboxConfigLoads(allocator, sb_bin, SB_CANDIDATE_PATH)) {
        ui.fail("The installed sing-box rejects the generated config — the egress was NOT started");
        ui.info("The rejected config is at " ++ SB_CANDIDATE_PATH ++ " (the running one is untouched); run it through `sing-box check -c` for the reason. An outbound type this build does not know (hysteria2 needs sing-box 1.5.0+) rejects the whole file, including the other endpoints in a pool.");
        return;
    }
    var installed_config = false;
    if (sys.exec(allocator, &.{ "mv", "-f", SB_CANDIDATE_PATH, SB_CONFIG_PATH })) |r| {
        defer r.deinit();
        installed_config = r.exit_code == 0;
    } else |_| {}
    if (!installed_config) {
        ui.fail("Failed to install " ++ SB_CONFIG_PATH);
        return;
    }

    sys.writeFileMode(SB_ROUTE_SCRIPT, SB_ROUTE_SCRIPT_BODY, 0o755) catch {
        ui.fail("Failed to write the routing helper");
        return;
    };

    const unit = try renderEgressUnit(a, sb_bin);
    sys.writeFile(SB_SERVICE_PATH, unit) catch {
        ui.fail("Failed to write the systemd unit");
        return;
    };
    _ = sys.exec(allocator, &.{ "systemctl", "daemon-reload" }) catch {};
    var start_ok = false;
    if (sys.exec(allocator, &.{ "systemctl", "enable", "--now", SB_SERVICE_NAME })) |r| {
        defer r.deinit();
        start_ok = r.exit_code == 0;
    } else |_| {}
    if (!start_ok or !egressTunIsUp(allocator)) {
        // Never rewire the proxy onto an egress that did not come up: `sing-box check`
        // validates the config's SHAPE only, and the run reported "egress up" while every
        // DC connection failed.
        ui.fail("sing-box egress did not come up — the proxy was NOT rewired to it");
        ui.hint("journalctl -u " ++ SB_SERVICE_NAME ++ " -n 50 --no-pager");
        ui.info("Usual causes: no /dev/net/tun (LXC/OpenVZ container), no CAP_NET_ADMIN, or an option sing-box only validates at Start().");
        return;
    }
    ui.ok("sing-box tunnel egress up (tun " ++ TUN_IFACE ++ ")");
    ui.info(trL(
        ui,
        "If the egress ever stops, marked traffic is dropped, not sent out the host's real IP — DC connections fail loudly instead of silently leaking the origin.",
        "Если egress остановится, помеченный трафик будет отброшен, а не выпущен через реальный IP хоста — соединения с DC упадут, но origin не утечёт.",
    ));

    if (sys.fileExists(CONFIG_PATH)) {
        // Order mtproto-proxy after the egress so sbx0 + its route exist before the proxy
        // marks DC sockets — otherwise a reboot races and DC connects fail until retry.
        try std.Io.Dir.cwd().createDirPath(std.Io.Threaded.global_single_threaded.io(), PROXY_DROPIN_DIR);
        sys.writeFile(PROXY_DROPIN_PATH, PROXY_EGRESS_DROPIN) catch {};
        _ = sys.exec(allocator, &.{ "systemctl", "daemon-reload" }) catch {};
        wireUpstreamTunnel(allocator, link_texts) catch {
            ui.warn("tunnel is up, but updating config.toml failed — set [upstream] type=tunnel, [upstream.tunnel] interface=" ++ TUN_IFACE ++ " manually");
            return;
        };
        _ = sys.exec(allocator, &.{ "systemctl", "restart", "mtproto-proxy" }) catch {};
        if (sys.isServiceActive("mtproto-proxy")) {
            ui.ok("upstream set to tunnel via " ++ TUN_IFACE ++ "; mtproto-proxy restarted");
        } else {
            ui.fail("config.toml was updated but mtproto-proxy did not come back");
            ui.hint("journalctl -u mtproto-proxy -n 30 --no-pager");
        }
        warnMiddleProxyOverTun(ui, allocator);
    } else {
        ui.warn("mtproto-proxy not installed here — the sing-box tunnel is up on " ++ TUN_IFACE ++ "; set [upstream] type=tunnel, [upstream.tunnel] interface=" ++ TUN_IFACE);
    }
}

/// Did the egress actually come up? A zero exit from `enable --now` does not say so: the
/// unit is Type=simple, so systemd is satisfied once sing-box has been exec'd and its
/// ExecStartPost returned, and a sing-box that dies at Start() (no /dev/net/tun in an LXC
/// container, an option only validated at Start()) leaves a fully green run over a proxy
/// about to be rewired onto an egress that does not exist. Ask the two questions that do
/// answer it — the unit is still active, and sbx0 is present — with a few seconds of grace
/// for a process that exits a moment after being started.
fn egressTunIsUp(allocator: std.mem.Allocator) bool {
    var attempt: usize = 0;
    while (attempt < 5) : (attempt += 1) {
        if (attempt > 0) sleepSeconds(1);
        if (!sys.isServiceActive(SB_SERVICE_NAME)) continue;
        const r = sys.exec(allocator, &.{ "ip", "link", "show", TUN_IFACE }) catch continue;
        defer r.deinit();
        if (r.exit_code == 0) return true;
    }
    return false;
}

/// A sing-box TUN egress and MiddleProxy do not work together, and the failure is silent
/// where it matters: every connection still works, it just loses the ad-tag and ME media.
///
/// Measured on a live host — 3 clients, `use_middle_proxy = true`:
///   upstream = tunnel  ->  middleproxy_fallback_total 3 / 3
///   upstream = direct  ->  middleproxy_fallback_total 0 / 3
/// The RPC_NONCE exchange succeeds and the middle proxy then drops the connection at
/// `waiting_rpc_handshake_response`. That is the documented signature of an egress which
/// rewrites the source PORT (see [server].middle_proxy_nat_ip): sing-box terminates the
/// proxy's TCP in its netstack and re-dials on its own socket, so the port Telegram
/// observes is not the one the handshake announced. `middle_proxy_nat_ip` fixes the
/// address half; there is no port equivalent, and there cannot be one.
///
/// The runtime already warns once connections start falling back ("ad-tag likely
/// inactive"), but by then the operator has left the terminal. Say it while they are
/// still here.
fn warnMiddleProxyOverTun(ui: *Tui, allocator: std.mem.Allocator) void {
    var doc = toml.TomlDoc.load(allocator, CONFIG_PATH) catch return;
    defer doc.deinit();
    const v = doc.get("general", "use_middle_proxy") orelse return;
    if (!(std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "1") or std.ascii.eqlIgnoreCase(v, "yes"))) return;

    ui.warn(trL(
        ui,
        "[general] use_middle_proxy = true, but a sing-box TUN egress breaks the MiddleProxy handshake.",
        "[general] use_middle_proxy = true, но sing-box TUN-egress ломает хендшейк MiddleProxy.",
    ));
    ui.info(trL(
        ui,
        "Every connection will fall back to a direct DC path: it still works, but carries no ad-tag and no MiddleProxy media (photos/videos/stories for non-Premium users).",
        "Все соединения будут откатываться на прямой путь к DC: связь работает, но без ad-tag и без медиа через MiddleProxy (фото/видео/истории у не-Premium).",
    ));
    ui.info(trL(
        ui,
        "The egress re-dials on its own socket, so the source port Telegram sees is not the one the handshake announced — [server].middle_proxy_nat_ip fixes the address, not the port. Use a native WireGuard/AmneziaWG tunnel, or set use_middle_proxy = false.",
        "Egress передиаливает своим сокетом, поэтому Telegram видит не тот source-порт, который объявлен в хендшейке — [server].middle_proxy_nat_ip чинит адрес, но не порт. Используйте нативный WireGuard/AmneziaWG-туннель или выставьте use_middle_proxy = false.",
    ));
}

fn wireUpstreamTunnel(allocator: std.mem.Allocator, link_texts: []const []const u8) !void {
    var doc = try toml.TomlDoc.load(allocator, CONFIG_PATH);
    defer doc.deinit();
    try doc.setString("upstream", "type", "tunnel");
    // Point both the plural pool list (which the proxy reads first) and the singular key
    // at sbx0, and clear any pinned awg interface, so no stale awg name shadows sbx0.
    try doc.set("upstream.tunnel", "interfaces", "[\"" ++ TUN_IFACE ++ "\"]");
    try doc.setString("upstream.tunnel", "pinned_interface", "");
    try doc.setString("upstream.tunnel", "interface", TUN_IFACE);
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

const PROXY_DROPIN_DIR = "/etc/systemd/system/mtproto-proxy.service.d";
const PROXY_DROPIN_PATH = PROXY_DROPIN_DIR ++ "/egress.conf";

/// Split a TOML string-array value (`["a","b"]`) into its elements, as slices INTO
/// `value`. Deliberately forgiving rather than a real TOML array parser: the only value
/// it reads is `[upstream.xray] links`, which wireUpstreamTunnel writes itself as plain
/// quoted share links with no escaping, so nothing fancier can be in there.
fn parseTomlStringArray(a: std.mem.Allocator, value: []const u8) ![]const []const u8 {
    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer out.deinit(a);

    var i: usize = 0;
    while (i < value.len) {
        const open = std.mem.indexOfScalarPos(u8, value, i, '"') orelse break;
        const close = std.mem.indexOfScalarPos(u8, value, open + 1, '"') orelse break;
        if (close > open + 1) try out.append(a, value[open + 1 .. close]);
        i = close + 1;
    }
    return out.toOwnedSlice(a);
}

const SB_SERVER_KEY = "\"server\":\"";
const SB_PORT_KEY = "\"server_port\":";

/// The `"server":"H","server_port":N` descriptor `sbOutbound` emits, spanning from
/// `start` to the end of the port digits. Returns null when the pair is malformed.
fn egressEndpointAt(cfg: []const u8, start: usize) ?[]const u8 {
    const port_at = std.mem.indexOfPos(u8, cfg, start + SB_SERVER_KEY.len, SB_PORT_KEY) orelse return null;
    var end = port_at + SB_PORT_KEY.len;
    while (end < cfg.len and std.ascii.isDigit(cfg[end])) end += 1;
    if (end == port_at + SB_PORT_KEY.len) return null;
    if (end == cfg.len or (cfg[end] != ',' and cfg[end] != '}')) return null;
    return cfg[start .. end + 1];
}

fn countEgressEndpoints(cfg: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, cfg, i, SB_SERVER_KEY)) |at| : (n += 1) {
        i = at + SB_SERVER_KEY.len;
    }
    return n;
}

/// Do `existing` and `cfg` describe the same set of egress endpoints?
///
/// `[upstream.xray] links` is a best-effort RECORD, not the source of truth:
/// setupSingboxTunnel writes singbox-egress.json and starts the egress BEFORE it updates
/// config.toml, and a failure there is a warning, not a rollback. So a host can genuinely
/// be running endpoints the recorded links no longer mention — growing a single-endpoint
/// egress into a pool used to do exactly that, because the old formatKv ceiling aborted
/// the config.toml write once the link array passed 512 bytes.
///
/// Regenerating blindly there would swap a live pool for a dead endpoint, restart into
/// it, and report success. So repair only what we can prove is the same egress: every
/// endpoint currently configured must survive into the new config, and the count must
/// match so nothing is added either. Both sides come from the same generator, so an
/// in-sync host compares equal by construction.
fn sameEgressEndpoints(existing: []const u8, cfg: []const u8) bool {
    if (countEgressEndpoints(existing) != countEgressEndpoints(cfg)) return false;

    var i: usize = 0;
    while (std.mem.indexOfPos(u8, existing, i, SB_SERVER_KEY)) |at| {
        const descriptor = egressEndpointAt(existing, at) orelse return false;
        if (std.mem.indexOf(u8, cfg, descriptor) == null) return false;
        i = at + descriptor.len;
    }
    return true;
}

/// Does this sing-box config already carry the repaired TUN shape?
fn singboxConfigIsCurrent(cfg: []const u8) bool {
    return std.mem.indexOf(u8, cfg, "\"" ++ TUN_ADDR ++ "\"") != null and
        std.mem.indexOf(u8, cfg, "\"stack\":\"" ++ TUN_STACK ++ "\"") != null and
        std.mem.indexOf(u8, cfg, "\"mtu\":" ++ TUN_MTU) != null;
}

fn egressManualHint(ui: *Tui) void {
    ui.warn(trL(
        ui,
        "The sing-box egress predates the TUN fixes and could not be regenerated automatically.",
        "sing-box egress создан до починки TUN, и перегенерировать его автоматически не вышло.",
    ));
    ui.info(trL(
        ui,
        // -F, because in a POSIX regex `[upstream.xray]` is a bracket EXPRESSION: it
        // matches one character from that set, so `^[upstream.xray]` never matches the
        // section header and does match `user1 = "<secret>"` — printing secrets instead
        // of links.
        "Re-run: mtbuddy setup egress '<share-link>' [...]  (recover the links with: grep -A2 -F '[upstream.xray]' " ++ CONFIG_PATH ++ ")",
        "Запустите заново: mtbuddy setup egress '<share-link>' [...]  (ссылки можно достать: grep -A2 -F '[upstream.xray]' " ++ CONFIG_PATH ++ ")",
    ));
}

/// Repair an egress provisioned before the TUN fixes, in place — the `mtbuddy update`
/// counterpart of install.refreshTcpmssLoopbackExclusion / nfqws.refreshLoopbackExclusion.
///
/// The files `setup egress` writes are created once, at setup time, and an ordinary
/// update regenerates none of them. Without this an upgraded host keeps the /30 address
/// (whose next address sing-tun hands to systemd-resolved as sbx0's DNS server, killing
/// all resolution), the system stack and the default MTU (every bulk transfer dropped
/// while the egress reports itself up), and the orphaned
/// `ExecStartPre=+/usr/local/bin/setup_tunnel.sh` that restart-loops the proxy with
/// 203/EXEC — until somebody happens to re-run `setup egress` by hand.
///
/// No-op when no egress is configured, and no-op again once repaired.
pub fn refreshEgress(ui: *Tui, allocator: std.mem.Allocator) void {
    if (!sys.fileExists(SB_SERVICE_PATH)) return;
    refreshProxyDropin(ui, allocator);
    refreshFailClosedRouting(ui, allocator);
    refreshSingboxConfig(ui, allocator);
}

/// Repair an egress provisioned before the routing failed closed. Its helper only ever
/// installed `default dev sbx0`, so the moment sing-box stopped, table 200 went empty, the
/// fwmark rule fell through to `main` and every SO_MARK'd DC socket left via the host's
/// real uplink. Both halves (the helper and the unit's ExecStopPost) take effect on the
/// next start/stop, so nothing is restarted here.
fn refreshFailClosedRouting(ui: *Tui, allocator: std.mem.Allocator) void {
    const script = sys.readFileAllocAbsolute(allocator, SB_ROUTE_SCRIPT, 64 * 1024) orelse return;
    defer allocator.free(script);
    const unit = sys.readFileAllocAbsolute(allocator, SB_SERVICE_PATH, 64 * 1024) orelse return;
    defer allocator.free(unit);

    const script_current = std.mem.eql(u8, script, SB_ROUTE_SCRIPT_BODY);
    const unit_current = std.mem.indexOf(u8, unit, "ExecStopPost=") != null;
    if (script_current and unit_current) return;

    if (!script_current) {
        sys.writeFileMode(SB_ROUTE_SCRIPT, SB_ROUTE_SCRIPT_BODY, 0o755) catch return;
    }
    if (!unit_current) {
        const sb_bin = resolveSingboxBinary(allocator) catch return;
        defer allocator.free(sb_bin);
        const rendered = renderEgressUnit(allocator, sb_bin) catch return;
        defer allocator.free(rendered);
        sys.writeFile(SB_SERVICE_PATH, rendered) catch return;
        _ = sys.exec(allocator, &.{ "systemctl", "daemon-reload" }) catch {};
    }
    ui.ok(trL(
        ui,
        "egress routing now fails closed — a stopped tunnel drops marked traffic instead of leaking the host's real IP",
        "маршрутизация egress теперь fail-closed — остановленный туннель отбрасывает помеченный трафик, а не выпускает его с реального IP хоста",
    ));
}

/// Repairs an EXISTING drop-in only. A host whose egress predates this never had the
/// ordering either, and quietly adding an After=/Wants= to a unit during an update is a
/// bigger step than clearing a line that is actively breaking it.
fn refreshProxyDropin(ui: *Tui, allocator: std.mem.Allocator) void {
    const existing = sys.readFileAllocAbsolute(allocator, PROXY_DROPIN_PATH, 16 * 1024) orelse return;
    defer allocator.free(existing);
    // Content comparison, not a marker search: the drop-in has grown twice now (the
    // ExecStartPre reset, then CAP_NET_ADMIN), and a marker check would have skipped a
    // host that already had the first and still needed the second.
    if (std.mem.eql(u8, existing, PROXY_EGRESS_DROPIN)) return;

    sys.writeFile(PROXY_DROPIN_PATH, PROXY_EGRESS_DROPIN) catch return;
    _ = sys.exec(allocator, &.{ "systemctl", "daemon-reload" }) catch {};
    ui.ok(trL(
        ui,
        "egress drop-in no longer runs a stale tunnel helper",
        "egress drop-in больше не запускает устаревший tunnel-хелпер",
    ));
}

fn refreshSingboxConfig(ui: *Tui, allocator: std.mem.Allocator) void {
    const existing = sys.readFileAllocAbsolute(allocator, SB_CONFIG_PATH, 1024 * 1024) orelse return;
    defer allocator.free(existing);
    if (singboxConfigIsCurrent(existing)) return;

    // The share links wireUpstreamTunnel recorded are the only way to rebuild the
    // outbounds. Anything missing or unparseable here means we cannot regenerate
    // faithfully — say so and change nothing rather than write a config that drops
    // somebody's egress.
    var doc = toml.TomlDoc.load(allocator, CONFIG_PATH) catch {
        egressManualHint(ui);
        return;
    };
    defer doc.deinit();
    const raw = doc.get("upstream.xray", "links") orelse {
        egressManualHint(ui);
        return;
    };

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const texts = parseTomlStringArray(a, raw) catch {
        egressManualHint(ui);
        return;
    };
    if (texts.len == 0) {
        egressManualHint(ui);
        return;
    }

    const parsed = a.alloc(XrayLink, texts.len) catch return;
    for (texts, 0..) |t, i| {
        parsed[i] = parseXrayLink(a, t) catch {
            egressManualHint(ui);
            return;
        };
        var vbuf: [256]u8 = undefined;
        if (validateLink(parsed[i], &vbuf) != null) {
            egressManualHint(ui);
            return;
        }
    }

    const cfg = genSingboxConfig(a, parsed) catch {
        egressManualHint(ui);
        return;
    };

    if (!sameEgressEndpoints(existing, cfg)) {
        ui.warn(trL(
            ui,
            "The sing-box egress is running endpoints that [upstream.xray] links no longer describes — leaving it alone.",
            "sing-box egress работает на эндпоинтах, которых уже нет в [upstream.xray] links — не трогаю его.",
        ));
        egressManualHint(ui);
        return;
    }

    // Keep the file we are about to replace. The endpoints match, so this should never be
    // needed — but it is one copy of the only on-disk record of a working egress.
    sys.writeFileMode(SB_CONFIG_PATH ++ ".bak", existing, 0o600) catch {
        ui.warn("Failed to back up sing-box credentials; repair aborted");
        return;
    };

    sys.writeFileMode(SB_CONFIG_PATH, cfg, 0o600) catch {
        egressManualHint(ui);
        return;
    };

    // Never restart into a config this sing-box cannot load: put the old one back first.
    const sb_bin = resolveSingboxBinary(allocator) catch return;
    defer allocator.free(sb_bin);
    if (!singboxConfigLoads(allocator, sb_bin, SB_CONFIG_PATH)) {
        sys.writeFileMode(SB_CONFIG_PATH, existing, 0o600) catch {
            ui.fail("Failed to restore sing-box config from backup");
            return;
        };
        ui.warn(trL(
            ui,
            "The installed sing-box rejects the repaired egress config — restored the previous one and left the egress running.",
            "Установленный sing-box не принимает починенный конфиг egress — вернул прежний, egress работает как работал.",
        ));
        return;
    }

    // A restart, not `enable --now`: sing-box parses its config only at startup, and
    // `--now` is a no-op on a unit that is already running — which is exactly the host
    // this repair exists for.
    _ = sys.execForward(&.{ "systemctl", "restart", SB_SERVICE_NAME }) catch {};
    if (!sys.isServiceActive(SB_SERVICE_NAME)) {
        ui.fail("sing-box restart failed; the previous credentials remain in the .bak file for recovery");
        return;
    }
    std.Io.Dir.deleteFileAbsolute(std.Io.Threaded.global_single_threaded.io(), SB_CONFIG_PATH ++ ".bak") catch {
        ui.warn("Failed to remove the sing-box credentials backup");
    };
    ui.ok(trL(
        ui,
        "sing-box egress tun repaired (" ++ TUN_ADDR ++ ", stack " ++ TUN_STACK ++ ", mtu " ++ TUN_MTU ++ ")",
        "sing-box egress tun починен (" ++ TUN_ADDR ++ ", stack " ++ TUN_STACK ++ ", mtu " ++ TUN_MTU ++ ")",
    ));
}

/// `sing-box check -c <path>`: does the installed binary accept this config at all?
///
/// The reason this exists is version skew. ensureSingboxInstalled keeps whatever sing-box
/// is already on the host, and an outbound type it does not know — hysteria2 needs 1.5.0+
/// — makes it reject the WHOLE config, taking any co-configured vless/trojan outbound
/// down with it. Without the probe that lands as "egress up" plus a dead unit.
///
/// Returns true when the check passes OR could not be run at all: a missing//unrunnable
/// binary is ensureSingboxInstalled's problem, and failing closed on it would refuse
/// configs that are perfectly fine.
fn singboxConfigLoads(allocator: std.mem.Allocator, sb_bin: []const u8, path: []const u8) bool {
    const r = sys.exec(allocator, &.{ sb_bin, "check", "-c", path }) catch return true;
    defer r.deinit();
    return r.exit_code == 0;
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

fn resolveSingboxBinary(allocator: std.mem.Allocator) ![]u8 {
    if (sys.fileExists(SB_BIN)) return allocator.dupe(u8, SB_BIN);
    const result = try sys.exec(allocator, &.{ "sh", "-c", "command -v sing-box" });
    defer result.deinit();
    const path = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (result.exit_code != 0 or !std.fs.path.isAbsolute(path) or std.mem.indexOfAny(u8, path, " \t\r\n\"%") != null) return error.InvalidBinaryPath;
    return allocator.dupe(u8, path);
}

/// Download + install the static sing-box binary for this arch. The release asset name
/// and SHA-256 digest are pinned; extraction uses a private temporary directory.
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
    // Official release asset digests: https://api.github.com/repos/SagerNet/sing-box/releases/tags/v1.13.13
    const ver = "1.13.13";
    const expected_sha256 = if (std.mem.eql(u8, arch, "amd64"))
        "bb99cabf47694625db421ee17898f36cdc1f9c2cb5decf65b12bac8d8437e842"
    else
        "d7fab87b921933eb281d8ee7bd5377cdd8228089f1f7c807c9363a6a2329286c";
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
        const r = sys.exec(allocator, &.{ "sha256sum", tgz }) catch return false;
        defer r.deinit();
        if (r.exit_code != 0 or r.stdout.len < 64 or !std.mem.eql(u8, r.stdout[0..64], expected_sha256)) return false;
    }
    {
        const r = sys.exec(allocator, &.{ "tar", "xzf", tgz, "-C", td, "--no-same-owner" }) catch return false;
        defer r.deinit();
        if (r.exit_code != 0) return false;
    }
    const extracted = std.fmt.allocPrint(allocator, "{s}/sing-box-{s}-linux-{s}/sing-box", .{ td, ver, arch }) catch return false;
    defer allocator.free(extracted);
    // The archive hash is pinned above and checked before extraction or execution.
    // Verify that the authenticated binary also runs on this host.
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
    // The TUN must carry an explicit MTU and the gvisor stack, and a /32 address. An
    // unset mtu leaves a Linux TUN at 65535, which passes handshakes and drops every bulk
    // transfer — an egress that looks up and moves 0 B/s. A /30 makes sing-tun hand
    // 172.19.0.2 to systemd-resolved as sbx0's DNS server and kills all resolution. See
    // the TUN_ADDR / TUN_MTU doc comments; pin all three so none can regress silently.
    try std.testing.expect(std.mem.indexOf(u8, one, "\"172.19.0.1/32\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, one, "/30") == null);
    try std.testing.expect(std.mem.indexOf(u8, one, "\"mtu\":1400") != null);
    try std.testing.expect(std.mem.indexOf(u8, one, "\"stack\":\"gvisor\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, one, "\"stack\":\"system\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, one, "xtls-rprx-vision") != null);
    try std.testing.expect(std.mem.indexOf(u8, one, "\"urltest\"") == null);

    const pool = try genSingboxConfig(a, &.{ vless, ss });
    _ = try std.json.parseFromSlice(std.json.Value, a, pool, .{});
    try std.testing.expect(std.mem.indexOf(u8, pool, "\"urltest\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pool, "egress-0") != null);
    try std.testing.expect(std.mem.indexOf(u8, pool, "egress-1") != null);
    try std.testing.expect(std.mem.indexOf(u8, pool, "shadowsocks") != null);
}

test "the egress drop-in resets ExecStartPre so a stale tunnel helper can't break the proxy" {
    // A host that ran `setup tunnel` before `setup egress` carries
    // `ExecStartPre=+/usr/local/bin/setup_tunnel.sh` in mtproto-proxy.service. The
    // pool-retire path deletes that script (203/EXEC restart loop), and where it
    // survives it re-points table 200 at awg0 and steals the route from sbx0.
    try std.testing.expect(std.mem.indexOf(u8, PROXY_EGRESS_DROPIN, "[Service]") != null);
    try std.testing.expect(std.mem.indexOf(u8, PROXY_EGRESS_DROPIN, "\nExecStartPre=\n") != null);
    // Empty, not repointed: the sing-box unit's ExecStartPost owns sbx0's routing.
    try std.testing.expect(std.mem.indexOf(u8, PROXY_EGRESS_DROPIN, "setup_tunnel.sh") == null);
    // And it still orders the proxy after the egress, which is why the drop-in exists.
    try std.testing.expect(std.mem.indexOf(u8, PROXY_EGRESS_DROPIN, "After=" ++ SB_SERVICE_NAME) != null);
    try std.testing.expect(std.mem.indexOf(u8, PROXY_EGRESS_DROPIN, "Wants=" ++ SB_SERVICE_NAME) != null);

    // And it grants CAP_NET_ADMIN. Wiring the egress sets [upstream] type = tunnel, so
    // the proxy SO_MARKs its DC sockets — which needs that capability. Without it a host
    // that never ran `setup tunnel` runs under the default unit (CAP_NET_BIND_SERVICE
    // only) and EVERY DC connect fails with EPERM while setup reports success.
    // Verified on a live host: adding it turned "upstream connect start failed" into a
    // relaying connection.
    try std.testing.expect(std.mem.indexOf(u8, PROXY_EGRESS_DROPIN, "AmbientCapabilities=CAP_NET_ADMIN") != null);
    try std.testing.expect(std.mem.indexOf(u8, PROXY_EGRESS_DROPIN, "CapabilityBoundingSet=CAP_NET_ADMIN") != null);
}

test "egress auto-repair: detects a stale config and accepts a freshly generated one" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const vless = try parseXrayLink(a, "vless://95e0edb9-4a0b-4312-a71f-1d4b8b6db79b@154.59.110.32:443?type=tcp&security=reality&pbk=PBK&sni=www.microsoft.com&sid=SID&flow=xtls-rprx-vision#v");
    const fresh = try genSingboxConfig(a, &.{vless});
    try std.testing.expect(singboxConfigIsCurrent(fresh));

    // What `setup egress` wrote before v1.12.0: /30 address, system stack, no mtu. Each
    // of the three defects on its own must be enough to trigger a regeneration, or a
    // partially-repaired host is left in place.
    const legacy = "{\"inbounds\":[{\"type\":\"tun\",\"interface_name\":\"sbx0\",\"address\":[\"172.19.0.1/30\"],\"auto_route\":false,\"stack\":\"system\"}]}";
    try std.testing.expect(!singboxConfigIsCurrent(legacy));

    const only_addr_stale = "{\"address\":[\"172.19.0.1/30\"],\"stack\":\"gvisor\",\"mtu\":1400}";
    try std.testing.expect(!singboxConfigIsCurrent(only_addr_stale));

    const only_stack_stale = "{\"address\":[\"172.19.0.1/32\"],\"stack\":\"system\",\"mtu\":1400}";
    try std.testing.expect(!singboxConfigIsCurrent(only_stack_stale));

    const only_mtu_missing = "{\"address\":[\"172.19.0.1/32\"],\"stack\":\"gvisor\"}";
    try std.testing.expect(!singboxConfigIsCurrent(only_mtu_missing));
}

test "egress auto-repair: refuses to regenerate when the recorded links moved on" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const A = try parseXrayLink(a, "vless://95e0edb9-4a0b-4312-a71f-1d4b8b6db79b@154.59.110.32:443?type=tcp&security=reality&pbk=P&sni=s.example&sid=S&flow=xtls-rprx-vision#A");
    const B = try parseXrayLink(a, "vless://95e0edb9-4a0b-4312-a71f-1d4b8b6db79b@198.51.100.7:443?type=tcp&security=reality&pbk=P&sni=s.example&sid=S&flow=xtls-rprx-vision#B");
    const C = try parseXrayLink(a, "ss://YWVzLTI1Ni1nY206ZzdaR000c0JwNUZ1elBndktRZ1lnQQ==@203.0.113.9:9443#C");

    const only_a = try genSingboxConfig(a, &.{A});
    const pool_bc = try genSingboxConfig(a, &.{ B, C });

    // Same egress, regenerated: every endpoint survives, so the repair may proceed.
    try std.testing.expect(sameEgressEndpoints(only_a, try genSingboxConfig(a, &.{A})));
    try std.testing.expect(sameEgressEndpoints(pool_bc, try genSingboxConfig(a, &.{ B, C })));

    // The dangerous case: config.toml still records A while the host actually runs B+C
    // (setup egress writes the JSON and starts the egress BEFORE updating config.toml,
    // and that write used to abort on a long link array). Regenerating from A would
    // replace a live pool with one dead endpoint.
    try std.testing.expect(!sameEgressEndpoints(pool_bc, only_a));

    // And the other direction: never quietly ADD endpoints the host was not running.
    try std.testing.expect(!sameEgressEndpoints(only_a, try genSingboxConfig(a, &.{ A, B })));

    // Same count, different host — a bare count check would let this through.
    try std.testing.expect(!sameEgressEndpoints(only_a, try genSingboxConfig(a, &.{B})));

    // A legacy (pre-1.12.0) config compares by endpoint, not by TUN shape: the outbound
    // JSON is byte-identical across the TUN fix, so an in-sync host still matches.
    const legacy_a = "{\"inbounds\":[{\"type\":\"tun\",\"address\":[\"172.19.0.1/30\"],\"stack\":\"system\"}]," ++
        "\"outbounds\":[{\"type\":\"vless\",\"tag\":\"egress-0\",\"server\":\"154.59.110.32\",\"server_port\":443,\"uuid\":\"u\"}]}";
    try std.testing.expect(!singboxConfigIsCurrent(legacy_a));
    try std.testing.expect(sameEgressEndpoints(legacy_a, only_a));
    try std.testing.expect(!sameEgressEndpoints(legacy_a, pool_bc));
}

test "egress auto-repair: reads the share links back out of [upstream.xray]" {
    const a = std.testing.allocator;

    // Exactly what wireUpstreamTunnel writes, as TomlDoc.get hands it back.
    const one = try parseTomlStringArray(a, "[\"vless://a@1.2.3.4:443#x\"]");
    defer a.free(one);
    try std.testing.expectEqual(@as(usize, 1), one.len);
    try std.testing.expectEqualStrings("vless://a@1.2.3.4:443#x", one[0]);

    const pool = try parseTomlStringArray(a, "[\"vless://a@1.2.3.4:443#x\",\"ss://b@5.6.7.8:9443#y\"]");
    defer a.free(pool);
    try std.testing.expectEqual(@as(usize, 2), pool.len);
    try std.testing.expectEqualStrings("ss://b@5.6.7.8:9443#y", pool[1]);

    // Whitespace the operator may have introduced by hand, and the empty forms: an empty
    // list must come back empty so the caller falls through to the manual hint rather
    // than regenerating an outbound-less config.
    const spaced = try parseTomlStringArray(a, "[ \"vless://a@1.2.3.4:443\" , \"trojan://c@9.9.9.9:443\" ]");
    defer a.free(spaced);
    try std.testing.expectEqual(@as(usize, 2), spaced.len);

    const empty = try parseTomlStringArray(a, "[]");
    defer a.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);

    const blank_entry = try parseTomlStringArray(a, "[\"\"]");
    defer a.free(blank_entry);
    try std.testing.expectEqual(@as(usize, 0), blank_entry.len);
}

test "hysteria2: real-world link shapes parse, and the config is QUIC-correct" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Exactly what `hysteria share` emits: a trailing '/' before the query. The Xray
    // parser ran parseInt over "40443/" and failed the whole link.
    const canonical = try parseXrayLink(a, "hysteria2://letmein@example.com:40443/?sni=cover.example&obfs=salamander&obfs-password=cats#EU");
    try std.testing.expectEqual(Scheme.hysteria2, canonical.scheme);
    try std.testing.expectEqualStrings("example.com", canonical.address);
    try std.testing.expectEqual(@as(u16, 40443), canonical.port);
    try std.testing.expectEqualStrings("letmein", canonical.password.?);
    try std.testing.expectEqualStrings("cover.example", canonical.sni.?);
    try std.testing.expectEqualStrings("salamander", canonical.obfs.?);
    try std.testing.expectEqualStrings("cats", canonical.obfs_password.?);
    try std.testing.expectEqualStrings("EU", canonical.name);

    // Auth is optional, and so is the port (443).
    const bare = try parseXrayLink(a, "hy2://example.com");
    try std.testing.expectEqualStrings("example.com", bare.address);
    try std.testing.expectEqual(@as(u16, 443), bare.port);
    try std.testing.expect(bare.password == null);

    // user:pass@ is one opaque auth string, and percent-decoded.
    const userpass = try parseXrayLink(a, "hysteria2://bob%3As3cret@1.2.3.4:443/#n");
    try std.testing.expectEqualStrings("bob:s3cret", userpass.password.?);

    // IPv6 literal, with and without a port.
    const v6 = try parseXrayLink(a, "hysteria2://pw@[2001:db8::1]:8443/?insecure=1#v6");
    try std.testing.expectEqualStrings("2001:db8::1", v6.address);
    try std.testing.expectEqual(@as(u16, 8443), v6.port);
    try std.testing.expect(v6.insecure);

    // Port hopping is refused, not silently truncated to the first port: sing-box wants
    // server_ports:["a:b"] with a colon, so keeping 40443 would dial the wrong place.
    try std.testing.expectError(error.UnsupportedPortHopping, parseXrayLink(a, "hysteria2://pw@example.com:40443,50000-60000/#hop"));

    // ── generated config ──
    const cfg = try genSingboxConfig(a, &.{canonical});
    _ = try std.json.parseFromSlice(std.json.Value, a, cfg, .{});
    try std.testing.expect(std.mem.indexOf(u8, cfg, "\"type\":\"hysteria2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, cfg, "\"password\":\"letmein\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, cfg, "\"obfs\":{\"type\":\"salamander\",\"password\":\"cats\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, cfg, "\"server_name\":\"cover.example\"") != null);
    // TLS must be present — sing-box's hysteria2 outbound refuses to load without it.
    try std.testing.expect(std.mem.indexOf(u8, cfg, "\"tls\":{\"enabled\":true") != null);
    // And uTLS must NOT be: it has no STDConfig, so sing-quic fails every connection with
    // "unsupported usage for uTLS" while `sing-box check` still passes.
    try std.testing.expect(std.mem.indexOf(u8, cfg, "utls") == null);
    // No ws/grpc transport block on a QUIC outbound either.
    try std.testing.expect(std.mem.indexOf(u8, cfg, "\"transport\"") == null);

    // insecure rides through as a real JSON bool.
    const insecure_cfg = try genSingboxConfig(a, &.{v6});
    try std.testing.expect(std.mem.indexOf(u8, insecure_cfg, "\"insecure\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, cfg, "\"insecure\":false") != null);

    // Mixed pool with an Xray member: one urltest, both outbound types, utls only on the
    // vless member.
    const vless = try parseXrayLink(a, "vless://95e0edb9-4a0b-4312-a71f-1d4b8b6db79b@154.59.110.32:443?type=tcp&security=reality&pbk=P&sni=s.example&sid=S&flow=xtls-rprx-vision#v");
    const pool = try genSingboxConfig(a, &.{ vless, canonical });
    _ = try std.json.parseFromSlice(std.json.Value, a, pool, .{});
    try std.testing.expect(std.mem.indexOf(u8, pool, "\"urltest\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pool, "\"type\":\"hysteria2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pool, "\"reality\"") != null);
}

test "hysteria2: links we cannot emit faithfully are rejected, not degraded" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var buf: [256]u8 = undefined;

    const ok = try parseXrayLink(a, "hysteria2://pw@example.com:443/#n");
    try std.testing.expect(validateLink(ok, &buf) == null);

    // pinSHA256: hysteria pins the DER cert (colon-hex), sing-box pins the SPKI (base64).
    // A 64-char hex pin even decodes as valid base64 into 48 wrong bytes, so a naive
    // pass-through gives a config that checks clean and fails every handshake.
    const pinned = try parseXrayLink(a, "hysteria2://pw@example.com:443/?pinSHA256=deadbeef#n");
    try std.testing.expect(validateLink(pinned, &buf) != null);

    const ech = try parseXrayLink(a, "hysteria2://pw@example.com:443/?ech=AEX+DQBB#n");
    try std.testing.expect(validateLink(ech, &buf) != null);

    // salamander is the only obfs that exists, and it is useless without its password.
    const bad_obfs = try parseXrayLink(a, "hysteria2://pw@example.com:443/?obfs=xplus&obfs-password=p#n");
    try std.testing.expect(validateLink(bad_obfs, &buf) != null);

    const obfs_no_pw = try parseXrayLink(a, "hysteria2://pw@example.com:443/?obfs=salamander#n");
    try std.testing.expect(validateLink(obfs_no_pw, &buf) != null);
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
