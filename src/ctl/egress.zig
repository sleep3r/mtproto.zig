//! egress.zig — `mtbuddy setup egress <share-link>...`
//!
//! Provision an upstream egress for the proxy from VPN share-links, dispatching by URI
//! scheme onto the `type = tunnel` egress shape (transparent L3, policy-routed — the same
//! abstraction as AmneziaWG):
//!
//!   wireguard://                         -> native kernel WG/AmneziaWG tunnel (reuses
//!                                           tunnel.zig: policy routing + pool)
//!   vless:// vmess:// trojan:// ss://     -> a local sing-box client in TUN mode (sbx0);
//!                                           the proxy's SO_MARK'd DC traffic is policy-
//!                                           routed through it (fwmark 200 -> table 200 ->
//!                                           sbx0). >1 link -> a sing-box urltest failover
//!                                           pool. VLESS-Reality camouflages the hop as TLS.
//!
//! The proxy relay is unchanged (it just SO_MARKs, as for any tunnel). The two providers
//! are mutually exclusive on table 200 — setting one up retires the other. This module
//! lives entirely in mtbuddy (ctl).

const std = @import("std");
const builtin = @import("builtin");
const sys = @import("sys.zig");
const toml = @import("toml.zig");
const tunnel = @import("tunnel.zig");
const tui_mod = @import("tui.zig");
const Tui = tui_mod.Tui;

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

// ── URI helpers ───────────────────────────────────────────────────────────────

/// Decode percent-escapes (%2F -> '/') into `out` (must be >= s.len). Returns the slice.
pub fn percentDecode(out: []u8, s: []const u8) []const u8 {
    var w: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '%' and i + 2 < s.len) {
            const hi = std.fmt.charToDigit(s[i + 1], 16) catch {
                out[w] = s[i];
                w += 1;
                continue;
            };
            const lo = std.fmt.charToDigit(s[i + 2], 16) catch {
                out[w] = s[i];
                w += 1;
                continue;
            };
            out[w] = @intCast(hi * 16 + lo);
            w += 1;
            i += 2;
        } else {
            out[w] = s[i];
            w += 1;
        }
    }
    return out[0..w];
}

/// Percent-decode into a freshly allocated buffer.
fn percentDecodeAlloc(a: std.mem.Allocator, s: []const u8) ![]const u8 {
    const buf = try a.alloc(u8, s.len);
    const decoded = percentDecode(buf, s);
    return decoded;
}

/// Return the (raw, undecoded) value of `key` in a `k=v&k2=v2` query string, or null.
pub fn queryParam(query: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], key)) return pair[eq + 1 ..];
    }
    return null;
}

/// Standard or url-safe base64 decode (tolerant of missing padding), into alloc.
fn base64Decode(a: std.mem.Allocator, s_in: []const u8) ![]u8 {
    const s = std.mem.trim(u8, s_in, " \t\r\n");
    const url_safe = std.mem.indexOfAny(u8, s, "-_") != null;
    // Re-pad to a multiple of 4 for the standard decoders.
    const pad = (4 - (s.len % 4)) % 4;
    var tmp = try a.alloc(u8, s.len + pad);
    @memcpy(tmp[0..s.len], s);
    var p: usize = 0;
    while (p < pad) : (p += 1) tmp[s.len + p] = '=';
    const dec = if (url_safe) std.base64.url_safe.Decoder else std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(tmp) catch return error.BadBase64;
    const out = try a.alloc(u8, n);
    dec.decode(out, tmp) catch return error.BadBase64;
    return out;
}

// ── Parsed link model ──────────────────────────────────────────────────────────

pub const Scheme = enum { vless, vmess, trojan, shadowsocks, wireguard, unknown };

pub fn detectScheme(link_in: []const u8) Scheme {
    const link = std.mem.trim(u8, link_in, " \t\r\n");
    if (std.mem.startsWith(u8, link, "vless://")) return .vless;
    if (std.mem.startsWith(u8, link, "vmess://")) return .vmess;
    if (std.mem.startsWith(u8, link, "trojan://")) return .trojan;
    if (std.mem.startsWith(u8, link, "ss://")) return .shadowsocks;
    if (std.mem.startsWith(u8, link, "wireguard://") or std.mem.startsWith(u8, link, "wg://")) return .wireguard;
    return .unknown;
}

/// A parsed Xray-family link (vless/vmess/trojan/ss). All string fields are owned by
/// the allocator passed to the parser (use an arena and free it all at once). Fields
/// not relevant to a given protocol stay null/empty.
pub const XrayLink = struct {
    scheme: Scheme,
    name: []const u8 = "egress",
    address: []const u8,
    port: u16,
    // auth
    id: ?[]const u8 = null, // uuid (vless/vmess)
    password: ?[]const u8 = null, // trojan / ss
    method: ?[]const u8 = null, // ss cipher
    alter_id: u16 = 0, // vmess aid
    cipher: []const u8 = "auto", // vmess scy (auto|none|zero|aes-128-gcm|chacha20-poly1305)
    // transport / security
    network: []const u8 = "tcp", // tcp | ws | grpc | http
    security: []const u8 = "none", // none | tls | reality
    flow: ?[]const u8 = null, // vless xtls flow
    sni: ?[]const u8 = null,
    host: ?[]const u8 = null, // ws/http Host header
    path: ?[]const u8 = null, // ws/http path or grpc serviceName
    fingerprint: ?[]const u8 = null, // utls fp (chrome,...)
    public_key: ?[]const u8 = null, // reality pbk
    short_id: ?[]const u8 = null, // reality sid
};

fn splitHostPort(hp: []const u8) !struct { host: []const u8, port: u16 } {
    // IPv6 literal in brackets: [::1]:443
    if (hp.len > 0 and hp[0] == '[') {
        const close = std.mem.indexOfScalar(u8, hp, ']') orelse return error.BadAddress;
        const host = hp[1..close];
        if (close + 1 >= hp.len or hp[close + 1] != ':') return error.BadAddress;
        const port = std.fmt.parseInt(u16, hp[close + 2 ..], 10) catch return error.BadAddress;
        return .{ .host = host, .port = port };
    }
    const colon = std.mem.lastIndexOfScalar(u8, hp, ':') orelse return error.BadAddress;
    const port = std.fmt.parseInt(u16, hp[colon + 1 ..], 10) catch return error.BadAddress;
    return .{ .host = hp[0..colon], .port = port };
}

/// Parse vless:// or trojan:// (same URI shape: cred@host:port?params#name).
fn parseUriCred(a: std.mem.Allocator, link: []const u8, scheme: Scheme, prefix: []const u8) !XrayLink {
    var rest = link[prefix.len..];
    // fragment (name)
    var name: []const u8 = "egress";
    if (std.mem.indexOfScalar(u8, rest, '#')) |h| {
        name = try percentDecodeAlloc(a, rest[h + 1 ..]);
        rest = rest[0..h];
    }
    // query
    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, rest, '?')) |q| {
        query = rest[q + 1 ..];
        rest = rest[0..q];
    }
    const at = std.mem.indexOfScalar(u8, rest, '@') orelse return error.BadLink;
    const cred = try percentDecodeAlloc(a, rest[0..at]);
    const hp = try splitHostPort(rest[at + 1 ..]);

    var l = XrayLink{ .scheme = scheme, .name = name, .address = try a.dupe(u8, hp.host), .port = hp.port };
    if (scheme == .vless) l.id = cred else l.password = cred;

    if (queryParam(query, "type")) |v| l.network = try percentDecodeAlloc(a, v);
    if (queryParam(query, "security")) |v| l.security = try percentDecodeAlloc(a, v);
    if (queryParam(query, "flow")) |v| l.flow = try percentDecodeAlloc(a, v);
    if (queryParam(query, "sni")) |v| l.sni = try percentDecodeAlloc(a, v);
    if (queryParam(query, "host")) |v| l.host = try percentDecodeAlloc(a, v);
    if (queryParam(query, "path")) |v| l.path = try percentDecodeAlloc(a, v);
    if (queryParam(query, "serviceName")) |v| l.path = try percentDecodeAlloc(a, v);
    if (queryParam(query, "fp")) |v| l.fingerprint = try percentDecodeAlloc(a, v);
    if (queryParam(query, "pbk")) |v| l.public_key = try percentDecodeAlloc(a, v);
    if (queryParam(query, "sid")) |v| l.short_id = try percentDecodeAlloc(a, v);
    return l;
}

fn jsonStr(obj: std.json.Value, key: []const u8) ?[]const u8 {
    const v = obj.object.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        .integer => |i| std.fmt.allocPrint(std.heap.page_allocator, "{d}", .{i}) catch null,
        else => null,
    };
}

/// Parse vmess:// (base64-encoded JSON object).
fn parseVmess(a: std.mem.Allocator, link: []const u8) !XrayLink {
    const decoded = try base64Decode(a, link["vmess://".len..]);
    const parsed = std.json.parseFromSlice(std.json.Value, a, decoded, .{}) catch return error.BadLink;
    const o = parsed.value;
    if (o != .object) return error.BadLink;
    const add = jsonStr(o, "add") orelse return error.BadLink;
    const port_s = jsonStr(o, "port") orelse return error.BadLink;
    const id = jsonStr(o, "id") orelse return error.BadLink;
    var l = XrayLink{
        .scheme = .vmess,
        .name = try a.dupe(u8, jsonStr(o, "ps") orelse "egress"),
        .address = try a.dupe(u8, add),
        .port = std.fmt.parseInt(u16, std.mem.trim(u8, port_s, " "), 10) catch return error.BadLink,
        .id = try a.dupe(u8, id),
    };
    if (jsonStr(o, "aid")) |s| l.alter_id = std.fmt.parseInt(u16, std.mem.trim(u8, s, " "), 10) catch 0;
    if (jsonStr(o, "scy")) |s| if (s.len > 0) {
        l.cipher = try a.dupe(u8, s);
    };
    if (jsonStr(o, "net")) |s| l.network = try a.dupe(u8, s);
    if (jsonStr(o, "host")) |s| l.host = try a.dupe(u8, s);
    if (jsonStr(o, "path")) |s| l.path = try a.dupe(u8, s);
    if (jsonStr(o, "sni")) |s| l.sni = try a.dupe(u8, s);
    const tls = jsonStr(o, "tls") orelse "";
    if (tls.len > 0) l.security = "tls";
    return l;
}

/// Parse ss:// — SIP002 (`ss://b64(method:pass)@host:port#name`) or legacy
/// (`ss://b64(method:pass@host:port)#name`).
fn parseSs(a: std.mem.Allocator, link: []const u8) !XrayLink {
    var rest = link["ss://".len..];
    var name: []const u8 = "egress";
    if (std.mem.indexOfScalar(u8, rest, '#')) |h| {
        name = try percentDecodeAlloc(a, rest[h + 1 ..]);
        rest = rest[0..h];
    }
    if (std.mem.indexOfScalar(u8, rest, '?')) |q| rest = rest[0..q]; // drop plugin params
    var method: []const u8 = undefined;
    var password: []const u8 = undefined;
    var hostport: []const u8 = undefined;
    if (std.mem.indexOfScalar(u8, rest, '@')) |at| {
        // SIP002: userinfo (before @) is base64(method:password)
        const ui = base64Decode(a, rest[0..at]) catch rest[0..at];
        const colon = std.mem.indexOfScalar(u8, ui, ':') orelse return error.BadLink;
        method = ui[0..colon];
        password = ui[colon + 1 ..];
        hostport = rest[at + 1 ..];
    } else {
        // legacy: whole thing is base64(method:password@host:port)
        const dec = try base64Decode(a, rest);
        const at = std.mem.indexOfScalar(u8, dec, '@') orelse return error.BadLink;
        const colon = std.mem.indexOfScalar(u8, dec[0..at], ':') orelse return error.BadLink;
        method = dec[0..colon];
        password = dec[colon + 1 .. at];
        hostport = dec[at + 1 ..];
    }
    const hp = try splitHostPort(hostport);
    return XrayLink{
        .scheme = .shadowsocks,
        .name = name,
        .address = try a.dupe(u8, hp.host),
        .port = hp.port,
        .method = try a.dupe(u8, method),
        .password = try a.dupe(u8, password),
    };
}

/// Parse any Xray-family share link into an XrayLink (arena-owned strings).
pub fn parseXrayLink(a: std.mem.Allocator, link_in: []const u8) !XrayLink {
    const link = std.mem.trim(u8, link_in, " \t\r\n");
    return switch (detectScheme(link)) {
        .vless => parseUriCred(a, link, .vless, "vless://"),
        .trojan => parseUriCred(a, link, .trojan, "trojan://"),
        .vmess => parseVmess(a, link),
        .shadowsocks => parseSs(a, link),
        else => error.UnsupportedScheme,
    };
}

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

const Family = enum { wireguard, xray };
fn schemeFamily(s: Scheme) Family {
    return if (s == .wireguard) .wireguard else .xray;
}

// Ciphers sing-box accepts for shadowsocks. An unknown one makes sing-box reject the
// WHOLE config, so we reject the link up front with a clear message instead.
const supported_ss_methods = [_][]const u8{
    "aes-128-gcm",             "aes-192-gcm",
    "aes-256-gcm",             "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    "none",
};

/// Reject links whose transport/cipher our generator can't faithfully emit — better a
/// clear error than silently degrading an unsupported transport to plain TCP (which the
/// server rejects) or emitting an unknown SS cipher (which sing-box refuses to load).
/// Returns an error message in `buf`, or null when the link is supported.
fn validateLink(l: XrayLink, buf: []u8) ?[]const u8 {
    const net = l.network;
    if (!(net.len == 0 or std.mem.eql(u8, net, "tcp") or std.mem.eql(u8, net, "ws") or std.mem.eql(u8, net, "grpc"))) {
        return std.fmt.bufPrint(buf, "unsupported transport '{s}' for {s} — only tcp/ws/grpc are supported", .{ net, l.address }) catch "unsupported transport";
    }
    if (l.scheme == .shadowsocks) {
        const m = l.method orelse "";
        for (supported_ss_methods) |sm| {
            if (std.mem.eql(u8, m, sm)) return null;
        }
        return std.fmt.bufPrint(buf, "unsupported shadowsocks cipher '{s}' for {s}", .{ m, l.address }) catch "unsupported shadowsocks cipher";
    }
    return null;
}

pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    var links: std.ArrayListUnmanaged([]const u8) = .empty;
    defer links.deinit(allocator);
    while (args.next()) |arg| {
        if (arg.len > 0 and arg[0] != '-') links.append(allocator, arg) catch {};
    }
    if (links.items.len == 0) {
        ui.fail("Usage: mtbuddy setup egress <share-link> [<share-link>...]");
        ui.hint("vless:// vmess:// trojan:// ss://  ->  Xray SOCKS5 bridge (upstream.type=socks5)");
        ui.hint("wireguard://                       ->  native L3 tunnel");
        return;
    }
    // One egress = one provider family. Reject a mix of wireguard:// and Xray links.
    const fam0 = schemeFamily(detectScheme(links.items[0]));
    for (links.items) |l| {
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
        return setupWireguard(ui, allocator, links.items);
    }
    return setupSingboxTunnel(ui, allocator, links.items);
}

/// wireguard:// links -> native L3 tunnel. Convert each link to a WG/AmneziaWG .conf
/// (egress owns the URI parsing) and hand it to tunnel.zig's existing setup, which
/// brings up the interface + policy routing and, for >1 link, builds the tunnel pool.
fn setupWireguard(ui: *Tui, allocator: std.mem.Allocator, links: []const []const u8) !void {
    for (links, 0..) |link, idx| {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const conf = convertWireguardLink(a, link) catch {
            ui.fail("Failed to parse a wireguard:// link");
            return;
        };
        const tmp = try std.fmt.allocPrint(a, "/tmp/mtbuddy-wg-{d}.conf", .{idx});
        sys.writeFileMode(tmp, conf, 0o600) catch {
            ui.fail("Failed to stage the WireGuard config");
            return;
        };
        try tunnel.setupFromConf(ui, allocator, tmp);
        _ = sys.exec(allocator, &.{ "rm", "-f", tmp }) catch {};
    }
}

/// Convert a `wireguard://<privkey>@<host>:<port>?publickey=&address=&mtu=...#name`
/// share-link into a WireGuard/AmneziaWG `.conf`. AmneziaWG obfuscation params
/// (jc/jmin/jmax/s1/s2/h1..h4) and presharedkey are carried through when present.
pub fn convertWireguardLink(a: std.mem.Allocator, link_in: []const u8) ![]const u8 {
    const link = std.mem.trim(u8, link_in, " \t\r\n");
    const after = if (std.mem.startsWith(u8, link, "wireguard://"))
        link["wireguard://".len..]
    else if (std.mem.startsWith(u8, link, "wg://"))
        link["wg://".len..]
    else
        return error.UnsupportedScheme;

    var rest = after;
    if (std.mem.indexOfScalar(u8, rest, '#')) |h| rest = rest[0..h];
    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, rest, '?')) |q| {
        query = rest[q + 1 ..];
        rest = rest[0..q];
    }
    const at = std.mem.indexOfScalar(u8, rest, '@') orelse return error.BadLink;
    const private_key = try percentDecodeAlloc(a, rest[0..at]);
    const hp = try splitHostPort(rest[at + 1 ..]);

    const pub_key = try percentDecodeAlloc(a, queryParam(query, "publickey") orelse queryParam(query, "public_key") orelse return error.BadLink);
    const address = try percentDecodeAlloc(a, queryParam(query, "address") orelse "10.0.0.2/32");
    const mtu = queryParam(query, "mtu") orelse "1420";

    var aw: std.Io.Writer.Allocating = .init(a);
    const w = &aw.writer;
    try w.print("[Interface]\nPrivateKey = {s}\nAddress = {s}\nMTU = {s}\n", .{ private_key, address, mtu });
    if (queryParam(query, "dns")) |dns| try w.print("DNS = {s}\n", .{try percentDecodeAlloc(a, dns)});
    // AmneziaWG obfuscation knobs (only emitted when present).
    inline for (.{ "jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4" }) |k| {
        if (queryParam(query, k)) |v| {
            var ku: [4]u8 = undefined;
            const upper = std.ascii.upperString(&ku, k);
            try w.print("{s} = {s}\n", .{ upper, v });
        }
    }
    try w.print("\n[Peer]\nPublicKey = {s}\nEndpoint = {s}:{d}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n", .{ pub_key, hp.host, hp.port });
    if (queryParam(query, "presharedkey")) |psk| try w.print("PresharedKey = {s}\n", .{try percentDecodeAlloc(a, psk)});
    return aw.written();
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

    if (!sys.commandExists("sing-box") and !sys.fileExists(SB_BIN)) {
        ui.step("Installing sing-box...");
        if (!installSingbox(allocator)) {
            ui.fail("Failed to install sing-box (download/extract). Check network and retry.");
            return;
        }
        ui.ok("sing-box installed");
    }
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

test "parse vless reality link" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const l = try parseXrayLink(a, "vless://95e0edb9-4a0b-4312-a71f-1d4b8b6db79b@154.59.110.32:443?type=tcp&security=reality&pbk=PBK&fp=chrome&sni=www.microsoft.com&sid=ABCD&flow=xtls-rprx-vision#demo");
    try std.testing.expectEqual(Scheme.vless, l.scheme);
    try std.testing.expectEqualStrings("154.59.110.32", l.address);
    try std.testing.expectEqual(@as(u16, 443), l.port);
    try std.testing.expectEqualStrings("95e0edb9-4a0b-4312-a71f-1d4b8b6db79b", l.id.?);
    try std.testing.expectEqualStrings("reality", l.security);
    try std.testing.expectEqualStrings("www.microsoft.com", l.sni.?);
    try std.testing.expectEqualStrings("PBK", l.public_key.?);
    try std.testing.expectEqualStrings("ABCD", l.short_id.?);
    try std.testing.expectEqualStrings("xtls-rprx-vision", l.flow.?);
    try std.testing.expectEqualStrings("demo", l.name);
}

test "parse vmess base64 link" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // {"v":"2","ps":"demo-vmess","add":"154.59.110.32","port":"10443","id":"15750f7e-57df-4fb2-b3a4-a9edff4c0def","aid":"0","net":"tcp","type":"none","tls":""}
    const l = try parseXrayLink(a, "vmess://eyJ2IjogIjIiLCAicHMiOiAiZGVtby12bWVzcyIsICJhZGQiOiAiMTU0LjU5LjExMC4zMiIsICJwb3J0IjogIjEwNDQzIiwgImlkIjogIjE1NzUwZjdlLTU3ZGYtNGZiMi1iM2E0LWE5ZWRmZjRjMGRlZiIsICJhaWQiOiAiMCIsICJuZXQiOiAidGNwIiwgInR5cGUiOiAibm9uZSIsICJ0bHMiOiAiIn0=");
    try std.testing.expectEqual(Scheme.vmess, l.scheme);
    try std.testing.expectEqualStrings("154.59.110.32", l.address);
    try std.testing.expectEqual(@as(u16, 10443), l.port);
    try std.testing.expectEqualStrings("15750f7e-57df-4fb2-b3a4-a9edff4c0def", l.id.?);
    try std.testing.expectEqualStrings("demo-vmess", l.name);
}

test "parse shadowsocks sip002 link" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // base64("aes-256-gcm:g7ZGM4sBp5FuzPgvKQgYgA") @ host:port
    const l = try parseXrayLink(a, "ss://YWVzLTI1Ni1nY206ZzdaR000c0JwNUZ1elBndktRZ1lnQQ==@154.59.110.32:9443#demo-shadowsocks");
    try std.testing.expectEqual(Scheme.shadowsocks, l.scheme);
    try std.testing.expectEqualStrings("154.59.110.32", l.address);
    try std.testing.expectEqual(@as(u16, 9443), l.port);
    try std.testing.expectEqualStrings("aes-256-gcm", l.method.?);
    try std.testing.expectEqualStrings("g7ZGM4sBp5FuzPgvKQgYgA", l.password.?);
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

test "percentDecode + queryParam" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("10.11.11.2/32", percentDecode(&buf, "10.11.11.2%2F32"));
    try std.testing.expectEqualStrings("German WG-1", percentDecode(&buf, "German%20WG-1"));
    try std.testing.expectEqualStrings("1420", queryParam("publickey=X&address=Y&mtu=1420", "mtu").?);
    try std.testing.expect(queryParam("a=1&b=2", "c") == null);
}

test "validateLink rejects unsupported transport and ss cipher" {
    var buf: [256]u8 = undefined;
    try std.testing.expect(validateLink(.{ .scheme = .vless, .address = "h", .port = 1, .network = "ws" }, &buf) == null);
    try std.testing.expect(validateLink(.{ .scheme = .shadowsocks, .address = "h", .port = 1, .method = "aes-256-gcm" }, &buf) == null);
    try std.testing.expect(validateLink(.{ .scheme = .vless, .address = "h", .port = 1, .network = "quic" }, &buf) != null);
    try std.testing.expect(validateLink(.{ .scheme = .shadowsocks, .address = "h", .port = 1, .method = "rc4-md5-is-unsupported" }, &buf) != null);
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

test "detectScheme" {
    try std.testing.expectEqual(Scheme.vless, detectScheme("vless://x"));
    try std.testing.expectEqual(Scheme.wireguard, detectScheme("wireguard://x"));
    try std.testing.expectEqual(Scheme.shadowsocks, detectScheme("ss://x"));
    try std.testing.expectEqual(Scheme.unknown, detectScheme("http://x"));
}

test "convertWireguardLink builds a WG/AmneziaWG conf" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const conf = try convertWireguardLink(a, "wireguard://PRIVK%2Fey@111.222.33.194:19666?publickey=PUBKEY&address=10.11.11.2%2F32&mtu=1420&presharedkey=PSK&jc=4&s1=50#German%20WG-1");
    const has = struct {
        fn f(h: []const u8, n: []const u8) bool {
            return std.mem.indexOf(u8, h, n) != null;
        }
    }.f;
    try std.testing.expect(has(conf, "[Interface]"));
    try std.testing.expect(has(conf, "PrivateKey = PRIVK/ey")); // %2F decoded
    try std.testing.expect(has(conf, "Address = 10.11.11.2/32"));
    try std.testing.expect(has(conf, "MTU = 1420"));
    try std.testing.expect(has(conf, "JC = 4")); // AmneziaWG knob, uppercased
    try std.testing.expect(has(conf, "S1 = 50"));
    try std.testing.expect(has(conf, "[Peer]"));
    try std.testing.expect(has(conf, "PublicKey = PUBKEY"));
    try std.testing.expect(has(conf, "Endpoint = 111.222.33.194:19666"));
    try std.testing.expect(has(conf, "AllowedIPs = 0.0.0.0/0, ::/0"));
    try std.testing.expect(has(conf, "PresharedKey = PSK"));
}
