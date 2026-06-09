//! egress.zig — `mtbuddy setup egress <share-link>...`
//!
//! Provision an upstream egress for the proxy from VPN share-links, dispatching by
//! URI scheme onto the two egress shapes the proxy already supports:
//!
//!   wireguard://                         -> native L3 tunnel (reuses tunnel.zig:
//!                                           kernel WG/AmneziaWG + policy routing + pool)
//!   vless:// vmess:// trojan:// ss://     -> a local Xray client exposing a SOCKS5
//!                                           inbound; the proxy egresses via
//!                                           upstream.type = socks5. Multiple links ->
//!                                           an Xray balancer + observatory (failover),
//!                                           mirroring the tunnel pool.
//!
//! The proxy relay is unchanged: the SOCKS5 upstream client already exists. This module
//! lives entirely in mtbuddy (ctl).

const std = @import("std");

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

/// JSON-escape + quote a string (returns including the surrounding quotes).
fn js(a: std.mem.Allocator, s: []const u8) []const u8 {
    var buf = a.alloc(u8, s.len * 2 + 2) catch return "\"\"";
    var w: usize = 0;
    buf[w] = '"';
    w += 1;
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
        else => {
            buf[w] = c;
            w += 1;
        },
    };
    buf[w] = '"';
    w += 1;
    return buf[0..w];
}

fn streamSettings(a: std.mem.Allocator, l: XrayLink) ![]const u8 {
    if (l.scheme == .shadowsocks) return "";
    const sni = l.sni orelse l.host orelse l.address;
    const fp = l.fingerprint orelse "chrome";
    var sec: []const u8 = ",\"security\":\"none\"";
    if (std.mem.eql(u8, l.security, "reality")) {
        sec = try std.fmt.allocPrint(a, ",\"security\":\"reality\",\"realitySettings\":{{\"serverName\":{s},\"fingerprint\":{s},\"publicKey\":{s},\"shortId\":{s},\"spiderX\":\"/\"}}", .{ js(a, sni), js(a, fp), js(a, l.public_key orelse ""), js(a, l.short_id orelse "") });
    } else if (std.mem.eql(u8, l.security, "tls")) {
        sec = try std.fmt.allocPrint(a, ",\"security\":\"tls\",\"tlsSettings\":{{\"serverName\":{s},\"fingerprint\":{s},\"allowInsecure\":false}}", .{ js(a, sni), js(a, fp) });
    }
    var trans: []const u8 = "";
    if (std.mem.eql(u8, l.network, "ws")) {
        trans = try std.fmt.allocPrint(a, ",\"wsSettings\":{{\"path\":{s},\"headers\":{{\"Host\":{s}}}}}", .{ js(a, l.path orelse "/"), js(a, l.host orelse sni) });
    } else if (std.mem.eql(u8, l.network, "grpc")) {
        trans = try std.fmt.allocPrint(a, ",\"grpcSettings\":{{\"serviceName\":{s}}}", .{js(a, l.path orelse "")});
    }
    return std.fmt.allocPrint(a, ",\"streamSettings\":{{\"network\":{s}{s}{s}}}", .{ js(a, l.network), sec, trans });
}

fn outbound(a: std.mem.Allocator, l: XrayLink, tag: []const u8) ![]const u8 {
    const stream = try streamSettings(a, l);
    return switch (l.scheme) {
        .vless => blk: {
            const flow = if (l.flow) |f| try std.fmt.allocPrint(a, ",\"flow\":{s}", .{js(a, f)}) else "";
            break :blk std.fmt.allocPrint(a, "{{\"protocol\":\"vless\",\"tag\":{s},\"settings\":{{\"vnext\":[{{\"address\":{s},\"port\":{d},\"users\":[{{\"id\":{s},\"encryption\":\"none\"{s}}}]}}]}}{s}}}", .{ js(a, tag), js(a, l.address), l.port, js(a, l.id.?), flow, stream });
        },
        .vmess => std.fmt.allocPrint(a, "{{\"protocol\":\"vmess\",\"tag\":{s},\"settings\":{{\"vnext\":[{{\"address\":{s},\"port\":{d},\"users\":[{{\"id\":{s},\"alterId\":{d},\"security\":\"auto\"}}]}}]}}{s}}}", .{ js(a, tag), js(a, l.address), l.port, js(a, l.id.?), l.alter_id, stream }),
        .trojan => std.fmt.allocPrint(a, "{{\"protocol\":\"trojan\",\"tag\":{s},\"settings\":{{\"servers\":[{{\"address\":{s},\"port\":{d},\"password\":{s}}}]}}{s}}}", .{ js(a, tag), js(a, l.address), l.port, js(a, l.password.?), stream }),
        .shadowsocks => std.fmt.allocPrint(a, "{{\"protocol\":\"shadowsocks\",\"tag\":{s},\"settings\":{{\"servers\":[{{\"address\":{s},\"port\":{d},\"method\":{s},\"password\":{s}}}]}}}}", .{ js(a, tag), js(a, l.address), l.port, js(a, l.method.?), js(a, l.password.?) }),
        else => error.UnsupportedScheme,
    };
}

/// Build a full Xray client config: a SOCKS5 inbound on 127.0.0.1:`socks_port` and one
/// outbound per link. With >1 link, add a leastPing balancer + observatory so a dead
/// egress fails over to a healthy one (the Xray analogue of the tunnel pool).
pub fn genXrayConfig(a: std.mem.Allocator, links: []const XrayLink, socks_port: u16) ![]const u8 {
    var obs: std.ArrayListUnmanaged(u8) = .empty;
    for (links, 0..) |l, i| {
        const tag = try std.fmt.allocPrint(a, "egress-{d}", .{i});
        if (i != 0) try obs.append(a, ',');
        try obs.appendSlice(a, try outbound(a, l, tag));
    }
    const routing = if (links.len > 1)
        ",\"routing\":{\"balancers\":[{\"tag\":\"egress\",\"selector\":[\"egress-\"],\"strategy\":{\"type\":\"leastPing\"}}],\"rules\":[{\"type\":\"field\",\"network\":\"tcp,udp\",\"balancerTag\":\"egress\"}]},\"observatory\":{\"subjectSelector\":[\"egress-\"],\"probeUrl\":\"https://www.gstatic.com/generate_204\",\"probeInterval\":\"10s\"}"
    else
        "";
    return std.fmt.allocPrint(a, "{{\"log\":{{\"loglevel\":\"warning\"}},\"inbounds\":[{{\"tag\":\"socks-in\",\"listen\":\"127.0.0.1\",\"port\":{d},\"protocol\":\"socks\",\"settings\":{{\"udp\":true,\"auth\":\"noauth\"}}}}],\"outbounds\":[{s},{{\"protocol\":\"freedom\",\"tag\":\"direct\"}}]{s}}}", .{ socks_port, obs.items, routing });
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

test "genXrayConfig is valid JSON; balancer only for a pool" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const vless = try parseXrayLink(a, "vless://95e0edb9-4a0b-4312-a71f-1d4b8b6db79b@154.59.110.32:443?type=tcp&security=reality&pbk=PBK&sni=www.microsoft.com&sid=SID&flow=xtls-rprx-vision#v");
    const ss = try parseXrayLink(a, "ss://YWVzLTI1Ni1nY206ZzdaR000c0JwNUZ1elBndktRZ1lnQQ==@154.59.110.32:9443#s");

    const one = try genXrayConfig(a, &.{vless}, 10808);
    _ = try std.json.parseFromSlice(std.json.Value, a, one, .{}); // well-formed JSON
    try std.testing.expect(std.mem.indexOf(u8, one, "\"reality\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, one, "\"port\":10808") != null);
    try std.testing.expect(std.mem.indexOf(u8, one, "xtls-rprx-vision") != null);
    try std.testing.expect(std.mem.indexOf(u8, one, "\"balancers\"") == null);

    const pool = try genXrayConfig(a, &.{ vless, ss }, 10808);
    _ = try std.json.parseFromSlice(std.json.Value, a, pool, .{});
    try std.testing.expect(std.mem.indexOf(u8, pool, "\"balancers\"") != null);
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

test "detectScheme" {
    try std.testing.expectEqual(Scheme.vless, detectScheme("vless://x"));
    try std.testing.expectEqual(Scheme.wireguard, detectScheme("wireguard://x"));
    try std.testing.expectEqual(Scheme.shadowsocks, detectScheme("ss://x"));
    try std.testing.expectEqual(Scheme.unknown, detectScheme("http://x"));
}
