//! sharelink.zig — VPN share-link parsing & transforms (std-only, no I/O).
//!
//! Pure functions that turn VPN share-links into structured data or alternate config
//! formats. The transport/security knobs of Xray-family links (vless/vmess/trojan/ss)
//! are parsed into `XrayLink`; wireguard:// links are rendered to a WG/AmneziaWG `.conf`.
//! Nothing here touches the filesystem, the network, or systemd — callers own all I/O.
//!
//!   detectScheme / parseXrayLink   -> classify + parse an Xray-family link
//!   validateLink                   -> reject transports/ciphers a generator can't emit
//!   schemeFamily                   -> wireguard:// vs Xray (one egress = one family)
//!   convertWireguardLink           -> wireguard:// share-link -> WG/AmneziaWG .conf

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

// ── Link family + validation ────────────────────────────────────────────────────

pub const Family = enum { wireguard, xray };
pub fn schemeFamily(s: Scheme) Family {
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
pub fn validateLink(l: XrayLink, buf: []u8) ?[]const u8 {
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

// ── wireguard:// -> .conf transform ──────────────────────────────────────────────

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
