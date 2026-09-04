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

/// True if `s` contains any control character (incl. CR/LF) or DEL. Such bytes, once
/// percent-decoded, would let a share-link field break out of its `Key = value` line in
/// a generated WireGuard `.conf` and inject arbitrary [Interface] directives — notably
/// PostUp/PreUp/PostDown, which wg-quick/awg-quick execute as shell commands as root.
fn hasControlBytes(s: []const u8) bool {
    for (s) |c| {
        if (c < 0x20 or c == 0x7f) return true;
    }
    return false;
}

/// Percent-decode a share-link field and reject it if the result smuggles control bytes.
/// Used for every field that lands verbatim in a generated config (CWE-78 hardening).
fn percentDecodeChecked(a: std.mem.Allocator, s: []const u8) ![]const u8 {
    const decoded = try percentDecodeAlloc(a, s);
    if (hasControlBytes(decoded)) return error.UnsafeLinkField;
    return decoded;
}

/// Validate a raw (un-decoded) field that is emitted verbatim into a config line.
fn rawFieldChecked(s: []const u8) ![]const u8 {
    if (hasControlBytes(s)) return error.UnsafeLinkField;
    return s;
}

/// True when a WHOLE share-link is safe to record verbatim. `setup egress` writes the
/// pasted text into `[upstream.xray] links` in the root-owned config.toml as a bare quoted
/// array, so a newline in the link emits extra physical lines into a file the proxy parses
/// back: an injected `[access.users]` entry hands the proxy to whoever wrote the link, and
/// an injected `[general] tls_domain` invalidates every distributed tg:// link. A
/// share-link is a single URI, so a control byte or a `"` in it is never legitimate.
pub fn linkTextIsSafe(s: []const u8) bool {
    if (hasControlBytes(s)) return false;
    return std.mem.indexOfScalar(u8, s, '"') == null;
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

pub const Scheme = enum { vless, vmess, trojan, shadowsocks, hysteria2, wireguard, unknown };

pub fn detectScheme(link_in: []const u8) Scheme {
    const link = std.mem.trim(u8, link_in, " \t\r\n");
    if (std.mem.startsWith(u8, link, "vless://")) return .vless;
    if (std.mem.startsWith(u8, link, "vmess://")) return .vmess;
    if (std.mem.startsWith(u8, link, "trojan://")) return .trojan;
    if (std.mem.startsWith(u8, link, "ss://")) return .shadowsocks;
    if (std.mem.startsWith(u8, link, "hysteria2://") or std.mem.startsWith(u8, link, "hy2://")) return .hysteria2;
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
    plugin: ?[]const u8 = null, // ss SIP002 `plugin=` (v2ray-plugin/obfs/shadow-tls)
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
    // hysteria2
    obfs: ?[]const u8 = null, // only "salamander" exists
    obfs_password: ?[]const u8 = null,
    /// `insecure=1` (hysteria2) / `allowInsecure=1` (vless/trojan): skip certificate
    /// verification. Hysteria servers are commonly self-signed, and unlike the Xray family
    /// the scheme has no Reality-style pinning we can emit faithfully, so the link has to
    /// say so explicitly. 3x-ui hands out `allowInsecure=1` on tls links for the same
    /// reason: dropping the flag built an outbound that verifies strictly, so `sing-box
    /// check` passed and every dial then failed on x509 behind a green "egress up".
    insecure: bool = false,
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
    // trojan is TLS by definition — the original trojan-gfw URI carries no `security=` at
    // all. Left at the "none" default it generated a PLAINTEXT trojan outbound that ships
    // the password in the clear on the first packet and can never connect, while
    // `sing-box check` passed and setup reported the egress up.
    if (scheme == .trojan) l.security = "tls";

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
    // Panels (3x-ui) emit `allowInsecure=1` for endpoints with a self-signed certificate;
    // `insecure=1` is the same flag under the hysteria2 spelling. See XrayLink.insecure.
    if (queryParam(query, "allowInsecure") orelse queryParam(query, "insecure")) |v| {
        l.insecure = std.mem.eql(u8, v, "1") or std.ascii.eqlIgnoreCase(v, "true");
    }
    return l;
}

fn jsonStr(a: std.mem.Allocator, obj: std.json.Value, key: []const u8) ?[]const u8 {
    const v = obj.object.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        // Integer-typed JSON fields (e.g. "port": 10443) are formatted into the SAME
        // arena as every other field so XrayLink's "all strings owned by `a`" contract
        // holds and nothing leaks onto the page allocator.
        .integer => |i| std.fmt.allocPrint(a, "{d}", .{i}) catch null,
        else => null,
    };
}

/// Parse vmess:// (base64-encoded JSON object).
fn parseVmess(a: std.mem.Allocator, link: []const u8) !XrayLink {
    const decoded = try base64Decode(a, link["vmess://".len..]);
    defer a.free(decoded);
    const parsed = std.json.parseFromSlice(std.json.Value, a, decoded, .{}) catch return error.BadLink;
    defer parsed.deinit();
    const o = parsed.value;
    if (o != .object) return error.BadLink;
    const add = jsonStr(a, o, "add") orelse return error.BadLink;
    const port_s = jsonStr(a, o, "port") orelse return error.BadLink;
    const id = jsonStr(a, o, "id") orelse return error.BadLink;
    var l = XrayLink{
        .scheme = .vmess,
        .name = try a.dupe(u8, jsonStr(a, o, "ps") orelse "egress"),
        .address = try a.dupe(u8, add),
        .port = std.fmt.parseInt(u16, std.mem.trim(u8, port_s, " "), 10) catch return error.BadLink,
        .id = try a.dupe(u8, id),
    };
    if (jsonStr(a, o, "aid")) |s| l.alter_id = std.fmt.parseInt(u16, std.mem.trim(u8, s, " "), 10) catch 0;
    if (jsonStr(a, o, "scy")) |s| if (s.len > 0) {
        l.cipher = try a.dupe(u8, s);
    };
    if (jsonStr(a, o, "net")) |s| l.network = try a.dupe(u8, s);
    if (jsonStr(a, o, "host")) |s| l.host = try a.dupe(u8, s);
    if (jsonStr(a, o, "path")) |s| l.path = try a.dupe(u8, s);
    if (jsonStr(a, o, "sni")) |s| l.sni = try a.dupe(u8, s);
    const tls = jsonStr(a, o, "tls") orelse "";
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
    // The query is not part of the credential/authority, but `plugin=` is KEPT: it names
    // the transport (v2ray-plugin, obfs-local, shadow-tls) the server actually speaks, and
    // our generator emits a bare shadowsocks outbound. Dropped, the link looked ordinary,
    // `sing-box check` passed, and every connection to such a server died — so it is
    // carried into validateLink as a rejection instead.
    var plugin: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, rest, '?')) |q| {
        if (queryParam(rest[q + 1 ..], "plugin")) |v| plugin = try percentDecodeAlloc(a, v);
        rest = rest[0..q];
    }
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
        .plugin = plugin,
    };
}

/// Parse `hysteria2://[auth@]host[:port][/][?params][#name]`.
///
/// Deliberately its own parser rather than another `parseUriCred` caller — the grammar
/// differs in three ways that each silently break that one:
///   * a PATH. `hysteria share` always emits the trailing `/` before `?`, and
///     splitHostPort would run parseInt over "443/" and fail the whole link.
///   * auth is OPTIONAL, while parseUriCred returns error.BadLink without an `@`.
///   * the port is optional and defaults to 443.
/// Every test written from the vless template would pass while every real link failed.
fn parseHysteria2(a: std.mem.Allocator, link: []const u8) !XrayLink {
    const prefix_len: usize = if (std.mem.startsWith(u8, link, "hysteria2://"))
        "hysteria2://".len
    else
        "hy2://".len;
    var rest = link[prefix_len..];

    var name: []const u8 = "egress";
    if (std.mem.indexOfScalar(u8, rest, '#')) |h| {
        name = try percentDecodeAlloc(a, rest[h + 1 ..]);
        rest = rest[0..h];
    }
    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, rest, '?')) |q| {
        query = rest[q + 1 ..];
        rest = rest[0..q];
    }

    // Optional auth, then an optional path we drop (the scheme carries no path semantics
    // sing-box can use; upstream emits "/" purely so the URI is well-formed).
    var authority = rest;
    var auth: ?[]const u8 = null;
    if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| {
        auth = try percentDecodeAlloc(a, authority[0..at]);
        authority = authority[at + 1 ..];
    }
    if (std.mem.indexOfScalar(u8, authority, '/')) |slash| authority = authority[0..slash];
    if (authority.len == 0) return error.BadAddress;

    const hp = try splitHysteria2HostPort(authority);

    var l = XrayLink{
        .scheme = .hysteria2,
        .name = name,
        .address = try a.dupe(u8, hp.host),
        .port = hp.port,
        // QUIC is always TLS; there is no plaintext hysteria2. Recorded so the generator
        // can key off the same field the rest of the family uses.
        .security = "tls",
    };
    if (auth) |p| l.password = p;

    if (queryParam(query, "sni")) |v| l.sni = try percentDecodeAlloc(a, v);
    if (queryParam(query, "obfs")) |v| l.obfs = try percentDecodeAlloc(a, v);
    if (queryParam(query, "obfs-password")) |v| l.obfs_password = try percentDecodeAlloc(a, v);
    if (queryParam(query, "insecure")) |v| l.insecure = std.mem.eql(u8, v, "1") or std.ascii.eqlIgnoreCase(v, "true");
    // pinSHA256 / ech are carried into validateLink as a rejection, not silently dropped.
    if (queryParam(query, "pinSHA256")) |v| l.fingerprint = try percentDecodeAlloc(a, v);
    if (queryParam(query, "ech")) |v| l.path = try percentDecodeAlloc(a, v);

    return l;
}

/// Host/port for hysteria2: the port is optional (443), and a `,`-separated port-hopping
/// list is refused here rather than truncated — sing-box wants `server_ports: ["a:b"]`
/// with a COLON, so quietly keeping the first port would build a config that connects to
/// the wrong place.
fn splitHysteria2HostPort(hp: []const u8) !struct { host: []const u8, port: u16 } {
    if (std.mem.indexOfScalar(u8, hp, ',') != null) return error.UnsupportedPortHopping;

    if (hp.len > 0 and hp[0] == '[') {
        const close = std.mem.indexOfScalar(u8, hp, ']') orelse return error.BadAddress;
        const host = hp[1..close];
        if (host.len == 0) return error.BadAddress;
        if (close + 1 >= hp.len) return .{ .host = host, .port = 443 };
        if (hp[close + 1] != ':') return error.BadAddress;
        return .{ .host = host, .port = std.fmt.parseInt(u16, hp[close + 2 ..], 10) catch return error.BadAddress };
    }

    const colon = std.mem.lastIndexOfScalar(u8, hp, ':') orelse return .{ .host = hp, .port = 443 };
    const port = std.fmt.parseInt(u16, hp[colon + 1 ..], 10) catch return error.BadAddress;
    if (colon == 0) return error.BadAddress;
    return .{ .host = hp[0..colon], .port = port };
}

/// Parse any Xray-family share link into an XrayLink (arena-owned strings).
pub fn parseXrayLink(a: std.mem.Allocator, link_in: []const u8) !XrayLink {
    const link = std.mem.trim(u8, link_in, " \t\r\n");
    return switch (detectScheme(link)) {
        .vless => parseUriCred(a, link, .vless, "vless://"),
        .trojan => parseUriCred(a, link, .trojan, "trojan://"),
        .vmess => parseVmess(a, link),
        .shadowsocks => parseSs(a, link),
        .hysteria2 => parseHysteria2(a, link),
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
    // The generator emits a TLS block for exactly "tls" and "reality"; every other value
    // (legacy `security=xtls`, a typo) falls through to a PLAINTEXT outbound that
    // `sing-box check` accepts and whose every dial then fails. `none` is deliberately
    // legal — vless+ws behind a CDN is a real plaintext-to-the-edge shape.
    const sec = l.security;
    if (!(sec.len == 0 or std.mem.eql(u8, sec, "none") or std.mem.eql(u8, sec, "tls") or std.mem.eql(u8, sec, "reality"))) {
        return std.fmt.bufPrint(buf, "unsupported security '{s}' for {s} — only tls/reality/none are supported", .{ sec, l.address }) catch "unsupported security";
    }
    // A flow (xtls-rprx-vision) without TLS is the same trap one level down: sing-box's
    // vless outbound only rejects an UNKNOWN flow name, so `check` exits 0 and the failure
    // appears per-dial inside NewVisionConn ("not a valid supported TLS connection").
    if (l.flow) |flow| {
        if (flow.len > 0 and !(std.mem.eql(u8, sec, "tls") or std.mem.eql(u8, sec, "reality"))) {
            return std.fmt.bufPrint(buf, "flow '{s}' needs security=tls or reality ({s})", .{ flow, l.address }) catch "flow without tls";
        }
    }
    if (l.scheme == .hysteria2) {
        // pinSHA256 pins sha256 of the whole DER certificate, colon-hex. sing-box's
        // nearest field pins the SPKI, base64 — a different preimage AND a different
        // encoding, not convertible without holding the certificate. Worse, a 64-char hex
        // pin decodes as valid base64 into 48 wrong bytes, so `sing-box check` passes and
        // every handshake fails. Refuse rather than emit something that looks fine.
        if (l.fingerprint != null) {
            return std.fmt.bufPrint(buf, "pinSHA256 has no sing-box equivalent ({s}) — use a link with a real certificate, or insecure=1", .{l.address}) catch "pinSHA256 unsupported";
        }
        if (l.path != null) {
            return std.fmt.bufPrint(buf, "hysteria2 ECH is not supported ({s})", .{l.address}) catch "hysteria2 ech unsupported";
        }
        if (l.obfs) |o| {
            if (!std.ascii.eqlIgnoreCase(o, "salamander")) {
                return std.fmt.bufPrint(buf, "unknown hysteria2 obfs '{s}' for {s} — only salamander exists", .{ o, l.address }) catch "unknown hysteria2 obfs";
            }
            const pw = l.obfs_password orelse "";
            if (pw.len == 0) {
                return std.fmt.bufPrint(buf, "hysteria2 obfs=salamander needs obfs-password ({s})", .{l.address}) catch "missing obfs-password";
            }
        }
        return null;
    }
    if (l.scheme == .shadowsocks) {
        // sing-box does support `plugin`/`plugin_opts`, but our generator emits neither, so
        // a v2ray-plugin/obfs/shadow-tls endpoint would get a plain shadowsocks outbound
        // and drop every connection behind a config that checks clean.
        if (l.plugin) |p| {
            if (p.len > 0) {
                const name = p[0 .. std.mem.indexOfScalar(u8, p, ';') orelse p.len];
                return std.fmt.bufPrint(buf, "shadowsocks plugin '{s}' is not supported ({s})", .{ name, l.address }) catch "shadowsocks plugin unsupported";
            }
        }
        const m = l.method orelse "";
        for (supported_ss_methods) |sm| {
            if (std.mem.eql(u8, m, sm)) return null;
        }
        return std.fmt.bufPrint(buf, "unsupported shadowsocks cipher '{s}' for {s}", .{ m, l.address }) catch "unsupported shadowsocks cipher";
    }
    return null;
}

// ── wireguard:// -> .conf transform ──────────────────────────────────────────────

test "wireguard requires an explicit tunnel address" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.BadLink, convertWireguardLink(arena.allocator(), "wireguard://PRIVATE@example.com:51820?publickey=PUBLIC"));
}

/// Convert a wireguard share-link into a WireGuard/AmneziaWG config.
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
    const private_key = try percentDecodeChecked(a, rest[0..at]);
    const hp = try splitHostPort(rest[at + 1 ..]);
    const host = try rawFieldChecked(hp.host);

    const pub_key = try percentDecodeChecked(a, queryParam(query, "publickey") orelse queryParam(query, "public_key") orelse return error.BadLink);
    const address = try percentDecodeChecked(a, queryParam(query, "address") orelse return error.BadLink);
    if (address.len == 0) return error.BadLink;
    const mtu = try rawFieldChecked(queryParam(query, "mtu") orelse "1420");

    var aw: std.Io.Writer.Allocating = .init(a);
    errdefer aw.deinit();
    const w = &aw.writer;
    try w.print("[Interface]\nPrivateKey = {s}\nAddress = {s}\nMTU = {s}\n", .{ private_key, address, mtu });
    if (queryParam(query, "dns")) |dns| try w.print("DNS = {s}\n", .{try percentDecodeChecked(a, dns)});
    // AmneziaWG obfuscation knobs (only emitted when present).
    inline for (.{ "jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4" }) |k| {
        if (queryParam(query, k)) |v| {
            var ku: [4]u8 = undefined;
            const upper = std.ascii.upperString(&ku, k);
            try w.print("{s} = {s}\n", .{ upper, try rawFieldChecked(v) });
        }
    }
    try w.print("\n[Peer]\nPublicKey = {s}\nEndpoint = {s}:{d}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n", .{ pub_key, host, hp.port });
    if (queryParam(query, "presharedkey")) |psk| try w.print("PresharedKey = {s}\n", .{try percentDecodeChecked(a, psk)});
    return try aw.toOwnedSlice();
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

test "a share link that would inject TOML is refused before it is recorded" {
    // `setup egress` writes the pasted argv verbatim into `[upstream.xray] links`, so a
    // newline in the link adds physical lines to the root-owned config.toml — an
    // `[access.users]` entry the proxy honours, or a `tls_domain` that kills every link.
    try std.testing.expect(linkTextIsSafe("vless://u@1.2.3.4:443?security=tls#name"));
    try std.testing.expect(!linkTextIsSafe("vless://u@1.2.3.4:443?security=tls#x\n[access.users]\nattacker = \"00\""));
    try std.testing.expect(!linkTextIsSafe("vless://u@1.2.3.4:443#x\r\nfoo"));
    // A bare quote alone already closes the TOML array element.
    try std.testing.expect(!linkTextIsSafe("vless://u@1.2.3.4:443#x\",\"y"));
}

test "trojan is TLS by default and an unusable security/flow combination is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var buf: [256]u8 = undefined;

    // The original trojan-gfw URI has no `security=`: at the "none" default the generator
    // emitted a PLAINTEXT trojan outbound (password in the clear, never connects).
    const trojan = try parseXrayLink(a, "trojan://pw@vpn.example:443?sni=vpn.example#t");
    try std.testing.expectEqualStrings("tls", trojan.security);
    try std.testing.expect(validateLink(trojan, &buf) == null);

    // Legacy/typo'd security values must be refused, not silently degraded to plaintext.
    const xtls = try parseXrayLink(a, "vless://u@h:443?type=tcp&security=xtls&sni=s#x");
    try std.testing.expect(validateLink(xtls, &buf) != null);

    // A flow with no TLS builds fine (`sing-box check` exits 0) and fails every dial.
    const flow_no_tls = try parseXrayLink(a, "vless://u@h:443?type=tcp&flow=xtls-rprx-vision&sni=s&fp=chrome#x");
    try std.testing.expect(validateLink(flow_no_tls, &buf) != null);
    // ...while the same flow over reality stays supported.
    const flow_reality = try parseXrayLink(a, "vless://u@h:443?type=tcp&security=reality&pbk=P&sid=S&flow=xtls-rprx-vision#x");
    try std.testing.expect(validateLink(flow_reality, &buf) == null);
    // security=none remains legal: vless+ws behind a CDN is a real deployment shape.
    const ws_plain = try parseXrayLink(a, "vless://u@h:443?type=ws&path=%2Fx#x");
    try std.testing.expect(validateLink(ws_plain, &buf) == null);
}

test "allowInsecure survives parsing instead of being dropped" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const l = try parseXrayLink(a, "trojan://pw@vpn.example:443?security=tls&sni=vpn.example&allowInsecure=1#t");
    try std.testing.expect(l.insecure);
    const strict = try parseXrayLink(a, "trojan://pw@vpn.example:443?security=tls&sni=vpn.example#t");
    try std.testing.expect(!strict.insecure);
}

test "ss plugin params are rejected, not silently dropped" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var buf: [256]u8 = undefined;

    // A v2ray-plugin (websocket+TLS) server against a bare shadowsocks outbound drops
    // every connection while `sing-box check` passes.
    const plugged = try parseXrayLink(a, "ss://YWVzLTI1Ni1nY206cHc=@vpn.example:443?plugin=v2ray-plugin%3Btls%3Bhost%3Dvpn.example#EU");
    try std.testing.expectEqualStrings("v2ray-plugin;tls;host=vpn.example", plugged.plugin.?);
    const msg = validateLink(plugged, &buf) orelse return error.TestExpectedEqual;
    try std.testing.expect(std.mem.indexOf(u8, msg, "v2ray-plugin") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, ";tls") == null); // name only, not the opts

    // A plain SIP002 link is untouched.
    const plain = try parseXrayLink(a, "ss://YWVzLTI1Ni1nY206cHc=@vpn.example:443#EU");
    try std.testing.expect(plain.plugin == null);
    try std.testing.expect(validateLink(plain, &buf) == null);
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
