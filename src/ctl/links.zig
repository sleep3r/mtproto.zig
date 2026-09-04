//! Explicit sensitive-output helpers for mtbuddy.
//!
//! Runtime proxy logs intentionally hide secrets. This module provides an
//! operator-invoked path for printing Telegram links from config.toml and for
//! generating fresh 32-hex secrets.

const std = @import("std");
const tui_mod = @import("tui.zig");
const sys = @import("sys.zig");
const Config = @import("proxy_config").Config;
const web_capability = @import("web_capability");

const Tui = tui_mod.Tui;

const installed_config_path = "/opt/mtproto-proxy/config.toml";
const local_config_path = "config.toml";

const LinkOpts = struct {
    config_path: ?[]const u8 = null,
    server: ?[]const u8 = null,
    port: ?u16 = null,
    domain: ?[]const u8 = null,
};

pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    var opts = LinkOpts{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--config") or std.mem.eql(u8, arg, "-c")) {
            opts.config_path = args.next() orelse {
                ui.fail("Missing value for --config");
                return;
            };
        } else if (std.mem.eql(u8, arg, "--server") or std.mem.eql(u8, arg, "-s")) {
            opts.server = args.next() orelse {
                ui.fail("Missing value for --server");
                return;
            };
        } else if (std.mem.eql(u8, arg, "--port") or std.mem.eql(u8, arg, "-p")) {
            const raw = args.next() orelse {
                ui.fail("Missing value for --port");
                return;
            };
            opts.port = std.fmt.parseInt(u16, raw, 10) catch {
                ui.fail("Invalid --port value");
                return;
            };
        } else if (std.mem.eql(u8, arg, "--domain") or std.mem.eql(u8, arg, "-d")) {
            opts.domain = args.next() orelse {
                ui.fail("Missing value for --domain");
                return;
            };
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printLinksHelp(ui);
            return;
        } else {
            ui.print("  unknown links option: {s}\n", .{arg});
            printLinksHelp(ui);
            return;
        }
    }

    try printLinks(ui, allocator, opts);
}

pub fn runSecret(ui: *Tui) void {
    var secret: [32]u8 = undefined;
    sys.generateSecret(&secret) catch {
        ui.fail(ui.str(.install_secret_gen_failed));
        return;
    };
    ui.print("{s}\n", .{secret[0..]});
}

fn printLinks(ui: *Tui, allocator: std.mem.Allocator, opts: LinkOpts) !void {
    const config_path = opts.config_path orelse defaultConfigPath();

    var cfg = Config.loadFromFile(allocator, config_path) catch |err| {
        ui.print("  failed to load {s}: {any}\n", .{ config_path, err });
        return error.ConfigLoadFailed;
    };
    defer cfg.deinit(allocator);

    if (cfg.users.count() == 0) {
        ui.fail("No users found in [access.users]");
        return error.NoUsersConfigured;
    }

    // Under `[web].only` the proxy answers no direct MTProto at all, so the public
    // address is not part of any link it can hand out — and a host reached only through
    // a CDN may have none to detect. Not having one stops being fatal there.
    const web_only = cfg.web.onlyActive();
    const detected = if (opts.server == null and cfg.public_ip == null) sys.detectPublicIp(allocator) else null;
    defer if (detected) |owned| allocator.free(owned);
    const server = opts.server orelse cfg.public_ip orelse detected orelse blk: {
        if (web_only) break :blk "";
        ui.fail("Could not determine public server address");
        ui.hint("Pass --server <ip-or-domain>, or set [server].public_ip in config.toml");
        return error.PublicAddressUnavailable;
    };
    const port = opts.port orelse cfg.publicLinkPort();
    const domain = opts.domain orelse cfg.tls_domain;

    ui.section("MTProto links");
    ui.info(config_path);
    ui.warn("Sensitive output: these links contain user secrets.");
    ui.writeRaw("\n");

    // WEB links are only emitted once the relay is actually configured — a link whose
    // domain does not serve the bridge is worse than no link at all. The hostname is
    // normalized exactly as Telegram Desktop normalizes it, because the bridge
    // capability is an HMAC over that canonical string.
    var web_domain_buf: [web_capability.max_host_len]u8 = undefined;
    const web_domain: ?[]const u8 = blk: {
        if (!cfg.web.enabled) break :blk null;
        const raw = cfg.web.domain orelse break :blk null;
        break :blk web_capability.normalizeHost(raw, &web_domain_buf) catch {
            ui.warn("[web].domain is not a hostname Telegram Desktop accepts — skipping WEB links.");
            break :blk null;
        };
    };

    if (web_only) {
        ui.info("[web].only is on: the proxy masks direct MTProto, so only WEB links are printed.");
        if (web_domain == null) {
            ui.fail("[web].only is on but [web].domain is not a hostname Telegram Desktop accepts — there is no working link to print.");
            ui.hint("Fix [web].domain, or turn WEB-only off with: sudo mtbuddy setup web --no-only");
            return error.WebOnlyWithoutDomain;
        }
    }

    var it = cfg.users.iterator();
    while (it.next()) |entry| {
        var secret_hex: [32]u8 = undefined;
        bytesToHex(entry.value_ptr.*, &secret_hex);

        var ee_buf: [576]u8 = undefined;
        const ee_secret = buildEeSecret(secret_hex[0..], domain, &ee_buf) catch {
            ui.fail("Cannot encode FakeTLS link: secret or domain is invalid or too long.");
            return;
        };

        var encoded_server_buf: [768]u8 = undefined;
        const safe_server = encodeServerForProxyLink(server, &encoded_server_buf);

        var tg_buf: [1024]u8 = undefined;
        const tg_link = std.fmt.bufPrint(&tg_buf, "tg://proxy?server={s}&port={d}&secret={s}", .{
            safe_server,
            port,
            ee_secret,
        }) catch continue;

        var tme_buf: [1024]u8 = undefined;
        const tme_link = std.fmt.bufPrint(&tme_buf, "https://t.me/proxy?server={s}&port={d}&secret={s}", .{
            safe_server,
            port,
            ee_secret,
        }) catch continue;

        ui.print("  {s}:\n", .{entry.key_ptr.*});
        ui.print("    secret: {s}\n", .{secret_hex[0..]});
        // Same rule as the dd block below, for the same reason: under `[web].only` the
        // proxy masks a FakeTLS handshake instead of serving it, so an ee link would be
        // a link that silently never connects.
        if (!web_only) {
            ui.print("    fakeTLS tg:   {s}\n", .{tg_link});
            ui.print("    fakeTLS t.me: {s}\n", .{tme_link});
        }

        // dd (non-TLS, DPI-fingerprintable) links are printed ONLY when the
        // operator has explicitly enabled the dd transport. With the secure
        // default (fake_tls_only = true) the proxy rejects dd, so printing dd
        // links would hand out non-working, fingerprintable links.
        if (!cfg.fake_tls_only and !web_only) {
            var dd_buf: [128]u8 = undefined;
            const dd_secret = buildDdSecret(secret_hex[0..], &dd_buf);

            var tg_dd_buf: [1024]u8 = undefined;
            const tg_dd_link = std.fmt.bufPrint(&tg_dd_buf, "tg://proxy?server={s}&port={d}&secret={s}", .{
                safe_server,
                port,
                dd_secret,
            }) catch continue;

            var tme_dd_buf: [1024]u8 = undefined;
            const tme_dd_link = std.fmt.bufPrint(&tme_dd_buf, "https://t.me/proxy?server={s}&port={d}&secret={s}", .{
                safe_server,
                port,
                dd_secret,
            }) catch continue;

            ui.print("    dd tg:        {s}\n", .{tg_dd_link});
            ui.print("    dd t.me:      {s}\n", .{tme_dd_link});
        }

        // WEB links (Telegram Desktop 7.1+). Same 16-byte user secret, but carried as
        // `dd…`: the client reports an `ee` FakeTLS secret as Unsupported for a WEB
        // proxy, because the relay is a raw byte pipe that adds no TLS-emulation record.
        // Port 443 is implicit and must not appear in the link.
        if (web_domain) |web_host| {
            var web_secret_buf: [128]u8 = undefined;
            const web_secret = buildDdSecret(secret_hex[0..], &web_secret_buf);

            var tg_web_buf: [1024]u8 = undefined;
            const tg_web_link = std.fmt.bufPrint(&tg_web_buf, "tg://webproxy?server={s}&secret={s}", .{
                web_host,
                web_secret,
            }) catch continue;

            var tme_web_buf: [1024]u8 = undefined;
            const tme_web_link = std.fmt.bufPrint(&tme_web_buf, "https://t.me/webproxy?server={s}&secret={s}", .{
                web_host,
                web_secret,
            }) catch continue;

            ui.print("    WEB tg:       {s}\n", .{tg_web_link});
            ui.print("    WEB t.me:     {s}\n", .{tme_web_link});
        }
        ui.print("\n", .{});
    }
}

fn defaultConfigPath() []const u8 {
    if (sys.fileExists(installed_config_path)) return installed_config_path;
    return local_config_path;
}

fn printLinksHelp(ui: *Tui) void {
    ui.writeRaw("\n");
    ui.writeRaw("  mtbuddy links [--config <path>] [--server <host>] [--port <port>] [--domain <tls-domain>]\n\n");
    ui.writeRaw("  Prints tg:// and t.me proxy links from [access.users].\n");
    ui.writeRaw("  Adds tg://webproxy links when [web] is enabled (Telegram Desktop 7.1+).\n");
    ui.writeRaw("  With [web].only set, prints the WEB links alone — the others no longer connect.\n");
    ui.writeRaw("  Link port defaults to [server].public_port, then [server].port.\n");
    ui.writeRaw("  Sensitive output: links contain user secrets.\n\n");
    ui.writeRaw("  mtbuddy secret\n");
    ui.writeRaw("  Prints a fresh 32-hex MTProto secret.\n\n");
}

fn buildEeSecret(secret: []const u8, tls_domain: []const u8, ee_buf: []u8) ![]const u8 {
    if (secret.len != 32 or tls_domain.len == 0 or tls_domain.len > 253) return error.InvalidSecretOrDomain;
    if (ee_buf.len < 34) return error.NoSpaceLeft;
    var pos: usize = 0;
    @memcpy(ee_buf[pos..][0..2], "ee");
    pos += 2;

    const sec_len = secret.len;
    @memcpy(ee_buf[pos..][0..sec_len], secret[0..sec_len]);
    pos += sec_len;

    const domain_hex = try sys.domainToHex(tls_domain, ee_buf[pos..]);
    pos += domain_hex.len;

    return ee_buf[0..pos];
}

fn buildDdSecret(secret: []const u8, dd_buf: []u8) []const u8 {
    var pos: usize = 0;
    @memcpy(dd_buf[pos..][0..2], "dd");
    pos += 2;

    // Strip surrounding quotes so a config-derived (possibly quoted) secret never
    // produces a malformed dd"..." link. Mirrors install.zig's buildDdSecret to
    // keep the two copies behaviourally identical (no quote-handling divergence).
    var clean_secret = secret;
    if (clean_secret.len >= 2 and clean_secret[0] == '"' and clean_secret[clean_secret.len - 1] == '"') {
        clean_secret = clean_secret[1 .. clean_secret.len - 1];
    }

    const sec_len = @min(clean_secret.len, dd_buf.len - pos);
    @memcpy(dd_buf[pos..][0..sec_len], clean_secret[0..sec_len]);
    pos += sec_len;

    return dd_buf[0..pos];
}

fn encodeServerForProxyLink(server: []const u8, out: []u8) []const u8 {
    var required_len: usize = 0;
    for (server) |c| {
        required_len += if (c == ':' or c == '[' or c == ']') 3 else 1;
    }
    if (required_len > out.len) return server;

    var pos: usize = 0;
    for (server) |c| {
        if (c == ':') {
            @memcpy(out[pos..][0..3], "%3A");
            pos += 3;
        } else if (c == '[') {
            @memcpy(out[pos..][0..3], "%5B");
            pos += 3;
        } else if (c == ']') {
            @memcpy(out[pos..][0..3], "%5D");
            pos += 3;
        } else {
            out[pos] = c;
            pos += 1;
        }
    }
    return out[0..pos];
}

fn bytesToHex(bytes: [16]u8, out: *[32]u8) void {
    const hex = "0123456789abcdef";
    for (bytes, 0..) |byte, idx| {
        out[idx * 2] = hex[byte >> 4];
        out[idx * 2 + 1] = hex[byte & 0x0f];
    }
}

test "links - ee secret includes domain hex" {
    var buf: [512]u8 = undefined;
    const ee = try buildEeSecret("0123456789abcdef0123456789abcdef", "wb.ru", &buf);
    try std.testing.expectEqualStrings("ee0123456789abcdef0123456789abcdef77622e7275", ee);
}

test "links - long domains are complete or explicitly rejected" {
    const secret = "0123456789abcdef0123456789abcdef";
    const domain = [_]u8{'a'} ** 253;
    var full: [576]u8 = undefined;
    const result = try buildEeSecret(secret, &domain, &full);
    try std.testing.expectEqual(@as(usize, 540), result.len);
    var small: [512]u8 = undefined;
    try std.testing.expectError(error.NoSpaceLeft, buildEeSecret(secret, &domain, &small));
}

test "links - dd secret uses secure transport prefix" {
    var buf: [128]u8 = undefined;
    const dd = buildDdSecret("0123456789abcdef0123456789abcdef", &buf);
    try std.testing.expectEqualStrings("dd0123456789abcdef0123456789abcdef", dd);
}

test "links - dd secret strips surrounding quotes (no malformed link)" {
    var buf: [128]u8 = undefined;
    const dd = buildDdSecret("\"0123456789abcdef0123456789abcdef\"", &buf);
    try std.testing.expectEqualStrings("dd0123456789abcdef0123456789abcdef", dd);
}

test "links - server escaping preserves IPv4 and escapes IPv6 punctuation" {
    var ipv4_buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("1.2.3.4", encodeServerForProxyLink("1.2.3.4", &ipv4_buf));

    var ipv6_buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("%5B2001%3Adb8%3A%3A1%5D", encodeServerForProxyLink("[2001:db8::1]", &ipv6_buf));
}

test "links - bytesToHex" {
    var out: [32]u8 = undefined;
    bytesToHex(.{
        0x00, 0x01, 0x23, 0x45,
        0x67, 0x89, 0xab, 0xcd,
        0xef, 0xfe, 0xdc, 0xba,
        0x98, 0x76, 0x54, 0x32,
    }, &out);
    try std.testing.expectEqualStrings("000123456789abcdeffedcba98765432", out[0..]);
}
