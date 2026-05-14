//! Explicit sensitive-output helpers for mtbuddy.
//!
//! Runtime proxy logs intentionally hide secrets. This module provides an
//! operator-invoked path for printing Telegram links from config.toml and for
//! generating fresh 32-hex secrets.

const std = @import("std");
const tui_mod = @import("tui.zig");
const sys = @import("sys.zig");
const Config = @import("proxy_config").Config;

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
    sys.generateSecret(&secret);
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

    const server = opts.server orelse cfg.public_ip orelse sys.detectPublicIp(allocator) orelse {
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

    var it = cfg.users.iterator();
    while (it.next()) |entry| {
        var secret_hex: [32]u8 = undefined;
        bytesToHex(entry.value_ptr.*, &secret_hex);

        var ee_buf: [512]u8 = undefined;
        const ee_secret = buildEeSecret(secret_hex[0..], domain, &ee_buf);

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
        ui.print("    tg:     {s}\n", .{tg_link});
        ui.print("    t.me:   {s}\n\n", .{tme_link});
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
    ui.writeRaw("  Link port defaults to [server].public_port, then [server].port.\n");
    ui.writeRaw("  Sensitive output: links contain user secrets.\n\n");
    ui.writeRaw("  mtbuddy secret\n");
    ui.writeRaw("  Prints a fresh 32-hex MTProto secret.\n\n");
}

fn buildEeSecret(secret: []const u8, tls_domain: []const u8, ee_buf: *[512]u8) []const u8 {
    var pos: usize = 0;
    @memcpy(ee_buf[pos..][0..2], "ee");
    pos += 2;

    const sec_len = @min(secret.len, ee_buf.len - pos);
    @memcpy(ee_buf[pos..][0..sec_len], secret[0..sec_len]);
    pos += sec_len;

    var domain_hex_buf: [512]u8 = undefined;
    const domain_hex = sys.domainToHex(tls_domain, &domain_hex_buf);
    const domain_len = @min(domain_hex.len, ee_buf.len - pos);
    @memcpy(ee_buf[pos..][0..domain_len], domain_hex[0..domain_len]);
    pos += domain_len;

    return ee_buf[0..pos];
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
    const ee = buildEeSecret("0123456789abcdef0123456789abcdef", "wb.ru", &buf);
    try std.testing.expectEqualStrings("ee0123456789abcdef0123456789abcdef77622e7275", ee);
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
