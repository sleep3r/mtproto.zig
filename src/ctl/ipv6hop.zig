//! IPv6 hopping command for mtproto-ctl.
//!
//! Ports ipv6-hop.sh (159 lines bash) — rotates IPv6 address when ban
//! detected. TSPU can't ban /64 subnets without breaking legitimate traffic.
//!
//! Also includes update_dns.sh (46 lines) — Cloudflare DNS A record update.

const std = @import("std");
const tui_mod = @import("tui.zig");
const i18n = @import("i18n.zig");
const sys = @import("sys.zig");

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;
const SummaryLine = tui_mod.SummaryLine;

const PROXY_SERVICE = "mtproto-proxy";

pub const Ipv6Opts = struct {
    mode: Mode = .manual,
    interface: []const u8 = "eth0",
    ipv6_prefix: []const u8 = "2a01:48a0:4301:bf",
    dns_name: []const u8 = "proxy.sleep3r.ru",
    ban_threshold: u32 = 10,
};

pub const Mode = enum { manual, check, auto };

/// Run in CLI mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.ArgIterator) !void {
    var opts = Ipv6Opts{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--check")) {
            opts.mode = .check;
        } else if (std.mem.eql(u8, arg, "--auto")) {
            opts.mode = .auto;
        } else if (std.mem.eql(u8, arg, "--prefix")) {
            if (args.next()) |val| opts.ipv6_prefix = val;
        } else if (std.mem.eql(u8, arg, "--interface")) {
            if (args.next()) |val| opts.interface = val;
        } else if (std.mem.eql(u8, arg, "--dns")) {
            if (args.next()) |val| opts.dns_name = val;
        } else if (std.mem.eql(u8, arg, "--threshold")) {
            if (args.next()) |val| {
                opts.ban_threshold = std.fmt.parseInt(u32, val, 10) catch 10;
            }
        }
    }
    try execute(ui, allocator, opts);
}

/// Run in interactive mode.
pub fn runInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    ui.section(i18n.get(ui.lang, .menu_ipv6_hop));

    const mode_choice = try ui.menu("IPv6 hop mode", &.{
        "Manual — rotate now",
        "Check — show current status",
        "Auto — loop, rotate on ban detection",
    });

    const mode: Mode = switch (mode_choice) {
        0 => .manual,
        1 => .check,
        2 => .auto,
        else => .manual,
    };

    var prefix_buf: [64]u8 = undefined;
    const prefix = try ui.input(
        "IPv6 /64 prefix",
        "Your allocated /64 prefix without trailing ::.",
        "2a01:48a0:4301:bf",
        &prefix_buf,
    );

    try execute(ui, allocator, .{ .mode = mode, .ipv6_prefix = prefix });
}

fn execute(ui: *Tui, allocator: std.mem.Allocator, opts: Ipv6Opts) !void {
    if (!sys.isRoot()) {
        ui.fail(i18n.get(ui.lang, .error_not_root));
        return;
    }

    switch (opts.mode) {
        .check => {
            // Show current status
            const current = readStateFile(allocator);
            ui.print("\n  Current IPv6: {s}\n", .{current orelse "none"});

            const timeouts = countRecentTimeouts(allocator);
            ui.print("  Recent Handshake timeouts (60s): {d}\n\n", .{timeouts});
        },

        .manual => {
            ui.step("Manual IPv6 rotation...");
            removeOldIpv6(allocator, opts.interface);
            const new_ip = addNewIpv6(allocator, opts.ipv6_prefix, opts.interface);
            if (new_ip) |ip| {
                ui.ok("New IPv6 added");
                updateDns(ui, allocator, ip, opts.dns_name);
                ui.summaryBox("IPv6 Hop Complete", &.{
                    .{ .label = "New address:", .value = ip },
                    .{ .label = "Interface:", .value = opts.interface },
                    .{ .label = "DNS:", .value = opts.dns_name },
                });
            } else {
                ui.fail("Failed to add new IPv6");
            }
        },

        .auto => {
            ui.info("Auto-hop mode started");
            ui.print("  Ban threshold: {d} timeouts/60s\n", .{opts.ban_threshold});
            ui.info("Running in foreground. Ctrl+C to stop.");
            ui.writeRaw("\n");

            // Auto-hop loop — runs forever
            while (true) {
                const timeouts = countRecentTimeouts(allocator);
                if (timeouts >= opts.ban_threshold) {
                    ui.warn("Ban detected — rotating IPv6...");
                    removeOldIpv6(allocator, opts.interface);
                    const new_ip = addNewIpv6(allocator, opts.ipv6_prefix, opts.interface);
                    if (new_ip) |ip| {
                        ui.ok("Hopped to new IPv6");
                        updateDns(ui, allocator, ip, opts.dns_name);
                        ui.stepOk("Hop complete, sleeping 60s", ip);
                    }
                    std.Thread.sleep(60 * std.time.ns_per_s);
                } else {
                    std.Thread.sleep(15 * std.time.ns_per_s);
                }
            }
        },
    }
}

// ── Helpers ─────────────────────────────────────────────────────

const STATE_FILE = "/tmp/mtproto-ipv6-current";

fn readStateFile(allocator: std.mem.Allocator) ?[]const u8 {
    const r = sys.exec(allocator, &.{ "cat", STATE_FILE }) catch return null;
    defer r.deinit();
    const trimmed = std.mem.trim(u8, r.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (trimmed.len == 0) return null;
    return allocator.dupe(u8, trimmed) catch null;
}

fn removeOldIpv6(allocator: std.mem.Allocator, interface: []const u8) void {
    const old_ip = readStateFile(allocator) orelse return;
    defer allocator.free(old_ip);

    var addr_buf: [128]u8 = undefined;
    const addr = std.fmt.bufPrint(&addr_buf, "{s}/64", .{old_ip}) catch return;
    _ = sys.exec(allocator, &.{ "ip", "-6", "addr", "del", addr, "dev", interface }) catch {};
}

fn addNewIpv6(allocator: std.mem.Allocator, prefix: []const u8, interface: []const u8) ?[]const u8 {
    // Generate random suffix
    var rand_bytes: [8]u8 = undefined;
    std.crypto.random.bytes(&rand_bytes);

    var ip_buf: [128]u8 = undefined;
    const ip = std.fmt.bufPrint(&ip_buf, "{s}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
        prefix,
        rand_bytes[0], rand_bytes[1],
        rand_bytes[2], rand_bytes[3],
        rand_bytes[4], rand_bytes[5],
        rand_bytes[6], rand_bytes[7],
    }) catch return null;

    var addr_buf: [192]u8 = undefined;
    const addr = std.fmt.bufPrint(&addr_buf, "{s}/64", .{ip}) catch return null;

    const r = sys.exec(allocator, &.{ "ip", "-6", "addr", "add", addr, "dev", interface }) catch return null;
    defer r.deinit();
    if (r.exit_code != 0) return null;

    // Save state using native I/O
    sys.writeFile(STATE_FILE, ip) catch {};

    return allocator.dupe(u8, ip) catch null;
}

fn countRecentTimeouts(allocator: std.mem.Allocator) u32 {
    const r = sys.exec(allocator, &.{
        "bash", "-c",
        "journalctl -u " ++ PROXY_SERVICE ++ " --since '60 seconds ago' --no-pager -q 2>/dev/null | grep -c 'Handshake timeout' || echo 0",
    }) catch return 0;
    defer r.deinit();
    const trimmed = std.mem.trim(u8, r.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
    return std.fmt.parseInt(u32, trimmed, 10) catch 0;
}

fn updateDns(ui: *Tui, allocator: std.mem.Allocator, new_ip: []const u8, dns_name: []const u8) void {
    // Load CF credentials: check env first, then .env file
    const cf_token = std.posix.getenv("CF_TOKEN") orelse
        sys.readEnvFile(allocator, "/opt/mtproto-proxy/.env", "CF_TOKEN") orelse {
        ui.warn("CF_TOKEN not set — skipping DNS update");
        return;
    };
    const cf_zone = std.posix.getenv("CF_ZONE") orelse
        sys.readEnvFile(allocator, "/opt/mtproto-proxy/.env", "CF_ZONE") orelse {
        ui.warn("CF_ZONE not set — skipping DNS update");
        return;
    };

    if (cf_token.len == 0 or cf_zone.len == 0) {
        ui.warn("CF_TOKEN or CF_ZONE empty — skipping DNS update");
        return;
    }

    // Get record ID
    var get_cmd_buf: [512]u8 = undefined;
    const get_cmd = std.fmt.bufPrint(&get_cmd_buf,
        "curl -s -X GET 'https://api.cloudflare.com/client/v4/zones/{s}/dns_records?type=AAAA&name={s}' " ++
        "-H 'Authorization: Bearer {s}' -H 'Content-Type: application/json' | " ++
        "grep -oE '\"id\":\"[^\"]+\"' | head -1 | cut -d'\"' -f4",
    .{ cf_zone, dns_name, cf_token }) catch return;

    const id_result = sys.exec(allocator, &.{ "bash", "-c", get_cmd }) catch return;
    defer id_result.deinit();
    const record_id = std.mem.trim(u8, id_result.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });

    // Create or update
    var dns_cmd_buf: [1024]u8 = undefined;
    if (record_id.len == 0) {
        const dns_cmd = std.fmt.bufPrint(&dns_cmd_buf,
            "curl -s -X POST 'https://api.cloudflare.com/client/v4/zones/{s}/dns_records' " ++
            "-H 'Authorization: Bearer {s}' -H 'Content-Type: application/json' " ++
            "--data '{{\"type\":\"AAAA\",\"name\":\"{s}\",\"content\":\"{s}\",\"ttl\":30,\"proxied\":false}}' > /dev/null",
        .{ cf_zone, cf_token, dns_name, new_ip }) catch return;
        _ = sys.exec(allocator, &.{ "bash", "-c", dns_cmd }) catch {};
    } else {
        const dns_cmd = std.fmt.bufPrint(&dns_cmd_buf,
            "curl -s -X PUT 'https://api.cloudflare.com/client/v4/zones/{s}/dns_records/{s}' " ++
            "-H 'Authorization: Bearer {s}' -H 'Content-Type: application/json' " ++
            "--data '{{\"type\":\"AAAA\",\"name\":\"{s}\",\"content\":\"{s}\",\"ttl\":30,\"proxied\":false}}' > /dev/null",
        .{ cf_zone, record_id, cf_token, dns_name, new_ip }) catch return;
        _ = sys.exec(allocator, &.{ "bash", "-c", dns_cmd }) catch {};
    }

    ui.ok("DNS AAAA record updated");
}

/// Update DNS A record (from update_dns.sh).
pub fn updateDnsA(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.ArgIterator) !void {
    const new_ip = args.next() orelse {
        ui.fail("Usage: mtproto-ctl update-dns <new_ip>");
        return;
    };

    const dns_name = "proxy.sleep3r.ru";

    // Load .env natively (child shell env doesn't propagate to parent)
    const cf_token = std.posix.getenv("CF_TOKEN") orelse
        sys.readEnvFile(allocator, "/opt/mtproto-proxy/.env", "CF_TOKEN") orelse {
        ui.warn("CF_TOKEN not set — skipping DNS update");
        return;
    };
    const cf_zone = std.posix.getenv("CF_ZONE") orelse
        sys.readEnvFile(allocator, "/opt/mtproto-proxy/.env", "CF_ZONE") orelse {
        ui.warn("CF_ZONE not set — skipping DNS update");
        return;
    };

    ui.step("Updating DNS A record...");

    var get_buf: [512]u8 = undefined;
    const get_cmd = std.fmt.bufPrint(&get_buf,
        "curl -s -X GET 'https://api.cloudflare.com/client/v4/zones/{s}/dns_records?type=A&name={s}' " ++
        "-H 'Authorization: Bearer {s}' -H 'Content-Type: application/json' | " ++
        "grep -oE '\"id\":\"[^\"]+\"' | head -1 | cut -d'\"' -f4",
    .{ cf_zone, dns_name, cf_token }) catch return;

    const id_r = sys.exec(allocator, &.{ "bash", "-c", get_cmd }) catch return;
    defer id_r.deinit();
    const record_id = std.mem.trim(u8, id_r.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });

    var cmd_buf: [1024]u8 = undefined;
    if (record_id.len == 0) {
        const cmd = std.fmt.bufPrint(&cmd_buf,
            "curl -s -X POST 'https://api.cloudflare.com/client/v4/zones/{s}/dns_records' " ++
            "-H 'Authorization: Bearer {s}' -H 'Content-Type: application/json' " ++
            "--data '{{\"type\":\"A\",\"name\":\"{s}\",\"content\":\"{s}\",\"ttl\":60,\"proxied\":false}}' > /dev/null",
        .{ cf_zone, cf_token, dns_name, new_ip }) catch return;
        _ = sys.exec(allocator, &.{ "bash", "-c", cmd }) catch {};
    } else {
        const cmd = std.fmt.bufPrint(&cmd_buf,
            "curl -s -X PUT 'https://api.cloudflare.com/client/v4/zones/{s}/dns_records/{s}' " ++
            "-H 'Authorization: Bearer {s}' -H 'Content-Type: application/json' " ++
            "--data '{{\"type\":\"A\",\"name\":\"{s}\",\"content\":\"{s}\",\"ttl\":60,\"proxied\":false}}' > /dev/null",
        .{ cf_zone, record_id, cf_token, dns_name, new_ip }) catch return;
        _ = sys.exec(allocator, &.{ "bash", "-c", cmd }) catch {};
    }

    ui.ok("DNS A record updated successfully");
}
