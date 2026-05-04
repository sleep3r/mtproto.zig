//! IPv6 hopping command for mtbuddy.
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
const CLOUDFLARE_ENV_PATH = "/opt/mtproto-proxy/.env";

const CloudflareRecordType = enum {
    a,
    aaaa,
};

const CloudflareCredentials = struct {
    token: []const u8,
    zone: []const u8,

    fn deinit(self: *const CloudflareCredentials, allocator: std.mem.Allocator) void {
        allocator.free(self.token);
        allocator.free(self.zone);
    }
};

fn sleepSeconds(seconds: u64) void {
    const req: std.posix.timespec = .{
        .sec = @intCast(seconds),
        .nsec = 0,
    };
    _ = std.os.linux.nanosleep(&req, null);
}

fn fillRandom(bytes: []u8) bool {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = std.os.linux.getrandom(bytes[off..].ptr, bytes.len - off, 0);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return false;
                off += rc;
            },
            .INTR => continue,
            else => return false,
        }
    }
    return true;
}

pub const Ipv6Opts = struct {
    mode: Mode = .manual,
    interface: []const u8 = "eth0",
    ipv6_prefix: []const u8 = "2a01:48a0:4301:bf",
    dns_name: []const u8 = "proxy.sleep3r.ru",
    ban_threshold: u32 = 10,
};

pub const Mode = enum { manual, check, auto };

/// Run in CLI mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
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
                    sleepSeconds(60);
                } else {
                    sleepSeconds(15);
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
    if (!fillRandom(&rand_bytes)) return null;

    var ip_buf: [128]u8 = undefined;
    const ip = std.fmt.bufPrint(&ip_buf, "{s}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
        prefix,
        rand_bytes[0],
        rand_bytes[1],
        rand_bytes[2],
        rand_bytes[3],
        rand_bytes[4],
        rand_bytes[5],
        rand_bytes[6],
        rand_bytes[7],
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
        "journalctl",
        "-u",
        PROXY_SERVICE,
        "--since",
        "60 seconds ago",
        "--no-pager",
        "-q",
    }) catch return 0;
    defer r.deinit();

    var count: u32 = 0;
    var lines = std.mem.splitScalar(u8, r.stdout, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, "Handshake timeout") != null) {
            count +|= 1;
        }
    }
    return count;
}

fn updateDns(ui: *Tui, allocator: std.mem.Allocator, new_ip: []const u8, dns_name: []const u8) void {
    if (updateCloudflareRecord(ui, allocator, .aaaa, dns_name, new_ip, 30)) {
        ui.ok("DNS AAAA record updated");
    }
}

/// Update DNS A record (from update_dns.sh).
pub fn updateDnsA(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    const new_ip = args.next() orelse {
        ui.fail("Usage: mtbuddy update-dns <new_ip>");
        return;
    };

    const dns_name = "proxy.sleep3r.ru";

    ui.step("Updating DNS A record...");
    if (!updateCloudflareRecord(ui, allocator, .a, dns_name, new_ip, 60)) return;
    ui.ok("DNS A record updated successfully");
}

fn updateCloudflareRecord(
    ui: *Tui,
    allocator: std.mem.Allocator,
    record_type: CloudflareRecordType,
    dns_name: []const u8,
    new_ip: []const u8,
    ttl: u16,
) bool {
    const creds = loadCloudflareCredentials(ui, allocator) orelse return false;
    defer creds.deinit(allocator);

    const header_file = createCloudflareHeaderFile(allocator, creds.token) catch {
        ui.warn("Failed to prepare Cloudflare auth headers");
        return false;
    };
    defer allocator.free(header_file);
    defer deleteFileBestEffort(header_file);

    const maybe_record_id = findCloudflareRecordId(allocator, creds.zone, dns_name, record_type, header_file) catch {
        ui.warn("Cloudflare DNS lookup failed");
        return false;
    };
    defer if (maybe_record_id) |record_id| allocator.free(record_id);

    const payload = std.json.Stringify.valueAlloc(allocator, .{
        .type = cloudflareRecordTypeText(record_type),
        .name = dns_name,
        .content = new_ip,
        .ttl = ttl,
        .proxied = false,
    }, .{}) catch {
        ui.warn("Failed to prepare Cloudflare DNS request body");
        return false;
    };
    defer allocator.free(payload);

    const url = if (maybe_record_id) |record_id|
        std.fmt.allocPrint(allocator, "https://api.cloudflare.com/client/v4/zones/{s}/dns_records/{s}", .{ creds.zone, record_id }) catch {
            ui.warn("Failed to prepare Cloudflare DNS request URL");
            return false;
        }
    else
        std.fmt.allocPrint(allocator, "https://api.cloudflare.com/client/v4/zones/{s}/dns_records", .{creds.zone}) catch {
            ui.warn("Failed to prepare Cloudflare DNS request URL");
            return false;
        };
    defer allocator.free(url);

    const method = if (maybe_record_id != null) "PUT" else "POST";
    var response = curlJsonRequest(allocator, method, url, header_file, payload) catch {
        ui.warn("Cloudflare DNS update request failed");
        return false;
    };
    defer response.deinit();

    if (response.exit_code != 0) {
        ui.warn("Cloudflare DNS update command exited with non-zero status");
        return false;
    }
    if (!cloudflareResponseSuccess(allocator, response.stdout)) {
        ui.warn("Cloudflare API returned an unsuccessful response");
        return false;
    }
    return true;
}

fn loadCloudflareCredentials(ui: *Tui, allocator: std.mem.Allocator) ?CloudflareCredentials {
    const token = sys.readEnvFile(allocator, CLOUDFLARE_ENV_PATH, "CF_TOKEN") orelse {
        ui.warn("CF_TOKEN not set — skipping DNS update");
        return null;
    };
    errdefer allocator.free(token);

    const zone = sys.readEnvFile(allocator, CLOUDFLARE_ENV_PATH, "CF_ZONE") orelse {
        ui.warn("CF_ZONE not set — skipping DNS update");
        return null;
    };
    errdefer allocator.free(zone);

    if (token.len == 0 or zone.len == 0) {
        ui.warn("CF_TOKEN or CF_ZONE empty — skipping DNS update");
        return null;
    }

    return .{
        .token = token,
        .zone = zone,
    };
}

fn createCloudflareHeaderFile(allocator: std.mem.Allocator, token: []const u8) ![]u8 {
    var rand_bytes: [8]u8 = undefined;
    if (!fillRandom(&rand_bytes)) return error.RandomUnavailable;

    const path = try std.fmt.allocPrint(
        allocator,
        "/tmp/mtbuddy-cf-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}.headers",
        .{
            rand_bytes[0],
            rand_bytes[1],
            rand_bytes[2],
            rand_bytes[3],
            rand_bytes[4],
            rand_bytes[5],
            rand_bytes[6],
            rand_bytes[7],
        },
    );
    errdefer allocator.free(path);

    const content = try std.fmt.allocPrint(
        allocator,
        "Authorization: Bearer {s}\nContent-Type: application/json\n",
        .{token},
    );
    defer allocator.free(content);

    try sys.writeFileMode(path, content, 0o600);
    return path;
}

fn deleteFileBestEffort(path: []const u8) void {
    std.Io.Dir.deleteFileAbsolute(std.Io.Threaded.global_single_threaded.io(), path) catch {};
}

fn curlJsonRequest(
    allocator: std.mem.Allocator,
    method: []const u8,
    url: []const u8,
    header_file: []const u8,
    payload: []const u8,
) !sys.ExecResult {
    const header_arg = try std.fmt.allocPrint(allocator, "@{s}", .{header_file});
    defer allocator.free(header_arg);
    return sys.exec(allocator, &.{
        "curl",
        "-fsS",
        "-X",
        method,
        url,
        "-H",
        header_arg,
        "--data",
        payload,
    });
}

fn curlGetRequest(
    allocator: std.mem.Allocator,
    url: []const u8,
    header_file: []const u8,
) !sys.ExecResult {
    const header_arg = try std.fmt.allocPrint(allocator, "@{s}", .{header_file});
    defer allocator.free(header_arg);
    return sys.exec(allocator, &.{
        "curl",
        "-fsS",
        "-X",
        "GET",
        url,
        "-H",
        header_arg,
    });
}

fn findCloudflareRecordId(
    allocator: std.mem.Allocator,
    zone: []const u8,
    dns_name: []const u8,
    record_type: CloudflareRecordType,
    header_file: []const u8,
) !?[]u8 {
    const query_url = try std.fmt.allocPrint(
        allocator,
        "https://api.cloudflare.com/client/v4/zones/{s}/dns_records?type={s}&name={s}",
        .{ zone, cloudflareRecordTypeText(record_type), dns_name },
    );
    defer allocator.free(query_url);

    var response = try curlGetRequest(allocator, query_url, header_file);
    defer response.deinit();
    if (response.exit_code != 0) return error.CloudflareRequestFailed;

    return cloudflareExtractRecordId(allocator, response.stdout);
}

fn cloudflareRecordTypeText(record_type: CloudflareRecordType) []const u8 {
    return switch (record_type) {
        .a => "A",
        .aaaa => "AAAA",
    };
}

fn cloudflareExtractRecordId(allocator: std.mem.Allocator, response_json: []const u8) ?[]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, response_json, .{}) catch return null;
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |object| object,
        else => return null,
    };
    const result_value = root.get("result") orelse return null;

    return switch (result_value) {
        .array => |arr| blk: {
            if (arr.items.len == 0) break :blk null;
            const first = switch (arr.items[0]) {
                .object => |obj| obj,
                else => break :blk null,
            };
            const id_value = first.get("id") orelse break :blk null;
            break :blk switch (id_value) {
                .string => |id| allocator.dupe(u8, id) catch null,
                else => null,
            };
        },
        .object => |obj| blk: {
            const id_value = obj.get("id") orelse break :blk null;
            break :blk switch (id_value) {
                .string => |id| allocator.dupe(u8, id) catch null,
                else => null,
            };
        },
        else => null,
    };
}

fn cloudflareResponseSuccess(allocator: std.mem.Allocator, response_json: []const u8) bool {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, response_json, .{}) catch return false;
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |object| object,
        else => return false,
    };
    const success_value = root.get("success") orelse return false;
    return switch (success_value) {
        .bool => |ok| ok,
        else => false,
    };
}
