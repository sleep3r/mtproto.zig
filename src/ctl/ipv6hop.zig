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

fn cloudflareDnsTtl() u16 {
    return 60;
}

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
    /// Operator's allocated /64 prefix (no trailing ::). Required for rotation — there is
    /// no sensible universal default, so it stays empty until provided via --prefix.
    ipv6_prefix: []const u8 = "",
    /// Hostname whose Cloudflare A/AAAA record to update. Empty = skip DNS updates.
    dns_name: []const u8 = "",
    // F15-18: hs_timeout fires for ANY handshake-in-progress slot that stalls
    // handshake_timeout_sec after its first byte — scanners, dropped mobile clients, and
    // (per proxy.zig's own comment) upstream-side stalls like a dead DC or a stale
    // MiddleProxy secret, none of which are censorship. 10/60s is ordinary background
    // noise on a public proxy; an order of magnitude fewer false positives still catches
    // a real block (which holds the rate for the life of the ban, not one window).
    ban_threshold: u32 = 100,
};

// F15-18: a single breaching 60s window is one scanner burst or one bad minute, not a
// ban — a real TSPU block holds hs_timeout elevated continuously. Require several
// consecutive breaching windows before treating a spike as a ban.
const CONSECUTIVE_BREACHES_REQUIRED: u32 = 3;

// F15-18: even a genuine, persistent false positive (dead upstream, stale MiddleProxy
// secret) must not be allowed to tear the proxy down every ~75s forever — each rotation
// deletes the live address (killing every connection on it) and rewrites the AAAA
// record. Cap rotations to at most one per hour so the blast radius is bounded even when
// the detector keeps firing.
const ROTATION_COOLDOWN_SEC: i64 = 3600;

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
        } else {
            ui.print("Unknown option: {s}\n", .{arg});
            return error.UnknownOption;
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
        "Auto — monitor suspected blocking (rotation is manual)",
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
        "Your allocated /64 prefix without trailing :: (e.g. 2001:db8:1234:5678).",
        "",
        &prefix_buf,
    );

    const default_route = sys.exec(allocator, &.{ "ip", "-6", "route", "show", "default" }) catch null;
    defer if (default_route) |result| result.deinit();
    var detected_interface: []const u8 = "eth0";
    if (default_route) |result| {
        var tokens = std.mem.tokenizeAny(u8, result.stdout, " \t\r\n");
        while (tokens.next()) |token| {
            if (std.mem.eql(u8, token, "dev")) {
                detected_interface = tokens.next() orelse "eth0";
                break;
            }
        }
    }
    var interface_buf: [64]u8 = undefined;
    const interface = try ui.input("Network interface", "Interface carrying the routed IPv6 prefix (for example ens3).", detected_interface, &interface_buf);
    var dns_buf: [256]u8 = undefined;
    const dns = try ui.input("DNS hostname (optional)", "Cloudflare hostname whose AAAA record should be updated.", "", &dns_buf);
    var threshold_buf: [16]u8 = undefined;
    const threshold = if (mode == .auto)
        std.fmt.parseInt(u32, try ui.input("Timeout threshold", "Monitoring threshold per 60 seconds.", "100", &threshold_buf), 10) catch return error.InvalidThreshold
    else
        100;
    try execute(ui, allocator, .{ .mode = mode, .ipv6_prefix = prefix, .interface = interface, .dns_name = dns, .ban_threshold = threshold });
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
            defer if (current) |ip| allocator.free(ip);
            ui.print("\n  Current IPv6: {s}\n", .{current orelse "none"});

            const timeouts = countRecentTimeouts(allocator);
            ui.print("  Recent Handshake timeouts (60s): {d}\n\n", .{timeouts});
        },

        .manual => {
            if (opts.ipv6_prefix.len == 0) {
                ui.fail("No IPv6 /64 prefix given — pass --prefix <your-/64> (e.g. 2001:db8:1234:5678)");
                return;
            }
            ui.step("Manual IPv6 rotation...");
            const old_ip = readStateFile(allocator);
            defer if (old_ip) |ip| allocator.free(ip);
            const new_ip = addNewIpv6(allocator, opts.ipv6_prefix, opts.interface);
            if (new_ip) |ip| {
                if (old_ip) |old| removeIpv6(allocator, opts.interface, old);
                ui.ok("New IPv6 added");
                updateDns(ui, allocator, ip, opts.dns_name);
                ui.summaryBox("IPv6 Hop Complete", &.{
                    .{ .label = "New address:", .value = ip },
                    .{ .label = "Interface:", .value = opts.interface },
                    .{ .label = "DNS:", .value = if (opts.dns_name.len > 0) opts.dns_name else "(none)" },
                });
            } else {
                ui.fail("Failed to add new IPv6");
            }
        },

        .auto => {
            if (opts.ipv6_prefix.len == 0) {
                ui.fail("No IPv6 /64 prefix given — pass --prefix <your-/64> (e.g. 2001:db8:1234:5678)");
                return;
            }
            ui.info("IPv6 timeout monitor started (manual rotation only)");
            ui.print("  Ban threshold: {d} timeouts/60s\n", .{opts.ban_threshold});
            ui.info("Running in foreground. Ctrl+C to stop.");
            ui.writeRaw("\n");

            // F15-18: consecutive_breaches turns one noisy window into a requirement for
            // several in a row (see CONSECUTIVE_BREACHES_REQUIRED); last_rotation_unix
            // enforces ROTATION_COOLDOWN_SEC between rotations regardless. Both live
            // outside the loop body so they persist across iterations/arenas.
            var consecutive_breaches: u32 = 0;
            var last_rotation_unix: i64 = 0; // 0 == never rotated this run

            // Auto-hop loop — runs forever. Each iteration uses its own arena so the
            // journalctl/exec output captured for ban detection (and any rotation's dup'd
            // IP + Cloudflare JSON) is freed every cycle instead of accumulating for the
            // life of the process on the shared init arena.
            while (true) {
                var it_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
                defer it_arena.deinit();
                const a = it_arena.allocator();

                const timeouts = countRecentTimeouts(a);
                const now: i64 = @intCast(std.Io.Clock.real.now(std.Io.Threaded.global_single_threaded.io()).toSeconds());
                const decision = evaluateBanWindow(timeouts, opts.ban_threshold, consecutive_breaches, now, last_rotation_unix);
                consecutive_breaches = decision.consecutive_breaches;

                if (decision.rotate) {
                    ui.warn("Sustained handshake timeouts: check reachability externally before rotating IPv6 manually. Timeouts alone do not establish a ban.");
                    last_rotation_unix = now;
                    sleepSeconds(60);
                } else {
                    sleepSeconds(15);
                }
            }
        },
    }
}

// ── Helpers ─────────────────────────────────────────────────────

// Root-owned location (not world-writable /tmp): a local user must not be able to
// pre-create/poison this file (its content is fed to `ip -6 addr del`) or symlink-clobber
// it via root's truncating write. /opt/mtproto-proxy is created 0755 root by the installer.
const STATE_FILE = "/opt/mtproto-proxy/ipv6-current";

/// Conservative IPv6 literal sanity check: hex digits and at least two colons only. Guards
/// `ip -6 addr del <content>` against a poisoned/garbage state file deleting the wrong
/// address (e.g. the host's primary IPv6) — defense in depth atop the root-owned path.
fn looksLikeIpv6(s: []const u8) bool {
    _ = std.Io.net.IpAddress.parseIp6(s, 0) catch return false;
    return !std.mem.eql(u8, s, "::");
}

fn readStateFile(allocator: std.mem.Allocator) ?[]const u8 {
    const content = sys.readFileAllocAbsolute(allocator, STATE_FILE, 128) orelse return null;
    defer allocator.free(content);
    const trimmed = std.mem.trim(u8, content, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (trimmed.len == 0) return null;
    return allocator.dupe(u8, trimmed) catch null;
}

fn removeIpv6(allocator: std.mem.Allocator, interface: []const u8, old_ip: []const u8) void {
    // Never pass an unvalidated value to `ip -6 addr del` — a poisoned state file could
    // otherwise delete the host's primary IPv6 and cut connectivity.
    if (!looksLikeIpv6(old_ip)) return;

    var addr_buf: [128]u8 = undefined;
    const addr = std.fmt.bufPrint(&addr_buf, "{s}/64", .{old_ip}) catch return;
    _ = sys.exec(allocator, &.{ "ip", "-6", "addr", "del", addr, "dev", interface }) catch {};
}

fn hostAddress(buf: []u8, prefix: []const u8, rand_bytes: [8]u8) ![]const u8 {
    var groups = std.mem.splitScalar(u8, prefix, ':');
    var count: usize = 0;
    while (groups.next()) |group| {
        if (group.len == 0 or group.len > 4) return error.InvalidPrefix;
        _ = std.fmt.parseInt(u16, group, 16) catch return error.InvalidPrefix;
        count += 1;
    }
    if (count != 4) return error.InvalidPrefix;
    return std.fmt.bufPrint(buf, "{s}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
        prefix, rand_bytes[0], rand_bytes[1], rand_bytes[2], rand_bytes[3], rand_bytes[4], rand_bytes[5], rand_bytes[6], rand_bytes[7],
    });
}

fn addNewIpv6(allocator: std.mem.Allocator, prefix: []const u8, interface: []const u8) ?[]const u8 {
    if (interface.len == 0) return null;
    for (interface) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and c != '.') return null;
    }
    // Generate random suffix
    var rand_bytes: [8]u8 = undefined;
    if (!fillRandom(&rand_bytes)) return null;

    var ip_buf: [128]u8 = undefined;
    const ip = hostAddress(&ip_buf, prefix, rand_bytes) catch return null;

    if (!looksLikeIpv6(ip)) return null;

    var addr_buf: [192]u8 = undefined;
    const addr = std.fmt.bufPrint(&addr_buf, "{s}/64", .{ip}) catch return null;

    const r = sys.exec(allocator, &.{ "ip", "-6", "addr", "add", addr, "dev", interface }) catch return null;
    defer r.deinit();
    if (r.exit_code != 0) return null;

    var saved = false;
    defer if (!saved) removeIpv6(allocator, interface, ip);
    // Restore the current address before the proxy starts after a reboot.
    const unit = std.fmt.allocPrint(allocator, "[Unit]\nDescription=Restore mtbuddy IPv6 address\nWants=network-online.target\nAfter=network-online.target\nBefore=mtproto-proxy.service\n[Service]\nType=oneshot\nExecStart=/usr/sbin/ip -6 addr replace {s} dev {s}\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n", .{ addr, interface }) catch return null;
    defer allocator.free(unit);
    sys.writeFileMode("/etc/systemd/system/mtproto-ipv6.service", unit, 0o644) catch return null;
    const reload = sys.exec(allocator, &.{ "systemctl", "daemon-reload" }) catch return null;
    defer reload.deinit();
    if (reload.exit_code != 0) return null;
    const enable = sys.exec(allocator, &.{ "systemctl", "enable", "mtproto-ipv6.service" }) catch return null;
    defer enable.deinit();
    if (enable.exit_code != 0) return null;

    // Save state 0600 in the root-owned dir (no symlink-following hazard there).
    sys.writeFileMode(STATE_FILE, ip, 0o600) catch return null;
    saved = true;
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
        "--lines=1000",
        "-q",
    }) catch |err| {
        std.log.warn("Cannot read timeout journal: {s}; this window is unknown", .{@errorName(err)});
        return 0;
    };
    defer r.deinit();
    if (r.exit_code != 0) {
        std.log.warn("Cannot query timeout journal; this window is unknown", .{});
        return 0;
    }

    // The proxy never logs the literal "Handshake timeout"; per-event closes are at debug
    // level and filtered out by default. It DOES emit per-interval drop deltas at info,
    // e.g. "  drops: cap+=0 ... hs_timeout+=12 mp_fallback+=0 pool+=0". Sum the
    // hs_timeout deltas observed in the window — that's the real timeout count.
    return sumHandshakeTimeoutDeltas(r.stdout);
}

/// One auto-hop poll window's ban-detection outcome. Pure (no exec/journalctl/clock
/// calls) so the consecutive-window + cooldown logic is testable without mocking the
/// system — see F15-18. `consecutive_breaches` in the result replaces the caller's
/// running counter for the next call.
const BanDecision = struct {
    consecutive_breaches: u32,
    rotate: bool,
};

fn evaluateBanWindow(
    timeouts: u32,
    threshold: u32,
    consecutive_breaches_in: u32,
    now: i64,
    last_rotation_unix: i64,
) BanDecision {
    const consecutive_breaches = if (timeouts >= threshold) consecutive_breaches_in +| 1 else 0;
    const cooldown_elapsed = last_rotation_unix == 0 or now -| last_rotation_unix >= ROTATION_COOLDOWN_SEC;
    const rotate = consecutive_breaches >= CONSECUTIVE_BREACHES_REQUIRED and cooldown_elapsed;
    return .{
        // Reset the streak once we've actually acted on it, same as a non-breaching window.
        .consecutive_breaches = if (rotate) 0 else consecutive_breaches,
        .rotate = rotate,
    };
}

/// Sum every `hs_timeout+=N` delta in proxy journal output. Pure for testability.
fn sumHandshakeTimeoutDeltas(journal: []const u8) u32 {
    var count: u32 = 0;
    const marker = "hs_timeout+=";
    var search = journal;
    while (std.mem.indexOf(u8, search, marker)) |idx| {
        const after = search[idx + marker.len ..];
        var end: usize = 0;
        while (end < after.len and after[end] >= '0' and after[end] <= '9') end += 1;
        if (end > 0) {
            count +|= std.fmt.parseInt(u32, after[0..end], 10) catch 0;
        }
        search = after[end..];
    }
    return count;
}

fn updateDns(ui: *Tui, allocator: std.mem.Allocator, new_ip: []const u8, dns_name: []const u8) void {
    if (dns_name.len == 0) return; // No hostname configured — nothing to update.
    if (updateCloudflareRecord(ui, allocator, .aaaa, dns_name, new_ip, cloudflareDnsTtl())) {
        ui.ok("DNS AAAA record updated");
    }
}

/// Update DNS A record (from update_dns.sh).
pub fn updateDnsA(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    const new_ip = args.next() orelse {
        ui.fail("Usage: mtbuddy update-dns <new_ip> <hostname>");
        return;
    };

    // Hostname must be supplied by the operator — there is no shared default. (Previously
    // hardcoded to the author's personal domain, so it never worked for anyone else.)
    const dns_name = args.next() orelse {
        ui.fail("Usage: mtbuddy update-dns <new_ip> <hostname>");
        return;
    };

    ui.step("Updating DNS A record...");
    if (!updateCloudflareRecord(ui, allocator, .a, dns_name, new_ip, cloudflareDnsTtl())) return;
    ui.ok("DNS A record updated successfully");
}

fn cloudflareRecordPayload(allocator: std.mem.Allocator, record_type: CloudflareRecordType, dns_name: []const u8, new_ip: []const u8, ttl: u16, existing: bool) ![]u8 {
    if (existing) return std.json.Stringify.valueAlloc(allocator, .{ .content = new_ip }, .{});
    return std.json.Stringify.valueAlloc(allocator, .{ .type = cloudflareRecordTypeText(record_type), .name = dns_name, .content = new_ip, .ttl = ttl, .proxied = false }, .{});
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

    const maybe_record_ids = findCloudflareRecordId(allocator, creds.zone, dns_name, record_type, header_file) catch {
        ui.warn("Cloudflare DNS lookup failed");
        return false;
    };
    defer if (maybe_record_ids) |record_ids| allocator.free(record_ids);
    var records = std.mem.splitScalar(u8, maybe_record_ids orelse "", ',');
    while (records.next()) |record_id_text| {
        const maybe_record_id: ?[]const u8 = if (record_id_text.len == 0) null else record_id_text;

        const payload = cloudflareRecordPayload(allocator, record_type, dns_name, new_ip, ttl, maybe_record_id != null) catch {
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

        const method = if (maybe_record_id != null) "PATCH" else "POST";
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
            if (std.json.parseFromSlice(std.json.Value, allocator, response.stdout, .{})) |parsed| {
                defer parsed.deinit();
                if (parsed.value == .object) {
                    if (parsed.value.object.get("errors")) |errors| {
                        if (errors == .array and errors.array.items.len > 0 and errors.array.items[0] == .object) {
                            if (errors.array.items[0].object.get("message")) |message| {
                                if (message == .string) ui.warn(message.string);
                            }
                        }
                    }
                }
            } else |_| {}
            return false;
        }
    }
    return true;
}

fn loadCloudflareCredentials(ui: *Tui, allocator: std.mem.Allocator) ?CloudflareCredentials {
    const token = sys.readEnvFile(allocator, CLOUDFLARE_ENV_PATH, "CF_TOKEN") orelse {
        ui.warn("CF_TOKEN not set — skipping DNS update");
        return null;
    };
    // NOTE: errdefer does NOT run on `return null` (only on error returns), so every
    // null-return path below frees `token`/`zone` explicitly — otherwise the Cloudflare
    // bearer token leaks (and lingers un-zeroed) on each partial-config call.
    const zone = sys.readEnvFile(allocator, CLOUDFLARE_ENV_PATH, "CF_ZONE") orelse {
        allocator.free(token);
        ui.warn("CF_ZONE not set — skipping DNS update");
        return null;
    };

    if (token.len == 0 or zone.len == 0) {
        allocator.free(token);
        allocator.free(zone);
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
        "/run/mtbuddy-cf-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}.headers",
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
        "-sS",
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
        "-sS",
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
    var encoded_name: std.ArrayList(u8) = .empty;
    defer encoded_name.deinit(allocator);
    for (dns_name) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '.') {
            try encoded_name.append(allocator, c);
        } else {
            const hex = "0123456789ABCDEF";
            try encoded_name.appendSlice(allocator, &.{ '%', hex[c >> 4], hex[c & 15] });
        }
    }
    const query_url = try std.fmt.allocPrint(
        allocator,
        "https://api.cloudflare.com/client/v4/zones/{s}/dns_records?type={s}&name={s}&per_page=100",
        .{ zone, cloudflareRecordTypeText(record_type), encoded_name.items },
    );
    defer allocator.free(query_url);

    var response = try curlGetRequest(allocator, query_url, header_file);
    defer response.deinit();
    if (response.exit_code != 0) return error.CloudflareRequestFailed;
    if (!cloudflareResponseSuccess(allocator, response.stdout)) return error.CloudflareRequestFailed;

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, response.stdout, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.CloudflareRequestFailed;
    const results = parsed.value.object.get("result") orelse return error.CloudflareRequestFailed;
    if (results != .array or results.array.items.len >= 100) return error.CloudflareRequestFailed;
    var ids: std.ArrayList(u8) = .empty;
    errdefer ids.deinit(allocator);
    for (results.array.items) |record| {
        if (record != .object) return error.CloudflareRequestFailed;
        const id = record.object.get("id") orelse return error.CloudflareRequestFailed;
        if (id != .string or id.string.len == 0 or std.mem.indexOfScalar(u8, id.string, ',') != null) return error.CloudflareRequestFailed;
        if (ids.items.len > 0) try ids.append(allocator, ',');
        try ids.appendSlice(allocator, id.string);
    }
    if (ids.items.len == 0) return null;
    return try ids.toOwnedSlice(allocator);
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

// ── Tests ───────────────────────────────────────────────────────

test "looksLikeIpv6 accepts valid literals and rejects junk" {
    try std.testing.expect(!looksLikeIpv6("::::"));
    try std.testing.expect(!looksLikeIpv6("::"));
    try std.testing.expect(looksLikeIpv6("2001:db8::1"));
    try std.testing.expect(looksLikeIpv6("2a01:48a0:4301:bf:1122:3344:5566:7788"));
    try std.testing.expect(!looksLikeIpv6(""));
    try std.testing.expect(!looksLikeIpv6("eth0"));
    try std.testing.expect(!looksLikeIpv6("192.168.1.1")); // dots, not hex/colon
    try std.testing.expect(!looksLikeIpv6("2001:db8::1; rm -rf /")); // shell metachars
    try std.testing.expect(!looksLikeIpv6("nocolons"));
}

test "sumHandshakeTimeoutDeltas sums hs_timeout deltas, ignores other fields" {
    const journal =
        \\Jun 10 conn stats: active=5/512 hs_inflight=0
        \\Jun 10   drops: cap+=0 sat+=1 rate+=0 flood_guard+=0 hs_budget+=2 hs_timeout+=7 mp_fallback+=0 pool+=0
        \\Jun 10   drops: cap+=0 sat+=0 rate+=0 flood_guard+=0 hs_budget+=0 hs_timeout+=5 mp_fallback+=1 pool+=0
    ;
    try std.testing.expectEqual(@as(u32, 12), sumHandshakeTimeoutDeltas(journal));
    try std.testing.expectEqual(@as(u32, 0), sumHandshakeTimeoutDeltas("no markers here\nhs_budget+=99"));
}

test "cloudflareExtractRecordId reads id from array and object results" {
    const a = std.testing.allocator;
    {
        const id = cloudflareExtractRecordId(a, "{\"result\":[{\"id\":\"abc123\",\"name\":\"x\"}]}") orelse return error.TestUnexpectedNull;
        defer a.free(id);
        try std.testing.expectEqualStrings("abc123", id);
    }
    {
        const id = cloudflareExtractRecordId(a, "{\"result\":{\"id\":\"def456\"}}") orelse return error.TestUnexpectedNull;
        defer a.free(id);
        try std.testing.expectEqualStrings("def456", id);
    }
    try std.testing.expect(cloudflareExtractRecordId(a, "{\"result\":[]}") == null);
    try std.testing.expect(cloudflareExtractRecordId(a, "not json") == null);
}

test "cloudflareResponseSuccess parses the success flag" {
    const a = std.testing.allocator;
    try std.testing.expect(cloudflareResponseSuccess(a, "{\"success\":true,\"result\":{}}"));
    try std.testing.expect(!cloudflareResponseSuccess(a, "{\"success\":false}"));
    try std.testing.expect(!cloudflareResponseSuccess(a, "{}"));
    try std.testing.expect(!cloudflareResponseSuccess(a, "garbage"));
}

test "cloudflareRecordTypeText" {
    try std.testing.expectEqualStrings("A", cloudflareRecordTypeText(.a));
    try std.testing.expectEqualStrings("AAAA", cloudflareRecordTypeText(.aaaa));
}

test "Cloudflare payloads preserve existing settings and use valid TTL on creation" {
    for ([_]CloudflareRecordType{ .a, .aaaa }) |kind| {
        const payload = try cloudflareRecordPayload(std.testing.allocator, kind, "proxy.example", "2001:db8::1", cloudflareDnsTtl(), false);
        defer std.testing.allocator.free(payload);
        const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, payload, .{});
        defer parsed.deinit();
        try std.testing.expectEqual(@as(i64, 60), parsed.value.object.get("ttl").?.integer);
        try std.testing.expectEqualStrings(cloudflareRecordTypeText(kind), parsed.value.object.get("type").?.string);
    }
    const patch = try cloudflareRecordPayload(std.testing.allocator, .aaaa, "proxy.example", "2001:db8::1", 60, true);
    defer std.testing.allocator.free(patch);
    try std.testing.expectEqualStrings("{\"content\":\"2001:db8::1\"}", patch);
}

test "IPv6 host address requires four prefix groups and preserves the suffix" {
    var buf: [128]u8 = undefined;
    const suffix = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
    try std.testing.expectEqualStrings("2001:db8:1234:5678:0001:0203:0405:0607", try hostAddress(&buf, "2001:db8:1234:5678", suffix));
    try std.testing.expectError(error.InvalidPrefix, hostAddress(&buf, "2001:db8::", suffix));
    try std.testing.expectError(error.InvalidPrefix, hostAddress(&buf, "2001:db8:1234:xyz", suffix));
}

test "Cloudflare DNS TTL meets the provider minimum" {
    try std.testing.expectEqual(@as(u16, 60), cloudflareDnsTtl());
}
