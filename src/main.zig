//! MTProto Proxy — Zig implementation
//!
//! A production-grade Telegram MTProto proxy supporting TLS-fronted
//! obfuscated connections to Telegram datacenters.

const std = @import("std");
const builtin = @import("builtin");
const constants = @import("protocol/constants.zig");
const crypto = @import("crypto/crypto.zig");
const obfuscation = @import("protocol/obfuscation.zig");
const tls = @import("protocol/tls.zig");
const config = @import("config.zig");
const proxy = @import("proxy/proxy.zig");
const linux_io = @import("linux_io");
const version_mod = @import("version");
const runtime_log = @import("runtime_log.zig");
const web_capability = @import("web/capability.zig");
const web_relay = @import("web/relay.zig");

// Custom lock-free log function: formats into a stack buffer and writes
// to stderr in a single write() syscall. On Linux, write() is atomic for
// sizes <= PIPE_BUF (4096 bytes), so messages from different threads
// don't interleave. This avoids the global stderr_mutex that Zig's
// default logger uses, which causes catastrophic contention under
// hundreds of concurrent threads.
pub const std_options = std.Options{
    // Set comptime level to .debug so all log calls are compiled in.
    // Runtime filtering is done in lockFreeLog via runtime_log.level.
    .log_level = if (builtin.is_test) .err else .debug,
    .logFn = lockFreeLog,
};

fn lockFreeLog(
    comptime message_level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    // Runtime filter: skip messages below configured level
    if (@intFromEnum(message_level) > @intFromEnum(runtime_log.level.load(.monotonic))) return;

    const level_txt = comptime message_level.asText();
    const prefix2 = comptime if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, level_txt ++ prefix2 ++ format ++ "\n", args) catch |err| switch (err) {
        error.NoSpaceLeft => blk: {
            if (buf.len >= 2) {
                buf[buf.len - 2] = '\n';
                buf[buf.len - 1] = 0;
                break :blk buf[0 .. buf.len - 1];
            }
            return;
        },
        else => return,
    };
    linux_io.writeAllFd(std.posix.STDERR_FILENO, msg);
}

const log = std.log.scoped(.mtproto);

pub const version = version_mod.version;

// ============= Output Helpers =============

/// Write a formatted string to stdout via posix write.
fn writeStdout(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const slice = std.fmt.bufPrint(&buf, fmt, args) catch return;
    linux_io.writeAllFd(std.posix.STDOUT_FILENO, slice);
}

/// Write a formatted string to stderr.
fn writeStderr(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const slice = std.fmt.bufPrint(&buf, fmt, args) catch return;
    linux_io.writeAllFd(std.posix.STDERR_FILENO, slice);
}

/// Write raw string to stdout.
fn writeRaw(s: []const u8) void {
    linux_io.writeAllFd(std.posix.STDOUT_FILENO, s);
}

// ============= Public IP Detection =============

const fetchUrlBytes = @import("proxy/http_fetch.zig").fetchUrlBytes;

/// Try to detect the server's public IP address via external services.
/// Returns the IP string (caller owns memory) or null on failure.
fn detectPublicIp(allocator: std.mem.Allocator) ?[]const u8 {
    // Prefer IPv4 first because many Telegram clients/networks still fail on
    // deep links that only contain an IPv6 endpoint.
    const ipv4_services = [_][]const u8{
        "https://api4.ipify.org",
        "https://ipv4.icanhazip.com",
        "https://v4.ident.me",
    };
    if (detectPublicIpFromServices(allocator, ipv4_services[0..], true)) |ip| {
        return ip;
    }

    // Fallback to any detected public IP (IPv4 or IPv6).
    const fallback_services = [_][]const u8{
        "https://ifconfig.me",
        "https://api.ipify.org",
        "https://icanhazip.com",
    };
    return detectPublicIpFromServices(allocator, fallback_services[0..], false);
}

fn detectPublicIpFromServices(
    allocator: std.mem.Allocator,
    services: []const []const u8,
    ipv4_only: bool,
) ?[]const u8 {
    for (services) |url| {
        const stdout = fetchUrlBytes(allocator, url) catch continue;
        // Trim whitespace/newlines
        const trimmed = std.mem.trim(u8, stdout, &[_]u8{ ' ', '\t', '\n', '\r' });
        if (trimmed.len == 0 or trimmed.len > 45) {
            allocator.free(stdout);
            continue;
        }

        // Basic validation: should look like an IP
        const has_dot = std.mem.indexOfScalar(u8, trimmed, '.') != null;
        const has_colon = std.mem.indexOfScalar(u8, trimmed, ':') != null;
        const is_valid = if (ipv4_only)
            (has_dot and !has_colon)
        else
            (has_dot or has_colon);

        if (is_valid) {
            // If trimmed is a sub-slice of stdout, dupe it so we can free stdout
            const ip = allocator.dupe(u8, trimmed) catch {
                allocator.free(stdout);
                continue;
            };
            allocator.free(stdout);
            return ip;
        }
        allocator.free(stdout);
    }
    return null;
}

const CapacityEstimate = struct {
    total_ram_bytes: u64,
    per_conn_bytes: u64,
    safe_connections: u32,
};

fn detectTotalRamBytes() ?u64 {
    if (builtin.os.tag != .linux) return null;

    // Prefer sysinfo(2): no /proc dependency and works under stricter sandboxing.
    if (detectTotalRamBytesSysinfo()) |total| {
        return total;
    }

    // Fallback: parse /proc/meminfo. Read to EOF rather than Reader.allocRemaining, which
    // sizes its result from stat().size — always 0 for procfs, so it would hand back an
    // empty document and this fallback could never find MemTotal. (Masked so far because
    // sysinfo(2) above normally answers first.)
    const io = std.Io.Threaded.global_single_threaded.io();
    var file = std.Io.Dir.openFileAbsolute(io, "/proc/meminfo", .{}) catch return null;
    defer file.close(io);

    var read_buf: [4096]u8 = undefined;
    var reader = file.reader(io, &read_buf);

    var meminfo_buf: [16 * 1024]u8 = undefined;
    var len: usize = 0;
    while (len < meminfo_buf.len) {
        const n = reader.interface.readSliceShort(meminfo_buf[len..]) catch return null;
        if (n == 0) break;
        len += n;
    }
    const content_bytes = meminfo_buf[0..len];

    const key = "MemTotal:";
    var lines = std.mem.splitScalar(u8, content_bytes, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, key)) continue;

        var i: usize = key.len;
        while (i < line.len and (line[i] == ' ' or line[i] == '\t')) : (i += 1) {}
        const start = i;
        while (i < line.len and line[i] >= '0' and line[i] <= '9') : (i += 1) {}
        if (i == start) return null;

        const total_kib = std.fmt.parseInt(u64, line[start..i], 10) catch return null;
        return total_kib * 1024;
    }

    return null;
}

fn detectTotalRamBytesSysinfo() ?u64 {
    if (builtin.os.tag != .linux) return null;

    var info: std.os.linux.Sysinfo = undefined;
    const rc = std.os.linux.sysinfo(&info);
    if (std.os.linux.errno(rc) != .SUCCESS) return null;

    const mem_unit: u128 = if (info.mem_unit == 0) 1 else info.mem_unit;
    const total_bytes: u128 = @as(u128, info.totalram) * mem_unit;
    if (total_bytes == 0 or total_bytes > std.math.maxInt(u64)) return null;
    return @intCast(total_bytes);
}

fn estimateCapacity(cfg: *const config.Config, total_ram_bytes: u64) CapacityEstimate {
    // Approximate per-connection user-space working set in the epoll model:
    // - preallocated slot state and small relay buffers
    // - optional middle-proxy stream buffers (2 per-connection buffers)
    // - allocator/socket bookkeeping cushion
    const tls_working_bytes: u64 = @intCast(6 * 1024);
    const middleproxy_per_conn_bytes: u64 = if (cfg.use_middle_proxy or cfg.force_media_middle_proxy or cfg.tag != null)
        @intCast(cfg.middleProxyBufferBytes() * 2)
    else
        0;
    // Event loop also keeps 2 shared scratch buffers for middle-proxy
    // encapsulate/decapsulate temporary output.
    const middleproxy_shared_bytes: u64 = if (cfg.use_middle_proxy or cfg.force_media_middle_proxy or cfg.tag != null)
        @intCast(cfg.middleProxySharedBytes())
    else
        0;
    const overhead_bytes: u64 = 2 * 1024 + 2 * 32 * 1024; // two bounded queue block caches
    const per_conn_bytes = tls_working_bytes + middleproxy_per_conn_bytes + overhead_bytes;

    // Keep safety headroom for kernel TCP memory, page cache, and baseline process state.
    const usable_bytes = (total_ram_bytes * 70) / 100;
    const reserve_bytes = @max(@as(u64, 256 * 1024 * 1024), (total_ram_bytes * 10) / 100);
    const fixed_overhead_bytes = reserve_bytes + middleproxy_shared_bytes;
    const budget_bytes = if (usable_bytes > fixed_overhead_bytes) usable_bytes - fixed_overhead_bytes else 0;

    const raw_cap = if (per_conn_bytes > 0) budget_bytes / per_conn_bytes else 0;
    const safe_connections_u64 = @max(@as(u64, 32), @min(raw_cap, @as(u64, std.math.maxInt(u32))));

    return .{
        .total_ram_bytes = total_ram_bytes,
        .per_conn_bytes = per_conn_bytes,
        .safe_connections = @intCast(safe_connections_u64),
    };
}

fn enforceCapacitySafety(cfg: *config.Config, capacity_estimate: ?CapacityEstimate) !void {
    const est = capacity_estimate orelse {
        if (builtin.os.tag == .linux and !cfg.unsafe_override_limits) {
            const log_main = std.log.scoped(.config);
            log_main.warn(
                "could not detect total RAM; skipping max_connections safety clamp. " ++
                    "set a conservative [server].max_connections to avoid OOM.",
                .{},
            );
        }
        return;
    };

    if (cfg.max_connections <= est.safe_connections) return;

    const log_main = std.log.scoped(.config);
    if (cfg.unsafe_override_limits) {
        log_main.warn(
            "max_connections={d} is above RAM-safe estimate ({d}); " ++
                "unsafe_override_limits=true, keeping configured limit.",
            .{ cfg.max_connections, est.safe_connections },
        );
        return;
    }

    const configured_limit = cfg.max_connections;
    cfg.max_connections = est.safe_connections;

    std.debug.assert(cfg.max_connections <= est.safe_connections);

    log_main.warn(
        "auto-clamping max_connections from {d} to {d} " ++
            "(host has {d} MiB RAM, ~{d} KiB/connection). " ++
            "To disable this safety clamp, set unsafe_override_limits = true in [server].",
        .{
            configured_limit,
            est.safe_connections,
            est.total_ram_bytes / (1024 * 1024),
            est.per_conn_bytes / 1024,
        },
    );
}

// ============= Startup Banner =============

/// Print a stylish startup banner with config summary and connection links.
fn printBanner(allocator: std.mem.Allocator, cfg: config.Config, capacity_estimate: ?CapacityEstimate) void {
    const R = "\x1b[0m";
    const B = "\x1b[1m";
    const D = "\x1b[2m";
    const cyan = "\x1b[36m";
    const green = "\x1b[32m";
    const yellow = "\x1b[33m";
    const white = "\x1b[97m";
    const red = "\x1b[31m";

    // Detect public IP
    var public_ip_alloc: ?[]const u8 = null;
    if (cfg.public_ip == null) {
        writeRaw("\n" ++ D ++ "  Detecting public IP..." ++ R);
        public_ip_alloc = detectPublicIp(allocator);
        writeRaw("\r\x1b[K");
    }
    defer if (public_ip_alloc) |ip| allocator.free(ip);

    const has_ip = cfg.public_ip != null or public_ip_alloc != null;
    const server_ip = cfg.public_ip orelse (public_ip_alloc orelse "<SERVER_IP>");

    // Logo
    writeRaw("\n" ++ B ++ cyan);
    writeRaw("       __  __ _____ ____            _\n");
    writeRaw("      |  \\/  |_   _|  _ \\ _ __ ___ | |_ ___\n");
    writeRaw("      | |\\/| | | | | |_) | '__/ _ \\| __/ _ \\\n");
    writeRaw("      | |  | | | | |  __/| | | (_) | || (_) |\n");
    writeRaw("      |_|  |_| |_| |_|   |_|  \\___/ \\__\\___/\n");
    writeRaw(R);
    writeStdout("      {s}{s}proxy · zig edition · v{s}{s}\n", .{ D, white, version, R });
    writeStdout("      {s}keeping your people connected{s}\n\n", .{ D, R });

    // ─── SERVER ─────────────────────────────────────
    writeRaw("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "SERVER" ++ R ++ " " ++ D ++ "──────────────────────────────────────" ++ R ++ "\n");
    if (cfg.bind_address) |ba| {
        writeStdout("      Listen       " ++ B ++ green ++ "{s}:{d}" ++ R ++ "\n", .{ ba, cfg.port });
    } else {
        writeStdout("      Listen       " ++ B ++ green ++ "0.0.0.0:{d}" ++ R ++ "\n", .{cfg.port});
    }
    writeStdout("      Public IP    " ++ B ++ "{s}{s}" ++ R ++ "\n", .{
        if (has_ip) green else yellow,
        server_ip,
    });
    if (cfg.public_port) |public_port| {
        if (public_port != cfg.port) {
            writeStdout("      Public Port  " ++ B ++ green ++ "{d}" ++ R ++ "\n", .{public_port});
        }
    }
    writeStdout("      TLS Domain   " ++ B ++ yellow ++ "{s}" ++ R ++ "\n", .{cfg.tls_domain});
    writeRaw("      Masking      " ++ B);
    if (cfg.mask) {
        writeRaw(green ++ "enabled");
    } else {
        writeRaw(yellow ++ "disabled");
    }
    writeRaw(R ++ "\n\n");

    if (capacity_estimate) |est| {
        writeRaw("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "CAPACITY" ++ R ++ " " ++ D ++ "────────────────────────────────────" ++ R ++ "\n");
        writeStdout("      Host RAM     " ++ B ++ "{d} MiB" ++ R ++ "\n", .{est.total_ram_bytes / (1024 * 1024)});
        writeStdout("      Per conn     ~{d} KiB ({s})\n", .{
            est.per_conn_bytes / 1024,
            if (cfg.use_middle_proxy) "middleproxy mode" else "direct mode",
        });
        writeStdout("      Safe cap     " ++ B ++ "~{d}" ++ R ++ " connections\n", .{est.safe_connections});
        if (cfg.max_connections > est.safe_connections) {
            writeStdout("      " ++ yellow ++ "max_connections={d} is above safe estimate" ++ R ++ "\n", .{cfg.max_connections});
        }
        writeRaw("\n");
    }

    // ─── USERS ──────────────────────────────────────
    writeStdout("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "USERS" ++ R ++ " ({d}) " ++ D ++ "────────────────────────────────────" ++ R ++ "\n", .{cfg.users.count()});
    var it = @constCast(&cfg.users).iterator();
    while (it.next()) |entry| {
        writeStdout("      " ++ green ++ "●" ++ R ++ " " ++ B ++ "{s}" ++ R ++ "\n", .{entry.key_ptr.*});
    }
    writeRaw("\n");

    // ─── SECURITY ───────────────────────────────────
    writeRaw("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "SECURITY" ++ R ++ " " ++ D ++ "───────────────────────────────────" ++ R ++ "\n");
    if (!has_ip) {
        writeRaw("      " ++ red ++ "⚠  Could not detect public IP automatically." ++ R ++ "\n");
    }
    writeRaw("      " ++ D ++ "User secrets and proxy links are hidden in runtime logs." ++ R ++ "\n");
    writeRaw("      " ++ D ++ "Use mtbuddy install output or trusted local tooling to generate links." ++ R ++ "\n");

    // Footer
    writeRaw("\n  " ++ D ++ "──────────────────────────────────────────────────" ++ R ++ "\n");
    writeRaw("  " ++ B ++ cyan ++ "⏳ Your door is open. Waiting for the people you love..." ++ R ++ "\n\n");
}

/// Entry point for `mtproto-proxy web-relay`.
fn runWebRelay(allocator: std.mem.Allocator, config_path: []const u8) !void {
    var cfg = config.Config.loadFromFile(allocator, config_path) catch |err| {
        writeStderr("\x1b[1m\x1b[31m  \u{2717} Failed to load config '{s}': {}\x1b[0m\n", .{ config_path, err });
        std.process.exit(1);
    };
    defer cfg.deinit(allocator);
    runtime_log.level.store(cfg.log_level, .monotonic);

    // `opts.domain` borrows this frame, which outlives the relay.
    var domain_buf: [web_capability.max_host_len]u8 = undefined;
    var opts = web_relay.Options.fromConfig(&cfg, &domain_buf) catch |err| {
        const hint = switch (err) {
            error.WebProxyDisabled => "set [web].enabled = true",
            error.MissingDomain => "set [web].domain to the public hostname of the relay",
            error.InvalidDomain => "[web].domain must be a real DNS name in ASCII/xn-- form, never an IP",
            error.InvalidBackend => "[web].backend must be host:port",
            error.NoUsersConfigured => "add at least one user to [access.users]",
        };
        writeStderr("\x1b[1m\x1b[31m  \u{2717} web relay cannot start: {} \u{2014} {s}\x1b[0m\n", .{ err, hint });
        std.process.exit(1);
    };
    opts.backend = web_relay.resolveBackend(allocator, &cfg) catch |err| {
        writeStderr("\x1b[1m\x1b[31m  \u{2717} web relay: cannot resolve [web].backend: {}\x1b[0m\n", .{err});
        std.process.exit(1);
    };

    var relay = try web_relay.Relay.init(allocator, opts, &cfg);
    defer relay.deinit();
    try relay.run();
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    // Parse config path from args
    var args = try init.minimal.args.iterateAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // skip program name
    const first_arg = args.next();

    if (first_arg) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            writeStdout(
                \\
                \\  Usage: mtproto-proxy [config.toml]
                \\         mtproto-proxy web-relay <config.toml>
                \\
                \\  Starts the MTProto proxy using the given config file.
                \\  Defaults to 'config.toml' in the current directory.
                \\
                \\  Options:
                \\    -h, --help            Show this help message and exit
                \\    -v, --version         Show version and exit
                \\    --check-config [path] Validate the config and exit (0=ok, 1=invalid)
                \\
                \\
            , .{});
            return;
        }
        if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            writeStdout("mtproto-proxy v" ++ version ++ "\n", .{});
            return;
        }
        // Config dry-run (like `nginx -t`): parse + validate, then exit with a
        // shell-usable status. Usage: mtproto-proxy --check-config [config.toml]
        if (std.mem.eql(u8, arg, "--check-config") or std.mem.eql(u8, arg, "--check")) {
            const path = args.next() orelse "config.toml";
            var check_cfg = config.Config.loadFromFile(allocator, path) catch |err| {
                writeStderr("\x1b[1m\x1b[31m  ✗ config '{s}' is INVALID: {}\x1b[0m\n", .{ path, err });
                std.process.exit(1);
            };
            defer check_cfg.deinit(allocator);
            runtime_log.level.store(check_cfg.log_level, .monotonic);
            check_cfg.emitWarnings();
            writeStdout("  \x1b[32m✓\x1b[0m config '{s}' is valid ({d} user(s))\n", .{ path, check_cfg.users.count() });
            std.process.exit(0);
        }

        // `mtproto-proxy web-relay [config.toml]` runs the WEB proxy relay instead of
        // the data plane: same binary (so `mtbuddy update` ships it for free), separate
        // process and systemd unit (so a fault there cannot take the proxy down).
        if (std.mem.eql(u8, arg, "web-relay")) {
            const path = args.next() orelse "config.toml";
            return runWebRelay(allocator, path);
        }
    }

    const config_path = first_arg orelse "config.toml";

    // Parse config
    var cfg = config.Config.loadFromFile(allocator, config_path) catch |err| {
        writeStderr("\x1b[1m\x1b[31m  ✗ Failed to load config '{s}': {}\x1b[0m\n", .{ config_path, err });
        writeStderr("\n  Usage: mtproto-proxy [config.toml]\n\n", .{});
        return err;
    };
    var cfg_owned_by_main = true;
    defer if (cfg_owned_by_main) cfg.deinit(allocator);

    // Apply runtime log level from config
    runtime_log.level.store(cfg.log_level, .monotonic);

    if (!std.crypto.core.aes.has_hardware_support and (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64)) {
        const log_main = std.log.scoped(.config);
        log_main.warn(
            "AES backend is software-only for this build/target. MiddleProxy video traffic will be CPU-heavy. " ++
                "Rebuild with CPU features enabled (example: -Dcpu=native or -Dcpu=x86_64_v3+aes).",
            .{},
        );
    }

    const capacity_estimate = if (detectTotalRamBytes()) |total_ram|
        estimateCapacity(&cfg, total_ram)
    else
        null;

    try enforceCapacitySafety(&cfg, capacity_estimate);

    // Print the startup banner (includes IP detection)
    printBanner(allocator, cfg, capacity_estimate);

    // Emit config warnings (e.g. buffer too small, memory concerns)
    cfg.emitWarnings();

    // Create shared state (DI — no globals)
    const state = try allocator.create(proxy.ProxyState);
    defer allocator.destroy(state);
    state.* = try proxy.ProxyState.init(allocator, cfg, config_path);
    cfg_owned_by_main = false;
    defer state.deinit();

    // systemd notify/watchdog wiring (no-op when not run under systemd). The env
    // strings are owned by the process environ and live for the whole run.
    state.notify_socket = init.environ_map.get("NOTIFY_SOCKET");
    state.watchdog_usec = @import("proxy/sd_notify.zig").watchdogInterval(
        init.environ_map.get("WATCHDOG_USEC"),
        init.environ_map.get("WATCHDOG_PID"),
        @intCast(std.os.linux.getpid()),
    );

    // Run the proxy
    try state.run();
}

test {
    // Zig's server-mode test runner reports any warning output as "failed command"
    // even on exit 0. Expected warning-path regressions should remain quiet.
    std.testing.log_level = .err;
    _ = constants;
    _ = crypto;
    _ = obfuscation;
    _ = tls;
    _ = config;
    _ = proxy;
    _ = @import("tunnel.zig");
    _ = @import("web/frame.zig");
    _ = @import("web/capability.zig");
    _ = @import("web/ws.zig");
    _ = @import("web/http.zig");
    _ = @import("web/page.zig");
    _ = web_relay;
}

test "capacity safety clamp enforces safe cap when override disabled" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .max_connections = 4096,
        .unsafe_override_limits = false,
    };
    defer cfg.deinit(std.testing.allocator);

    const est = CapacityEstimate{
        .total_ram_bytes = 2 * 1024 * 1024 * 1024,
        .per_conn_bytes = 2 * 1024 * 1024,
        .safe_connections = 585,
    };

    try enforceCapacitySafety(&cfg, est);
    try std.testing.expectEqual(@as(u32, 585), cfg.max_connections);
}

test "capacity estimate includes forced media MiddleProxy buffers" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .use_middle_proxy = false,
        .force_media_middle_proxy = false,
    };
    defer cfg.deinit(std.testing.allocator);
    const direct = estimateCapacity(&cfg, 2 * 1024 * 1024 * 1024);
    cfg.force_media_middle_proxy = true;
    const media = estimateCapacity(&cfg, 2 * 1024 * 1024 * 1024);
    try std.testing.expectEqual(direct.per_conn_bytes + cfg.middleProxyBufferBytes() * 2, media.per_conn_bytes);
    try std.testing.expect(media.safe_connections < direct.safe_connections);
}

test "capacity safety clamp keeps configured limit when override enabled" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .max_connections = 4096,
        .unsafe_override_limits = true,
    };
    defer cfg.deinit(std.testing.allocator);

    const est = CapacityEstimate{
        .total_ram_bytes = 2 * 1024 * 1024 * 1024,
        .per_conn_bytes = 2 * 1024 * 1024,
        .safe_connections = 585,
    };

    try enforceCapacitySafety(&cfg, est);
    try std.testing.expectEqual(@as(u32, 4096), cfg.max_connections);
}
