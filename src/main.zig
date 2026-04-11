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

// Custom lock-free log function: formats into a stack buffer and writes
// to stderr in a single write() syscall. On Linux, write() is atomic for
// sizes <= PIPE_BUF (4096 bytes), so messages from different threads
// don't interleave. This avoids the global stderr_mutex that Zig's
// default logger uses, which causes catastrophic contention under
// hundreds of concurrent threads.
// Runtime log level, set from config.toml at startup.
// Checked by lockFreeLog to filter messages without recompilation.
pub var runtime_log_level: std.log.Level = .info;

pub const std_options = std.Options{
    // Set comptime level to .debug so all log calls are compiled in.
    // Runtime filtering is done in lockFreeLog via runtime_log_level.
    .log_level = .debug,
    .logFn = lockFreeLog,
};

fn lockFreeLog(
    comptime message_level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    // Runtime filter: skip messages below configured level
    if (@intFromEnum(message_level) > @intFromEnum(runtime_log_level)) return;

    const level_txt = comptime message_level.asText();
    const prefix2 = comptime if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, level_txt ++ prefix2 ++ format ++ "\n", args) catch return;
    _ = std.posix.write(std.posix.STDERR_FILENO, msg) catch return;
}

const log = std.log.scoped(.mtproto);

const version = "0.15.1"; // x-release-please-version

// ============= Output Helpers (Zig 0.15 compatible) =============

/// Write a formatted string to stdout via posix write.
fn writeStdout(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const slice = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = std.posix.write(std.posix.STDOUT_FILENO, slice) catch return;
}

/// Write a formatted string to stderr.
fn writeStderr(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const slice = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = std.posix.write(std.posix.STDERR_FILENO, slice) catch return;
}

/// Write a hex byte to stdout.
fn writeHexByte(byte: u8) void {
    const hex = "0123456789abcdef";
    const out = [2]u8{ hex[byte >> 4], hex[byte & 0x0f] };
    _ = std.posix.write(std.posix.STDOUT_FILENO, &out) catch return;
}

/// Write raw string to stdout.
fn writeRaw(s: []const u8) void {
    _ = std.posix.write(std.posix.STDOUT_FILENO, s) catch return;
}

// ============= Public IP Detection =============

fn fetchUrlBytes(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
    const uri = try std.Uri.parse(url);

    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    var req = try client.request(.GET, uri, .{
        .redirect_behavior = @enumFromInt(3),
        .keep_alive = false,
        .headers = .{
            .accept_encoding = .{ .override = "identity" },
        },
    });
    defer req.deinit();

    try req.sendBodiless();

    var redirect_buf: [8 * 1024]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);
    if (response.head.status.class() != .success) return error.HttpRequestFailed;

    var transfer_buf: [4 * 1024]u8 = undefined;
    const reader = response.reader(&transfer_buf);
    return reader.allocRemaining(allocator, .limited(64 * 1024));
}

/// Try to detect the server's public IP address via external services.
/// Returns the IP string (caller owns memory) or null on failure.
fn detectPublicIp(allocator: std.mem.Allocator) ?[]const u8 {
    // Try multiple services in order
    const services = [_][]const u8{
        "https://ifconfig.me",
        "https://api.ipify.org",
        "https://icanhazip.com",
    };

    for (services) |url| {
        const stdout = fetchUrlBytes(allocator, url) catch continue;
        // Trim whitespace/newlines
        const trimmed = std.mem.trim(u8, stdout, &[_]u8{ ' ', '\t', '\n', '\r' });
        if (trimmed.len == 0 or trimmed.len > 45) {
            allocator.free(stdout);
            continue;
        }

        // Basic validation: should look like an IP
        if (std.mem.indexOfScalar(u8, trimmed, '.') != null or
            std.mem.indexOfScalar(u8, trimmed, ':') != null)
        {
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

fn detectTotalRamBytes(allocator: std.mem.Allocator) ?u64 {
    if (builtin.os.tag != .linux) return null;

    const file = std.fs.openFileAbsolute("/proc/meminfo", .{}) catch return null;
    defer file.close();

    const content = file.readToEndAlloc(allocator, 16 * 1024) catch return null;
    defer allocator.free(content);

    const key = "MemTotal:";
    var lines = std.mem.splitScalar(u8, content, '\n');
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

fn estimateCapacity(cfg: *const config.Config, total_ram_bytes: u64) CapacityEstimate {
    // Approximate per-connection user-space working set in the epoll model:
    // - preallocated slot state and small relay buffers
    // - optional middle-proxy stream buffers (2 per-connection buffers)
    // - allocator/socket bookkeeping cushion
    const tls_working_bytes: u64 = @intCast(6 * 1024);
    const middleproxy_per_conn_bytes: u64 = if (cfg.use_middle_proxy)
        @intCast(cfg.middleProxyBufferBytes() * 2)
    else
        0;
    // Event loop also keeps 2 shared scratch buffers for middle-proxy
    // encapsulate/decapsulate temporary output.
    const middleproxy_shared_bytes: u64 = if (cfg.use_middle_proxy)
        @intCast(cfg.middleProxyBufferBytes() * 2)
    else
        0;
    const overhead_bytes: u64 = 2 * 1024;
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
                "could not read /proc/meminfo; skipping max_connections safety clamp. " ++
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
    const magenta = "\x1b[35m";
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
    writeStdout("      {s}{s}proxy · zig edition · v{s}{s}\n\n", .{ D, white, version, R });

    // ─── SERVER ─────────────────────────────────────
    writeRaw("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "SERVER" ++ R ++ " " ++ D ++ "──────────────────────────────────────" ++ R ++ "\n");
    writeStdout("      Listen       " ++ B ++ green ++ "0.0.0.0:{d}" ++ R ++ "\n", .{cfg.port});
    writeStdout("      Public IP    " ++ B ++ "{s}{s}" ++ R ++ "\n", .{
        if (has_ip) green else yellow,
        server_ip,
    });
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
        writeStdout("      " ++ green ++ "●" ++ R ++ " " ++ B ++ "{s}" ++ R ++ "  " ++ D, .{entry.key_ptr.*});
        for (entry.value_ptr.*) |byte| {
            writeHexByte(byte);
        }
        writeRaw(R ++ "\n");
    }
    writeRaw("\n");

    // ─── LINKS ──────────────────────────────────────
    writeRaw("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "LINKS" ++ R ++ " " ++ D ++ "──────────────────────────────────────" ++ R ++ "\n");
    if (!has_ip) {
        writeRaw("      " ++ red ++ "⚠  Could not detect IP. Replace <SERVER_IP> manually." ++ R ++ "\n");
    }

    var it2 = @constCast(&cfg.users).iterator();
    while (it2.next()) |entry| {
        writeStdout("      " ++ B ++ magenta ++ "{s}" ++ R ++ "\n", .{entry.key_ptr.*});

        // tg:// deep link
        writeStdout("      " ++ cyan ++ "tg://" ++ R ++ "proxy?server={s}&port={d}&secret=", .{ server_ip, cfg.port });
        writeRaw(green ++ "ee");
        for (entry.value_ptr.*) |byte| {
            writeHexByte(byte);
        }
        for (cfg.tls_domain) |byte| {
            writeHexByte(byte);
        }
        writeRaw(R ++ "\n");

        // t.me link
        writeStdout("      " ++ D ++ "t.me/proxy?server={s}&port={d}&secret=ee", .{ server_ip, cfg.port });
        for (entry.value_ptr.*) |byte| {
            writeHexByte(byte);
        }
        for (cfg.tls_domain) |byte| {
            writeHexByte(byte);
        }
        writeRaw(R ++ "\n");
    }

    // Footer
    writeRaw("\n  " ++ D ++ "──────────────────────────────────────────────────" ++ R ++ "\n");
    writeRaw("  " ++ B ++ cyan ++ "⏳ Waiting for connections..." ++ R ++ "\n\n");
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = false }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse config path from args
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // skip program name
    const first_arg = args.next();

    if (first_arg) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            writeStderr(
                \\
                \\  Usage: mtproto-proxy [config.toml]
                \\
                \\  Starts the MTProto proxy using the given config file.
                \\  Defaults to 'config.toml' in the current directory.
                \\
                \\  Options:
                \\    -h, --help       Show this help message and exit
                \\    -v, --version    Show version and exit
                \\
                \\
            , .{});
            return;
        }
        if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            writeStderr("mtproto-proxy v" ++ version ++ "\n", .{});
            return;
        }
    }

    const config_path = first_arg orelse "config.toml";

    // Parse config
    var cfg = config.Config.loadFromFile(allocator, config_path) catch |err| {
        writeStderr("\x1b[1m\x1b[31m  ✗ Failed to load config '{s}': {}\x1b[0m\n", .{ config_path, err });
        writeStderr("\n  Usage: mtproto-proxy [config.toml]\n\n", .{});
        return;
    };
    defer cfg.deinit(allocator);

    // Apply runtime log level from config
    runtime_log_level = cfg.log_level;

    if (!std.crypto.core.aes.has_hardware_support and (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64)) {
        const log_main = std.log.scoped(.config);
        log_main.warn(
            "AES backend is software-only for this build/target. MiddleProxy video traffic will be CPU-heavy. " ++
                "Rebuild with CPU features enabled (example: -Dcpu=native or -Dcpu=x86_64_v3+aes).",
            .{},
        );
    }

    const capacity_estimate = if (detectTotalRamBytes(allocator)) |total_ram|
        estimateCapacity(&cfg, total_ram)
    else
        null;

    try enforceCapacitySafety(&cfg, capacity_estimate);

    // Print the startup banner (includes IP detection)
    printBanner(allocator, cfg, capacity_estimate);

    // Emit config warnings (e.g. buffer too small, memory concerns)
    cfg.emitWarnings();

    // Create shared state (DI — no globals)
    var state = proxy.ProxyState.init(allocator, cfg);
    defer state.deinit();

    // Run the proxy
    try state.run();
}

test {
    _ = constants;
    _ = crypto;
    _ = obfuscation;
    _ = tls;
    _ = config;
    _ = proxy;
    _ = @import("tunnel.zig");
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
