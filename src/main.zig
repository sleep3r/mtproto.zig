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
pub const std_options = std.Options{
    // Do NOT set log_level here. In ReleaseFast, Zig's default is .info,
    // which eliminates all log.debug calls at comptime (zero overhead).
    // Setting .debug here floods stderr with thousands of messages/sec
    // under heavy load, even with the lock-free logger.
    .logFn = lockFreeLog,
};

fn lockFreeLog(
    comptime message_level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const level_txt = comptime message_level.asText();
    const prefix2 = comptime if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, level_txt ++ prefix2 ++ format ++ "\n", args) catch return;
    _ = std.posix.write(std.posix.STDERR_FILENO, msg) catch return;
}

const log = std.log.scoped(.mtproto);

const version = "0.5.1"; // x-release-please-version

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

/// Try to detect the server's public IP address via external services.
/// Returns the IP string (caller owns memory) or null on failure.
fn detectPublicIp(allocator: std.mem.Allocator) ?[]const u8 {
    // Try multiple services in order
    const services = [_][]const []const u8{
        &.{ "curl", "-s", "--max-time", "3", "https://ifconfig.me" },
        &.{ "curl", "-s", "--max-time", "3", "https://api.ipify.org" },
        &.{ "curl", "-s", "--max-time", "3", "https://icanhazip.com" },
    };

    for (services) |argv| {
        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = argv,
        }) catch continue;

        defer allocator.free(result.stderr);

        const stdout = result.stdout;
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
    const stack_bytes: u64 = @intCast(cfg.threadStackBytes());

    // Approximate per-connection user-space working set:
    // - thread stack
    // - handshake + relay TLS buffers
    // - optional middle-proxy stream buffers (4 buffers)
    // - allocator/socket bookkeeping cushion
    const tls_working_bytes: u64 = @intCast(
        constants.max_tls_ciphertext_size * 3 +
            (constants.max_tls_plaintext_size + 5) * 2,
    );
    const middleproxy_bytes: u64 = if (cfg.use_middle_proxy)
        @intCast(cfg.middleProxyBufferBytes() * 4)
    else
        0;
    const overhead_bytes: u64 = 64 * 1024;
    const per_conn_bytes = stack_bytes + tls_working_bytes + middleproxy_bytes + overhead_bytes;

    // Keep safety headroom for kernel TCP memory, page cache, and baseline process state.
    const usable_bytes = (total_ram_bytes * 70) / 100;
    const reserve_bytes = @max(@as(u64, 256 * 1024 * 1024), (total_ram_bytes * 10) / 100);
    const budget_bytes = if (usable_bytes > reserve_bytes) usable_bytes - reserve_bytes else 0;

    const raw_cap = if (per_conn_bytes > 0) budget_bytes / per_conn_bytes else 0;
    const safe_connections_u64 = @max(@as(u64, 32), @min(raw_cap, @as(u64, std.math.maxInt(u32))));

    return .{
        .total_ram_bytes = total_ram_bytes,
        .per_conn_bytes = per_conn_bytes,
        .safe_connections = @intCast(safe_connections_u64),
    };
}

// ============= Startup Banner =============

/// Print a stylish startup banner with config summary and connection links.
fn printBanner(allocator: std.mem.Allocator, cfg: config.Config) void {
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
    writeRaw("\n" ++ D ++ "  Detecting public IP..." ++ R);
    const public_ip = detectPublicIp(allocator);
    defer if (public_ip) |ip| allocator.free(ip);
    writeRaw("\r\x1b[K");

    const server_ip = public_ip orelse "<SERVER_IP>";

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
        if (public_ip != null) green else yellow,
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

    if (detectTotalRamBytes(allocator)) |total_ram| {
        const est = estimateCapacity(&cfg, total_ram);
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
    if (public_ip == null) {
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
    // Use page_allocator instead of GeneralPurposeAllocator for production.
    // GPA has an internal mutex that causes deadlocks under heavy thread contention
    // (1000+ simultaneous connections all doing TLS validation allocations).
    const allocator = std.heap.page_allocator;

    // Parse config path from args
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // skip program name
    const config_path = args.next() orelse "config.toml";

    // Parse config
    const cfg = config.Config.loadFromFile(allocator, config_path) catch |err| {
        writeStderr("\x1b[1m\x1b[31m  ✗ Failed to load config '{s}': {}\x1b[0m\n", .{ config_path, err });
        writeStderr("\n  Usage: mtproto-proxy [config.toml]\n\n", .{});
        return;
    };
    defer cfg.deinit(allocator);

    // Print the startup banner (includes IP detection)
    printBanner(allocator, cfg);

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
}
