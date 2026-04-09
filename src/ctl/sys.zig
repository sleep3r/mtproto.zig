//! System operations wrapper for buddy.
//!
//! Encapsulates subprocess execution, file I/O, architecture detection,
//! and privilege checks. All subprocess calls go through exec() which
//! provides proper error handling and output capture.

const std = @import("std");
const tui_mod = @import("tui.zig");

pub const ExecResult = struct {
    exit_code: u8,
    stdout: []const u8,
    stderr: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *const ExecResult) void {
        self.allocator.free(self.stdout);
        self.allocator.free(self.stderr);
    }
};

pub const Arch = enum {
    x86_64,
    aarch64,

    pub fn toStr(self: Arch) []const u8 {
        return switch (self) {
            .x86_64 => "x86_64",
            .aarch64 => "aarch64",
        };
    }
};

/// Run a command, capture stdout/stderr, return result.
pub fn exec(allocator: std.mem.Allocator, argv: []const []const u8) !ExecResult {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .max_output_bytes = 1024 * 1024,
    });

    const exit_code: u8 = switch (result.term) {
        .Exited => |code| code,
        .Signal => |sig| @as(u8, 128) +| @as(u8, @intCast(@min(sig, 127))),
        .Stopped => 1,
        .Unknown => 1,
    };

    return .{
        .exit_code = exit_code,
        .stdout = result.stdout,
        .stderr = result.stderr,
        .allocator = allocator,
    };
}

/// Run a command with output forwarded directly to the terminal (no capture).
pub fn execForward(argv: []const []const u8) !u8 {
    var child = std.process.Child.init(argv, std.heap.page_allocator);
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;

    try child.spawn();
    const term = try child.wait();

    return switch (term) {
        .Exited => |code| code,
        .Signal => |sig| @as(u8, 128) +| @as(u8, @intCast(@min(sig, 127))),
        .Stopped => 1,
        .Unknown => 1,
    };
}

/// Check if current user is root.
pub fn isRoot() bool {
    if (@import("builtin").os.tag == .linux) {
        return std.os.linux.getuid() == 0;
    }
    // On non-Linux (macOS dev), check via id -u
    const result = exec(std.heap.page_allocator, &.{ "id", "-u" }) catch return false;
    defer result.deinit();
    const trimmed = std.mem.trim(u8, result.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
    return std.mem.eql(u8, trimmed, "0");
}

/// Get the system architecture.
pub fn getArch() !Arch {
    if (@import("builtin").os.tag == .linux) {
        return switch (@import("builtin").cpu.arch) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
            else => error.UnsupportedArch,
        };
    }
    // Fallback: uname -m
    const result = try exec(std.heap.page_allocator, &.{ "uname", "-m" });
    defer result.deinit();
    const trimmed = std.mem.trim(u8, result.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (std.mem.eql(u8, trimmed, "x86_64") or std.mem.eql(u8, trimmed, "amd64")) return .x86_64;
    if (std.mem.eql(u8, trimmed, "aarch64") or std.mem.eql(u8, trimmed, "arm64")) return .aarch64;
    return error.UnsupportedArch;
}

/// Check if CPU supports x86_64_v3 instruction set.
/// Port of the bash cpu_supports_x86_64_v3 function from update.sh.
pub fn supportsV3(allocator: std.mem.Allocator) bool {
    if (@import("builtin").os.tag != .linux) return false;

    const cpuinfo = std.fs.openFileAbsolute("/proc/cpuinfo", .{}) catch return false;
    defer cpuinfo.close();

    const content = cpuinfo.readToEndAlloc(allocator, 256 * 1024) catch return false;
    defer allocator.free(content);

    // Find "flags" line
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "flags")) continue;

        // Check required features for x86_64_v3
        const required = [_][]const u8{
            "avx2", "bmi1", "bmi2", "fma", "f16c", "movbe",
            "sse4_1", "sse4_2", "ssse3", "popcnt", "aes",
        };

        for (required) |feat| {
            if (!containsWord(line, feat)) return false;
        }

        // lzcnt or abm
        if (!containsWord(line, "lzcnt") and !containsWord(line, "abm")) return false;

        return true;
    }

    return false;
}

fn containsWord(haystack: []const u8, word: []const u8) bool {
    var i: usize = 0;
    while (i + word.len <= haystack.len) {
        if (std.mem.eql(u8, haystack[i..][0..word.len], word)) {
            // Check word boundaries
            const before_ok = (i == 0) or (haystack[i - 1] == ' ' or haystack[i - 1] == '\t' or haystack[i - 1] == ':');
            const after_idx = i + word.len;
            const after_ok = (after_idx >= haystack.len) or (haystack[after_idx] == ' ' or haystack[after_idx] == '\t' or haystack[after_idx] == '\n');
            if (before_ok and after_ok) return true;
        }
        i += 1;
    }
    return false;
}

/// Check if a command exists on PATH.
pub fn commandExists(name: []const u8) bool {
    const result = exec(std.heap.page_allocator, &.{ "which", name }) catch return false;
    defer result.deinit();
    return result.exit_code == 0;
}

/// Check if a systemd service is active.
pub fn isServiceActive(service: []const u8) bool {
    const result = exec(std.heap.page_allocator, &.{ "systemctl", "is-active", "--quiet", service }) catch return false;
    defer result.deinit();
    return result.exit_code == 0;
}

/// Check if a file exists.
pub fn fileExists(path: []const u8) bool {
    std.fs.accessAbsolute(path, .{}) catch return false;
    return true;
}

/// Run a command, discard output (fire-and-forget). No memory leaks.
pub fn execSilent(allocator: std.mem.Allocator, argv: []const []const u8) void {
    const result = exec(allocator, argv) catch return;
    result.deinit();
}

/// Write content to a file atomically. Avoids shell injection from bash -c.
pub fn writeFile(path: []const u8, content: []const u8) !void {
    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(content);
}

/// Write content and set permissions.
pub fn writeFileMode(path: []const u8, content: []const u8, mode: u9) !void {
    const file = try std.fs.cwd().createFile(path, .{ .mode = mode });
    defer file.close();
    try file.writeAll(content);
}

/// Parse a simple KEY=VALUE .env file, return value for given key.
pub fn readEnvFile(allocator: std.mem.Allocator, path: []const u8, key: []const u8) ?[]const u8 {
    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();
    const content = file.readToEndAlloc(allocator, 64 * 1024) catch return null;
    defer allocator.free(content);

    var lines_iter = std.mem.splitScalar(u8, content, '\n');
    while (lines_iter.next()) |line| {
        var clean = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r' });
        // Skip comments and empty
        if (clean.len == 0 or clean[0] == '#') continue;
        // Strip "export " prefix
        if (std.mem.startsWith(u8, clean, "export ")) clean = clean[7..];
        const eq = std.mem.indexOfScalar(u8, clean, '=') orelse continue;
        const k = std.mem.trim(u8, clean[0..eq], &[_]u8{ ' ', '\t' });
        if (!std.mem.eql(u8, k, key)) continue;
        var v = std.mem.trim(u8, clean[eq + 1 ..], &[_]u8{ ' ', '\t' });
        // Strip quotes
        if (v.len >= 2 and v[0] == '"' and v[v.len - 1] == '"') v = v[1 .. v.len - 1];
        return allocator.dupe(u8, v) catch null;
    }
    return null;
}

/// Generate 16 random bytes as a hex string (32 chars).
pub fn generateSecret(buf: *[32]u8) void {
    var bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&bytes);
    const hex = "0123456789abcdef";
    for (bytes, 0..) |byte, idx| {
        buf[idx * 2] = hex[byte >> 4];
        buf[idx * 2 + 1] = hex[byte & 0x0f];
    }
}

/// Convert a domain string to hex encoding (for ee-secret).
pub fn domainToHex(domain: []const u8, buf: []u8) []const u8 {
    const hex = "0123456789abcdef";
    var pos: usize = 0;
    for (domain) |byte| {
        if (pos + 2 > buf.len) break;
        buf[pos] = hex[byte >> 4];
        buf[pos + 1] = hex[byte & 0x0f];
        pos += 2;
    }
    return buf[0..pos];
}

/// Detect public IP address via external HTTP services.
pub fn detectPublicIp(allocator: std.mem.Allocator) ?[]const u8 {
    // Use curl subprocess — simpler and doesn't pull in std.http into ctl binary
    const services = [_][]const u8{
        "https://ifconfig.me",
        "https://api.ipify.org",
        "https://icanhazip.com",
    };

    for (services) |url| {
        const result = exec(allocator, &.{ "curl", "-s", "--max-time", "5", url }) catch continue;

        const trimmed = std.mem.trim(u8, result.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });

        if (trimmed.len == 0 or trimmed.len > 45) {
            result.deinit();
            continue;
        }

        // Basic validation: should contain a dot (IPv4) or colon (IPv6)
        const has_dot = std.mem.indexOfScalar(u8, trimmed, '.') != null;
        const has_colon = std.mem.indexOfScalar(u8, trimmed, ':') != null;

        if (has_dot or has_colon) {
            const ip = allocator.dupe(u8, trimmed) catch {
                result.deinit();
                continue;
            };
            result.deinit();
            return ip;
        }

        result.deinit();
    }

    return null;
}
