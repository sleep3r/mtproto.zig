//! Minimal native sd_notify(3) — talk to the systemd notification socket named
//! by $NOTIFY_SOCKET with zero dependencies. Everything is BEST-EFFORT: if the
//! env var is absent (not run under systemd) or any syscall fails, it is a
//! silent no-op, so the proxy runs identically with or without systemd.

const std = @import("std");
const posix = std.posix;

/// Build an AF_UNIX address for `name`. `name` is either an absolute path or an
/// abstract socket starting with '@' (encoded as a leading NUL byte). Returns
/// the address plus its used length, or null if it doesn't fit.
fn buildAddr(name: []const u8) ?struct { addr: posix.sockaddr.un, len: posix.socklen_t } {
    if (name.len == 0) return null;
    var addr: posix.sockaddr.un = .{ .family = posix.AF.UNIX, .path = undefined };
    const base: posix.socklen_t = @offsetOf(posix.sockaddr.un, "path");
    if (name[0] == '@') {
        // Abstract namespace: path = NUL ++ name[1..], no trailing NUL.
        if (name.len > addr.path.len) return null; // 1 (NUL) + (name.len-1) chars
        addr.path[0] = 0;
        @memcpy(addr.path[1..name.len], name[1..]);
        return .{ .addr = addr, .len = base + @as(posix.socklen_t, @intCast(name.len)) };
    } else {
        // Filesystem path: name ++ NUL.
        if (name.len + 1 > addr.path.len) return null;
        @memcpy(addr.path[0..name.len], name);
        addr.path[name.len] = 0;
        return .{ .addr = addr, .len = base + @as(posix.socklen_t, @intCast(name.len + 1)) };
    }
}

/// Send a newline-terminated status message to $NOTIFY_SOCKET. No-op on any error.
pub fn notify(socket_path: ?[]const u8, message: []const u8) void {
    const path = socket_path orelse return;
    const built = buildAddr(path) orelse return;
    var a = built;

    const fd_rc = posix.system.socket(posix.AF.UNIX, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    if (posix.errno(fd_rc) != .SUCCESS) return;
    const fd: posix.fd_t = @intCast(fd_rc);
    defer _ = posix.system.close(fd);

    _ = posix.system.sendto(fd, message.ptr, message.len, 0, @ptrCast(&a.addr), a.len);
}

/// Tell systemd the service finished startup and is ready (Type=notify gate).
pub fn ready(socket_path: ?[]const u8) void {
    notify(socket_path, "READY=1\n");
}

/// Pet the systemd watchdog (requires WatchdogSec= in the unit).
pub fn watchdog(socket_path: ?[]const u8) void {
    notify(socket_path, "WATCHDOG=1\n");
}

test "sd_notify abstract vs path address encoding" {
    const base = @offsetOf(posix.sockaddr.un, "path");
    // Abstract: '@foo' -> [0,'f','o','o'], len = base + 4 (no trailing NUL).
    const abs = buildAddr("@foo").?;
    try std.testing.expectEqual(@as(posix.socklen_t, base + 4), abs.len);
    try std.testing.expectEqual(@as(u8, 0), abs.addr.path[0]);
    try std.testing.expectEqualStrings("foo", abs.addr.path[1..4]);
    // Path: '/run/x' -> '/run/x\0', len = base + 7 (with trailing NUL).
    const p = buildAddr("/run/x").?;
    try std.testing.expectEqual(@as(posix.socklen_t, base + 7), p.len);
    try std.testing.expectEqualStrings("/run/x", p.addr.path[0..6]);
    try std.testing.expectEqual(@as(u8, 0), p.addr.path[6]);
    try std.testing.expect(buildAddr("") == null);
}
