const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const net = std.Io.net;
const Address = net.IpAddress;

pub const AcceptError = error{
    ConnectionAborted,
    ConnectionResetByPeer,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    UnexpectedAccept,
};

pub const AcceptResult = struct {
    fd: posix.fd_t,
    addr: Address,
};

pub fn epollCreate() !posix.fd_t {
    const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub fn realtimeSeconds() i64 {
    var ts: posix.timespec = undefined;
    const rc = posix.system.clock_gettime(.REALTIME, &ts);
    if (posix.errno(rc) == .SUCCESS) return @intCast(ts.sec);
    return @divTrunc(nowMs(), 1000);
}

pub fn nowMs() i64 {
    var ts: posix.timespec = undefined;
    const rc = posix.system.clock_gettime(.MONOTONIC, &ts);
    if (posix.errno(rc) == .SUCCESS) {
        return @as(i64, @intCast(ts.sec)) * std.time.ms_per_s +
            @as(i64, @intCast(@divTrunc(ts.nsec, std.time.ns_per_ms)));
    }
    return 0;
}

pub fn nowNs() i128 {
    var ts: posix.timespec = undefined;
    const rc = posix.system.clock_gettime(.MONOTONIC, &ts);
    if (posix.errno(rc) == .SUCCESS) {
        return @as(i128, @intCast(ts.sec)) * std.time.ns_per_s + @as(i128, @intCast(ts.nsec));
    }
    return @as(i128, nowMs()) * std.time.ns_per_ms;
}

pub fn sleepNs(ns: u64) void {
    var req: posix.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    while (true) {
        var rem: posix.timespec = undefined;
        const rc = posix.system.nanosleep(&req, &rem);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => req = rem,
            else => return,
        }
    }
}

pub fn closeFd(fd: posix.fd_t) void {
    while (true) {
        switch (posix.errno(posix.system.close(fd))) {
            .SUCCESS => return,
            .INTR => continue,
            else => return,
        }
    }
}

pub fn connectSockaddr(fd: posix.fd_t, addr: *const posix.sockaddr, addr_len: posix.socklen_t) !void {
    while (true) switch (posix.errno(posix.system.connect(fd, addr, addr_len))) {
        .SUCCESS => return,
        .INTR => continue,
        .ADDRNOTAVAIL => return error.AddressUnavailable,
        .AFNOSUPPORT => return error.AddressFamilyUnsupported,
        .AGAIN, .INPROGRESS => return error.WouldBlock,
        .ALREADY => return error.ConnectionPending,
        .CONNREFUSED => return error.ConnectionRefused,
        .CONNRESET => return error.ConnectionResetByPeer,
        .HOSTUNREACH => return error.HostUnreachable,
        .NETUNREACH => return error.NetworkUnreachable,
        .TIMEDOUT => return error.Timeout,
        else => |err| return posix.unexpectedErrno(err),
    };
}

pub fn checkSocketConnectError(fd: posix.fd_t) !void {
    var so_error: i32 = 0;
    var opt_len: linux.socklen_t = @sizeOf(i32);
    const so_error_opt: u32 = 4; // SO_ERROR
    const rc = linux.getsockopt(fd, posix.SOL.SOCKET, so_error_opt, std.mem.asBytes(&so_error).ptr, &opt_len);
    if (linux.errno(rc) != .SUCCESS) return error.Unexpected;
    if (so_error == 0) return;
    // Map SO_ERROR to a specific error so failover logs distinguish DPI blackholing/
    // throttling (ETIMEDOUT/EHOSTUNREACH/ENETUNREACH) from a genuine refusal — the old code
    // collapsed every cause into ConnectionRefused, hiding exactly what an operator needs.
    return switch (@as(posix.E, @enumFromInt(so_error))) {
        .TIMEDOUT => error.Timeout,
        .CONNREFUSED => error.ConnectionRefused,
        .HOSTUNREACH => error.HostUnreachable,
        .NETUNREACH => error.NetworkUnreachable,
        .CONNRESET => error.ConnectionResetByPeer,
        else => error.ConnectionRefused,
    };
}

pub fn addressFromSockaddrStorage(storage: *const posix.sockaddr.storage) ?Address {
    return switch (storage.family) {
        posix.AF.INET => blk: {
            const sa4: *const posix.sockaddr.in = @ptrCast(storage);
            break :blk .{
                .ip4 = .{
                    .bytes = @bitCast(sa4.addr),
                    .port = std.mem.bigToNative(u16, sa4.port),
                },
            };
        },
        posix.AF.INET6 => blk: {
            const sa6: *const posix.sockaddr.in6 = @ptrCast(storage);
            break :blk .{
                .ip6 = .{
                    .bytes = sa6.addr,
                    .port = std.mem.bigToNative(u16, sa6.port),
                    .flow = sa6.flowinfo,
                    .interface = .{ .index = sa6.scope_id },
                },
            };
        },
        else => null,
    };
}

pub fn acceptClient(listen_fd: posix.fd_t) AcceptError!?AcceptResult {
    while (true) {
        var storage: posix.sockaddr.storage = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        const rc = linux.accept4(listen_fd, @ptrCast(&storage), &addr_len, posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                const fd: posix.fd_t = @intCast(rc);
                const addr = addressFromSockaddrStorage(&storage) orelse {
                    closeFd(fd);
                    continue;
                };
                return .{ .fd = fd, .addr = addr };
            },
            .INTR => continue,
            .AGAIN => return null,
            .CONNABORTED => return error.ConnectionAborted,
            .CONNRESET => return error.ConnectionResetByPeer,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOBUFS, .NOMEM => return error.SystemResources,
            else => return error.UnexpectedAccept,
        }
    }
}

pub fn localSocketAddress(fd: posix.fd_t) !Address {
    var storage: posix.sockaddr.storage = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    while (true) {
        const rc = posix.system.getsockname(fd, @ptrCast(&storage), &addr_len);
        switch (posix.errno(rc)) {
            .SUCCESS => return addressFromSockaddrStorage(&storage) orelse error.UnsupportedAddressFamily,
            .INTR => continue,
            else => return error.GetSockNameFailed,
        }
    }
}

pub fn setNonBlocking(fd: posix.fd_t) void {
    var fl_flags = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
    if (posix.errno(fl_flags) != .SUCCESS) return;
    fl_flags |= @as(usize, 1 << @bitOffsetOf(posix.O, "NONBLOCK"));
    if (posix.errno(posix.system.fcntl(fd, posix.F.SETFL, fl_flags)) != .SUCCESS) return;
}

pub fn secondsToMs(sec: u32) i64 {
    return @as(i64, @intCast(sec)) * std.time.ms_per_s;
}

/// Bound how long unacknowledged transmit data may stay outstanding before the connection
/// is failed. Unlike SO_SNDTIMEO (which only affects BLOCKING send and is therefore inert
/// on our non-blocking relay sockets), TCP_USER_TIMEOUT works regardless of blocking mode.
pub fn setTcpUserTimeout(fd: posix.fd_t, timeout_ms: u32) void {
    const sol_tcp: i32 = 6; // IPPROTO_TCP
    const tcp_user_timeout: u32 = 18; // TCP_USER_TIMEOUT
    const val: c_uint = timeout_ms;
    posix.setsockopt(fd, sol_tcp, tcp_user_timeout, std.mem.asBytes(&val)) catch return;
}

pub fn setTcpKeepalive(fd: posix.fd_t) void {
    const sol_tcp: i32 = 6;

    const enable: c_int = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&enable)) catch return;

    const idle: c_int = 60;
    posix.setsockopt(fd, sol_tcp, 4, std.mem.asBytes(&idle)) catch return;

    const interval: c_int = 10;
    posix.setsockopt(fd, sol_tcp, 5, std.mem.asBytes(&interval)) catch return;

    const count: c_int = 3;
    posix.setsockopt(fd, sol_tcp, 6, std.mem.asBytes(&count)) catch return;
}

pub fn setTcpNoDelay(fd: posix.fd_t) void {
    const enable: c_int = 1;
    posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.NODELAY, std.mem.asBytes(&enable)) catch return;
}

/// Force a TCP RST on close instead of a graceful FIN, via SO_LINGER with a zero
/// timeout. Used to mirror a server/middlebox that resets a rejected handshake.
pub fn setLingerReset(fd: posix.fd_t) void {
    // Linux `struct linger { int l_onoff; int l_linger; }`. Defined locally as an
    // i32/i32 extern struct so it compiles on every target (only the Linux runtime
    // path actually sets it); setsockopt just copies the bytes.
    const Linger = extern struct { l_onoff: i32, l_linger: i32 };
    const lin = Linger{ .l_onoff = 1, .l_linger = 0 };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.LINGER, std.mem.asBytes(&lin)) catch return;
}

pub fn configureRelaySocket(fd: posix.fd_t) void {
    setTcpNoDelay(fd);
    setTcpKeepalive(fd);
    // 30s cap on unacknowledged data (effective on non-blocking sockets, unlike SO_SNDTIMEO).
    setTcpUserTimeout(fd, 30_000);
}

pub fn formatAddress(addr: Address, buf: *[64]u8) []const u8 {
    return switch (addr) {
        .ip4 => |ip4_addr| std.fmt.bufPrint(buf, "[ipv4]:{d}", .{ip4_addr.port}) catch "?",
        .ip6 => |ip6_addr| blk: {
            const bytes = &ip6_addr.bytes;
            const is_ipv4_mapped = std.mem.eql(u8, bytes[0..10], &[_]u8{0} ** 10) and
                std.mem.eql(u8, bytes[10..12], &[_]u8{ 0xff, 0xff });
            if (is_ipv4_mapped) {
                break :blk std.fmt.bufPrint(buf, "[ipv4]:{d}", .{ip6_addr.port}) catch "?";
            }
            break :blk std.fmt.bufPrint(buf, "[ipv6]:{d}", .{ip6_addr.port}) catch "?";
        },
    };
}
