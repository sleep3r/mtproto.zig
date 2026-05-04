//! Upstream transport abstraction for proxy egress connections.
//!
//! This tagged union defines the transport interface used by the proxy
//! when creating upstream sockets. Today it provides:
//!   - direct: plain TCP connect (namespace-level tunnels like AmneziaWG)
//!   - socks5: SOCKS5 proxy with optional username/password auth
//!   - http_connect: HTTP CONNECT proxy with optional Basic auth
//!
//! For SOCKS5 and HTTP CONNECT, the initial `connect()` creates a TCP
//! socket to the *proxy server*. The actual proxy protocol handshake
//! (SOCKS5 greeting→auth→connect, or HTTP CONNECT request→response)
//! is driven by the event loop as non-blocking state machine phases.
//!
//! The `tunnel_info` field carries metadata about the active tunnel
//! (see `tunnel.zig`). For namespace-based tunnels like AmneziaWG,
//! the connect variant stays `direct`, but may apply `SO_MARK` so Linux
//! policy routing can steer selected sockets through the tunnel.

const std = @import("std");
const builtin = @import("builtin");
const net = std.Io.net;
const posix = std.posix;
const tunnel_mod = @import("../tunnel.zig");
const Address = net.IpAddress;

pub const Tunnel = tunnel_mod.Tunnel;

const SocketAddr = union(enum) {
    ip4: posix.sockaddr.in,
    ip6: posix.sockaddr.in6,
};

fn socketFamily(addr: Address) posix.sa_family_t {
    return switch (addr) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
}

fn toSocketAddr(addr: Address) SocketAddr {
    return switch (addr) {
        .ip4 => |ip4| .{ .ip4 = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, ip4.port),
            .addr = @bitCast(ip4.bytes),
        } },
        .ip6 => |ip6| .{ .ip6 = .{
            .family = posix.AF.INET6,
            .port = std.mem.nativeToBig(u16, ip6.port),
            .flowinfo = ip6.flow,
            .addr = ip6.bytes,
            .scope_id = ip6.interface.index,
        } },
    };
}

fn connectSocket(fd: posix.fd_t, addr: Address) !void {
    var sa = toSocketAddr(addr);
    switch (sa) {
        .ip4 => |*a| try connectSockaddr(fd, @ptrCast(&a.*), @sizeOf(posix.sockaddr.in)),
        .ip6 => |*a| try connectSockaddr(fd, @ptrCast(&a.*), @sizeOf(posix.sockaddr.in6)),
    }
}

fn createTcpSocket(family: posix.sa_family_t) !posix.fd_t {
    const flags = posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC;
    while (true) {
        const rc = posix.system.socket(family, flags, posix.IPPROTO.TCP);
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .PROTONOSUPPORT => return error.ProtocolUnsupportedByAddressFamily,
            .PROTOTYPE => return error.SocketModeUnsupported,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn closeFd(fd: posix.fd_t) void {
    while (true) switch (posix.errno(posix.system.close(fd))) {
        .SUCCESS => return,
        .INTR => continue,
        else => return,
    };
}

fn connectSockaddr(fd: posix.fd_t, addr: *const posix.sockaddr, addr_len: posix.socklen_t) !void {
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

/// What proxy-level handshake (if any) must be completed after TCP connect.
pub const ProxyHandshake = enum {
    /// Direct connection — no proxy handshake needed.
    none,
    /// SOCKS5 handshake required (greeting → auth → CONNECT).
    socks5,
    /// HTTP CONNECT handshake required (CONNECT request → response).
    http_connect,
};

pub const ConnectResult = struct {
    fd: posix.fd_t,
    pending: bool,
    /// What proxy handshake to run after TCP connect completes.
    proxy_handshake: ProxyHandshake = .none,
};

pub const Tag = enum {
    direct,
    socks5,
    http_connect,
};

pub const Upstream = union(Tag) {
    direct: Direct,
    socks5: Socks5,
    http_connect: HttpConnect,

    pub fn initDirect() Upstream {
        return .{ .direct = .{} };
    }

    pub fn initDirectWithMark(mark: u32) Upstream {
        return .{ .direct = .{ .socket_mark = mark } };
    }

    pub fn initSocks5(
        proxy_addr: Address,
        username: ?[]const u8,
        password: ?[]const u8,
    ) Upstream {
        return .{ .socks5 = .{
            .proxy_addr = proxy_addr,
            .username = username,
            .password = password,
        } };
    }

    pub fn initHttpConnect(
        proxy_addr: Address,
        username: ?[]const u8,
        password: ?[]const u8,
    ) Upstream {
        return .{ .http_connect = .{
            .proxy_addr = proxy_addr,
            .username = username,
            .password = password,
        } };
    }

    /// Create a non-blocking upstream socket.
    ///
    /// For `direct`, connects to `addr` directly.
    /// For proxy variants, connects to the proxy server; the caller
    /// must check `proxy_handshake` and run the appropriate handshake
    /// before using the socket for DC traffic.
    pub fn connect(self: *const Upstream, addr: Address) !ConnectResult {
        return switch (self.*) {
            .direct => |connector| connector.connect(addr),
            .socks5 => |connector| connector.connect(),
            .http_connect => |connector| connector.connect(),
        };
    }

    /// Get the proxy server address (for logging), or null for direct.
    pub fn proxyAddr(self: *const Upstream) ?Address {
        return switch (self.*) {
            .direct => null,
            .socks5 => |s| s.proxy_addr,
            .http_connect => |h| h.proxy_addr,
        };
    }

    /// Get proxy credentials for the handshake protocol modules.
    pub fn proxyUsername(self: *const Upstream) ?[]const u8 {
        return switch (self.*) {
            .direct => null,
            .socks5 => |s| s.username,
            .http_connect => |h| h.username,
        };
    }

    pub fn proxyPassword(self: *const Upstream) ?[]const u8 {
        return switch (self.*) {
            .direct => null,
            .socks5 => |s| s.password,
            .http_connect => |h| h.password,
        };
    }
};

pub const Direct = struct {
    socket_mark: ?u32 = null,

    pub fn connect(self: Direct, addr: Address) !ConnectResult {
        const fd = try createTcpSocket(socketFamily(addr));
        errdefer closeFd(fd);

        if (self.socket_mark) |mark| {
            try applySocketMark(fd, mark);
        }

        connectSocket(fd, addr) catch |err| switch (err) {
            error.WouldBlock, error.ConnectionPending => {
                return .{ .fd = fd, .pending = true };
            },
            else => return err,
        };

        return .{ .fd = fd, .pending = false };
    }
};

pub const Socks5 = struct {
    proxy_addr: Address,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    socket_mark: ?u32 = null,

    /// Connect to the SOCKS5 proxy server (not the target DC).
    /// Returns a result with `.proxy_handshake = .socks5`.
    pub fn connect(self: Socks5) !ConnectResult {
        const fd = try createTcpSocket(socketFamily(self.proxy_addr));
        errdefer closeFd(fd);

        if (self.socket_mark) |mark| {
            try applySocketMark(fd, mark);
        }

        connectSocket(fd, self.proxy_addr) catch |err| switch (err) {
            error.WouldBlock, error.ConnectionPending => {
                return .{ .fd = fd, .pending = true, .proxy_handshake = .socks5 };
            },
            else => return err,
        };

        return .{ .fd = fd, .pending = false, .proxy_handshake = .socks5 };
    }

    /// Whether auth is needed (username is non-null and non-empty).
    pub fn needsAuth(self: Socks5) bool {
        if (self.username) |u| return u.len > 0;
        return false;
    }
};

pub const HttpConnect = struct {
    proxy_addr: Address,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    socket_mark: ?u32 = null,

    /// Connect to the HTTP proxy server (not the target DC).
    /// Returns a result with `.proxy_handshake = .http_connect`.
    pub fn connect(self: HttpConnect) !ConnectResult {
        const fd = try createTcpSocket(socketFamily(self.proxy_addr));
        errdefer closeFd(fd);

        if (self.socket_mark) |mark| {
            try applySocketMark(fd, mark);
        }

        connectSocket(fd, self.proxy_addr) catch |err| switch (err) {
            error.WouldBlock, error.ConnectionPending => {
                return .{ .fd = fd, .pending = true, .proxy_handshake = .http_connect };
            },
            else => return err,
        };

        return .{ .fd = fd, .pending = false, .proxy_handshake = .http_connect };
    }
};

fn applySocketMark(fd: posix.fd_t, mark: u32) !void {
    if (builtin.os.tag != .linux) return;

    const so_mark: u32 = 36;
    var mark_value: u32 = mark;
    try posix.setsockopt(fd, posix.SOL.SOCKET, so_mark, std.mem.asBytes(&mark_value));
}
