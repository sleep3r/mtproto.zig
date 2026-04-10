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
//! the connect variant stays `direct` because the proxy process itself
//! runs inside the namespace — so all TCP connects implicitly traverse
//! the tunnel without socket-level wrapping.

const std = @import("std");
const net = std.net;
const posix = std.posix;
const tunnel_mod = @import("../tunnel.zig");

pub const Tunnel = tunnel_mod.Tunnel;

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

    pub fn initSocks5(
        proxy_addr: net.Address,
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
        proxy_addr: net.Address,
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
    pub fn connect(self: *const Upstream, addr: net.Address) !ConnectResult {
        return switch (self.*) {
            .direct => |connector| connector.connect(addr),
            .socks5 => |connector| connector.connect(),
            .http_connect => |connector| connector.connect(),
        };
    }

    /// Get the proxy server address (for logging), or null for direct.
    pub fn proxyAddr(self: *const Upstream) ?net.Address {
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
    pub fn connect(_: Direct, addr: net.Address) !ConnectResult {
        const fd = try posix.socket(
            addr.any.family,
            posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC,
            posix.IPPROTO.TCP,
        );
        errdefer posix.close(fd);

        posix.connect(fd, &addr.any, addr.getOsSockLen()) catch |err| switch (err) {
            error.WouldBlock, error.ConnectionPending => {
                return .{ .fd = fd, .pending = true };
            },
            else => return err,
        };

        return .{ .fd = fd, .pending = false };
    }
};

pub const Socks5 = struct {
    proxy_addr: net.Address,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,

    /// Connect to the SOCKS5 proxy server (not the target DC).
    /// Returns a result with `.proxy_handshake = .socks5`.
    pub fn connect(self: Socks5) !ConnectResult {
        const fd = try posix.socket(
            self.proxy_addr.any.family,
            posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC,
            posix.IPPROTO.TCP,
        );
        errdefer posix.close(fd);

        posix.connect(fd, &self.proxy_addr.any, self.proxy_addr.getOsSockLen()) catch |err| switch (err) {
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
    proxy_addr: net.Address,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,

    /// Connect to the HTTP proxy server (not the target DC).
    /// Returns a result with `.proxy_handshake = .http_connect`.
    pub fn connect(self: HttpConnect) !ConnectResult {
        const fd = try posix.socket(
            self.proxy_addr.any.family,
            posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC,
            posix.IPPROTO.TCP,
        );
        errdefer posix.close(fd);

        posix.connect(fd, &self.proxy_addr.any, self.proxy_addr.getOsSockLen()) catch |err| switch (err) {
            error.WouldBlock, error.ConnectionPending => {
                return .{ .fd = fd, .pending = true, .proxy_handshake = .http_connect };
            },
            else => return err,
        };

        return .{ .fd = fd, .pending = false, .proxy_handshake = .http_connect };
    }
};
