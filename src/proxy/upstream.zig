//! Upstream transport abstraction for proxy egress connections.
//!
//! This tagged union defines the transport interface used by the proxy
//! when creating upstream sockets. Today it only provides a direct TCP
//! connector, but new variants (SOCKS5, HTTP CONNECT, custom tunnels)
//! can be added without changing the event loop call sites.

const std = @import("std");
const net = std.net;
const posix = std.posix;

pub const ConnectResult = struct {
    fd: posix.fd_t,
    pending: bool,
};

pub const Tag = enum {
    direct,
};

pub const Upstream = union(Tag) {
    direct: Direct,

    pub fn initDirect() Upstream {
        return .{ .direct = .{} };
    }

    pub fn connect(self: *const Upstream, addr: net.Address) !ConnectResult {
        return switch (self.*) {
            .direct => |connector| connector.connect(addr),
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
