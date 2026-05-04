const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

pub const ConnectionPhase = enum {
    idle,
    reading_tls_header,
    reading_client_hello_body,
    writing_server_hello_first,
    desync_wait,
    writing_server_hello_rest,
    reading_mtproto_tls_header,
    reading_mtproto_tls_body,
    connecting_upstream,
    // SOCKS5 proxy handshake sub-phases
    proxy_socks5_greeting,
    proxy_socks5_greeting_resp,
    proxy_socks5_auth,
    proxy_socks5_auth_resp,
    proxy_socks5_connect,
    proxy_socks5_connect_resp,
    // HTTP CONNECT proxy handshake sub-phases
    proxy_http_connect,
    proxy_http_connect_resp,
    writing_dc_nonce,
    middle_proxy_handshake,
    relaying,
    mask_relaying,
    closing,
};

pub fn hasFatalEpollHangup(events: u32) bool {
    return (events & (linux.EPOLL.ERR | linux.EPOLL.HUP | linux.EPOLL.RDHUP)) != 0;
}

/// Check if a phase is one of the proxy handshake sub-phases.
pub fn isProxyHandshakePhase(phase: ConnectionPhase) bool {
    return switch (phase) {
        .proxy_socks5_greeting,
        .proxy_socks5_greeting_resp,
        .proxy_socks5_auth,
        .proxy_socks5_auth_resp,
        .proxy_socks5_connect,
        .proxy_socks5_connect_resp,
        .proxy_http_connect,
        .proxy_http_connect_resp,
        => true,
        else => false,
    };
}

pub fn shouldCloseOnFatalHangup(phase: ConnectionPhase, event_fd: posix.fd_t, upstream_fd: posix.fd_t) bool {
    if (phase == .idle) return false;

    // During connecting_upstream, EPOLLERR on upstream fd is expected and
    // handled via onUpstreamWritable -> onUpstreamConnectComplete.
    if (phase == .connecting_upstream and event_fd == upstream_fd) return false;

    // During proxy handshake phases, upstream hangup is a proxy
    // connect failure — let the handler deal with it.
    if (isProxyHandshakePhase(phase) and event_fd == upstream_fd) return false;

    return true;
}

test "epoll hangup helper" {
    try std.testing.expect(hasFatalEpollHangup(linux.EPOLL.RDHUP));
    try std.testing.expect(hasFatalEpollHangup(linux.EPOLL.HUP));
    try std.testing.expect(hasFatalEpollHangup(linux.EPOLL.ERR));
    try std.testing.expect(!hasFatalEpollHangup(linux.EPOLL.IN));
}

test "fatal hangup close policy distinguishes client/upstream while connecting" {
    const client_fd: posix.fd_t = 41;
    const upstream_fd: posix.fd_t = 42;

    try std.testing.expect(shouldCloseOnFatalHangup(.connecting_upstream, client_fd, upstream_fd));
    try std.testing.expect(!shouldCloseOnFatalHangup(.connecting_upstream, upstream_fd, upstream_fd));
    try std.testing.expect(shouldCloseOnFatalHangup(.reading_tls_header, client_fd, upstream_fd));
    try std.testing.expect(!shouldCloseOnFatalHangup(.idle, client_fd, upstream_fd));
}
