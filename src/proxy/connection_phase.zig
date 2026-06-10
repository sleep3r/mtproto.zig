const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

pub const ConnectionPhase = enum {
    idle,
    reading_tls_header,
    reading_direct_obfuscated_handshake,
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

/// True when a handshake-phase timeout is attributable to the CLIENT (we are reading the
/// client's handshake or writing our ServerHello to it), as opposed to an upstream-driven
/// stall: connecting to a DC, talking to an upstream SOCKS5/HTTP proxy, or running the
/// middleproxy RPC handshake. Only client-driven timeouts should feed the per-IP flood
/// guard; otherwise an upstream outage behind one CGNAT IP turns into client blocks.
pub fn isClientDrivenHandshakePhase(phase: ConnectionPhase) bool {
    return switch (phase) {
        .reading_tls_header,
        .reading_direct_obfuscated_handshake,
        .reading_client_hello_body,
        .writing_server_hello_first,
        .desync_wait,
        .writing_server_hello_rest,
        .reading_mtproto_tls_header,
        .reading_mtproto_tls_body,
        => true,
        // connecting_upstream, writing_dc_nonce, middle_proxy_handshake, all proxy_*
        // handshake sub-phases, and non-handshake phases are not the client's fault.
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

test "client-driven handshake phase classification" {
    // Client-side handshake phases are the client's fault on timeout.
    try std.testing.expect(isClientDrivenHandshakePhase(.reading_tls_header));
    try std.testing.expect(isClientDrivenHandshakePhase(.reading_direct_obfuscated_handshake));
    try std.testing.expect(isClientDrivenHandshakePhase(.reading_mtproto_tls_body));
    try std.testing.expect(isClientDrivenHandshakePhase(.writing_server_hello_first));
    // Upstream-driven phases must NOT be blamed on the client (NAT/VPN false positives).
    try std.testing.expect(!isClientDrivenHandshakePhase(.connecting_upstream));
    try std.testing.expect(!isClientDrivenHandshakePhase(.writing_dc_nonce));
    try std.testing.expect(!isClientDrivenHandshakePhase(.middle_proxy_handshake));
    try std.testing.expect(!isClientDrivenHandshakePhase(.proxy_socks5_greeting));
    try std.testing.expect(!isClientDrivenHandshakePhase(.proxy_http_connect_resp));
    try std.testing.expect(!isClientDrivenHandshakePhase(.relaying));
}

test "fatal hangup close policy distinguishes client/upstream while connecting" {
    const client_fd: posix.fd_t = 41;
    const upstream_fd: posix.fd_t = 42;

    try std.testing.expect(shouldCloseOnFatalHangup(.connecting_upstream, client_fd, upstream_fd));
    try std.testing.expect(!shouldCloseOnFatalHangup(.connecting_upstream, upstream_fd, upstream_fd));
    try std.testing.expect(shouldCloseOnFatalHangup(.reading_tls_header, client_fd, upstream_fd));
    try std.testing.expect(shouldCloseOnFatalHangup(.reading_direct_obfuscated_handshake, client_fd, upstream_fd));
    try std.testing.expect(!shouldCloseOnFatalHangup(.idle, client_fd, upstream_fd));
}
