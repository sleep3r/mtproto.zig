const std = @import("std");
const posix = std.posix;

const http_connect = @import("http_connect.zig");
const socks5 = @import("socks5.zig");

const log = std.log.scoped(.proxy);

fn hasUpstreamPending(slot: anytype) bool {
    return !slot.upstream_queue.isEmpty();
}

fn sendSocks5Auth(
    loop: anytype,
    slot: anytype,
    comptime queue_upstream: fn (@TypeOf(loop), @TypeOf(slot), []const u8) anyerror!bool,
    comptime close_slot: fn (@TypeOf(loop), @TypeOf(slot), []const u8) void,
) void {
    const username = loop.state.upstream.proxyUsername() orelse "";
    const password = loop.state.upstream.proxyPassword() orelse "";

    const msg = socks5.buildAuthRequest(&slot.proxy_handshake_buf, username, password);
    if (msg.len == 0) {
        close_slot(loop, slot, "socks5 auth request build failed");
        return;
    }

    if (queue_upstream(loop, slot, msg)) |_| {} else |err| {
        log.debug("[{d}] socks5 auth queue error: {any}", .{ slot.conn_id, err });
        close_slot(loop, slot, "socks5 auth queue failed");
        return;
    }

    slot.phase = if (hasUpstreamPending(slot))
        .proxy_socks5_auth
    else
        .proxy_socks5_auth_resp;
    slot.proxy_handshake_pos = 0;
}

fn sendSocks5Connect(
    loop: anytype,
    slot: anytype,
    comptime queue_upstream: fn (@TypeOf(loop), @TypeOf(slot), []const u8) anyerror!bool,
    comptime close_slot: fn (@TypeOf(loop), @TypeOf(slot), []const u8) void,
) void {
    const target = slot.proxy_target_addr orelse {
        close_slot(loop, slot, "socks5 no target addr");
        return;
    };

    const msg = socks5.buildConnectRequest(&slot.proxy_handshake_buf, target);
    if (msg.len == 0) {
        close_slot(loop, slot, "socks5 connect request build failed");
        return;
    }

    if (queue_upstream(loop, slot, msg)) |_| {} else |err| {
        log.debug("[{d}] socks5 connect queue error: {any}", .{ slot.conn_id, err });
        close_slot(loop, slot, "socks5 connect queue failed");
        return;
    }

    slot.phase = if (hasUpstreamPending(slot))
        .proxy_socks5_connect
    else
        .proxy_socks5_connect_resp;
    slot.proxy_handshake_pos = 0;
}

pub fn startSocks5(
    loop: anytype,
    slot: anytype,
    comptime queue_upstream: fn (@TypeOf(loop), @TypeOf(slot), []const u8) anyerror!bool,
    comptime close_slot: fn (@TypeOf(loop), @TypeOf(slot), []const u8) void,
) void {
    const needs_auth = loop.state.upstream.socks5.needsAuth();
    const msg = socks5.buildGreeting(&slot.proxy_handshake_buf, needs_auth);
    if (msg.len == 0) {
        close_slot(loop, slot, "socks5 greeting build failed");
        return;
    }

    if (queue_upstream(loop, slot, msg)) |_| {} else |err| {
        log.debug("[{d}] socks5 greeting queue error: {any}", .{ slot.conn_id, err });
        close_slot(loop, slot, "socks5 greeting queue failed");
        return;
    }

    slot.phase = if (hasUpstreamPending(slot))
        .proxy_socks5_greeting
    else
        .proxy_socks5_greeting_resp;
    slot.proxy_handshake_pos = 0;
}

pub fn onSocks5Readable(
    loop: anytype,
    slot: anytype,
    comptime queue_upstream: fn (@TypeOf(loop), @TypeOf(slot), []const u8) anyerror!bool,
    comptime close_slot: fn (@TypeOf(loop), @TypeOf(slot), []const u8) void,
    comptime handshake_complete: fn (@TypeOf(loop), @TypeOf(slot)) void,
) void {
    // Read into proxy_handshake_buf at current pos
    const pos: usize = slot.proxy_handshake_pos;
    const space = slot.proxy_handshake_buf[pos..];
    if (space.len == 0) {
        close_slot(loop, slot, "socks5 response buffer overflow");
        return;
    }

    const n = posix.read(slot.upstream_fd, space) catch |err| {
        log.debug("[{d}] socks5 read error: {any}", .{ slot.conn_id, err });
        if (err == error.WouldBlock) return;
        close_slot(loop, slot, "socks5 read failed");
        return;
    };

    if (n == 0) {
        close_slot(loop, slot, "socks5 proxy closed connection");
        return;
    }

    slot.proxy_handshake_pos += @intCast(n);
    const have = slot.proxy_handshake_buf[0..slot.proxy_handshake_pos];

    switch (slot.phase) {
        .proxy_socks5_greeting_resp => {
            if (have.len < socks5.greeting_response_len) return; // need more

            const method = socks5.parseGreetingResponse(have) orelse {
                close_slot(loop, slot, "socks5 invalid greeting response");
                return;
            };

            switch (method) {
                .no_auth => {
                    sendSocks5Connect(loop, slot, queue_upstream, close_slot);
                },
                .username_password => {
                    sendSocks5Auth(loop, slot, queue_upstream, close_slot);
                },
                .no_acceptable => {
                    log.debug("[{d}] socks5 proxy rejected all auth methods", .{slot.conn_id});
                    close_slot(loop, slot, "socks5 no acceptable auth");
                },
            }
        },
        .proxy_socks5_auth_resp => {
            if (have.len < socks5.auth_response_len) return; // need more

            const ok = socks5.parseAuthResponse(have) orelse {
                close_slot(loop, slot, "socks5 invalid auth response");
                return;
            };

            if (!ok) {
                log.debug("[{d}] socks5 authentication failed", .{slot.conn_id});
                close_slot(loop, slot, "socks5 auth rejected");
                return;
            }

            sendSocks5Connect(loop, slot, queue_upstream, close_slot);
        },
        .proxy_socks5_connect_resp => {
            const result = socks5.parseConnectResponse(have) orelse return; // need more

            if (result.reply != .succeeded) {
                log.debug("[{d}] socks5 CONNECT failed: reply={d}", .{
                    slot.conn_id, @intFromEnum(result.reply),
                });
                close_slot(loop, slot, "socks5 connect rejected");
                return;
            }

            // Telegram DCs (and MiddleProxies) never speak first after a
            // SOCKS5 CONNECT success — they wait for our 64-byte handshake
            // nonce. Any bytes piggy-backed onto the SOCKS5 reply are either
            // garbage from a misbehaving upstream or an active MITM probe.
            //
            // Critically, `slot.pipelined_data` is the *client-side* pipeline
            // buffer: on startRelay it is fed through `client_decryptor.apply`.
            // Mixing upstream bytes into it desynchronises the client CTR
            // stream (and, with MiddleProxy, encapsulates garbage into a
            // valid RPC_PROXY_REQ frame). Drop the connection instead.
            if (have.len > result.consumed) {
                log.warn("[{d}] socks5 upstream sent {d} unsolicited bytes after CONNECT success", .{
                    slot.conn_id, have.len - result.consumed,
                });
                close_slot(loop, slot, "socks5 unsolicited upstream data");
                return;
            }

            // SOCKS5 handshake complete — proceed to DC path
            handshake_complete(loop, slot);
        },
        else => {},
    }
}

pub fn startHttpConnect(
    loop: anytype,
    slot: anytype,
    comptime queue_upstream: fn (@TypeOf(loop), @TypeOf(slot), []const u8) anyerror!bool,
    comptime close_slot: fn (@TypeOf(loop), @TypeOf(slot), []const u8) void,
) void {
    const target = slot.proxy_target_addr orelse {
        close_slot(loop, slot, "http proxy no target addr");
        return;
    };

    const username = loop.state.upstream.proxyUsername();
    const password = loop.state.upstream.proxyPassword();

    const msg = http_connect.buildConnectRequest(
        &slot.proxy_handshake_buf,
        target,
        username,
        password,
    );
    if (msg.len == 0) {
        close_slot(loop, slot, "http connect request build failed");
        return;
    }

    if (queue_upstream(loop, slot, msg)) |_| {} else |err| {
        log.debug("[{d}] http connect queue error: {any}", .{ slot.conn_id, err });
        close_slot(loop, slot, "http connect queue failed");
        return;
    }

    slot.phase = if (hasUpstreamPending(slot))
        .proxy_http_connect
    else
        .proxy_http_connect_resp;
    slot.proxy_handshake_pos = 0;
}

pub fn onHttpConnectReadable(
    loop: anytype,
    slot: anytype,
    comptime close_slot: fn (@TypeOf(loop), @TypeOf(slot), []const u8) void,
    comptime handshake_complete: fn (@TypeOf(loop), @TypeOf(slot)) void,
) void {
    const pos: usize = slot.proxy_handshake_pos;
    const space = slot.proxy_handshake_buf[pos..];
    if (space.len == 0) {
        close_slot(loop, slot, "http connect response buffer overflow");
        return;
    }

    const n = posix.read(slot.upstream_fd, space) catch |err| {
        log.debug("[{d}] http connect read error: {any}", .{ slot.conn_id, err });
        if (err == error.WouldBlock) return;
        close_slot(loop, slot, "http connect read failed");
        return;
    };

    if (n == 0) {
        close_slot(loop, slot, "http proxy closed connection");
        return;
    }

    slot.proxy_handshake_pos += @intCast(n);
    const have = slot.proxy_handshake_buf[0..slot.proxy_handshake_pos];

    const result = http_connect.parseResponse(have) orelse return; // need more

    if (result.status < 200 or result.status >= 300) {
        log.debug("[{d}] HTTP CONNECT failed: status={d}", .{ slot.conn_id, result.status });
        close_slot(loop, slot, "http connect rejected");
        return;
    }

    // Same invariant as SOCKS5: the DC never speaks first. Any bytes the
    // HTTP proxy appended after the "200 OK" line would be wrongly routed
    // through the *client* decryption path in startRelay, corrupting the
    // CTR stream. Reject the upstream.
    if (have.len > result.header_end) {
        log.warn("[{d}] http connect upstream sent {d} unsolicited bytes after 2xx", .{
            slot.conn_id, have.len - result.header_end,
        });
        close_slot(loop, slot, "http connect unsolicited upstream data");
        return;
    }

    // HTTP CONNECT handshake complete — proceed to DC path
    handshake_complete(loop, slot);
}
