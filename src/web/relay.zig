//! The WEB proxy relay: an HTTPS site that carries MTProto for Telegram Desktop 7.1+.
//!
//! ## What it is
//!
//! Desktop's WEB proxy type opens **no MTProto socket of its own**. A hidden native
//! WebView navigates to `https://<domain>/?bridge=<capability>`, and the page we serve
//! shuttles multiplexed frames over a same-origin WebSocket. On the wire the censor sees
//! a genuine browser TLS handshake to an ordinary website — real fingerprint, real HTTP,
//! real CA-chained certificate — because it *is* one.
//!
//! This process terminates that carrier and, for each logical stream the client opens,
//! dials the stock MTProxy next door (us) and pipes the bytes through untouched. It never
//! looks inside them: the client's MTProxy obfuscation and the proxy's user
//! authentication are end-to-end, exactly as with a direct connection.
//!
//!     browser TLS ─▶ [terminator: nginx / CDN] ─▶ relay ─▶ mtproto-proxy ─▶ Telegram
//!
//! ## Why its own process, and its own event loop
//!
//! Own *process* (`mtproto-proxy web-relay`, unit `mtproto-web-relay.service`): a fault
//! here must not take the data plane down with it, and the proxy is built ReleaseSafe, so
//! a bug is a process abort. Same *binary*, though — `mtbuddy update` swaps exactly one
//! proxy artifact, so a new binary would reach nobody until the already-installed mtbuddy
//! learned to fetch it.
//!
//! Own *event loop*: `std.http.Server` exists in Zig 0.16 and even has `respondWebSocket`,
//! but it is a blocking `Io.Reader`/`Io.Writer` API (thread-per-connection) and its
//! `readSmallMessage` rejects every fragmented frame. A session here has to multiplex one
//! WebSocket against N backend sockets, so it needs readiness notification anyway. This
//! loop is the same shape as the data plane's: level-triggered epoll, `data.fd` tagging,
//! and close deferred to the top of the next iteration so the kernel cannot recycle an fd
//! number inside one event batch.
//!
//! ## Flow control
//!
//! Every stream starts with an implicit 4 MiB window in each direction (never negotiated;
//! both halves simply assume it). We spend `send_window` to push DATA at the client and
//! only replenish `recv_window` once the client's bytes have actually left for the
//! backend — so a stalled backend stops the client rather than growing our memory.
//!
//! Protocol reference: tdesktop `docs/web-proxy-plan.md` §6–§8.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;

const config = @import("../config.zig");
const crypto = @import("../crypto/crypto.zig");
const socket_utils = @import("../proxy/socket_utils.zig");
const net_helpers = @import("../proxy/net_helpers.zig");
const dns_cache = @import("../proxy/dns_cache.zig");
const message_queue = @import("../proxy/message_queue.zig");
const queue_io = @import("../proxy/queue_io.zig");

const proxy_protocol = @import("../proxy/proxy_protocol.zig");
const trusted_peers = @import("../proxy/trusted_peers.zig");

const capability = @import("capability.zig");
const frame = @import("frame.zig");
const http = @import("http.zig");
const page = @import("page.zig");
const ws = @import("ws.zig");

const log = std.log.scoped(.web);

const Address = net_helpers.Address;
const MessageQueue = message_queue.MessageQueue;
const closeFd = socket_utils.closeFd;
const nowMs = socket_utils.nowMs;

// ── tunables ──────────────────────────────────────────────────────────────────

/// Accepts per readiness notification, so one busy moment cannot starve the loop.
const accept_batch_limit: usize = 64;
/// How long the listener stays disarmed after running out of file descriptors.
const accept_backoff_ms: i64 = 500;
const event_loop_wait_ms: i32 = 50;
const read_buf_size: usize = 64 * 1024;

/// A client has this long to finish a request head, and this long to send another
/// request on a kept-alive connection.
const http_head_timeout_ms: i64 = 15_000;
const http_idle_timeout_ms: i64 = 30_000;

const backend_connect_timeout_ms: i64 = 10_000;

/// Sessions are kept alive by PING/PONG, not by traffic: an idle MTProto connection is
/// legitimately silent for minutes.
const ping_interval_ms: i64 = 20_000;
const session_silence_timeout_ms: i64 = 90_000;

/// Coalesce WINDOW grants the way tdesktop does — flush at 256 KiB or on the next tick.
const window_flush_bytes: u32 = 256 * 1024;

/// Largest DATA payload we emit. tdesktop caps its own at the same 64 KiB.
const data_frame_size: usize = 64 * 1024;

/// Stop draining backends into a carrier this far behind.
const carrier_high_water: usize = 4 * 1024 * 1024;

/// Hard ceiling on one carrier's outbound queue. Past this the client is simply not
/// reading, and the queue is memory we can never hand over.
const carrier_queue_limit: usize = 8 * 1024 * 1024;

/// Hard ceiling on one stream's queue towards the backend. The client's own credit
/// already bounds this at the 4 MiB window; the backend is loopback, so anything near
/// this means the proxy is wedged and the stream is better off dead.
const backend_queue_limit: usize = frame.initial_stream_window + 256;

/// Cap on an HTTP connection's response queue. Every response we emit is a few KiB.
const http_queue_limit: usize = 256 * 1024;

/// Recently-closed stream ids we tolerate late frames for, mirroring tdesktop's own
/// retention: an ordinary cross-direction close race must not fail unrelated streams.
const closed_history: usize = 64;

pub const Error = error{
    WebProxyDisabled,
    MissingDomain,
    InvalidDomain,
    InvalidBackend,
    NoUsersConfigured,
};

// ── options ───────────────────────────────────────────────────────────────────

/// Everything the relay needs, resolved once from `[web]` + `[access.users]`.
pub const Options = struct {
    /// Canonical A-label hostname, exactly as it appears in `tg://webproxy` links and in
    /// the capability HMAC.
    domain: []const u8,
    listen_host: []const u8,
    listen_port: u16,
    ws_path: []const u8,
    backend: Address,
    max_sessions: u32,
    max_streams: u32,
    /// Aggregate ceiling on everything queued across all connections. The per-connection
    /// caps bound each peer; this bounds the process.
    max_buffer_bytes: usize,
    trust_forwarded_for: bool,
    client_ip_header: []const u8,
    check_origin: bool,

    pub fn fromConfig(cfg: *const config.Config, domain_buf: []u8) Error!Options {
        if (!cfg.web.enabled) return error.WebProxyDisabled;
        if (cfg.users.count() == 0) return error.NoUsersConfigured;
        const raw_domain = cfg.web.domain orelse return error.MissingDomain;
        const domain = capability.normalizeHost(raw_domain, domain_buf) catch return error.InvalidDomain;
        return .{
            .domain = domain,
            .listen_host = cfg.web.effectiveHost(),
            .listen_port = cfg.web.port,
            .ws_path = cfg.web.effectiveWsPath(),
            .backend = undefined, // resolved by the caller, which may do DNS
            .max_sessions = cfg.web.max_sessions,
            .max_streams = cfg.web.max_streams,
            .max_buffer_bytes = @as(usize, cfg.web.max_buffer_mb) * 1024 * 1024,
            .trust_forwarded_for = cfg.web.trust_forwarded_for,
            .client_ip_header = cfg.web.effectiveClientIpHeader(),
            .check_origin = cfg.web.check_origin,
        };
    }
};

/// A specific listener must be reached on its bound address; another service
/// may own loopback on that port. Wildcard listeners still use loopback.
fn defaultBackendHost(cfg: *const config.Config) ![]const u8 {
    const host = cfg.bind_address orelse return "127.0.0.1";
    const addr = try Address.parse(host, cfg.port);
    switch (addr) {
        .ip4 => |v4| if (std.mem.allEqual(u8, &v4.bytes, 0)) return "127.0.0.1",
        .ip6 => |v6| if (std.mem.allEqual(u8, &v6.bytes, 0)) return "::1",
    }
    return host;
}

/// Parse `[web].backend` (`host:port`), defaulting to this proxy's listener.
pub fn resolveBackend(allocator: std.mem.Allocator, cfg: *const config.Config) !Address {
    const spec = cfg.web.backend orelse {
        return Address.parse(try defaultBackendHost(cfg), cfg.port);
    };
    const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return error.InvalidBackend;
    const host = std.mem.trim(u8, spec[0..colon], "[] ");
    const port = std.fmt.parseInt(u16, spec[colon + 1 ..], 10) catch return error.InvalidBackend;
    if (host.len == 0) return error.InvalidBackend;
    const list = net_helpers.getAddressList(allocator, host, port) catch return error.InvalidBackend;
    defer list.deinit();
    if (list.addrs.len == 0) return error.InvalidBackend;
    return list.addrs[0];
}

// ── capabilities ──────────────────────────────────────────────────────────────

const UserCapability = struct {
    value: capability.Capability,
    user: []const u8,
};

/// Precompute the bridge capability for every configured user, in both secret encodings
/// tdesktop accepts for a WEB proxy (`dd…` random-padding, which our links use, and a
/// bare 16-byte secret). `ee` FakeTLS secrets are excluded by construction — the client
/// reports them as `Status::Unsupported`.
fn buildCapabilities(
    allocator: std.mem.Allocator,
    cfg: *const config.Config,
    domain: []const u8,
) ![]UserCapability {
    var list: std.ArrayList(UserCapability) = .empty;
    errdefer list.deinit(allocator);
    var it = @constCast(&cfg.users).iterator();
    while (it.next()) |entry| {
        const secret = entry.value_ptr.*;
        try list.append(allocator, .{
            .value = capability.deriveForPaddedSecret(domain, secret),
            .user = entry.key_ptr.*,
        });
        try list.append(allocator, .{
            .value = capability.derive(domain, &secret),
            .user = entry.key_ptr.*,
        });
    }
    return list.toOwnedSlice(allocator);
}

// ── connection model ──────────────────────────────────────────────────────────

const ConnKind = enum { http, websocket, backend };

const Conn = struct {
    accounted_bytes: usize = 0,
    batch: std.ArrayList(u8) = .empty,
    batch_pending: bool = false,
    batch_frames: usize = 0,
    fd: posix.fd_t,
    kind: ConnKind,
    peer: Address,
    out: MessageQueue,
    /// Request head (http) or WebSocket byte stream (websocket).
    in: std.ArrayList(u8) = .empty,
    /// Reassembly buffer for a fragmented WebSocket message.
    msg: std.ArrayList(u8) = .empty,
    msg_active: bool = false,
    want_in: bool = false,
    want_out: bool = false,
    /// Deadline in monotonic ms; 0 disables.
    deadline_ms: i64 = 0,
    /// Close as soon as the out queue drains (a final HTTP response or a CLOSE frame).
    close_after_flush: bool = false,
    session: ?*Session = null,
    stream: ?*Stream = null,
    connecting: bool = false,
    backend_candidates: net_helpers.AddressCandidates = .{},
    backend_next: usize = 0,
    /// Diagnostics for the one failure mode that matters here — bytes arriving from the
    /// proxy but never reaching the client. Comparing `rx_bytes` against the proxy's own
    /// `s2c=` for the same connection localises a stall to one side of the socket in a
    /// single log line, and the stall counters say which backpressure rule parked it.
    rx_bytes: u64 = 0,
    rx_passes: u32 = 0,
    stall_window: u32 = 0,
    stall_carrier: u32 = 0,
    /// Client credit seen on the last read pass. Sampled here because closeStream
    /// detaches the stream before closeConn logs, so reading it at close is always 0.
    last_window: u32 = 0,
};

const Stream = struct {
    id: u32,
    session: *Session,
    /// Backend socket, or null once it is gone.
    conn: ?*Conn = null,
    /// Credit we may spend sending DATA to the client.
    send_window: u32 = frame.initial_stream_window,
    /// Credit the client may spend sending DATA to us.
    recv_window: u32 = frame.initial_stream_window,
    /// Granted-but-unsent credit, coalesced into one WINDOW frame.
    pending_grant: u32 = 0,
    /// Bytes queued to the backend that are ours, not the client's (the PROXY header).
    /// Draining those must not hand the client credit it never spent.
    grant_debt: usize = 0,
};

const Session = struct {
    conn: *Conn,
    user: []const u8,
    /// The real browser address, announced to the proxy with a PROXY-protocol header so
    /// per-IP accounting, flood guard and Telegram all see the actual client.
    client_addr: ?Address,
    welcomed: bool = false,
    tearing_down: bool = false,
    streams: std.AutoHashMapUnmanaged(u32, *Stream) = .empty,
    closed_ids: []u32 = &.{},
    closed_pos: usize = 0,
    last_rx_ms: i64 = 0,
    last_ping_ms: i64 = 0,
    ping_payload: [8]u8 = [_]u8{0} ** 8,
    needs_window_flush: bool = false,
    /// DATA frames and payload bytes pushed at the client. Their ratio is the average
    /// frame size, which is what decides how much work the client's JS thread does per
    /// megabyte — it base64-encodes and crosses the native bridge once per frame.
    data_frames: u64 = 0,
    data_bytes: u64 = 0,
    /// Most streams this carrier ever held at once, and how many OPENs were refused for
    /// being over `max_streams`. Reported when the session closes: without it, hitting
    /// the cap looks to the client like an ordinary connection failure and to the
    /// operator like nothing at all.
    streams_high_water: u32 = 0,
    streams_refused: u32 = 0,

    fn rememberClosed(self: *Session, id: u32) void {
        if (self.closed_ids.len == 0) return;
        self.closed_ids[self.closed_pos] = id;
        self.closed_pos = (self.closed_pos + 1) % self.closed_ids.len;
    }

    fn recentlyClosed(self: *const Session, id: u32) bool {
        for (self.closed_ids) |seen| {
            if (seen == id and id != 0) return true;
        }
        return false;
    }
};

test "closed stream retention scales beyond the former 64-id cap" {
    var ids: [256]u32 = [_]u32{0} ** 256;
    var session = Session{ .conn = undefined, .user = "test", .client_addr = null, .closed_ids = &ids };
    for (1..257) |id| session.rememberClosed(@intCast(id));
    try std.testing.expect(session.recentlyClosed(1));
    try std.testing.expect(session.recentlyClosed(256));
    try std.testing.expect(!session.recentlyClosed(0));
}

test "backend queue accommodates a complete granted receive window" {
    try std.testing.expect(backend_queue_limit >= frame.initial_stream_window + 52);
    try std.testing.expect(ws.max_message >= frame.max_payload + frame.header_size);
}

// ── the relay ─────────────────────────────────────────────────────────────────

pub const Relay = struct {
    allocator: std.mem.Allocator,
    opts: Options,
    backend_dns: ?*dns_cache.Cache = null,
    backend_dns_id: usize = 0,
    /// Only the implicit backend is guaranteed to be this host's proxy.
    local_backend: bool = false,
    caps: []UserCapability,
    /// Pre-rendered responses; the bridge page carries no per-user bytes.
    /// The cover page is generated per deployment (see `page.renderCover`), so it is
    /// owned here rather than being a constant.
    cover_page: []u8,
    bridge_page: []u8,
    bridge_headers: []u8,
    cover_headers: []u8,
    notfound_headers: []u8,

    epoll_fd: posix.fd_t,
    listen_fd: posix.fd_t,
    signal_fd: posix.fd_t,
    old_sigmask: posix.sigset_t,

    conns: std.AutoHashMapUnmanaged(posix.fd_t, *Conn) = .empty,
    pending_close: std.ArrayList(posix.fd_t) = .empty,
    /// Closed connections whose memory is released at the top of the next loop
    /// iteration, together with their fd. See `closeConn`.
    pending_free: std.ArrayList(*Conn) = .empty,
    batch_fds: std.ArrayList(posix.fd_t) = .empty,
    /// Reused snapshot of connection fds, so timers can close connections without
    /// mutating the map they are walking.
    tick_scratch: std.ArrayList(posix.fd_t) = .empty,
    /// While set, the listener's read interest is disarmed after fd exhaustion.
    accept_resume_ms: i64 = 0,
    session_count: u32 = 0,
    http_count: u32 = 0,

    bytes_out: std.atomic.Value(u64) = .init(0),
    buffered_bytes: usize = 0,
    streams_refused: u64 = 0,
    accepts_refused: u64 = 0,
    /// Soft backpressure before the hard budget enforced at every buffer mutation.
    throttled: bool = false,
    stop: bool = false,
    read_buf: [read_buf_size]u8 = undefined,

    pub fn init(allocator: std.mem.Allocator, opts: Options, cfg: *const config.Config) !Relay {
        const caps = try buildCapabilities(allocator, cfg, opts.domain);
        errdefer allocator.free(caps);

        const cover_page = try page.renderCover(allocator, opts.domain);
        errdefer allocator.free(cover_page);

        // The bridge page IS the cover page plus the script: a capability holder must be
        // served the same visible site a prober gets, or the cover proves nothing.
        const bridge_page = try page.renderBridge(allocator, cover_page, opts.ws_path);
        errdefer allocator.free(bridge_page);

        // The bridge response must be framable by tdesktop's loopback fallback page,
        // which serves itself from a random numeric loopback origin, and must carry no
        // X-Frame-Options. `connect-src 'self'` covers the same-origin WebSocket: CSP
        // treats an `https` source as matching `wss` on the same host.
        const bridge_headers = try std.fmt.allocPrint(allocator, "Content-Type: text/html; charset=utf-8\r\n" ++
            "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; " ++
            "style-src 'unsafe-inline'; connect-src 'self' wss://{s}; base-uri 'none'; " ++
            "form-action 'none'; frame-ancestors http://127.0.0.1:*\r\n" ++
            "Referrer-Policy: no-referrer\r\n" ++
            "X-Content-Type-Options: nosniff\r\n" ++
            "Cache-Control: no-store\r\n", .{opts.domain});
        errdefer allocator.free(bridge_headers);

        const cover_headers = try allocator.dupe(u8, "Content-Type: text/html; charset=utf-8\r\n" ++
            "X-Content-Type-Options: nosniff\r\n" ++
            "Cache-Control: public, max-age=300\r\n");
        errdefer allocator.free(cover_headers);

        const notfound_headers = try allocator.dupe(u8, "Content-Type: text/html; charset=utf-8\r\n" ++
            "X-Content-Type-Options: nosniff\r\n" ++
            "Cache-Control: no-store\r\n");
        errdefer allocator.free(notfound_headers);

        const epoll_fd = try socket_utils.epollCreate();
        errdefer closeFd(epoll_fd);

        const listen_fd = try listen(opts.listen_host, opts.listen_port);
        errdefer closeFd(listen_fd);

        var mask = posix.sigemptyset();
        posix.sigaddset(&mask, .TERM);
        posix.sigaddset(&mask, .INT);
        posix.sigaddset(&mask, .HUP);
        var old_sigmask: posix.sigset_t = undefined;
        posix.sigprocmask(posix.SIG.BLOCK, &mask, &old_sigmask);
        errdefer posix.sigprocmask(posix.SIG.SETMASK, &old_sigmask, null);
        const signal_fd = try posix.signalfd(-1, &mask, linux.SFD.CLOEXEC | linux.SFD.NONBLOCK);
        errdefer closeFd(signal_fd);
        const cache = try dns_cache.Cache.create(allocator);
        errdefer cache.destroy();
        const spec = cfg.web.backend;
        const colon = if (spec) |s| std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.InvalidBackend else 0;
        const host = if (spec) |s| std.mem.trim(u8, s[0..colon], "[] ") else try defaultBackendHost(cfg);
        const port = if (spec) |s| try std.fmt.parseInt(u16, s[colon + 1 ..], 10) else cfg.port;
        const addresses = try net_helpers.getAddressList(allocator, host, port);
        defer addresses.deinit();
        const dns_id = try cache.add(host, port, net_helpers.AddressCandidates.init(addresses.addrs));
        try cache.start();

        return .{
            .allocator = allocator,
            .opts = opts,
            .backend_dns = cache,
            .backend_dns_id = dns_id,
            .local_backend = spec == null,
            .caps = caps,
            .cover_page = cover_page,
            .bridge_page = bridge_page,
            .bridge_headers = bridge_headers,
            .cover_headers = cover_headers,
            .notfound_headers = notfound_headers,
            .epoll_fd = epoll_fd,
            .listen_fd = listen_fd,
            .signal_fd = signal_fd,
            .old_sigmask = old_sigmask,
        };
    }

    pub fn deinit(self: *Relay) void {
        if (self.backend_dns) |cache| cache.destroy();
        var it = self.conns.valueIterator();
        while (it.next()) |conn_ptr| {
            const conn = conn_ptr.*;
            // Sessions and their streams hang off the websocket connection, so they have
            // to be released here too — closeConn is not what runs on this path.
            if (conn.kind == .websocket) {
                if (conn.session) |session| {
                    var streams = session.streams.valueIterator();
                    while (streams.next()) |stream_ptr| self.allocator.destroy(stream_ptr.*);
                    session.streams.deinit(self.allocator);
                    self.allocator.free(session.closed_ids);
                    self.allocator.destroy(session);
                }
            }
            closeFd(conn.fd);
            self.destroyConn(conn);
        }
        self.conns.deinit(self.allocator);
        for (self.pending_close.items) |fd| closeFd(fd);
        self.pending_close.deinit(self.allocator);
        for (self.pending_free.items) |conn| self.destroyConn(conn);
        self.pending_free.deinit(self.allocator);
        self.batch_fds.deinit(self.allocator);
        self.tick_scratch.deinit(self.allocator);
        closeFd(self.signal_fd);
        posix.sigprocmask(posix.SIG.SETMASK, &self.old_sigmask, null);
        closeFd(self.listen_fd);
        closeFd(self.epoll_fd);
        self.allocator.free(self.caps);
        self.allocator.free(self.cover_page);
        self.allocator.free(self.bridge_page);
        self.allocator.free(self.bridge_headers);
        self.allocator.free(self.cover_headers);
        self.allocator.free(self.notfound_headers);
    }

    pub fn run(self: *Relay) !void {
        try self.addFd(self.listen_fd, true, false);
        try self.addFd(self.signal_fd, true, false);
        var backend_buf: [64]u8 = undefined;
        log.info("web relay listening on {s}:{d} for https://{s} (ws {s}, backend {s})", .{
            self.opts.listen_host,
            self.opts.listen_port,
            self.opts.domain,
            self.opts.ws_path,
            socket_utils.formatAddress(self.opts.backend, &backend_buf),
        });

        var events: [128]linux.epoll_event = undefined;
        var last_tick_ms = nowMs();
        while (!self.stop) {
            self.drainPendingCloses();

            const rc = linux.epoll_wait(self.epoll_fd, events[0..].ptr, @intCast(events.len), event_loop_wait_ms);
            switch (posix.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                else => |err| return posix.unexpectedErrno(err),
            }
            const n: usize = @intCast(rc);
            for (events[0..n]) |ev| {
                const fd = ev.data.fd;
                if (fd == self.signal_fd) {
                    var info: linux.signalfd_siginfo = undefined;
                    const size = posix.read(fd, std.mem.asBytes(&info)) catch continue;
                    if (size == @sizeOf(linux.signalfd_siginfo)) {
                        if (info.signo == @intFromEnum(posix.SIG.HUP)) {
                            log.info("SIGHUP received; relay configuration changes require a restart", .{});
                        } else self.stop = true;
                    }
                    continue;
                }
                if (fd == self.listen_fd) {
                    self.acceptNew();
                    continue;
                }
                const conn = self.conns.get(fd) orelse continue;
                self.dispatch(conn, ev.events);
            }
            self.flushBatches();

            const now = nowMs();
            if (now - last_tick_ms >= event_loop_wait_ms) {
                last_tick_ms = now;
                self.tick(now);
            }
        }
        log.info("web relay shutting down", .{});
    }

    // ── epoll plumbing ────────────────────────────────────────────────────────

    /// RDHUP is subscribed to only while we actually want to read. A connection parked
    /// by flow control still has ERR/HUP armed, but a half-closed peer would otherwise
    /// re-notify on every wait with nothing to consume — a 100% CPU spin.
    fn addFd(self: *Relay, fd: posix.fd_t, want_in: bool, want_out: bool) !void {
        var flags: u32 = linux.EPOLL.ERR | linux.EPOLL.HUP;
        if (want_in) flags |= linux.EPOLL.IN | linux.EPOLL.RDHUP;
        if (want_out) flags |= linux.EPOLL.OUT;
        var ev = linux.epoll_event{ .events = flags, .data = .{ .fd = fd } };
        const rc = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_ADD, fd, &ev);
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    fn modFd(self: *Relay, fd: posix.fd_t, want_in: bool, want_out: bool) void {
        var flags: u32 = linux.EPOLL.ERR | linux.EPOLL.HUP;
        if (want_in) flags |= linux.EPOLL.IN | linux.EPOLL.RDHUP;
        if (want_out) flags |= linux.EPOLL.OUT;
        var ev = linux.epoll_event{ .events = flags, .data = .{ .fd = fd } };
        _ = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_MOD, fd, &ev);
    }

    fn delFd(self: *Relay, fd: posix.fd_t) void {
        var ev = linux.epoll_event{ .events = 0, .data = .{ .fd = fd } };
        _ = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, fd, &ev);
    }

    /// Close is deferred to the top of the next loop iteration: the kernel recycles fd
    /// numbers eagerly, and a number reused inside one event batch would misattribute a
    /// stale hangup to a fresh connection.
    fn deferClose(self: *Relay, fd: posix.fd_t) void {
        self.pending_close.appendAssumeCapacity(fd);
    }

    fn drainPendingCloses(self: *Relay) void {
        for (self.pending_close.items) |fd| closeFd(fd);
        self.pending_close.clearRetainingCapacity();
        for (self.pending_free.items) |conn| self.destroyConn(conn);
        self.pending_free.clearRetainingCapacity();
    }

    /// A connection is alive exactly while its fd is still mapped. Callers hold the fd,
    /// not the pointer, precisely so this stays true after a re-entrant close.
    fn alive(self: *const Relay, fd: posix.fd_t) bool {
        return self.conns.contains(fd);
    }

    // ── accept ────────────────────────────────────────────────────────────────

    fn acceptNew(self: *Relay) void {
        var accepted: usize = 0;
        while (accepted < accept_batch_limit) : (accepted += 1) {
            const result = socket_utils.acceptClient(self.listen_fd) catch |err| switch (err) {
                error.ConnectionAborted, error.ConnectionResetByPeer => continue,
                error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded, error.SystemResources => {
                    // Level-triggered epoll would re-notify immediately and spin the loop
                    // at 100% CPU, so disarm the listener and come back on a timer — the
                    // same pause the data plane applies for the same reason.
                    log.warn("accept failed ({any}); pausing accepts for {d}ms", .{ err, accept_backoff_ms });
                    self.modFd(self.listen_fd, false, false);
                    self.accept_resume_ms = nowMs() + accept_backoff_ms;
                    return;
                },
                else => {
                    log.warn("accept failed: {any}", .{err});
                    return;
                },
            } orelse return;

            // One HTTP connection per session plus slack for cover-site traffic.
            const http_cap = @min(@as(u64, self.opts.max_sessions) * 4 + 32, 4096);
            if (self.http_count >= http_cap) {
                var oldest: ?*Conn = null;
                var peers = self.conns.valueIterator();
                while (peers.next()) |candidate| {
                    const idle = candidate.*;
                    if (idle.kind != .http or idle.in.items.len != 0 or !idle.out.isEmpty()) continue;
                    if (oldest == null or idle.deadline_ms < oldest.?.deadline_ms) oldest = idle;
                }
                if (oldest) |idle| self.closeConn(idle, "idle HTTP connection evicted for capacity");
            }
            if (self.http_count >= http_cap) {
                self.accepts_refused +|= 1;
                closeFd(result.fd);
                continue;
            }
            socket_utils.setTcpNoDelay(result.fd);
            const conn = self.createConn(result.fd, .http, result.addr) catch {
                closeFd(result.fd);
                continue;
            };
            conn.deadline_ms = nowMs() + http_head_timeout_ms;
            self.http_count += 1;
            self.sync(conn, true, false);
        }
    }

    fn createConn(self: *Relay, fd: posix.fd_t, kind: ConnKind, peer: Address) !*Conn {
        // Reserve teardown storage before publishing an fd into an event batch.
        const capacity = self.conns.count() + self.pending_close.items.len + 1;
        try self.pending_close.ensureTotalCapacity(self.allocator, capacity);
        try self.pending_free.ensureTotalCapacity(self.allocator, capacity);
        const conn = try self.allocator.create(Conn);
        errdefer self.allocator.destroy(conn);
        conn.* = .{
            .fd = fd,
            .kind = kind,
            .peer = peer,
            .out = .{ .allocator = self.allocator },
        };
        try self.conns.put(self.allocator, fd, conn);
        errdefer _ = self.conns.remove(fd);
        try self.addFd(fd, false, false);
        return conn;
    }

    fn destroyConn(self: *Relay, conn: *Conn) void {
        self.buffered_bytes -= conn.accounted_bytes;
        conn.out.deinit();
        conn.in.deinit(self.allocator);
        conn.msg.deinit(self.allocator);
        conn.batch.deinit(self.allocator);
        self.allocator.destroy(conn);
    }

    fn accountConn(self: *Relay, conn: *Conn) void {
        const current = conn.out.total_len + conn.in.items.len + conn.msg.items.len + conn.batch.items.len;
        self.buffered_bytes = self.buffered_bytes - conn.accounted_bytes + current;
        conn.accounted_bytes = current;
    }

    fn canBuffer(self: *const Relay, extra: usize) bool {
        return extra <= self.opts.max_buffer_bytes -| self.buffered_bytes;
    }

    fn writePair(self: *Relay, conn: *Conn, first: []const u8, second: []const u8) !bool {
        if (!self.canBuffer(first.len + second.len)) return error.BufferBudgetExceeded;
        defer self.accountConn(conn);
        // Until SO_ERROR confirms the connection, keep every byte available for retry.
        if (conn.connecting) {
            try conn.out.appendCopy(first);
            try conn.out.appendCopy(second);
            return false;
        }
        return queue_io.queueOrWriteMsgPair(conn.fd, &conn.out, first, second, &self.bytes_out, null);
    }

    fn appendInput(self: *Relay, conn: *Conn, data: []const u8, fragmented: bool) !void {
        if (!self.canBuffer(data.len)) return error.BufferBudgetExceeded;
        defer self.accountConn(conn);
        const buffer = if (fragmented) &conn.msg else &conn.in;
        try buffer.appendSlice(self.allocator, data);
    }

    fn flushBatch(self: *Relay, conn: *Conn) !void {
        if (conn.batch.items.len == 0) return;
        var header: [ws.max_server_header]u8 = undefined;
        const framing = try ws.writeHeader(&header, true, .binary, conn.batch.items.len);
        if (!self.canBuffer(framing.len)) return error.BufferBudgetExceeded;
        // Transfer already-accounted batch bytes to the socket queue.
        defer self.accountConn(conn);
        errdefer {
            conn.batch.clearRetainingCapacity();
            conn.batch_frames = 0;
        }
        _ = try queue_io.queueOrWriteMsgPair(conn.fd, &conn.out, framing, conn.batch.items, &self.bytes_out, null);
        conn.batch.clearRetainingCapacity();
        conn.batch_frames = 0;
        self.syncConn(conn);
    }

    fn flushBatches(self: *Relay) void {
        for (self.batch_fds.items) |fd| {
            const conn = self.conns.get(fd) orelse continue;
            conn.batch_pending = false;
            self.flushBatch(conn) catch self.closeConn(conn, "carrier batch write failed");
        }
        self.batch_fds.clearRetainingCapacity();
    }

    fn closeConn(self: *Relay, conn: *Conn, reason: []const u8) void {
        const fd = conn.fd;
        if (self.conns.fetchRemove(fd) == null) return;
        self.delFd(fd);
        self.deferClose(fd);

        switch (conn.kind) {
            .http => self.http_count -|= 1,
            .websocket => {
                self.http_count -|= 1;
                if (conn.session) |session| {
                    conn.session = null;
                    self.destroySession(session);
                }
            },
            .backend => {
                if (conn.stream) |stream| {
                    conn.stream = null;
                    stream.conn = null;
                    self.closeStream(stream, true);
                }
            },
        }
        if (conn.kind == .backend) {
            log.debug("closed backend conn: {s} rx={d} passes={d} stall_window={d} stall_carrier={d} window={d} want_in={}", .{
                reason,
                conn.rx_bytes,
                conn.rx_passes,
                conn.stall_window,
                conn.stall_carrier,
                conn.last_window,
                conn.want_in,
            });
        } else {
            log.debug("closed {s} conn: {s}", .{ @tagName(conn.kind), reason });
        }
        // The object outlives this call by one loop iteration. Closing is re-entrant
        // (a websocket close tears down its streams, which closes their backends, which
        // can try to notify the websocket), so every caller that still holds `conn` on
        // return would otherwise be reading freed memory. Freeing on the same schedule
        // as the fd keeps `alive(fd)` an honest liveness check for all of them.
        self.pending_free.appendAssumeCapacity(conn);
    }

    /// Recompute epoll interest, writing it out only when it changed.
    fn sync(self: *Relay, conn: *Conn, want_in: bool, want_out: bool) void {
        if (conn.want_in == want_in and conn.want_out == want_out) return;
        conn.want_in = want_in;
        conn.want_out = want_out;
        self.modFd(conn.fd, want_in, want_out);
    }

    fn syncConn(self: *Relay, conn: *Conn) void {
        switch (conn.kind) {
            .http => self.sync(conn, !conn.close_after_flush, !conn.out.isEmpty()),
            .websocket => self.sync(conn, !conn.close_after_flush, !conn.out.isEmpty()),
            .backend => {
                const stream = conn.stream;
                const readable = blk: {
                    if (conn.connecting) break :blk false;
                    if (self.throttled) break :blk false;
                    const s = stream orelse break :blk false;
                    if (s.session.conn.close_after_flush) break :blk false;
                    if (s.send_window == 0) break :blk false;
                    break :blk s.session.conn.out.total_len < carrier_high_water;
                };
                // Every "the WEB proxy is slow" report so far has had the same shape: the
                // proxy keeps writing while the relay stops reading its backends. Naming
                // the reason costs one debug line and saves a kernel-level hunt.
                if (!readable and !conn.connecting) {
                    log.debug("backend read parked: was_armed={} throttled={} stream={} window={d} carrier_out={d}", .{
                        conn.want_in,
                        self.throttled,
                        stream != null,
                        if (stream) |s| s.send_window else 0,
                        if (stream) |s| s.session.conn.out.total_len else 0,
                    });
                }
                self.sync(conn, readable, conn.connecting or !conn.out.isEmpty());
            },
        }
    }

    // ── event dispatch ────────────────────────────────────────────────────────

    fn dispatch(self: *Relay, conn: *Conn, events: u32) void {
        const fd = conn.fd;
        const fatal = (events & (linux.EPOLL.ERR | linux.EPOLL.HUP)) != 0;
        // A failed/prematurely closed connect must not enter the read/flush path:
        // doing so can discard the queued preamble before trying another address.
        if (conn.connecting and (fatal or (events & linux.EPOLL.RDHUP) != 0)) {
            if (!self.retryBackend(conn)) self.closeConn(conn, "backend connect failed");
            return;
        }
        if ((events & linux.EPOLL.OUT) != 0) {
            self.onWritable(conn);
            if (!self.alive(fd)) return;
        }
        if ((events & linux.EPOLL.IN) != 0 or (events & linux.EPOLL.RDHUP) != 0) {
            self.onReadable(conn);
            if (!self.alive(fd)) return;
        }
        if (fatal) {
            self.closeConn(conn, "socket error or hangup");
            return;
        }
        self.syncConn(conn);
    }

    fn onWritable(self: *Relay, conn: *Conn) void {
        defer self.accountConn(conn);
        if (conn.kind == .backend and conn.connecting) {
            socket_utils.checkSocketConnectError(conn.fd) catch |err| {
                log.debug("backend connect failed: {any}", .{err});
                if (!self.retryBackend(conn)) self.closeConn(conn, "backend connect failed");
                return;
            };
            conn.connecting = false;
            conn.deadline_ms = 0;
            socket_utils.configureRelaySocket(conn.fd);
        }
        const fd = conn.fd;
        const before = conn.out.total_len;
        const drained = queue_io.flushQueue(conn.fd, &conn.out, &self.bytes_out, null) catch {
            self.closeConn(conn, "write failed");
            return;
        };
        if (conn.kind == .backend) {
            self.creditDrain(conn, before);
            if (!self.alive(fd)) return;
        }
        if (drained and conn.close_after_flush) {
            self.closeConn(conn, "flushed and closing");
            return;
        }
        // A carrier that was above the high-water mark parked every backend feeding it.
        // Nothing else would ever wake them, because their own sockets are quiet.
        if (conn.kind == .websocket and before >= carrier_high_water and conn.out.total_len < carrier_high_water) {
            if (conn.session) |session| self.resumeBackends(session);
        }
        self.syncConn(conn);
    }

    /// Re-arm read interest on every backend of a session whose carrier just drained.
    fn resumeBackends(self: *Relay, session: *Session) void {
        var it = session.streams.valueIterator();
        while (it.next()) |stream_ptr| {
            if (stream_ptr.*.conn) |backend| self.syncConn(backend);
        }
    }

    fn onReadable(self: *Relay, conn: *Conn) void {
        switch (conn.kind) {
            .http => self.onHttpReadable(conn),
            .websocket => self.onWsReadable(conn),
            .backend => self.onBackendReadable(conn),
        }
    }

    // ── HTTP ──────────────────────────────────────────────────────────────────

    fn onHttpReadable(self: *Relay, conn: *Conn) void {
        const n = posix.read(conn.fd, &self.read_buf) catch |err| {
            if (err == error.WouldBlock) return;
            self.closeConn(conn, "http read error");
            return;
        };
        if (n == 0) {
            self.closeConn(conn, "client closed");
            return;
        }
        self.appendInput(conn, self.read_buf[0..n], false) catch {
            self.closeConn(conn, "out of memory");
            return;
        };
        const fd = conn.fd;
        while (http.headEnd(conn.in.items) != null) {
            const request = http.parse(conn.in.items) catch |err| {
                self.respondStatus(conn, if (err == error.HeadTooLarge) "431 Request Header Fields Too Large" else "400 Bad Request");
                return;
            };
            // `request` borrows slices out of conn.in, so the head can only be dropped
            // once serve() is done reading it — including the upgrade path, which must
            // keep any bytes that followed the head as the start of the WebSocket stream.
            const consumed = request.head_len;
            self.serve(conn, &request);
            if (!self.alive(fd)) return;
            dropFront(&conn.in, consumed);
            self.accountConn(conn);
            if (conn.kind != .http) {
                // Upgraded. Anything pipelined behind the request head is already the
                // WebSocket stream, and no further readiness event will announce it.
                if (conn.in.items.len > 0) self.processWsBuffer(conn);
                return;
            }
            if (conn.close_after_flush) return;
            conn.deadline_ms = nowMs() + http_idle_timeout_ms;
        }
        if (conn.in.items.len >= http.max_head_bytes) self.respondStatus(conn, "431 Request Header Fields Too Large");
    }

    fn serve(self: *Relay, conn: *Conn, request: *const http.Request) void {
        const keep = request.keepAlive();
        if (std.mem.eql(u8, request.path(), "/metrics") and metricsRequestAllowed(conn.peer, request)) {
            var metrics_buf: [2048]u8 = undefined;
            const body = self.renderMetrics(&metrics_buf) catch {
                self.respondStatus(conn, "500 Internal Server Error");
                return;
            };
            self.respondPage(conn, "200 OK", "Content-Type: text/plain; version=0.0.4\r\nCache-Control: no-store\r\n", body, keep, request.method == .head);
            return;
        }
        if (request.method == .other) {
            self.respondStatus(conn, "405 Method Not Allowed");
            return;
        }

        const presented = request.query("b") orelse request.query("bridge");
        const user = if (presented) |value| self.matchCapability(value) else null;

        if (http.isWebSocketUpgrade(request) and
            std.mem.eql(u8, request.path(), self.opts.ws_path))
        {
            if (user) |name| {
                self.upgrade(conn, request, name);
            } else {
                // No valid capability: behave exactly like any other unknown path.
                self.respondPage(conn, "404 Not Found", self.notfound_headers, self.cover_page, keep, request.method == .head);
            }
            return;
        }

        if (std.mem.eql(u8, request.path(), "/")) {
            if (user != null) {
                self.respondPage(conn, "200 OK", self.bridge_headers, self.bridge_page, keep, request.method == .head);
            } else {
                self.respondPage(conn, "200 OK", self.cover_headers, self.cover_page, keep, request.method == .head);
            }
            return;
        }
        self.respondPage(conn, "404 Not Found", self.notfound_headers, self.cover_page, keep, request.method == .head);
    }

    fn renderMetrics(self: *const Relay, buffer: []u8) ![]const u8 {
        var streams: usize = 0;
        var it = self.conns.valueIterator();
        while (it.next()) |conn| {
            if (conn.*.session) |session| streams += session.streams.count();
        }
        return std.fmt.bufPrint(buffer, "# TYPE mtproto_web_sessions gauge\nmtproto_web_sessions {d}\n" ++
            "# TYPE mtproto_web_streams gauge\nmtproto_web_streams {d}\n" ++
            "# TYPE mtproto_web_streams_refused_total counter\nmtproto_web_streams_refused_total {d}\n" ++
            "# TYPE mtproto_web_accept_refused_total counter\nmtproto_web_accept_refused_total {d}\n" ++
            "# TYPE mtproto_web_throttled gauge\nmtproto_web_throttled {d}\n" ++
            "# TYPE mtproto_web_buffered_bytes gauge\nmtproto_web_buffered_bytes {d}\n" ++
            "# TYPE mtproto_web_bytes_out_total counter\nmtproto_web_bytes_out_total {d}\n", .{ self.session_count, streams, self.streams_refused, self.accepts_refused, @intFromBool(self.throttled), self.buffered_bytes, self.bytes_out.load(.monotonic) });
    }

    /// Constant-time match of a presented capability against every configured user.
    /// Iterating the whole set regardless of an early hit keeps the timing flat.
    fn matchCapability(self: *Relay, presented: []const u8) ?[]const u8 {
        var found: ?[]const u8 = null;
        for (self.caps) |cap| {
            if (capability.matches(presented, cap.value)) found = cap.user;
        }
        return found;
    }

    fn respondPage(
        self: *Relay,
        conn: *Conn,
        status: []const u8,
        headers: []const u8,
        body: []const u8,
        keep_alive: bool,
        head_only: bool,
    ) void {
        var head_buf: [1024]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&head_buf);
        var date_buf: [40]u8 = undefined;
        const seconds = std.Io.Clock.real.now(std.Io.Threaded.global_single_threaded.io()).toSeconds();
        const date = httpDate(&date_buf, @intCast(@max(0, seconds))) catch "Thu, 01 Jan 1970 00:00:00 GMT";
        writer.print("HTTP/1.1 {s}\r\nDate: {s}\r\nServer: nginx\r\n{s}Content-Length: {d}\r\nConnection: {s}\r\n\r\n", .{
            status,
            date,
            headers,
            body.len,
            if (keep_alive) "keep-alive" else "close",
        }) catch {
            self.closeConn(conn, "response too large");
            return;
        };
        if (conn.out.total_len > http_queue_limit) {
            self.closeConn(conn, "response queue limit exceeded");
            return;
        }
        conn.close_after_flush = !keep_alive;
        const payload = if (head_only) "" else body;
        const drained = self.writePair(conn, writer.buffered(), payload) catch {
            self.closeConn(conn, "response write failed");
            return;
        };
        // A short response usually leaves nothing queued, so no EPOLLOUT would ever
        // arrive to run the close — the connection would just sit until it timed out.
        if (drained and conn.close_after_flush) {
            self.closeConn(conn, "response sent");
            return;
        }
        self.syncConn(conn);
    }

    fn respondStatus(self: *Relay, conn: *Conn, status: []const u8) void {
        var body_buf: [512]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf, "<!doctype html><html><head><title>{s}</title></head><body><h1>{s}</h1></body></html>\n", .{ status, status }) catch self.cover_page;
        self.respondPage(conn, status, self.notfound_headers, body, false, false);
    }

    // ── WebSocket upgrade ─────────────────────────────────────────────────────

    fn upgrade(self: *Relay, conn: *Conn, request: *const http.Request, user: []const u8) void {
        if (self.session_count >= self.opts.max_sessions) {
            self.respondStatus(conn, "503 Service Unavailable");
            return;
        }
        const key = request.header("sec-websocket-key") orelse {
            self.respondStatus(conn, "400 Bad Request");
            return;
        };
        if (!ws.validKey(key)) {
            self.respondStatus(conn, "400 Bad Request");
            return;
        }
        if (self.opts.check_origin) {
            const origin = request.header("origin") orelse "";
            var expected: [capability.max_host_len + 16]u8 = undefined;
            const want = std.fmt.bufPrint(&expected, "https://{s}", .{self.opts.domain}) catch "";
            if (!std.mem.eql(u8, origin, want)) {
                log.debug("rejecting websocket upgrade with unexpected origin", .{});
                self.respondPage(conn, "404 Not Found", self.notfound_headers, self.cover_page, false, false);
                return;
            }
        }

        const accept = ws.acceptKey(key);
        var head_buf: [256]u8 = undefined;
        const head = std.fmt.bufPrint(&head_buf, "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n\r\n", .{accept}) catch {
            self.closeConn(conn, "upgrade response too large");
            return;
        };

        const session = self.allocator.create(Session) catch {
            self.closeConn(conn, "out of memory");
            return;
        };
        session.* = .{
            .conn = conn,
            .user = user,
            .client_addr = self.clientAddress(conn, request),
            .last_rx_ms = nowMs(),
            .last_ping_ms = nowMs(),
        };
        session.closed_ids = self.allocator.alloc(u32, @max(closed_history, self.opts.max_streams)) catch {
            self.allocator.destroy(session);
            self.closeConn(conn, "out of memory");
            return;
        };
        @memset(session.closed_ids, 0);

        conn.kind = .websocket;
        conn.session = session;
        conn.close_after_flush = false;
        conn.deadline_ms = 0;
        self.session_count += 1;

        _ = self.writePair(conn, head, "") catch {
            self.closeConn(conn, "upgrade write failed");
            return;
        };
        // Whether the real client address survived the masking hop is the one thing an
        // operator cannot see from outside, and it decides what Telegram is told about
        // this user — so say it, without ever logging the address itself.
        const client_known = if (session.client_addr) |addr| !trusted_peers.isLoopback(addr) else false;
        log.info("web session opened for user {s} (client address: {s})", .{
            user,
            if (client_known) "real" else "loopback — Telegram will see this user as 127.0.0.1",
        });
        self.syncConn(conn);
    }

    /// The address to announce to the proxy.
    ///
    /// Behind a TLS terminator the socket peer is the terminator, so a forwarded-for
    /// header is the only source of the real client. Only its right-most entry is read,
    /// because that is the one our own hop wrote and the one a client cannot forge —
    /// and only the LAST such header line, because a terminator that appends a line
    /// rather than replacing ours would otherwise leave the client's own line first.
    ///
    /// In `--mode mask` this legitimately resolves to loopback: the masking hop inside
    /// the proxy is a raw byte pipe that carries no client address, so nginx genuinely
    /// observes 127.0.0.1. That costs per-IP granularity for relayed users, which is why
    /// they are exempt from the per-IP guards rather than sharing one key with them.
    fn clientAddress(self: *Relay, conn: *Conn, request: *const http.Request) ?Address {
        if (self.opts.trust_forwarded_for and self.opts.client_ip_header.len > 0 and trusted_peers.isLoopback(conn.peer)) {
            if (request.lastHeader(self.opts.client_ip_header)) |value| {
                if (http.forwardedForClient(value)) |text| {
                    if (Address.parse(text, 0)) |addr| {
                        if (!trusted_peers.isLoopback(addr)) return addr;
                    } else |_| {}
                }
            }
        }
        return conn.peer;
    }

    fn destroySession(self: *Relay, session: *Session) void {
        if (session.tearing_down) return;
        session.tearing_down = true;
        var it = session.streams.valueIterator();
        while (it.next()) |stream_ptr| {
            const stream = stream_ptr.*;
            if (stream.conn) |backend| {
                backend.stream = null;
                self.closeConn(backend, "session closed");
            }
            self.allocator.destroy(stream);
        }
        session.streams.deinit(self.allocator);
        self.allocator.free(session.closed_ids);
        self.session_count -|= 1;
        const avg_frame = if (session.data_frames > 0) session.data_bytes / session.data_frames else 0;
        log.info("web session closed for user {s} (peak {d}/{d} streams, {d} refused, {d} KiB in {d} frames, avg {d} B)", .{
            session.user,
            session.streams_high_water,
            self.opts.max_streams,
            session.streams_refused,
            session.data_bytes / 1024,
            session.data_frames,
            avg_frame,
        });
        self.allocator.destroy(session);
    }

    // ── WebSocket frames ──────────────────────────────────────────────────────

    fn onWsReadable(self: *Relay, conn: *Conn) void {
        const n = posix.read(conn.fd, &self.read_buf) catch |err| {
            if (err == error.WouldBlock) return;
            self.closeConn(conn, "websocket read error");
            return;
        };
        if (n == 0) {
            self.closeConn(conn, "websocket closed by peer");
            return;
        }
        self.appendInput(conn, self.read_buf[0..n], false) catch {
            self.closeConn(conn, "out of memory");
            return;
        };
        if (conn.session) |session| session.last_rx_ms = nowMs();
        self.processWsBuffer(conn);
    }

    /// Parse and dispatch every complete WebSocket frame buffered in `conn.in`.
    ///
    /// Frames are consumed with a cursor and the buffer is compacted **once**, when the
    /// pass ends. `dropFront` memmoves the whole remainder, so compacting per frame made
    /// this O(n²) in the size of one read: a peer packing a 64 KiB read with minimal
    /// 6-byte frames (a masked zero-length PONG costs it nothing and is answered by
    /// nothing) moved ~340 MiB per pass and pinned the relay's single thread, stalling
    /// every other WEB session on the box.
    fn processWsBuffer(self: *Relay, conn: *Conn) void {
        if (conn.close_after_flush) return;
        const fd = conn.fd;
        var used: usize = 0;
        // Only a still-mapped connection may be touched: a frame handler can close this
        // one, and then `conn` is queued for release and its buffer is no longer ours.
        defer if (self.alive(fd)) {
            dropFront(&conn.in, used);
            self.accountConn(conn);
        };
        while (true) {
            const rest = conn.in.items[used..];
            const parsed = ws.parseHeader(rest) catch |err| {
                self.failCarrier(conn, if (err == error.TooBig) ws.close_message_too_big else ws.close_protocol_error, "bad websocket frame");
                return;
            };
            const header = switch (parsed) {
                .incomplete => return,
                .header => |h| h,
            };
            if (rest.len < header.totalLen()) {
                return;
            }
            const payload = rest[header.header_len..header.totalLen()];
            ws.unmask(payload, header.mask, 0);
            // Counted before dispatch: the handler may return through the `defer` above.
            used += header.totalLen();
            self.handleWsFrame(conn, header, payload);
            if (!self.alive(fd) or conn.close_after_flush) return;
        }
    }

    fn handleWsFrame(self: *Relay, conn: *Conn, header: ws.Header, payload: []u8) void {
        switch (header.opcode) {
            .close => {
                self.failCarrier(conn, ws.close_normal, "websocket close from client");
                return;
            },
            .ping => {
                // A client that pings faster than it reads would otherwise grow this
                // queue at line rate; it has nothing to gain from that.
                if (conn.out.total_len + payload.len + ws.max_server_header > carrier_queue_limit) {
                    self.closeConn(conn, "pong queue limit exceeded");
                    return;
                }
                var head: [ws.max_server_header]u8 = undefined;
                const framing = ws.writeHeader(&head, true, .pong, payload.len) catch return;
                _ = self.writePair(conn, framing, payload) catch {
                    self.closeConn(conn, "pong write failed");
                    return;
                };
                self.syncConn(conn);
                return;
            },
            .pong => return,
            .text => {
                // The bridge page only ever sends binary carrier messages.
                self.failCarrier(conn, ws.close_unsupported_data, "unexpected text frame");
                return;
            },
            .binary, .continuation => {},
            _ => {
                self.failCarrier(conn, ws.close_protocol_error, "unknown opcode");
                return;
            },
        }

        if (header.opcode == .binary and conn.msg_active) {
            self.failCarrier(conn, ws.close_protocol_error, "interleaved message");
            return;
        }
        if (header.opcode == .continuation and !conn.msg_active) {
            self.failCarrier(conn, ws.close_protocol_error, "continuation without start");
            return;
        }

        if (header.fin and !conn.msg_active) {
            self.handleCarrierMessage(conn, payload);
            return;
        }
        if (conn.msg.items.len + payload.len > ws.max_message) {
            self.failCarrier(conn, ws.close_message_too_big, "fragmented message too large");
            return;
        }
        self.appendInput(conn, payload, true) catch {
            self.closeConn(conn, "out of memory");
            return;
        };
        conn.msg_active = !header.fin;
        if (!header.fin) return;
        const fd = conn.fd;
        self.handleCarrierMessage(conn, conn.msg.items);
        if (!self.alive(fd)) return;
        conn.msg.clearRetainingCapacity();
        self.accountConn(conn);
    }

    /// One carrier message holds one or more complete relay frames — an empty message or
    /// a trailing partial frame is a protocol error, exactly as it is on the client side.
    fn handleCarrierMessage(self: *Relay, conn: *Conn, message: []const u8) void {
        const fd = conn.fd;
        const session = conn.session orelse return;
        if (message.len == 0) {
            self.failCarrier(conn, ws.close_protocol_error, "empty carrier message");
            return;
        }
        var it = frame.Iterator.init(message);
        while (true) {
            const maybe = it.next() catch {
                self.failCarrier(conn, ws.close_protocol_error, "malformed relay frame");
                return;
            };
            const f = maybe orelse break;
            self.handleRelayFrame(session, f) catch |err| {
                log.debug("relay protocol error: {any}", .{err});
                // `error.CarrierClosed` means sendFrame already dropped the carrier —
                // and destroySession freed `session` with it. Only a still-live carrier
                // gets the BYE.
                if (!self.alive(fd)) return;
                self.byeAndClose(session);
                return;
            };
            // failCarrier may have condemned the carrier without closing it yet (it
            // still has a CLOSE frame to flush); nothing after that point is useful.
            if (!self.alive(fd) or conn.close_after_flush) return;
        }
        if (it.rest().len != 0) {
            self.failCarrier(conn, ws.close_protocol_error, "partial trailing frame");
        }
    }

    const ProtocolError = error{Protocol};
    /// Returned by `sendFrame` once the carrier is gone, so callers stop touching it.
    const CarrierError = error{CarrierClosed};

    fn handleRelayFrame(self: *Relay, session: *Session, f: frame.Frame) !void {
        if (!session.welcomed) {
            // Nothing may precede HELLO.
            if (f.type != .hello or f.stream_id != 0) return error.Protocol;
        }
        if (f.stream_id == 0) {
            switch (f.type) {
                .hello => {
                    if (session.welcomed) return error.Protocol;
                    if (f.payload.len != 1 or f.payload[0] != 1) return error.Protocol;
                    session.welcomed = true;
                    // WELCOME must arrive alone: the client parses the first carrier
                    // message and requires exactly one WELCOME frame in it.
                    try self.sendFrame(session, .welcome, 0, "");
                },
                .pong => {
                    if (f.payload.len > frame.max_ping_payload) return error.Protocol;
                    // Any inbound frame updates last_rx_ms; a late PONG remains valid.
                },
                .ping => {
                    if (f.payload.len > frame.max_ping_payload) return error.Protocol;
                    try self.sendFrame(session, .pong, 0, f.payload);
                },
                .bye => self.byeAndClose(session),
                else => return error.Protocol,
            }
            return;
        }

        const entry = session.streams.get(f.stream_id) orelse {
            if (session.recentlyClosed(f.stream_id)) {
                // Late DATA/WINDOW/CLOSE for a stream we just closed is an ordinary
                // cross-direction race. An OPEN is not: the client never reuses an id,
                // so answer it with a CLOSE rather than leaving it believing the socket
                // is live.
                if (f.type == .open) self.sendFrame(session, .close, f.stream_id, "") catch {};
                return;
            }
            if (f.type != .open) return error.Protocol;
            try self.openStream(session, f.stream_id);
            return;
        };

        switch (f.type) {
            .open => return error.Protocol,
            .data => {
                if (f.payload.len == 0) return error.Protocol;
                if (f.payload.len > entry.recv_window) return error.Protocol;
                entry.recv_window -= @intCast(f.payload.len);
                self.writeToBackend(entry, f.payload);
            },
            .window => {
                const amount = frame.readWindow(f.payload) orelse return error.Protocol;
                entry.send_window = @intCast(@min(
                    @as(u64, entry.send_window) + amount,
                    @as(u64, std.math.maxInt(u32)),
                ));
                if (entry.conn) |backend| self.syncConn(backend);
            },
            .close => {
                if (f.payload.len != 0) return error.Protocol;
                self.closeStream(entry, false);
            },
            else => return error.Protocol,
        }
    }

    fn sendFrame(self: *Relay, session: *Session, kind: frame.FrameType, stream_id: u32, payload: []const u8) !void {
        const conn = session.conn;
        if (conn.close_after_flush) return error.CarrierClosed;
        if (kind != .welcome and kind != .bye) {
            if (conn.batch.items.len + frame.header_size + payload.len > data_frame_size or conn.batch_frames >= frame.max_batch_frames) {
                self.flushBatch(conn) catch {
                    self.closeConn(conn, "carrier batch write failed");
                    return error.CarrierClosed;
                };
            }
            if (!self.canBuffer(frame.header_size + payload.len) or conn.out.total_len + conn.batch.items.len + frame.header_size + payload.len > carrier_queue_limit) {
                self.closeConn(conn, "carrier buffer budget exceeded");
                return error.CarrierClosed;
            }
            if (!conn.batch_pending) {
                self.batch_fds.append(self.allocator, conn.fd) catch {
                    self.closeConn(conn, "out of memory");
                    return error.CarrierClosed;
                };
                conn.batch_pending = true;
            }
            var relay_header: [frame.header_size]u8 = undefined;
            frame.writeHeader(&relay_header, kind, stream_id, @intCast(payload.len));
            conn.batch.ensureUnusedCapacity(self.allocator, relay_header.len + payload.len) catch {
                self.closeConn(conn, "out of memory");
                return error.CarrierClosed;
            };
            conn.batch.appendSliceAssumeCapacity(&relay_header);
            conn.batch.appendSliceAssumeCapacity(payload);
            conn.batch_frames += 1;
            self.accountConn(conn);
            return;
        }
        self.flushBatch(conn) catch {
            self.closeConn(conn, "carrier batch write failed");
            return error.CarrierClosed;
        };
        var head: [ws.max_server_header + frame.header_size]u8 = undefined;
        const total = frame.header_size + payload.len;
        const framing = ws.writeHeader(head[0..ws.max_server_header], true, .binary, total) catch return error.Protocol;
        frame.writeHeader(head[framing.len..][0..frame.header_size], kind, stream_id, @intCast(payload.len));
        const prefix = head[0 .. framing.len + frame.header_size];
        if (conn.out.total_len + prefix.len + payload.len > carrier_queue_limit) {
            // The client is not draining. Everything past this point would be memory we
            // can never hand over, so drop the carrier and let it reconnect.
            self.closeConn(conn, "carrier queue limit exceeded");
            return error.CarrierClosed;
        }
        _ = self.writePair(conn, prefix, payload) catch {
            self.closeConn(conn, "carrier write failed");
            return error.CarrierClosed;
        };
        self.syncConn(conn);
    }

    /// Send BYE and drop the carrier. The client fails its live streams and retries with
    /// a fresh WebView after its own backoff.
    fn byeAndClose(self: *Relay, session: *Session) void {
        const conn = session.conn;
        const fd = conn.fd;
        self.sendFrame(session, .bye, 0, "") catch {};
        if (!self.alive(fd)) return;
        self.failCarrier(conn, ws.close_normal, "relay closed the carrier");
    }

    fn failCarrier(self: *Relay, conn: *Conn, code: u16, reason: []const u8) void {
        // Discard unsent logical frames before the terminal WebSocket CLOSE.
        conn.batch.clearRetainingCapacity();
        conn.batch_frames = 0;
        self.accountConn(conn);
        var buf: [8]u8 = undefined;
        if (ws.closeFrame(&buf, code)) |close_frame| {
            _ = self.writePair(conn, close_frame, "") catch {};
        } else |_| {}
        conn.close_after_flush = true;
        log.debug("carrier failing: {s}", .{reason});
        if (conn.out.isEmpty()) {
            self.closeConn(conn, reason);
            return;
        }
        self.syncConn(conn);
    }

    // ── streams ───────────────────────────────────────────────────────────────

    fn openStream(self: *Relay, session: *Session, id: u32) !void {
        if (id == 0 or id > frame.max_stream_id) return error.Protocol;
        if (session.streams.count() >= self.opts.max_streams) {
            // Refuse this one socket rather than the whole carrier: the client treats a
            // CLOSE as an ordinary connection failure and retries, whereas a protocol
            // error would drop every other stream with it. It does mean the client sees
            // an unexplained failure, so make the cause visible here.
            session.streams_refused +|= 1;
            self.streams_refused +|= 1;
            if (session.streams_refused == 1) {
                log.warn("user {s}: refused a stream over the [web].max_streams cap of {d}; " ++
                    "the client will retry it as a failed connection. Raise max_streams if this repeats.", .{
                    session.user,
                    self.opts.max_streams,
                });
            }
            session.rememberClosed(id);
            self.sendFrame(session, .close, id, "") catch {};
            return;
        }

        const stream = self.allocator.create(Stream) catch return error.Protocol;
        stream.* = .{ .id = id, .session = session };
        session.streams.put(self.allocator, id, stream) catch {
            self.allocator.destroy(stream);
            return error.Protocol;
        };
        const live: u32 = @intCast(session.streams.count());
        if (live > session.streams_high_water) session.streams_high_water = live;

        const candidates = if (self.backend_dns) |cache| cache.snapshot(self.backend_dns_id) else net_helpers.AddressCandidates.init(&.{self.opts.backend});
        var next: usize = 0;
        const dialed_fd = self.dialCandidate(candidates, &next) catch |err| {
            log.debug("backend dial failed: {any}", .{err});
            self.closeStream(stream, true);
            return;
        };
        const conn = self.createConn(dialed_fd, .backend, candidates.addresses[next - 1]) catch {
            closeFd(dialed_fd);
            self.closeStream(stream, true);
            return;
        };
        conn.stream = stream;
        conn.connecting = true;
        conn.backend_candidates = candidates;
        conn.backend_next = next;
        conn.deadline_ms = nowMs() + backend_connect_timeout_ms;
        stream.conn = conn;

        const backend_fd = conn.fd;
        self.sendProxyHeader(stream, session);
        if (!self.alive(backend_fd)) return;
        self.syncConn(conn);
    }

    fn dialCandidate(self: *Relay, candidates: net_helpers.AddressCandidates, next: *usize) !posix.fd_t {
        while (next.* < candidates.len) {
            const address = candidates.addresses[next.*];
            next.* += 1;
            return dialBackend(address, self.local_backend) catch continue;
        }
        return error.BackendAddressesExhausted;
    }

    fn retryBackend(self: *Relay, conn: *Conn) bool {
        const fd = self.dialCandidate(conn.backend_candidates, &conn.backend_next) catch return false;
        // Preserve the old fd until the event batch ends; preserve the connection's queue.
        self.pending_close.ensureTotalCapacity(self.allocator, self.conns.count() + self.pending_close.items.len + 1) catch {
            closeFd(fd);
            return false;
        };
        self.conns.put(self.allocator, fd, conn) catch {
            closeFd(fd);
            return false;
        };
        self.addFd(fd, false, true) catch {
            _ = self.conns.remove(fd);
            closeFd(fd);
            return false;
        };
        const old_fd = conn.fd;
        self.delFd(old_fd);
        _ = self.conns.remove(old_fd);
        self.deferClose(old_fd);
        conn.fd = fd;
        conn.peer = conn.backend_candidates.addresses[conn.backend_next - 1];
        conn.want_in = false;
        conn.want_out = true;
        conn.deadline_ms = nowMs() + backend_connect_timeout_ms;
        return true;
    }

    fn dialBackend(address: Address, local_backend: bool) !posix.fd_t {
        const family: u32 = if (net_helpers.isIpv6(address)) posix.AF.INET6 else posix.AF.INET;
        const flags = posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC;
        const rc = posix.system.socket(family, flags, posix.IPPROTO.TCP);
        const fd: posix.fd_t = switch (posix.errno(rc)) {
            .SUCCESS => @intCast(rc),
            else => return error.SocketFailed,
        };
        errdefer closeFd(fd);
        var storage: posix.sockaddr.storage = undefined;
        if (local_backend) {
            // Preserve the existing loopback-only trust boundary even when the
            // proxy binds a specific public IP. Never do this for remote backends.
            const source = switch (address) {
                .ip4 => net_helpers.ip4(.{ 127, 0, 0, 1 }, 0),
                .ip6 => |v6| try Address.parse(if (std.mem.allEqual(u8, v6.bytes[0..10], 0) and
                    v6.bytes[10] == 0xff and v6.bytes[11] == 0xff)
                    "::ffff:127.0.0.1"
                else
                    "::1", 0),
            };
            const source_len = addressToSockaddr(source, &storage);
            if (posix.errno(posix.system.bind(fd, @ptrCast(&storage), source_len)) != .SUCCESS)
                return error.BackendSourceBindFailed;
        }
        const len = addressToSockaddr(address, &storage);
        socket_utils.connectSockaddr(fd, @ptrCast(&storage), len) catch |err| {
            if (err != error.WouldBlock) return err;
        };
        return fd;
    }

    /// Announce the real browser address to the proxy. Without this every relayed user
    /// arrives from 127.0.0.1, which collapses the proxy's per-IP flood guard onto one
    /// key and makes Telegram see one client IP for everybody.
    fn sendProxyHeader(self: *Relay, stream: *Stream, session: *Session) void {
        const conn = stream.conn orelse return;
        var buf: [64]u8 = undefined;
        const header = proxy_protocol.buildV2(&buf, session.client_addr, self.opts.backend);
        const before = conn.out.total_len;
        _ = self.writePair(conn, header, "") catch {
            self.closeConn(conn, "proxy header write failed");
            return;
        };
        // Only the part that landed in the queue can later look like a drain, so only
        // that part may be discounted from the client's credit. A header written inline
        // never shows up in the drain accounting and must not be charged at all.
        stream.grant_debt += conn.out.total_len - before;
    }

    fn writeToBackend(self: *Relay, stream: *Stream, data: []const u8) void {
        const conn = stream.conn orelse {
            // The backend is gone but the client has not seen CLOSE yet; drop the bytes,
            // exactly as the client's own TCP path drops undelivered data on a close.
            return;
        };
        if (conn.out.total_len + data.len > backend_queue_limit) {
            // The loopback backend is not draining. Fail this one stream; the client
            // reconnects it, and the other streams on this carrier are unaffected.
            log.debug("stream {d}: backend queue limit exceeded", .{stream.id});
            self.closeStream(stream, true);
            return;
        }
        const fd = conn.fd;
        const before = conn.out.total_len;
        _ = self.writePair(conn, data, "") catch {
            self.closeConn(conn, "backend write failed");
            return;
        };
        self.creditDrainWith(conn, before + data.len);
        if (!self.alive(fd)) return;
        self.syncConn(conn);
    }

    /// Replenish client credit for bytes that actually left for the backend.
    fn creditDrain(self: *Relay, conn: *Conn, before: usize) void {
        self.creditDrainWith(conn, before);
    }

    fn creditDrainWith(self: *Relay, conn: *Conn, owed_before: usize) void {
        const stream = conn.stream orelse return;
        const after = conn.out.total_len;
        if (owed_before <= after) return;
        var written = owed_before - after;
        if (stream.grant_debt > 0) {
            const paid = @min(stream.grant_debt, written);
            stream.grant_debt -= paid;
            written -= paid;
        }
        if (written == 0) return;
        self.grantWindow(stream, @intCast(written));
    }

    fn grantWindow(self: *Relay, stream: *Stream, amount: u32) void {
        const headroom = frame.initial_stream_window - stream.recv_window;
        const grant = @min(amount, headroom);
        if (grant == 0) return;
        stream.recv_window += grant;
        stream.pending_grant += grant;
        // Over budget the grant is recorded but not announced: the client keeps waiting
        // on credit until the queues drain, and the accounting above guarantees the
        // credit is released — never lost — once the throttle lifts.
        if (self.throttled) {
            stream.session.needs_window_flush = true;
            return;
        }
        if (stream.pending_grant >= window_flush_bytes) {
            self.flushWindow(stream);
        } else {
            stream.session.needs_window_flush = true;
        }
    }

    fn flushWindow(self: *Relay, stream: *Stream) void {
        if (stream.pending_grant == 0) return;
        const amount = stream.pending_grant;
        stream.pending_grant = 0;
        const payload = frame.windowPayload(amount);
        self.sendFrame(stream.session, .window, stream.id, &payload) catch {};
    }

    fn closeStream(self: *Relay, stream: *Stream, notify_client: bool) void {
        const session = stream.session;
        if (session.streams.fetchRemove(stream.id) == null) return;
        session.rememberClosed(stream.id);
        if (stream.conn) |backend| {
            backend.stream = null;
            stream.conn = null;
            self.closeConn(backend, "stream closed");
        }
        if (notify_client and !session.tearing_down) {
            self.sendFrame(session, .close, stream.id, "") catch {};
        }
        self.allocator.destroy(stream);
    }

    fn onBackendReadable(self: *Relay, conn: *Conn) void {
        const fd = conn.fd;
        const stream = conn.stream orelse {
            self.closeConn(conn, "orphan backend");
            return;
        };
        if (conn.connecting) return;
        const session = stream.session;
        conn.rx_passes += 1;
        if (session.conn.close_after_flush or self.throttled) return;
        conn.last_window = stream.send_window;
        while (true) {
            const budget = @min(@as(usize, stream.send_window), data_frame_size);
            if (budget == 0) {
                conn.stall_window += 1;
                return;
            }
            if (session.conn.out.total_len >= carrier_high_water) {
                conn.stall_carrier += 1;
                return;
            }

            // Coalesce whatever the socket already holds into ONE frame rather than
            // emitting a frame per read. The client pays per frame, not per byte: each
            // one is a base64 encode plus a native bridge crossing on the WebView's JS
            // thread, and that thread also has to answer the client's own health probe.
            // A download arriving as thousands of small frames can starve it; the same
            // bytes as tens of 64 KiB frames do not. Reads are non-blocking, so this only
            // gathers data already buffered — it adds no latency for interactive traffic.
            var filled: usize = 0;
            var hit_eof = false;
            var read_failed = false;
            while (filled < budget) {
                const n = posix.read(conn.fd, self.read_buf[filled..budget]) catch |err| {
                    if (err != error.WouldBlock) read_failed = true;
                    break;
                };
                if (n == 0) {
                    hit_eof = true;
                    break;
                }
                filled += n;
            }

            if (filled > 0) {
                conn.rx_bytes += filled;
                stream.send_window -= @intCast(filled);
                session.data_frames += 1;
                session.data_bytes += filled;
                // Deliver before acting on EOF: bytes read alongside a graceful close are
                // still the client's.
                self.sendFrame(session, .data, stream.id, self.read_buf[0..filled]) catch return;
                if (!self.alive(fd)) return;
            }
            if (read_failed) {
                self.closeConn(conn, "backend read error");
                return;
            }
            if (hit_eof) {
                self.closeConn(conn, "backend closed");
                return;
            }
            if (filled < budget) return; // socket drained
        }
    }

    // ── timers ────────────────────────────────────────────────────────────────

    fn tick(self: *Relay, now: i64) void {
        if (self.accept_resume_ms != 0 and now >= self.accept_resume_ms) {
            self.accept_resume_ms = 0;
            self.modFd(self.listen_fd, true, false);
            log.info("resuming accepts", .{});
        }

        // Snapshot the fds first: anything below can close a connection (a failed
        // WINDOW or PING write), and that mutates the very map an iterator would be
        // walking. The scratch list is reused so a 50 ms tick allocates nothing.
        self.tick_scratch.clearRetainingCapacity();
        var queued: usize = 0;
        var it = self.conns.iterator();
        while (it.next()) |entry| {
            queued += entry.value_ptr.*.accounted_bytes;
            self.tick_scratch.append(self.allocator, entry.key_ptr.*) catch break;
        }
        const was_throttled = self.throttled;
        self.throttled = queued >= self.opts.max_buffer_bytes -| (2 * read_buf_size);
        if (self.throttled != was_throttled) {
            log.warn("relay {s} at {d} KiB queued (budget {d} KiB)", .{
                if (self.throttled) "throttling" else "resuming",
                queued / 1024,
                self.opts.max_buffer_bytes / 1024,
            });
        }

        for (self.tick_scratch.items) |fd| {
            const conn = self.conns.get(fd) orelse continue;
            if (conn.deadline_ms != 0 and now >= conn.deadline_ms) {
                if (conn.connecting and self.retryBackend(conn)) continue;
                self.closeConn(conn, "timed out");
                continue;
            }
            if (conn.kind != .websocket) continue;
            const session = conn.session orelse continue;

            // Checked before `welcomed`, so a carrier that upgrades and then never
            // sends HELLO is reaped instead of living forever.
            if (now - session.last_rx_ms >= session_silence_timeout_ms) {
                self.closeConn(conn, "carrier silent");
                continue;
            }
            if (was_throttled and !self.throttled) self.resumeBackends(session);
            // Grants recorded while throttled are announced only once the budget allows.
            if (session.needs_window_flush and !self.throttled) {
                session.needs_window_flush = false;
                var streams = session.streams.valueIterator();
                while (streams.next()) |stream_ptr| {
                    self.flushWindow(stream_ptr.*);
                    if (!self.alive(fd)) break;
                }
                if (!self.alive(fd)) continue;
            }
            if (!session.welcomed) continue;
            // Probe only a QUIET carrier, and never let the probe itself be lethal.
            //
            // A PING shares one FIFO with bulk DATA, and the client processes that queue
            // serially across its WebView bridge — so during a download the probe can sit
            // behind megabytes and be answered long after the interval. Killing on a
            // single unanswered probe tore down perfectly healthy carriers mid-transfer,
            // which the client saw as a dead connection and retried, restarting every
            // download from zero. Any inbound frame already proves the carrier is alive
            // (`last_rx_ms`), and a genuinely half-open socket produces none at all, so
            // `session_silence_timeout_ms` above is the correct — and only — kill.
            const quiet_for = now - session.last_rx_ms;
            if (quiet_for >= ping_interval_ms and now - session.last_ping_ms >= ping_interval_ms) {
                session.last_ping_ms = now;
                crypto.randomBytes(&session.ping_payload);
                self.sendFrame(session, .ping, 0, &session.ping_payload) catch {};
            }
        }
    }
};

// ── helpers ───────────────────────────────────────────────────────────────────

fn httpDate(buffer: []u8, seconds: u64) ![]const u8 {
    const epoch = std.time.epoch.EpochSeconds{ .secs = seconds };
    const day = epoch.getEpochDay();
    const year = day.calculateYearDay();
    const month = year.calculateMonthDay();
    const time = epoch.getDaySeconds();
    const weekdays = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    return std.fmt.bufPrint(buffer, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{ weekdays[(day.day + 4) % 7], @as(u8, month.day_index) + 1, months[month.month.numeric() - 1], year.year, time.getHoursIntoDay(), time.getMinutesIntoHour(), time.getSecondsIntoMinute() });
}

test "HTTP Date uses IMF-fixdate in UTC" {
    var buffer: [40]u8 = undefined;
    try std.testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", try httpDate(&buffer, 0));
    try std.testing.expectEqualStrings("Sun, 06 Nov 1994 08:49:37 GMT", try httpDate(&buffer, 784111777));
}

/// Only a direct loopback scrape, never a request forwarded by the public terminator.
fn metricsRequestAllowed(peer: Address, request: *const http.Request) bool {
    if (!trusted_peers.isLoopback(peer) or (request.method != .get and request.method != .head)) return false;
    if (request.header("x-forwarded-for") != null or request.header("forwarded") != null or request.header("origin") != null) return false;
    const host = request.header("host") orelse return false;
    return std.mem.eql(u8, host, "127.0.0.1") or std.mem.startsWith(u8, host, "127.0.0.1:") or std.mem.eql(u8, host, "[::1]") or std.mem.startsWith(u8, host, "[::1]:");
}

/// Test-only witness: `processWsBuffer` must compact once per read pass, never once per
/// frame. Counting it is the only way a test can see the O(n²) memmove come back.
var compactions_for_test: usize = 0;

fn testRelay(allocator: std.mem.Allocator, limit: usize) Relay {
    var options: Options = undefined;
    options.max_buffer_bytes = limit;
    return .{
        .allocator = allocator,
        .opts = options,
        .caps = &.{},
        .cover_page = "",
        .bridge_page = "",
        .bridge_headers = "",
        .cover_headers = "",
        .notfound_headers = "",
        .epoll_fd = -1,
        .listen_fd = -1,
        .signal_fd = -1,
        .old_sigmask = undefined,
    };
}

test "aggregate budget includes input and fragment buffers and releases consumed bytes" {
    const allocator = std.testing.allocator;
    var relay = testRelay(allocator, 8);
    var conn = Conn{ .fd = -1, .kind = .websocket, .peer = net_helpers.ip4(.{ 127, 0, 0, 1 }, 0), .out = .{ .allocator = allocator } };
    defer conn.in.deinit(allocator);
    defer conn.msg.deinit(allocator);
    try relay.appendInput(&conn, "12345", false);
    try relay.appendInput(&conn, "678", true);
    try std.testing.expectEqual(@as(usize, 8), relay.buffered_bytes);
    try std.testing.expectError(error.BufferBudgetExceeded, relay.appendInput(&conn, "9", false));
    dropFront(&conn.in, 3);
    relay.accountConn(&conn);
    try relay.appendInput(&conn, "abc", true);
    try std.testing.expectEqual(@as(usize, 8), relay.buffered_bytes);
}

test "production emitter batches exact DATA and WINDOW bytes and refuses condemned carriers" {
    const allocator = std.testing.allocator;
    var relay = testRelay(allocator, 1024);
    defer relay.batch_fds.deinit(allocator);
    var conn = Conn{ .fd = -1, .kind = .websocket, .peer = net_helpers.ip4(.{ 127, 0, 0, 1 }, 0), .out = .{ .allocator = allocator } };
    defer conn.batch.deinit(allocator);
    var session = Session{ .conn = &conn, .user = "test", .client_addr = null };
    try relay.sendFrame(&session, .data, 7, "abc");
    const grant = frame.windowPayload(4096);
    try relay.sendFrame(&session, .window, 7, &grant);
    try std.testing.expectEqualSlices(u8, &.{ 2, 0, 0, 7, 0, 0, 0, 3, 'a', 'b', 'c', 4, 0, 0, 7, 0, 0, 0, 4, 0, 0, 16, 0 }, conn.batch.items);
    try std.testing.expectEqual(@as(usize, 2), conn.batch_frames);
    try std.testing.expectEqual(@as(usize, 1), relay.batch_fds.items.len);
    try std.testing.expectEqual(conn.batch.items.len, relay.buffered_bytes);
    conn.close_after_flush = true;
    try std.testing.expectError(error.CarrierClosed, relay.sendFrame(&session, .data, 7, "ignored"));
    try std.testing.expectEqual(@as(usize, 2), conn.batch_frames);
}

test "backend credit excludes PROXY header debt and grants only drained client bytes" {
    const allocator = std.testing.allocator;
    var relay = testRelay(allocator, 1024);
    var carrier = Conn{ .fd = -1, .kind = .websocket, .peer = net_helpers.ip4(.{ 127, 0, 0, 1 }, 0), .out = .{ .allocator = allocator } };
    var session = Session{ .conn = &carrier, .user = "test", .client_addr = null };
    var stream = Stream{ .id = 1, .session = &session, .recv_window = frame.initial_stream_window - 100, .grant_debt = 4 };
    var backend = Conn{ .fd = -1, .kind = .backend, .peer = carrier.peer, .stream = &stream, .out = .{ .allocator = allocator } };
    defer backend.out.deinit();
    try backend.out.appendCopy("0123456789");
    relay.creditDrainWith(&backend, 14);
    try std.testing.expectEqual(@as(usize, 0), stream.grant_debt);
    try std.testing.expectEqual(@as(u32, 0), stream.pending_grant);
    relay.creditDrainWith(&backend, 110);
    try std.testing.expectEqual(frame.initial_stream_window, stream.recv_window);
    try std.testing.expectEqual(@as(u32, 100), stream.pending_grant);
    try std.testing.expect(session.needs_window_flush);
    relay.creditDrainWith(&backend, 10); // no new bytes drained
    try std.testing.expectEqual(@as(u32, 100), stream.pending_grant);
}

test "metrics accepts direct loopback requests and rejects public or forwarded requests" {
    const request = try http.parse("GET /metrics HTTP/1.1\r\nHost: 127.0.0.1:8081\r\n\r\n");
    try std.testing.expect(metricsRequestAllowed(net_helpers.ip4(.{ 127, 0, 0, 1 }, 0), &request));
    try std.testing.expect(!metricsRequestAllowed(net_helpers.ip4(.{ 203, 0, 113, 7 }, 0), &request));
    const forwarded = try http.parse("GET /metrics HTTP/1.1\r\nHost: 127.0.0.1:8081\r\nX-Forwarded-For: 203.0.113.7\r\n\r\n");
    try std.testing.expect(!metricsRequestAllowed(net_helpers.ip4(.{ 127, 0, 0, 1 }, 0), &forwarded));
    var relay = testRelay(std.testing.allocator, 1024);
    relay.session_count = 3;
    relay.streams_refused = 7;
    var buffer: [2048]u8 = undefined;
    const metrics = try relay.renderMetrics(&buffer);
    try std.testing.expect(std.mem.indexOf(u8, metrics, "mtproto_web_sessions 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, metrics, "mtproto_web_streams_refused_total 7\n") != null);
}

test "a queued websocket CLOSE stops the rest of the same read batch" {
    const allocator = std.testing.allocator;
    var relay = testRelay(allocator, 1024);
    defer relay.conns.deinit(allocator);
    var conn = Conn{ .fd = -1, .kind = .websocket, .peer = net_helpers.ip4(.{ 127, 0, 0, 1 }, 0), .out = .{ .allocator = allocator } };
    conn.want_out = true; // epoll interest is already correct; no OS call in this unit test
    defer conn.in.deinit(allocator);
    defer conn.out.deinit();
    try relay.conns.put(allocator, conn.fd, &conn);
    try conn.out.appendCopy("x"); // prevent an inline write on the fake fd
    const close = [_]u8{ 0x88, 0x80, 1, 2, 3, 4 };
    try conn.in.appendSlice(allocator, &close);
    try conn.in.appendSlice(allocator, &close);
    relay.accountConn(&conn);
    relay.processWsBuffer(&conn);
    try std.testing.expect(conn.close_after_flush);
    try std.testing.expectEqual(@as(usize, 5), conn.out.total_len);
    try std.testing.expectEqualSlices(u8, &close, conn.in.items);
}

fn dropFront(list: *std.ArrayList(u8), n: usize) void {
    if (n == 0) return;
    if (builtin.is_test) compactions_for_test += 1;
    std.debug.assert(n <= list.items.len);
    const rest = list.items.len - n;
    if (rest > 0) std.mem.copyForwards(u8, list.items[0..rest], list.items[n..]);
    list.shrinkRetainingCapacity(rest);
}

fn listen(host: []const u8, port: u16) !posix.fd_t {
    const addr = Address.parse(host, port) catch |err| {
        log.err("[web].host must be an IP literal, got '{s}': {any}", .{ host, err });
        return err;
    };
    const server = net_helpers.listen(addr, 128, false) catch |err| {
        log.err("Cannot bind WEB relay to {s}:{d}: {any}; check [web].host/port and other listeners", .{ host, port, err });
        return err;
    };
    const fd = server.socket.handle;
    socket_utils.setNonBlocking(fd);
    return fd;
}

fn addressToSockaddr(addr: Address, storage: *posix.sockaddr.storage) posix.socklen_t {
    switch (addr) {
        .ip4 => |v4| {
            const sa: *posix.sockaddr.in = @ptrCast(@alignCast(storage));
            sa.* = .{
                .family = posix.AF.INET,
                .port = std.mem.nativeToBig(u16, v4.port),
                .addr = @bitCast(v4.bytes),
                .zero = [_]u8{0} ** 8,
            };
            return @sizeOf(posix.sockaddr.in);
        },
        .ip6 => |v6| {
            const sa: *posix.sockaddr.in6 = @ptrCast(@alignCast(storage));
            sa.* = .{
                .family = posix.AF.INET6,
                .port = std.mem.nativeToBig(u16, v6.port),
                .flowinfo = v6.flow,
                .addr = v6.bytes,
                .scope_id = v6.interface.index,
            };
            return @sizeOf(posix.sockaddr.in6);
        },
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

test "implicit local backend keeps a trusted loopback source on a specific IPv4 listener" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // UDP connect selects a local interface without sending any packets.
    const rc = posix.system.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    if (posix.errno(rc) != .SUCCESS) return error.SocketFailed;
    const probe: posix.fd_t = @intCast(rc);
    defer closeFd(probe);
    var storage: posix.sockaddr.storage = undefined;
    const len = addressToSockaddr(net_helpers.ip4(.{ 192, 0, 2, 1 }, 9), &storage);
    try socket_utils.connectSockaddr(probe, @ptrCast(&storage), len);
    var target = try socket_utils.localSocketAddress(probe);
    target.ip4.port = 0;
    try std.testing.expect(!trusted_peers.isLoopback(target));
    const server = try net_helpers.listen(target, 8, false);
    defer closeFd(server.socket.handle);
    target = try socket_utils.localSocketAddress(server.socket.handle);
    const fd = try Relay.dialBackend(target, true);
    defer closeFd(fd);
    const source = try socket_utils.localSocketAddress(fd);
    try std.testing.expect(trusted_peers.isLoopback(source));
    const peers = trusted_peers.TrustedPeers{ .enabled = true };
    try std.testing.expect(peers.contains(source));
    // Explicit remote backends must retain normal routing, not a loopback source.
    const explicit = try Relay.dialBackend(target, false);
    defer closeFd(explicit);
    try std.testing.expect(!peers.contains(try socket_utils.localSocketAddress(explicit)));
}

test "local backend source binding supports IPv6 and IPv4-mapped listeners" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    for ([_][]const u8{ "::1", "::ffff:127.0.0.1" }) |host| {
        const server = try net_helpers.listen(try Address.parse(host, 0), 8, false);
        defer closeFd(server.socket.handle);
        const target = try socket_utils.localSocketAddress(server.socket.handle);
        const fd = try Relay.dialBackend(target, true);
        defer closeFd(fd);
        try std.testing.expect(trusted_peers.isLoopback(try socket_utils.localSocketAddress(fd)));
    }
}

test "backend retry freezes candidates and preserves queued bytes while retiring stale fd" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const listener = try net_helpers.listen(net_helpers.ip4(.{ 127, 0, 0, 1 }, 0), 8, false);
    defer closeFd(listener.socket.handle);
    const target = try socket_utils.localSocketAddress(listener.socket.handle);
    var relay = Relay{
        .allocator = allocator,
        .opts = undefined,
        .caps = undefined,
        .cover_page = undefined,
        .bridge_page = undefined,
        .bridge_headers = undefined,
        .cover_headers = undefined,
        .notfound_headers = undefined,
        .epoll_fd = try socket_utils.epollCreate(),
        .listen_fd = -1,
        .signal_fd = -1,
        .old_sigmask = undefined,
    };
    relay.opts.max_buffer_bytes = 1024;
    defer closeFd(relay.epoll_fd);
    defer relay.conns.deinit(allocator);
    defer relay.pending_close.deinit(allocator);
    defer relay.pending_free.deinit(allocator);
    defer relay.tick_scratch.deinit(allocator);
    defer relay.drainPendingCloses();
    const first = try Relay.dialBackend(target, false);
    const conn = try relay.createConn(first, .backend, target);
    defer {
        closeFd(conn.fd);
        relay.destroyConn(conn);
    }
    conn.connecting = true;
    conn.backend_candidates = net_helpers.AddressCandidates.init(&.{ target, target, target, target });
    conn.backend_next = 1;
    try std.testing.expect(!try relay.writePair(conn, "PROXY", "payload"));
    try std.testing.expectEqual(@as(usize, 12), conn.out.total_len);
    relay.dispatch(conn, linux.EPOLL.ERR);
    try std.testing.expect(!relay.alive(first));
    try std.testing.expect(relay.alive(conn.fd));
    try std.testing.expectEqual(@as(usize, 1), relay.pending_close.items.len);
    try std.testing.expectEqual(@as(usize, 12), conn.out.total_len);
    try std.testing.expectEqual(@as(u64, 0), relay.bytes_out.load(.monotonic));
    const second = conn.fd;
    relay.tick(conn.deadline_ms);
    try std.testing.expect(!relay.alive(second));
    try std.testing.expect(relay.alive(conn.fd));
    try std.testing.expectEqual(@as(usize, 2), relay.pending_close.items.len);
    try std.testing.expectEqual(@as(usize, 12), conn.out.total_len);
    const third = conn.fd;
    relay.dispatch(conn, linux.EPOLL.RDHUP);
    try std.testing.expect(!relay.alive(third));
    try std.testing.expect(relay.alive(conn.fd));
    try std.testing.expectEqual(@as(usize, 3), relay.pending_close.items.len);
    try std.testing.expectEqual(@as(usize, 12), conn.out.total_len);
    // A stale event has no mapped connection, and exhausted candidates cannot loop.
    try std.testing.expect(!relay.retryBackend(conn));
    var empty_next: usize = 0;
    try std.testing.expectError(error.BackendAddressesExhausted, relay.dialCandidate(.{}, &empty_next));
}

test "proxy v2 header round-trips through the proxy's own parser" {
    var buf: [64]u8 = undefined;
    const client = net_helpers.ip4(.{ 203, 0, 113, 7 }, 51234);
    const backend = net_helpers.ip4(.{ 127, 0, 0, 1 }, 443);
    const header = proxy_protocol.buildV2(&buf, client, backend);
    try std.testing.expectEqual(@as(usize, 28), header.len);

    switch (proxy_protocol.parse(header)) {
        .ok => |res| {
            try std.testing.expectEqual(@as(usize, 28), res.consumed);
            const src = res.src.?;
            try std.testing.expectEqualSlices(u8, &[_]u8{ 203, 0, 113, 7 }, &src.ip4.bytes);
            try std.testing.expectEqual(@as(u16, 51234), src.ip4.port);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "an ipv4-mapped client is reported as ipv4" {
    var buf: [64]u8 = undefined;
    var mapped: [16]u8 = [_]u8{0} ** 16;
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    mapped[12] = 198;
    mapped[13] = 51;
    mapped[14] = 100;
    mapped[15] = 9;
    const client = net_helpers.ip6(mapped, 4242, 0, 0);
    const header = proxy_protocol.buildV2(&buf, client, net_helpers.ip4(.{ 127, 0, 0, 1 }, 443));
    try std.testing.expectEqual(@as(u8, 0x11), header[13]);
    switch (proxy_protocol.parse(header)) {
        .ok => |res| try std.testing.expectEqualSlices(u8, &[_]u8{ 198, 51, 100, 9 }, &res.src.?.ip4.bytes),
        else => return error.TestUnexpectedResult,
    }
}

test "an ipv6 client survives an ipv4 backend" {
    var buf: [64]u8 = undefined;
    var v6: [16]u8 = [_]u8{0} ** 16;
    v6[0] = 0x20;
    v6[1] = 0x01;
    v6[15] = 0x01;
    const header = proxy_protocol.buildV2(&buf, net_helpers.ip6(v6, 1234, 0, 0), net_helpers.ip4(.{ 127, 0, 0, 1 }, 443));
    try std.testing.expectEqual(@as(usize, 52), header.len);
    try std.testing.expectEqual(@as(u8, 0x21), header[13]);
    switch (proxy_protocol.parse(header)) {
        .ok => |res| try std.testing.expectEqualSlices(u8, &v6, &res.src.?.ip6.bytes),
        else => return error.TestUnexpectedResult,
    }
}

test "an unknown client becomes a LOCAL header the proxy tolerates" {
    var buf: [64]u8 = undefined;
    const header = proxy_protocol.buildV2(&buf, null, net_helpers.ip4(.{ 127, 0, 0, 1 }, 443));
    try std.testing.expectEqual(@as(usize, 16), header.len);
    switch (proxy_protocol.parse(header)) {
        .ok => |res| try std.testing.expectEqual(@as(?Address, null), res.src),
        else => return error.TestUnexpectedResult,
    }
}

test "a burst of tiny websocket frames compacts the carrier buffer once, not once per frame" {
    const allocator = std.testing.allocator;
    // Only the fields this path touches are real: a pong is answered by nothing, so no
    // socket, session or epoll fd is reached. `alive()` is the connection map alone.
    var relay = Relay{
        .allocator = allocator,
        .opts = undefined,
        .caps = undefined,
        .cover_page = undefined,
        .bridge_page = undefined,
        .bridge_headers = undefined,
        .cover_headers = undefined,
        .notfound_headers = undefined,
        .epoll_fd = -1,
        .listen_fd = -1,
        .signal_fd = -1,
        .old_sigmask = undefined,
    };
    defer relay.conns.deinit(allocator);
    var conn = Conn{
        .fd = 7,
        .kind = .websocket,
        .peer = net_helpers.ip4(.{ 127, 0, 0, 1 }, 0),
        .out = .{ .allocator = allocator },
    };
    defer conn.out.deinit();
    defer conn.in.deinit(allocator);
    try relay.conns.put(allocator, conn.fd, &conn);

    // The cheapest frame a client can send: masked, zero-length, opcode PONG.
    const tiny_pong = [_]u8{ 0x8a, 0x80, 1, 2, 3, 4 };
    for (0..512) |_| try conn.in.appendSlice(allocator, &tiny_pong);

    compactions_for_test = 0;
    relay.processWsBuffer(&conn);
    try std.testing.expectEqual(@as(usize, 0), conn.in.items.len);
    // One memmove for the pass. Per-frame compaction moved the whole remainder every
    // time, which is what let one peer burn a core with a few MB/s of pongs.
    try std.testing.expectEqual(@as(usize, 1), compactions_for_test);

    // The cursor must still leave a trailing partial frame in place for the next read.
    try conn.in.appendSlice(allocator, &tiny_pong);
    try conn.in.appendSlice(allocator, tiny_pong[0..2]);
    compactions_for_test = 0;
    relay.processWsBuffer(&conn);
    try std.testing.expectEqualSlices(u8, tiny_pong[0..2], conn.in.items);
    try std.testing.expectEqual(@as(usize, 1), compactions_for_test);
}

test "dropFront compacts a buffer" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    try list.appendSlice(std.testing.allocator, "abcdef");
    dropFront(&list, 2);
    try std.testing.expectEqualStrings("cdef", list.items);
    dropFront(&list, 4);
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
}

test "default backend follows the proxy bind address" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .port = 9443,
    };
    defer cfg.deinit(std.testing.allocator);
    const cases = .{
        .{ "192.0.2.7", "192.0.2.7" },
        .{ "2001:db8::7", "2001:db8::7" },
        .{ "0.0.0.0", "127.0.0.1" },
        .{ "::", "::1" },
    };
    inline for (cases) |case| {
        cfg.bind_address = try std.testing.allocator.dupe(u8, case[0]);
        const addr = try resolveBackend(std.testing.allocator, &cfg);
        try std.testing.expect(trusted_peers.sameHost(try Address.parse(case[1], 9443), addr));
        try std.testing.expectEqual(@as(u16, 9443), addr.getPort());
        std.testing.allocator.free(cfg.bind_address.?);
        cfg.bind_address = null;
    }
    cfg.bind_address = try std.testing.allocator.dupe(u8, "192.0.2.7");
    cfg.web.backend = try std.testing.allocator.dupe(u8, "127.0.0.1:8443");
    const explicit = try resolveBackend(std.testing.allocator, &cfg);
    try std.testing.expect(trusted_peers.isLoopback(explicit));
    try std.testing.expectEqual(@as(u16, 8443), explicit.getPort());
}

test "backend spec parsing rejects nonsense" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .port = 443,
    };
    defer cfg.deinit(std.testing.allocator);

    const fallback = try resolveBackend(std.testing.allocator, &cfg);
    try std.testing.expectEqual(@as(u16, 443), fallback.ip4.port);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &fallback.ip4.bytes);

    cfg.web.backend = try std.testing.allocator.dupe(u8, "127.0.0.1:8443");
    const parsed = try resolveBackend(std.testing.allocator, &cfg);
    try std.testing.expectEqual(@as(u16, 8443), parsed.ip4.port);

    std.testing.allocator.free(cfg.web.backend.?);
    cfg.web.backend = try std.testing.allocator.dupe(u8, "no-port-here");
    try std.testing.expectError(error.InvalidBackend, resolveBackend(std.testing.allocator, &cfg));
}

test "options require an enabled section, a domain and at least one user" {
    var buf: [capability.max_host_len]u8 = undefined;
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
    };
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectError(error.WebProxyDisabled, Options.fromConfig(&cfg, &buf));
    cfg.web.enabled = true;
    try std.testing.expectError(error.NoUsersConfigured, Options.fromConfig(&cfg, &buf));
    try cfg.users.put(try std.testing.allocator.dupe(u8, "alice"), [_]u8{7} ** 16);
    try std.testing.expectError(error.MissingDomain, Options.fromConfig(&cfg, &buf));
    cfg.web.domain = try std.testing.allocator.dupe(u8, "127.0.0.1");
    try std.testing.expectError(error.InvalidDomain, Options.fromConfig(&cfg, &buf));
    std.testing.allocator.free(cfg.web.domain.?);
    cfg.web.domain = try std.testing.allocator.dupe(u8, "Proxy.Example.COM");
    const opts = try Options.fromConfig(&cfg, &buf);
    try std.testing.expectEqualStrings("proxy.example.com", opts.domain);
    try std.testing.expectEqualStrings("/api/v1/socket", opts.ws_path);
    try std.testing.expectEqualStrings("127.0.0.1", opts.listen_host);
}

test "capabilities cover both accepted secret encodings for every user" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
    };
    defer cfg.deinit(std.testing.allocator);
    const secret = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    try cfg.users.put(try std.testing.allocator.dupe(u8, "alice"), secret);

    const caps = try buildCapabilities(std.testing.allocator, &cfg, "proxy.example.com");
    defer std.testing.allocator.free(caps);
    try std.testing.expectEqual(@as(usize, 2), caps.len);

    var saw_padded = false;
    var saw_plain = false;
    for (caps) |cap| {
        try std.testing.expectEqualStrings("alice", cap.user);
        if (std.mem.eql(u8, &cap.value, "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA")) saw_padded = true;
        if (std.mem.eql(u8, &cap.value, "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk")) saw_plain = true;
    }
    try std.testing.expect(saw_padded and saw_plain);
}
