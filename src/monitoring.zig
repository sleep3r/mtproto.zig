const std = @import("std");
const builtin = @import("builtin");
const net = std.net;
const posix = std.posix;
const linux = std.os.linux;
const proxy = @import("proxy/proxy.zig");
const config = @import("config.zig");
const version = @import("version").version;

const log = std.log.scoped(.monitoring);
const metrics_content_type = "text/plain; version=0.0.4";

const ProcessMetrics = struct {
    resident_memory_bytes: ?u64 = null,
    virtual_memory_bytes: ?u64 = null,
    cpu_seconds_total: ?f64 = null,
    open_fds: ?u64 = null,
    max_fds: ?u64 = null,
    cgroup_memory_usage_bytes: ?u64 = null,
    cgroup_memory_limit_bytes: ?u64 = null,
};

pub fn start(state: *proxy.ProxyState) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

    const host = state.config.monitoring.host;
    const port = state.config.monitoring.port;

    const addr_list = try net.getAddressList(std.heap.page_allocator, host, port);
    defer addr_list.deinit();

    if (addr_list.addrs.len == 0) return error.AddressNotAvailable;

    var server = try addr_list.addrs[0].listen(.{
        .reuse_address = true,
        .kernel_backlog = 64,
    });
    errdefer server.deinit();

    log.info("metrics endpoint listening on {s}:{d}", .{ host, port });

    const thread = try std.Thread.spawn(.{}, acceptLoop, .{ state, server });
    thread.detach();
}

fn acceptLoop(state: *proxy.ProxyState, server: net.Server) void {
    var local_server = server;
    defer local_server.deinit();

    while (true) {
        const conn = local_server.accept() catch |err| {
            log.warn("metrics accept failed: {any}", .{err});
            std.Thread.sleep(200 * std.time.ns_per_ms);
            continue;
        };
        handleConnection(state, conn.stream.handle);
    }
}

fn handleConnection(state: *proxy.ProxyState, fd: posix.fd_t) void {
    defer posix.close(fd);

    var req_buf: [2048]u8 = undefined;
    const req_len = posix.read(fd, &req_buf) catch return;
    if (req_len == 0) return;

    const request = req_buf[0..req_len];
    if (!isGetRequest(request)) {
        writeSimpleResponse(fd, "405 Method Not Allowed", "text/plain", "method not allowed\n");
        return;
    }
    if (!isGetMetrics(request)) {
        writeSimpleResponse(fd, "404 Not Found", "text/plain", "not found\n");
        return;
    }
    writeMetricsResponse(fd, state) catch {
        writeSimpleResponse(fd, "500 Internal Server Error", "text/plain", "internal error\n");
    };
}

fn writeMetricsResponse(fd: posix.fd_t, state: *proxy.ProxyState) !void {
    var body_buf: [16 * 1024]u8 = undefined;
    var body_stream = std.io.fixedBufferStream(&body_buf);
    try writeMetrics(body_stream.writer(), state, collectProcessMetrics());
    const body = body_stream.getWritten();

    var header_buf: [256]u8 = undefined;
    var header_stream = std.io.fixedBufferStream(&header_buf);
    const w = header_stream.writer();
    try w.print(
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: {s}\r\nContent-Length: {d}\r\n\r\n",
        .{ metrics_content_type, body.len },
    );
    try writeAll(fd, header_stream.getWritten());
    try writeAll(fd, body);
}

fn writeSimpleResponse(fd: posix.fd_t, status: []const u8, content_type: []const u8, body: []const u8) void {
    var buf: [512]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const w = stream.writer();
    w.print(
        "HTTP/1.1 {s}\r\nConnection: close\r\nContent-Type: {s}\r\nContent-Length: {d}\r\n\r\n{s}",
        .{ status, content_type, body.len, body },
    ) catch return;
    writeAll(fd, stream.getWritten()) catch {};
}

fn writeAll(fd: posix.fd_t, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        off += try posix.write(fd, bytes[off..]);
    }
}

fn isGetRequest(request: []const u8) bool {
    return std.mem.startsWith(u8, request, "GET ");
}

fn isGetMetrics(request: []const u8) bool {
    if (!std.mem.startsWith(u8, request, "GET /metrics")) return false;
    if (request.len < "GET /metrics".len + 1) return false;
    const next = request["GET /metrics".len];
    return next == ' ' or next == '?' or next == '\r';
}

fn writeMetrics(writer: anytype, state: *proxy.ProxyState, process: ProcessMetrics) !void {
    const snapshot = state.getMetricsSnapshot();

    try writeMetricHeader(writer, "mtproto_build_info", "build and version metadata", "gauge");
    try writer.print("mtproto_build_info{{version=\"{s}\"}} 1\n", .{version});

    try writeGauge(writer, "mtproto_start_time_seconds", "proxy process start time", snapshot.start_time_seconds);
    try writeGauge(writer, "mtproto_uptime_seconds", "proxy process uptime", snapshot.uptime_seconds);
    try writeGauge(writer, "mtproto_connections_active", "current active client connections", snapshot.connections_active);
    try writeGauge(writer, "mtproto_connections_max", "configured maximum concurrent connections", snapshot.connections_max);
    try writeGauge(writer, "mtproto_handshakes_inflight", "current handshake budget usage", snapshot.handshakes_inflight);
    try writeCounter(writer, "mtproto_connections_accepted_total", "accepted client connections", snapshot.connections_accepted_total);
    try writeCounter(writer, "mtproto_connections_closed_total", "closed client connections", snapshot.connections_closed_total);
    try writeCounter(writer, "mtproto_connections_total", "total accepted client connections", snapshot.connections_total);
    try writeGauge(writer, "mtproto_accept_paused", "whether accepts are paused due to fd pressure", boolToInt(snapshot.accept_paused));
    try writeGauge(writer, "mtproto_saturation_paused", "whether accepts are paused due to saturation", boolToInt(snapshot.saturation_paused));
    try writeCounter(writer, "mtproto_drops_capacity_total", "connections dropped because max_connections was reached", snapshot.drops_capacity_total);
    try writeCounter(writer, "mtproto_drops_saturation_total", "accept attempts dropped due to saturation hysteresis", snapshot.drops_saturation_total);
    try writeCounter(writer, "mtproto_drops_rate_limit_total", "connections dropped by subnet rate limiter", snapshot.drops_rate_limit_total);
    try writeCounter(writer, "mtproto_drops_handshake_budget_total", "connections dropped because handshake budget was exhausted", snapshot.drops_handshake_budget_total);
    try writeCounter(writer, "mtproto_handshake_timeouts_total", "connections dropped due to handshake timeout", snapshot.handshake_timeouts_total);
    try writeCounter(writer, "mtproto_middleproxy_fallback_total", "times middleproxy fell back to direct path", snapshot.middleproxy_fallback_total);
    try writeCounter(writer, "mtproto_client_to_upstream_bytes_total", "bytes successfully written from client side toward upstream", snapshot.client_to_upstream_bytes_total);
    try writeCounter(writer, "mtproto_upstream_to_client_bytes_total", "bytes successfully written from upstream toward client side", snapshot.upstream_to_client_bytes_total);
    try writeGauge(writer, "mtproto_config_max_connections", "configured max_connections", snapshot.config_max_connections);
    try writeGauge(writer, "mtproto_config_port", "configured MTProto listen port", snapshot.config_port);
    try writeGauge(writer, "mtproto_middleproxy_enabled", "whether middleproxy mode is enabled", boolToInt(snapshot.middleproxy_enabled));
    try writeGauge(writer, "mtproto_fast_mode_enabled", "whether fast mode is enabled", boolToInt(snapshot.fast_mode_enabled));
    try writeGauge(writer, "mtproto_mask_enabled", "whether masking is enabled", boolToInt(snapshot.mask_enabled));
    try writeGauge(writer, "mtproto_desync_enabled", "whether desync is enabled", boolToInt(snapshot.desync_enabled));
    try writeGauge(writer, "mtproto_drs_enabled", "whether dynamic record sizing is enabled", boolToInt(snapshot.drs_enabled));
    try writePerUserMetrics(writer, state);

    if (process.resident_memory_bytes) |value| {
        try writeGauge(writer, "process_resident_memory_bytes", "resident set size", value);
    }
    if (process.virtual_memory_bytes) |value| {
        try writeGauge(writer, "process_virtual_memory_bytes", "virtual memory size", value);
    }
    if (process.cpu_seconds_total) |value| {
        try writeMetricHeader(writer, "process_cpu_seconds_total", "user and system CPU time", "counter");
        try writer.print("process_cpu_seconds_total {d:.6}\n", .{value});
    }
    if (process.open_fds) |value| {
        try writeGauge(writer, "process_open_fds", "open file descriptors", value);
    }
    if (process.max_fds) |value| {
        try writeGauge(writer, "process_max_fds", "maximum file descriptors", value);
    }
    if (process.cgroup_memory_usage_bytes) |value| {
        try writeGauge(writer, "mtproto_cgroup_memory_usage_bytes", "memory usage reported by cgroup", value);
    }
    if (process.cgroup_memory_limit_bytes) |value| {
        try writeGauge(writer, "mtproto_cgroup_memory_limit_bytes", "memory limit reported by cgroup", value);
    }
}

fn writeMetricHeader(writer: anytype, name: []const u8, help: []const u8, metric_type: []const u8) !void {
    try writer.print("# HELP {s} {s}\n", .{ name, help });
    try writer.print("# TYPE {s} {s}\n", .{ name, metric_type });
}

fn writePerUserMetrics(writer: anytype, state: *proxy.ProxyState) !void {
    try writeMetricHeader(writer, "mtproto_user_connections_active", "active connections by configured user", "gauge");
    for (state.user_metrics) |entry| {
        try writeLabeledMetricLine(
            writer,
            "mtproto_user_connections_active",
            entry.name,
            entry.connections_active.load(.monotonic),
        );
    }

    try writeMetricHeader(writer, "mtproto_user_client_to_upstream_bytes_total", "bytes successfully written upstream by configured user", "counter");
    for (state.user_metrics) |entry| {
        try writeLabeledMetricLine(
            writer,
            "mtproto_user_client_to_upstream_bytes_total",
            entry.name,
            entry.client_to_upstream_bytes_total.load(.monotonic),
        );
    }

    try writeMetricHeader(writer, "mtproto_user_upstream_to_client_bytes_total", "bytes successfully written to client by configured user", "counter");
    for (state.user_metrics) |entry| {
        try writeLabeledMetricLine(
            writer,
            "mtproto_user_upstream_to_client_bytes_total",
            entry.name,
            entry.upstream_to_client_bytes_total.load(.monotonic),
        );
    }
}

fn writeLabeledMetricLine(writer: anytype, metric_name: []const u8, user_name: []const u8, value: anytype) !void {
    try writer.print("{s}{{user=\"", .{metric_name});
    try writePrometheusLabelValue(writer, user_name);
    try writer.print("\"}} {d}\n", .{value});
}

fn writePrometheusLabelValue(writer: anytype, value: []const u8) !void {
    for (value) |ch| {
        switch (ch) {
            '\\' => try writer.writeAll("\\\\"),
            '"' => try writer.writeAll("\\\""),
            '\n' => try writer.writeAll("\\n"),
            else => try writer.writeByte(ch),
        }
    }
}

fn writeGauge(writer: anytype, name: []const u8, help: []const u8, value: anytype) !void {
    try writeMetricHeader(writer, name, help, "gauge");
    try writer.print("{s} {d}\n", .{ name, value });
}

fn writeCounter(writer: anytype, name: []const u8, help: []const u8, value: anytype) !void {
    try writeMetricHeader(writer, name, help, "counter");
    try writer.print("{s} {d}\n", .{ name, value });
}

fn boolToInt(value: bool) u8 {
    return if (value) 1 else 0;
}

fn collectProcessMetrics() ProcessMetrics {
    return .{
        .resident_memory_bytes = readStatusValueBytes("VmRSS:"),
        .virtual_memory_bytes = readStatusValueBytes("VmSize:"),
        .cpu_seconds_total = readCpuSecondsTotal(),
        .open_fds = countOpenFds(),
        .max_fds = readMaxFds(),
        .cgroup_memory_usage_bytes = readCgroupMemoryCurrent(),
        .cgroup_memory_limit_bytes = readCgroupMemoryLimit(),
    };
}

fn readCgroupMemoryCurrent() ?u64 {
    return readNumericFileAbsolute("/sys/fs/cgroup/memory.current") orelse
        readNumericFileAbsolute("/sys/fs/cgroup/memory/memory.usage_in_bytes");
}

fn readCgroupMemoryLimit() ?u64 {
    return readCgroupMemoryLimitFile("/sys/fs/cgroup/memory.max") orelse
        readCgroupMemoryLimitFile("/sys/fs/cgroup/memory/memory.limit_in_bytes");
}

fn readCgroupMemoryLimitFile(path: []const u8) ?u64 {
    var buf: [256]u8 = undefined;
    const text = readFileAbsolute(path, &buf) orelse return null;
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len == 0 or std.mem.eql(u8, trimmed, "max")) return null;
    return std.fmt.parseInt(u64, trimmed, 10) catch null;
}

fn readNumericFileAbsolute(path: []const u8) ?u64 {
    var buf: [256]u8 = undefined;
    const text = readFileAbsolute(path, &buf) orelse return null;
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len == 0) return null;
    return std.fmt.parseInt(u64, trimmed, 10) catch null;
}

fn readStatusValueBytes(label: []const u8) ?u64 {
    var buf: [16 * 1024]u8 = undefined;
    const text = readFileAbsolute("/proc/self/status", &buf) orelse return null;

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, label)) continue;
        var it = std.mem.tokenizeAny(u8, line[label.len..], " \t");
        const value_txt = it.next() orelse return null;
        const kib = std.fmt.parseInt(u64, value_txt, 10) catch return null;
        return kib * 1024;
    }
    return null;
}

fn readCpuSecondsTotal() ?f64 {
    var buf: [8 * 1024]u8 = undefined;
    const text = readFileAbsolute("/proc/self/stat", &buf) orelse return null;
    const close_idx = std.mem.lastIndexOfScalar(u8, text, ')') orelse return null;
    if (close_idx + 2 >= text.len) return null;

    var fields = std.mem.tokenizeScalar(u8, text[close_idx + 2 ..], ' ');
    var idx: usize = 0;
    var utime_ticks: ?u64 = null;
    var stime_ticks: ?u64 = null;
    while (fields.next()) |field| : (idx += 1) {
        if (idx == 11) {
            utime_ticks = std.fmt.parseInt(u64, field, 10) catch return null;
        } else if (idx == 12) {
            stime_ticks = std.fmt.parseInt(u64, field, 10) catch return null;
            break;
        }
    }
    if (utime_ticks == null or stime_ticks == null) return null;
    return @as(f64, @floatFromInt(utime_ticks.? + stime_ticks.?)) / 100.0;
}

fn countOpenFds() ?u64 {
    var dir = std.fs.openDirAbsolute("/proc/self/fd", .{ .iterate = true }) catch return null;
    defer dir.close();

    var it = dir.iterate();
    var count: u64 = 0;
    while (it.next() catch return null) |_| {
        count += 1;
    }
    return count;
}

fn readMaxFds() ?u64 {
    if (builtin.os.tag != .linux) return null;

    var lim: linux.rlimit = undefined;
    const rc = linux.getrlimit(.NOFILE, &lim);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(lim.cur),
        else => return null,
    }
}

fn readFileAbsolute(path: []const u8, buffer: []u8) ?[]const u8 {
    const file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();
    const len = file.readAll(buffer) catch return null;
    return buffer[0..len];
}

test "monitoring metrics output contains required metrics" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
    };
    defer cfg.deinit(std.testing.allocator);

    var state = proxy.ProxyState.init(std.testing.allocator, cfg);
    defer state.deinit();

    var buf: [16 * 1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try writeMetrics(stream.writer(), &state, .{});
    const out = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, out, "mtproto_connections_active") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "mtproto_build_info") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "mtproto_client_to_upstream_bytes_total") != null);
}

test "monitoring rejects unknown path" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
    };
    defer cfg.deinit(std.testing.allocator);

    var state = proxy.ProxyState.init(std.testing.allocator, cfg);
    defer state.deinit();

    try std.testing.expect(!isGetMetrics("GET /nope HTTP/1.1\r\nHost: localhost\r\n\r\n"));
    try std.testing.expect(isGetRequest("GET /nope HTTP/1.1\r\nHost: localhost\r\n\r\n"));
}
