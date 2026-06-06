const std = @import("std");

const log = std.log.scoped(.proxy);

pub const ProxyKind = enum {
    socks5,
    http_connect,
};

pub const ProxyFetchOptions = struct {
    kind: ProxyKind,
    host: []const u8,
    port: u16,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
};

test "http fetch - proxy endpoint brackets IPv6 hosts" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("127.0.0.1:1080", formatProxyEndpoint("127.0.0.1", 1080, &buf));
    try std.testing.expectEqualStrings("[2001:db8::1]:1080", formatProxyEndpoint("2001:db8::1", 1080, &buf));
}

test "http fetch - curl config escaping backslash and double-quote" {
    var buf: [128]u8 = undefined;
    // Plain text is copied verbatim.
    const a = curlEscapeInto(&buf, 0, "alice").?;
    try std.testing.expectEqualStrings("alice", buf[0..a]);
    // Backslash and double-quote are backslash-escaped for curl's quoted value.
    const b = curlEscapeInto(&buf, 0, "p\"a\\ss").?;
    try std.testing.expectEqualStrings("p\\\"a\\\\ss", buf[0..b]);
    // Overflow is reported as null rather than truncating silently.
    var tiny: [1]u8 = undefined;
    try std.testing.expect(curlEscapeInto(&tiny, 0, "\"") == null);
}

pub fn fetchUrlBytes(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
    const uri = try std.Uri.parse(url);

    var client: std.http.Client = .{
        .allocator = allocator,
        .io = std.Io.Threaded.global_single_threaded.io(),
    };
    defer client.deinit();

    var req = try client.request(.GET, uri, .{
        .redirect_behavior = @enumFromInt(3),
        .keep_alive = false,
        .headers = .{
            .accept_encoding = .{ .override = "identity" },
        },
    });
    defer req.deinit();

    try req.sendBodiless();

    var redirect_buf: [8 * 1024]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);
    if (response.head.status.class() != .success) return error.HttpRequestFailed;

    var transfer_buf: [4 * 1024]u8 = undefined;
    const reader = response.reader(&transfer_buf);
    return reader.allocRemaining(allocator, .limited(1 * 1024 * 1024));
}

fn formatProxyEndpoint(host: []const u8, port: u16, out: []u8) []const u8 {
    const has_colon = std.mem.indexOfScalar(u8, host, ':') != null;
    const already_bracketed = host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']';
    if (has_colon and !already_bracketed) {
        return std.fmt.bufPrint(out, "[{s}]:{d}", .{ host, port }) catch out[0..0];
    }
    return std.fmt.bufPrint(out, "{s}:{d}", .{ host, port }) catch out[0..0];
}

/// Append `s` into `buf` starting at `start`, escaping `\` and `"` for curl's
/// double-quoted config-file value syntax. Returns the new position, or null on
/// overflow.
fn curlEscapeInto(buf: []u8, start: usize, s: []const u8) ?usize {
    var pos = start;
    for (s) |c| {
        if (c == '\\' or c == '"') {
            if (pos + 2 > buf.len) return null;
            buf[pos] = '\\';
            buf[pos + 1] = c;
            pos += 2;
        } else {
            if (pos + 1 > buf.len) return null;
            buf[pos] = c;
            pos += 1;
        }
    }
    return pos;
}

/// Write a curl config file (mode 0600) carrying the proxy URL and credentials,
/// and return its path (the caller unlinks it). Passing creds via `--config`
/// instead of `--proxy-user` keeps the password off the world-readable process
/// cmdline (/proc/<pid>/cmdline), and — unlike replacing the child environment —
/// lets curl inherit the full parent environment (PATH, CA bundle paths, locale).
fn writeCurlProxyConfig(
    io: std.Io,
    scheme: []const u8,
    endpoint: []const u8,
    username: []const u8,
    password: []const u8,
    path_buf: []u8,
    content_buf: []u8,
) ![]const u8 {
    // Unpredictable name (random suffix, not just the pid) so a local attacker
    // cannot pre-create the path to read the staged proxy-user password or symlink
    // it onto a target file. Combined with .exclusive=true (O_EXCL) below — which
    // refuses to open an existing file OR a final-component symlink — this closes
    // the CWE-377/CWE-59 insecure-temp-file window.
    var rnd_source: std.Random.IoSource = .{ .io = std.Io.Threaded.global_single_threaded.io() };
    const rnd = rnd_source.interface().int(u64);
    const path = std.fmt.bufPrint(path_buf, "/tmp/.mtproxy-curl-{d}-{x}.conf", .{ std.os.linux.getpid(), rnd }) catch
        return error.CurlConfigPathTooLong;

    const header = std.fmt.bufPrint(content_buf, "proxy = \"{s}://{s}\"\nproxy-user = \"", .{ scheme, endpoint }) catch
        return error.CurlConfigTooLong;
    var pos: usize = header.len;
    pos = curlEscapeInto(content_buf, pos, username) orelse return error.CurlConfigTooLong;
    if (pos >= content_buf.len) return error.CurlConfigTooLong;
    content_buf[pos] = ':';
    pos += 1;
    pos = curlEscapeInto(content_buf, pos, password) orelse return error.CurlConfigTooLong;
    if (pos + 2 > content_buf.len) return error.CurlConfigTooLong;
    content_buf[pos] = '"';
    content_buf[pos + 1] = '\n';
    pos += 2;

    var file = std.Io.Dir.createFileAbsolute(io, path, .{
        .permissions = std.Io.File.Permissions.fromMode(0o600),
        .exclusive = true,
    }) catch return error.CurlConfigWriteFailed;
    defer file.close(io);
    file.writeStreamingAll(io, content_buf[0..pos]) catch return error.CurlConfigWriteFailed;
    return path;
}

pub fn fetchUrlBytesViaProxy(
    allocator: std.mem.Allocator,
    url: []const u8,
    opts: ProxyFetchOptions,
) ![]u8 {
    var endpoint_buf: [512]u8 = undefined;
    const endpoint = formatProxyEndpoint(opts.host, opts.port, &endpoint_buf);
    if (endpoint.len == 0) return error.InvalidProxyEndpoint;

    const has_creds = (opts.username != null and opts.username.?.len > 0) or
        (opts.password != null and opts.password.?.len > 0);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);

    try argv.appendSlice(allocator, &.{
        "curl",
        "--silent",
        "--fail",
        "--show-error",
        "--location",
        "--max-time",
        "10",
    });

    var io_instance: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer io_instance.deinit();
    const io = io_instance.io();

    // When the upstream proxy needs credentials, pass them via a 0600 curl
    // config file (--config) instead of `--proxy-user` on argv, so the password
    // never appears on the world-readable process cmdline (CWE-214). curl keeps
    // its full inherited environment (PATH, CA paths, locale). The config-file
    // path itself is not secret.
    var cfg_path_buf: [64]u8 = undefined;
    var cfg_content_buf: [1024]u8 = undefined;
    var cfg_path: ?[]const u8 = null;
    defer if (cfg_path) |p| std.Io.Dir.deleteFileAbsolute(io, p) catch {};

    var proxy_url_buf: [640]u8 = undefined;
    if (has_creds) {
        const scheme = switch (opts.kind) {
            .socks5 => "socks5h",
            .http_connect => "http",
        };
        cfg_path = writeCurlProxyConfig(
            io,
            scheme,
            endpoint,
            opts.username orelse "",
            opts.password orelse "",
            &cfg_path_buf,
            &cfg_content_buf,
        ) catch |err| {
            log.warn("failed to stage curl proxy config: {any}", .{err});
            return error.UnexpectedConnectFailure;
        };
        try argv.appendSlice(allocator, &.{ "--config", cfg_path.? });
    } else {
        const proxy_url = switch (opts.kind) {
            .socks5 => endpoint,
            .http_connect => std.fmt.bufPrint(&proxy_url_buf, "http://{s}", .{endpoint}) catch return error.InvalidProxyEndpoint,
        };
        switch (opts.kind) {
            .socks5 => try argv.appendSlice(allocator, &.{ "--socks5-hostname", proxy_url }),
            .http_connect => try argv.appendSlice(allocator, &.{ "--proxy", proxy_url }),
        }
    }
    try argv.append(allocator, url);

    const result = std.process.run(allocator, io, .{
        .argv = argv.items,
        .stdout_limit = std.Io.Limit.limited(1 * 1024 * 1024),
        .stderr_limit = std.Io.Limit.limited(1 * 1024 * 1024),
    }) catch |err| {
        log.warn("curl proxy fetch failed to spawn: {any}", .{err});
        return error.UnexpectedConnectFailure;
    };
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                log.warn("curl {s} via configured proxy exited with {d}: {s}", .{
                    url,
                    code,
                    std.mem.trim(u8, result.stderr, " \t\r\n"),
                });
                allocator.free(result.stdout);
                return error.UnexpectedConnectFailure;
            }
        },
        else => {
            log.warn("curl {s} via configured proxy terminated abnormally", .{url});
            allocator.free(result.stdout);
            return error.UnexpectedConnectFailure;
        },
    }

    return result.stdout;
}

/// Fetch a URL by shelling out to `curl`, binding the outgoing socket to the
/// given network interface. This is the censorship-aware refresh path: when
/// the proxy host sits in a network where `core.telegram.org` is unreachable
/// over the default route, but the tunnel interface (e.g. AWG) provides a
/// clean path, we use curl as an off-the-shelf HTTPS client without pulling
/// a full TLS stack into the proxy binary.
pub fn fetchUrlBytesViaInterface(
    allocator: std.mem.Allocator,
    url: []const u8,
    interface: []const u8,
) ![]u8 {
    // curl requires --interface and its value as separate argv elements; the
    // `--interface=<iface>` form is a common shell idiom but not supported by
    // every curl version, hence the split.
    const argv = [_][]const u8{
        "curl",
        "--silent",
        "--fail",
        "--show-error",
        "--location",
        "--max-time",
        "10",
        "--interface",
        interface,
        url,
    };

    var io_instance: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer io_instance.deinit();

    const result = std.process.run(allocator, io_instance.io(), .{
        .argv = &argv,
        .stdout_limit = std.Io.Limit.limited(1 * 1024 * 1024),
        .stderr_limit = std.Io.Limit.limited(1 * 1024 * 1024),
    }) catch |err| {
        log.warn("curl fallback failed to spawn: {any}", .{err});
        return error.UnexpectedConnectFailure;
    };
    // Free stderr regardless of outcome; stdout is returned to the caller.
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                log.warn("curl {s} via {s} exited with {d}: {s}", .{
                    url,                                        interface, code,
                    std.mem.trim(u8, result.stderr, " \t\r\n"),
                });
                allocator.free(result.stdout);
                return error.UnexpectedConnectFailure;
            }
        },
        else => {
            log.warn("curl {s} via {s} terminated abnormally", .{ url, interface });
            allocator.free(result.stdout);
            return error.UnexpectedConnectFailure;
        },
    }

    return result.stdout;
}
