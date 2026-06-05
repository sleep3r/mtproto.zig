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

test "http fetch - userinfo percent-encoding escapes URL-reserved characters" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("alice", percentEncodeUserinfo("alice", &buf));
    // ':' '@' '/' and space must be encoded so they don't corrupt the proxy URL.
    try std.testing.expectEqualStrings("p%40ss%3Aw%2Frd%20", percentEncodeUserinfo("p@ss:w/rd ", &buf));
    try std.testing.expectEqualStrings("", percentEncodeUserinfo("", &buf));
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

/// Percent-encode a URL userinfo subcomponent (RFC 3986 unreserved set kept
/// literal, everything else %XX-encoded) so credentials can be safely embedded
/// in a proxy URL without ':'/'@'/'/' corrupting the parse.
fn percentEncodeUserinfo(s: []const u8, out: []u8) []const u8 {
    const hex = "0123456789ABCDEF";
    var pos: usize = 0;
    for (s) |c| {
        const unreserved = (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or c == '-' or c == '_' or c == '.' or c == '~';
        if (unreserved) {
            if (pos >= out.len) break;
            out[pos] = c;
            pos += 1;
        } else {
            if (pos + 3 > out.len) break;
            out[pos] = '%';
            out[pos + 1] = hex[c >> 4];
            out[pos + 2] = hex[c & 0x0F];
            pos += 3;
        }
    }
    return out[0..pos];
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

    // When the upstream proxy needs credentials, pass the whole proxy URL (with
    // the percent-encoded user:pass embedded) through the ALL_PROXY environment
    // variable instead of `--proxy-user` on argv. /proc/<pid>/environ is 0400
    // (owner/root only) whereas /proc/<pid>/cmdline is world-readable, so this
    // keeps the upstream proxy password out of `ps`/cmdline (CWE-214).
    var env_map = std.process.Environ.Map.init(allocator);
    defer env_map.deinit();
    var all_proxy_buf: [1100]u8 = undefined;
    var proxy_url_buf: [640]u8 = undefined;

    if (has_creds) {
        var user_buf: [320]u8 = undefined;
        var pass_buf: [320]u8 = undefined;
        const enc_user = percentEncodeUserinfo(opts.username orelse "", &user_buf);
        const enc_pass = percentEncodeUserinfo(opts.password orelse "", &pass_buf);
        const scheme = switch (opts.kind) {
            .socks5 => "socks5h",
            .http_connect => "http",
        };
        const all_proxy = std.fmt.bufPrint(&all_proxy_buf, "{s}://{s}:{s}@{s}", .{
            scheme, enc_user, enc_pass, endpoint,
        }) catch return error.InvalidProxyEndpoint;
        try env_map.put("ALL_PROXY", all_proxy);
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

    var io_instance: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer io_instance.deinit();

    const result = std.process.run(allocator, io_instance.io(), .{
        .argv = argv.items,
        .environ_map = if (has_creds) &env_map else null,
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
