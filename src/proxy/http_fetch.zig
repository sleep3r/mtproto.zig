const std = @import("std");

const log = std.log.scoped(.proxy);

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
