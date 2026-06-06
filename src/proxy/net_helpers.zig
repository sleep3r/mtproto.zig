const std = @import("std");
const net = std.Io.net;

pub const Address = net.IpAddress;

pub const AddressList = struct {
    allocator: std.mem.Allocator,
    addrs: []Address,

    pub fn deinit(self: *const AddressList) void {
        self.allocator.free(self.addrs);
    }
};

pub fn ip4(bytes: [4]u8, port: u16) Address {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}

pub fn ip6(bytes: [16]u8, port: u16, flow: u32, scope_id: u32) Address {
    return .{ .ip6 = .{
        .bytes = bytes,
        .port = port,
        .flow = flow,
        .interface = .{ .index = scope_id },
    } };
}

pub fn isIpv6(addr: Address) bool {
    return switch (addr) {
        .ip6 => true,
        .ip4 => false,
    };
}

pub fn addressEql(a: Address, b: Address) bool {
    return net.IpAddress.eql(&a, &b);
}

pub fn getAddressList(allocator: std.mem.Allocator, host: []const u8, port: u16) !AddressList {
    if (net.IpAddress.parse(host, port)) |literal| {
        const addrs = try allocator.alloc(Address, 1);
        addrs[0] = literal;
        return .{ .allocator = allocator, .addrs = addrs };
    } else |_| {}

    // Try the std resolver first; if it fails (notably error.ResolvConfParseFailed,
    // which std raises on a /etc/resolv.conf whose last line has no trailing
    // newline — as SolusVM and several VPS images generate), fall back to the
    // system NSS resolver via `getent`, which tolerates such files. Without this,
    // the proxy can resolve IP literals but no hostnames (mask_target, upstream
    // proxy host), so real-domain fronting silently breaks.
    return lookupViaStd(allocator, host, port) catch
        lookupViaGetent(allocator, host, port);
}

fn lookupViaStd(allocator: std.mem.Allocator, host: []const u8, port: u16) !AddressList {
    const host_name = try net.HostName.init(host);
    const io_ctx = std.Io.Threaded.global_single_threaded.io();

    var results_buf: [32]net.HostName.LookupResult = undefined;
    var results: std.Io.Queue(net.HostName.LookupResult) = .init(&results_buf);

    try host_name.lookup(io_ctx, &results, .{ .port = port });

    var addrs: std.ArrayList(Address) = .empty;
    defer addrs.deinit(allocator);

    while (results.getOneUncancelable(io_ctx)) |entry| {
        switch (entry) {
            .address => |addr| try addrs.append(allocator, addr),
            .canonical_name => {},
        }
    } else |err| switch (err) {
        error.Closed => {},
    }

    if (addrs.items.len == 0) return error.NoAddressReturned;
    return .{
        .allocator = allocator,
        .addrs = try addrs.toOwnedSlice(allocator),
    };
}

fn lookupViaGetent(allocator: std.mem.Allocator, host: []const u8, port: u16) !AddressList {
    // Only resolve plain hostnames (no shell metacharacters); host comes from
    // config (mask_target / upstream proxy host), but stay defensive.
    for (host) |c| {
        const ok = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or c == '.' or c == '-' or c == '_';
        if (!ok) return error.ResolveFailed;
    }

    var io_instance: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer io_instance.deinit();

    const result = std.process.run(allocator, io_instance.io(), .{
        .argv = &.{ "getent", "ahosts", host },
        .stdout_limit = std.Io.Limit.limited(64 * 1024),
        .stderr_limit = std.Io.Limit.limited(4 * 1024),
    }) catch return error.ResolveFailed;
    defer allocator.free(result.stderr);
    defer allocator.free(result.stdout);
    switch (result.term) {
        .exited => |code| if (code != 0) return error.ResolveFailed,
        else => return error.ResolveFailed,
    }
    return parseGetentAhosts(allocator, result.stdout, port);
}

/// Parse `getent ahosts <host>` output (lines of "<ip>  <socktype> [name]") into a
/// deduplicated AddressList. Pure + testable.
fn parseGetentAhosts(allocator: std.mem.Allocator, stdout: []const u8, port: u16) !AddressList {
    var addrs: std.ArrayList(Address) = .empty;
    defer addrs.deinit(allocator);

    var lines = std.mem.tokenizeAny(u8, stdout, "\r\n");
    while (lines.next()) |line| {
        var toks = std.mem.tokenizeAny(u8, line, " \t");
        const ip_tok = toks.next() orelse continue;
        const addr = net.IpAddress.parse(ip_tok, port) catch continue;
        var dup = false;
        for (addrs.items) |a| {
            if (net.IpAddress.eql(&a, &addr)) {
                dup = true;
                break;
            }
        }
        if (!dup) try addrs.append(allocator, addr);
    }

    if (addrs.items.len == 0) return error.NoAddressReturned;
    return .{ .allocator = allocator, .addrs = try addrs.toOwnedSlice(allocator) };
}

test "parseGetentAhosts dedupes ip/socktype lines" {
    const sample =
        "178.218.46.1    STREAM wb.ru\n" ++
        "178.218.46.1    DGRAM \n" ++
        "178.218.46.1    RAW \n" ++
        "2a00:1148:1::1  STREAM\n";
    const list = try parseGetentAhosts(std.testing.allocator, sample, 443);
    defer list.deinit();
    try std.testing.expectEqual(@as(usize, 2), list.addrs.len); // one v4 + one v6, deduped
    try std.testing.expect(!isIpv6(list.addrs[0]));
    try std.testing.expect(isIpv6(list.addrs[1]));
    // No trailing newline on the last line must still parse.
    const no_nl = "8.8.8.8 STREAM dns\n1.1.1.1 STREAM dns";
    const l2 = try parseGetentAhosts(std.testing.allocator, no_nl, 53);
    defer l2.deinit();
    try std.testing.expectEqual(@as(usize, 2), l2.addrs.len);
}
