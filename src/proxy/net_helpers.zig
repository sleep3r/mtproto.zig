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

/// Bounded DNS snapshot, copied for the lifetime of a connect attempt.
pub const AddressCandidates = struct {
    addresses: [16]Address = undefined,
    len: u8 = 0,

    pub fn init(addresses: []const Address) AddressCandidates {
        var self: AddressCandidates = .{};
        self.len = @intCast(@min(addresses.len, self.addresses.len));
        @memcpy(self.addresses[0..self.len], addresses[0..self.len]);
        return self;
    }

    pub fn slice(self: *const AddressCandidates) []const Address {
        return self.addresses[0..self.len];
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

/// Linux listener with explicit dual-stack and worker-sharing policy.
pub fn listen(addr: Address, backlog: u31, reuse_port: bool) !std.Io.net.Server {
    const posix = std.posix;
    const family: u32 = if (isIpv6(addr)) posix.AF.INET6 else posix.AF.INET;
    const rc = posix.system.socket(family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP);
    const fd: posix.fd_t = switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .AFNOSUPPORT => return error.AddressFamilyUnsupported,
        else => |err| return posix.unexpectedErrno(err),
    };
    errdefer _ = posix.system.close(fd);
    const on: c_int = 1;
    const off: c_int = 0;
    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&on));
    if (reuse_port) try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, std.mem.asBytes(&on));
    if (isIpv6(addr)) try posix.setsockopt(fd, posix.IPPROTO.IPV6, std.os.linux.IPV6.V6ONLY, std.mem.asBytes(&off));
    const bind_rc = switch (addr) {
        .ip4 => |a| blk: {
            var sa = posix.sockaddr.in{ .family = posix.AF.INET, .port = std.mem.nativeToBig(u16, a.port), .addr = @bitCast(a.bytes), .zero = [_]u8{0} ** 8 };
            break :blk posix.system.bind(fd, @ptrCast(&sa), @sizeOf(@TypeOf(sa)));
        },
        .ip6 => |a| blk: {
            var sa = posix.sockaddr.in6{ .family = posix.AF.INET6, .port = std.mem.nativeToBig(u16, a.port), .flowinfo = a.flow, .addr = a.bytes, .scope_id = a.interface.index };
            break :blk posix.system.bind(fd, @ptrCast(&sa), @sizeOf(@TypeOf(sa)));
        },
    };
    switch (posix.errno(bind_rc)) {
        .SUCCESS => {},
        .ADDRINUSE => return error.AddressInUse,
        else => |err| return posix.unexpectedErrno(err),
    }
    switch (posix.errno(posix.system.listen(fd, backlog))) {
        .SUCCESS => {},
        else => |err| return posix.unexpectedErrno(err),
    }
    return .{ .socket = .{ .handle = fd, .address = addr }, .options = {} };
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
    const resolved = lookupViaStd(allocator, host, port) catch |err| blk: {
        if (err == error.ResolvConfParseFailed or err == error.DetectingNetworkConfigurationFailed)
            break :blk try lookupViaGetent(allocator, host, port);
        return err;
    };
    // Stable IPv4-first order across native DNS and NSS/getent. Preserve order
    // within each family rather than depending on the resolver implementation.
    preferIpv4(resolved.addrs);
    return resolved;
}

fn preferIpv4(addresses: []Address) void {
    std.mem.sort(Address, addresses, {}, struct {
        fn less(_: void, a: Address, b: Address) bool {
            return a == .ip4 and b == .ip6;
        }
    }.less);
}

const LookupProducer = struct {
    host: net.HostName,
    io: std.Io,
    results: *std.Io.Queue(net.HostName.LookupResult),
    port: u16,
    failure: ?anyerror = null,
    fn run(self: *LookupProducer) void {
        self.host.lookup(self.io, self.results, .{ .port = self.port }) catch |err| {
            self.failure = err;
        };
    }
};

fn lookupViaStd(allocator: std.mem.Allocator, host: []const u8, port: u16) !AddressList {
    const host_name = try net.HostName.init(host);
    const io_ctx = std.Io.Threaded.global_single_threaded.io();

    var results_buf: [32]net.HostName.LookupResult = undefined;
    var results: std.Io.Queue(net.HostName.LookupResult) = .init(&results_buf);

    var producer: LookupProducer = .{ .host = host_name, .io = io_ctx, .results = &results, .port = port };
    const thread = try std.Thread.spawn(.{}, LookupProducer.run, .{&producer});

    const drained = drainLookupResults(allocator, &results, io_ctx);
    // Draining is complete even when allocation failed; joining cannot deadlock
    // against a producer suspended on a full queue.
    thread.join();
    const addrs = try drained;
    errdefer addrs.deinit();
    if (producer.failure) |err| return err;
    return addrs;
}

fn drainLookupResults(allocator: std.mem.Allocator, results: *std.Io.Queue(net.HostName.LookupResult), io_ctx: std.Io) !AddressList {
    var addrs: std.ArrayList(Address) = .empty;
    defer addrs.deinit(allocator);
    var allocation_failed = false;

    while (results.getOneUncancelable(io_ctx)) |entry| {
        switch (entry) {
            .address => |addr| if (!allocation_failed) {
                addrs.append(allocator, addr) catch {
                    allocation_failed = true;
                };
            },
            .canonical_name => {},
        }
    } else |err| switch (err) {
        error.Closed => {},
    }
    if (allocation_failed) return error.OutOfMemory;

    if (addrs.items.len == 0) return error.NoAddressReturned;
    return .{
        .allocator = allocator,
        .addrs = try addrs.toOwnedSlice(allocator),
    };
}

pub fn lookupViaGetent(allocator: std.mem.Allocator, host: []const u8, port: u16) !AddressList {
    // Only resolve plain hostnames (no shell metacharacters); host comes from
    // config (mask_target / upstream proxy host), but stay defensive.
    for (host) |c| {
        const ok = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or c == '.' or c == '-' or c == '_';
        if (!ok) return error.ResolveFailed;
    }

    var io_instance: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer io_instance.deinit();

    const result = @import("child_process").run(allocator, io_instance.io(), .{
        .argv = &.{ "getent", "ahosts", "--", host },
        .timeout = .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } },
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

const SyntheticLookupProducer = struct {
    fn run(results: *std.Io.Queue(net.HostName.LookupResult), io_ctx: std.Io) void {
        defer results.close(io_ctx);
        for (0..97) |i| results.putOneUncancelable(io_ctx, .{ .address = ip4(.{ 192, 0, 2, @intCast(i) }, 443) }) catch return;
    }
};

test "DNS queue drains more answers than its fixed capacity" {
    const io_ctx = std.Io.Threaded.global_single_threaded.io();
    var storage: [32]net.HostName.LookupResult = undefined;
    var queue: std.Io.Queue(net.HostName.LookupResult) = .init(&storage);
    const producer = try std.Thread.spawn(.{}, SyntheticLookupProducer.run, .{ &queue, io_ctx });
    const result = drainLookupResults(std.testing.allocator, &queue, io_ctx);
    producer.join();
    const list = try result;
    defer list.deinit();
    try std.testing.expectEqual(@as(usize, 97), list.addrs.len);
    for (list.addrs, 0..) |addr, i| try std.testing.expect(addressEql(addr, ip4(.{ 192, 0, 2, @intCast(i) }, 443)));
}

test "DNS queue still drains its producer after allocation failure" {
    const io_ctx = std.Io.Threaded.global_single_threaded.io();
    var storage: [32]net.HostName.LookupResult = undefined;
    var queue: std.Io.Queue(net.HostName.LookupResult) = .init(&storage);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const producer = try std.Thread.spawn(.{}, SyntheticLookupProducer.run, .{ &queue, io_ctx });
    const result = drainLookupResults(failing.allocator(), &queue, io_ctx);
    producer.join();
    try std.testing.expectError(error.OutOfMemory, result);
}

test "DNS ordering is IPv4 first and stable within each family" {
    const a = ip4(.{ 192, 0, 2, 1 }, 443);
    const b = ip4(.{ 192, 0, 2, 2 }, 443);
    const c = ip6(@splat(1), 443, 0, 0);
    const d = ip6(@splat(2), 443, 0, 0);
    var addresses = [_]Address{ c, a, d, b };
    preferIpv4(&addresses);
    for (addresses, [_]Address{ a, b, c, d }) |actual, expected| try std.testing.expect(addressEql(actual, expected));
}

test "startup address snapshots bound retained answers to sixteen" {
    const addresses = [_]Address{ip4(.{ 192, 0, 2, 1 }, 443)} ** 97;
    const candidates = AddressCandidates.init(&addresses);
    try std.testing.expectEqual(@as(usize, 16), candidates.slice().len);
}
