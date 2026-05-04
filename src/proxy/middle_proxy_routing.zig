const std = @import("std");
const posix = std.posix;
const net = std.Io.net;
const Address = net.IpAddress;

const constants = @import("../protocol/constants.zig");
const Config = @import("../config.zig").Config;

pub const DcConnectPlan = struct {
    candidates: [16]Address = undefined,
    count: usize = 0,
    use_middle_proxy: bool = false,
    is_media_path: bool = false,
    direct_fallback: ?Address = null,
};

pub const MiddleProxySnapshot = struct {
    addrs_primary: [5]Address,
    addrs_media_primary: [5]Address,
    addr_203: Address,
    addrs_dc4: [16]Address,
    addrs_dc4_len: usize,
    addrs_media_dc4: [16]Address,
    addrs_media_dc4_len: usize,
    addrs_203: [8]Address,
    addrs_203_len: usize,
    secret: [256]u8,
    secret_len: usize,

    /// Pick the single primary endpoint for (dc_abs, media?). Media-path
    /// traffic (client sent dc_idx<0) must go to the media MP fleet.
    pub fn getForDc(self: *const MiddleProxySnapshot, dc_abs: usize, media: bool) ?Address {
        if (dc_abs == 203) return self.addr_203;
        if (dc_abs >= 1 and dc_abs <= self.addrs_primary.len) {
            if (media) return self.addrs_media_primary[dc_abs - 1];
            return self.addrs_primary[dc_abs - 1];
        }
        return null;
    }
};

pub const DcSignFilter = enum {
    any, // accept proxy_for with dc == target_dc (any sign) — legacy
    positive_only, // only `proxy_for  N  addr;` — regular traffic
    negative_only, // only `proxy_for -N  addr;` — media traffic (dc_idx < 0)
};

fn addressEql(a: Address, b: Address) bool {
    return net.IpAddress.eql(&a, &b);
}

fn isSameIpEndpoint(a: Address, b: Address) bool {
    return addressEql(a, b);
}

fn appendUniqueAddress(addrs: *[16]Address, count: *usize, addr: Address) void {
    if (count.* >= addrs.len) return;
    for (addrs[0..count.*]) |existing| {
        if (isSameIpEndpoint(existing, addr)) return;
    }
    addrs[count.*] = addr;
    count.* += 1;
}

pub fn buildDcConnectPlan(
    cfg: *const Config,
    dc_abs: usize,
    dc_idx: i16,
    snapshot: ?*const MiddleProxySnapshot,
    user_name: []const u8,
) DcConnectPlan {
    var plan = DcConnectPlan{};
    plan.is_media_path = (dc_idx < 0) or (dc_abs == 203);

    if (cfg.datacenter_override) |override| {
        plan.candidates[0] = override;
        plan.count = 1;
        plan.use_middle_proxy = false;
        plan.direct_fallback = null;
        return plan;
    }

    if (cfg.userBypassesMiddleProxy(user_name)) {
        plan.candidates[0] = constants.getDcAddressV4(dc_abs);
        plan.count = 1;
        plan.use_middle_proxy = false;
        plan.direct_fallback = null;
        return plan;
    }

    var middle_addr: ?Address = null;
    if (snapshot) |snap| {
        middle_addr = snap.getForDc(dc_abs, plan.is_media_path);
        if (middle_addr == null and plan.is_media_path) {
            // Media pool is empty in this snapshot (e.g. first run, refresh
            // hasn't succeeded yet and bundled media list is mis-seeded).
            // Fall back to the regular MP — connections still complete, just
            // without media-optimized routing.
            middle_addr = snap.getForDc(dc_abs, false);
        }
    }

    const force_media_middle_proxy = cfg.force_media_middle_proxy and plan.is_media_path and middle_addr != null;
    plan.use_middle_proxy = if (force_media_middle_proxy)
        true
    else
        cfg.use_middle_proxy and middle_addr != null;

    if (!plan.use_middle_proxy) {
        plan.candidates[0] = constants.getDcAddressV4(dc_abs);
        plan.count = 1;
        plan.direct_fallback = null;
        return plan;
    }

    if (snapshot) |snap| {
        if (dc_abs == 4) {
            if (plan.is_media_path and snap.addrs_media_dc4_len > 0) {
                var n: usize = 0;
                while (n < snap.addrs_media_dc4_len and plan.count < plan.candidates.len) : (n += 1) {
                    appendUniqueAddress(&plan.candidates, &plan.count, snap.addrs_media_dc4[n]);
                }
            } else if (snap.addrs_dc4_len > 0) {
                var n: usize = 0;
                while (n < snap.addrs_dc4_len and plan.count < plan.candidates.len) : (n += 1) {
                    appendUniqueAddress(&plan.candidates, &plan.count, snap.addrs_dc4[n]);
                }
            }
        } else if (dc_abs == 203 and snap.addrs_203_len > 0) {
            var n: usize = 0;
            while (n < snap.addrs_203_len and plan.count < plan.candidates.len) : (n += 1) {
                appendUniqueAddress(&plan.candidates, &plan.count, snap.addrs_203[n]);
            }
        }
    }

    if (plan.count == 0 and middle_addr != null) {
        appendUniqueAddress(&plan.candidates, &plan.count, middle_addr.?);
    }

    if (plan.count == 0) {
        // Safety fallback: if cache has no middle-proxy endpoint for this DC,
        // avoid dropping valid users and go direct.
        plan.use_middle_proxy = false;
        plan.candidates[0] = constants.getDcAddressV4(dc_abs);
        plan.count = 1;
        plan.direct_fallback = null;
        return plan;
    }

    // If middle-proxy connect/handshake fails, retry the same DC via direct mode.
    // This keeps media paths functional in environments where middle-proxy transport
    // itself is degraded (for example due to strict NAT behavior in upstream tunnels).
    plan.direct_fallback = constants.getDcAddressV4(dc_abs);
    return plan;
}

fn parseIpAndPortAddress(text: []const u8) !Address {
    return net.IpAddress.parseLiteral(text);
}

pub fn parseMiddleProxyAddressesForDc(
    config_text: []const u8,
    target_dc: i16,
    sign: DcSignFilter,
    out: []Address,
) usize {
    if (out.len == 0) return 0;

    var lines = std.mem.splitScalar(u8, config_text, '\n');
    var count: usize = 0;

    while (lines.next()) |raw_line| {
        var line = std.mem.trim(u8, raw_line, &[_]u8{ ' ', '\t', '\r' });
        if (line.len == 0 or line[0] == '#') continue;
        if (line[line.len - 1] == ';') line = line[0 .. line.len - 1];

        var parts = std.mem.tokenizeAny(u8, line, " \t");
        const keyword = parts.next() orelse continue;
        if (!std.mem.eql(u8, keyword, "proxy_for")) continue;

        const dc_text = parts.next() orelse continue;
        const host_port = parts.next() orelse continue;

        const dc_idx = std.fmt.parseInt(i16, dc_text, 10) catch continue;
        const abs_target: i16 = if (target_dc < 0) -target_dc else target_dc;
        switch (sign) {
            .any => if (dc_idx != abs_target and dc_idx != -abs_target) continue,
            .positive_only => if (dc_idx != abs_target) continue,
            .negative_only => if (dc_idx != -abs_target) continue,
        }

        const parsed = parseIpAndPortAddress(host_port) catch continue;

        var dup = false;
        for (out[0..count]) |existing| {
            if (addressEql(existing, parsed)) {
                dup = true;
                break;
            }
        }
        if (dup) continue;

        out[count] = parsed;
        count += 1;
        if (count == out.len) break;
    }

    return count;
}

pub fn parseMiddleProxyAddressForDc(config_text: []const u8, target_dc: i16) ?Address {
    var one: [1]Address = undefined;
    const sign: DcSignFilter = if (target_dc < 0) .negative_only else .positive_only;
    const n = parseMiddleProxyAddressesForDc(config_text, target_dc, sign, &one);
    if (n == 0) return null;
    return one[0];
}

pub fn trySelectReachableMiddleProxy(candidates: []const Address, timeout_ms: i32) ?Address {
    for (candidates) |addr| {
        if (isAddressReachable(addr, timeout_ms)) return addr;
    }
    return null;
}

pub fn addressesEqual(a: []const Address, b: []const Address) bool {
    if (a.len != b.len) return false;
    for (a, b) |lhs, rhs| {
        if (!addressEql(lhs, rhs)) return false;
    }
    return true;
}

fn closeFd(fd: posix.fd_t) void {
    while (true) {
        switch (posix.errno(posix.system.close(fd))) {
            .SUCCESS => return,
            .INTR => continue,
            else => return,
        }
    }
}

fn connectSockaddr(fd: posix.fd_t, addr: *const posix.sockaddr, addr_len: posix.socklen_t) !void {
    while (true) switch (posix.errno(posix.system.connect(fd, addr, addr_len))) {
        .SUCCESS => return,
        .INTR => continue,
        .ADDRNOTAVAIL => return error.AddressUnavailable,
        .AFNOSUPPORT => return error.AddressFamilyUnsupported,
        .AGAIN, .INPROGRESS => return error.WouldBlock,
        .ALREADY => return error.ConnectionPending,
        .CONNREFUSED => return error.ConnectionRefused,
        .CONNRESET => return error.ConnectionResetByPeer,
        .HOSTUNREACH => return error.HostUnreachable,
        .NETUNREACH => return error.NetworkUnreachable,
        .TIMEDOUT => return error.Timeout,
        else => |err| return posix.unexpectedErrno(err),
    };
}

fn isAddressReachable(address: Address, timeout_ms: i32) bool {
    const sock_flags = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
    const family: posix.sa_family_t = switch (address) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
    const fd = fd: {
        const rc = posix.system.socket(family, sock_flags, posix.IPPROTO.TCP);
        if (posix.errno(rc) != .SUCCESS) return false;
        break :fd @as(posix.fd_t, @intCast(rc));
    };
    defer closeFd(fd);

    switch (address) {
        .ip4 => |ip4_addr| {
            var sa: posix.sockaddr.in = .{
                .family = posix.AF.INET,
                .port = std.mem.nativeToBig(u16, ip4_addr.port),
                .addr = @bitCast(ip4_addr.bytes),
            };
            connectSockaddr(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in)) catch |err| switch (err) {
                error.WouldBlock, error.ConnectionPending => {},
                else => return false,
            };
        },
        .ip6 => |ip6_addr| {
            var sa: posix.sockaddr.in6 = .{
                .family = posix.AF.INET6,
                .port = std.mem.nativeToBig(u16, ip6_addr.port),
                .flowinfo = ip6_addr.flow,
                .addr = ip6_addr.bytes,
                .scope_id = ip6_addr.interface.index,
            };
            connectSockaddr(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in6)) catch |err| switch (err) {
                error.WouldBlock, error.ConnectionPending => {},
                else => return false,
            };
        },
    }

    var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
    const ready = posix.poll(&fds, timeout_ms) catch return false;
    if (ready == 0) return false;
    const revents = fds[0].revents;
    if ((revents & posix.POLL.OUT) == 0) return false;
    if ((revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL)) != 0) return false;
    return true;
}

test "parse middle proxy address for dc203" {
    const cfg =
        "# force_probability 10 10\n" ++
        "default 2;\n" ++
        "proxy_for 1 149.154.175.50:8888;\n" ++
        "proxy_for 203 91.105.192.110:443;\n" ++
        "proxy_for -203 91.105.192.110:443;\n";

    const addr = parseMiddleProxyAddressForDc(cfg, 203) orelse return error.TestExpectedEqual;
    try std.testing.expect(switch (addr) {
        .ip4 => true,
        .ip6 => false,
    });
    try std.testing.expectEqual(@as(u16, 443), addr.getPort());
}

test "direct users bypass middle-proxy routing" {
    const cfg_text =
        \\[general]
        \\use_middle_proxy = true
        \\[access.users]
        \\admin = "00112233445566778899aabbccddeeff"
        \\regular = "ffeeddccbbaa99887766554433221100"
        \\[access.direct_users]
        \\admin = true
    ;

    var cfg = try Config.parse(std.testing.allocator, cfg_text);
    defer cfg.deinit(std.testing.allocator);

    const mp_dc4: Address = .{ .ip4 = .{ .bytes = .{ 11, 11, 11, 11 }, .port = 443 } };
    const mp_dc203: Address = .{ .ip4 = .{ .bytes = .{ 12, 12, 12, 12 }, .port = 443 } };
    const snapshot = MiddleProxySnapshot{
        .addrs_primary = .{
            constants.tg_middle_proxies_v4[0],
            constants.tg_middle_proxies_v4[1],
            constants.tg_middle_proxies_v4[2],
            mp_dc4,
            constants.tg_middle_proxies_v4[4],
        },
        .addrs_media_primary = constants.tg_media_middle_proxies_v4,
        .addr_203 = mp_dc203,
        .addrs_dc4 = [_]Address{mp_dc4} ++ ([_]Address{mp_dc4} ** 15),
        .addrs_dc4_len = 1,
        .addrs_media_dc4 = [_]Address{constants.tg_media_middle_proxies_v4[3]} ++ ([_]Address{constants.tg_media_middle_proxies_v4[3]} ** 15),
        .addrs_media_dc4_len = 1,
        .addrs_203 = [_]Address{mp_dc203} ++ ([_]Address{mp_dc203} ** 7),
        .addrs_203_len = 1,
        .secret = [_]u8{0} ** 256,
        .secret_len = 16,
    };

    const regular_plan = buildDcConnectPlan(&cfg, 4, 4, &snapshot, "regular");
    try std.testing.expect(regular_plan.use_middle_proxy);
    try std.testing.expect(regular_plan.direct_fallback != null);
    try std.testing.expect(addressEql(regular_plan.candidates[0], mp_dc4));

    const admin_plan = buildDcConnectPlan(&cfg, 4, 4, &snapshot, "admin");
    try std.testing.expect(!admin_plan.use_middle_proxy);
    try std.testing.expect(admin_plan.direct_fallback == null);
    try std.testing.expect(addressEql(admin_plan.candidates[0], constants.getDcAddressV4(4)));

    const regular_media = buildDcConnectPlan(&cfg, 203, -203, &snapshot, "regular");
    try std.testing.expect(regular_media.use_middle_proxy);
    try std.testing.expect(addressEql(regular_media.candidates[0], mp_dc203));

    const admin_media = buildDcConnectPlan(&cfg, 203, -203, &snapshot, "admin");
    try std.testing.expect(!admin_media.use_middle_proxy);
    try std.testing.expect(addressEql(admin_media.candidates[0], constants.getDcAddressV4(203)));
}
