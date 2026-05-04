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
