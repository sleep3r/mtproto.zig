const std = @import("std");

pub fn main() !void {
    const addr = try std.net.Address.parseIp6("::ffff:192.168.1.1", 443);
    var buf: [64]u8 = undefined;
    const str = try std.fmt.bufPrint(&buf, "{}", .{addr});
    std.debug.print("Address string: {s}\n", .{str});
}
