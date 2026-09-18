const std = @import("std");
const page = @import("page");
const frame = @import("frame");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const html = try page.renderSessionBridge(
        allocator,
        "/api/v1/socket",
        "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT",
        "NNNNNNNNNNNNNNNNNNNNNNNN",
    );
    defer allocator.free(html);
    var frame_buf: [16]u8 = undefined;
    const hello = try frame.serialize(&frame_buf, .hello, 0, &.{1});
    const hello_hex = std.fmt.bytesToHex(hello[0..9].*, .lower);
    const welcome = try frame.serialize(&frame_buf, .welcome, 0, "");
    const welcome_hex = std.fmt.bytesToHex(welcome[0..8].*, .lower);
    const stdout = std.Io.File.stdout();
    try stdout.writeStreamingAll(init.io, &hello_hex);
    try stdout.writeStreamingAll(init.io, "\n");
    try stdout.writeStreamingAll(init.io, &welcome_hex);
    try stdout.writeStreamingAll(init.io, "\n");
    try stdout.writeStreamingAll(init.io, html);
}
