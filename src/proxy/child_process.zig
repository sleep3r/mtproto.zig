const std = @import("std");
const builtin = @import("builtin");

/// Linux deployments use GNU coreutils (Debian/Ubuntu and the published image).
/// Reset the signalfd owner's inherited mask in the child, never on a live
/// event-loop thread. No shell interpolation; the original argv stays separate.
pub fn run(allocator: std.mem.Allocator, io: std.Io, requested: std.process.RunOptions) !std.process.RunResult {
    var options = requested;
    if (options.timeout == .none) options.timeout = .{ .duration = .{ .raw = .fromSeconds(12), .clock = .awake } };
    if (builtin.os.tag != .linux) return std.process.run(allocator, io, options);
    const argv = try allocator.alloc([]const u8, options.argv.len + 2);
    defer allocator.free(argv);
    argv[0] = "/usr/bin/env";
    argv[1] = "--default-signal=TERM,INT,HUP,USR1";
    @memcpy(argv[2..], options.argv);
    options.argv = argv;
    return std.process.run(allocator, io, options);
}

test "child runner clears inherited signalfd signal mask" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var mask = std.posix.sigemptyset();
    std.posix.sigaddset(&mask, .TERM);
    var old: std.posix.sigset_t = undefined;
    std.posix.sigprocmask(std.posix.SIG.BLOCK, &mask, &old);
    defer std.posix.sigprocmask(std.posix.SIG.SETMASK, &old, null);
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const result = try run(std.testing.allocator, threaded.io(), .{ .argv = &.{ "/bin/sh", "-c", "kill -TERM $$; exit 99" } });
    defer std.testing.allocator.free(result.stdout);
    defer std.testing.allocator.free(result.stderr);
    try std.testing.expect(result.term == .signal);
    try std.testing.expectEqual(std.posix.SIG.TERM, result.term.signal);
}
