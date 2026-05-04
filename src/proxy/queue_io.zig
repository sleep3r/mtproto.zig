const std = @import("std");
const posix = std.posix;

const MessageQueue = @import("message_queue.zig").MessageQueue;

const max_scatter_parts: usize = 64;

fn writeFd(fd: posix.fd_t, data: []const u8) !usize {
    while (true) {
        const rc = posix.system.write(fd, data.ptr, data.len);
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNRESET, .PIPE => return error.ConnectionReset,
            else => return error.UnexpectedWrite,
        }
    }
}

fn writevFd(fd: posix.fd_t, iovecs: []const posix.iovec_const) !usize {
    while (true) {
        const rc = posix.system.writev(fd, iovecs.ptr, @intCast(iovecs.len));
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNRESET, .PIPE => return error.ConnectionReset,
            else => return error.UnexpectedWritev,
        }
    }
}

fn noteTraffic(counter: *std.atomic.Value(u64), bytes: usize) void {
    if (bytes == 0) return;
    _ = counter.fetchAdd(@intCast(bytes), .monotonic);
}

fn noteTrafficOptional(counter: ?*std.atomic.Value(u64), bytes: usize) void {
    if (counter) |ptr| noteTraffic(ptr, bytes);
}

pub fn queueOrWriteMsg(
    fd: posix.fd_t,
    queue: *MessageQueue,
    data: []const u8,
    counter: *std.atomic.Value(u64),
    user_counter: ?*std.atomic.Value(u64),
) !bool {
    if (data.len == 0) return true;

    if (queue.isEmpty()) {
        const n = writeFd(fd, data) catch |err| {
            if (err == error.WouldBlock) {
                try queue.appendCopy(data);
                return false;
            }
            return err;
        };

        noteTraffic(counter, n);
        noteTrafficOptional(user_counter, n);
        if (n == data.len) return true;
        try queue.appendCopy(data[n..]);
        return false;
    }

    try queue.appendCopy(data);
    return false;
}

pub fn queueOrWriteMsgPair(
    fd: posix.fd_t,
    queue: *MessageQueue,
    first: []const u8,
    second: []const u8,
    counter: *std.atomic.Value(u64),
    user_counter: ?*std.atomic.Value(u64),
) !bool {
    if (first.len == 0 and second.len == 0) return true;

    if (queue.isEmpty()) {
        var iovecs: [2]posix.iovec_const = undefined;
        var n_iov: usize = 0;
        if (first.len > 0) {
            iovecs[n_iov] = .{ .base = first.ptr, .len = first.len };
            n_iov += 1;
        }
        if (second.len > 0) {
            iovecs[n_iov] = .{ .base = second.ptr, .len = second.len };
            n_iov += 1;
        }

        const total_len = first.len + second.len;
        const n = writevFd(fd, iovecs[0..n_iov]) catch |err| {
            if (err == error.WouldBlock) {
                try queue.appendCopy(first);
                try queue.appendCopy(second);
                return false;
            }
            return err;
        };

        if (n == 0) return error.ConnectionReset;
        noteTraffic(counter, n);
        noteTrafficOptional(user_counter, n);
        if (n == total_len) return true;

        if (n < first.len) {
            try queue.appendCopy(first[n..]);
            try queue.appendCopy(second);
            return false;
        }

        const consumed_second = n - first.len;
        if (consumed_second < second.len) {
            try queue.appendCopy(second[consumed_second..]);
        }
        return false;
    }

    try queue.appendCopy(first);
    try queue.appendCopy(second);
    return false;
}

pub fn queueOrWriteOwnedMsg(
    fd: posix.fd_t,
    queue: *MessageQueue,
    owned: []u8,
    counter: *std.atomic.Value(u64),
    user_counter: ?*std.atomic.Value(u64),
) !bool {
    if (owned.len == 0) {
        queue.allocator.free(owned);
        return true;
    }

    if (queue.isEmpty()) {
        const n = writeFd(fd, owned) catch |err| {
            if (err == error.WouldBlock) {
                try queue.appendOwned(owned);
                return false;
            }
            queue.allocator.free(owned);
            return err;
        };

        noteTraffic(counter, n);
        noteTrafficOptional(user_counter, n);
        if (n == owned.len) {
            queue.allocator.free(owned);
            return true;
        }

        const remaining = owned[n..];
        try queue.appendCopy(remaining);
        queue.allocator.free(owned);
        return false;
    }

    try queue.appendOwned(owned);
    return false;
}

pub fn flushQueue(
    fd: posix.fd_t,
    queue: *MessageQueue,
    counter: *std.atomic.Value(u64),
    user_counter: ?*std.atomic.Value(u64),
) !bool {
    if (queue.isEmpty()) return true;

    var iovecs: [max_scatter_parts]posix.iovec_const = undefined;

    while (!queue.isEmpty()) {
        const n_iov = queue.prepareIovecs(iovecs[0..]);
        if (n_iov == 0) return true;

        var total_req: usize = 0;
        for (iovecs[0..n_iov]) |iov| total_req += iov.len;

        const n = writevFd(fd, iovecs[0..n_iov]) catch |err| {
            if (err == error.WouldBlock) return false;
            return err;
        };

        if (n == 0) return error.ConnectionReset;
        noteTraffic(counter, n);
        noteTrafficOptional(user_counter, n);
        try queue.consume(n);

        if (n < total_req) return false;
    }

    return true;
}
