const std = @import("std");
const posix = std.posix;

const msg_block_size: usize = 2048;
const msg_free_cap_per_queue: usize = 4;

const MsgBlock = struct {
    len: usize,
    data: [msg_block_size]u8,
};

pub const MessageQueue = struct {
    allocator: std.mem.Allocator,
    free: std.ArrayListUnmanaged(*MsgBlock) = .empty,
    blocks: std.ArrayListUnmanaged(*MsgBlock) = .empty,
    head_idx: usize = 0,
    offset: usize = 0,
    total_len: usize = 0,

    pub fn deinit(self: *MessageQueue) void {
        self.clear();

        for (self.free.items) |blk| self.allocator.destroy(blk);

        self.free.deinit(self.allocator);
        self.blocks.deinit(self.allocator);
    }

    pub fn clear(self: *MessageQueue) void {
        for (self.blocks.items[self.head_idx..]) |blk| {
            self.recycleBlock(blk);
        }
        self.blocks.clearRetainingCapacity();
        self.head_idx = 0;
        self.offset = 0;
        self.total_len = 0;
    }

    pub fn isEmpty(self: *const MessageQueue) bool {
        return self.total_len == 0;
    }

    pub fn appendCopy(self: *MessageQueue, data: []const u8) !void {
        if (data.len == 0) return;

        var off: usize = 0;

        if (self.blocks.items.len > 0) {
            const last_blk = self.blocks.items[self.blocks.items.len - 1];
            if (last_blk.len < msg_block_size) {
                const space = msg_block_size - last_blk.len;
                const take = @min(space, data.len);
                @memcpy(last_blk.data[last_blk.len .. last_blk.len + take], data[off .. off + take]);
                last_blk.len += take;
                self.total_len += take;
                off += take;
            }
        }

        while (off < data.len) {
            const rem = data.len - off;
            const take = @min(rem, msg_block_size);

            const blk = try self.acquireBlock();
            errdefer self.recycleBlock(blk);

            blk.len = take;
            @memcpy(blk.data[0..take], data[off .. off + take]);
            try self.blocks.append(self.allocator, blk);
            self.total_len += take;
            off += take;
        }
    }

    pub fn appendOwned(self: *MessageQueue, owned: []u8) !void {
        defer self.allocator.free(owned);
        try self.appendCopy(owned);
    }

    pub fn prepareIovecs(self: *const MessageQueue, out: []posix.iovec_const) usize {
        if (self.head_idx >= self.blocks.items.len) return 0;

        var count: usize = 0;
        var local_off = self.offset;
        for (self.blocks.items[self.head_idx..]) |blk| {
            if (count >= out.len) break;

            if (local_off >= blk.len) {
                local_off -= blk.len;
                continue;
            }

            out[count] = .{ .base = blk.data[local_off..blk.len].ptr, .len = blk.len - local_off };
            count += 1;
            local_off = 0;
        }
        return count;
    }

    pub fn consume(self: *MessageQueue, bytes: usize) !void {
        if (bytes == 0 or self.total_len == 0) return;

        var remaining = @min(bytes, self.total_len);
        self.total_len -= remaining;

        while (remaining > 0 and self.head_idx < self.blocks.items.len) {
            const blk = self.blocks.items[self.head_idx];
            const blk_left = blk.len - self.offset;

            if (remaining < blk_left) {
                self.offset += remaining;
                remaining = 0;
                break;
            }

            remaining -= blk_left;
            self.offset = 0;
            self.head_idx += 1;
            self.recycleBlock(blk);
        }

        if (self.head_idx > 0 and (self.head_idx >= self.blocks.items.len or self.head_idx >= 64)) {
            const rem = self.blocks.items.len - self.head_idx;
            if (rem > 0) {
                std.mem.copyForwards(*MsgBlock, self.blocks.items[0..rem], self.blocks.items[self.head_idx..]);
            }
            self.blocks.shrinkRetainingCapacity(rem);
            self.head_idx = 0;
        }

        if (self.total_len == 0) {
            self.head_idx = 0;
            self.offset = 0;
        }
    }

    fn acquireBlock(self: *MessageQueue) !*MsgBlock {
        if (self.free.items.len > 0) {
            return self.free.pop().?;
        }

        const blk = try self.allocator.create(MsgBlock);
        blk.* = .{
            .len = 0,
            .data = undefined,
        };
        return blk;
    }

    fn recycleBlock(self: *MessageQueue, blk: *MsgBlock) void {
        blk.len = 0;
        if (self.free.items.len >= msg_free_cap_per_queue) {
            self.allocator.destroy(blk);
            return;
        }

        self.free.append(self.allocator, blk) catch {
            self.allocator.destroy(blk);
        };
    }
};

test "message queue consume is stable" {
    var q = MessageQueue{ .allocator = std.testing.allocator };
    defer q.deinit();

    try q.appendCopy("abc");
    try q.appendCopy("defg");
    try std.testing.expectEqual(@as(usize, 7), q.total_len);

    try q.consume(2);
    try std.testing.expectEqual(@as(usize, 5), q.total_len);

    var iov: [8]posix.iovec_const = undefined;
    const n = q.prepareIovecs(iov[0..]);
    try std.testing.expect(n >= 1);
    try std.testing.expectEqual(@as(u8, 'c'), iov[0].base[0]);

    try q.consume(5);
    try std.testing.expect(q.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), q.offset);
    try std.testing.expectEqual(@as(usize, 0), q.head_idx);
}

test "message queue append fills tail block" {
    var q = MessageQueue{ .allocator = std.testing.allocator };
    defer q.deinit();

    try q.appendCopy("abcde");
    try q.appendCopy("fghij");

    try std.testing.expectEqual(@as(usize, 10), q.total_len);
    try std.testing.expectEqual(@as(usize, 1), q.blocks.items.len);
    try std.testing.expectEqual(@as(usize, 10), q.blocks.items[0].len);
}
