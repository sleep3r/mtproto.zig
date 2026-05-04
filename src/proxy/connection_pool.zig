const std = @import("std");
const posix = std.posix;

pub fn ConnectionPool(comptime SlotType: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        slots: []?*SlotType,
        free_stack: []u32,
        free_count: u32,
        allocated_hi: u32,
        fd_to_slot: std.AutoHashMapUnmanaged(posix.fd_t, u32) = .{},

        pub fn init(allocator: std.mem.Allocator, capacity: u32) !Self {
            const slots = try allocator.alloc(?*SlotType, capacity);
            errdefer allocator.free(slots);

            const free_stack = try allocator.alloc(u32, capacity);
            errdefer allocator.free(free_stack);

            for (slots) |*slot| {
                slot.* = null;
            }

            var i: usize = 0;
            while (i < capacity) : (i += 1) {
                free_stack[i] = @intCast(capacity - 1 - i);
            }

            var pool = Self{
                .allocator = allocator,
                .slots = slots,
                .free_stack = free_stack,
                .free_count = capacity,
                .allocated_hi = 0,
                .fd_to_slot = .{},
            };
            try pool.fd_to_slot.ensureTotalCapacity(allocator, @as(u32, capacity * 2));
            return pool;
        }

        pub fn deinit(self: *Self) void {
            for (self.slots) |slot_opt| {
                if (slot_opt) |slot_ptr| {
                    self.allocator.destroy(slot_ptr);
                }
            }
            self.fd_to_slot.deinit(self.allocator);
            self.allocator.free(self.free_stack);
            self.allocator.free(self.slots);
        }

        pub fn acquire(self: *Self) ?*SlotType {
            if (self.free_count == 0) return null;
            self.free_count -= 1;
            const idx = self.free_stack[self.free_count];
            if (self.slots[idx] == null) {
                const fresh = self.allocator.create(SlotType) catch {
                    self.free_stack[self.free_count] = idx;
                    self.free_count += 1;
                    return null;
                };
                fresh.* = .{};
                self.slots[idx] = fresh;
                const hi = idx + 1;
                if (hi > self.allocated_hi) self.allocated_hi = hi;
            }

            const slot = self.slots[idx].?;
            slot.* = .{};
            slot.index = idx;
            slot.client_queue.allocator = self.allocator;
            slot.upstream_queue.allocator = self.allocator;
            return slot;
        }

        pub fn release(self: *Self, slot: *SlotType) void {
            self.free_stack[self.free_count] = slot.index;
            self.free_count += 1;
            slot.phase = .idle;
        }

        pub fn mapFd(self: *Self, fd: posix.fd_t, idx: u32) !void {
            try self.fd_to_slot.put(self.allocator, fd, idx);
        }

        pub fn unmapFd(self: *Self, fd: posix.fd_t) void {
            _ = self.fd_to_slot.remove(fd);
        }

        pub fn getByFd(self: *Self, fd: posix.fd_t) ?*SlotType {
            const idx = self.fd_to_slot.get(fd) orelse return null;
            return self.slots[idx];
        }
    };
}
