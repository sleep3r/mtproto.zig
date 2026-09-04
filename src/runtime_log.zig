const std = @import("std");

const AtomicLevel = struct {
    value: std.atomic.Value(u8) = .init(@intFromEnum(std.log.Level.info)),

    pub fn load(self: *const AtomicLevel, comptime order: std.builtin.AtomicOrder) std.log.Level {
        return @enumFromInt(self.value.load(order));
    }

    pub fn store(self: *AtomicLevel, new_level: std.log.Level, comptime order: std.builtin.AtomicOrder) void {
        self.value.store(@intFromEnum(new_level), order);
    }
};

pub var level: AtomicLevel = .{};
