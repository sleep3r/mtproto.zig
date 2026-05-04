const std = @import("std");
const constants = @import("../protocol/constants.zig");

pub const DynamicRecordSizer = struct {
    current_size: usize,
    records_sent: u32,
    bytes_sent: u64,
    enabled: bool,

    pub const initial_size: usize = 1369;
    pub const full_size: usize = constants.max_tls_plaintext_size;
    pub const ramp_record_threshold: u32 = 8;
    pub const ramp_byte_threshold: u64 = 128 * 1024;

    pub fn init(enabled: bool) DynamicRecordSizer {
        // When DRS is disabled the user opted out of anti-DPI record-size
        // masking, so there is no reason to keep clamping records to the
        // probe-friendly 1369-byte size — doing so only hurts throughput.
        // Start at the full TLS plaintext size and short-circuit ramp-up.
        return .{
            .current_size = if (enabled) initial_size else full_size,
            .records_sent = 0,
            .bytes_sent = 0,
            .enabled = enabled,
        };
    }

    pub fn nextRecordSize(self: *DynamicRecordSizer) usize {
        return self.current_size;
    }

    pub fn recordSent(self: *DynamicRecordSizer, payload_len: usize) void {
        if (!self.enabled) return;
        self.records_sent += 1;
        self.bytes_sent += @as(u64, @intCast(payload_len));
        if (self.current_size == initial_size and
            (self.records_sent >= ramp_record_threshold or self.bytes_sent >= ramp_byte_threshold))
        {
            self.current_size = full_size;
        }
    }
};

test "DRS disabled skips ramp and uses full TLS record size" {
    // Regression: prior behaviour initialised `current_size` to the probe-
    // friendly 1369-byte size even when the user disabled DRS, bottlenecking
    // downstream throughput forever. Disabled DRS must start (and stay) at
    // the full TLS plaintext size.
    var drs = DynamicRecordSizer.init(false);
    try std.testing.expectEqual(DynamicRecordSizer.full_size, drs.nextRecordSize());
    for (0..32) |_| drs.recordSent(1369);
    try std.testing.expectEqual(DynamicRecordSizer.full_size, drs.nextRecordSize());
}

test "DRS enabled ramps" {
    var drs = DynamicRecordSizer.init(true);
    for (0..8) |_| drs.recordSent(1369);
    try std.testing.expectEqual(DynamicRecordSizer.full_size, drs.nextRecordSize());
}
