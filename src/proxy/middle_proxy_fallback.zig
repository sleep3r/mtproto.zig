const std = @import("std");

const constants = @import("../protocol/constants.zig");
const socket_utils = @import("socket_utils.zig");

const formatAddress = socket_utils.formatAddress;

const log = std.log.scoped(.proxy);

pub fn fallbackToDirect(
    loop: anytype,
    slot: anytype,
    comptime cleanup_failed_upstream_connect: fn (@TypeOf(loop), @TypeOf(slot)) void,
    comptime set_single_upstream_candidate: fn (@TypeOf(loop), @TypeOf(slot), @TypeOf(slot.direct_fallback_addr.?)) anyerror!void,
    comptime start_direct_connect: fn (@TypeOf(loop), @TypeOf(slot), @TypeOf(slot.direct_fallback_addr.?)) anyerror!void,
) bool {
    if (slot.direct_fallback_addr == null or slot.direct_fallback_used) return false;

    _ = slot.obf_params orelse return false;
    slot.direct_fallback_used = true;
    _ = loop.state.stats_mp_fallback.fetchAdd(1, .monotonic);
    slot.use_middle_proxy = false;
    slot.mp_step = .none;
    slot.mp_enc = null;
    slot.mp_dec = null;

    slot.use_fast_mode = loop.state.config.fast_mode and
        (slot.dc_abs >= 1 and slot.dc_abs <= constants.tg_datacenters_v4.len);

    // Reset nonce path state to cleanly re-send direct nonce.
    if (slot.dc_initial_tail) |tail| {
        loop.state.allocator.free(tail);
        slot.dc_initial_tail = null;
    }
    if (slot.tg_encryptor) |*enc| enc.wipe();
    if (slot.tg_decryptor) |*dec| dec.wipe();
    slot.tg_encryptor = null;
    slot.tg_decryptor = null;

    const fallback = slot.direct_fallback_addr.?;
    // The current socket has already been used for a rejected MiddleProxy
    // handshake. Reconnect even when the direct fallback has the same endpoint
    // (DC203), otherwise we may write a direct nonce to a half-closed socket.
    cleanup_failed_upstream_connect(loop, slot);
    slot.upstream_candidate_next = 1;

    set_single_upstream_candidate(loop, slot, fallback) catch {
        return false;
    };

    start_direct_connect(loop, slot, fallback) catch |err| {
        log.warn("[{d}] direct fallback connect start failed: {any}", .{ slot.conn_id, err });
        return false;
    };

    var fb_buf: [64]u8 = undefined;
    const fb_str = formatAddress(fallback, &fb_buf);
    log.warn("[{d}] middle-proxy handshake failed, reconnecting direct to {s}", .{ slot.conn_id, fb_str });
    return true;
}

test "fallback reconnects when direct endpoint matches current middle-proxy endpoint" {
    const Address = std.Io.net.IpAddress;
    const FakeStep = enum { none, middle_proxy_handshake };
    const FakeCipher = struct {
        wiped: bool = false,

        fn wipe(self: *@This()) void {
            self.wiped = true;
        }
    };
    const FakeConfig = struct {
        fast_mode: bool = true,
    };
    const FakeState = struct {
        stats_mp_fallback: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        config: FakeConfig = .{},
        allocator: std.mem.Allocator = std.testing.allocator,
    };
    const FakeLoop = struct {
        state: FakeState = .{},
        cleanup_calls: usize = 0,
        set_candidate_calls: usize = 0,
        start_connect_calls: usize = 0,
        started_addr: ?Address = null,
    };
    const FakeSlot = struct {
        direct_fallback_addr: ?Address = null,
        direct_fallback_used: bool = false,
        obf_params: ?void = {},
        use_middle_proxy: bool = true,
        mp_step: FakeStep = .middle_proxy_handshake,
        mp_enc: ?FakeCipher = null,
        mp_dec: ?FakeCipher = null,
        dc_abs: u16 = 203,
        use_fast_mode: bool = false,
        dc_initial_tail: ?[]u8 = null,
        tg_encryptor: ?FakeCipher = null,
        tg_decryptor: ?FakeCipher = null,
        upstream_candidate_next: u8 = 0,
        current_upstream_addr: ?Address = null,
        conn_id: u64 = 42,
    };
    const Callbacks = struct {
        fn cleanup(loop: *FakeLoop, slot: *FakeSlot) void {
            _ = slot;
            loop.cleanup_calls += 1;
        }

        fn setCandidate(loop: *FakeLoop, slot: *FakeSlot, addr: Address) !void {
            _ = slot;
            _ = addr;
            loop.set_candidate_calls += 1;
        }

        fn startConnect(loop: *FakeLoop, slot: *FakeSlot, addr: Address) !void {
            _ = slot;
            loop.start_connect_calls += 1;
            loop.started_addr = addr;
        }
    };

    const fallback = Address{ .ip4 = .{ .bytes = .{ 91, 105, 192, 110 }, .port = 443 } };
    var loop = FakeLoop{};
    var slot = FakeSlot{
        .direct_fallback_addr = fallback,
        .current_upstream_addr = fallback,
    };

    try std.testing.expect(fallbackToDirect(
        &loop,
        &slot,
        Callbacks.cleanup,
        Callbacks.setCandidate,
        Callbacks.startConnect,
    ));
    try std.testing.expectEqual(@as(usize, 1), loop.cleanup_calls);
    try std.testing.expectEqual(@as(usize, 1), loop.set_candidate_calls);
    try std.testing.expectEqual(@as(usize, 1), loop.start_connect_calls);
    try std.testing.expectEqual(true, slot.direct_fallback_used);
    try std.testing.expectEqual(false, slot.use_middle_proxy);
    try std.testing.expectEqual(FakeStep.none, slot.mp_step);
    try std.testing.expectEqual(@as(u64, 1), loop.state.stats_mp_fallback.load(.monotonic));
    try std.testing.expect(Address.eql(&fallback, &loop.started_addr.?));
}
