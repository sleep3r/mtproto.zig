const std = @import("std");

const net_helpers = @import("net_helpers.zig");
const socket_utils = @import("socket_utils.zig");
const constants = @import("../protocol/constants.zig");

const addressEql = net_helpers.addressEql;
const formatAddress = socket_utils.formatAddress;

const log = std.log.scoped(.proxy);

test "candidate exhaustion falls back once and updates fast mode and metrics" {
    const Address = std.Io.net.IpAddress;
    const Slot = struct {
        upstream_candidates_inline: [2]Address,
        upstream_candidates_heap: ?[]Address = null,
        upstream_candidate_count: usize = 2,
        upstream_candidate_next: usize = 1,
        current_upstream_addr: ?Address = null,
        direct_fallback_addr: ?Address,
        direct_fallback_used: bool = false,
        use_middle_proxy: bool = true,
        use_fast_mode: bool = false,
        dc_abs: usize = 4,
        is_media_path: bool = false,
        conn_id: u64 = 1,
    };
    const Loop = struct {
        state: struct {
            stats_mp_fallback: std.atomic.Value(u64) = .init(0),
            config: struct { fast_mode: bool = true } = .{},
        } = .{},
        starts: usize = 0,
    };
    const Cb = struct {
        fn start(loop: *Loop, slot: *Slot, addr: Address) !void {
            slot.current_upstream_addr = addr;
            loop.starts += 1;
        }
        fn set(_: *Loop, slot: *Slot, addr: Address) !void {
            slot.upstream_candidates_inline[0] = addr;
            slot.upstream_candidate_count = 1;
        }
    };
    const a = Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 443 } };
    const b = Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 2 }, .port = 443 } };
    var slot = Slot{ .upstream_candidates_inline = .{ a, b }, .direct_fallback_addr = a };
    var loop = Loop{};
    try std.testing.expect(tryNextDcEndpoint(&loop, &slot, error.Timeout, Cb.start, Cb.set));
    try std.testing.expectEqual(@as(usize, 2), slot.upstream_candidate_next);
    try std.testing.expect(tryNextDcEndpoint(&loop, &slot, error.Timeout, Cb.start, Cb.set));
    try std.testing.expect(slot.direct_fallback_used and slot.use_fast_mode and !slot.use_middle_proxy);
    try std.testing.expectEqual(@as(u64, 1), loop.state.stats_mp_fallback.load(.monotonic));
    try std.testing.expect(!tryNextDcEndpoint(&loop, &slot, error.Timeout, Cb.start, Cb.set));
    try std.testing.expectEqual(@as(usize, 2), loop.starts);
}

fn upstreamCandidates(slot: anytype) []const @TypeOf(slot.upstream_candidates_inline[0]) {
    const count: usize = slot.upstream_candidate_count;
    if (slot.upstream_candidates_heap) |heap| return heap[0..count];
    return slot.upstream_candidates_inline[0..count];
}

pub fn tryNextDcEndpoint(
    loop: anytype,
    slot: anytype,
    err: anyerror,
    comptime start_connect_upstream_dc: fn (@TypeOf(loop), @TypeOf(slot), @TypeOf(slot.current_upstream_addr.?)) anyerror!void,
    comptime set_single_upstream_candidate: fn (@TypeOf(loop), @TypeOf(slot), @TypeOf(slot.current_upstream_addr.?)) anyerror!void,
) bool {
    const candidates = upstreamCandidates(slot);
    if (candidates.len == 0) return false;
    const attempt_addr = slot.current_upstream_addr orelse candidates[@min(slot.upstream_candidate_next -| 1, candidates.len - 1)];
    const candidate_count = candidates.len;

    const next_u: usize = slot.upstream_candidate_next;
    if (next_u < candidates.len) {
        const next_idx = next_u;
        const next_addr = candidates[next_idx];
        slot.upstream_candidate_next += 1;
        start_connect_upstream_dc(loop, slot, next_addr) catch |next_err| {
            log.warn("[{d}] dc connect candidate {d}/{d} failed immediately: {any}", .{
                slot.conn_id,
                next_idx + 1,
                candidate_count,
                next_err,
            });
            return tryNextDcEndpoint(
                loop,
                slot,
                next_err,
                start_connect_upstream_dc,
                set_single_upstream_candidate,
            );
        };

        {
            var prev_buf: [64]u8 = undefined;
            const prev_str = formatAddress(attempt_addr, &prev_buf);
            log.warn("[{d}] dc connect failed ({any}), retry candidate {d}/{d} after {s}", .{
                slot.conn_id,
                err,
                next_idx + 1,
                candidate_count,
                prev_str,
            });
        }
        return true;
    }

    if (!slot.direct_fallback_used and slot.direct_fallback_addr != null and slot.use_middle_proxy) {
        slot.direct_fallback_used = true;
        slot.use_middle_proxy = false;
        _ = loop.state.stats_mp_fallback.fetchAdd(1, .monotonic);
        slot.use_fast_mode = loop.state.config.fast_mode and
            (slot.dc_abs >= 1 and slot.dc_abs <= constants.tg_datacenters_v4.len);
        const fallback = slot.direct_fallback_addr.?;
        slot.upstream_candidate_next = 1;

        set_single_upstream_candidate(loop, slot, fallback) catch {
            return false;
        };

        start_connect_upstream_dc(loop, slot, fallback) catch |fallback_err| {
            log.warn("[{d}] direct fallback connect failed: {any}", .{ slot.conn_id, fallback_err });
            return false;
        };

        var fb_buf: [64]u8 = undefined;
        const fb_str = formatAddress(fallback, &fb_buf);
        log.warn("[{d}] middle-proxy exhausted, fallback to direct {s}", .{ slot.conn_id, fb_str });
        return true;
    }

    if (slot.is_media_path) {
        log.warn("[{d}] media path connect failed after all candidates: {any}", .{ slot.conn_id, err });
    }
    return false;
}
