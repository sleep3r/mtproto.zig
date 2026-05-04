const std = @import("std");

const net_helpers = @import("net_helpers.zig");
const socket_utils = @import("socket_utils.zig");

const addressEql = net_helpers.addressEql;
const formatAddress = socket_utils.formatAddress;

const log = std.log.scoped(.proxy);

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
    const attempt_addr = slot.current_upstream_addr;
    const candidates = upstreamCandidates(slot);
    if (candidates.len == 0) return false;
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

        if (attempt_addr) |addr| {
            var prev_buf: [64]u8 = undefined;
            const prev_str = formatAddress(addr, &prev_buf);
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
