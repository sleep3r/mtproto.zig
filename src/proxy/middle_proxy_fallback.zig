const std = @import("std");

const constants = @import("../protocol/constants.zig");
const net_helpers = @import("net_helpers.zig");
const socket_utils = @import("socket_utils.zig");

const addressEql = net_helpers.addressEql;
const formatAddress = socket_utils.formatAddress;

const log = std.log.scoped(.proxy);

pub fn fallbackToDirect(
    loop: anytype,
    slot: anytype,
    comptime send_dc_nonce: fn (@TypeOf(loop), @TypeOf(slot)) void,
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

    // If current connected endpoint is already the direct fallback, continue inline.
    const fallback = slot.direct_fallback_addr.?;
    if (slot.current_upstream_addr) |cur| {
        if (addressEql(cur, fallback)) {
            send_dc_nonce(loop, slot);
            return true;
        }
    }

    // Otherwise reconnect to direct fallback endpoint.
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
