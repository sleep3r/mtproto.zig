const std = @import("std");
const net = std.net;
const crypto = @import("crypto/crypto.zig");
const middleproxy = @import("protocol/middleproxy.zig");
const constants = @import("protocol/constants.zig");

const Mode = enum {
    bench,
    soak,
};

const Options = struct {
    mode: Mode = .bench,
    seconds: u32 = 30,
    threads: usize = 0,
    max_payload: usize = 128 * 1024,
};

const SoakShared = struct {
    deadline_ms: i64,
    total_ops: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_in_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_out_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    errors: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
};

const WorkerArgs = struct {
    worker_id: usize,
    max_payload: usize,
    shared: *SoakShared,
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const opts = parseArgs(allocator) catch |err| {
        if (err != error.ShowHelp) {
            std.debug.print("error: {any}\n\n", .{err});
        }
        printUsage();
        if (err == error.ShowHelp) return;
        return err;
    };

    switch (opts.mode) {
        .bench => try runBench(allocator),
        .soak => try runSoak(allocator, opts),
    }
}

fn runBench(allocator: std.mem.Allocator) !void {
    const sizes = [_]usize{ 64, 256, 1024, 4096, 16384, 65536, 131072 };
    const target_bytes = 128 * 1024 * 1024;

    std.debug.print("benchmark: encapsulateSingleMessageC2S (proto={s})\n", .{@tagName(constants.ProtoTag.intermediate)});
    std.debug.print("payload_bytes iterations ns_per_op in_mib_per_s out_mib_per_s\n", .{});

    for (sizes) |payload_size| {
        var ctx = try initContext(allocator, .intermediate);
        defer ctx.deinit(allocator);

        const payload = try allocator.alloc(u8, payload_size);
        defer allocator.free(payload);
        fillPayload(payload);

        const out_buf = try allocator.alloc(u8, payload_size + 256);
        defer allocator.free(out_buf);

        var iters = target_bytes / payload_size;
        if (iters < 1_000) iters = 1_000;
        if (iters > 300_000) iters = 300_000;

        const warmup_iters = @min(iters, 256);
        var w: usize = 0;
        while (w < warmup_iters) : (w += 1) {
            payload[0] +%= 1;
            _ = try ctx.encapsulateSingleMessageC2S(payload, (w & 1) == 1, out_buf);
        }

        var timer = try std.time.Timer.start();

        var produced_out_bytes: u64 = 0;
        var i: usize = 0;
        while (i < iters) : (i += 1) {
            payload[0] +%= 1;
            const written = try ctx.encapsulateSingleMessageC2S(payload, (i & 1) == 1, out_buf);
            produced_out_bytes += @as(u64, @intCast(written));
        }

        const elapsed_ns = timer.read();
        const total_in_bytes = @as(u64, @intCast(payload_size)) * @as(u64, @intCast(iters));
        const ns_per_op = elapsedNsPerOp(elapsed_ns, iters);

        std.debug.print("{d} {d} {d} {d} {d}\n", .{
            payload_size,
            iters,
            ns_per_op,
            bytesPerSecToMiB(total_in_bytes, elapsed_ns),
            bytesPerSecToMiB(produced_out_bytes, elapsed_ns),
        });
    }
}

fn runSoak(allocator: std.mem.Allocator, opts: Options) !void {
    const start_ms = std.time.milliTimestamp();
    const duration_ms = @as(i64, @intCast(opts.seconds)) * 1000;

    var shared = SoakShared{
        .deadline_ms = start_ms + duration_ms,
    };

    std.debug.print("soak: workers={d} duration={d}s max_payload={d}\n", .{
        opts.threads,
        opts.seconds,
        opts.max_payload,
    });

    var threads: std.ArrayList(std.Thread) = .empty;
    defer threads.deinit(allocator);

    for (0..opts.threads) |worker_id| {
        const worker = WorkerArgs{
            .worker_id = worker_id,
            .max_payload = opts.max_payload,
            .shared = &shared,
        };
        const thread = try std.Thread.spawn(.{}, soakWorker, .{worker});
        try threads.append(allocator, thread);
    }

    for (threads.items) |thread| {
        thread.join();
    }

    const end_ms = std.time.milliTimestamp();
    const elapsed_ms_i64 = @max(@as(i64, 1), end_ms - start_ms);
    const elapsed_ms: u64 = @intCast(elapsed_ms_i64);

    const ops = shared.total_ops.load(.monotonic);
    const in_bytes = shared.total_in_bytes.load(.monotonic);
    const out_bytes = shared.total_out_bytes.load(.monotonic);
    const errors = shared.errors.load(.monotonic);

    std.debug.print("result: ops={d} ops/s={d} in_mib/s={d} out_mib/s={d} errors={d}\n", .{
        ops,
        perSec(ops, elapsed_ms),
        bytesPerSecToMiBMs(in_bytes, elapsed_ms),
        bytesPerSecToMiBMs(out_bytes, elapsed_ms),
        errors,
    });

    if (errors != 0 or ops == 0) {
        return error.SoakFailed;
    }
}

fn soakWorker(args: WorkerArgs) void {
    const allocator = std.heap.page_allocator;

    var ctx = initContext(allocator, .intermediate) catch {
        _ = args.shared.errors.fetchAdd(1, .monotonic);
        return;
    };
    defer ctx.deinit(allocator);

    const payload_buf = allocator.alloc(u8, args.max_payload) catch {
        _ = args.shared.errors.fetchAdd(1, .monotonic);
        return;
    };
    defer allocator.free(payload_buf);
    fillPayload(payload_buf);

    const out_buf = allocator.alloc(u8, args.max_payload + 256) catch {
        _ = args.shared.errors.fetchAdd(1, .monotonic);
        return;
    };
    defer allocator.free(out_buf);

    var rng_state = makeSeed(args.worker_id);

    while (std.time.milliTimestamp() < args.shared.deadline_ms) {
        const payload_len = nextPayloadLen(&rng_state, args.max_payload);
        payload_buf[0] +%= 1;
        const quickack = (nextRand(&rng_state) & 1) == 1;

        const written = ctx.encapsulateSingleMessageC2S(payload_buf[0..payload_len], quickack, out_buf) catch {
            _ = args.shared.errors.fetchAdd(1, .monotonic);
            return;
        };

        _ = args.shared.total_ops.fetchAdd(1, .monotonic);
        _ = args.shared.total_in_bytes.fetchAdd(@as(u64, @intCast(payload_len)), .monotonic);
        _ = args.shared.total_out_bytes.fetchAdd(@as(u64, @intCast(written)), .monotonic);
    }
}

fn initContext(allocator: std.mem.Allocator, proto_tag: constants.ProtoTag) !middleproxy.MiddleProxyContext {
    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    return middleproxy.MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        proto_tag,
        null,
    );
}

fn fillPayload(buf: []u8) void {
    for (buf, 0..) |*byte, idx| {
        byte.* = @truncate((idx * 17 + 11) % 251);
    }
}

fn parseArgs(allocator: std.mem.Allocator) !Options {
    var opts = Options{};

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "bench")) {
            opts.mode = .bench;
            continue;
        }
        if (std.mem.eql(u8, arg, "soak")) {
            opts.mode = .soak;
            continue;
        }
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return error.ShowHelp;
        }
        if (std.mem.startsWith(u8, arg, "--seconds=")) {
            opts.seconds = try parsePositiveU32(arg["--seconds=".len..]);
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--threads=")) {
            opts.threads = try parsePositiveUsize(arg["--threads=".len..]);
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--max-payload=")) {
            opts.max_payload = try parsePositiveUsize(arg["--max-payload=".len..]);
            continue;
        }

        return error.InvalidArgument;
    }

    if (opts.threads == 0) {
        const cpu_count = std.Thread.getCpuCount() catch 4;
        opts.threads = @max(@as(usize, 1), cpu_count);
    }

    if (opts.max_payload < 64) return error.InvalidArgument;

    return opts;
}

fn parsePositiveU32(text: []const u8) !u32 {
    const value = try std.fmt.parseInt(u32, text, 10);
    if (value == 0) return error.InvalidArgument;
    return value;
}

fn parsePositiveUsize(text: []const u8) !usize {
    const value = try std.fmt.parseInt(usize, text, 10);
    if (value == 0) return error.InvalidArgument;
    return value;
}

fn printUsage() void {
    std.debug.print(
        \\Usage:
        \\  zig build bench
        \\  zig build bench -- --help
        \\  zig build soak -- --seconds=30 --threads=8 --max-payload=131072
        \\
        \\Modes:
        \\  bench (default): microbenchmark for C2S encapsulation
        \\  soak: multithreaded crash/stability stress test
        \\
    , .{});
}

fn elapsedNsPerOp(elapsed_ns: u64, iters: usize) u64 {
    if (iters == 0) return 0;
    return elapsed_ns / @as(u64, @intCast(iters));
}

fn bytesPerSecToMiB(bytes: u64, elapsed_ns: u64) u64 {
    if (elapsed_ns == 0) return 0;
    const numerator = @as(u128, bytes) * std.time.ns_per_s;
    const denominator = @as(u128, elapsed_ns) * 1024 * 1024;
    return @intCast(numerator / denominator);
}

fn perSec(value: u64, elapsed_ms: u64) u64 {
    if (elapsed_ms == 0) return 0;
    const numerator = @as(u128, value) * 1000;
    return @intCast(numerator / elapsed_ms);
}

fn bytesPerSecToMiBMs(bytes: u64, elapsed_ms: u64) u64 {
    if (elapsed_ms == 0) return 0;
    const numerator = @as(u128, bytes) * 1000;
    const denominator = @as(u128, elapsed_ms) * 1024 * 1024;
    return @intCast(numerator / denominator);
}

fn makeSeed(worker_id: usize) u64 {
    const now_ms = std.time.milliTimestamp();
    const base: u64 = if (now_ms >= 0)
        @intCast(now_ms)
    else
        @intCast(-now_ms);
    var seed = base ^ (@as(u64, @intCast(worker_id + 1)) *% 0x9e3779b97f4a7c15);
    if (seed == 0) seed = 1;
    return seed;
}

fn nextRand(state: *u64) u64 {
    state.* = state.* *% 6364136223846793005 +% 1442695040888963407;
    return state.*;
}

fn nextPayloadLen(state: *u64, max_payload: usize) usize {
    const hot_sizes = [_]usize{ 64, 256, 1024, 4096, 16384, 32768, 65535, 65536, 65537, 131072 };

    const pick_hot = (nextRand(state) % 10) < 7;
    if (pick_hot) {
        const idx: usize = @intCast(nextRand(state) % hot_sizes.len);
        const capped = @min(hot_sizes[idx], max_payload);
        return if (capped == 0) 1 else capped;
    }

    const max_u64 = @as(u64, @intCast(@max(@as(usize, 1), max_payload)));
    return 1 + @as(usize, @intCast(nextRand(state) % max_u64));
}
