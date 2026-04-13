const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const version_mod = b.createModule(.{
        .root_source_file = b.path("src/version.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "version", .module = version_mod },
        },
    });

    const exe = b.addExecutable(.{
        .name = "mtproto-proxy",
        .root_module = exe_mod,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the proxy");
    run_step.dependOn(&run_cmd.step);

    const bench_mod = b.createModule(.{
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = optimize,
    });

    const bench_exe = b.addExecutable(.{
        .name = "mtproto-bench",
        .root_module = bench_mod,
    });

    b.installArtifact(bench_exe);

    const run_bench_cmd = b.addRunArtifact(bench_exe);
    if (b.args) |args| {
        run_bench_cmd.addArgs(args);
    }

    const bench_step = b.step("bench", "Run encapsulation microbenchmarks");
    bench_step.dependOn(&run_bench_cmd.step);

    const run_soak_cmd = b.addRunArtifact(bench_exe);
    run_soak_cmd.addArg("soak");
    if (b.args) |args| {
        run_soak_cmd.addArgs(args);
    }

    const soak_step = b.step("soak", "Run multithreaded soak stress test");
    soak_step.dependOn(&run_soak_cmd.step);

    // ── mtbuddy (installer & control panel) ──
    const tunnel_mod = b.createModule(.{
        .root_source_file = b.path("src/tunnel.zig"),
        .target = target,
        .optimize = optimize,
    });

    const ctl_mod = b.createModule(.{
        .root_source_file = b.path("src/ctl/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "tunnel", .module = tunnel_mod },
            .{ .name = "version", .module = version_mod },
        },
    });

    const ctl_exe = b.addExecutable(.{
        .name = "mtbuddy",
        .root_module = ctl_mod,
    });

    b.installArtifact(ctl_exe);

    const run_ctl_cmd = b.addRunArtifact(ctl_exe);
    run_ctl_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_ctl_cmd.addArgs(args);
    }

    const ctl_step = b.step("mtbuddy", "Run mtbuddy — the installer/control panel");
    ctl_step.dependOn(&run_ctl_cmd.step);

    // Tests
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "version", .module = version_mod },
        },
    });

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
