const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The proxy parses untrusted network input (FakeTLS/obfuscation/middleproxy/
    // socks5/http/TOML) on the most internet-exposed process. Ship its data plane
    // with runtime bounds/overflow/null checks ON: a single off-by-one becomes a
    // safe panic instead of exploitable UB. mtbuddy/bench keep the requested mode.
    // ReleaseSafe grows the binary and adds parse-loop overhead (AES is HW
    // accelerated) vs the marketed ReleaseFast numbers — measure before relying on
    // them. Override with -Ddataplane_safety=false to force the requested mode.
    const dataplane_safety = b.option(
        bool,
        "dataplane_safety",
        "Build the internet-facing proxy with runtime safety on (ReleaseSafe) even in release builds (default: true)",
    ) orelse true;
    const dataplane_optimize: std.builtin.OptimizeMode =
        if (dataplane_safety and (optimize == .ReleaseFast or optimize == .ReleaseSmall)) .ReleaseSafe else optimize;
    const pinned_minisign_pubkey = "RWT8YwmUuq/3WpUnYJjD6rAfQugYdZKWr61U3O+2kdNvriLSyrvVU/NO";
    const minisign_pubkey = b.option(
        []const u8,
        "minisign_pubkey",
        "Minisign public key (base64) for release signature verification",
    ) orelse pinned_minisign_pubkey;

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "minisign_pubkey", minisign_pubkey);
    build_options.addOption([]const u8, "proxy_service", @embedFile("deploy/mtproto-proxy.service"));
    const build_options_mod = build_options.createModule();
    const version_mod = b.createModule(.{
        .root_source_file = b.path("src/version.zig"),
        .target = target,
        .optimize = optimize,
    });
    const linux_io_mod = b.createModule(.{
        .root_source_file = b.path("src/linux_io.zig"),
        .target = target,
        .optimize = optimize,
    });
    const proxy_config_mod = b.createModule(.{
        .root_source_file = b.path("src/config.zig"),
        .target = target,
        .optimize = optimize,
    });

    const child_process_mod = b.createModule(.{
        .root_source_file = b.path("src/proxy/child_process.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = dataplane_optimize,
        .imports = &.{
            .{ .name = "version", .module = version_mod },
            .{ .name = "linux_io", .module = linux_io_mod },
            .{ .name = "child_process", .module = child_process_mod },
        },
    });

    const exe = b.addExecutable(.{
        .name = "mtproto-proxy",
        .root_module = exe_mod,
    });

    // Exploit mitigation on the internet-facing proxy: position-independent
    // executable (ASLR). Full RELRO is already Zig's default (link_z_relro =
    // true, link_z_lazy = false → -z relro -z now). Stack canaries are NOT
    // enabled because they require libc (__stack_chk_fail) and this binary is
    // deliberately libc-free; ReleaseSafe bounds/overflow checks cover the data
    // plane instead.
    exe.pie = true;

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

    const install_bench = b.addInstallArtifact(bench_exe, .{});
    b.step("install-bench", "Install the optional benchmark binary").dependOn(&install_bench.step);

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

    const proxy_http_fetch_mod = b.createModule(.{
        .root_source_file = b.path("src/proxy/http_fetch.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "child_process", .module = child_process_mod }},
    });

    const proxy_net_helpers_mod = b.createModule(.{
        .root_source_file = b.path("src/proxy/net_helpers.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "child_process", .module = child_process_mod }},
    });

    // The WEB proxy hostname rules and bridge-capability derivation are shared: the relay
    // enforces them at runtime and mtbuddy validates a domain against the exact same code
    // before it ends up baked into links.
    const web_capability_mod = b.createModule(.{
        .root_source_file = b.path("src/web/capability.zig"),
        .target = target,
        .optimize = optimize,
    });

    const ctl_mod = b.createModule(.{
        .root_source_file = b.path("src/ctl/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "cover_page", .module = b.createModule(.{ .root_source_file = b.path("src/web/page.zig"), .target = target, .optimize = optimize }) },
            .{ .name = "tunnel", .module = tunnel_mod },
            .{ .name = "version", .module = version_mod },
            .{ .name = "linux_io", .module = linux_io_mod },
            .{ .name = "proxy_config", .module = proxy_config_mod },
            .{ .name = "proxy_http_fetch", .module = proxy_http_fetch_mod },
            .{ .name = "proxy_net_helpers", .module = proxy_net_helpers_mod },
            .{ .name = "web_capability", .module = web_capability_mod },
            .{ .name = "build_options", .module = build_options_mod },
        },
    });

    const ctl_exe = b.addExecutable(.{
        .name = "mtbuddy",
        .root_module = ctl_mod,
    });
    ctl_exe.pie = target.result.os.tag == .linux;

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
            .{ .name = "child_process", .module = child_process_mod },
            .{ .name = "version", .module = version_mod },
            .{ .name = "linux_io", .module = linux_io_mod },
        },
    });

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);

    const ctl_tests = b.addTest(.{
        .root_module = ctl_mod,
    });

    const run_ctl_tests = b.addRunArtifact(ctl_tests);

    const test_step = b.step("test", "Run unit tests");
    const obf_gen = b.addExecutable(.{
        .name = "e2e-obf-handshake-gen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/e2e_obf_handshake_gen.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    test_step.dependOn(&obf_gen.step);
    test_step.dependOn(&run_unit_tests.step);
    test_step.dependOn(&run_ctl_tests.step);

    // CLI localization smoke test (Linux hosts only).
    if (target.query.isNative() and target.result.os.tag == .linux) {
        const run_mtbuddy_help_ru = b.addRunArtifact(ctl_exe);
        run_mtbuddy_help_ru.addArgs(&.{ "--lang", "ru", "--help" });
        _ = run_mtbuddy_help_ru.captureStdOut(.{});
        _ = run_mtbuddy_help_ru.captureStdErr(.{});
        test_step.dependOn(&run_mtbuddy_help_ru.step);
        const bad_invocations = [_][]const []const u8{
            &.{"unknown-command"},
            &.{"--lang"},
            &.{ "setup", "unknown" },
            &.{ "setup", "masking", "--lang", "ru" },
            &.{ "config", "validate", "--config" },
            &.{ "install", "--secert", "bad" },
            &.{ "update", "--unknown" },
            &.{ "setup", "web", "--unknown" },
            &.{ "setup", "egress", "--unknown" },
            &.{ "setup", "tunnel", "--unknown" },
            &.{ "setup", "masking", "--unknown" },
            &.{ "setup", "dashboard", "--unknown" },
            &.{ "setup", "nfqws", "--unknown" },
            &.{ "setup", "recovery", "--unknown" },
            &.{ "setup", "syn-limit", "--unknown" },
            &.{ "ipv6-hop", "--unknown" },
        };
        for (bad_invocations) |argv| {
            const bad_usage = b.addRunArtifact(ctl_exe);
            bad_usage.addArgs(argv);
            bad_usage.expectExitCode(1);
            _ = bad_usage.captureStdOut(.{});
            _ = bad_usage.captureStdErr(.{});
            test_step.dependOn(&bad_usage.step);
        }
    }

    // E2E / integration harness (process-level scenarios).
    const e2e_cmd = b.addSystemCommand(&.{"python3"});
    e2e_cmd.addFileArg(b.path("test/e2e/run.py"));
    e2e_cmd.addArg("--obf-gen");
    e2e_cmd.addFileArg(obf_gen.getEmittedBin());
    e2e_cmd.step.dependOn(&exe.step);
    e2e_cmd.addArg("--proxy-bin");
    e2e_cmd.addFileArg(exe.getEmittedBin());
    if (b.args) |args| {
        e2e_cmd.addArgs(args);
    }

    const e2e_step = b.step("e2e", "Run E2E/integration tests");
    e2e_step.dependOn(&e2e_cmd.step);

    // WEB proxy bridge-page contract tests. The page in src/web/page.zig is the only
    // code here that runs in the user's browser, against two Telegram Desktop boundaries
    // that fail silently when they are wrong — so it is driven by a scripted client in
    // node rather than left unexercised. Kept out of `test` because it needs python3 and
    // node; the runner skips cleanly when node is absent.
    const web_bridge_cmd = b.addSystemCommand(&.{"python3"});
    web_bridge_cmd.addFileArg(b.path("test/web-bridge/run.py"));
    const web_bridge_step = b.step("web-bridge", "Run WEB proxy bridge-page contract tests");
    web_bridge_step.dependOn(&web_bridge_cmd.step);
}
