//! Setup nfqws command for mtbuddy.
//!
//! Ports setup_nfqws.sh (258 lines bash) — installs zapret's nfqws
//! for OS-level TCP desync (fake packets + split to defeat stateful DPI).

const std = @import("std");
const tui_mod = @import("tui.zig");
const i18n = @import("i18n.zig");
const sys = @import("sys.zig");
const toml = @import("toml.zig");

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;
const SummaryLine = tui_mod.SummaryLine;

const ZAPRET_DIR = "/opt/zapret";
const SERVICE_NAME = "nfqws-mtproto";
const NFQUEUE_NUM = "200";
const INSTALL_DIR = "/opt/mtproto-proxy";

pub const NfqwsOpts = struct {
    ttl: []const u8 = "6",
    remove: bool = false,
};

/// Run in CLI mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    var opts = NfqwsOpts{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--ttl")) {
            if (args.next()) |val| opts.ttl = val;
        } else if (std.mem.eql(u8, arg, "--remove") or std.mem.eql(u8, arg, "--uninstall")) {
            opts.remove = true;
        }
    }
    try execute(ui, allocator, opts);
}

/// Run in interactive mode.
pub fn runInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    ui.section("nfqws TCP Desync (Zapret)");

    var ttl_buf: [8]u8 = undefined;
    const ttl = try ui.input(
        "Fake packet TTL",
        "Number of hops for fake packets. 4-8 works for most Russian ISPs.\nToo low = no effect, too high = breaks real connections.",
        "6",
        &ttl_buf,
    );

    if (!try ui.confirm(i18n.get(ui.lang, .confirm_proceed), true)) {
        ui.info(i18n.get(ui.lang, .aborting));
        return;
    }

    try execute(ui, allocator, .{ .ttl = ttl });
}

pub fn execute(ui: *Tui, allocator: std.mem.Allocator, opts: NfqwsOpts) !void {
    if (!sys.isRoot()) {
        ui.fail(i18n.get(ui.lang, .error_not_root));
        return;
    }

    // Read proxy port from config
    var port: []const u8 = "443";
    {
        var doc = toml.TomlDoc.load(allocator, INSTALL_DIR ++ "/config.toml") catch null;
        if (doc) |*d| {
            defer d.deinit();
            port = d.get("server", "port") orelse "443";
        }
    }

    // ── Uninstall ──
    if (opts.remove) {
        const ipt = iptablesCommands();

        ui.step("Removing nfqws-mtproto...");
        _ = sys.execForward(&.{ "systemctl", "stop", SERVICE_NAME }) catch {};
        _ = sys.execForward(&.{ "systemctl", "disable", SERVICE_NAME }) catch {};
        _ = sys.exec(allocator, &.{ "rm", "-f", "/etc/systemd/system/" ++ SERVICE_NAME ++ ".service" }) catch {};
        _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};

        // Remove iptables rules
        removeNfqwsRules(allocator, ipt.iptables);
        removeNfqwsRules(allocator, ipt.ip6tables);
        var save_cmd_buf: [512]u8 = undefined;
        const save_cmd = std.fmt.bufPrint(&save_cmd_buf, "{s} > /etc/iptables/rules.v4 2>/dev/null; {s} > /etc/iptables/rules.v6 2>/dev/null", .{
            ipt.iptables_save,
            ipt.ip6tables_save,
        }) catch "";
        if (save_cmd.len > 0) {
            _ = sys.exec(allocator, &.{ "bash", "-c", save_cmd }) catch {};
        }

        ui.ok("nfqws-mtproto removed");
        return;
    }

    // ── Install dependencies ──
    ui.step("Installing build dependencies...");
    if (!runLogged(ui, allocator, &.{ "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", "DPkg::Lock::Timeout=600", "update", "-qq" }, "apt-get update failed")) return;
    if (!runLogged(ui, allocator, &.{
        "env",
        "DEBIAN_FRONTEND=noninteractive",
        "apt-get",
        "-o",
        "DPkg::Lock::Timeout=600",
        "-o",
        "Dpkg::Options::=--force-confdef",
        "-o",
        "Dpkg::Options::=--force-confold",
        "install",
        "-y",
        "build-essential",
        "gcc",
        "g++",
        "cpp",
        "make",
        "binutils",
        "libc6-dev",
        "git",
        "libnetfilter-queue-dev",
        "libnfnetlink-dev",
        "libcap-dev",
        "iptables",
        "libmnl-dev",
        "zlib1g-dev",
    }, "Failed to install nfqws build dependencies")) return;
    ui.ok("Dependencies installed");

    const ipt = iptablesCommands();

    // ── Clone and build zapret ──
    if (sys.fileExists(ZAPRET_DIR ++ "/nfq/nfqws")) {
        ui.ok("nfqws already built");
    } else {
        const cc = chooseWorkingCCompiler(ui, allocator) orelse return;

        ui.step("Cloning and building zapret...");
        _ = sys.exec(allocator, &.{ "rm", "-rf", ZAPRET_DIR }) catch {};
        if (!runLogged(ui, allocator, &.{
            "git", "clone", "--depth", "1", "https://github.com/bol-van/zapret.git", ZAPRET_DIR,
        }, "Failed to clone zapret")) return;

        _ = sys.exec(allocator, &.{ "bash", "-c", "cd " ++ ZAPRET_DIR ++ "/nfq && make clean" }) catch {};
        var make_cmd_buf: [128]u8 = undefined;
        const make_cmd = std.fmt.bufPrint(
            &make_cmd_buf,
            "cd " ++ ZAPRET_DIR ++ "/nfq && PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin make CC={s}",
            .{cc},
        ) catch "cd " ++ ZAPRET_DIR ++ "/nfq && make";
        if (!runLogged(ui, allocator, &.{
            "bash", "-c", make_cmd,
        }, "nfqws build failed")) return;

        if (!sys.fileExists(ZAPRET_DIR ++ "/nfq/nfqws")) {
            ui.fail("nfqws build finished but /opt/zapret/nfq/nfqws was not created");
            return;
        }
        ui.ok("nfqws built successfully");
    }

    // ── Configure iptables NFQUEUE ──
    ui.step("Setting up NFQUEUE rules...");
    removeNfqwsRules(allocator, ipt.iptables);
    removeNfqwsRules(allocator, ipt.ip6tables);

    if (!runLogged(ui, allocator, &.{
        ipt.iptables, "-t",          "mangle",    "-A", "OUTPUT",
        "-p",         "tcp",         "--sport",   port, "-j",
        "NFQUEUE",    "--queue-num", NFQUEUE_NUM,
    }, "Failed to apply IPv4 NFQUEUE rule")) return;
    _ = sys.exec(allocator, &.{
        ipt.ip6tables, "-t",          "mangle",    "-A", "OUTPUT",
        "-p",          "tcp",         "--sport",   port, "-j",
        "NFQUEUE",     "--queue-num", NFQUEUE_NUM,
    }) catch {};

    if (!outputRuleContains(allocator, ipt.iptables, "NFQUEUE")) {
        ui.fail("IPv4 NFQUEUE rule was not installed");
        return;
    }

    var save_cmd_buf: [512]u8 = undefined;
    const save_cmd = std.fmt.bufPrint(&save_cmd_buf, "mkdir -p /etc/iptables && {s} > /etc/iptables/rules.v4 && {s} > /etc/iptables/rules.v6", .{
        ipt.iptables_save,
        ipt.ip6tables_save,
    }) catch "";
    if (save_cmd.len > 0) {
        _ = sys.exec(allocator, &.{ "bash", "-c", save_cmd }) catch {};
    }
    ui.ok("NFQUEUE rules applied (queue " ++ NFQUEUE_NUM ++ ")");

    // ── Create systemd service ──
    ui.step("Creating systemd service...");
    var svc_buf: [3072]u8 = undefined;
    const svc_content = std.fmt.bufPrint(&svc_buf,
        \\[Unit]
        \\Description=nfqws TCP desync for MTProto proxy
        \\After=network.target
        \\Before=mtproto-proxy.service
        \\
        \\[Service]
        \\Type=simple
        \\ExecStartPre=-{[iptables]s} -t mangle -D OUTPUT -p tcp --sport {[port]s} -j NFQUEUE --queue-num {[queue]s}
        \\ExecStartPre=-{[ip6tables]s} -t mangle -D OUTPUT -p tcp --sport {[port]s} -j NFQUEUE --queue-num {[queue]s}
        \\ExecStartPre={[iptables]s} -t mangle -A OUTPUT -p tcp --sport {[port]s} -j NFQUEUE --queue-num {[queue]s}
        \\ExecStartPre=-{[ip6tables]s} -t mangle -A OUTPUT -p tcp --sport {[port]s} -j NFQUEUE --queue-num {[queue]s}
        \\ExecStart={[zapret_dir]s}/nfq/nfqws \
        \\    --qnum={[queue]s} \
        \\    --dpi-desync=fake,split2 \
        \\    --dpi-desync-ttl={[ttl]s} \
        \\    --dpi-desync-split-pos=1 \
        \\    --dpi-desync-fooling=md5sig
        \\Restart=always
        \\RestartSec=5
        \\CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
        \\AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
        \\NoNewPrivileges=true
        \\ProtectSystem=strict
        \\ProtectHome=true
        \\PrivateTmp=true
        \\
        \\[Install]
        \\WantedBy=multi-user.target
    , .{
        .iptables = ipt.iptables,
        .ip6tables = ipt.ip6tables,
        .port = port,
        .zapret_dir = ZAPRET_DIR,
        .queue = NFQUEUE_NUM,
        .ttl = opts.ttl,
    }) catch "";

    if (svc_content.len > 0) {
        sys.writeFile("/etc/systemd/system/" ++ SERVICE_NAME ++ ".service", svc_content) catch {
            ui.fail("Failed to write systemd service");
            return;
        };
    }

    _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};
    _ = sys.exec(allocator, &.{ "systemctl", "enable", SERVICE_NAME }) catch {};
    _ = sys.execForward(&.{ "systemctl", "restart", SERVICE_NAME }) catch {};

    if (sys.isServiceActive(SERVICE_NAME)) {
        ui.ok("nfqws service started");
    } else {
        ui.warn("nfqws may have failed to start");
    }

    // ── Summary ──
    ui.summaryBox("nfqws TCP Desync Configured", &.{
        .{ .label = "Binary:", .value = ZAPRET_DIR ++ "/nfq/nfqws" },
        .{ .label = "Service:", .value = SERVICE_NAME },
        .{ .label = "Queue:", .value = "NFQUEUE #" ++ NFQUEUE_NUM },
        .{ .label = "TTL:", .value = opts.ttl },
        .{ .label = "", .style = .blank },
        .{ .label = "Strategy: fake + split2", .style = .highlight },
        .{ .label = "Fake TLS → DPI sees valid handshake", .style = .success },
        .{ .label = "Split at byte 1 → DPI can't reassemble", .style = .success },
        .{ .label = "MD5sig fooling → fake never reaches client", .style = .success },
    });
}

const IptablesCommands = struct {
    iptables: []const u8,
    ip6tables: []const u8,
    iptables_save: []const u8,
    ip6tables_save: []const u8,
};

fn iptablesCommands() IptablesCommands {
    return .{
        .iptables = sys.commandOrPath("iptables", &.{ "/usr/sbin/iptables", "/sbin/iptables" }),
        .ip6tables = sys.commandOrPath("ip6tables", &.{ "/usr/sbin/ip6tables", "/sbin/ip6tables" }),
        .iptables_save = sys.commandOrPath("iptables-save", &.{ "/usr/sbin/iptables-save", "/sbin/iptables-save" }),
        .ip6tables_save = sys.commandOrPath("ip6tables-save", &.{ "/usr/sbin/ip6tables-save", "/sbin/ip6tables-save" }),
    };
}

fn chooseWorkingCCompiler(ui: *Tui, allocator: std.mem.Allocator) ?[]const u8 {
    if (sys.fileExists("/usr/bin/gcc")) return "/usr/bin/gcc";
    if (sys.commandExists("gcc")) return "gcc";

    ui.warn("GCC not found after dependency install; reinstalling GCC toolchain...");
    if (!repairGccToolchain(ui, allocator)) return null;

    if (sys.fileExists("/usr/bin/gcc")) return "/usr/bin/gcc";
    if (sys.commandExists("gcc")) return "gcc";

    ui.fail("GCC is required to build nfqws but was not found");
    ui.info("On Debian install it with: apt-get install gcc build-essential");
    return null;
}

fn repairGccToolchain(ui: *Tui, allocator: std.mem.Allocator) bool {
    _ = sys.exec(allocator, &.{ "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", "DPkg::Lock::Timeout=600", "update", "-qq" }) catch {};

    if (!runLogged(ui, allocator, &.{
        "env",
        "DEBIAN_FRONTEND=noninteractive",
        "apt-get",
        "-o",
        "DPkg::Lock::Timeout=600",
        "-o",
        "Dpkg::Options::=--force-confdef",
        "-o",
        "Dpkg::Options::=--force-confold",
        "install",
        "--reinstall",
        "-y",
        "build-essential",
        "gcc",
        "g++",
        "cpp",
        "make",
        "binutils",
        "libc6-dev",
    }, "Failed to reinstall GCC toolchain")) return false;

    reinstallVersionedGccPackages(ui, allocator);
    return true;
}

fn reinstallVersionedGccPackages(ui: *Tui, allocator: std.mem.Allocator) void {
    const result = sys.exec(allocator, &.{ "gcc", "-dumpversion" }) catch return;
    defer result.deinit();
    if (result.exit_code != 0) return;

    const version = std.mem.trim(u8, result.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
    var dot_pos = std.mem.indexOfScalar(u8, version, '.') orelse version.len;
    if (dot_pos == 0) return;
    dot_pos = @min(dot_pos, 8);
    const major = version[0..dot_pos];
    for (major) |c| {
        if (!std.ascii.isDigit(c)) return;
    }

    var gcc_pkg_buf: [32]u8 = undefined;
    var cpp_pkg_buf: [32]u8 = undefined;
    const gcc_pkg = std.fmt.bufPrint(&gcc_pkg_buf, "gcc-{s}", .{major}) catch return;
    const cpp_pkg = std.fmt.bufPrint(&cpp_pkg_buf, "cpp-{s}", .{major}) catch return;

    const reinstall = sys.exec(allocator, &.{
        "env",
        "DEBIAN_FRONTEND=noninteractive",
        "apt-get",
        "-o",
        "DPkg::Lock::Timeout=600",
        "install",
        "--reinstall",
        "-y",
        gcc_pkg,
        cpp_pkg,
    }) catch return;
    defer reinstall.deinit();
    if (reinstall.exit_code != 0) {
        ui.warn("Versioned GCC package reinstall was skipped");
    }
}

fn removeNfqwsRules(allocator: std.mem.Allocator, ipt: []const u8) void {
    // Remove any existing NFQUEUE rules for our queue number
    var cmd_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(
        &cmd_buf,
        "{s} -t mangle -S OUTPUT 2>/dev/null | grep 'NFQUEUE --queue-num {s}' | while read -r line; do rule=$(echo \"$line\" | sed 's/-A /-D /'); {s} -t mangle $rule 2>/dev/null || true; done",
        .{ ipt, NFQUEUE_NUM, ipt },
    ) catch return;
    _ = sys.exec(allocator, &.{ "bash", "-c", cmd }) catch {};
}

fn outputRuleContains(allocator: std.mem.Allocator, ipt: []const u8, needle: []const u8) bool {
    const result = sys.exec(allocator, &.{ ipt, "-t", "mangle", "-S", "OUTPUT" }) catch return false;
    defer result.deinit();
    if (result.exit_code != 0) return false;
    return std.mem.indexOf(u8, result.stdout, needle) != null;
}

fn runLogged(ui: *Tui, allocator: std.mem.Allocator, argv: []const []const u8, failure_msg: []const u8) bool {
    const result = sys.exec(allocator, argv) catch |err| {
        ui.fail(failure_msg);
        ui.print("  {s}◆{s} Failed to spawn command: {s}\n", .{ Color.info, Color.reset, @errorName(err) });
        return false;
    };
    defer result.deinit();

    if (result.exit_code == 0) return true;

    ui.fail(failure_msg);
    printCommandOutput(ui, &result);
    return false;
}

fn printCommandOutput(ui: *Tui, result: *const sys.ExecResult) void {
    const stderr = std.mem.trim(u8, result.stderr, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (stderr.len > 0) {
        ui.print("  stderr:\n{s}\n", .{tailBytes(stderr, 4096)});
    }

    const stdout = std.mem.trim(u8, result.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (stdout.len > 0) {
        ui.print("  stdout:\n{s}\n", .{tailBytes(stdout, 4096)});
    }
}

fn tailBytes(bytes: []const u8, max_len: usize) []const u8 {
    if (bytes.len <= max_len) return bytes;
    return bytes[bytes.len - max_len ..];
}
