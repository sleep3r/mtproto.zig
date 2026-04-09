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
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.ArgIterator) !void {
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
        ui.step("Removing nfqws-mtproto...");
        _ = sys.execForward(&.{ "systemctl", "stop", SERVICE_NAME }) catch {};
        _ = sys.execForward(&.{ "systemctl", "disable", SERVICE_NAME }) catch {};
        _ = sys.exec(allocator, &.{ "rm", "-f", "/etc/systemd/system/" ++ SERVICE_NAME ++ ".service" }) catch {};
        _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};

        // Remove iptables rules
        removeNfqwsRules(allocator, "iptables");
        removeNfqwsRules(allocator, "ip6tables");
        _ = sys.exec(allocator, &.{ "bash", "-c", "iptables-save > /etc/iptables/rules.v4 2>/dev/null; ip6tables-save > /etc/iptables/rules.v6 2>/dev/null" }) catch {};

        ui.ok("nfqws-mtproto removed");
        return;
    }

    // ── Install dependencies ──
    ui.step("Installing build dependencies...");
    _ = sys.execForward(&.{ "apt-get", "update", "-qq" }) catch {};
    _ = sys.execForward(&.{
        "apt-get", "install", "-y", "build-essential", "git",
        "libnetfilter-queue-dev", "libcap-dev", "iptables", "libmnl-dev", "zlib1g-dev",
    }) catch {};
    ui.ok("Dependencies installed");

    // ── Clone and build zapret ──
    if (sys.fileExists(ZAPRET_DIR ++ "/nfq/nfqws")) {
        ui.ok("nfqws already built");
    } else {
        ui.step("Cloning and building zapret...");
        _ = sys.exec(allocator, &.{ "rm", "-rf", ZAPRET_DIR }) catch {};
        const build_result = sys.execForward(&.{
            "bash", "-c",
            "git clone --depth 1 https://github.com/bol-van/zapret.git " ++ ZAPRET_DIR ++
                " && cd " ++ ZAPRET_DIR ++ "/nfq && make clean >/dev/null 2>&1 || true && make >/dev/null 2>&1",
        }) catch {
            ui.fail("nfqws build failed");
            return;
        };
        if (build_result != 0 or !sys.fileExists(ZAPRET_DIR ++ "/nfq/nfqws")) {
            ui.fail("nfqws build failed");
            return;
        }
        ui.ok("nfqws built successfully");
    }

    // ── Configure iptables NFQUEUE ──
    ui.step("Setting up NFQUEUE rules...");
    removeNfqwsRules(allocator, "iptables");
    removeNfqwsRules(allocator, "ip6tables");

    _ = sys.exec(allocator, &.{
        "iptables", "-t", "mangle", "-A", "OUTPUT",
        "-p", "tcp", "--sport", port,
        "-j", "NFQUEUE", "--queue-num", NFQUEUE_NUM,
    }) catch {};
    _ = sys.exec(allocator, &.{
        "ip6tables", "-t", "mangle", "-A", "OUTPUT",
        "-p", "tcp", "--sport", port,
        "-j", "NFQUEUE", "--queue-num", NFQUEUE_NUM,
    }) catch {};

    _ = sys.exec(allocator, &.{ "bash", "-c", "mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4 && ip6tables-save > /etc/iptables/rules.v6" }) catch {};
    ui.ok("NFQUEUE rules applied (queue " ++ NFQUEUE_NUM ++ ")");

    // ── Create systemd service ──
    ui.step("Creating systemd service...");
    var svc_buf: [2048]u8 = undefined;
    const svc_content = std.fmt.bufPrint(&svc_buf,
        \\[Unit]
        \\Description=nfqws TCP desync for MTProto proxy
        \\After=network.target
        \\Before=mtproto-proxy.service
        \\
        \\[Service]
        \\Type=simple
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
    , .{ .zapret_dir = ZAPRET_DIR, .queue = NFQUEUE_NUM, .ttl = opts.ttl }) catch "";

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

fn removeNfqwsRules(allocator: std.mem.Allocator, ipt: []const u8) void {
    // Remove any existing NFQUEUE rules for our queue number
    var cmd_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf,
        "{s} -t mangle -S OUTPUT 2>/dev/null | grep 'NFQUEUE --queue-num {s}' | while read -r line; do rule=$(echo \"$line\" | sed 's/-A /-D /'); {s} -t mangle $rule 2>/dev/null || true; done",
        .{ ipt, NFQUEUE_NUM, ipt },
    ) catch return;
    _ = sys.exec(allocator, &.{ "bash", "-c", cmd }) catch {};
}
