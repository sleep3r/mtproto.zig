const std = @import("std");
const tui_mod = @import("tui.zig");
const sys = @import("sys.zig");
const i18n = @import("i18n.zig");

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;

pub fn runInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    ui.section(ui.str(.uninstall_header));

    // Warn the user and ask for confirmation
    const proceed = try ui.confirm(ui.str(.uninstall_warning), false);
    if (!proceed) {
        ui.print("  {s}{s}{s}\n", .{ Color.dim, ui.str(.aborting), Color.reset });
        return;
    }

    try execute(ui, allocator);
}

pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.ArgIterator) void {
    var yes_flag = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--yes") or std.mem.eql(u8, arg, "-y")) {
            yes_flag = true;
        } else {
            ui.fail("Unknown flag for uninstall. See mtbuddy --help");
            return;
        }
    }

    if (!yes_flag) {
        ui.fail("Uninstall is a destructive action. Pass --yes to confirm non-interactively.");
        return;
    }

    ui.section(ui.str(.uninstall_header));
    execute(ui, allocator) catch {};
}

fn execute(ui: *Tui, allocator: std.mem.Allocator) !void {
    _ = allocator;
    if (!sys.isRoot()) {
        ui.fail(ui.str(.error_not_root));
        return;
    }

    ui.writeRaw("\n");
    ui.rule();

    var sp = ui.spinner(ui.str(.uninstall_in_progress));
    sp.start();

    // 1. Stop and disable all associated systemd services
    const services = &[_][]const u8{
        "mtproto-proxy",
        "proxy-monitor",
        "nfqws-mtproto",
        "mtproto-mask-health.timer",
        "mtproto-mask-health.service",
    };
    for (services) |svc| {
        _ = sys.execForward(&.{ "systemctl", "stop", svc }) catch {};
        _ = sys.execForward(&.{ "systemctl", "disable", svc }) catch {};
        // Remove unit files
        var path_buf: [128]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/etc/systemd/system/{s}.service", .{svc}) catch continue;
        _ = sys.execForward(&.{ "rm", "-f", path }) catch {};
    }

    _ = sys.execForward(&.{ "rm", "-f", "/etc/systemd/system/mtproto-mask-health.timer" }) catch {};
    _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};

    // 2. Remove directories
    _ = sys.execForward(&.{ "rm", "-rf", "/opt/mtproto-proxy" }) catch {};
    _ = sys.execForward(&.{ "rm", "-rf", "/opt/zapret" }) catch {};

    // 3. Remove user
    _ = sys.execForward(&.{ "userdel", "mtproto" }) catch {};

    // 4. Cleanup tunnel routing artifacts (new + legacy)
    _ = sys.execForward(&.{ "ip", "-4", "rule", "del", "fwmark", "200", "table", "200" }) catch {};
    _ = sys.execForward(&.{ "ip", "-4", "route", "flush", "table", "200" }) catch {};
    _ = sys.execForward(&.{ "rm", "-f", "/usr/local/bin/setup_tunnel.sh" }) catch {};
    _ = sys.execForward(&.{ "rm", "-f", "/usr/local/bin/setup_netns.sh" }) catch {};
    _ = sys.execForward(&.{ "ip", "netns", "del", "tg_proxy_ns" }) catch {};

    // 5. Remove masking config if exists
    _ = sys.execForward(&.{ "rm", "-f", "/etc/nginx/sites-enabled/mtproto-mask" }) catch {};
    _ = sys.execForward(&.{ "rm", "-f", "/etc/nginx/sites-available/mtproto-mask" }) catch {};
    _ = sys.execForward(&.{ "rm", "-rf", "/etc/nginx/ssl/mtproto" }) catch {};

    // Attempt Nginx reload if active, to flush deleted configs
    if (sys.isServiceActive("nginx")) {
        _ = sys.execForward(&.{ "systemctl", "try-reload-or-restart", "nginx" }) catch {};
    }

    // 6. Attempt to clear TCPMSS iptables rules specifically set by install
    _ = sys.execForward(&.{ "bash", "-c", "while iptables -t mangle -D OUTPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -j TCPMSS --set-mss 88 2>/dev/null; do true; done" }) catch {};

    // Note: Self-removal: The mtbuddy binary is running right now. Removing it while running usually works on Linux.
    _ = sys.execForward(&.{ "rm", "-f", "/usr/local/bin/mtbuddy" }) catch {};

    sp.stop(true, "");

    ui.writeRaw("\n");
    ui.print("  {s}{s} {s}{s}\n", .{ Color.ok, "✔", ui.str(.uninstall_success), Color.reset });
}
