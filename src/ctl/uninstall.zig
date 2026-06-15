const std = @import("std");
const tui_mod = @import("tui.zig");
const sys = @import("sys.zig");
const i18n = @import("i18n.zig");
const toml = @import("toml.zig");

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

pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) void {
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
    if (!sys.isRoot()) {
        ui.fail(ui.str(.error_not_root));
        return;
    }

    ui.writeRaw("\n");
    ui.rule();

    var sp = ui.spinner(ui.str(.uninstall_in_progress));
    sp.start();

    // Read the configured listen port BEFORE we delete /opt, so we can revert
    // the port-specific ufw rule the installer added.
    var port_buf: [8]u8 = undefined;
    var configured_port: []const u8 = "443";
    {
        var doc = toml.TomlDoc.load(allocator, "/opt/mtproto-proxy/config.toml") catch null;
        if (doc) |*d| {
            defer d.deinit();
            if (d.get("server", "port")) |p| {
                const copy_len = @min(p.len, port_buf.len);
                @memcpy(port_buf[0..copy_len], p[0..copy_len]);
                configured_port = port_buf[0..copy_len];
            }
        }
    }

    // 1. Stop and disable all associated systemd services
    const services = &[_][]const u8{
        "mtproto-proxy",
        "proxy-monitor",
        "nfqws-mtproto",
        "mtproto-syn-limit",
        "mtproto-mask-health.timer",
        "mtproto-mask-health.service",
        "mtproto-tunnel-pool.timer",
        "mtproto-tunnel-pool.service",
        "mtproto-singbox-egress.service",
    };
    for (services) |svc| {
        // Quiet: this runs under a spinner and most of these units aren't present in any
        // given deploy, so `stop`/`disable` would spew "Unit not loaded" / "Removed ..."
        // noise even on a perfectly clean uninstall.
        sys.execSilent(allocator, &.{ "systemctl", "stop", svc });
        sys.execSilent(allocator, &.{ "systemctl", "disable", svc });
        // Remove the unit file. Entries already carrying a `.timer`/`.service` suffix are
        // full unit names; bare ones (e.g. "mtproto-proxy") get `.service` appended. The
        // old code always appended `.service`, so "mtproto-mask-health.service" tried to
        // delete "...service.service" and left the real file behind.
        var path_buf: [160]u8 = undefined;
        const path = if (std.mem.indexOfScalar(u8, svc, '.') != null)
            std.fmt.bufPrint(&path_buf, "/etc/systemd/system/{s}", .{svc}) catch continue
        else
            std.fmt.bufPrint(&path_buf, "/etc/systemd/system/{s}.service", .{svc}) catch continue;
        _ = sys.execForward(&.{ "rm", "-f", path }) catch {};
    }

    // sing-box tunnel egress provider artifacts (upstream.type=tunnel via sbx0).
    _ = sys.execForward(&.{ "rm", "-f", "/etc/systemd/system/mtproto-singbox-egress.service" }) catch {};
    _ = sys.execForward(&.{ "rm", "-f", "/etc/mtproto-proxy/singbox-egress.json" }) catch {};
    _ = sys.execForward(&.{ "rm", "-f", "/usr/local/bin/mtproto-singbox-route.sh" }) catch {};
    _ = sys.execForward(&.{ "rm", "-f", "/usr/local/bin/sing-box" }) catch {};

    _ = sys.execForward(&.{ "rm", "-f", "/etc/systemd/system/mtproto-mask-health.timer" }) catch {};
    // recovery.zig installs this script; update.zig treats its mere existence as "recovery
    // is installed" and silently re-enables the whole timer stack. Remove it on uninstall
    // so a later reinstall+update doesn't resurrect recovery.
    _ = sys.execForward(&.{ "rm", "-f", "/usr/local/bin/mtproto-mask-health.sh" }) catch {};
    _ = sys.execForward(&.{ "rm", "-f", "/etc/systemd/system/mtproto-tunnel-pool.timer" }) catch {};
    _ = sys.execForward(&.{ "rm", "-f", "/etc/systemd/system/mtproto-tunnel-pool.service" }) catch {};

    // Remove the systemd drop-ins recovery.zig may have written. Only delete our
    // own files; rmdir the nginx drop-in dir only if it ends up empty so we don't
    // clobber unrelated operator drop-ins.
    _ = sys.execForward(&.{ "rm", "-f", "/etc/systemd/system/nginx.service.d/restart.conf" }) catch {};
    _ = sys.execForward(&.{ "bash", "-c", "rmdir /etc/systemd/system/nginx.service.d 2>/dev/null || true" }) catch {};
    _ = sys.execForward(&.{ "rm", "-rf", "/etc/systemd/system/mtproto-proxy.service.d" }) catch {};

    _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};

    // 2. Remove directories
    _ = sys.execForward(&.{ "rm", "-rf", "/opt/mtproto-proxy" }) catch {};
    _ = sys.execForward(&.{ "rm", "-rf", "/opt/zapret" }) catch {};

    // 3. Remove user
    const userdel = sys.commandOrPath("userdel", &.{ "/usr/sbin/userdel", "/sbin/userdel" });
    sys.execSilent(allocator, &.{ userdel, "mtproto" });

    // 4. Cleanup tunnel routing artifacts (new + legacy). Loop the rule delete: the
    //    sing-box egress adds an unprioritized `fwmark 200 lookup 200` rule while the awg
    //    pool adds a prioritized one, so several matching rules may exist.
    _ = sys.execForward(&.{ "bash", "-c", "while ip -4 rule del fwmark 200 table 200 2>/dev/null; do :; done; while ip -4 rule del fwmark 200 lookup 200 2>/dev/null; do :; done" }) catch {};
    // Quiet: an empty/absent table 200 or netns makes these print "FIB table does not
    // exist" / "Cannot remove namespace" even though there's simply nothing to clean.
    sys.execSilent(allocator, &.{ "ip", "-4", "route", "flush", "table", "200" });
    _ = sys.execForward(&.{ "rm", "-f", "/usr/local/bin/setup_tunnel.sh" }) catch {};
    _ = sys.execForward(&.{ "rm", "-f", "/usr/local/bin/setup_netns.sh" }) catch {};
    sys.execSilent(allocator, &.{ "ip", "netns", "del", "tg_proxy_ns" });

    // Bring down WG/AmneziaWG tunnel interfaces and remove their configs. The egress
    // feature writes VPN provider PRIVATE KEYS to /etc/amnezia/**.conf (0600) and brings
    // up awg0..N; leaving them up keeps live tunnels and leaves the provider's keys on
    // disk after "uninstall succeeded". Best-effort down + ip link del + rm the configs.
    const tunnel_teardown =
        \\for conf in /etc/amnezia/amneziawg/*.conf /etc/amnezia/awg*.conf /etc/wireguard/awg*.conf; do
        \\  [ -f "$conf" ] || continue
        \\  iface=$(basename "$conf" .conf)
        \\  command -v awg-quick >/dev/null 2>&1 && awg-quick down "$conf" 2>/dev/null || true
        \\  command -v wg-quick  >/dev/null 2>&1 && wg-quick  down "$conf" 2>/dev/null || true
        \\  ip link del "$iface" 2>/dev/null || true
        \\done
        \\rm -rf /etc/amnezia 2>/dev/null || true
    ;
    _ = sys.execForward(&.{ "bash", "-c", tunnel_teardown }) catch {};

    // 5. Remove masking config. The site name MUST match masking.zig
    //    ("mtproto-masking"); the old "mtproto-mask" name never matched the
    //    installed vhost, so it was left enabled while its cert was deleted,
    //    breaking every later nginx reload.
    _ = sys.execForward(&.{ "rm", "-f", "/etc/nginx/sites-enabled/mtproto-masking" }) catch {};
    _ = sys.execForward(&.{ "rm", "-f", "/etc/nginx/sites-available/mtproto-masking" }) catch {};
    // Legacy name from older installs (best-effort).
    _ = sys.execForward(&.{ "rm", "-f", "/etc/nginx/sites-enabled/mtproto-mask" }) catch {};
    _ = sys.execForward(&.{ "rm", "-f", "/etc/nginx/sites-available/mtproto-mask" }) catch {};
    _ = sys.execForward(&.{ "rm", "-rf", "/etc/nginx/ssl/mtproto" }) catch {};
    // The masking installer disables the default site; restore it so nginx has a
    // valid vhost again instead of a dangling (now deleted) masking config.
    _ = sys.execForward(&.{ "bash", "-c", "[ -f /etc/nginx/sites-available/default ] && ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default || true" }) catch {};

    // Attempt Nginx reload if active, to flush deleted configs
    if (sys.isServiceActive("nginx")) {
        sys.execSilent(allocator, &.{ "systemctl", "try-reload-or-restart", "nginx" });
    }

    // 6. Clear the TCPMSS SYN/ACK clamp the installer set. The install rule
    //    carries `--sport <port>`, so a `-D` without it never matches. List the
    //    live rules and replay them as deletes (exact match), for BOTH IPv4 and
    //    IPv6, then re-persist rules.v4/v6 so the clamp doesn't return on reboot.
    //    Match any `--set-mss <n>` (not just the default 88) so a custom
    //    `--tcpmss <n>` clamp is also removed.
    //    Also replay-delete any orphaned nfqws NFQUEUE rule: its unit adds the rule in
    //    ExecStartPre with no ExecStopPost, so stopping the (now-removed) unit leaves the
    //    `-j NFQUEUE --queue-num 200` rule live — and the iptables-save below would
    //    otherwise re-persist that dead rule across reboots.
    const tcpmss_cleanup =
        \\for ipt in iptables ip6tables; do
        \\  "$ipt" -t mangle -S OUTPUT 2>/dev/null | grep -E -- '-j (TCPMSS --set-mss [0-9]+|NFQUEUE --queue-num [0-9]+)' | while read -r line; do
        \\    rule=$(printf '%s' "$line" | sed 's/^-A /-D /')
        \\    "$ipt" -t mangle $rule 2>/dev/null || true
        \\  done
        \\done
        \\if [ -d /etc/iptables ]; then
        \\  command -v iptables-save >/dev/null 2>&1 && iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        \\  command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
        \\fi
    ;
    _ = sys.execForward(&.{ "bash", "-c", tcpmss_cleanup }) catch {};

    // Clear the optional kernel SYN rate-limiter (mtbuddy setup syn-limit). The unit was
    // already stopped/removed in the services loop above; here we tear down its live
    // iptables chain (both families) by replay-deleting every INPUT jump to it — robust
    // to a --dport that changed since apply — then flush + delete the chain and remove
    // the generated apply/flush script.
    const synlimit_cleanup =
        \\for ipt in iptables ip6tables; do
        \\  "$ipt" -S INPUT 2>/dev/null | grep -- '-j MTPROTO_SYNLIMIT' | while read -r line; do
        \\    rule=$(printf '%s' "$line" | sed 's/^-A /-D /')
        \\    "$ipt" $rule 2>/dev/null || true
        \\  done
        \\  "$ipt" -F MTPROTO_SYNLIMIT 2>/dev/null || true
        \\  "$ipt" -X MTPROTO_SYNLIMIT 2>/dev/null || true
        \\done
        \\rm -f /usr/local/sbin/mtproto-syn-limit.sh
    ;
    _ = sys.execForward(&.{ "bash", "-c", synlimit_cleanup }) catch {};

    // Revert the port-specific ufw allow rule the installer added.
    if (sys.commandExists("ufw")) {
        var ufw_buf: [16]u8 = undefined;
        const port_rule = std.fmt.bufPrint(&ufw_buf, "{s}/tcp", .{configured_port}) catch "443/tcp";
        sys.execSilent(allocator, &.{ "ufw", "delete", "allow", port_rule });
    }

    // Note: Self-removal: The mtbuddy binary is running right now. Removing it while running usually works on Linux.
    _ = sys.execForward(&.{ "bash", "-c", "[ \"$(readlink -f /usr/bin/mtbuddy 2>/dev/null)\" = /usr/local/bin/mtbuddy ] && rm -f /usr/bin/mtbuddy || true" }) catch {};
    _ = sys.execForward(&.{ "rm", "-f", "/usr/local/bin/mtbuddy" }) catch {};

    sp.stop(true, "");

    ui.writeRaw("\n");
    ui.print("  {s}{s} {s}{s}\n", .{ Color.ok, "✔", ui.str(.uninstall_success), Color.reset });
}
