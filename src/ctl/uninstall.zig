const std = @import("std");
const tui_mod = @import("tui.zig");
const sys = @import("sys.zig");
const i18n = @import("i18n.zig");
const toml = @import("toml.zig");
const tunnel = @import("tunnel.zig");
const tunnel_wg = @import("tunnel_wg.zig");

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

    // Same reason, same ordering: the tunnel pool lives in that config.toml and is the
    // only record of which interfaces this proxy ever routed through. `rm -rf /opt`
    // below would take it with it, and the tunnel teardown runs after that.
    const tunnel_pool = tunnel.loadConfiguredTunnelPool(allocator) catch &[_][]const u8{};
    defer tunnel_wg.freeOwnedStringSlice(allocator, tunnel_pool);

    // 1. Stop and disable all associated systemd services
    const services = &[_][]const u8{
        "mtproto-proxy",
        "proxy-monitor",
        "nfqws-mtproto",
        "mtproto-syn-limit",
        "mtproto-tcpmss",
        "mtproto-mask-health.timer",
        "mtproto-mask-health.service",
        "mtproto-tunnel-pool.timer",
        "mtproto-tunnel-pool.service",
        "mtproto-singbox-egress.service",
        "mtproto-web-relay",
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
    // Both the config and the copy `mtbuddy update`'s egress repair keeps beside it. That
    // .bak is not clutter: it is a full sing-box config, so it carries the share links —
    // server addresses, passwords, obfs passwords — and leaving it behind means an
    // uninstall leaves credentials on disk.
    _ = sys.execForward(&.{ "rm", "-f", "/etc/mtproto-proxy/singbox-egress.json", "/etc/mtproto-proxy/singbox-egress.json.bak" }) catch {};
    _ = sys.execForward(&.{ "rm", "-f", "/usr/local/bin/mtproto-singbox-route.sh" }) catch {};
    _ = sys.execForward(&.{ "rm", "-f", "/usr/local/bin/sing-box" }) catch {};
    // rmdir, not rm -rf: it removes the directory only once it is empty, so anything an
    // operator put there of their own is left alone rather than silently deleted.
    // Wrapped like the nginx drop-in rmdir below, because a deploy that never created
    // the directory would otherwise print "No such file or directory" on every uninstall.
    _ = sys.execForward(&.{ "bash", "-c", "rmdir --ignore-fail-on-non-empty /etc/mtproto-proxy 2>/dev/null || true" }) catch {};

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

    // Bring down the WG/AmneziaWG interfaces mtbuddy set up and remove their configs.
    // The egress feature writes VPN provider PRIVATE KEYS to /etc/amnezia/**.conf
    // (0600) and brings up awg0..N; leaving those up keeps live tunnels and leaves the
    // provider's keys on disk after "uninstall succeeded".
    //
    // What this must NOT do is what it used to: glob every *.conf in /etc/amnezia and
    // /etc/wireguard, tear each interface down, and `rm -rf /etc/amnezia`. mtbuddy
    // shares AmneziaWG's own directory, so that took an operator's pre-existing awg1 —
    // its config, its keys, its running interface — with it (issue #402). Scope now: only
    // configs carrying mtbuddy's ownership banner. Anything else stays exactly as it is,
    // interface up and file untouched, and is named at the end of the run if this proxy
    // was routing through it.
    var kept_configs: std.ArrayList([]const u8) = .empty;
    defer {
        for (kept_configs.items) |item| allocator.free(item);
        kept_configs.deinit(allocator);
    }
    {
        // Enumerate the two directories mtbuddy ever writes a tunnel config into rather
        // than trusting the pool alone: a host whose config.toml was hand-edited or lost
        // would otherwise leave our own configs — and their private keys — behind. The
        // banner is what decides, so widening the search cannot widen the damage.
        const listing = sys.exec(allocator, &.{
            "find",      "/etc/amnezia/amneziawg", "/etc/wireguard",
            "-maxdepth", "1",                      "-type",
            "f",         "-name",                  "*.conf",
            "-print",
        }) catch null;
        defer if (listing) |l| l.deinit();

        const awg_down = sys.commandOrPath("awg-quick", &.{ "/usr/bin/awg-quick", "/usr/local/bin/awg-quick" });
        const wg_down = sys.commandOrPath("wg-quick", &.{ "/usr/bin/wg-quick", "/usr/local/bin/wg-quick" });

        var lines = std.mem.splitScalar(u8, if (listing) |l| l.stdout else "", '\n');
        while (lines.next()) |raw| {
            const conf = std.mem.trim(u8, raw, &[_]u8{ ' ', '\t', '\r' });
            if (conf.len == 0 or !sys.fileExists(conf)) continue;

            const base = std.fs.path.basename(conf);
            if (!std.mem.endsWith(u8, base, ".conf")) continue;
            const iface = base[0 .. base.len - ".conf".len];
            if (!tunnel_wg.isValidTunnelInterfaceName(iface)) continue;

            if (!tunnel_wg.configIsOwned(allocator, conf)) {
                // Report only what this proxy actually routed through. A config that was
                // never in the pool is none of mtbuddy's business, not even to mention.
                if (tunnel_wg.containsInterface(tunnel_pool, iface)) {
                    kept_configs.append(allocator, allocator.dupe(u8, conf) catch continue) catch {};
                }
                continue;
            }

            // Quiet: `down` on an interface that is not up is a normal outcome here.
            sys.execSilent(allocator, &.{ awg_down, "down", conf });
            sys.execSilent(allocator, &.{ wg_down, "down", conf });
            sys.execSilent(allocator, &.{ "ip", "link", "del", iface });
            _ = sys.execForward(&.{ "rm", "-f", conf }) catch {};
        }
    }
    // A pool member whose config is already gone is a leftover of ours — `setup tunnel`
    // never accepts an interface without a config source, so there is no operator
    // interface this can be. Drop the dangling link; nothing else will.
    for (tunnel_pool) |iface| {
        if (!tunnel_wg.isValidTunnelInterfaceName(iface)) continue;
        if (tunnel.hasForeignConfig(allocator, iface)) continue;
        var awg_buf: [256]u8 = undefined;
        var wg_buf: [256]u8 = undefined;
        const awg_conf = tunnel_wg.awgConfigPath(&awg_buf, iface) catch "";
        const wg_conf = std.fmt.bufPrint(&wg_buf, "/etc/wireguard/{s}.conf", .{iface}) catch "";
        if (sys.fileExists(awg_conf) or sys.fileExists(wg_conf)) continue;
        sys.execSilent(allocator, &.{ "ip", "link", "del", iface });
    }
    // /etc/amnezia/awg0.conf is a symlink `setup tunnel` creates and nothing else does,
    // and the staging files are ours too — a `setup egress` that failed part-way leaves
    // one behind, holding a provider private key at 0600.
    _ = sys.execForward(&.{ "bash", "-c", "[ -L /etc/amnezia/awg0.conf ] && rm -f /etc/amnezia/awg0.conf; rm -f /etc/amnezia/.mtbuddy-stage-*.conf; exit 0" }) catch {};
    // rmdir, not rm -rf: the directories go only once they are empty, so an operator's
    // own configs — and the rest of an Amnezia install — survive. Same discipline as
    // /etc/mtproto-proxy above. Child first, then the parent.
    _ = sys.execForward(&.{ "bash", "-c", "rmdir --ignore-fail-on-non-empty /etc/amnezia/amneziawg /etc/amnezia 2>/dev/null || true" }) catch {};

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
    // WEB proxy relay vhosts (TLS + the port-80 ACME responder) and its renewal hook.
    // The Let's Encrypt certificate itself is left alone: it belongs to a domain the
    // operator owns and may still be in use elsewhere.
    _ = sys.execForward(&.{ "rm", "-f", "/etc/nginx/sites-enabled/mtproto-web", "/etc/nginx/sites-available/mtproto-web", "/etc/nginx/sites-enabled/mtproto-web-acme", "/etc/nginx/sites-available/mtproto-web-acme", "/etc/letsencrypt/renewal-hooks/deploy/mtproto-web-reload.sh" }) catch {};
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
    //    The clamp now also owns mtproto-tcpmss.service (stopped/removed with the other
    //    units above, which runs its `flush`); this sweep still runs so a rule left by a
    //    pre-unit install, or by a unit that failed to stop, is removed too.
    const tcpmss_cleanup =
        \\for ipt in iptables ip6tables; do
        \\  "$ipt" -t mangle -S OUTPUT 2>/dev/null | grep -E -- '-j (TCPMSS --set-mss [0-9]+|NFQUEUE --queue-num [0-9]+)' | while read -r line; do
        \\    rule=$(printf '%s' "$line" | sed 's/^-A /-D /')
        \\    "$ipt" -t mangle $rule 2>/dev/null || true
        \\  done
        \\done
        \\rm -f /usr/local/sbin/mtproto-tcpmss.sh
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

    // Said after the spinner, not under it, and deliberately not phrased as a failure:
    // these files are still there because mtbuddy is not sure it created them, which is
    // the whole point of the change. An operator who wants them gone needs the paths.
    if (kept_configs.items.len > 0) {
        ui.writeRaw("\n");
        ui.warn(tr(
            ui,
            "Left in place — mtbuddy did not create these tunnel configs (adopted with --iface, or set up before ownership was tracked):",
            "Оставлено без изменений — эти конфиги туннелей mtbuddy не создавал (приняты через --iface или заведены до появления пометки):",
        ));
        for (kept_configs.items) |conf| {
            ui.print("    {s}{s}{s}\n", .{ Color.dim, conf, Color.reset });
        }
        ui.hint(tr(
            ui,
            "Their interfaces are still up. They may hold VPN private keys — remove them yourself if they were only for the proxy.",
            "Их интерфейсы всё ещё подняты. В них могут быть приватные ключи VPN — удалите вручную, если они были нужны только для прокси.",
        ));
    }
}

fn tr(ui: *const Tui, en: []const u8, ru: []const u8) []const u8 {
    return switch (ui.lang) {
        .en => en,
        .ru => ru,
    };
}
