//! Setup auto-recovery command for mtbuddy.
//!
//! Ports setup_mask_monitor.sh (246 lines bash) — installs masking health
//! self-healing via systemd timer. Monitors nginx + mtproto-proxy health
//! and restarts services automatically on failure.

const std = @import("std");
const tui_mod = @import("tui.zig");
const i18n = @import("i18n.zig");
const sys = @import("sys.zig");

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;
const SummaryLine = tui_mod.SummaryLine;

const INSTALL_DIR = "/opt/mtproto-proxy";
const MASK_HEALTH_SCRIPT = "/usr/local/bin/mtproto-mask-health.sh";
const MASK_HEALTH_SERVICE = "/etc/systemd/system/mtproto-mask-health.service";
const MASK_HEALTH_TIMER = "/etc/systemd/system/mtproto-mask-health.timer";
const NGINX_DROPIN_DIR = "/etc/systemd/system/nginx.service.d";
const PROXY_DROPIN_DIR = "/etc/systemd/system/mtproto-proxy.service.d";

/// Health-check script installed at MASK_HEALTH_SCRIPT and run by the systemd timer.
///
/// read_censorship_value()'s awk uses `[[:space:]]` (POSIX bracket expression), never
/// `\s` — `\s` is a gawk-only regex extension. Debian/Ubuntu ship mawk as /usr/bin/awk
/// (gawk is not installed by default) and mawk/BWK awk treat `\s` as a literal `s`, so
/// the old pattern degraded to `^s*mask_ports*=` and never matched `mask_port = 8443`
/// (TomlDoc.formatKv always writes `key = value` with spaces). That silently returned
/// the "443" fallback, and the `[[ "$mask_port" == "443" ]] && exit 0` guard below then
/// skipped every probe — nginx could be dead for hours with the timer reporting active
/// and this "Auto-restart" summary box claiming coverage.
const HEALTH_SCRIPT =
    \\#!/usr/bin/env bash
    \\set -euo pipefail
    \\
    \\CONFIG_FILE="/opt/mtproto-proxy/config.toml"
    \\LOCAL_HOST_IP="127.0.0.1"
    \\
    \\read_censorship_value() {
    \\    local key="$1"
    \\    local default_value="$2"
    \\    [[ -f "$CONFIG_FILE" ]] || { printf '%s\n' "$default_value"; return; }
    \\    awk -v want_key="$key" -v fallback="$default_value" '
    \\        BEGIN { in_section=0; value="" }
    \\        /^[[:space:]]*\[censorship\][[:space:]]*$/ { in_section=1; next }
    \\        /^[[:space:]]*\[[^\]]+\][[:space:]]*$/ { in_section=0; next }
    \\        in_section { line=$0; sub(/#.*/,"",line)
    \\            if (line ~ "^[[:space:]]*" want_key "[[:space:]]*=") {
    \\                split(line,parts,"="); value=parts[2]
    \\                gsub(/^[[:space:]]+|[[:space:]]+$/,"",value); gsub(/^"|"$/,"",value)
    \\            }
    \\        }
    \\        END { print (value=="" ? fallback : value) }
    \\    ' "$CONFIG_FILE"
    \\}
    \\
    \\probe_endpoint() {
    \\    local host="$1" port="$2"
    \\    curl -sk --max-time 3 "https://${host}:${port}/" >/dev/null 2>&1
    \\}
    \\
    \\command -v systemctl >/dev/null 2>&1 || exit 0
    \\command -v curl >/dev/null 2>&1 || { logger -t mtproto-mask-health "curl not found"; exit 1; }
    \\systemctl list-unit-files --type=service --no-legend 2>/dev/null | grep -q '^nginx\.service\s' || exit 0
    \\
    \\mask_enabled=$(read_censorship_value "mask" "true" | tr '[:upper:]' '[:lower:]')
    \\case "$mask_enabled" in true|1|yes|on) ;; *) exit 0 ;; esac
    \\
    \\mask_port=$(read_censorship_value "mask_port" "443" | tr -cd '0-9')
    \\mask_port="${mask_port:-443}"
    \\[[ "$mask_port" == "443" ]] && exit 0
    \\
    \\target_host="$LOCAL_HOST_IP"
    \\
    \\if ! systemctl is-active --quiet nginx; then
    \\    logger -t mtproto-mask-health "nginx inactive, restarting"
    \\    systemctl restart nginx || true; sleep 1
    \\fi
    \\
    \\probe_endpoint "$target_host" "$mask_port" && exit 0
    \\
    \\logger -t mtproto-mask-health "endpoint ${target_host}:${mask_port} unreachable; restarting nginx"
    \\systemctl restart nginx || true; sleep 1
    \\probe_endpoint "$target_host" "$mask_port" && { logger -t mtproto-mask-health "recovered after nginx restart"; exit 0; }
    \\
    \\logger -t mtproto-mask-health "critical: endpoint still unreachable"
    \\exit 1
;

pub const RecoveryOpts = struct {
    quiet: bool = false,
};

const WEB_HEALTH_SCRIPT =
    \\#!/usr/bin/env bash
    \\set -euo pipefail
    \\read_web() {
    \\  awk -v key="$1" -v fallback="$2" '
    \\    /^\[web\]$/ { inside=1; next }
    \\    /^\[/ { inside=0 }
    \\    inside && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
    \\      sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]*#.*/, ""); gsub(/"/, ""); value=$0
    \\    }
    \\    END { print value == "" ? fallback : value }
    \\  ' /opt/mtproto-proxy/config.toml
    \\}
    \\[[ "$(read_web enabled false)" == true ]] || exit 0
    \\port=$(read_web port 8081)
    \\host=$(read_web host 127.0.0.1)
    \\domain=$(read_web domain '')
    \\[[ "$port" =~ ^[0-9]{1,5}$ ]] && ((10#$port > 0 && 10#$port < 65536)) || exit 1
    \\[[ "$host" =~ ^[0-9a-fA-F:.]+$ ]] || exit 1
    \\[[ "$domain" =~ ^[a-zA-Z0-9.-]+$ ]] || exit 1
    \\[[ "$host" == 0.0.0.0 ]] && host=127.0.0.1
    \\[[ "$host" == :: ]] && host=::1
    \\[[ "$host" == *:* ]] && host="[$host]"
    \\healthy=false
    \\for attempt in 1 2 3; do
    \\  if curl --noproxy '*' -fsS --max-time 5 "http://${host}:${port}/" >/dev/null; then healthy=true; break; fi
    \\  sleep 1
    \\done
    \\if [[ "$healthy" != true ]]; then
    \\  logger -t mtproto-web-health 'relay failed three local probes; restarting relay only'
    \\  systemctl restart mtproto-web-relay.service
    \\  exit 1
    \\fi
    \\if ! curl --noproxy '*' -fsS --max-time 8 "https://${domain}/" >/dev/null; then
    \\  logger -t mtproto-web-health 'public HTTPS path failed; check DNS, certificate and terminator'
    \\  exit 1
    \\fi
;

pub fn installWebHealth(allocator: std.mem.Allocator) !void {
    try sys.writeFileMode("/usr/local/bin/mtproto-web-health.sh", WEB_HEALTH_SCRIPT, 0o755);
    try sys.writeFile("/etc/systemd/system/mtproto-web-health.service", "[Unit]\nDescription=MTProto WEB relay health check\nAfter=network-online.target\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/mtproto-web-health.sh\nTimeoutStartSec=30\n");
    try sys.writeFile("/etc/systemd/system/mtproto-web-health.timer", "[Unit]\nDescription=Check the MTProto WEB path every minute\n\n[Timer]\nOnBootSec=2min\nOnUnitActiveSec=1min\nRandomizedDelaySec=10s\n\n[Install]\nWantedBy=timers.target\n");
    const reload = try sys.exec(allocator, &.{ "systemctl", "daemon-reload" });
    defer reload.deinit();
    if (reload.exit_code != 0) return error.SystemdReloadFailed;
    const enable = try sys.exec(allocator, &.{ "systemctl", "enable", "--now", "mtproto-web-health.timer" });
    defer enable.deinit();
    if (enable.exit_code != 0) return error.WebHealthEnableFailed;
}

test "health recovery never restarts the data plane for an endpoint failure" {
    try std.testing.expect(std.mem.indexOf(u8, HEALTH_SCRIPT, "restart mtproto-proxy") == null);
    try std.testing.expect(std.mem.indexOf(u8, WEB_HEALTH_SCRIPT, "for attempt in 1 2 3") != null);
    try std.testing.expect(std.mem.indexOf(u8, WEB_HEALTH_SCRIPT, "restart mtproto-web-relay.service") != null);
    try std.testing.expect(std.mem.indexOf(u8, WEB_HEALTH_SCRIPT, "restart mtproto-proxy") == null);
}

/// Run in CLI mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    var opts = RecoveryOpts{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--quiet")) {
            opts.quiet = true;
        } else {
            ui.print("Unknown option: {s}\n", .{arg});
            return error.UnknownOption;
        }
    }
    try execute(ui, allocator, opts);
}

/// Run in interactive mode.
pub fn runInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    ui.section(i18n.get(ui.lang, .menu_setup_recovery));

    if (!try ui.confirm(i18n.get(ui.lang, .confirm_proceed), true)) {
        ui.info(i18n.get(ui.lang, .aborting));
        return;
    }

    try execute(ui, allocator, .{});
}

pub fn execute(ui: *Tui, allocator: std.mem.Allocator, opts: RecoveryOpts) !void {
    if (!sys.isRoot()) {
        ui.fail(i18n.get(ui.lang, .error_not_root));
        return;
    }

    // ── Create drop-in for nginx auto-restart ──
    _ = sys.exec(allocator, &.{ "mkdir", "-p", NGINX_DROPIN_DIR, PROXY_DROPIN_DIR }) catch {};

    try sys.writeFile(NGINX_DROPIN_DIR ++ "/restart.conf", "[Service]\nRestart=on-failure\nRestartSec=2s\n");

    try sys.writeFile(PROXY_DROPIN_DIR ++ "/10-nginx.conf", "[Unit]\nWants=nginx.service\nAfter=nginx.service\n");

    {
        // Write using native Zig I/O (no shell needed)
        sys.writeFileMode(MASK_HEALTH_SCRIPT, HEALTH_SCRIPT, 0o755) catch {
            ui.fail("Failed to write health check script");
            return;
        };
    }

    try sys.writeFile(MASK_HEALTH_SERVICE, "[Unit]\nDescription=MTProto masking endpoint health check\n\n" ++
        "[Service]\nType=oneshot\nExecStart=" ++ MASK_HEALTH_SCRIPT ++ "\n");

    // ── Create timer unit ──
    try sys.writeFile(MASK_HEALTH_TIMER, "[Unit]\nDescription=Run MTProto masking health check every minute\n\n" ++
        "[Timer]\nOnBootSec=2min\nOnUnitActiveSec=1min\nRandomizedDelaySec=10s\n\n" ++
        "[Install]\nWantedBy=timers.target\n");

    // ── Enable and start ──
    _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};
    _ = sys.exec(allocator, &.{ "systemctl", "enable", "nginx" }) catch {};
    _ = sys.exec(allocator, &.{ "systemctl", "enable", "--now", "mtproto-mask-health.timer" }) catch {};

    if (sys.isServiceActive("nginx")) {
        _ = sys.exec(allocator, &.{ "systemctl", "try-reload-or-restart", "nginx" }) catch {};
    }
    _ = sys.exec(allocator, &.{ "systemctl", "start", "mtproto-mask-health.service" }) catch {};

    if (!opts.quiet) {
        // ── Report status ──
        if (sys.isServiceActive("mtproto-mask-health.timer")) {
            ui.ok("Masking health timer is active");
        } else {
            ui.warn("Masking health timer is not active");
        }

        if (sys.isServiceActive("nginx")) {
            ui.ok("Nginx service is active");
        } else {
            ui.warn("Nginx service is not active");
        }

        ui.summaryBox("DPI Auto-Recovery (Health Check) Activated", &.{
            .{ .label = "Health script:", .value = MASK_HEALTH_SCRIPT },
            .{ .label = "Timer:", .value = "systemctl status mtproto-mask-health.timer" },
            .{ .label = "Logs:", .value = "journalctl -t mtproto-mask-health -n 50" },
            .{ .label = "", .style = .blank },
            .{ .label = "Auto-restart nginx on failure", .style = .success },
            .{ .label = "Unhealthy masking is reported without restarting the data plane", .style = .success },
            .{ .label = "Checks every 60 seconds", .style = .success },
        });
    }
}
