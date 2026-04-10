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

pub const RecoveryOpts = struct {
    quiet: bool = false,
};

/// Run in CLI mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.ArgIterator) !void {
    var opts = RecoveryOpts{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--quiet")) {
            opts.quiet = true;
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

    sys.writeFile(NGINX_DROPIN_DIR ++ "/restart.conf", "[Service]\nRestart=on-failure\nRestartSec=2s\n") catch {};

    sys.writeFile(PROXY_DROPIN_DIR ++ "/10-nginx.conf", "[Unit]\nWants=nginx.service\nAfter=nginx.service\n") catch {};

    // ── Create health check script ──
    const health_script =
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
        \\        /^\s*\[censorship\]\s*$/ { in_section=1; next }
        \\        /^\s*\[[^\]]+\]\s*$/ { in_section=0; next }
        \\        in_section { line=$0; sub(/#.*/,"",line)
        \\            if (line ~ "^\\s*" want_key "\\s*=") {
        \\                split(line,parts,"="); value=parts[2]
        \\                gsub(/^\s+|\s+$/,"",value); gsub(/^"|"$/,"",value)
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
        \\if systemctl is-active --quiet mtproto-proxy; then
        \\    logger -t mtproto-mask-health "still unreachable; restarting mtproto-proxy"
        \\    systemctl restart mtproto-proxy || true; sleep 1
        \\fi
        \\
        \\probe_endpoint "$target_host" "$mask_port" && { logger -t mtproto-mask-health "recovered after proxy restart"; exit 0; }
        \\logger -t mtproto-mask-health "critical: endpoint still unreachable"
        \\exit 1
    ;

    {
        // Write using native Zig I/O (no shell needed)
        sys.writeFileMode(MASK_HEALTH_SCRIPT, health_script, 0o755) catch {
            ui.fail("Failed to write health check script");
            return;
        };
    }

    sys.writeFile(MASK_HEALTH_SERVICE, "[Unit]\nDescription=MTProto masking endpoint health check\n\n" ++
        "[Service]\nType=oneshot\nExecStart=" ++ MASK_HEALTH_SCRIPT ++ "\n") catch {};

    // ── Create timer unit ──
    sys.writeFile(MASK_HEALTH_TIMER, "[Unit]\nDescription=Run MTProto masking health check every minute\n\n" ++
        "[Timer]\nOnBootSec=2min\nOnUnitActiveSec=1min\nRandomizedDelaySec=10s\nPersistent=true\n\n" ++
        "[Install]\nWantedBy=timers.target\n") catch {};

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
            .{ .label = "Auto-restart mtproto-proxy if nginx recovery insufficient", .style = .success },
            .{ .label = "Checks every 60 seconds", .style = .success },
        });
    }
}
