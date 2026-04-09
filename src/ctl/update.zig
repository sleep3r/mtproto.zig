//! Update command for mtbuddy.
//!
//! Ports update.sh (260 lines of bash) into structured Zig code.
//! Downloads pre-built release artifacts from GitHub, validates
//! compatibility, and performs safe binary swap with rollback.

const std = @import("std");
const tui_mod = @import("tui.zig");
const i18n = @import("i18n.zig");
const sys = @import("sys.zig");

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;
const SummaryLine = tui_mod.SummaryLine;

const REPO_OWNER = "sleep3r";
const REPO_NAME = "mtproto.zig";
const INSTALL_DIR = "/opt/mtproto-proxy";
const SERVICE_NAME = "mtproto-proxy";
const SERVICE_FILE = "/etc/systemd/system/mtproto-proxy.service";

pub const UpdateOpts = struct {
    version: ?[]const u8 = null,
    force_service_update: bool = false,
};

/// Run update in CLI (non-interactive) mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.ArgIterator) !void {
    var opts = UpdateOpts{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            opts.version = args.next();
        } else if (std.mem.eql(u8, arg, "--force-service")) {
            opts.force_service_update = true;
        }
    }

    try execute(ui, allocator, opts);
}

/// Run update in interactive TUI mode.
pub fn runInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    ui.section(ui.str(.update_header));

    var version_buf: [32]u8 = undefined;
    const version_input = try ui.input(
        ui.str(.update_version_prompt),
        ui.str(.update_version_help),
        "latest",
        &version_buf,
    );

    var opts = UpdateOpts{};
    if (!std.mem.eql(u8, version_input, "latest")) {
        opts.version = version_input;
    }

    if (!try ui.confirm(ui.str(.confirm_proceed), true)) {
        ui.info(ui.str(.aborting));
        return;
    }

    try execute(ui, allocator, opts);
}

/// Execute the update steps.
fn execute(ui: *Tui, allocator: std.mem.Allocator, opts: UpdateOpts) !void {
    // ── Check root ──
    if (!sys.isRoot()) {
        ui.fail(ui.str(.error_not_root));
        return;
    }

    // ── Check install dir ──
    if (!sys.fileExists(INSTALL_DIR)) {
        ui.fail(ui.str(.error_install_dir_missing));
        return;
    }

    // ── Detect architecture ──
    const arch_enum = sys.getArch() catch {
        ui.fail(ui.str(.error_arch_unsupported));
        return;
    };
    const arch = arch_enum.toStr();

    // ── Build artifact candidates ──
    const supports_v3 = if (arch_enum == .x86_64) sys.supportsV3(allocator) else false;

    // ── Resolve version tag ──
    var tag_storage: [64]u8 = undefined;
    var tag: []const u8 = undefined;

    if (opts.version) |v| {
        if (v.len > 0 and v[0] != 'v') {
            tag_storage[0] = 'v';
            const copy_len = @min(v.len, tag_storage.len - 1);
            @memcpy(tag_storage[1..][0..copy_len], v[0..copy_len]);
            tag = tag_storage[0 .. copy_len + 1];
        } else {
            const copy_len = @min(v.len, tag_storage.len);
            @memcpy(tag_storage[0..copy_len], v[0..copy_len]);
            tag = tag_storage[0..copy_len];
        }
    } else {
        ui.step(ui.str(.update_resolving_tag));

        const result = sys.exec(allocator, &.{
            "curl", "-fsSL",
            "https://api.github.com/repos/" ++ REPO_OWNER ++ "/" ++ REPO_NAME ++ "/releases/latest",
        }) catch {
            ui.fail(ui.str(.error_no_release));
            return;
        };
        defer result.deinit();

        // Extract tag_name from JSON response (simple grep approach)
        const tag_parsed = extractTagName(result.stdout);
        if (tag_parsed) |t| {
            const copy_len = @min(t.len, tag_storage.len);
            @memcpy(tag_storage[0..copy_len], t[0..copy_len]);
            tag = tag_storage[0..copy_len];
            ui.stepOk(ui.str(.update_tag_resolved), tag);
        } else {
            ui.fail(ui.str(.error_no_release));
            return;
        }
    }

    // ── Download artifact ──
    ui.step(ui.str(.update_downloading));

    const candidates: []const []const u8 = if (supports_v3)
        &[_][]const u8{
            "mtproto-proxy-linux-x86_64_v3",
            "mtproto-proxy-linux-x86_64",
        }
    else if (arch_enum == .aarch64)
        &[_][]const u8{
            "mtproto-proxy-linux-aarch64",
        }
    else
        &[_][]const u8{
            "mtproto-proxy-linux-x86_64",
        };

    // We can't concatenate runtime strings at comptime, so use bufPrint
    var selected_asset: ?[]const u8 = null;
    var dl_path_buf: [256]u8 = undefined;
    var dl_path: []const u8 = undefined;

    for (candidates) |candidate| {
        var url_buf: [512]u8 = undefined;
        const url = std.fmt.bufPrint(&url_buf, "https://github.com/{s}/{s}/releases/download/{s}/{s}.tar.gz", .{
            REPO_OWNER, REPO_NAME, tag, candidate,
        }) catch continue;

        dl_path = std.fmt.bufPrint(&dl_path_buf, "/tmp/{s}.tar.gz", .{candidate}) catch continue;

        const dl = sys.exec(allocator, &.{ "curl", "-fsSL", url, "-o", dl_path }) catch continue;
        defer dl.deinit();

        if (dl.exit_code == 0) {
            selected_asset = candidate;
            break;
        }
    }

    if (selected_asset == null) {
        ui.fail(ui.str(.error_download_failed));
        return;
    }
    ui.stepOk(ui.str(.update_download_ok), selected_asset.?);

    // ── Attempt to download mtbuddy ──
    var buddy_candidate_buf: [256]u8 = undefined;
    var buddy_candidate: []const u8 = "";
    var has_mtbuddy = false;

    if (std.mem.indexOf(u8, selected_asset.?, "mtproto-proxy")) |idx| {
        const after = selected_asset.?[idx + "mtproto-proxy".len ..];
        buddy_candidate = std.fmt.bufPrint(&buddy_candidate_buf, "mtbuddy{s}", .{after}) catch "";

        if (buddy_candidate.len > 0) {
            var url_buf: [512]u8 = undefined;
            const url = std.fmt.bufPrint(&url_buf, "https://github.com/{s}/{s}/releases/download/{s}/{s}.tar.gz", .{
                REPO_OWNER, REPO_NAME, tag, buddy_candidate,
            }) catch "";

            if (url.len > 0) {
                const dl_buddy = sys.exec(allocator, &.{ "curl", "-fsSL", url, "-o", "/tmp/mtbuddy.tar.gz" }) catch null;
                if (dl_buddy) |b| {
                    if (b.exit_code == 0) has_mtbuddy = true;
                    b.deinit();
                }
            }
        }
    }

    // ── Extract ──
    var extract_dir_buf: [128]u8 = undefined;
    const extract_dir = std.fmt.bufPrint(&extract_dir_buf, "/tmp/mtproto-update-{s}", .{tag}) catch return;

    _ = sys.exec(allocator, &.{ "rm", "-rf", extract_dir }) catch {};
    _ = sys.exec(allocator, &.{ "mkdir", "-p", extract_dir }) catch {};
    _ = sys.execForward(&.{ "tar", "-xzf", dl_path, "-C", extract_dir }) catch {
        ui.fail(ui.str(.error_download_failed));
        return;
    };

    if (has_mtbuddy) {
        _ = sys.execForward(&.{ "tar", "-xzf", "/tmp/mtbuddy.tar.gz", "-C", extract_dir }) catch {};
    }

    var new_binary_buf: [256]u8 = undefined;
    const new_binary = std.fmt.bufPrint(&new_binary_buf, "{s}/{s}", .{ extract_dir, selected_asset.? }) catch return;

    if (!sys.fileExists(new_binary)) {
        ui.fail(ui.str(.error_binary_not_found));
        return;
    }

    // ── Validate binary ──
    ui.step(ui.str(.update_validating));
    {
        const check = sys.exec(allocator, &.{ new_binary, "/tmp/mtproto-proxy-update-check-does-not-exist.toml" }) catch {
            // If we can't even spawn the binary, it's incompatible (e.g. ExecFormatError)
            ui.fail(ui.str(.update_validation_fail));
            return;
        };
        defer check.deinit();

        // Exit code 132 = SIGILL (illegal instruction) — CPU incompatible
        if (check.exit_code == 132) {
            ui.fail(ui.str(.update_validation_fail));
            return;
        }
        ui.ok(ui.str(.update_validation_ok));
    }

    // ── Backup current binary ──
    ui.step(ui.str(.update_backing_up));
    var backup_path_buf: [256]u8 = undefined;
    var backup_path: ?[]const u8 = null;

    if (sys.fileExists(INSTALL_DIR ++ "/mtproto-proxy")) {
        const timestamp = sys.exec(allocator, &.{ "date", "+%Y%m%d%H%M%S" }) catch null;
        if (timestamp) |t| {
            const ts = std.mem.trim(u8, t.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
            backup_path = std.fmt.bufPrint(&backup_path_buf, "{s}/mtproto-proxy.backup.{s}", .{ INSTALL_DIR, ts }) catch null;
            // Don't deinit t here — with ArenaAllocator it's freed at exit
        } else {
            backup_path = std.fmt.bufPrint(&backup_path_buf, "{s}/mtproto-proxy.backup", .{INSTALL_DIR}) catch null;
        }

        if (backup_path) |bp| {
            _ = sys.execForward(&.{ "cp", INSTALL_DIR ++ "/mtproto-proxy", bp }) catch {};
            ui.stepOk(ui.str(.update_backing_up), bp);
        }
    }

    // ── Stop service ──
    ui.step(ui.str(.update_stopping));
    _ = sys.execForward(&.{ "systemctl", "stop", SERVICE_NAME }) catch {};

    // ── Install new binary ──
    ui.step(ui.str(.update_installing));
    _ = sys.execForward(&.{ "install", "-m", "0755", new_binary, INSTALL_DIR ++ "/mtproto-proxy" }) catch {};

    if (has_mtbuddy and buddy_candidate.len > 0) {
        var buddy_bin_buf: [256]u8 = undefined;
        const buddy_bin = std.fmt.bufPrint(&buddy_bin_buf, "{s}/{s}", .{ extract_dir, buddy_candidate }) catch "";
        if (sys.fileExists(buddy_bin)) {
            _ = sys.execForward(&.{ "install", "-m", "0755", buddy_bin, "/usr/local/bin/mtbuddy" }) catch {};
        }
    }

    // Fix ownership
    _ = sys.exec(allocator, &.{ "chown", "-R", "mtproto:mtproto", INSTALL_DIR }) catch {};

    // ── Update service file (unless tunnel-aware) ──
    if (opts.force_service_update or !isTunnelServiceUnit()) {
        const raw_base_buf = "https://raw.githubusercontent.com/" ++ REPO_OWNER ++ "/" ++ REPO_NAME ++ "/";
        var svc_url_buf: [512]u8 = undefined;
        const svc_url = std.fmt.bufPrint(&svc_url_buf, "{s}{s}/deploy/mtproto-proxy.service", .{ raw_base_buf, tag }) catch "";
        if (svc_url.len > 0) {
            _ = sys.exec(allocator, &.{ "curl", "-fsSL", svc_url, "-o", SERVICE_FILE }) catch {};
        }
    }
    _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};

    // ── Start service ──
    ui.step(ui.str(.update_starting));
    const start_result = sys.execForward(&.{ "systemctl", "restart", SERVICE_NAME }) catch 1;

    if (start_result != 0 or !sys.isServiceActive(SERVICE_NAME)) {
        ui.fail(ui.str(.error_service_failed));
        // Rollback
        if (backup_path) |bp| {
            ui.step(ui.str(.update_rollback));
            _ = sys.execForward(&.{ "cp", bp, INSTALL_DIR ++ "/mtproto-proxy" }) catch {};
            _ = sys.execForward(&.{ "systemctl", "restart", SERVICE_NAME }) catch {};
        }
        return;
    }

    ui.ok(ui.str(.update_starting));

    // ── Apply masking monitor ──
    if (sys.fileExists(INSTALL_DIR ++ "/setup_mask_monitor.sh")) {
        _ = sys.execForward(&.{ "bash", INSTALL_DIR ++ "/setup_mask_monitor.sh", "--quiet" }) catch {};
    }

    // ── Cleanup ──
    _ = sys.exec(allocator, &.{ "rm", "-rf", extract_dir }) catch {};
    _ = sys.exec(allocator, &.{ "rm", "-f", dl_path }) catch {};

    // ── Summary ──
    ui.summaryBox(ui.str(.update_success_header), &.{
        .{ .label = ui.str(.update_version_label), .value = tag },
        .{ .label = ui.str(.update_arch_label), .value = arch },
        .{ .label = ui.str(.update_artifact_label), .value = selected_asset.? },
        .{ .label = "Status:", .value = "systemctl status mtproto-proxy --no-pager" },
        .{ .label = "Logs:", .value = "journalctl -u mtproto-proxy -f" },
        .{ .label = ui.str(.update_backup_label), .value = backup_path orelse "none" },
    });
}

// ── Helpers ─────────────────────────────────────────────────────

/// Check if the current service file is a tunnel-aware unit.
fn isTunnelServiceUnit() bool {
    if (!sys.fileExists(SERVICE_FILE)) return false;
    const result = sys.exec(std.heap.page_allocator, &.{
        "grep", "-Eq", "setup_netns\\.sh|ip[[:space:]]+netns[[:space:]]+exec|AmneziaWG[[:space:]]+Tunnel", SERVICE_FILE,
    }) catch return false;
    defer result.deinit();
    return result.exit_code == 0;
}

/// Extract "tag_name" from GitHub API JSON response (simple string search).
fn extractTagName(json: []const u8) ?[]const u8 {
    // Look for "tag_name" : "vX.Y.Z"
    const needle = "\"tag_name\"";
    const idx = std.mem.indexOf(u8, json, needle) orelse return null;

    // Find the opening quote of the value
    var pos = idx + needle.len;
    while (pos < json.len and json[pos] != '"') : (pos += 1) {}
    if (pos >= json.len) return null;
    pos += 1; // skip opening quote

    // Find the closing quote
    const start = pos;
    while (pos < json.len and json[pos] != '"') : (pos += 1) {}
    if (pos >= json.len) return null;

    return json[start..pos];
}
