//! Update command for mtbuddy.
//!
//! Downloads pre-built release artifacts from GitHub, validates
//! compatibility, and performs safe binary swap with rollback.

const std = @import("std");
const tui_mod = @import("tui.zig");
const i18n = @import("i18n.zig");
const sys = @import("sys.zig");
const release = @import("release.zig");
const dashboard = @import("dashboard.zig");
const recovery = @import("recovery.zig");

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;
const SummaryLine = tui_mod.SummaryLine;

const INSTALL_DIR = release.INSTALL_DIR;
const SERVICE_NAME = release.SERVICE_NAME;
const SERVICE_FILE = release.SERVICE_FILE;

pub const UpdateOpts = struct {
    version: ?[]const u8 = null,
    force_service_update: bool = false,
    insecure: bool = false,
};

/// Run update in CLI (non-interactive) mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    var opts = UpdateOpts{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            opts.version = args.next();
        } else if (std.mem.eql(u8, arg, "--force-service")) {
            opts.force_service_update = true;
        } else if (std.mem.eql(u8, arg, "--insecure")) {
            opts.insecure = true;
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

    const insecure_mode = opts.insecure or sys.envFlagSet("MTPROTO_INSECURE");
    const signature_available = release.signatureVerificationAvailable();
    if (!signature_available and !insecure_mode) {
        ui.fail("This mtbuddy build has no embedded minisign public key.");
        ui.info("Rebuild with -Dminisign_pubkey=<RW...> or use --insecure (or MTPROTO_INSECURE=1).");
        return;
    }
    if (insecure_mode) {
        ui.warn("INSECURE mode enabled: release signature verification is disabled.");
    }

    // ── Ensure signature verifier dependency ──
    if (signature_available and !insecure_mode and !sys.commandExists("minisign")) {
        ui.step("Installing minisign for release signature verification...");
        _ = sys.exec(allocator, &.{ "apt-get", "-o", "DPkg::Lock::Timeout=600", "update", "-qq" }) catch {};
        _ = sys.exec(allocator, &.{ "apt-get", "-o", "DPkg::Lock::Timeout=600", "install", "-y", "minisign" }) catch {};
        if (!sys.commandExists("minisign")) {
            ui.fail("minisign is required for release signature verification");
            return;
        }
        ui.ok("minisign installed");
    }

    // ── Resolve release tag ──
    var tag = release.Tag{};
    {
        ui.step(ui.str(.update_resolving_tag));
        if (!release.resolveTag(allocator, opts.version, &tag)) {
            ui.fail(ui.str(.error_no_release));
            return;
        }
        ui.stepOk(ui.str(.update_tag_resolved), tag.slice());
    }

    // ── Download + validate proxy binary ──
    var artifact = release.Artifact{};
    defer release.cleanup(allocator, &artifact);
    {
        ui.step(ui.str(.update_downloading));
        if (!release.downloadProxyArtifact(allocator, tag.slice(), "update", !insecure_mode, &artifact)) {
            ui.fail(ui.str(.error_download_failed));
            return;
        }
        ui.stepOk(ui.str(.update_download_ok), artifact.asset_name);
    }

    ui.ok(ui.str(.update_validation_ok));

    // ── Download mtbuddy (optional) ──
    var buddy_buf: [256]u8 = undefined;
    ui.step(localized(
        ui,
        "Downloading mtbuddy updater...",
        "Скачивание обновления mtbuddy...",
    ));
    const buddy_path = release.downloadBuddyArtifact(
        allocator,
        tag.slice(),
        artifact.asset_name,
        artifact.extractDir(),
        !insecure_mode,
        &buddy_buf,
    );
    if (buddy_path) |_| {
        ui.stepOk(
            localized(ui, "mtbuddy updater downloaded", "Обновление mtbuddy скачано"),
            "mtbuddy",
        );
    } else {
        ui.warn(localized(
            ui,
            "mtbuddy artifact unavailable; updating proxy binary only",
            "Артефакт mtbuddy недоступен; обновляем только бинарник прокси",
        ));
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
    _ = sys.execForward(&.{ "install", "-m", "0755", artifact.binaryPath(), INSTALL_DIR ++ "/mtproto-proxy" }) catch {};

    if (buddy_path) |bp| {
        _ = sys.execForward(&.{ "install", "-m", "0755", bp, "/usr/local/bin/mtbuddy" }) catch {};
    }

    // Fix ownership
    _ = sys.exec(allocator, &.{ "chown", "-R", "mtproto:mtproto", INSTALL_DIR }) catch {};

    // ── Update service file (unless tunnel-aware) ──
    if (opts.force_service_update or !isTunnelServiceUnit()) {
        release.writeServiceFile();
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

    // ── Apply masking monitor (if recovery is already installed) ──
    if (sys.isServiceActive("mtproto-mask-health.timer") or sys.fileExists("/usr/local/bin/mtproto-mask-health.sh")) {
        recovery.execute(ui, allocator, .{ .quiet = true }) catch {};
    }

    // ── Redeploy dashboard (if already installed) ──
    if (sys.isServiceActive("proxy-monitor")) {
        dashboard.execute(ui, allocator, .{ .quiet = true }) catch {};
    }

    // ── Summary ──
    const arch_str = blk: {
        const a = sys.getArch() catch break :blk "unknown";
        break :blk a.toStr();
    };

    ui.summaryBox(ui.str(.update_success_header), &.{
        .{ .label = ui.str(.update_version_label), .value = tag.slice() },
        .{ .label = ui.str(.update_arch_label), .value = arch_str },
        .{ .label = ui.str(.update_artifact_label), .value = artifact.asset_name },
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
        "grep", "-Eq", "setup_(netns|tunnel)\\.sh|ip[[:space:]]+netns[[:space:]]+exec|AmneziaWG[[:space:]]+Tunnel|Tunnel[[:space:]]+Policy[[:space:]]+Routing", SERVICE_FILE,
    }) catch return false;
    defer result.deinit();
    return result.exit_code == 0;
}

fn localized(ui: *const Tui, en: []const u8, ru: []const u8) []const u8 {
    return switch (ui.lang) {
        .en => en,
        .ru => ru,
    };
}
