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
const web = @import("web.zig");
const recovery = @import("recovery.zig");
const install = @import("install.zig");
const nfqws = @import("nfqws.zig");
const tunnel_singbox = @import("tunnel_singbox.zig");

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
    force: bool = false,
    allow_downgrade: bool = false,
};

/// Run update in CLI (non-interactive) mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    var opts = UpdateOpts{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            opts.version = args.next();
        } else if (std.mem.eql(u8, arg, "--force-service")) {
            opts.force_service_update = true;
        } else if (std.mem.eql(u8, arg, "--force")) {
            opts.force = true;
        } else if (std.mem.eql(u8, arg, "--allow-downgrade")) {
            opts.allow_downgrade = true;
        } else if (std.mem.eql(u8, arg, "--insecure")) {
            opts.insecure = true;
        } else {
            ui.print("Unknown option: {s}\n", .{arg});
            return error.UnknownOption;
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

    // ── Repair an existing sing-box egress ──
    // FIRST, before anything that touches the network or the binaries.
    //
    // An egress provisioned before the TUN fixes hands 172.19.0.2 to systemd-resolved as
    // sbx0's DNS server with a `~.` route-only domain, which kills name resolution for
    // the WHOLE host — including this command. Run the repair any later and update dies
    // at "Resolving latest release" and never reaches it, so the one symptom that most
    // needs fixing is the one that prevents the fix. (Same shape as the 203/EXEC case:
    // a host that cannot start the proxy never reaches a post-restart repair either.)
    //
    // Nothing here depends on the new binaries or on the release having been resolved:
    // it reads config.toml, rewrites the drop-in and the sing-box config, and restarts
    // the egress. It is idempotent and no-ops when no egress is configured, so running it
    // even on an update that later fails is free — and leaves the host better off.
    tunnel_singbox.refreshEgress(ui, allocator);

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
        // apt first where it exists, then the pinned, SHA-256-verified upstream binary —
        // the same order `mtbuddy install` uses. The fallback is what makes this work on
        // a host we do not have a package manager for: without it, an apt-less system
        // (or an apt release with no minisign, e.g. Ubuntu 20.04 focal) could never
        // update at all, even though nothing else about updating is Debian-specific.
        if (sys.commandExists("apt-get")) {
            _ = sys.exec(allocator, &.{ "apt-get", "-o", "DPkg::Lock::Timeout=600", "update", "-qq" }) catch {};
            _ = sys.exec(allocator, &.{ "apt-get", "-o", "DPkg::Lock::Timeout=600", "install", "-y", "minisign" }) catch {};
        }
        if (!sys.commandExists("minisign")) {
            _ = install.installMinisignFromUpstream(allocator);
        }
        if (!sys.commandExists("minisign")) {
            ui.fail("minisign is required for release signature verification");
            ui.info("Neither the host package manager nor the pinned upstream binary could provide it (check network / checksum), or re-run with --insecure.");
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
    if (sys.fileExists(INSTALL_DIR ++ "/mtproto-proxy")) {
        const current = try sys.exec(allocator, &.{ INSTALL_DIR ++ "/mtproto-proxy", "--version" });
        defer current.deinit();
        if (current.exit_code != 0) return error.InstalledVersionUnavailable;
        const installed = installedVersion(current.stdout, current.stderr) orelse return error.InstalledVersionUnavailable;
        const desired = versionFromOutput(tag.slice()) orelse return error.InvalidReleaseVersion;
        switch (desired.order(installed)) {
            .eq => if (!opts.force and !opts.force_service_update) {
                ui.ok("Already up to date (use update --force to reapply host repairs)");
                return;
            },
            .lt => if (!opts.allow_downgrade) {
                ui.fail("Refusing downgrade; pass --allow-downgrade explicitly");
                return error.DowngradeRefused;
            },
            .gt => {},
        }
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

    // The service runs as User=mtproto. Older installs (pre-1.0 ran as root) never
    // created that account, so an `update` that rewrites the unit would otherwise
    // leave systemd failing the service with status=217/USER (issue #310). Ensure the
    // user exists up front — before we stop the running service — and abort cleanly if
    // we can't, so a missing account never takes the proxy down. Idempotent: a no-op
    // when the user already exists.
    if (!install.ensureServiceUser(ui, allocator)) return;

    // ── Backup current binary ──
    ui.step(ui.str(.update_backing_up));
    var backup_path: ?[]const u8 = null;
    const previous_unit = sys.readFileAllocAbsolute(allocator, SERVICE_FILE, 128 * 1024);
    defer if (previous_unit) |content| allocator.free(content);
    if (previous_unit == null and sys.fileExists(SERVICE_FILE)) return error.ServiceBackupFailed;

    if (sys.fileExists(INSTALL_DIR ++ "/mtproto-proxy")) {
        const bp = INSTALL_DIR ++ "/mtproto-proxy.backup.prev";
        if (try sys.execForward(&.{ "cp", INSTALL_DIR ++ "/mtproto-proxy", bp }) != 0) return error.BackupFailed;
        backup_path = bp;
        ui.stepOk(ui.str(.update_backing_up), bp);
    }

    // ── Stop service ──
    ui.step(ui.str(.update_stopping));
    if (try sys.execForward(&.{ "systemctl", "stop", SERVICE_NAME }) != 0) return error.StopFailed;

    // ── Install new binary ──
    ui.step(ui.str(.update_installing));
    // Capture the install(1) result: if the swap fails (ENOSPC, read-only /opt, immutable
    // attr) the OLD binary stays in place and the service below would restart it happily,
    // so reporting "updated to <tag>" would be a lie. Fail, restart the unchanged service
    // so the proxy comes back up, and abort.
    const proxy_install_rc = sys.execForward(&.{ "install", "-m", "0755", artifact.binaryPath(), INSTALL_DIR ++ "/mtproto-proxy" }) catch 1;
    if (proxy_install_rc != 0) {
        ui.fail("Failed to install the new mtproto-proxy binary — restoring backup");
        if (backup_path) |bp| {
            if (try sys.execForward(&.{ "install", "-m", "0755", bp, INSTALL_DIR ++ "/mtproto-proxy" }) != 0) return error.RollbackRestoreFailed;
        }
        if (try sys.execForward(&.{ "systemctl", "restart", SERVICE_NAME }) != 0) return error.RollbackRestartFailed;
        return error.UpdateFailed;
    }

    if (buddy_path) |bp| {
        const buddy_rc = sys.execForward(&.{ "install", "-m", "0755", bp, "/usr/local/bin/mtbuddy" }) catch 1;
        if (buddy_rc != 0) {
            ui.warn("Failed to update the mtbuddy CLI (proxy binary was updated)");
        } else {
            ui.info("This run finishes with the previous updater logic; run mtbuddy update --force once to apply the new updater's host repairs");
        }
    }

    // Fix ownership
    // The dashboard runs as root: never give its code, interpreter or token to
    // the network-facing service account.
    _ = sys.exec(allocator, &.{ "chown", "root:root", INSTALL_DIR }) catch {};
    if (sys.fileExists(INSTALL_DIR ++ "/monitor")) {
        _ = sys.exec(allocator, &.{ "chown", "-R", "root:root", INSTALL_DIR ++ "/monitor" }) catch {};
    }
    _ = sys.exec(allocator, &.{ "chown", "mtproto:mtproto", INSTALL_DIR ++ "/config.toml" }) catch {};

    // ── Update service file (unless tunnel-aware) ──
    var preparation_failed = false;
    if (opts.force_service_update or !isTunnelServiceUnit()) {
        release.writeServiceFile() catch |err| {
            ui.print("Failed to write proxy service: {any}; restoring the previous installation\n", .{err});
            preparation_failed = true;
        };
    }
    if ((sys.execForward(&.{ "systemctl", "daemon-reload" }) catch 1) != 0) preparation_failed = true;
    @import("synlimit.zig").repairInstalled(allocator);

    // ── Start service ──
    ui.step(ui.str(.update_starting));
    const start_result = if (preparation_failed) 1 else sys.execForward(&.{ "systemctl", "restart", SERVICE_NAME }) catch 1;

    if (start_result != 0 or !sys.isServiceActive(SERVICE_NAME)) {
        ui.fail(ui.str(.error_service_failed));
        // Rollback
        if (backup_path) |bp| {
            ui.step(ui.str(.update_rollback));
            if (try sys.execForward(&.{ "systemctl", "stop", SERVICE_NAME }) != 0) return error.RollbackStopFailed;
            if (try sys.execForward(&.{ "install", "-m", "0755", bp, INSTALL_DIR ++ "/mtproto-proxy" }) != 0) return error.RollbackRestoreFailed;
            if (previous_unit) |content| try sys.writeFile(SERVICE_FILE, content);
            if (try sys.execForward(&.{ "systemctl", "daemon-reload" }) != 0) return error.RollbackReloadFailed;
            if (try sys.execForward(&.{ "systemctl", "restart", SERVICE_NAME }) != 0 or !sys.isServiceActive(SERVICE_NAME)) return error.RollbackRestartFailed;
            ui.warn("Update failed; previous binary and service unit restored");
        }
        return error.UpdateFailed;
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

    // ── Repair the DPI firewall rules (if they predate the loopback exclusion) ──
    // Neither the TCPMSS script nor the nfqws unit is regenerated by an ordinary update,
    // so without this an upgraded host keeps clamping and queueing its own 127.0.0.1
    // traffic -- which is exactly the path the WEB relay uses to reach the proxy.
    install.refreshTcpmssLoopbackExclusion(ui, allocator);
    nfqws.refreshLoopbackExclusion(ui, allocator);

    // ── Re-apply the WEB proxy relay (if already installed) ──
    // Its systemd unit points at the proxy binary we just swapped, so this only
    // rewrites the unit and restarts it. `web.execute` skips the config.toml write when
    // nothing changed, which keeps `mtbuddy update` byte-identical on config.toml the
    // way test/installer-e2e asserts.
    if (web.isInstalled()) {
        web.execute(ui, allocator, .{ .quiet = true, .skip_cert = true, .yes = true }) catch {};
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
/// Also consulted by `install`, which must not stamp the stock unit (no CAP_NET_ADMIN,
/// no ExecStartPre) over a tunnel egress on a re-run.
pub fn isTunnelServiceUnit() bool {
    if (!sys.fileExists(SERVICE_FILE)) return false;
    const content = sys.readFileAllocAbsolute(std.heap.page_allocator, SERVICE_FILE, 128 * 1024) orelse return true;
    defer std.heap.page_allocator.free(content);
    for ([_][]const u8{ "setup_netns.sh", "setup_tunnel.sh", "netns", "AmneziaWG", "Tunnel Policy Routing", "CAP_NET_ADMIN", "SO_MARK" }) |marker| {
        if (std.mem.indexOf(u8, content, marker) != null) return true;
    }
    return false;
}

fn versionFromOutput(output: []const u8) ?std.SemanticVersion {
    var words = std.mem.tokenizeAny(u8, output, " \r\n\t");
    while (words.next()) |word| {
        const value = if (std.mem.startsWith(u8, word, "v")) word[1..] else word;
        return std.SemanticVersion.parse(value) catch continue;
    }
    return null;
}

fn installedVersion(stdout: []const u8, stderr: []const u8) ?std.SemanticVersion {
    // Released proxies before this audit printed --version to stderr.
    return versionFromOutput(stdout) orelse versionFromOutput(stderr);
}

test "release version parsing handles binary output and v-prefixed tags" {
    try std.testing.expectEqual(std.math.Order.gt, versionFromOutput("v1.13.1").?.order(versionFromOutput("mtproto-proxy 1.13.0\n").?));
    try std.testing.expect(versionFromOutput("garbage") == null);
    try std.testing.expectEqual(std.math.Order.eq, installedVersion("", "mtproto-proxy v1.13.0\n").?.order(try std.SemanticVersion.parse("1.13.0")));
    try std.testing.expectEqual(std.math.Order.eq, installedVersion("mtproto-proxy v1.13.1\n", "").?.order(try std.SemanticVersion.parse("1.13.1")));
}

fn localized(ui: *const Tui, en: []const u8, ru: []const u8) []const u8 {
    return switch (ui.lang) {
        .en => en,
        .ru => ru,
    };
}
