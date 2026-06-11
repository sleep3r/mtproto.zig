//! Setup dashboard command for mtbuddy.
//!
//! Embeds the Python FastAPI dashboard and its static files directly into the
//! mtbuddy binary using @embedFile. Uses `uv` (installed from GitHub) to manage an
//! isolated virtualenv with all Python dependencies, avoiding PEP 668 breakage
//! on modern Debian/Ubuntu systems.

const std = @import("std");
const tui_mod = @import("tui.zig");
const i18n = @import("i18n.zig");
const sys = @import("sys.zig");

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;
const SummaryLine = tui_mod.SummaryLine;

const INSTALL_DIR = "/opt/mtproto-proxy/monitor";
const VENV_DIR = INSTALL_DIR ++ "/.venv";
const VENV_PYTHON = VENV_DIR ++ "/bin/python";
const UV_PYTHON_INSTALL_DIR = INSTALL_DIR ++ "/.uv-python";
const UV_SUBPROCESS_PATH = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const UV_PYTHON_INSTALL_ENV = "UV_PYTHON_INSTALL_DIR=" ++ UV_PYTHON_INSTALL_DIR;
/// Pinned uv release (verified against its published .sha256 at install time).
/// Bump deliberately; do not float to "latest".
const UV_VERSION = "0.11.19";
const SERVICE_NAME = "proxy-monitor";
const SERVICE_FILE = "/etc/systemd/system/" ++ SERVICE_NAME ++ ".service";

const VENV_CREATE_ARGV = [_][]const u8{
    "env", UV_SUBPROCESS_PATH, UV_PYTHON_INSTALL_ENV, "uv", "venv", VENV_DIR, "--python", "python3",
};

const PIP_INSTALL_ARGV = [_][]const u8{
    "env",
    UV_SUBPROCESS_PATH,
    UV_PYTHON_INSTALL_ENV,
    "uv",
    "pip",
    "install",
    "--python",
    VENV_PYTHON,
    "fastapi==0.115.6",
    "uvicorn==0.34.0",
    "psutil==6.1.1",
    "websockets==14.1",
    "starlette==0.41.3",
};

// Embed dashboard assets at comptime
const server_py = @embedFile("dashboard_assets/server.py");
const index_html = @embedFile("dashboard_assets/static/index.html");
const style_css = @embedFile("dashboard_assets/static/style.css");
const app_js = @embedFile("dashboard_assets/static/app.js");
const logo_svg = @embedFile("dashboard_assets/static/logo.svg");

pub const DashboardOpts = struct {
    quiet: bool = false,
};

fn dashboardVenvCreateArgv() []const []const u8 {
    return &VENV_CREATE_ARGV;
}

fn dashboardPipInstallArgv() []const []const u8 {
    return &PIP_INSTALL_ARGV;
}

/// Run in CLI mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    var opts = DashboardOpts{};
    var do_remove = false;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--quiet")) {
            opts.quiet = true;
        } else if (std.mem.eql(u8, arg, "--remove") or std.mem.eql(u8, arg, "--uninstall")) {
            do_remove = true;
        }
    }
    if (do_remove) return removeDashboard(ui);
    try execute(ui, allocator, opts);
}

fn tr(lang: i18n.Lang, en: []const u8, ru: []const u8) []const u8 {
    return if (lang == .ru) ru else en;
}

/// Interactive entry (main menu): confirm, then remove the dashboard. Shown in place of
/// "Setup dashboard" once the dashboard is installed.
pub fn removeInteractive(ui: *Tui) void {
    const confirmed = ui.confirm(
        tr(ui.lang, "Remove the dashboard? The proxy keeps running.", "Удалить дашборд? Прокси продолжит работать."),
        false,
    ) catch return;
    if (!confirmed) {
        ui.info(i18n.get(ui.lang, .aborting));
        return;
    }
    removeDashboard(ui);
}

/// Stop and remove only the dashboard (`proxy-monitor`), leaving the proxy itself untouched.
/// `mtbuddy uninstall` removes everything; this is the targeted counterpart to
/// `mtbuddy setup dashboard`.
fn removeDashboard(ui: *Tui) void {
    if (!sys.isRoot()) {
        ui.fail(i18n.get(ui.lang, .error_not_root));
        return;
    }
    ui.section(tr(ui.lang, "Remove monitoring dashboard", "Удаление дашборда мониторинга"));

    if (!sys.fileExists(SERVICE_FILE) and !sys.isServiceActive(SERVICE_NAME)) {
        ui.info(tr(ui.lang, "Dashboard is not installed — nothing to remove.", "Дашборд не установлен — удалять нечего."));
        return;
    }

    ui.step(tr(ui.lang, "Stopping and disabling " ++ SERVICE_NAME ++ "...", "Останавливаю и отключаю " ++ SERVICE_NAME ++ "..."));
    _ = sys.execForward(&.{ "systemctl", "disable", "--now", SERVICE_NAME }) catch {};

    ui.step(tr(ui.lang, "Removing service unit and dashboard files...", "Удаляю unit и файлы дашборда..."));
    _ = sys.execForward(&.{ "rm", "-f", SERVICE_FILE }) catch {};
    _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};
    _ = sys.execForward(&.{ "rm", "-rf", INSTALL_DIR }) catch {};

    ui.ok(tr(ui.lang, "Dashboard removed. The proxy itself is untouched.", "Дашборд удалён. Сам прокси не затронут."));
}

/// Run in interactive mode.
pub fn runInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    ui.section(i18n.get(ui.lang, .menu_setup_dashboard));

    if (!try ui.confirm(i18n.get(ui.lang, .confirm_proceed), true)) {
        ui.info(i18n.get(ui.lang, .aborting));
        return;
    }

    try execute(ui, allocator, .{});
}

/// Check if `uv` is available on the system.
fn uvExists() bool {
    return sys.commandExists("uv");
}

/// Install `uv` from GitHub releases (astral.sh is blocked in some regions).
fn bootstrapUv(ui: *Tui, allocator: std.mem.Allocator) bool {
    ui.step("Installing uv package manager from GitHub...");

    const archive_name = switch (sys.getArch() catch {
        ui.fail("Unable to detect CPU architecture for uv bootstrap");
        return false;
    }) {
        .x86_64 => "uv-x86_64-unknown-linux-gnu.tar.gz",
        .aarch64 => "uv-aarch64-unknown-linux-gnu.tar.gz",
    };

    // Pin uv to a specific release (no moving "latest" target) and verify the
    // download against uv's own published .sha256 from that same release before
    // installing it as a root binary. This closes the unverified-root-download
    // supply-chain hole. (Hardcoding the per-arch SHA in-repo, Dockerfile-style,
    // is the stronger follow-up.)
    const uv_url = std.fmt.allocPrint(
        allocator,
        "https://github.com/astral-sh/uv/releases/download/" ++ UV_VERSION ++ "/{s}",
        .{archive_name},
    ) catch {
        ui.fail("Failed to prepare uv download URL");
        return false;
    };
    defer allocator.free(uv_url);

    const install_script = std.fmt.allocPrint(
        allocator,
        \\set -e
        \\UV_URL="{s}"
        \\TMP_DIR=$(mktemp -d)
        \\trap 'rm -rf "$TMP_DIR"' EXIT
        \\curl -fsSL "$UV_URL" -o "$TMP_DIR/uv.tar.gz"
        \\curl -fsSL "$UV_URL.sha256" -o "$TMP_DIR/uv.tar.gz.sha256"
        \\EXPECTED=$(cut -d' ' -f1 "$TMP_DIR/uv.tar.gz.sha256")
        \\ACTUAL=$(sha256sum "$TMP_DIR/uv.tar.gz" | cut -d' ' -f1)
        \\if [ -z "$EXPECTED" ] || [ "$EXPECTED" != "$ACTUAL" ]; then
        \\  echo "uv checksum mismatch (expected '$EXPECTED' got '$ACTUAL')" >&2
        \\  exit 1
        \\fi
        \\tar -xzf "$TMP_DIR/uv.tar.gz" -C "$TMP_DIR" --strip-components=1
        \\install -m 0755 "$TMP_DIR/uv" /usr/local/bin/uv
        \\if [ -f "$TMP_DIR/uvx" ]; then install -m 0755 "$TMP_DIR/uvx" /usr/local/bin/uvx; fi
    ,
        .{uv_url},
    ) catch {
        ui.fail("Failed to prepare uv install script");
        return false;
    };
    defer allocator.free(install_script);

    // Download the pinned release tarball from GitHub, verify its checksum, and
    // extract the `uv` binary. GitHub is reliably accessible even when astral.sh
    // is blocked.
    const result = sys.exec(allocator, &.{ "sh", "-c", install_script }) catch {
        ui.fail("Failed to download uv from GitHub");
        return false;
    };
    defer result.deinit();

    if (result.exit_code != 0) {
        ui.fail("uv installation from GitHub failed");
        return false;
    }

    if (!sys.commandExists("uv")) {
        ui.fail("uv binary installed but not found on PATH");
        return false;
    }

    ui.ok("uv installed successfully (from GitHub)");
    return true;
}

pub fn execute(ui: *Tui, allocator: std.mem.Allocator, opts: DashboardOpts) !void {
    if (!sys.isRoot()) {
        ui.fail(i18n.get(ui.lang, .error_not_root));
        return;
    }

    // ── Ensure uv is available ──
    if (!uvExists()) {
        if (!bootstrapUv(ui, allocator)) {
            return;
        }
    }

    // ── Provision Dashboard Files ──
    ui.step("Extracting embedded dashboard files...");

    _ = sys.exec(allocator, &.{ "mkdir", "-p", INSTALL_DIR ++ "/static" }) catch {};

    sys.writeFile(INSTALL_DIR ++ "/server.py", server_py) catch {
        ui.fail("Failed to write server.py");
        return;
    };
    sys.writeFile(INSTALL_DIR ++ "/static/index.html", index_html) catch {};
    sys.writeFile(INSTALL_DIR ++ "/static/style.css", style_css) catch {};
    sys.writeFile(INSTALL_DIR ++ "/static/app.js", app_js) catch {};
    sys.writeFile(INSTALL_DIR ++ "/static/logo.svg", logo_svg) catch {};

    ui.ok("Dashboard files extracted to " ++ INSTALL_DIR);

    // ── Create virtualenv & install dependencies ──
    ui.step("Setting up Python virtualenv via uv...");

    // Remove stale venv first — `make deploy` chowns everything to mtproto:mtproto,
    // so `uv venv` (running as root) can fail to overwrite it.
    _ = sys.exec(allocator, &.{ "rm", "-rf", VENV_DIR }) catch {};

    // The systemd unit uses ProtectHome=yes. uv-managed interpreters installed
    // under /root/.local/share/uv/python become invisible to ExecStart, so keep
    // any downloaded Python under /opt alongside the dashboard.
    const venv_res = sys.exec(allocator, dashboardVenvCreateArgv()) catch {
        ui.fail("Failed to create virtualenv with uv");
        return;
    };
    defer venv_res.deinit();

    if (venv_res.exit_code != 0) {
        ui.fail("uv venv creation failed");
        return;
    }

    ui.ok("Virtualenv created at " ++ VENV_DIR);

    ui.step("Installing Python dependencies (fastapi, uvicorn, psutil, websockets)...");

    // Pin exact versions instead of floating to latest (removes dependency
    // drift / confusion for the root-privileged control-plane venv). fastapi
    // 0.115.6 requires starlette>=0.40,<0.42, satisfied by 0.41.3. The stronger
    // `uv pip install --require-hashes -r requirements.txt` (full transitive hash
    // pinning) is the follow-up.
    const pip_res = sys.exec(allocator, dashboardPipInstallArgv()) catch {
        ui.fail("Failed to install Python dependencies via uv");
        return;
    };
    defer pip_res.deinit();

    if (pip_res.exit_code != 0) {
        ui.fail("uv pip install failed — check network connectivity");
        return;
    }

    ui.ok("Python dependencies installed");

    // ── Setup Systemd Service ──
    ui.step("Configuring systemd service...");

    const svc_content =
        \\[Unit]
        \\Description=MTProto Proxy Monitor
        \\After=network.target mtproto-proxy.service
        \\
        \\[Service]
        \\ExecStart=/opt/mtproto-proxy/monitor/.venv/bin/python /opt/mtproto-proxy/monitor/server.py
        \\Restart=on-failure
        \\RestartSec=5
        \\WorkingDirectory=/opt/mtproto-proxy/monitor
        \\# Defense-in-depth: this is a root control plane (it shells out to systemctl/ip/
        \\# journalctl and rewrites config.toml), so it keeps full filesystem write + caps,
        \\# but bounds the kernel attack surface a compromise of the Python process could
        \\# reach. AF_NETLINK is kept for `ip`; AF_UNIX for the systemd/dbus socket.
        \\NoNewPrivileges=yes
        \\ProtectKernelTunables=yes
        \\ProtectKernelModules=yes
        \\ProtectKernelLogs=yes
        \\ProtectControlGroups=yes
        \\ProtectClock=yes
        \\ProtectHome=yes
        \\PrivateTmp=yes
        \\RestrictRealtime=yes
        \\RestrictSUIDSGID=yes
        \\LockPersonality=yes
        \\RestrictNamespaces=yes
        \\RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
        \\
        \\[Install]
        \\WantedBy=multi-user.target
    ;

    sys.writeFile(SERVICE_FILE, svc_content) catch {
        ui.fail("Failed to write systemd service file");
        return;
    };

    _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};
    _ = sys.execForward(&.{ "systemctl", "enable", SERVICE_NAME }) catch {};

    ui.ok("Systemd service " ++ SERVICE_NAME ++ " enabled");

    // ── Start Service ──
    ui.step("Starting dashboard...");
    _ = sys.execForward(&.{ "systemctl", "restart", SERVICE_NAME }) catch {};

    // Let it bind
    _ = sys.execForward(&.{ "sleep", "1" }) catch {};

    if (!sys.isServiceActive(SERVICE_NAME)) {
        ui.fail("Dashboard failed to start. Check: journalctl -u " ++ SERVICE_NAME ++ " -n 30");
        return;
    }

    ui.ok("Dashboard started successfully");

    // ── Summary ──
    if (!opts.quiet) {
        ui.summaryBox("Monitoring Dashboard Installed", &.{
            .{ .label = "Status:", .value = "systemctl status " ++ SERVICE_NAME },
            .{ .label = "Logs:", .value = "journalctl -u " ++ SERVICE_NAME ++ " -f" },
            .{ .label = "Port:", .value = "61208 (default, see config.toml)" },
            .{ .label = "", .style = .blank },
            .{ .label = "Login: HTTP Basic auth (username: any)", .style = .success },
            .{ .label = "  password: cat /opt/mtproto-proxy/monitor/dashboard.token", .style = .success },
            .{ .label = "", .style = .blank },
            .{ .label = "Access via secure SSH Tunnel:", .style = .success },
            .{ .label = "  ssh -L 61208:localhost:61208 root@<server_ip>", .style = .success },
            .{ .label = "  open http://localhost:61208", .style = .success },
            .{ .label = "", .style = .blank },
            .{ .label = "Exposing publicly? Keep the token secret and put HTTPS +", .style = .highlight },
            .{ .label = "the proxy behind Nginx — never expose plain HTTP to the internet.", .style = .highlight },
        });
    }
}

test "dashboard venv keeps uv-managed Python outside ProtectHome paths" {
    const argv = dashboardVenvCreateArgv();
    try std.testing.expect(argv.len >= 4);
    try std.testing.expectEqualStrings("env", argv[0]);
    try std.testing.expectEqualStrings("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", argv[1]);
    try std.testing.expectEqualStrings("UV_PYTHON_INSTALL_DIR=/opt/mtproto-proxy/monitor/.uv-python", argv[2]);
    try std.testing.expectEqualStrings("uv", argv[3]);
}
