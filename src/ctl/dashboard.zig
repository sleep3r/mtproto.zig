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
const SERVICE_NAME = "proxy-monitor";
const SERVICE_FILE = "/etc/systemd/system/" ++ SERVICE_NAME ++ ".service";

// Embed dashboard assets at comptime
const server_py = @embedFile("dashboard_assets/server.py");
const index_html = @embedFile("dashboard_assets/static/index.html");
const style_css = @embedFile("dashboard_assets/static/style.css");
const app_js = @embedFile("dashboard_assets/static/app.js");
const logo_svg = @embedFile("dashboard_assets/static/logo.svg");

pub const DashboardOpts = struct {
    quiet: bool = false,
};

/// Run in CLI mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.ArgIterator) !void {
    var opts = DashboardOpts{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--quiet")) {
            opts.quiet = true;
        }
    }
    try execute(ui, allocator, opts);
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

    // Download the latest release tarball from GitHub and extract `uv` binary.
    // GitHub is reliably accessible even when astral.sh is blocked.
    const result = sys.exec(allocator, &.{
        "sh", "-c",
        \\set -e
        \\UV_URL="https://github.com/astral-sh/uv/releases/latest/download/uv-x86_64-unknown-linux-gnu.tar.gz"
        \\TMP_DIR=$(mktemp -d)
        \\trap 'rm -rf "$TMP_DIR"' EXIT
        \\curl -fsSL "$UV_URL" -o "$TMP_DIR/uv.tar.gz"
        \\tar -xzf "$TMP_DIR/uv.tar.gz" -C "$TMP_DIR" --strip-components=1
        \\install -m 0755 "$TMP_DIR/uv" /usr/local/bin/uv
        \\if [ -f "$TMP_DIR/uvx" ]; then install -m 0755 "$TMP_DIR/uvx" /usr/local/bin/uvx; fi
    }) catch {
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

    const venv_res = sys.exec(allocator, &.{
        "uv", "venv", VENV_DIR, "--python", "python3",
    }) catch {
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

    const pip_res = sys.exec(allocator, &.{
        "uv",     "pip",   "install",
        "--python", VENV_PYTHON,
        "fastapi", "uvicorn", "psutil", "websockets", "starlette",
    }) catch {
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
            .{ .label = "Logs:",   .value = "journalctl -u " ++ SERVICE_NAME ++ " -f" },
            .{ .label = "Port:",   .value = "61208 (default, see config.toml)" },
            .{ .label = "", .style = .blank },
            .{ .label = "Access via secure SSH Tunnel:", .style = .success },
            .{ .label = "  ssh -L 61208:localhost:61208 root@<server_ip>", .style = .success },
            .{ .label = "  open http://localhost:61208", .style = .success },
            .{ .label = "", .style = .blank },
            .{ .label = "Or expose to internet via Nginx proxy_pass", .style = .success },
        });
    }
}
