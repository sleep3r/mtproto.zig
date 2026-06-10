//! Setup masking command for mtbuddy.
//!
//! Ports setup_masking.sh (274 lines bash) — installs local Nginx
//! for zero-RTT DPI masking. Eliminates the timing side-channel
//! that TSPU uses to detect proxy masking connections.

const std = @import("std");
const tui_mod = @import("tui.zig");
const i18n = @import("i18n.zig");
const sys = @import("sys.zig");
const toml = @import("toml.zig");
const fronting_domain = @import("fronting_domain.zig");

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;
const SummaryLine = tui_mod.SummaryLine;

const INSTALL_DIR = "/opt/mtproto-proxy";
const CERT_DIR = "/etc/nginx/ssl";
pub const NGINX_PORT = "8443";

pub const MaskingOpts = struct {
    tls_domain: []const u8 = "rutube.ru",
    skip_monitor: bool = false,
    /// Operator explicitly asked for this domain (--domain / positional / interactive
    /// change). When false, execute() keeps the tls_domain already in config.toml.
    domain_explicit: bool = false,
    /// Allow changing an already-configured tls_domain even though it breaks every
    /// distributed share link.
    force: bool = false,
};

const config_path = INSTALL_DIR ++ "/config.toml";

/// Read the unquoted `[censorship].tls_domain` from config.toml into `buf`, or null when
/// absent/unreadable. tls_domain is immutable on a live deploy (every share link embeds
/// it), so callers default to this instead of clobbering it with "rutube.ru".
fn readConfiguredTlsDomain(allocator: std.mem.Allocator, buf: []u8) ?[]const u8 {
    if (!sys.fileExists(config_path)) return null;
    var doc = toml.TomlDoc.load(allocator, config_path) catch return null;
    defer doc.deinit();
    const raw = doc.get("censorship", "tls_domain") orelse return null;
    const trimmed = std.mem.trim(u8, raw, " \t\"");
    if (trimmed.len == 0 or trimmed.len > buf.len) return null;
    @memcpy(buf[0..trimmed.len], trimmed);
    return buf[0..trimmed.len];
}

/// Run in CLI mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    var opts = MaskingOpts{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--domain")) {
            if (args.next()) |val| {
                opts.tls_domain = val;
                opts.domain_explicit = true;
            }
        } else if (std.mem.eql(u8, arg, "--no-monitor")) {
            opts.skip_monitor = true;
        } else if (std.mem.eql(u8, arg, "--force")) {
            opts.force = true;
        } else if (arg.len > 0 and arg[0] != '-') {
            opts.tls_domain = arg;
            opts.domain_explicit = true;
        }
    }
    try execute(ui, allocator, opts);
}

/// Run in interactive mode.
pub fn runInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    ui.section(i18n.get(ui.lang, .menu_setup_masking));

    // Default the prompt to the domain already deployed — changing it breaks live links.
    var existing_buf: [320]u8 = undefined;
    const existing = readConfiguredTlsDomain(allocator, &existing_buf);

    var domain_buf: [256]u8 = undefined;
    const domain = try ui.input(
        i18n.get(ui.lang, .install_domain_prompt),
        i18n.get(ui.lang, .install_domain_help),
        existing orelse "rutube.ru",
        &domain_buf,
    );

    if (!try ui.confirm(i18n.get(ui.lang, .confirm_proceed), true)) {
        ui.info(i18n.get(ui.lang, .aborting));
        return;
    }

    // If the operator typed a domain different from the live one, require informed consent
    // before clobbering it.
    var force = false;
    if (existing) |e| {
        if (!std.mem.eql(u8, e, domain)) {
            var warn_buf: [512]u8 = undefined;
            const msg = std.fmt.bufPrint(&warn_buf, "Changing tls_domain from '{s}' to '{s}' INVALIDATES every share link already distributed.", .{ e, domain }) catch "Changing tls_domain invalidates every distributed share link.";
            ui.warn(msg);
            if (!try ui.confirm("Change tls_domain anyway?", false)) {
                ui.info(i18n.get(ui.lang, .aborting));
                return;
            }
            force = true;
        }
    }

    try execute(ui, allocator, .{ .tls_domain = domain, .domain_explicit = true, .force = force });
}

pub fn execute(ui: *Tui, allocator: std.mem.Allocator, opts_in: MaskingOpts) !void {
    if (!sys.isRoot()) {
        ui.fail(i18n.get(ui.lang, .error_not_root));
        return;
    }

    var opts = opts_in;

    // tls_domain is immutable on a live deploy — every distributed share link embeds it.
    // Keep whatever config.toml already has unless the operator explicitly chose a new one.
    var existing_domain_buf: [320]u8 = undefined;
    if (readConfiguredTlsDomain(allocator, &existing_domain_buf)) |cur| {
        if (!opts.domain_explicit) {
            opts.tls_domain = cur;
        } else if (!std.mem.eql(u8, cur, opts.tls_domain) and !opts.force) {
            var msg_buf: [512]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "Refusing to change tls_domain from '{s}' to '{s}' — this invalidates every distributed share link. Re-run with --force to override.", .{ cur, opts.tls_domain }) catch "Refusing to change tls_domain (would break share links); re-run with --force.";
            ui.fail(msg);
            return;
        }
    }

    _ = fronting_domain.warnIfPoorFrontingDomain(ui, allocator, opts.tls_domain);

    // ── Install Nginx ──
    if (sys.commandExists("nginx")) {
        ui.ok("Nginx already installed");
    } else {
        ui.step("Installing Nginx...");
        if (!runLogged(ui, allocator, &.{ "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", "DPkg::Lock::Timeout=600", "update", "-qq" }, "apt-get update failed")) return;
        if (!runLogged(ui, allocator, &.{
            "env",
            "DEBIAN_FRONTEND=noninteractive",
            "apt-get",
            "-o",
            "DPkg::Lock::Timeout=600",
            "-o",
            "Dpkg::Options::=--force-confdef",
            "-o",
            "Dpkg::Options::=--force-confold",
            "install",
            "-y",
            "nginx",
        }, "Failed to install Nginx")) return;
        ui.ok("Nginx installed");
    }

    // ── Generate certificates ──
    _ = sys.exec(allocator, &.{ "mkdir", "-p", CERT_DIR }) catch {};

    var cert_ok = false;
    if (sys.commandExists("certbot")) {
        ui.step("Attempting Let's Encrypt certificate...");
        const r = sys.exec(allocator, &.{
            "certbot",           "certonly",    "--nginx",                           "-d", opts.tls_domain,
            "--non-interactive", "--agree-tos", "--register-unsafely-without-email",
        }) catch null;
        if (r) |result| {
            defer result.deinit();
            if (result.exit_code == 0) {
                var symlink_buf: [256]u8 = undefined;
                const fullchain = std.fmt.bufPrint(&symlink_buf, "/etc/letsencrypt/live/{s}/fullchain.pem", .{opts.tls_domain}) catch "";
                if (fullchain.len > 0) {
                    _ = sys.exec(allocator, &.{ "ln", "-sf", fullchain, CERT_DIR ++ "/cert.pem" }) catch {};
                    var key_buf: [256]u8 = undefined;
                    const privkey = std.fmt.bufPrint(&key_buf, "/etc/letsencrypt/live/{s}/privkey.pem", .{opts.tls_domain}) catch "";
                    if (privkey.len > 0) {
                        _ = sys.exec(allocator, &.{ "ln", "-sf", privkey, CERT_DIR ++ "/key.pem" }) catch {};
                    }
                }
                ui.ok("Let's Encrypt certificate obtained");
                cert_ok = true;
            }
        }
    }

    if (!cert_ok) {
        ui.step("Generating self-signed certificate...");
        var subj_buf: [128]u8 = undefined;
        const subj = std.fmt.bufPrint(&subj_buf, "/CN={s}", .{opts.tls_domain}) catch "/CN=rutube.ru";
        _ = sys.execForward(&.{
            "openssl", "req",                  "-x509", "-newkey",               "ec",    "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-keyout", CERT_DIR ++ "/key.pem", "-out",  CERT_DIR ++ "/cert.pem", "-days", "3650",     "-nodes",
            "-subj",   subj,
        }) catch {};
        ui.ok("Self-signed certificate generated");
    }

    // openssl failures are swallowed above; a missing key/cert is exactly what makes the
    // later `nginx -t` fail, so bail now rather than tearing down the default site first.
    if (!sys.fileExists(CERT_DIR ++ "/cert.pem") or !sys.fileExists(CERT_DIR ++ "/key.pem")) {
        ui.fail("TLS certificate or key is missing — cannot configure masking");
        return;
    }

    // ── Configure Nginx ──
    ui.step("Configuring Nginx...");
    sys.execSilent(allocator, &.{ "mkdir", "-p", "/var/www/masking" });
    sys.writeFile("/var/www/masking/index.html", "<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>\n") catch {};

    var nginx_cfg_buf: [2048]u8 = undefined;
    const nginx_cfg = std.fmt.bufPrint(&nginx_cfg_buf,
        \\# MTProto proxy masking server — local only
        \\server {{
        \\    listen 127.0.0.1:{[port]s} ssl;
        \\
        \\    server_name {[domain]s};
        \\
        \\    ssl_certificate     {[cert_dir]s}/cert.pem;
        \\    ssl_certificate_key {[cert_dir]s}/key.pem;
        \\
        \\    ssl_protocols TLSv1.2 TLSv1.3;
        \\    ssl_prefer_server_ciphers off;
        \\
        \\    root /var/www/masking;
        \\    index index.html;
        \\
        \\    location / {{
        \\        try_files $uri $uri/ =404;
        \\    }}
        \\
        \\    access_log off;
        \\    error_log /var/log/nginx/masking-error.log warn;
        \\}}
    , .{
        .port = NGINX_PORT,
        .domain = opts.tls_domain,
        .cert_dir = CERT_DIR,
    }) catch "";

    if (nginx_cfg.len > 0) {
        // Write config using native Zig I/O (no shell injection risk)
        sys.writeFile("/etc/nginx/sites-available/mtproto-masking", nginx_cfg) catch {
            ui.fail("Failed to write Nginx config");
            return;
        };
    }

    // Enable our vhost and validate BEFORE removing the default site, so a failed test
    // never leaves nginx with a broken config and no default vhost (which would take
    // nginx fully down on its next restart — reboot, certbot hook, mask-health timer).
    _ = sys.exec(allocator, &.{ "ln", "-sf", "/etc/nginx/sites-available/mtproto-masking", "/etc/nginx/sites-enabled/" }) catch {};

    const nginx_test = sys.exec(allocator, &.{ "nginx", "-t" }) catch null;
    if (nginx_test) |r| {
        defer r.deinit();
        if (r.exit_code != 0) {
            // Roll back: drop only our vhost, leaving the existing config (incl. default).
            _ = sys.exec(allocator, &.{ "rm", "-f", "/etc/nginx/sites-enabled/mtproto-masking" }) catch {};
            ui.fail("Nginx config test failed — masking vhost rolled back, nginx left unchanged");
            return;
        }
    }

    // Config is valid — now it is safe to disable the default site and reload.
    _ = sys.exec(allocator, &.{ "rm", "-f", "/etc/nginx/sites-enabled/default" }) catch {};
    _ = sys.execForward(&.{ "systemctl", "restart", "nginx" }) catch {};
    _ = sys.exec(allocator, &.{ "systemctl", "enable", "nginx" }) catch {};
    ui.ok("Nginx configured on 127.0.0.1:" ++ NGINX_PORT);

    // ── Verify Nginx ──
    {
        const check = sys.exec(allocator, &.{ "curl", "-sk", "--max-time", "3", "https://127.0.0.1:" ++ NGINX_PORT ++ "/" }) catch null;
        if (check) |r| {
            defer r.deinit();
            if (r.exit_code == 0) {
                ui.ok("Nginx responding on https://127.0.0.1:" ++ NGINX_PORT);
            } else {
                ui.warn("Nginx not responding yet");
            }
        }
    }

    // ── Update mtproto config ──
    var config_written = false;
    if (sys.fileExists(config_path)) {
        var doc = toml.TomlDoc.load(allocator, config_path) catch {
            ui.warn("Could not read config.toml");
            return;
        };
        defer doc.deinit();

        var tls_domain_val_buf: [320]u8 = undefined;
        const tls_domain_val = std.fmt.bufPrint(&tls_domain_val_buf, "\"{s}\"", .{opts.tls_domain}) catch {
            ui.warn("Could not update tls_domain in config.toml");
            return;
        };

        try doc.set("censorship", "tls_domain", tls_domain_val);
        try doc.set("censorship", "mask_port", NGINX_PORT);
        try doc.set("censorship", "mask", "true");
        doc.save(config_path) catch {};
        _ = sys.exec(allocator, &.{ "chown", "mtproto:mtproto", config_path }) catch {};
        ui.ok("Updated config.toml with tls_domain, mask=true, mask_port = " ++ NGINX_PORT);
        config_written = true;
    }

    // The running proxy only re-reads config on reload/restart. Apply it now so masking
    // actually takes effect instead of waiting for some arbitrary later restart (the
    // fresh-install path is covered by install.zig's final restart; this is the standalone
    // `mtbuddy setup-masking` path).
    if (config_written and sys.isServiceActive("mtproto-proxy")) {
        var reloaded = false;
        if (sys.exec(allocator, &.{ "systemctl", "reload", "mtproto-proxy" }) catch null) |r| {
            defer r.deinit();
            reloaded = r.exit_code == 0;
        }
        if (!reloaded) _ = sys.execForward(&.{ "systemctl", "restart", "mtproto-proxy" }) catch {};
        ui.ok("Reloaded mtproto-proxy to apply masking");
    }

    // ── Install masking monitor ──
    if (!opts.skip_monitor) {
        const recovery = @import("recovery.zig");
        recovery.execute(ui, allocator, .{ .quiet = true }) catch |err| {
            ui.warn("Failed to install auto-recovery module");
            std.log.debug("Recovery install error: {any}", .{err});
        };
    }

    // ── Summary ──
    ui.summaryBox("Local Nginx Masking Configured", &.{
        .{ .label = "Nginx:", .value = "127.0.0.1:" ++ NGINX_PORT ++ " (TLS)" },
        .{ .label = "Domain:", .value = opts.tls_domain },
        .{ .label = "Cert:", .value = CERT_DIR ++ "/cert.pem" },
        .{ .label = "Monitor:", .value = "systemctl status mtproto-mask-health.timer" },
        .{ .label = "", .style = .blank },
        .{ .label = "Bad clients are now forwarded to local Nginx (<1ms RTT)", .style = .success },
        .{ .label = "Timing side-channel eliminated", .style = .success },
    });
}

fn runLogged(ui: *Tui, allocator: std.mem.Allocator, argv: []const []const u8, failure_msg: []const u8) bool {
    const result = sys.exec(allocator, argv) catch |err| {
        ui.fail(failure_msg);
        ui.print("  {s}◆{s} Failed to spawn command: {s}\n", .{ Color.info, Color.reset, @errorName(err) });
        return false;
    };
    defer result.deinit();

    if (result.exit_code == 0) return true;

    ui.fail(failure_msg);
    printCommandOutput(ui, &result);
    return false;
}

fn printCommandOutput(ui: *Tui, result: *const sys.ExecResult) void {
    const stderr = std.mem.trim(u8, result.stderr, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (stderr.len > 0) {
        ui.print("  stderr:\n{s}\n", .{tailBytes(stderr, 4096)});
    }

    const stdout = std.mem.trim(u8, result.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (stdout.len > 0) {
        ui.print("  stdout:\n{s}\n", .{tailBytes(stdout, 4096)});
    }
}

fn tailBytes(bytes: []const u8, max_len: usize) []const u8 {
    if (bytes.len <= max_len) return bytes;
    return bytes[bytes.len - max_len ..];
}
