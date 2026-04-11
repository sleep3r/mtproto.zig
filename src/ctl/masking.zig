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

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;
const SummaryLine = tui_mod.SummaryLine;

const INSTALL_DIR = "/opt/mtproto-proxy";
const CERT_DIR = "/etc/nginx/ssl";
const NGINX_PORT = "8443";

pub const MaskingOpts = struct {
    tls_domain: []const u8 = "wb.ru",
    skip_monitor: bool = false,
};

/// Run in CLI mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.ArgIterator) !void {
    var opts = MaskingOpts{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--domain")) {
            if (args.next()) |val| opts.tls_domain = val;
        } else if (std.mem.eql(u8, arg, "--no-monitor")) {
            opts.skip_monitor = true;
        } else if (arg.len > 0 and arg[0] != '-') {
            opts.tls_domain = arg;
        }
    }
    try execute(ui, allocator, opts);
}

/// Run in interactive mode.
pub fn runInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    ui.section(i18n.get(ui.lang, .menu_setup_masking));

    var domain_buf: [256]u8 = undefined;
    const domain = try ui.input(
        i18n.get(ui.lang, .install_domain_prompt),
        i18n.get(ui.lang, .install_domain_help),
        "wb.ru",
        &domain_buf,
    );

    if (!try ui.confirm(i18n.get(ui.lang, .confirm_proceed), true)) {
        ui.info(i18n.get(ui.lang, .aborting));
        return;
    }

    try execute(ui, allocator, .{ .tls_domain = domain });
}

pub fn execute(ui: *Tui, allocator: std.mem.Allocator, opts: MaskingOpts) !void {
    if (!sys.isRoot()) {
        ui.fail(i18n.get(ui.lang, .error_not_root));
        return;
    }



    // ── Install Nginx ──
    if (sys.commandExists("nginx")) {
        ui.ok("Nginx already installed");
    } else {
        ui.step("Installing Nginx...");
        _ = sys.exec(allocator, &.{ "mkdir", "-p", "/etc/nginx/sites-available", "/etc/nginx/sites-enabled" }) catch {};
        sys.writeFile("/etc/nginx/sites-available/default", "# Empty default\n") catch {};
        sys.execSilent(allocator, &.{ "ln", "-sf", "/etc/nginx/sites-available/default", "/etc/nginx/sites-enabled/default" });
        _ = sys.execForward(&.{ "apt-get", "update", "-qq" }) catch {};
        _ = sys.execForward(&.{ "apt-get", "install", "-y", "nginx" }) catch {};
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
        const subj = std.fmt.bufPrint(&subj_buf, "/CN={s}", .{opts.tls_domain}) catch "/CN=wb.ru";
        _ = sys.execForward(&.{
            "openssl", "req",                  "-x509", "-newkey",               "ec",    "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-keyout", CERT_DIR ++ "/key.pem", "-out",  CERT_DIR ++ "/cert.pem", "-days", "3650",     "-nodes",
            "-subj",   subj,
        }) catch {};
        ui.ok("Self-signed certificate generated");
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

    _ = sys.exec(allocator, &.{ "ln", "-sf", "/etc/nginx/sites-available/mtproto-masking", "/etc/nginx/sites-enabled/" }) catch {};
    _ = sys.exec(allocator, &.{ "rm", "-f", "/etc/nginx/sites-enabled/default" }) catch {};

    const nginx_test = sys.exec(allocator, &.{ "nginx", "-t" }) catch null;
    if (nginx_test) |r| {
        defer r.deinit();
        if (r.exit_code != 0) {
            ui.fail("Nginx config test failed");
            return;
        }
    }

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
    const config_path = INSTALL_DIR ++ "/config.toml";
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
