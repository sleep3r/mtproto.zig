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
    local_backend: bool = false,
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
        } else if (std.mem.eql(u8, arg, "--local")) {
            opts.local_backend = true;
        } else if (arg.len > 0 and arg[0] != '-') {
            opts.tls_domain = arg;
            opts.domain_explicit = true;
        } else {
            ui.print("Unknown option: {s}\n", .{arg});
            return error.UnknownOption;
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

    if (!fronting_domain.isSafeFrontingDomain(opts.tls_domain)) return error.InvalidFrontingDomain;
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

    // A borrowed fronting hostname cannot pass ACME ownership validation. Reuse
    // operator-provided certificates; certificate issuance belongs to setup web.
    const cert_ok = sys.fileExists(CERT_DIR ++ "/cert.pem") and sys.fileExists(CERT_DIR ++ "/key.pem");

    if (!cert_ok) {
        ui.step("Generating self-signed certificate...");
        var subj_buf: [280]u8 = undefined;
        const subj = try std.fmt.bufPrint(&subj_buf, "/CN={s}", .{opts.tls_domain});
        const generated = sys.execForward(&.{
            "openssl", "req",                             "-x509", "-newkey",                          "ec",    "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-keyout", CERT_DIR ++ "/selfsigned-key.pem", "-out",  CERT_DIR ++ "/selfsigned-cert.pem", "-days", "3650",     "-nodes",
            "-subj",   subj,
        }) catch return;
        if (generated != 0) {
            ui.fail("Certificate generation failed");
            return;
        }
        // Replace directory entries, never write through Let's Encrypt symlinks.
        std.Io.Dir.renameAbsolute(CERT_DIR ++ "/selfsigned-key.pem", CERT_DIR ++ "/key.pem", std.Io.Threaded.global_single_threaded.io()) catch return;
        std.Io.Dir.renameAbsolute(CERT_DIR ++ "/selfsigned-cert.pem", CERT_DIR ++ "/cert.pem", std.Io.Threaded.global_single_threaded.io()) catch return;
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
    const old_cover = sys.readFileAllocAbsolute(allocator, "/var/www/masking/index.html", 64 * 1024);
    defer if (old_cover) |p| allocator.free(p);
    const legacy_cover = "<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>\n";
    // Replace the known shipped placeholder, preserving operator content.
    if (old_cover == null or std.mem.eql(u8, old_cover.?, legacy_cover)) {
        var nonce: [16]u8 = undefined;
        std.Io.Threaded.global_single_threaded.io().random(&nonce);
        const page = try @import("cover_page").renderCover(allocator, &nonce);
        defer allocator.free(page);
        try sys.writeFile("/var/www/masking/index.html", page);
    }

    const nginx_cfg = try renderNginxConfig(allocator, opts.tls_domain);
    defer allocator.free(nginx_cfg);

    try sys.writeFile("/etc/nginx/sites-available/mtproto-masking", nginx_cfg);

    _ = sys.exec(allocator, &.{ "ln", "-sf", "/etc/nginx/sites-available/mtproto-masking", "/etc/nginx/sites-enabled/" }) catch {};
    const nginx_bin = sys.commandOrPath("nginx", &.{ "/usr/sbin/nginx", "/sbin/nginx" });
    const nginx_test = sys.exec(allocator, &.{ nginx_bin, "-t" }) catch {
        ui.fail("Could not run nginx -t; leaving the default site enabled");
        return error.NginxTestFailed;
    };
    defer nginx_test.deinit();
    if (nginx_test.exit_code != 0) {
        _ = sys.exec(allocator, &.{ "rm", "-f", "/etc/nginx/sites-enabled/mtproto-masking" }) catch {};
        return error.NginxTestFailed;
    }

    // Config is valid — now it is safe to disable the default site and reload.
    _ = sys.exec(allocator, &.{ "rm", "-f", "/etc/nginx/sites-enabled/default" }) catch {};
    _ = sys.execForward(&.{ "systemctl", "restart", "nginx" }) catch {};
    _ = sys.exec(allocator, &.{ "systemctl", "enable", "nginx" }) catch {};
    ui.ok("Nginx configured on 127.0.0.1:" ++ NGINX_PORT);

    var config_written = false;
    if (sys.fileExists(config_path)) {
        var doc = try toml.TomlDoc.load(allocator, config_path);
        defer doc.deinit();
        const domain_value = try std.fmt.allocPrint(allocator, "\"{s}\"", .{opts.tls_domain});
        defer allocator.free(domain_value);
        try doc.set("censorship", "tls_domain", domain_value);
        const previous_port = doc.get("censorship", "mask_port") orelse "443";
        if (opts.local_backend or !std.mem.eql(u8, std.mem.trim(u8, previous_port, " \t\""), "443")) {
            try doc.set("censorship", "mask_port", NGINX_PORT);
        } else ui.warn("Keeping remote-origin masking on port 443. Use setup masking --local to explicitly switch to the local cover site.");
        try doc.set("censorship", "mask", "true");
        try doc.save(config_path);
        config_written = true;
    }

    if (config_written and sys.isServiceActive("mtproto-proxy")) {
        const restarted = try sys.exec(allocator, &.{ "systemctl", "restart", "mtproto-proxy" });
        defer restarted.deinit();
        if (restarted.exit_code != 0) return error.ProxyRestartFailed;
    }
    if (!opts.skip_monitor) try @import("recovery.zig").execute(ui, allocator, .{ .quiet = true });
    ui.ok("Local Nginx cover site configured; remote-origin and local-cover masking have different fingerprint tradeoffs.");
}

fn renderNginxConfig(allocator: std.mem.Allocator, domain: []const u8) ![]u8 {
    if (!fronting_domain.isSafeFrontingDomain(domain)) return error.InvalidFrontingDomain;
    return std.fmt.allocPrint(allocator,
        \\# MTProto proxy masking server — local only
        \\server {{
        \\    listen 127.0.0.1:{[port]s} ssl default_server;
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
        .domain = domain,
        .cert_dir = CERT_DIR,
    });
}

test "masking renderer selects explicit default vhost and rejects injected domains" {
    const allocator = std.testing.allocator;
    const rendered = try renderNginxConfig(allocator, "example.com");
    defer allocator.free(rendered);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "listen 127.0.0.1:8443 ssl default_server;") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "server_name example.com;") != null);
    try std.testing.expectError(error.InvalidFrontingDomain, renderNginxConfig(allocator, "example.com;return 200"));
    try std.testing.expectError(error.InvalidFrontingDomain, renderNginxConfig(allocator, "bad..example"));
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
