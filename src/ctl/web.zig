//! `mtbuddy setup web` — provision the WEB proxy relay.
//!
//! Telegram Desktop 7.1 added a fourth proxy type whose carrier is a browser: a hidden
//! WebView loads `https://<domain>/?bridge=<capability>` and tunnels MTProto over a
//! same-origin WebSocket. To the network it is an ordinary visit to an ordinary website.
//! This module builds that website.
//!
//! ## The port-443 problem, and the two topologies
//!
//! The client hard-codes port 443 for the relay host, and our proxy already owns 443.
//! There are exactly two honest ways out, and this module implements both:
//!
//! **`--mode mask` (default).** The proxy already forwards every non-MTProto TLS
//! connection on :443 to its masking backend. So we make the relay *be* part of that
//! backend: a second nginx vhost on the masking port, selected by SNI, holding a real
//! Let's Encrypt certificate for the relay domain. A browser reaching `https://<domain>/`
//! hits the proxy, fails MTProto validation, is masked to nginx, and gets a genuine
//! site. Probes with any other SNI keep hitting the masking vhost exactly as before.
//! Nothing about the existing deployment changes except that one more vhost exists.
//!
//! **`--mode behind`.** The relay listens on plain HTTP and someone else terminates TLS
//! — Cloudflare, a second host, a spare IP. This is the stronger option for censorship
//! resistance (the client connects to CDN addresses, not to us) and the one to pick when
//! the operator already has a web presence.
//!
//! ## Order of operations
//!
//! nginx-touching steps follow `masking.zig`'s discipline exactly: symlink first, then
//! `nginx -t`, and on failure remove **only our own** symlink and leave nginx untouched.
//! A vhost that breaks nginx would otherwise be caught by the mask-health timer, which
//! restarts `mtproto-proxy` every minute while the masking probe fails.

const std = @import("std");
const tui_mod = @import("tui.zig");
const i18n = @import("i18n.zig");
const sys = @import("sys.zig");
const toml = @import("toml.zig");
const masking = @import("masking.zig");
const web_capability = @import("web_capability");

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;
const SummaryLine = tui_mod.SummaryLine;

const INSTALL_DIR = "/opt/mtproto-proxy";
const config_path = INSTALL_DIR ++ "/config.toml";

pub const SERVICE_NAME = "mtproto-web-relay";
const SERVICE_FILE = "/etc/systemd/system/" ++ SERVICE_NAME ++ ".service";
const NGINX_SITE = "/etc/nginx/sites-available/mtproto-web";
const NGINX_LINK = "/etc/nginx/sites-enabled/mtproto-web";
const ACME_ROOT = "/var/www/acme";
const RENEW_HOOK = "/etc/letsencrypt/renewal-hooks/deploy/mtproto-web-reload.sh";

/// Relay listener. Loopback only: TLS is always terminated in front of it.
pub const DEFAULT_PORT = "8081";

/// Second TLS listener for the relay vhost, distinguished from the masking port only by
/// `proxy_protocol`. The proxy sends masked connections whose SNI is the relay domain
/// here, prefixed with the real client address; everything else keeps using
/// `masking.NGINX_PORT` exactly as before.
pub const PROXY_PROTOCOL_PORT = "8444";

pub const Mode = enum {
    /// Serve the relay through the proxy's own masking backend on :443.
    mask,
    /// Someone else terminates TLS (CDN, another host, a spare IP).
    behind,
};

pub const WebOpts = struct {
    domain: []const u8 = "",
    mode: Mode = .mask,
    port: []const u8 = DEFAULT_PORT,
    /// Contact address for the ACME account; empty registers without one.
    email: []const u8 = "",
    /// Skip certificate issuance (the operator installed one already).
    skip_cert: bool = false,
    quiet: bool = false,
    yes: bool = false,
};

fn tr(ui: *Tui, en: []const u8, ru: []const u8) []const u8 {
    return if (ui.lang == .ru) ru else en;
}

// ── entry points ──────────────────────────────────────────────────────────────

pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    var opts = WebOpts{};
    var do_remove = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--domain") or std.mem.eql(u8, arg, "-d")) {
            opts.domain = args.next() orelse "";
        } else if (std.mem.eql(u8, arg, "--mode")) {
            const value = args.next() orelse "";
            if (std.mem.eql(u8, value, "mask")) {
                opts.mode = .mask;
            } else if (std.mem.eql(u8, value, "behind") or std.mem.eql(u8, value, "cdn")) {
                opts.mode = .behind;
            } else {
                ui.fail(tr(ui, "Unknown --mode (expected: mask|behind)", "Неизвестный --mode (ожидается: mask|behind)"));
                return;
            }
        } else if (std.mem.eql(u8, arg, "--port")) {
            opts.port = args.next() orelse DEFAULT_PORT;
        } else if (std.mem.eql(u8, arg, "--email")) {
            opts.email = args.next() orelse "";
        } else if (std.mem.eql(u8, arg, "--skip-cert")) {
            opts.skip_cert = true;
        } else if (std.mem.eql(u8, arg, "--quiet")) {
            opts.quiet = true;
        } else if (std.mem.eql(u8, arg, "--yes") or std.mem.eql(u8, arg, "-y")) {
            opts.yes = true;
        } else if (std.mem.eql(u8, arg, "--remove") or std.mem.eql(u8, arg, "--uninstall")) {
            do_remove = true;
        } else if (arg.len > 0 and arg[0] != '-') {
            opts.domain = arg;
        }
    }

    if (do_remove) return remove(ui, allocator);
    try execute(ui, allocator, opts);
}

pub fn runInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    ui.section(tr(ui, "WEB proxy (Telegram Desktop 7.1+)", "WEB-прокси (Telegram Desktop 7.1+)"));
    ui.print("  {s}{s}{s}\n\n", .{
        Color.dim,
        tr(
            ui,
            "A WEB proxy reaches Telegram through an ordinary HTTPS website, so a censor\n  sees a browser visiting a site — not a proxy connection. It needs a domain you\n  own, pointed at this server.",
            "WEB-прокси ходит в Telegram через обычный HTTPS-сайт: цензор видит визит\n  браузера на сайт, а не подключение к прокси. Нужен ваш домен, направленный\n  на этот сервер.",
        ),
        Color.reset,
    });

    var domain_buf: [256]u8 = undefined;
    var existing_buf: [256]u8 = undefined;
    const existing = readConfigured(allocator, "domain", &existing_buf);
    const domain = try ui.input(
        tr(ui, "Relay domain (e.g. relay.example.com)", "Домен релея (например relay.example.com)"),
        tr(ui, "Must be a real DNS name you control, with an A record pointing here.", "Настоящее DNS-имя под вашим контролем, A-запись должна вести сюда."),
        existing orelse null,
        &domain_buf,
    );

    const mode_choice = try ui.menu(
        tr(ui, "How is HTTPS terminated?", "Кто терминирует HTTPS?"),
        &.{
            tr(ui, "On this server, through the proxy's masking backend (recommended)", "На этом сервере, через masking-бэкенд прокси (рекомендуется)"),
            tr(ui, "Somewhere else — Cloudflare, another host, a spare IP", "Где-то ещё — Cloudflare, другой хост, отдельный IP"),
        },
    );

    if (!try ui.confirm(i18n.get(ui.lang, .confirm_proceed), true)) {
        ui.info(i18n.get(ui.lang, .aborting));
        return;
    }

    try execute(ui, allocator, .{
        .domain = domain,
        .mode = if (mode_choice == 1) .behind else .mask,
        .yes = true,
    });
}

/// Read one `[web]` key from the installed config into `buf`.
///
/// `TomlDoc.get` returns a slice that aliases the doc's own heap lines, so the value has
/// to be copied out before `deinit()` runs.
fn readConfigured(allocator: std.mem.Allocator, key: []const u8, buf: []u8) ?[]const u8 {
    if (!sys.fileExists(config_path)) return null;
    var doc = toml.TomlDoc.load(allocator, config_path) catch return null;
    defer doc.deinit();
    const raw = doc.get("web", key) orelse return null;
    const trimmed = std.mem.trim(u8, raw, " \t\"");
    if (trimmed.len == 0 or trimmed.len > buf.len) return null;
    @memcpy(buf[0..trimmed.len], trimmed);
    return buf[0..trimmed.len];
}

// ── the work ──────────────────────────────────────────────────────────────────

pub fn execute(ui: *Tui, allocator: std.mem.Allocator, opts_in: WebOpts) !void {
    if (!sys.isRoot()) {
        ui.fail(i18n.get(ui.lang, .error_not_root));
        return;
    }
    var opts = opts_in;

    if (!opts.quiet) ui.section(tr(ui, "WEB proxy relay", "Релей WEB-прокси"));

    // Keep whatever the config already has when the caller did not name a domain —
    // the domain is baked into every WEB link's bridge capability, so changing it
    // silently would break links exactly the way changing tls_domain does.
    var existing_buf: [256]u8 = undefined;
    if (opts.domain.len == 0) {
        opts.domain = readConfigured(allocator, "domain", &existing_buf) orelse {
            ui.fail(tr(ui, "No relay domain configured. Pass --domain <hostname>.", "Домен релея не задан. Укажите --domain <hostname>."));
            return;
        };
    }
    var port_buf: [16]u8 = undefined;
    if (std.mem.eql(u8, opts.port, DEFAULT_PORT)) {
        if (readConfigured(allocator, "port", &port_buf)) |configured| opts.port = configured;
    }

    // Validate exactly the way the client does, so a domain that would be silently
    // rejected in Telegram Desktop is caught here instead of after the links go out.
    var canonical_buf: [web_capability.max_host_len]u8 = undefined;
    const domain = web_capability.normalizeHost(opts.domain, &canonical_buf) catch |err| {
        var msg_buf: [320]u8 = undefined;
        const detail = switch (err) {
            error.IpLiteral => tr(ui, "an IP address is not accepted — WEB proxies need a DNS name", "IP-адрес не подходит — WEB-прокси требует DNS-имя"),
            error.NotFullyQualified => tr(ui, "needs at least one dot (a single label is rejected)", "нужна хотя бы одна точка (одно слово не принимается)"),
            error.NonAscii => tr(ui, "use the ASCII xn-- form of an international domain", "используйте ASCII-форму xn-- для международного домена"),
            else => tr(ui, "not a valid hostname", "некорректное имя хоста"),
        };
        const msg = std.fmt.bufPrint(&msg_buf, "{s} '{s}': {s}", .{
            tr(ui, "Telegram Desktop would reject", "Telegram Desktop отвергнет"),
            opts.domain,
            detail,
        }) catch tr(ui, "Invalid relay domain", "Некорректный домен релея");
        ui.fail(msg);
        return;
    };

    const port = std.fmt.parseInt(u16, opts.port, 10) catch {
        ui.fail(tr(ui, "--port must be a number", "--port должен быть числом"));
        return;
    };
    if (port == 443 or std.mem.eql(u8, opts.port, masking.NGINX_PORT)) {
        ui.fail(tr(
            ui,
            "The relay port must not collide with the proxy (443) or the masking backend (8443).",
            "Порт релея не должен совпадать с прокси (443) или masking-бэкендом (8443).",
        ));
        return;
    }

    checkDns(ui, allocator, domain);

    if (opts.mode == .mask) {
        if (!try prepareMaskTopology(ui, allocator, domain, opts)) return;
    } else if (!opts.quiet) {
        ui.info(tr(
            ui,
            "Mode 'behind': this host only runs the relay. Point your TLS terminator at it.",
            "Режим 'behind': здесь работает только релей. Направьте на него ваш TLS-терминатор.",
        ));
    }

    try writeConfig(ui, allocator, domain, opts.port, opts.mode == .mask);
    try installService(ui, allocator);

    if (opts.mode == .mask and !opts.quiet) verifyEndToEnd(ui, allocator, domain);
    if (!opts.quiet) printSummary(ui, allocator, domain, opts);
}

/// nginx + certificate + vhost, in the order that keeps a failure recoverable.
fn prepareMaskTopology(ui: *Tui, allocator: std.mem.Allocator, domain: []const u8, opts: WebOpts) !bool {
    if (!maskingIsOn(allocator)) {
        ui.fail(tr(
            ui,
            "Mode 'mask' needs the local masking backend. Run: sudo mtbuddy setup masking",
            "Режим 'mask' требует локального masking-бэкенда. Выполните: sudo mtbuddy setup masking",
        ));
        return false;
    }
    if (!unknownSniIsMasked(allocator)) {
        ui.fail(tr(
            ui,
            "Mode 'mask' needs [censorship].unknown_sni_action = \"mask\" — the browser reaches the relay as an unknown SNI.",
            "Режим 'mask' требует [censorship].unknown_sni_action = \"mask\" — браузер приходит на релей как неизвестный SNI.",
        ));
        return false;
    }
    if (!try ensureNginx(ui, allocator)) return false;
    if (!opts.skip_cert) {
        if (!try ensureCertificate(ui, allocator, domain, opts.email)) return false;
    }
    if (!try writeVhost(ui, allocator, domain, opts.port)) return false;
    return true;
}

/// `mask_port = 8443` (any non-443 value) means the proxy fronts a *local* backend,
/// which is the whole premise of the mask topology.
fn maskingIsOn(allocator: std.mem.Allocator) bool {
    if (!sys.fileExists(config_path)) return false;
    var doc = toml.TomlDoc.load(allocator, config_path) catch return false;
    defer doc.deinit();
    const mask = doc.get("censorship", "mask") orelse "true";
    if (std.mem.indexOf(u8, mask, "false") != null) return false;
    const mask_port = doc.get("censorship", "mask_port") orelse return false;
    const trimmed = std.mem.trim(u8, mask_port, " \t\"");
    return std.mem.eql(u8, trimmed, masking.NGINX_PORT);
}

/// The browser reaches the relay as an "unknown SNI" on the proxy's :443. With
/// `unknown_sni_action = reject|drop` that path is closed and mode "mask" cannot work.
fn unknownSniIsMasked(allocator: std.mem.Allocator) bool {
    if (!sys.fileExists(config_path)) return true;
    var doc = toml.TomlDoc.load(allocator, config_path) catch return true;
    defer doc.deinit();
    const action = doc.get("censorship", "unknown_sni_action") orelse return true;
    const trimmed = std.mem.trim(u8, action, " \t\"");
    return trimmed.len == 0 or std.mem.eql(u8, trimmed, "mask");
}

/// A relay domain that does not resolve to this host cannot be issued a certificate and
/// cannot be reached by clients — worth saying out loud before anything else fails.
fn checkDns(ui: *Tui, allocator: std.mem.Allocator, domain: []const u8) void {
    const public_ip = sys.detectPublicIp(allocator) orelse return;
    defer allocator.free(public_ip);

    const result = sys.exec(allocator, &.{ "getent", "ahostsv4", domain }) catch return;
    defer result.deinit();
    if (result.exit_code != 0 or result.stdout.len == 0) {
        var buf: [320]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "{s} '{s}'.", .{
            tr(ui, "Could not resolve", "Не удалось разрезолвить"),
            domain,
        }) catch return;
        ui.warn(msg);
        ui.hint(tr(ui, "Add an A record pointing at this server before handing out links.", "Добавьте A-запись на этот сервер до раздачи ссылок."));
        return;
    }
    if (std.mem.indexOf(u8, result.stdout, public_ip) == null) {
        var buf: [384]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "{s} '{s}' {s} {s}.", .{
            tr(ui, "DNS for", "DNS для"),
            domain,
            tr(ui, "does not point at", "не указывает на"),
            public_ip,
        }) catch return;
        ui.warn(msg);
        ui.hint(tr(ui, "Certificate issuance and client access both need it to.", "Это нужно и для выпуска сертификата, и для доступа клиентов."));
    }
}

fn ensureNginx(ui: *Tui, allocator: std.mem.Allocator) !bool {
    if (sys.commandExists("nginx")) return true;
    ui.step(tr(ui, "Installing Nginx...", "Устанавливаю Nginx..."));
    if (!aptInstall(allocator, &.{"nginx"})) {
        ui.fail(tr(ui, "Failed to install Nginx", "Не удалось установить Nginx"));
        return false;
    }
    return true;
}

fn aptInstall(allocator: std.mem.Allocator, packages: []const []const u8) bool {
    if (!sys.commandExists("apt-get")) return false;
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    argv.appendSlice(allocator, &.{
        "env",                             "DEBIAN_FRONTEND=noninteractive",
        "apt-get",                         "-o",
        "DPkg::Lock::Timeout=600",         "-o",
        "Dpkg::Options::=--force-confdef", "-o",
        "Dpkg::Options::=--force-confold", "install",
        "-y",
    }) catch return false;
    argv.appendSlice(allocator, packages) catch return false;
    const rc = sys.execForward(argv.items) catch return false;
    return rc == 0;
}

/// Obtain a publicly-trusted certificate over HTTP-01.
///
/// This is the first ACME path in the project. `masking.zig` only opportunistically uses
/// a `certbot` that already happens to be installed, and its target is a *borrowed*
/// fronting domain (`rutube.ru`) that could never validate. The relay domain is one the
/// operator actually owns, so issuance is both possible and required — a self-signed
/// certificate would make every client's WebView refuse the bridge.
fn ensureCertificate(ui: *Tui, allocator: std.mem.Allocator, domain: []const u8, email: []const u8) !bool {
    var live_buf: [512]u8 = undefined;
    const fullchain = std.fmt.bufPrint(&live_buf, "/etc/letsencrypt/live/{s}/fullchain.pem", .{domain}) catch return false;
    if (sys.fileExists(fullchain)) {
        ui.ok(tr(ui, "Certificate already present", "Сертификат уже есть"));
        // The lineage renews over HTTP-01 through our port-80 responder; (re)create it
        // so a re-setup after `--remove`, or a lineage issued by hand, keeps renewing.
        _ = sys.exec(allocator, &.{ "mkdir", "-p", ACME_ROOT ++ "/.well-known/acme-challenge" }) catch {};
        if (!sys.fileExists("/etc/nginx/sites-enabled/mtproto-web-acme")) {
            _ = try writeAcmeVhost(ui, allocator, domain);
        }
        try installRenewHook(ui, allocator);
        return true;
    }

    if (!sys.commandExists("certbot")) {
        ui.step(tr(ui, "Installing certbot...", "Устанавливаю certbot..."));
        if (!aptInstall(allocator, &.{"certbot"})) {
            ui.fail(tr(ui, "Failed to install certbot", "Не удалось установить certbot"));
            ui.hint(tr(ui, "Install it manually, or re-run with --skip-cert once a certificate exists.", "Установите вручную или запустите с --skip-cert, когда сертификат появится."));
            return false;
        }
    }

    // HTTP-01 needs port 80. It also makes the cover story better: a host that serves
    // HTTPS but refuses port 80 is unusual.
    _ = sys.exec(allocator, &.{ "mkdir", "-p", ACME_ROOT ++ "/.well-known/acme-challenge" }) catch {};
    if (!try writeAcmeVhost(ui, allocator, domain)) return false;
    if (sys.commandExists("ufw")) {
        sys.execSilent(allocator, &.{ sys.commandOrPath("ufw", &.{ "/usr/sbin/ufw", "/sbin/ufw" }), "allow", "80/tcp" });
    }

    ui.step(tr(ui, "Requesting a Let's Encrypt certificate...", "Запрашиваю сертификат Let's Encrypt..."));
    var email_arg_buf: [256]u8 = undefined;
    const email_args: []const []const u8 = if (email.len > 0)
        &.{ "--email", std.fmt.bufPrint(&email_arg_buf, "{s}", .{email}) catch email }
    else
        &.{"--register-unsafely-without-email"};

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.appendSlice(allocator, &.{ "certbot", "certonly", "--webroot", "-w", ACME_ROOT, "-d", domain, "--non-interactive", "--agree-tos", "--keep-until-expiring" });
    try argv.appendSlice(allocator, email_args);
    const rc = sys.execForward(argv.items) catch 1;
    if (rc != 0 or !sys.fileExists(fullchain)) {
        ui.fail(tr(ui, "Certificate issuance failed", "Не удалось выпустить сертификат"));
        ui.hint(tr(ui, "Check that the domain resolves here and that port 80 is reachable.", "Проверьте, что домен резолвится сюда и порт 80 доступен."));
        return false;
    }
    ui.ok(tr(ui, "Certificate issued", "Сертификат выпущен"));
    try installRenewHook(ui, allocator);
    return true;
}

/// A port-80 vhost that answers ACME challenges and redirects everything else. It is a
/// separate file from the relay vhost so a certificate failure never leaves the TLS
/// vhost half-written.
fn writeAcmeVhost(ui: *Tui, allocator: std.mem.Allocator, domain: []const u8) !bool {
    const content = try std.fmt.allocPrint(allocator,
        \\# MTProto WEB proxy — ACME challenge responder and canonical redirect.
        \\server {{
        \\    listen 80;
        \\    listen [::]:80;
        \\    server_name {s};
        \\
        \\    location /.well-known/acme-challenge/ {{
        \\        root {s};
        \\    }}
        \\
        \\    location / {{
        \\        return 301 https://$host$request_uri;
        \\    }}
        \\
        \\    access_log off;
        \\}}
        \\
    , .{ domain, ACME_ROOT });
    defer allocator.free(content);

    sys.writeFile("/etc/nginx/sites-available/mtproto-web-acme", content) catch {
        ui.fail(tr(ui, "Could not write the ACME vhost", "Не удалось записать ACME-vhost"));
        return false;
    };
    _ = sys.exec(allocator, &.{ "ln", "-sf", "/etc/nginx/sites-available/mtproto-web-acme", "/etc/nginx/sites-enabled/mtproto-web-acme" }) catch {};
    if (!nginxTestPasses(allocator)) {
        _ = sys.exec(allocator, &.{ "rm", "-f", "/etc/nginx/sites-enabled/mtproto-web-acme" }) catch {};
        ui.fail(tr(ui, "nginx rejected the ACME vhost — rolled back, nginx left unchanged", "nginx отверг ACME-vhost — откатил, nginx не тронут"));
        return false;
    }
    _ = sys.exec(allocator, &.{ "systemctl", "reload", "nginx" }) catch {};
    return true;
}

/// Renewal replaces the files under `live/`, which nginx has already opened. Without a
/// reload the relay serves the expired chain until something else restarts nginx.
fn installRenewHook(ui: *Tui, allocator: std.mem.Allocator) !void {
    _ = ui;
    _ = sys.exec(allocator, &.{ "mkdir", "-p", "/etc/letsencrypt/renewal-hooks/deploy" }) catch {};
    sys.writeFileMode(RENEW_HOOK,
        \\#!/bin/sh
        \\# Installed by mtbuddy setup web: pick up a renewed relay certificate.
        \\systemctl reload nginx 2>/dev/null || true
        \\
    , 0o755) catch {};
}

/// Render the relay vhost. Split out from `writeVhost` so its shape is unit-testable —
/// the two listeners and the X-Forwarded-For rule are both security-relevant.
fn writeVhostContent(allocator: std.mem.Allocator, domain: []const u8, port: []const u8) ![]u8 {
    // The `map` is http-level; sites-enabled is included inside http{}, so it belongs
    // here. The variable is name-spaced so it cannot collide with an operator's own.
    return std.fmt.allocPrint(allocator,
        \\# MTProto WEB proxy relay — selected by SNI on the masking backend.
        \\#
        \\# The proxy on :443 forwards every non-MTProto TLS connection here. This vhost
        \\# answers only for {s}; any other SNI keeps hitting the masking vhost, which is
        \\# loaded first and therefore stays the default server for this listener.
        \\map $http_upgrade $mtproto_web_upgrade {{
        \\    default upgrade;
        \\    ''      close;
        \\}}
        \\
        \\server {{
        \\    # Two listeners, one vhost. 8443 is the plain masking port (kept so an
        \\    # upgrade never leaves a window where this domain has no server), 8444 is the
        \\    # same thing plus a PROXY-protocol header carrying the real client address.
        \\    listen 127.0.0.1:{s} ssl;
        \\    listen 127.0.0.1:{s} ssl proxy_protocol;
        \\    server_name {s};
        \\
        \\    ssl_certificate     /etc/letsencrypt/live/{s}/fullchain.pem;
        \\    ssl_certificate_key /etc/letsencrypt/live/{s}/privkey.pem;
        \\    ssl_protocols TLSv1.2 TLSv1.3;
        \\    ssl_prefer_server_ciphers off;
        \\    ssl_session_cache shared:MTPROTOWEB:2m;
        \\
        \\    location / {{
        \\        proxy_pass http://127.0.0.1:{s};
        \\        proxy_http_version 1.1;
        \\        proxy_set_header Upgrade $http_upgrade;
        \\        proxy_set_header Connection $mtproto_web_upgrade;
        \\        proxy_set_header Host $host;
        \\        # Overwrite, never append: with $proxy_add_x_forwarded_for a hostile client
        \\        # could prepend an address of its choosing. The relay reads the right-most
        \\        # entry, so a single overwritten value is both correct and unforgeable.
        \\        # $proxy_protocol_addr is the address the proxy announced for this
        \\        # connection; it is empty on the 8443 listener, and the relay then falls
        \\        # back to the socket peer. Never $proxy_add_x_forwarded_for: that keeps
        \\        # whatever the client sent and a hostile client would pick its own IP.
        \\        proxy_set_header X-Forwarded-For $proxy_protocol_addr;
        \\        proxy_set_header X-Forwarded-Proto https;
        \\        # A relayed MTProto session is long-lived and mostly idle; the relay's
        \\        # own PING/PONG is what proves liveness, not traffic.
        \\        proxy_read_timeout 3600s;
        \\        proxy_send_timeout 3600s;
        \\        proxy_buffering off;
        \\    }}
        \\
        \\    access_log off;
        \\    error_log /var/log/nginx/mtproto-web-error.log warn;
        \\}}
        \\
    , .{ domain, masking.NGINX_PORT, PROXY_PROTOCOL_PORT, domain, domain, domain, port });
}

fn writeVhost(ui: *Tui, allocator: std.mem.Allocator, domain: []const u8, port: []const u8) !bool {
    const content = writeVhostContent(allocator, domain, port) catch {
        ui.fail(tr(ui, "Could not render the relay vhost", "Не удалось сформировать vhost релея"));
        return false;
    };
    defer allocator.free(content);

    sys.writeFile(NGINX_SITE, content) catch {
        ui.fail(tr(ui, "Could not write the relay vhost", "Не удалось записать vhost релея"));
        return false;
    };

    // Symlink first, then test, then roll back only our own link on failure — the same
    // order masking.zig uses, and for the same reason.
    _ = sys.exec(allocator, &.{ "ln", "-sf", NGINX_SITE, NGINX_LINK }) catch {};
    if (!nginxTestPasses(allocator)) {
        _ = sys.exec(allocator, &.{ "rm", "-f", NGINX_LINK }) catch {};
        _ = sys.exec(allocator, &.{ "systemctl", "reload", "nginx" }) catch {};
        ui.fail(tr(ui, "nginx rejected the relay vhost — rolled back, nginx left unchanged", "nginx отверг vhost релея — откатил, nginx не тронут"));
        return false;
    }
    _ = sys.exec(allocator, &.{ "systemctl", "reload", "nginx" }) catch {};
    ui.ok(tr(ui, "Relay vhost enabled", "vhost релея включён"));
    return true;
}

/// `nginx` lives in /usr/sbin, which `std.process.run`'s PATH expansion does not find
/// even when PATH lists it — so resolve it by absolute path first, like every other
/// sbin tool in mtbuddy. A spawn failure is a failed test, never a pass.
fn nginxBin() []const u8 {
    return sys.commandOrPath("nginx", &.{ "/usr/sbin/nginx", "/sbin/nginx" });
}

fn sleepSeconds(seconds: u64) void {
    const req: std.posix.timespec = .{ .sec = @intCast(seconds), .nsec = 0 };
    _ = std.os.linux.nanosleep(&req, null);
}

fn nginxTestPasses(allocator: std.mem.Allocator) bool {
    const result = sys.exec(allocator, &.{ nginxBin(), "-t" }) catch return false;
    defer result.deinit();
    return result.exit_code == 0;
}

/// Write `[web]` back into config.toml — but only when something actually differs.
///
/// `TomlDoc` round-trips add a trailing newline every time it saves, and
/// `test/installer-e2e` asserts `mtbuddy update` leaves config.toml byte-identical. This
/// module is re-run from `update`, so an unconditional save would fail that.
fn writeConfig(ui: *Tui, allocator: std.mem.Allocator, domain: []const u8, port: []const u8, mask_mode: bool) !void {
    if (!sys.fileExists(config_path)) {
        ui.warn(tr(ui, "config.toml not found — skipping [web] update", "config.toml не найден — пропускаю обновление [web]"));
        return;
    }
    var doc = toml.TomlDoc.load(allocator, config_path) catch {
        ui.warn(tr(ui, "Could not read config.toml", "Не удалось прочитать config.toml"));
        return;
    };
    defer doc.deinit();

    var quoted_domain_buf: [300]u8 = undefined;
    const quoted_domain = std.fmt.bufPrint(&quoted_domain_buf, "\"{s}\"", .{domain}) catch return;
    const quoted_mask_backend = "\"127.0.0.1:" ++ PROXY_PROTOCOL_PORT ++ "\"";

    var changed = false;
    changed = needsSet(&doc, "enabled", "true") or changed;
    changed = needsSet(&doc, "domain", quoted_domain) or changed;
    changed = needsSet(&doc, "port", port) or changed;
    if (mask_mode) changed = needsSet(&doc, "mask_backend", quoted_mask_backend) or changed;
    if (!changed) {
        ui.ok(tr(ui, "[web] already up to date", "[web] уже актуален"));
        return;
    }

    try doc.set("web", "enabled", "true");
    try doc.set("web", "domain", quoted_domain);
    try doc.set("web", "port", port);
    // Only mode "mask" routes through the proxy, so only it has a PROXY-protocol
    // terminator to point at.
    if (mask_mode) try doc.set("web", "mask_backend", quoted_mask_backend);
    doc.save(config_path) catch {};
    _ = sys.exec(allocator, &.{ "chown", "mtproto:mtproto", config_path }) catch {};

    // `[web].enabled` decides at startup whether the data plane trusts the relay, and
    // it is not part of the SIGHUP reload set — the proxy has to restart.
    ui.step(tr(ui, "Restarting the proxy to apply [web]...", "Перезапускаю прокси, чтобы применить [web]..."));
    _ = sys.exec(allocator, &.{ "systemctl", "restart", "mtproto-proxy" }) catch {};
}

/// True when `[web].key` differs from `value`, comparing without surrounding quotes on
/// either side — `doc.get` may or may not return them, and a false "changed" here
/// means an unnecessary config rewrite plus a proxy restart on every `mtbuddy update`.
fn needsSet(doc: *toml.TomlDoc, key: []const u8, value: []const u8) bool {
    const current = doc.get("web", key) orelse return true;
    const cur = std.mem.trim(u8, current, " \t\"");
    const want = std.mem.trim(u8, value, " \t\"");
    return !std.mem.eql(u8, cur, want);
}

fn unitContent() []const u8 {
    return
    \\[Unit]
    \\Description=MTProto WEB proxy relay (Telegram Desktop 7.1+)
    \\Documentation=https://github.com/sleep3r/mtproto.zig
    \\After=network-online.target mtproto-proxy.service
    \\Wants=network-online.target
    \\
    \\[Service]
    \\Type=simple
    \\User=mtproto
    \\Group=mtproto
    \\WorkingDirectory=/opt/mtproto-proxy
    \\ExecStart=/opt/mtproto-proxy/mtproto-proxy web-relay /opt/mtproto-proxy/config.toml
    \\KillSignal=SIGTERM
    \\TimeoutStopSec=15
    \\Restart=always
    \\RestartSec=3
    \\
    \\# Same hardening as the proxy unit, minus CAP_NET_BIND_SERVICE: the relay binds an
    \\# unprivileged loopback port and writes nothing.
    \\NoNewPrivileges=yes
    \\ProtectSystem=strict
    \\ProtectHome=yes
    \\PrivateTmp=yes
    \\ReadOnlyPaths=/opt/mtproto-proxy
    \\SystemCallFilter=@system-service
    \\SystemCallArchitectures=native
    \\SystemCallErrorNumber=EPERM
    \\RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
    \\MemoryDenyWriteExecute=yes
    \\RestrictNamespaces=yes
    \\LockPersonality=yes
    \\RestrictRealtime=yes
    \\RestrictSUIDSGID=yes
    \\ProtectKernelTunables=yes
    \\ProtectKernelModules=yes
    \\ProtectKernelLogs=yes
    \\ProtectControlGroups=yes
    \\ProtectClock=yes
    \\ProtectHostname=yes
    \\ProtectProc=invisible
    \\ProcSubset=pid
    \\PrivateDevices=yes
    \\RemoveIPC=yes
    \\UMask=0077
    \\CapabilityBoundingSet=
    \\
    \\LimitNOFILE=65536
    \\TasksMax=4096
    \\
    \\[Install]
    \\WantedBy=multi-user.target
    \\
    ;
}

fn installService(ui: *Tui, allocator: std.mem.Allocator) !void {
    ui.step(tr(ui, "Installing the relay service...", "Устанавливаю сервис релея..."));
    sys.writeFile(SERVICE_FILE, unitContent()) catch {
        ui.fail(tr(ui, "Could not write the systemd unit", "Не удалось записать systemd unit"));
        return;
    };
    _ = sys.exec(allocator, &.{ "systemctl", "daemon-reload" }) catch {};
    _ = sys.exec(allocator, &.{ "systemctl", "enable", "--now", SERVICE_NAME }) catch {};
    _ = sys.exec(allocator, &.{ "systemctl", "restart", SERVICE_NAME }) catch {};

    // Type=simple is "active" the instant it is exec'd; a relay that exits on a bad
    // config does so within the first second. Look after that, not before.
    sleepSeconds(1);
    if (sys.isServiceActive(SERVICE_NAME)) {
        ui.ok(tr(ui, "Relay service is running", "Сервис релея работает"));
    } else {
        ui.fail(tr(ui, "Relay service failed to start", "Сервис релея не запустился"));
        ui.hint("journalctl -u " ++ SERVICE_NAME ++ " -n 50 --no-pager");
    }
}

/// Fetch the relay's own domain over the public path: browser → proxy :443 → masking →
/// nginx → relay. Anything less than that does not prove the topology works.
fn verifyEndToEnd(ui: *Tui, allocator: std.mem.Allocator, domain: []const u8) void {
    if (!sys.commandExists("curl")) return;
    var url_buf: [320]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "https://{s}/", .{domain}) catch return;
    // The proxy was restarted and the relay started moments ago; `is-active` on a
    // Type=simple unit says nothing about the listener being bound yet. Give the
    // chain a few seconds before declaring it broken.
    var attempt: usize = 0;
    var code: []const u8 = "";
    var code_buf: [8]u8 = undefined;
    while (attempt < 6) : (attempt += 1) {
        if (attempt > 0) sleepSeconds(1);
        const result = sys.exec(allocator, &.{ "curl", "-s", "--max-time", "8", "-o", "/dev/null", "-w", "%{http_code}", url }) catch continue;
        defer result.deinit();
        const trimmed = std.mem.trim(u8, result.stdout, " \r\n");
        const n = @min(trimmed.len, code_buf.len);
        @memcpy(code_buf[0..n], trimmed[0..n]);
        code = code_buf[0..n];
        if (std.mem.eql(u8, code, "200")) break;
    }
    if (std.mem.eql(u8, code, "200")) {
        ui.ok(tr(ui, "The relay site answers over the public HTTPS path", "Сайт релея отвечает по публичному HTTPS"));
    } else {
        ui.warn(tr(ui, "Could not fetch the relay site from this host", "Не удалось получить сайт релея с этого хоста"));
        ui.hint(tr(ui, "Check DNS, the certificate, and that [censorship].mask is on.", "Проверьте DNS, сертификат и что [censorship].mask включён."));
    }
}

fn printSummary(ui: *Tui, allocator: std.mem.Allocator, domain: []const u8, opts: WebOpts) void {
    _ = allocator;
    var url_buf: [320]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "https://{s}/", .{domain}) catch "";

    const lines = [_]SummaryLine{
        .{ .label = tr(ui, "Domain", "Домен"), .value = domain },
        .{ .label = tr(ui, "Site", "Сайт"), .value = url },
        .{ .label = tr(ui, "Mode", "Режим"), .value = if (opts.mode == .mask) tr(ui, "through the proxy's masking backend", "через masking-бэкенд прокси") else tr(ui, "behind your own TLS terminator", "за вашим TLS-терминатором") },
        .{ .label = tr(ui, "Listener", "Слушает"), .value = "127.0.0.1:" ++ DEFAULT_PORT },
        .{ .label = tr(ui, "Service", "Сервис"), .value = SERVICE_NAME },
        .{ .style = .blank, .label = "" },
        .{ .label = tr(ui, "Get WEB links: sudo mtbuddy links", "Ссылки WEB: sudo mtbuddy links"), .style = .code },
    };
    ui.summaryBox(tr(ui, "WEB proxy relay ready", "Релей WEB-прокси готов"), &lines);

    if (opts.mode == .behind) {
        ui.hint(tr(
            ui,
            "Point your terminator at 127.0.0.1:" ++ DEFAULT_PORT ++ ", forward Upgrade/Connection, and pass X-Forwarded-For.",
            "Направьте терминатор на 127.0.0.1:" ++ DEFAULT_PORT ++ ", пробросьте Upgrade/Connection и X-Forwarded-For.",
        ));
    }
    ui.hint(tr(
        ui,
        "WEB links work in Telegram Desktop 7.1+ only; hand them out alongside the usual ones.",
        "WEB-ссылки работают только в Telegram Desktop 7.1+; раздавайте их вместе с обычными.",
    ));
}

// ── removal ───────────────────────────────────────────────────────────────────

pub fn removeInteractive(ui: *Tui, allocator: std.mem.Allocator) void {
    const confirmed = ui.confirm(
        tr(ui, "Remove the WEB proxy relay? Existing WEB links stop working.", "Удалить релей WEB-прокси? Выданные WEB-ссылки перестанут работать."),
        false,
    ) catch return;
    if (!confirmed) {
        ui.info(i18n.get(ui.lang, .aborting));
        return;
    }
    remove(ui, allocator);
}

pub fn remove(ui: *Tui, allocator: std.mem.Allocator) void {
    if (!sys.isRoot()) {
        ui.fail(i18n.get(ui.lang, .error_not_root));
        return;
    }
    ui.section(tr(ui, "Remove the WEB proxy relay", "Удаление релея WEB-прокси"));

    ui.step(tr(ui, "Stopping the relay service...", "Останавливаю сервис релея..."));
    _ = sys.exec(allocator, &.{ "systemctl", "disable", "--now", SERVICE_NAME }) catch {};
    _ = sys.exec(allocator, &.{ "rm", "-f", SERVICE_FILE }) catch {};
    _ = sys.exec(allocator, &.{ "systemctl", "daemon-reload" }) catch {};

    // The relay vhost goes; the port-80 ACME responder and the renewal hook stay, because
    // the certificate lineage is still registered with certbot and would otherwise fail
    // every renewal from now on. They are harmless on their own (a challenge path plus a
    // redirect to https), and a re-setup reuses them.
    ui.step(tr(ui, "Removing the relay vhost...", "Удаляю vhost релея..."));
    _ = sys.exec(allocator, &.{ "rm", "-f", NGINX_LINK, NGINX_SITE }) catch {};
    if (sys.commandExists("nginx") and nginxTestPasses(allocator)) {
        _ = sys.exec(allocator, &.{ "systemctl", "reload", "nginx" }) catch {};
    }

    if (sys.fileExists(config_path)) {
        var doc = toml.TomlDoc.load(allocator, config_path) catch null;
        if (doc) |*d| {
            defer d.deinit();
            d.set("web", "enabled", "false") catch {};
            d.save(config_path) catch {};
            _ = sys.exec(allocator, &.{ "chown", "mtproto:mtproto", config_path }) catch {};
        }
        _ = sys.exec(allocator, &.{ "systemctl", "restart", "mtproto-proxy" }) catch {};
    }

    ui.ok(tr(ui, "WEB proxy relay removed. The proxy keeps running.", "Релей WEB-прокси удалён. Прокси продолжает работать."));
    ui.hint(tr(
        ui,
        "The Let's Encrypt certificate, its port-80 challenge responder and renewal hook were left in place (certbot delete --cert-name <domain> to drop them).",
        "Сертификат Let's Encrypt, ACME-ответчик на порту 80 и hook продления оставлены (certbot delete --cert-name <domain>, чтобы убрать).",
    ));
}

// ── status ────────────────────────────────────────────────────────────────────

pub fn isInstalled() bool {
    return sys.fileExists(SERVICE_FILE);
}

/// Called from `mtbuddy status`; silent when the relay was never set up.
pub fn printStatus(ui: *Tui, allocator: std.mem.Allocator) void {
    if (!isInstalled()) return;
    if (sys.isServiceActive(SERVICE_NAME)) {
        var domain_buf: [256]u8 = undefined;
        if (readConfigured(allocator, "domain", &domain_buf)) |domain| {
            var msg_buf: [320]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "{s} https://{s}/", .{
                tr(ui, "WEB proxy relay is serving", "Релей WEB-прокси обслуживает"),
                domain,
            }) catch tr(ui, "WEB proxy relay is running", "Релей WEB-прокси работает");
            ui.ok(msg);
        } else {
            ui.ok(tr(ui, "WEB proxy relay is running", "Релей WEB-прокси работает"));
        }
    } else {
        ui.fail(tr(ui, "WEB proxy relay is installed but not running", "Релей WEB-прокси установлен, но не работает"));
        ui.hint("journalctl -u " ++ SERVICE_NAME ++ " -n 50 --no-pager");
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

test "the systemd unit runs the relay mode of the proxy binary and drops all capabilities" {
    const unit = unitContent();
    try std.testing.expect(std.mem.containsAtLeast(u8, unit, 1, "ExecStart=/opt/mtproto-proxy/mtproto-proxy web-relay /opt/mtproto-proxy/config.toml"));
    try std.testing.expect(std.mem.containsAtLeast(u8, unit, 1, "CapabilityBoundingSet=\n"));
    try std.testing.expect(std.mem.containsAtLeast(u8, unit, 1, "User=mtproto"));
    // No AmbientCapabilities line at all: the relay binds an unprivileged port.
    try std.testing.expect(!std.mem.containsAtLeast(u8, unit, 1, "AmbientCapabilities="));
    try std.testing.expect(std.mem.containsAtLeast(u8, unit, 1, "After=network-online.target mtproto-proxy.service"));
}

test "the relay vhost carries both listeners and never appends to X-Forwarded-For" {
    const rendered = try writeVhostContent(std.testing.allocator, "relay.example.com", "8081");
    defer std.testing.allocator.free(rendered);
    try std.testing.expect(std.mem.containsAtLeast(u8, rendered, 1, "listen 127.0.0.1:8443 ssl;"));
    try std.testing.expect(std.mem.containsAtLeast(u8, rendered, 1, "listen 127.0.0.1:8444 ssl proxy_protocol;"));
    try std.testing.expect(std.mem.containsAtLeast(u8, rendered, 1, "proxy_set_header X-Forwarded-For $proxy_protocol_addr;"));
    // $proxy_add_x_forwarded_for keeps a client-supplied prefix, so it must never be the
    // directive's value (the surrounding comment naming it is fine).
    try std.testing.expect(!std.mem.containsAtLeast(u8, rendered, 1, "X-Forwarded-For $proxy_add_x_forwarded_for"));
    try std.testing.expect(std.mem.containsAtLeast(u8, rendered, 1, "proxy_pass http://127.0.0.1:8081;"));
}

test "the relay port may not collide with the proxy or the masking backend" {
    // Guard rail encoded in execute(); assert the constants it compares are distinct.
    try std.testing.expect(!std.mem.eql(u8, DEFAULT_PORT, masking.NGINX_PORT));
    try std.testing.expect(!std.mem.eql(u8, DEFAULT_PORT, "443"));
}

test "domain validation matches the client's own rules" {
    var buf: [web_capability.max_host_len]u8 = undefined;
    try std.testing.expectEqualStrings("relay.example.com", try web_capability.normalizeHost("Relay.Example.COM", &buf));
    try std.testing.expectError(error.IpLiteral, web_capability.normalizeHost("203.0.113.7", &buf));
    try std.testing.expectError(error.NotFullyQualified, web_capability.normalizeHost("relay", &buf));
}
