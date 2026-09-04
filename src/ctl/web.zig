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
//! nginx-touching steps follow `masking.zig`'s discipline: symlink first, then `nginx -t`,
//! and on failure roll back rather than leave nginx broken. `writeVhost` goes one step
//! further than a fresh install needs to, because it is also how `mtbuddy update`
//! re-renders an already-live relay vhost: it takes an `nginx -t` baseline *before*
//! touching the file, so a tree that was already broken for an unrelated reason is
//! reported as such instead of blamed on us, and on failure it restores the previous
//! vhost content (not just the symlink) so a previously working relay actually comes
//! back up rather than staying disabled with the new, bad file still on disk. A vhost
//! that breaks nginx would otherwise be caught by the mask-health timer, which restarts
//! `mtproto-proxy` every minute while the masking probe fails.

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
    /// True when the caller actually named a `--mode`. Without it `execute` recovers the
    /// mode from config.toml, because `mtbuddy update` re-runs this module with plain
    /// defaults — and re-running a `behind` host as `mask` used to fail the masking
    /// precondition and return before the relay unit was rewritten, leaving the relay on
    /// the pre-upgrade binary.
    mode_explicit: bool = false,
    port: []const u8 = DEFAULT_PORT,
    /// Explicit bind address for a remote TLS terminator; defaults to loopback.
    host: ?[]const u8 = null,
    lets_encrypt: bool = false,
    /// Contact address for the ACME account; empty registers without one.
    email: []const u8 = "",
    /// Skip ACME issuance and keep whatever certificate is already on disk.
    skip_cert: bool = false,
    /// Bring your own certificate: absolute paths to a full chain and its private key.
    /// Empty means the Let's Encrypt lineage for `domain`. These are persisted, so an
    /// `mtbuddy update` that re-renders the vhost keeps pointing at them.
    cert: []const u8 = "",
    key: []const u8 = "",
    /// Serve only the WEB proxy — mask direct MTProto for everyone but the relay.
    /// `null` keeps whatever config.toml already says.
    only: ?bool = null,
    quiet: bool = false,
    yes: bool = false,
    /// Allow changing an already-configured [web].domain even though it breaks every
    /// distributed WEB link (same gate as masking.zig's tls_domain --force).
    force: bool = false,
};

fn tr(ui: *Tui, en: []const u8, ru: []const u8) []const u8 {
    return if (ui.lang == .ru) ru else en;
}

fn safeCertificatePath(path: []const u8) bool {
    if (path.len == 0 or path[0] != '/' or path.len > 512) return false;
    for (path) |c| {
        if (!(std.ascii.isAlphanumeric(c) or std.mem.indexOfScalar(u8, "/._-", c) != null)) return false;
    }
    return true;
}

fn dnsHasAddress(output: []const u8, address: []const u8) bool {
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        if (std.mem.eql(u8, fields.next() orelse continue, address)) return true;
    }
    return false;
}

test "certificate paths reject directive and TOML injection" {
    try std.testing.expect(safeCertificatePath("/etc/ssl/relay/fullchain.pem"));
    for ([_][]const u8{ "relative.pem", "/tmp/cert;", "/tmp/cert\n", "/tmp/a\"b", "/tmp/a b" }) |path| try std.testing.expect(!safeCertificatePath(path));
}

test "DNS check compares the first complete address field" {
    try std.testing.expect(dnsHasAddress("1.2.3.40 STREAM name\n1.2.3.4 DGRAM name\n", "1.2.3.4"));
    try std.testing.expect(!dnsHasAddress("1.2.3.40 STREAM name\n", "1.2.3.4"));
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
            opts.mode_explicit = true;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            opts.cert = args.next() orelse "";
        } else if (std.mem.eql(u8, arg, "--key")) {
            opts.key = args.next() orelse "";
        } else if (std.mem.eql(u8, arg, "--only") or std.mem.eql(u8, arg, "--web-only")) {
            opts.only = true;
        } else if (std.mem.eql(u8, arg, "--no-only") or std.mem.eql(u8, arg, "--no-web-only")) {
            opts.only = false;
        } else if (std.mem.eql(u8, arg, "--port")) {
            opts.port = args.next() orelse DEFAULT_PORT;
        } else if (std.mem.eql(u8, arg, "--host")) {
            opts.host = args.next() orelse return error.MissingHost;
        } else if (std.mem.eql(u8, arg, "--lets-encrypt")) {
            opts.lets_encrypt = true;
        } else if (std.mem.eql(u8, arg, "--email")) {
            opts.email = args.next() orelse "";
        } else if (std.mem.eql(u8, arg, "--skip-cert")) {
            opts.skip_cert = true;
        } else if (std.mem.eql(u8, arg, "--quiet")) {
            opts.quiet = true;
        } else if (std.mem.eql(u8, arg, "--yes") or std.mem.eql(u8, arg, "-y")) {
            opts.yes = true;
        } else if (std.mem.eql(u8, arg, "--force")) {
            opts.force = true;
        } else if (std.mem.eql(u8, arg, "--remove") or std.mem.eql(u8, arg, "--uninstall")) {
            do_remove = true;
        } else if (arg.len > 0 and arg[0] != '-') {
            opts.domain = arg;
        } else {
            ui.print("Unknown option: {s}\n", .{arg});
            return error.UnknownOption;
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

    // Offered only where it can be honoured: WEB-only masks direct MTProto rather than
    // closing it, and that needs the local masking backend.
    var only: ?bool = null;
    if (maskingIsOn(allocator)) {
        ui.print("  {s}{s}{s}\n", .{
            Color.dim,
            tr(
                ui,
                "WEB-only serves nothing but the website: a Telegram client that connects to\n  this IP directly gets the cover site instead of the proxy. Turn it on if a direct\n  connection is what gets your IP blocked — it invalidates every ee/dd link you have\n  already handed out.",
                "WEB-only отдаёт только сайт: клиент Telegram, подключившийся к этому IP напрямую,\n  получит сайт-прикрытие вместо прокси. Включайте, если блокировку вызывает именно\n  прямое подключение — все выданные ранее ee/dd-ссылки перестанут работать.",
            ),
            Color.reset,
        });
        only = try ui.confirm(
            tr(ui, "Serve only WEB links (mask direct MTProto)?", "Отдавать только WEB-ссылки (маскировать прямой MTProto)?"),
            false,
        );
    }

    if (!try ui.confirm(i18n.get(ui.lang, .confirm_proceed), true)) {
        ui.info(i18n.get(ui.lang, .aborting));
        return;
    }

    // If the operator typed a domain different from the live one, require informed
    // consent before clobbering it — same gate as masking.zig's tls_domain.
    var force = false;
    if (existing) |e| {
        if (!std.mem.eql(u8, e, domain)) {
            var warn_buf: [512]u8 = undefined;
            const msg = std.fmt.bufPrint(&warn_buf, "{s} '{s}' {s} '{s}' {s}", .{
                tr(ui, "Changing the relay domain from", "Смена домена релея с"),
                e,
                tr(ui, "to", "на"),
                domain,
                tr(ui, "INVALIDATES every WEB link already distributed.", "СДЕЛАЕТ НЕРАБОЧИМИ все уже выданные WEB-ссылки."),
            }) catch tr(ui, "Changing the relay domain invalidates every distributed WEB link.", "Смена домена релея сделает нерабочими все выданные WEB-ссылки.");
            ui.warn(msg);
            if (!try ui.confirm(tr(ui, "Change the relay domain anyway?", "Всё равно сменить домен релея?"), false)) {
                ui.info(i18n.get(ui.lang, .aborting));
                return;
            }
            force = true;
        }
    }

    try execute(ui, allocator, .{
        .domain = domain,
        .mode = if (mode_choice == 1) .behind else .mask,
        .mode_explicit = true,
        .only = only,
        .yes = true,
        .force = force,
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

/// Whether `[web].domain` may move from `existing` to `new`. Same rule as
/// [censorship].tls_domain in masking.zig: a live deploy's domain is baked into every
/// distributed link, so only an unchanged value or an explicit `--force` may pass.
fn domainChangeAllowed(existing: []const u8, new: []const u8, force: bool) bool {
    return std.mem.eql(u8, existing, new) or force;
}

fn configuredPort(allocator: std.mem.Allocator, section: []const u8, key: []const u8, fallback: u16) u16 {
    var doc = toml.TomlDoc.load(allocator, config_path) catch return fallback;
    defer doc.deinit();
    const text = doc.get(section, key) orelse return fallback;
    return std.fmt.parseInt(u16, std.mem.trim(u8, text, " \t\""), 10) catch fallback;
}

fn relayPortConflicts(port: u16, proxy_port: u16, mask_port: u16) bool {
    return port == 0 or port == proxy_port or port == mask_port or port == 8443 or port == 8444;
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
    const existing_domain = readConfigured(allocator, "domain", &existing_buf);
    if (opts.domain.len == 0) {
        opts.domain = existing_domain orelse {
            ui.fail(tr(ui, "No relay domain configured. Pass --domain <hostname>.", "Домен релея не задан. Укажите --domain <hostname>."));
            return;
        };
    } else if (existing_domain) |cur| {
        // Mirrors masking.zig's tls_domain gate: the caller named a domain that differs
        // from the one already configured. Every distributed tg://webproxy link's bridge
        // capability is HMAC'd over the OLD host (web_capability.deriveForPaddedSecret),
        // so writing this through unguarded breaks every one of them the moment the
        // relay restarts — refuse unless the operator explicitly overrides it.
        if (!domainChangeAllowed(cur, opts.domain, opts.force)) {
            var msg_buf: [512]u8 = undefined;
            const msg = std.fmt.bufPrint(
                &msg_buf,
                "Refusing to change [web].domain from '{s}' to '{s}' — this invalidates every distributed WEB link. Re-run with --force to override.",
                .{ cur, opts.domain },
            ) catch "Refusing to change [web].domain (would break WEB links); re-run with --force.";
            ui.fail(msg);
            return;
        }
    }
    var port_buf: [16]u8 = undefined;
    if (std.mem.eql(u8, opts.port, DEFAULT_PORT)) {
        if (readConfigured(allocator, "port", &port_buf)) |configured| opts.port = configured;
    }

    // Recover the rest of the deployment's shape from config.toml when the caller did
    // not name it. `mtbuddy update` calls us with bare defaults, and defaults are
    // `--mode mask` with a Let's Encrypt certificate — re-running a `behind` host or a
    // bring-your-own-cert host that way rewrote it into a topology it never asked for.
    if (!opts.mode_explicit) {
        var mode_buf: [16]u8 = undefined;
        if (readConfigured(allocator, "mode", &mode_buf)) |persisted| {
            opts.mode = if (std.ascii.eqlIgnoreCase(persisted, "behind")) .behind else .mask;
        } else if (isInstalled()) {
            // A relay installed before `[web].mode` existed. Only mode "mask" has a
            // PROXY-protocol terminator to point at, so the presence of `mask_backend`
            // is the best record of what it was set up as.
            var mask_backend_buf: [128]u8 = undefined;
            opts.mode = if (readConfigured(allocator, "mask_backend", &mask_backend_buf) != null) .mask else .behind;
        }
    }
    // Checked on what the CALLER passed, before the config fills in the missing half:
    // `--cert new.pem` alone would otherwise be silently paired with the key already in
    // config.toml, which is a mismatched pair nginx accepts at write time and fails on.
    if ((opts.cert.len == 0) != (opts.key.len == 0)) {
        ui.fail(tr(ui, "--cert and --key must be given together.", "--cert и --key задаются только вместе."));
        return;
    }
    var cert_buf: [512]u8 = undefined;
    var key_buf: [512]u8 = undefined;
    if (opts.lets_encrypt) {
        opts.cert = "";
        opts.key = "";
    } else if (opts.cert.len == 0 and opts.key.len == 0) {
        opts.cert = readConfigured(allocator, "cert", &cert_buf) orelse "";
        opts.key = readConfigured(allocator, "key", &key_buf) orelse "";
        // A config carrying only one of the two is not a pair either; ignore both and
        // fall back to the Let's Encrypt lineage rather than render a mismatch.
        if (opts.cert.len == 0 or opts.key.len == 0) {
            opts.cert = "";
            opts.key = "";
        }
    }

    if ((opts.cert.len > 0 and !safeCertificatePath(opts.cert)) or (opts.key.len > 0 and !safeCertificatePath(opts.key))) return error.InvalidCertificatePath;
    if (opts.host) |host| {
        _ = std.Io.net.IpAddress.parse(host, 0) catch return error.InvalidListenHost;
        if (opts.mode == .mask and !std.mem.eql(u8, host, "127.0.0.1")) return error.MaskRequiresLoopback;
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
    if (relayPortConflicts(port, configuredPort(allocator, "server", "port", 443), configuredPort(allocator, "censorship", "mask_port", 8443))) {
        ui.fail(tr(
            ui,
            "The relay port must not collide with the proxy (443) or the masking backend (8443).",
            "Порт релея не должен совпадать с прокси (443) или masking-бэкендом (8443).",
        ));
        return;
    }

    // WEB-only leans on the masking backend: the refusal has to *look* like the
    // wrong-secret path, and without a cover site every direct connection is simply
    // closed — which is a cleaner active-probe signal than serving MTProto ever was.
    if (opts.only == true and !maskingIsOn(allocator)) {
        ui.fail(tr(
            ui,
            "--only needs the local masking backend: without it every refused connection is closed, not covered. Run: sudo mtbuddy setup masking",
            "--only требует локального masking-бэкенда: без него отказ выглядит как закрытое соединение, а не как обычный сайт. Выполните: sudo mtbuddy setup masking",
        ));
        return;
    }

    if (!opts.quiet and opts.mode == .mask) checkDns(ui, allocator, domain);

    if (opts.mode == .mask) {
        if (!try prepareMaskTopology(ui, allocator, domain, opts)) {
            // The relay unit is independent of the nginx front it is served through, and
            // `mtbuddy update` runs this whole module only to re-point that unit at the
            // binary it just swapped. Refresh it even when the nginx side is unhappy, so
            // an unrelated vhost problem cannot strand the relay on the old binary.
            if (isInstalled()) try installService(ui, allocator);
            return;
        }
    } else if (!opts.quiet) {
        ui.info(tr(
            ui,
            "Mode 'behind': this host only runs the relay. Point your TLS terminator at it.",
            "Режим 'behind': здесь работает только релей. Направьте на него ваш TLS-терминатор.",
        ));
    }

    // `only` is written LAST, and only after the relay is up. writeConfig restarts the
    // proxy, and the restart is what starts masking every direct connection — so
    // enabling WEB-only before `installService` would take the direct door away in the
    // same breath as failing to open the WEB one, leaving a box that serves nobody.
    var staged = opts;
    staged.only = if (opts.only == true) null else opts.only;
    var config_changed = try writeConfig(ui, allocator, domain, staged);
    try installService(ui, allocator);
    if (opts.only == true) {
        if (!sys.isServiceActive(SERVICE_NAME) or !verifyEndToEnd(ui, allocator, domain)) {
            ui.fail(tr(
                ui,
                "The relay HTTPS path could not be verified; the existing WEB-only setting was left unchanged.",
                "Не удалось проверить HTTPS-путь релея; прежнее значение WEB-only оставлено без изменений.",
            ));
            ui.hint("journalctl -u " ++ SERVICE_NAME ++ " -n 50 --no-pager");
            opts.only = null;
        } else {
            config_changed = try writeConfig(ui, allocator, domain, opts) or config_changed;
        }
    }
    if (config_changed) {
        ui.step(tr(ui, "Restarting the proxy to apply [web]...", "Перезапускаю прокси, чтобы применить [web]..."));
        const restart = try sys.exec(allocator, &.{ "systemctl", "restart", "mtproto-proxy" });
        defer restart.deinit();
        if (restart.exit_code != 0) return error.ProxyRestartFailed;
    }

    if (opts.only != true and opts.mode == .mask and !opts.quiet) _ = verifyEndToEnd(ui, allocator, domain);
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
    // A certificate the operator brought is theirs to renew; we neither issue nor touch
    // it, and we do not install the certbot deploy hook for it either.
    const byo_cert = opts.cert.len > 0 and opts.key.len > 0;
    if (!opts.skip_cert and !byo_cert) {
        if (!try ensureCertificate(ui, allocator, domain, opts.email)) return false;
    }
    if (!try writeVhost(ui, allocator, domain, opts)) return false;
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
    if (!dnsHasAddress(result.stdout, public_ip)) {
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
fn prepareAcmeRoot(allocator: std.mem.Allocator) !void {
    const mkdir = try sys.exec(allocator, &.{ "mkdir", "-p", ACME_ROOT ++ "/.well-known/acme-challenge" });
    defer mkdir.deinit();
    if (mkdir.exit_code != 0) return error.AcmeDirectoryFailed;
    const chmod = try sys.exec(allocator, &.{ "chmod", "755", ACME_ROOT, ACME_ROOT ++ "/.well-known", ACME_ROOT ++ "/.well-known/acme-challenge" });
    defer chmod.deinit();
    if (chmod.exit_code != 0) return error.AcmeDirectoryFailed;
}

fn ensureCertificate(ui: *Tui, allocator: std.mem.Allocator, domain: []const u8, email: []const u8) !bool {
    var live_buf: [512]u8 = undefined;
    const fullchain = std.fmt.bufPrint(&live_buf, "/etc/letsencrypt/live/{s}/fullchain.pem", .{domain}) catch return false;
    const valid_certificate = blk: {
        if (!sys.fileExists(fullchain)) break :blk false;
        const result = sys.exec(allocator, &.{ "openssl", "x509", "-checkend", "86400", "-noout", "-in", fullchain }) catch break :blk false;
        defer result.deinit();
        break :blk result.exit_code == 0;
    };
    if (valid_certificate) {
        ui.ok(tr(ui, "Certificate already present", "Сертификат уже есть"));
        // The lineage renews over HTTP-01 through our port-80 responder; (re)create it
        // so a re-setup after `--remove`, or a lineage issued by hand, keeps renewing.
        try prepareAcmeRoot(allocator);
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
    try prepareAcmeRoot(allocator);
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
        \\        return 301 https://{s}$request_uri;
        \\    }}
        \\
        \\    access_log off;
        \\}}
        \\
    , .{ domain, ACME_ROOT, domain });
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
///
/// `cert`/`key` are absolute paths. They used to be hard-coded to the Let's Encrypt
/// lineage for `domain`, which made `--skip-cert` a trap: it skipped issuance but still
/// rendered a vhost pointing at a file that was not there, so `nginx -t` failed and the
/// whole setup rolled back. An operator with a certificate of their own (acme.sh, a
/// wildcard, a Cloudflare Origin cert behind the CDN) now passes it in.
fn writeVhostContent(
    allocator: std.mem.Allocator,
    domain: []const u8,
    port: []const u8,
    cert: []const u8,
    key: []const u8,
) ![]u8 {
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
        \\    ssl_certificate     {s};
        \\    ssl_certificate_key {s};
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
    , .{ domain, masking.NGINX_PORT, PROXY_PROTOCOL_PORT, domain, cert, key, port });
}

/// Where the relay vhost's certificate lives: the operator's own paths when they gave
/// us a pair, otherwise the Let's Encrypt lineage `ensureCertificate` maintains.
fn certPaths(buf: *[1024]u8, domain: []const u8, opts: WebOpts) !struct { cert: []const u8, key: []const u8 } {
    if (opts.cert.len > 0 and opts.key.len > 0) return .{ .cert = opts.cert, .key = opts.key };
    var writer: std.Io.Writer = .fixed(buf);
    try writer.print("/etc/letsencrypt/live/{s}/fullchain.pem", .{domain});
    const cert_len = writer.buffered().len;
    try writer.print("/etc/letsencrypt/live/{s}/privkey.pem", .{domain});
    const all = writer.buffered();
    return .{ .cert = all[0..cert_len], .key = all[cert_len..] };
}

fn writeVhost(ui: *Tui, allocator: std.mem.Allocator, domain: []const u8, opts: WebOpts) !bool {
    var paths_buf: [1024]u8 = undefined;
    const paths = certPaths(&paths_buf, domain, opts) catch {
        ui.fail(tr(ui, "Certificate path is too long", "Слишком длинный путь к сертификату"));
        return false;
    };
    // nginx would fail its own test on a missing file and we would roll the vhost back
    // with a message about nginx rather than about the path the operator typed.
    if (!sys.fileExists(paths.cert) or !sys.fileExists(paths.key)) {
        var msg_buf: [640]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "{s}: {s} / {s}", .{
            tr(ui, "Certificate or key not found", "Сертификат или ключ не найден"),
            paths.cert,
            paths.key,
        }) catch tr(ui, "Certificate or key not found", "Сертификат или ключ не найден");
        ui.fail(msg);
        ui.hint(tr(
            ui,
            "Issue one by re-running without --skip-cert, or point at your own with --cert <fullchain.pem> --key <privkey.pem>.",
            "Выпустите сертификат, запустив без --skip-cert, или укажите свой: --cert <fullchain.pem> --key <privkey.pem>.",
        ));
        return false;
    }

    const content = writeVhostContent(allocator, domain, opts.port, paths.cert, paths.key) catch {
        ui.fail(tr(ui, "Could not render the relay vhost", "Не удалось сформировать vhost релея"));
        return false;
    };
    defer allocator.free(content);

    // `nginx -t` validates the WHOLE /etc/nginx tree, not just this vhost. Take a
    // baseline BEFORE touching anything: if the tree is already broken (an unrelated
    // half-written vhost, a missing cert for some other site), that is not this vhost's
    // fault to fix, and clobbering the live file first would make a pre-existing
    // problem look like ours to roll back.
    if (!nginxTestPasses(allocator)) {
        ui.fail(tr(
            ui,
            "nginx's config was already broken before this change (unrelated to the relay vhost) — fix that first, then re-run.",
            "конфигурация nginx была сломана ещё до этого изменения (не из-за vhost релея) — сначала исправьте её, затем повторите.",
        ));
        return false;
    }

    // Back up whatever is live now, so a test failure below can restore the exact prior
    // state — which the check just above proved passes `nginx -t` — instead of leaving
    // the clobbered file on disk with only the symlink removed (the old rollback deleted
    // the symlink but left the overwritten file, so the previously working vhost stayed
    // both clobbered and disabled). Only a currently-ENABLED vhost was actually exercised
    // by that baseline test — nginx reads sites-enabled, not sites-available — so a stale
    // NGINX_SITE left over from an earlier failed run (not linked) is not "proven valid"
    // and must not be restored as if it were.
    const was_enabled = sys.fileExists(NGINX_LINK);
    const previous = if (was_enabled) sys.readFileAllocAbsolute(allocator, NGINX_SITE, 64 * 1024) else null;
    defer if (previous) |p| allocator.free(p);
    if (was_enabled and previous == null) {
        ui.fail("Cannot back up the active relay vhost; leaving it unchanged");
        return false;
    }

    sys.writeFile(NGINX_SITE, content) catch {
        ui.fail(tr(ui, "Could not write the relay vhost", "Не удалось записать vhost релея"));
        return false;
    };

    // Symlink first, then test, then roll back only our own link on failure — the same
    // order masking.zig uses, and for the same reason.
    _ = sys.exec(allocator, &.{ "ln", "-sf", NGINX_SITE, NGINX_LINK }) catch {};
    if (!nginxTestPasses(allocator)) {
        if (previous) |p| {
            // A previous vhost existed and the baseline above proved it valid — put it
            // back verbatim rather than just dropping the symlink, so the reload below
            // actually restores the working relay instead of leaving the bad content on
            // disk for the next reload/reboot to pick up.
            sys.writeFile(NGINX_SITE, p) catch {};
        } else {
            _ = sys.exec(allocator, &.{ "rm", "-f", NGINX_LINK, NGINX_SITE }) catch {};
        }
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
fn writeConfig(ui: *Tui, allocator: std.mem.Allocator, domain: []const u8, opts: WebOpts) !bool {
    if (!sys.fileExists(config_path)) {
        ui.warn(tr(ui, "config.toml not found — skipping [web] update", "config.toml не найден — пропускаю обновление [web]"));
        return error.ConfigNotFound;
    }
    var doc = toml.TomlDoc.load(allocator, config_path) catch {
        ui.warn(tr(ui, "Could not read config.toml", "Не удалось прочитать config.toml"));
        return error.ConfigReadFailed;
    };
    defer doc.deinit();

    const changed = try applyConfigDoc(&doc, domain, opts);
    if (!changed) {
        ui.ok(tr(ui, "[web] already up to date", "[web] уже актуален"));
        return false;
    }
    try doc.save(config_path);
    const owner = try sys.exec(allocator, &.{ "chown", "mtproto:mtproto", config_path });
    defer owner.deinit();
    if (owner.exit_code != 0) return error.ConfigOwnershipFailed;
    return true;
}

fn applyConfigDoc(doc: *toml.TomlDoc, domain: []const u8, opts: WebOpts) !bool {
    const mask_mode = opts.mode == .mask;
    var quoted_domain_buf: [300]u8 = undefined;
    const quoted_domain = try std.fmt.bufPrint(&quoted_domain_buf, "\"{s}\"", .{domain});
    const quoted_mask_backend = "\"127.0.0.1:" ++ PROXY_PROTOCOL_PORT ++ "\"";
    var quoted_cert_buf: [560]u8 = undefined;
    var quoted_key_buf: [560]u8 = undefined;
    const byo_cert = opts.cert.len > 0 and opts.key.len > 0;
    const quoted_cert = if (byo_cert) try std.fmt.bufPrint(&quoted_cert_buf, "\"{s}\"", .{opts.cert}) else "";
    const quoted_key = if (byo_cert) try std.fmt.bufPrint(&quoted_key_buf, "\"{s}\"", .{opts.key}) else "";
    // `only` is tri-state on the way in: null means "leave whatever is there", so an
    // `mtbuddy update` (which passes no flags) never flips a WEB-only deploy back.
    const only_text: ?[]const u8 = if (opts.only) |v| (if (v) "true" else "false") else null;

    // The mode is persisted only when the operator actually named one, or when the key
    // is already there. An `mtbuddy update` names none, and introducing a key on its own
    // would rewrite config.toml (and restart the proxy) on every update — which
    // test/installer-e2e asserts against.
    const write_mode = opts.mode_explicit or hasValue(doc, "mode");
    const mode_text: []const u8 = if (mask_mode) "\"mask\"" else "\"behind\"";

    var changed = false;
    var host_buf: [128]u8 = undefined;
    const quoted_host = if (opts.host) |host| try std.fmt.bufPrint(&host_buf, "\"{s}\"", .{host}) else null;
    if (quoted_host) |host| changed = needsSet(doc, "host", host) or changed;
    if (opts.lets_encrypt) changed = hasValue(doc, "cert") or hasValue(doc, "key") or changed;
    changed = needsSet(doc, "enabled", "true") or changed;
    changed = needsSet(doc, "domain", quoted_domain) or changed;
    changed = needsSet(doc, "port", opts.port) or changed;
    if (mask_mode) changed = needsSet(doc, "mask_backend", quoted_mask_backend) or changed;
    if (!mask_mode) changed = hasValue(doc, "mask_backend") or changed;
    if (write_mode) changed = needsSet(doc, "mode", mode_text) or changed;
    if (byo_cert) {
        changed = needsSet(doc, "cert", quoted_cert) or changed;
        changed = needsSet(doc, "key", quoted_key) or changed;
    }
    if (only_text) |v| changed = needsSet(doc, "only", v) or changed;
    if (!changed) return false;

    try doc.set("web", "enabled", "true");
    if (quoted_host) |host| try doc.set("web", "host", host);
    if (opts.lets_encrypt) {
        try doc.set("web", "cert", "\"\"");
        try doc.set("web", "key", "\"\"");
    }
    try doc.set("web", "domain", quoted_domain);
    try doc.set("web", "port", opts.port);
    // Only mode "mask" routes through the proxy, so only it has a PROXY-protocol
    // terminator to point at.
    if (mask_mode) try doc.set("web", "mask_backend", quoted_mask_backend);
    if (!mask_mode and hasValue(doc, "mask_backend")) try doc.set("web", "mask_backend", "\"\"");
    if (write_mode) try doc.set("web", "mode", mode_text);
    if (byo_cert) {
        try doc.set("web", "cert", quoted_cert);
        try doc.set("web", "key", quoted_key);
    }
    if (only_text) |v| try doc.set("web", "only", v);

    return true;
}

/// True when `[web].key` is present with a non-empty value. An empty string is how this
/// module expresses "unset" (TomlDoc cannot delete a key), so it must not read as set.
fn hasValue(doc: *toml.TomlDoc, key: []const u8) bool {
    const current = doc.get("web", key) orelse return false;
    return std.mem.trim(u8, current, " \t\"").len > 0;
}

/// Compare a persisted value without surrounding TOML quotes.
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
    \\StartLimitIntervalSec=0
    \\# The relay reads [access.users] once, at startup, and derives one bridge capability
    \\# per user from it — so a user added or removed later never reaches it and its WEB
    \\# link answers with the cover page instead of the bridge. Every path that changes
    \\# users (the dashboard, mtbuddy, install) restarts mtproto-proxy, and PartOf= makes
    \\# systemd propagate that restart here. It costs nothing: a proxy restart already
    \\# drops every relayed stream, since each one is a connection to the proxy.
    \\PartOf=mtproto-proxy.service
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
    _ = sys.exec(allocator, &.{ "systemctl", "enable", SERVICE_NAME }) catch {};
    _ = sys.exec(allocator, &.{ "systemctl", "restart", SERVICE_NAME }) catch {};
    try @import("recovery.zig").installWebHealth(allocator);

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
fn verifyEndToEnd(ui: *Tui, allocator: std.mem.Allocator, domain: []const u8) bool {
    if (!sys.commandExists("curl")) return false;
    var url_buf: [320]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "https://{s}/", .{domain}) catch return false;
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
        return true;
    } else {
        ui.warn(tr(ui, "Could not fetch the relay site from this host", "Не удалось получить сайт релея с этого хоста"));
        ui.hint(tr(ui, "Check DNS, the certificate, and that [censorship].mask is on.", "Проверьте DNS, сертификат и что [censorship].mask включён."));
        return false;
    }
}

fn printSummary(ui: *Tui, allocator: std.mem.Allocator, domain: []const u8, opts: WebOpts) void {
    var url_buf: [320]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "https://{s}/", .{domain}) catch "";

    // `only` is tri-state, so the effective value after a run that did not touch it
    // still has to come from the file we just wrote.
    var only_buf: [8]u8 = undefined;
    const only_now = opts.only orelse blk: {
        const configured = readConfigured(allocator, "only", &only_buf) orelse break :blk false;
        break :blk std.ascii.eqlIgnoreCase(configured, "true");
    };

    var lines_buf: [9]SummaryLine = undefined;
    var n: usize = 0;
    lines_buf[n] = .{ .label = tr(ui, "Domain", "Домен"), .value = domain };
    n += 1;
    lines_buf[n] = .{ .label = tr(ui, "Site", "Сайт"), .value = url };
    n += 1;
    lines_buf[n] = .{ .label = tr(ui, "Mode", "Режим"), .value = if (opts.mode == .mask) tr(ui, "through the proxy's masking backend", "через masking-бэкенд прокси") else tr(ui, "behind your own TLS terminator", "за вашим TLS-терминатором") };
    n += 1;
    lines_buf[n] = .{ .label = tr(ui, "Serves", "Отдаёт"), .value = if (only_now) tr(ui, "WEB links only — direct MTProto is masked", "только WEB-ссылки — прямой MTProto маскируется") else tr(ui, "WEB links alongside the usual MTProto ones", "WEB-ссылки вместе с обычными MTProto") };
    n += 1;
    if (opts.cert.len > 0) {
        lines_buf[n] = .{ .label = tr(ui, "Certificate", "Сертификат"), .value = opts.cert };
        n += 1;
    }
    var listener_buf: [64]u8 = undefined;
    var configured_host: [64]u8 = undefined;
    const host = opts.host orelse readConfigured(allocator, "host", &configured_host) orelse "127.0.0.1";
    const listener = std.fmt.bufPrint(&listener_buf, "{s}:{s}", .{ host, opts.port }) catch "";
    lines_buf[n] = .{ .label = tr(ui, "Listener", "Слушает"), .value = listener };
    n += 1;
    lines_buf[n] = .{ .label = tr(ui, "Service", "Сервис"), .value = SERVICE_NAME };
    n += 1;
    lines_buf[n] = .{ .style = .blank, .label = "" };
    n += 1;
    lines_buf[n] = .{ .label = tr(ui, "Get WEB links: sudo mtbuddy links", "Ссылки WEB: sudo mtbuddy links"), .style = .code };
    n += 1;
    ui.summaryBox(tr(ui, "WEB proxy relay ready", "Релей WEB-прокси готов"), lines_buf[0..n]);

    if (only_now) {
        ui.hint(tr(
            ui,
            "WEB-only is on: every ee/dd link you handed out before stops working, and one desktop client costs one [web].max_sessions slot.",
            "WEB-only включён: все выданные ранее ee/dd-ссылки перестают работать, а каждый десктоп-клиент занимает слот [web].max_sessions.",
        ));
    }
    if (opts.mode == .behind) {
        var hint_buf: [256]u8 = undefined;
        ui.hint(std.fmt.bufPrint(&hint_buf, "Point your terminator at {s}; forward Upgrade/Connection. Use --host <IP> for a remote terminator and restrict access with your firewall.", .{listener}) catch "Configure your TLS terminator to forward Upgrade/Connection.");
    }
    ui.hint(if (only_now)
        tr(
            ui,
            "WEB links work in Telegram Desktop 7.1+ only — under WEB-only there is no other kind to hand out.",
            "WEB-ссылки работают только в Telegram Desktop 7.1+ — в режиме WEB-only других ссылок нет.",
        )
    else
        tr(
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
    sys.execSilent(allocator, &.{ "systemctl", "disable", "--now", "mtproto-web-health.timer", "mtproto-web-health.service" });
    sys.execSilent(allocator, &.{ "rm", "-f", "/usr/local/bin/mtproto-web-health.sh", "/etc/systemd/system/mtproto-web-health.service", "/etc/systemd/system/mtproto-web-health.timer" });
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
            // Clear the WEB-only gate with it. `Web.onlyActive()` already refuses to
            // honour `only` without `enabled`, so leaving it could not brick the proxy —
            // but a stale `only = true` would silently switch WEB-only back on the next
            // time someone runs `setup web`, which is not what "remove" means.
            d.set("web", "only", "false") catch {};
            d.save(config_path) catch {};
            _ = sys.exec(allocator, &.{ "chown", "mtproto:mtproto", config_path }) catch {};
        }
        _ = sys.exec(allocator, &.{ "systemctl", "restart", "mtproto-proxy" }) catch {};
    }

    ui.ok(tr(ui, "WEB proxy relay removed. The proxy keeps running.", "Релей WEB-прокси удалён. Прокси продолжает работать."));
    ui.hint(tr(
        ui,
        "Retained shared resources: the Let's Encrypt certificate, mtproto-web-acme nginx site, /var/www/acme, certbot renewal hook, and firewall port 80. If no other service needs them, delete the certificate with certbot delete --cert-name <domain>, remove the ACME site/hook/root, reload nginx, and close port 80 manually.",
        "Сохранены общие ресурсы: сертификат Let's Encrypt, сайт nginx mtproto-web-acme, /var/www/acme, hook certbot и порт 80 в firewall. Если они больше не нужны, удалите сертификат через certbot delete --cert-name <domain>, сайт/hook/каталог ACME, перезагрузите nginx и вручную закройте порт 80.",
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
        // `[web].only` is read at boot and is not in the SIGHUP reload set, so an
        // operator who edited config.toml by hand can otherwise believe it took effect.
        // Say it out loud wherever the proxy's state is printed.
        var only_buf: [8]u8 = undefined;
        var enabled_buf: [8]u8 = undefined;
        const web_enabled = if (readConfigured(allocator, "enabled", &enabled_buf)) |v|
            std.ascii.eqlIgnoreCase(v, "true")
        else
            false;
        if (readConfigured(allocator, "only", &only_buf)) |value| {
            // Same gate as Config.Web.onlyActive(): `only` without `enabled` does
            // nothing, and saying otherwise here would send an operator hunting for a
            // masking problem that is not there.
            if (web_enabled and std.ascii.eqlIgnoreCase(value, "true")) {
                ui.info(tr(
                    ui,
                    "WEB-only: direct MTProto is masked — only tg://webproxy links work.",
                    "WEB-only: прямой MTProto маскируется — работают только ссылки tg://webproxy.",
                ));
            }
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

test "the relay unit restarts with the proxy, so user changes reach its capabilities" {
    // Capabilities are built once from [access.users]; without this line adding a user
    // restarts only mtproto-proxy and the new WEB link keeps getting the cover page.
    try std.testing.expect(std.mem.containsAtLeast(u8, unitContent(), 1, "\nPartOf=mtproto-proxy.service\n"));
}

test "the relay vhost carries both listeners and never appends to X-Forwarded-For" {
    const rendered = try writeVhostContent(
        std.testing.allocator,
        "relay.example.com",
        "8081",
        "/etc/letsencrypt/live/relay.example.com/fullchain.pem",
        "/etc/letsencrypt/live/relay.example.com/privkey.pem",
    );
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
    for ([_]u16{ 0, 443, 9443, 8443, 8444 }) |port| try std.testing.expect(relayPortConflicts(port, 443, 9443));
    try std.testing.expect(relayPortConflicts(try std.fmt.parseInt(u16, "08443", 10), 443, 9443));
    try std.testing.expect(!relayPortConflicts(8081, 443, 9443));
}

test "WEB provisioning preserves only on update and clears stale mask and certificate keys" {
    var doc = toml.TomlDoc.initEmpty(std.testing.allocator);
    defer doc.deinit();
    var opts: WebOpts = .{ .mode = .mask, .port = "8081", .only = true, .cert = "/cert.pem", .key = "/key.pem" };
    try std.testing.expect(try applyConfigDoc(&doc, "relay.example.com", opts));
    opts.only = null;
    try std.testing.expect(!try applyConfigDoc(&doc, "relay.example.com", opts));
    try std.testing.expect(!needsSet(&doc, "only", "true"));
    opts.mode = .behind;
    opts.mode_explicit = true;
    opts.lets_encrypt = true;
    opts.cert = "";
    opts.key = "";
    opts.only = false;
    try std.testing.expect(try applyConfigDoc(&doc, "relay.example.com", opts));
    try std.testing.expect(!hasValue(&doc, "mask_backend"));
    try std.testing.expect(!hasValue(&doc, "cert"));
    try std.testing.expect(!hasValue(&doc, "key"));
    try std.testing.expect(!needsSet(&doc, "only", "false"));
    try std.testing.expect(!try applyConfigDoc(&doc, "relay.example.com", opts));
}

test "changing [web].domain is refused without --force, same as tls_domain" {
    // Same domain (or none configured yet, which execute() never routes through this
    // helper): no gate needed either way.
    try std.testing.expect(domainChangeAllowed("relay.example.com", "relay.example.com", false));
    // A different domain silently written through would break every distributed
    // tg://webproxy link's HMAC'd bridge capability the moment the relay restarts.
    try std.testing.expect(!domainChangeAllowed("relay.example.com", "relay2.example.com", false));
    // --force is the operator's informed override, same as masking.zig's tls_domain gate.
    try std.testing.expect(domainChangeAllowed("relay.example.com", "relay2.example.com", true));
}

test "domain validation matches the client's own rules" {
    var buf: [web_capability.max_host_len]u8 = undefined;
    try std.testing.expectEqualStrings("relay.example.com", try web_capability.normalizeHost("Relay.Example.COM", &buf));
    try std.testing.expectError(error.IpLiteral, web_capability.normalizeHost("203.0.113.7", &buf));
    try std.testing.expectError(error.NotFullyQualified, web_capability.normalizeHost("relay", &buf));
}

test "certPaths defaults to the Let's Encrypt lineage and honours a bring-your-own pair" {
    var buf: [1024]u8 = undefined;
    const defaulted = try certPaths(&buf, "relay.example.com", .{});
    try std.testing.expectEqualStrings("/etc/letsencrypt/live/relay.example.com/fullchain.pem", defaulted.cert);
    try std.testing.expectEqualStrings("/etc/letsencrypt/live/relay.example.com/privkey.pem", defaulted.key);

    const byo = try certPaths(&buf, "relay.example.com", .{
        .cert = "/etc/ssl/relay/fullchain.pem",
        .key = "/etc/ssl/relay/privkey.pem",
    });
    try std.testing.expectEqualStrings("/etc/ssl/relay/fullchain.pem", byo.cert);
    try std.testing.expectEqualStrings("/etc/ssl/relay/privkey.pem", byo.key);

    // Only a complete pair counts; a half-configured one falls back rather than
    // rendering a vhost with one operator path and one Let's Encrypt path.
    const half = try certPaths(&buf, "relay.example.com", .{ .cert = "/etc/ssl/relay/fullchain.pem" });
    try std.testing.expectEqualStrings("/etc/letsencrypt/live/relay.example.com/fullchain.pem", half.cert);
}

test "a bring-your-own certificate reaches the rendered vhost verbatim" {
    const rendered = try writeVhostContent(
        std.testing.allocator,
        "relay.example.com",
        "8081",
        "/etc/ssl/relay/fullchain.pem",
        "/etc/ssl/relay/privkey.pem",
    );
    defer std.testing.allocator.free(rendered);
    try std.testing.expect(std.mem.containsAtLeast(u8, rendered, 1, "ssl_certificate     /etc/ssl/relay/fullchain.pem;"));
    try std.testing.expect(std.mem.containsAtLeast(u8, rendered, 1, "ssl_certificate_key /etc/ssl/relay/privkey.pem;"));
    // The old renderer hard-coded this path; a leak of it back in is the regression.
    try std.testing.expect(!std.mem.containsAtLeast(u8, rendered, 1, "/etc/letsencrypt/"));
}
