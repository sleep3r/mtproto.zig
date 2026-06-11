//! mtbuddy — interactive installer & control panel for mtproto.zig
//!
//! Replaces the collection of bash scripts in deploy/ with a single
//! Zig binary. Supports both interactive TUI mode (--interactive)
//! and non-interactive CLI with flags.
//!
//! One-liner install:
//!   sudo mtbuddy install --port 443 --domain rutube.ru --yes
//!   sudo mtbuddy install --port 443 --domain rutube.ru --secret <hex> --user myuser --yes
//!
//! Interactive wizard:
//!   sudo mtbuddy --interactive

const std = @import("std");
const i18n = @import("i18n.zig");
const tui_mod = @import("tui.zig");
const linux_io = @import("linux_io");
const install = @import("install.zig");
const update = @import("update.zig");
const masking = @import("masking.zig");
const nfqws = @import("nfqws.zig");
const tunnel = @import("tunnel.zig");
const recovery = @import("recovery.zig");
const dashboard = @import("dashboard.zig");
const tunnel_singbox = @import("tunnel_singbox.zig");
const ipv6hop = @import("ipv6hop.zig");
const version_mod = @import("version");
const uninstall = @import("uninstall.zig");
const config_cmd = @import("config_cmd.zig");
const links = @import("links.zig");

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;

pub const version = version_mod.version;

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();

    var args = try init.minimal.args.iterateAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // skip program name

    // ── Parse global flags ──
    var lang: ?i18n.Lang = null;
    var interactive = false;
    var command: ?[]const u8 = null;
    var remaining_args = args;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--interactive") or std.mem.eql(u8, arg, "-i")) {
            interactive = true;
        } else if (std.mem.eql(u8, arg, "--lang")) {
            const lang_val = args.next() orelse {
                printLangFlagError("Missing value for --lang (expected: en|ru)\n");
                return;
            };
            lang = parseLangFlag(lang_val) orelse {
                var buf: [96]u8 = undefined;
                const msg = std.fmt.bufPrint(&buf, "Unsupported language '{s}' (expected: en|ru)\n", .{lang_val}) catch "Unsupported language (expected: en|ru)\n";
                printLangFlagError(msg);
                return;
            };
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            const help_lang = lang orelse i18n.Lang.fromEnvMap(init.environ_map);
            printHelp(help_lang);
            return;
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            printVersion();
            return;
        } else {
            command = arg;
            remaining_args = args;
            break;
        }
    }

    const resolved_lang = lang orelse i18n.Lang.fromEnvMap(init.environ_map);
    var ui = Tui.init(resolved_lang);

    // ── Interactive mode ──
    if (interactive) {
        ui.banner(version);

        if (lang == null) {
            const lang_choice = try ui.menu(
                i18n.get(.en, .select_language),
                &.{
                    i18n.get(.en, .lang_english),
                    i18n.get(.en, .lang_russian),
                },
            );
            ui.lang = if (lang_choice == 1) .ru else .en;
        }

        ui.print("  {s}{s}{s}\n", .{
            Color.dim,
            tr(ui.lang, "Hi — I'm mtbuddy. Let's get your people online.", "Привет — я mtbuddy. Давайте подключим ваших близких."),
            Color.reset,
        });

        try interactiveMain(&ui, allocator);
        return;
    }

    // ── CLI dispatch ──
    if (command) |cmd| {
        // CLI convention: `-h`/`--help` after a subcommand shows help, never runs the
        // action. The per-subcommand parsers silently ignore unknown flags, so without
        // this guard `mtbuddy update --help` would DOWNLOAD + INSTALL instead of
        // printing help (issue #310). Scan a copy so the real iterator stays intact.
        var help_scan = remaining_args;
        while (help_scan.next()) |a| {
            if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
                if (std.mem.eql(u8, cmd, "install")) {
                    install.printInstallHelp(&ui);
                } else {
                    printHelp(ui.lang);
                }
                return;
            }
        }

        if (std.mem.eql(u8, cmd, "install")) {
            return install.run(&ui, allocator, &remaining_args);
        } else if (std.mem.eql(u8, cmd, "uninstall")) {
            return uninstall.run(&ui, allocator, &remaining_args);
        } else if (std.mem.eql(u8, cmd, "update")) {
            return update.run(&ui, allocator, &remaining_args);
        } else if (std.mem.eql(u8, cmd, "setup")) {
            if (remaining_args.next()) |sub| {
                if (std.mem.eql(u8, sub, "masking")) {
                    return masking.run(&ui, allocator, &remaining_args);
                } else if (std.mem.eql(u8, sub, "nfqws")) {
                    return nfqws.run(&ui, allocator, &remaining_args);
                } else if (std.mem.eql(u8, sub, "tunnel")) {
                    return tunnel.run(&ui, allocator, &remaining_args);
                } else if (std.mem.eql(u8, sub, "egress")) {
                    return tunnel_singbox.run(&ui, allocator, &remaining_args);
                } else if (std.mem.eql(u8, sub, "recovery")) {
                    return recovery.run(&ui, allocator, &remaining_args);
                } else if (std.mem.eql(u8, sub, "dashboard")) {
                    return dashboard.run(&ui, allocator, &remaining_args);
                } else {
                    ui.print("\n  {s}{s}:{s} {s}\n", .{
                        Color.err,
                        tr(ui.lang, "Unknown setup subcommand", "Неизвестная подкоманда setup"),
                        Color.reset,
                        sub,
                    });
                    ui.hint(tr(ui.lang, "Available: masking, nfqws, tunnel, egress, recovery, dashboard", "Доступно: masking, nfqws, tunnel, egress, recovery, dashboard"));
                    return;
                }
            } else {
                ui.fail(tr(ui.lang, "Usage: mtbuddy setup <masking|nfqws|tunnel|egress|recovery|dashboard>", "Использование: mtbuddy setup <masking|nfqws|tunnel|egress|recovery|dashboard>"));
                return;
            }
        } else if (std.mem.eql(u8, cmd, "ipv6-hop")) {
            return ipv6hop.run(&ui, allocator, &remaining_args);
        } else if (std.mem.eql(u8, cmd, "update-dns")) {
            return ipv6hop.updateDnsA(&ui, allocator, &remaining_args);
        } else if (std.mem.eql(u8, cmd, "status")) {
            showStatus(&ui, allocator);
            return;
        } else if (std.mem.eql(u8, cmd, "config")) {
            return config_cmd.run(&ui, allocator, &remaining_args);
        } else if (std.mem.eql(u8, cmd, "links")) {
            return links.run(&ui, allocator, &remaining_args);
        } else if (std.mem.eql(u8, cmd, "secret")) {
            links.runSecret(&ui);
            return;
        } else if (std.mem.eql(u8, cmd, "reload")) {
            reloadProxy(&ui, allocator);
            return;
        } else {
            ui.print("\n  {s}{s}:{s} {s}\n\n", .{
                Color.err,
                tr(ui.lang, "Unknown command", "Неизвестная команда"),
                Color.reset,
                cmd,
            });
            printHelp(ui.lang);
            return;
        }
    }

    // No command — show help
    printHelp(ui.lang);
}

const Action = enum {
    install,
    update,
    masking,
    tunnel,
    recovery,
    dashboard,
    remove_dashboard,
    ipv6hop,
    status,
    restart,
    uninstall,
    exit,
};

fn interactiveMain(ui: *Tui, allocator: std.mem.Allocator) !void {
    while (true) {
        const sys = @import("sys.zig");
        const is_installed = sys.fileExists("/opt/mtproto-proxy");

        var items: std.ArrayList([]const u8) = .empty;
        defer items.deinit(allocator);
        var actions: std.ArrayList(Action) = .empty;
        defer actions.deinit(allocator);

        if (!is_installed) {
            try items.append(allocator, i18n.get(ui.lang, .menu_install));
            try actions.append(allocator, .install);
        }

        if (is_installed) {
            try items.append(allocator, i18n.get(ui.lang, .menu_update));
            try actions.append(allocator, .update);
            try items.append(allocator, i18n.get(ui.lang, .menu_setup_masking));
            try actions.append(allocator, .masking);
            try items.append(allocator, i18n.get(ui.lang, .menu_setup_tunnel));
            try actions.append(allocator, .tunnel);

            const has_dashboard = sys.isServiceActive("proxy-monitor");
            const has_recovery = sys.isServiceActive("mtproto-mask-health.timer");

            if (!has_dashboard) {
                try items.append(allocator, i18n.get(ui.lang, .menu_setup_dashboard));
                try actions.append(allocator, .dashboard);
            } else {
                // Dashboard is installed: offer to remove it instead of installing again.
                try items.append(allocator, i18n.get(ui.lang, .menu_remove_dashboard));
                try actions.append(allocator, .remove_dashboard);
            }
            if (!has_recovery) {
                try items.append(allocator, i18n.get(ui.lang, .menu_setup_recovery));
                try actions.append(allocator, .recovery);
            }
            try items.append(allocator, i18n.get(ui.lang, .menu_ipv6_hop));
            try actions.append(allocator, .ipv6hop);
            try items.append(allocator, i18n.get(ui.lang, .menu_status));
            try actions.append(allocator, .status);
            try items.append(allocator, i18n.get(ui.lang, .menu_restart));
            try actions.append(allocator, .restart);
            try items.append(allocator, i18n.get(ui.lang, .menu_uninstall));
            try actions.append(allocator, .uninstall);
        }

        try items.append(allocator, i18n.get(ui.lang, .menu_exit));
        try actions.append(allocator, .exit);

        const choice_idx = try ui.menu(i18n.get(ui.lang, .menu_title), items.items);
        const action = actions.items[choice_idx];

        switch (action) {
            .install => try install.runInteractive(ui, allocator),
            .update => try update.runInteractive(ui, allocator),
            .masking => try masking.runInteractive(ui, allocator),
            .tunnel => try tunnelOrEgressInteractive(ui, allocator),
            .dashboard => try dashboard.runInteractive(ui, allocator),
            .remove_dashboard => dashboard.removeInteractive(ui),
            .recovery => try recovery.runInteractive(ui, allocator),
            .ipv6hop => try ipv6hop.runInteractive(ui, allocator),
            .status => showStatus(ui, allocator),
            .restart => restartProxy(ui, allocator),
            .uninstall => try uninstall.runInteractive(ui, allocator),
            .exit => return,
        }
    }
}

// "Setup tunnel" now asks for the upstream egress type first: AmneziaWG config (the
// existing flow) or a VPN share-link (vless/vmess/trojan/ss -> sing-box TUN tunnel,
// wireguard:// -> native WG tunnel). Dispatched here (not inside tunnel.zig) so tunnel
// and egress don't import each other.
fn tunnelOrEgressInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    const items = [_][]const u8{
        i18n.get(ui.lang, .tunnel_vpn_amneziawg),
        tr(ui.lang, "VPN share-link (VLESS-Reality / VMess / Trojan / Shadowsocks / WireGuard)", "VPN-ссылка (VLESS-Reality / VMess / Trojan / Shadowsocks / WireGuard)"),
    };
    const idx = try ui.menu(i18n.get(ui.lang, .tunnel_vpn_type_prompt), &items);
    if (idx == 1) return tunnel_singbox.runInteractive(ui, allocator);
    return tunnel.runInteractive(ui, allocator);
}

fn restartProxy(ui: *Tui, allocator: std.mem.Allocator) void {
    var sp = ui.spinner(tr(ui.lang, "Restarting", "Перезапуск"));
    sp.start();
    _ = @import("sys.zig").exec(allocator, &.{ "systemctl", "restart", "mtproto-proxy" }) catch {};
    _ = @import("sys.zig").exec(allocator, &.{ "systemctl", "restart", "nfqws-mtproto" }) catch {};
    sp.stop(true, i18n.get(ui.lang, .restart_success));
}

fn reloadProxy(ui: *Tui, allocator: std.mem.Allocator) void {
    var sp = ui.spinner(tr(ui.lang, "Reloading", "Перезагрузка"));
    sp.start();
    const sys = @import("sys.zig");
    const reload_rc = sys.exec(allocator, &.{ "systemctl", "reload", "mtproto-proxy" }) catch null;
    if (reload_rc) |res| {
        defer res.deinit();
        if (res.exit_code == 0) {
            sp.stop(true, tr(ui.lang, "Config reloaded (SIGHUP)", "Конфигурация перезагружена (SIGHUP)"));
            return;
        }
    }

    const restart_rc = sys.exec(allocator, &.{ "systemctl", "restart", "mtproto-proxy" }) catch null;
    if (restart_rc) |res| {
        defer res.deinit();
        if (res.exit_code == 0) {
            sp.stop(true, tr(ui.lang, "Reload unsupported by unit; restarted service", "Reload не поддерживается unit'ом; выполнен restart"));
            return;
        }
    }
    sp.stop(false, tr(ui.lang, "Failed to reload mtproto-proxy", "Не удалось перезагрузить mtproto-proxy"));
}

fn showStatus(ui: *Tui, allocator: std.mem.Allocator) void {
    ui.section(i18n.get(ui.lang, .menu_status));

    const sys = @import("sys.zig");

    const svc_active = sys.isServiceActive("mtproto-proxy");
    // The one question the user opened this to answer — first, in plain words.
    if (svc_active) {
        ui.ok(tr(ui.lang, "You're online — your proxy is up and accepting connections.", "Вы онлайн — прокси работает и принимает подключения."));
    } else {
        ui.fail(tr(ui.lang, "Your proxy is offline — friends can't connect until it's back. Try \"Restart proxy\".", "Прокси офлайн — близкие не смогут подключиться, пока он не запустится. Попробуйте «Перезапустить прокси»."));
    }
    ui.writeRaw("\n");

    const nginx_active = sys.isServiceActive("nginx");
    if (nginx_active) {
        ui.ok(tr(ui.lang, "Camouflage backend (Nginx) is running", "Бэкенд маскировки (Nginx) запущен"));
    } else {
        ui.info(tr(ui.lang, "Camouflage backend (Nginx) is not running", "Бэкенд маскировки (Nginx) не запущен"));
    }

    const nfqws_active = sys.isServiceActive("nfqws-mtproto");
    if (nfqws_active) {
        ui.ok(tr(ui.lang, "Extra TCP protection (nfqws) is running", "Дополнительная TCP-защита (nfqws) запущена"));
    } else {
        ui.info(tr(ui.lang, "Extra TCP protection (nfqws) is not running", "Дополнительная TCP-защита (nfqws) не запущена"));
    }

    const timer_active = sys.isServiceActive("mtproto-mask-health.timer");
    if (timer_active) {
        ui.ok(tr(ui.lang, "DPI auto-recovery is active", "Автовосстановление DPI активно"));
    } else {
        ui.info(tr(ui.lang, "DPI auto-recovery is not installed", "Автовосстановление DPI не установлено"));
    }

    const dashboard_active = sys.isServiceActive("proxy-monitor");
    if (dashboard_active) {
        ui.ok(tr(ui.lang, "monitoring dashboard is running", "дашборд мониторинга запущен"));
        ui.summaryBox(tr(ui.lang, "Dashboard", "Дашборд"), &.{
            .{ .label = tr(ui.lang, "Status:", "Статус:"), .value = tr(ui.lang, "active", "активен"), .style = .label_value },
            .{ .label = tr(ui.lang, "Port:", "Порт:"), .value = "61208", .style = .label_value },
            .{ .label = tr(ui.lang, "Service:", "Сервис:"), .value = "systemctl status proxy-monitor", .style = .label_value },
            .{ .label = "", .value = "", .style = .blank },
            .{ .label = tr(ui.lang, "Access via SSH tunnel:", "Доступ через SSH-туннель:"), .value = "", .style = .highlight },
            .{ .label = tr(ui.lang, "Command:", "Команда:"), .value = "ssh -L 61208:localhost:61208 root@<ip>", .style = .label_value },
            .{ .label = tr(ui.lang, "Open:", "Открыть:"), .value = "http://localhost:61208", .style = .label_value },
        });
    } else {
        ui.info(tr(ui.lang, "monitoring dashboard is not installed (mtbuddy setup dashboard)", "дашборд мониторинга не установлен (mtbuddy setup dashboard)"));
    }

    const result = @import("sys.zig").exec(allocator, &.{
        "systemctl", "status", "mtproto-proxy", "--no-pager", "-l",
    }) catch return;
    defer result.deinit();

    if (result.stdout.len > 0) {
        ui.writeRaw("\n");
        ui.print("  {s}", .{Color.dim});
        var lines = std.mem.splitScalar(u8, result.stdout, '\n');
        var count: usize = 0;
        while (lines.next()) |line| {
            if (count >= 15) break;
            ui.print("  {s}\n", .{line});
            count += 1;
        }
        ui.print("{s}\n", .{Color.reset});
    }
}

fn printHelp(lang: i18n.Lang) void {
    var ui = Tui.init(lang);

    ui.writeRaw("\n");
    ui.print("  {s}⚡ mtbuddy{s} {s}v{s}{s}  —  {s}{s}{s}\n", .{
        Color.header, Color.reset,
        Color.dim,    version,
        Color.reset,  Color.header,
        tr(lang, "a door they can't close.", "дверь, которую им не закрыть."),
        Color.reset,
    });
    ui.print("  {s}{s}{s}\n\n", .{
        Color.dim,
        tr(lang, "MTProto Proxy installer & control panel", "Установщик и панель управления MTProto Proxy"),
        Color.reset,
    });

    // ── One-liner examples ──
    ui.print("  {s}{s}:{s}\n\n", .{ Color.accent, tr(lang, "Quick install (one-liner)", "Быстрая установка (one-liner)"), Color.reset });
    ui.print("    {s}# {s}:{s}\n", .{ Color.gray, tr(lang, "Minimal — auto-generates secret", "Минимум — секрет сгенерируется автоматически"), Color.reset });
    ui.print("    {s}sudo mtbuddy install --port 443 --domain rutube.ru --yes{s}\n\n", .{ Color.bright_yellow, Color.reset });
    ui.print("    {s}# {s}:{s}\n", .{ Color.gray, tr(lang, "Full control — bring your own secret and username", "Полный контроль — свой секрет и имя пользователя"), Color.reset });
    ui.print("    {s}sudo mtbuddy install --port 443 --domain rutube.ru \\\n", .{Color.bright_yellow});
    ui.print("    {s}  --secret <32-hex> --user alice --yes{s}\n\n", .{ Color.bright_yellow, Color.reset });
    ui.print("    {s}# {s}:{s}\n", .{ Color.gray, tr(lang, "No DPI bypass (bare install)", "Без обхода DPI (чистая установка)"), Color.reset });
    ui.print("    {s}sudo mtbuddy install --port 443 --domain rutube.ru --no-dpi --yes{s}\n\n", .{ Color.bright_yellow, Color.reset });

    ui.print("  {s}{s}:{s}\n\n", .{ Color.accent, tr(lang, "Interactive wizard", "Интерактивный мастер"), Color.reset });
    ui.print("    {s}sudo mtbuddy --interactive{s}\n\n", .{ Color.bright_yellow, Color.reset });
    ui.print("    {s}mtbuddy --lang ru --help{s}\n\n", .{ Color.bright_yellow, Color.reset });

    // ── Commands ──
    ui.print("  {s}{s}:{s}\n\n", .{ Color.accent, tr(lang, "Commands", "Команды"), Color.reset });
    printCmd(&ui, "install", tr(lang, "Install mtproto-proxy from release", "Установить mtproto-proxy из релиза"));
    printCmd(&ui, "uninstall", tr(lang, "Uninstall mtproto-proxy completely", "Полностью удалить mtproto-proxy"));
    printCmd(&ui, "update", tr(lang, "Update to latest GitHub release", "Обновить до последнего GitHub релиза"));
    printCmd(&ui, "setup masking", tr(lang, "Setup local Nginx DPI masking", "Настроить локальную DPI-маскировку через Nginx"));
    printCmd(&ui, "setup nfqws", tr(lang, "Setup nfqws TCP desync (Zapret)", "Настроить nfqws TCP desync (Zapret)"));
    printCmd(&ui, "setup tunnel [--deps-only] [--iface awgN] <conf|vpn://>", tr(lang, "Setup AmneziaWG tunnel pool member", "Настроить участника пула туннелей AmneziaWG"));
    printCmd(&ui, "setup egress [--deps-only] <share-link...>", tr(lang, "Setup VPN share-link egress", "Настроить egress через VPN-ссылку"));
    printCmd(&ui, "setup dashboard", tr(lang, "Install web monitoring dashboard", "Установить веб-дашборд мониторинга"));
    printCmd(&ui, "setup recovery", tr(lang, "Install DPI auto-recovery", "Установить авто-восстановление DPI"));
    printCmd(&ui, "ipv6-hop", tr(lang, "IPv6 address rotation", "Ротация IPv6 адреса"));
    printCmd(&ui, "update-dns <ip>", tr(lang, "Update Cloudflare DNS A record", "Обновить A-запись Cloudflare DNS"));
    printCmd(&ui, "config <validate|doctor|print-effective>", tr(lang, "Config diagnostics and effective values", "Диагностика и эффективные значения конфига"));
    printCmd(&ui, "links", tr(lang, "Print tg:// links from config (sensitive)", "Показать tg:// ссылки из конфига (секретно)"));
    printCmd(&ui, "secret", tr(lang, "Generate a fresh 32-hex secret", "Сгенерировать новый 32-hex секрет"));
    printCmd(&ui, "status", tr(lang, "Show service status", "Показать статус сервисов"));
    printCmd(&ui, "reload", tr(lang, "Reload config (SIGHUP)", "Перезагрузить конфиг (SIGHUP)"));
    ui.writeRaw("\n");

    // ── Install options ──
    ui.print("  {s}{s}:{s}\n\n", .{ Color.accent, tr(lang, "Install options", "Опции установки"), Color.reset });
    printOpt(&ui, "--port,   -p <port>", tr(lang, "Proxy port (default: 443)", "Порт прокси (по умолчанию: 443)"));
    printOpt(&ui, "--public-port <port>", tr(lang, "Port advertised in Telegram links", "Порт для Telegram-ссылок"));
    printOpt(&ui, "--domain, -d <domain>", tr(lang, "TLS masking domain (default: rutube.ru)", "TLS-домен маскировки (по умолчанию: rutube.ru)"));
    printOpt(&ui, "--secret, -s <hex32>", tr(lang, "User secret (32 hex chars, auto-generated if omitted)", "Секрет пользователя (32 hex, если не задан — генерируется)"));
    printOpt(&ui, "--user,   -u <name>", tr(lang, "Username in config.toml (default: user)", "Имя пользователя в config.toml (по умолчанию: user)"));
    printOpt(&ui, "--config, -c <path>", tr(lang, "Use existing config.toml file", "Использовать существующий config.toml"));
    printOpt(&ui, "--yes,    -y", tr(lang, "Skip confirmation prompt (non-interactive)", "Пропустить подтверждение (non-interactive)"));
    printOpt(&ui, "--max-connections <N>", tr(lang, "Max proxy connections (default: 512)", "Максимум подключений (по умолчанию: 512)"));
    printOpt(&ui, "--no-masking", tr(lang, "Disable Nginx DPI masking", "Отключить DPI-маскировку через Nginx"));
    printOpt(&ui, "--no-nfqws", tr(lang, "Disable nfqws TCP desync", "Отключить nfqws TCP desync"));
    printOpt(&ui, "--no-tcpmss", tr(lang, "Disable TCPMSS clamping", "Отключить TCPMSS-клампинг"));
    printOpt(&ui, "--tcpmss <n>", tr(lang, "TCPMSS clamp value (default: 88)", "Значение TCPMSS-клампинга (по умолчанию: 88)"));
    printOpt(&ui, "--no-dpi", tr(lang, "Disable all DPI bypass modules", "Отключить все DPI-модули"));
    printOpt(&ui, "--bind,   -b <ip>", tr(lang, "Bind to specific IP (default: all interfaces)", "Слушать конкретный IP (по умолчанию: все интерфейсы)"));
    printOpt(&ui, "--middle-proxy", tr(lang, "Enable Telegram MiddleProxy relay", "Включить Telegram MiddleProxy relay"));
    printOpt(&ui, "--ipv6-hop", tr(lang, "Enable IPv6 auto-hopping", "Включить автоматическую ротацию IPv6"));
    printOpt(&ui, "--version, -v <tag>", tr(lang, "Release version to install (default: latest)", "Версия релиза для установки (по умолчанию: latest)"));
    printOpt(&ui, "--insecure", tr(lang, "Allow unsigned assets (disables minisign verification)", "Разрешить неподписанные артефакты (отключает minisign verification)"));
    ui.writeRaw("\n");

    // ── Update options ──
    ui.print("  {s}{s}:{s}\n\n", .{ Color.accent, tr(lang, "Update options", "Опции обновления"), Color.reset });
    printOpt(&ui, "--version, -v <tag>", tr(lang, "Pin to specific release tag", "Зафиксировать конкретный тег релиза"));
    printOpt(&ui, "--force-service", tr(lang, "Force systemd unit update", "Принудительно обновить systemd unit"));
    printOpt(&ui, "--insecure", tr(lang, "Allow unsigned assets (disables minisign verification)", "Разрешить неподписанные артефакты (отключает minisign verification)"));
    ui.writeRaw("\n");

    // ── Setup options ──
    ui.print("  {s}{s}:{s}\n\n", .{ Color.accent, tr(lang, "Setup options", "Опции setup"), Color.reset });
    printOpt(&ui, "--domain <domain>", tr(lang, "TLS masking domain", "TLS-домен маскировки"));
    printOpt(&ui, "--ttl <N>", tr(lang, "nfqws fake packet TTL (default: 6)", "TTL фейковых пакетов nfqws (по умолчанию: 6)"));
    printOpt(&ui, "--remove", tr(lang, "Remove nfqws installation", "Удалить установленный nfqws"));
    ui.writeRaw("\n");

    // ── IPv6 options ──
    ui.print("  {s}{s}:{s}\n\n", .{ Color.accent, tr(lang, "IPv6 options", "Опции IPv6"), Color.reset });
    printOpt(&ui, "--check", tr(lang, "Show current IPv6 rotation status", "Показать текущий статус ротации IPv6"));
    printOpt(&ui, "--auto", tr(lang, "Auto-rotate on ban detection", "Авто-ротация при обнаружении блокировки"));
    printOpt(&ui, "--prefix <prefix>", tr(lang, "IPv6 /64 prefix", "IPv6 /64 префикс"));
    printOpt(&ui, "--threshold <N>", tr(lang, "Ban detection threshold (default: 10)", "Порог обнаружения блокировки (по умолчанию: 10)"));
    ui.writeRaw("\n");

    // ── Global options ──
    ui.print("  {s}{s}:{s}\n\n", .{ Color.accent, tr(lang, "Global options", "Глобальные опции"), Color.reset });
    printOpt(&ui, "-i, --interactive", tr(lang, "Interactive TUI wizard", "Интерактивный TUI-мастер"));
    printOpt(&ui, "--lang <en|ru>", tr(lang, "Language (default: auto-detect)", "Язык (по умолчанию: auto-detect)"));
    printOpt(&ui, "-h, --help", tr(lang, "Show this help", "Показать эту справку"));
    printOpt(&ui, "--version", tr(lang, "Show version", "Показать версию"));
    ui.writeRaw("\n");
}

fn printCmd(ui: *Tui, cmd: []const u8, desc: []const u8) void {
    const col = 28;
    const pad = if (cmd.len < col) col - cmd.len else 1;
    var buf: [32]u8 = undefined;
    @memset(buf[0..@min(pad, buf.len)], ' ');
    ui.print("    {s}{s}{s}{s}{s}{s}\n", .{
        Color.bright_yellow,        cmd,       Color.reset,
        buf[0..@min(pad, buf.len)], Color.dim, desc,
    });
    ui.writeRaw(Color.reset);
}

fn printOpt(ui: *Tui, flag: []const u8, desc: []const u8) void {
    const col = 30;
    const pad = if (flag.len < col) col - flag.len else 1;
    var buf: [32]u8 = undefined;
    @memset(buf[0..@min(pad, buf.len)], ' ');
    ui.print("    {s}{s}{s}{s}{s}{s}\n", .{
        Color.info,                 flag,      Color.reset,
        buf[0..@min(pad, buf.len)], Color.dim, desc,
    });
    ui.writeRaw(Color.reset);
}

fn printVersion() void {
    linux_io.writeAllFd(std.posix.STDOUT_FILENO, "mtbuddy v" ++ version ++ "\n");
}

fn parseLangFlag(raw: []const u8) ?i18n.Lang {
    if (std.ascii.eqlIgnoreCase(raw, "en")) return .en;
    if (std.ascii.eqlIgnoreCase(raw, "ru")) return .ru;
    return null;
}

fn printLangFlagError(msg: []const u8) void {
    linux_io.writeAllFd(std.posix.STDERR_FILENO, msg);
}

fn tr(lang: i18n.Lang, en: []const u8, ru: []const u8) []const u8 {
    return if (lang == .ru) ru else en;
}

test {
    // Zig only collects tests from files reachable through analyzed test code. The root
    // test previously referenced only `tunnel`, so 25+ tests in modules reached solely
    // from main() (sharelink, links, config_cmd, fronting_domain, install, ipv6hop, …)
    // never ran under `zig build test` — CI was green on code it never exercised. Pull in
    // every test-bearing ctl module explicitly.
    std.testing.refAllDecls(tunnel);
    _ = @import("sharelink.zig");
    _ = @import("tunnel_wg.zig");
    _ = @import("tunnel_singbox.zig");
    _ = @import("links.zig");
    _ = @import("config_cmd.zig");
    _ = @import("fronting_domain.zig");
    _ = @import("install.zig");
    _ = @import("ipv6hop.zig");
    _ = @import("toml.zig");
    _ = @import("i18n.zig");
    _ = @import("tui.zig");
    _ = @import("release.zig");
    _ = @import("nfqws.zig");
    _ = @import("masking.zig");
    _ = @import("uninstall.zig");
    _ = @import("update.zig");
}
