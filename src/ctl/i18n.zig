//! Comptime bilingual string table for mtbuddy.
//!
//! All user-facing strings are defined here in English and Russian.
//! Language selection happens once at startup; lookups are a simple
//! array index with zero runtime overhead.

pub const Lang = enum {
    en,
    ru,

    pub fn fromEnv() Lang {
        const lang_env = @import("std").posix.getenv("LANG") orelse
            @import("std").posix.getenv("LC_ALL") orelse
            return .en;
        if (indexOf(lang_env, "ru") != null) return .ru;
        return .en;
    }

    fn indexOf(haystack: []const u8, needle: []const u8) ?usize {
        if (needle.len > haystack.len) return null;
        for (0..haystack.len - needle.len + 1) |i| {
            if (@import("std").mem.eql(u8, haystack[i..][0..needle.len], needle)) return i;
        }
        return null;
    }
};

pub const S = enum(u16) {
    // ── Language selection ──
    select_language,
    lang_english,
    lang_russian,

    // ── Main menu ──
    menu_title,
    menu_install,
    menu_update,
    menu_setup_masking,
    menu_setup_tunnel,
    menu_setup_recovery,
    menu_setup_dashboard,
    menu_ipv6_hop,
    menu_edit_config,
    menu_status,
    menu_restart,
    menu_uninstall,
    menu_exit,

    // ── Common ──
    checking_root,
    error_not_root,
    press_enter,
    yes,
    no,
    done,
    failed,
    skipped,
    version_label,
    confirm_proceed,
    aborting,
    restart_success,

    // ── Monitor ──
    monitor_header,
    monitor_port_prompt,
    monitor_port_help,

    // ── Tunnel ──
    tunnel_conf_prompt,
    tunnel_conf_help,

    // ── Install ──
    install_header,
    install_port_prompt,
    install_port_help,
    install_domain_prompt,
    install_domain_help,
    install_secret_prompt,
    install_secret_help,
    install_secret_generated,
    install_dpi_header,
    install_dpi_tcpmss,
    install_dpi_tcpmss_help,
    install_dpi_masking,
    install_dpi_masking_help,
    install_dpi_nfqws,
    install_dpi_nfqws_help,
    install_dpi_ipv6,
    install_dpi_ipv6_help,
    install_dpi_desync,
    install_dpi_desync_help,
    install_dpi_drs,
    install_dpi_drs_help,
    install_checking_deps,
    install_resolving_tag,
    install_download_ok,
    install_downloading,
    install_validating,
    install_binary_ok,
    install_config_generated,
    install_config_exists,
    install_user_created,
    install_service_installed,
    install_firewall_ok,
    install_tcpmss_ok,
    install_success_header,
    install_status_cmd,
    install_logs_cmd,
    install_config_path,
    install_connection_link,
    install_dpi_active,

    // ── Update ──
    update_header,
    update_version_prompt,
    update_version_help,
    update_resolving_tag,
    update_tag_resolved,
    update_downloading,
    update_download_ok,
    update_validating,
    update_validation_ok,
    update_validation_fail,
    update_backing_up,
    update_stopping,
    update_installing,
    update_starting,
    update_rollback,
    update_success_header,
    update_version_label,
    update_arch_label,
    update_artifact_label,
    update_backup_label,

    // ── Uninstall ──
    uninstall_header,
    uninstall_warning,
    uninstall_in_progress,
    uninstall_success,

    // ── Errors ──
    error_arch_unsupported,
    error_no_release,
    error_download_failed,
    error_binary_not_found,
    error_service_failed,
    error_install_dir_missing,
};

/// Get a localized string by key.
pub fn get(lang: Lang, key: S) []const u8 {
    const idx = @intFromEnum(key);
    return switch (lang) {
        .en => en_strings[idx],
        .ru => ru_strings[idx],
    };
}

// ── English strings ─────────────────────────────────────────────

const en_strings = [_][]const u8{
    // select_language
    "Select language / Выберите язык:",
    // lang_english
    "English",
    // lang_russian
    "Русский",

    // ── Main menu ──
    // menu_title
    "What would you like to do?",
    // menu_install
    "\xF0\x9F\x86\x95  Install proxy",
    // menu_update
    "\xE2\xAC\x86\xEF\xB8\x8F  Update proxy",
    // menu_setup_masking
    "\xF0\x9F\x9B\xA1\xEF\xB8\x8F  Setup DPI evasion",
    // menu_setup_tunnel
    "\xF0\x9F\x94\x97  Setup AmneziaWG tunnel",
    // menu_setup_recovery
    "🚑  Setup auto-recovery",
    // menu_setup_dashboard
    "📊  Install Monitoring Dashboard",
    // menu_ipv6_hop
    "\xF0\x9F\x94\x84  IPv6 hopping",
    // menu_edit_config
    "\xE2\x9A\x99\xEF\xB8\x8F  Edit configuration",
    // menu_status
    "\xF0\x9F\x93\x8B  Show status",
    // menu_restart
    "\xE2\x86\xA9\xEF\xB8\x8F  Restart proxy",
    // menu_uninstall
    "\xF0\x9F\x97\x91\xEF\xB8\x8F  Uninstall (Remove completely)",
    // menu_exit
    "\xF0\x9F\x9A\xAA  Exit",

    // ── Common ──
    // checking_root
    "Checking root privileges...",
    // error_not_root
    "This command requires root. Run: sudo mtbuddy",
    // press_enter
    "Press Enter to continue...",
    // yes
    "yes",
    // no
    "no",
    // done
    "done",
    // failed
    "failed",
    // skipped
    "skipped",
    // version_label
    "version",
    // confirm_proceed
    "Proceed?",
    // aborting
    "Aborted.",
    // restart_success
    "Proxy restarted successfully.",

    // ── Monitor ──
    // monitor_header
    "Configure Monitor API",
    // monitor_port_prompt
    "API port",
    // monitor_port_help
    "Port for Prometheus metrics / API.",

    // ── Tunnel ──
    // tunnel_conf_prompt
    "AmneziaWG config file path",
    // tunnel_conf_help
    "Path to your .conf file from AmneziaVPN app or provider.",

    // ── Install ──
    // install_header
    "Install MTProto Proxy",
    // install_port_prompt
    "Proxy port",
    // install_port_help
    "Telegram clients will connect to this port.\n443 is recommended — looks like regular HTTPS traffic.",
    // install_domain_prompt
    "TLS masking domain",
    // install_domain_help
    "The domain your proxy pretends to be.\nDPI sees a connection to this site instead of Telegram.\nShort domains like wb.ru look like legitimate traffic.",
    // install_secret_prompt
    "Proxy secret (32 hex chars)",
    // install_secret_help
    "Leave as 'auto' to generate a random secure secret automatically.",
    // install_secret_generated
    "User secret auto-generated",
    // install_dpi_header
    "DPI evasion modules",
    // install_dpi_tcpmss
    "TCPMSS clamping",
    // install_dpi_tcpmss_help
    "Fragments ClientHello into tiny packets to bypass passive DPI.",
    // install_dpi_masking
    "Nginx masking (zero-RTT)",
    // install_dpi_masking_help
    "Local Nginx serves TLS responses for probes, eliminating timing fingerprints.",
    // install_dpi_nfqws
    "nfqws TCP desync (Zapret)",
    // install_dpi_nfqws_help
    "OS-level TCP desync: fake packets + split to defeat stateful DPI.",
    // install_dpi_ipv6
    "IPv6 auto-hopping",
    // install_dpi_ipv6_help
    "Rotate IPv6 address when ban is detected. Requires Cloudflare API.",
    // install_dpi_desync
    "ServerHello desync",
    // install_dpi_desync_help
    "Split ServerHello into 1-byte + 3ms delay + rest (defeats passive DPI signatures).",
    // install_dpi_drs
    "Dynamic Record Sizing (DRS)",
    // install_dpi_drs_help
    "Ramp TLS records 1369→16384 bytes to mimic browser behavior, evade traffic analysis.",
    // install_checking_deps
    "Installing system dependencies...",
    // install_resolving_tag
    "Resolving latest release...",
    // install_download_ok
    "Binary downloaded",
    // install_downloading
    "Downloading proxy binary...",
    // install_validating
    "Validating binary compatibility...",
    // install_binary_ok
    "Binary installed",
    // install_config_generated
    "Config generated with new secret",
    // install_config_exists
    "Config already exists, keeping it",
    // install_user_created
    "Created system user 'mtproto'",
    // install_service_installed
    "Systemd service installed and started",
    // install_firewall_ok
    "Firewall port opened",
    // install_tcpmss_ok
    "TCPMSS clamping applied",
    // install_success_header
    "MTProto Proxy installed successfully!",
    // install_status_cmd
    "Status:",
    // install_logs_cmd
    "Logs:",
    // install_config_path
    "Config:",
    // install_connection_link
    "Connection link:",
    // install_dpi_active
    "DPI bypass active:",

    // ── Update ──
    // update_header
    "Update mtproto-proxy",
    // update_version_prompt
    "Version",
    // update_version_help
    "Leave empty for latest, or specify e.g. v0.11.0",
    // update_resolving_tag
    "Resolving latest release...",
    // update_tag_resolved
    "Latest release:",
    // update_downloading
    "Downloading artifact...",
    // update_download_ok
    "Artifact downloaded",
    // update_validating
    "Validating binary compatibility...",
    // update_validation_ok
    "Binary compatible with this CPU",
    // update_validation_fail
    "Binary incompatible with this CPU (illegal instruction)",
    // update_backing_up
    "Backing up current binary...",
    // update_stopping
    "Stopping service...",
    // update_installing
    "Installing new binary...",
    // update_starting
    "Starting service...",
    // update_rollback
    "Rolling back to previous binary...",
    // update_success_header
    "Update completed",
    // update_version_label
    "Version:",
    // update_arch_label
    "Arch:",
    // update_artifact_label
    "Artifact:",
    // update_backup_label
    "Backup:",

    // ── Uninstall ──
    // uninstall_header
    "Uninstall mtproto-proxy",
    // uninstall_warning
    "This will completely remove mtbuddy, mtproto-proxy, nfqws, and all related configurations. Are you sure?",
    // uninstall_in_progress
    "Removing components",
    // uninstall_success
    "mtproto-proxy and all its components have been removed.",

    // ── Errors ──
    // error_arch_unsupported
    "Unsupported architecture",
    // error_no_release
    "Could not determine latest release tag",
    // error_download_failed
    "Failed to download artifact",
    // error_binary_not_found
    "Extracted binary not found in artifact",
    // error_service_failed
    "Service failed to start after update",
    // error_install_dir_missing
    "Install directory not found: /opt/mtproto-proxy",
};

// ── Russian strings ─────────────────────────────────────────────

const ru_strings = [_][]const u8{
    // select_language
    "Select language / Выберите язык:",
    // lang_english
    "English",
    // lang_russian
    "Русский",

    // ── Main menu ──
    // menu_title
    "Что вы хотите сделать?",
    // menu_install
    "\xF0\x9F\x86\x95  Установить прокси",
    // menu_update
    "\xE2\xAC\x86\xEF\xB8\x8F  Обновить прокси",
    // menu_setup_masking
    "\xF0\x9F\x9B\xA1\xEF\xB8\x8F  Настроить обход DPI",
    // menu_setup_tunnel
    "\xF0\x9F\x94\x97  Настроить AmneziaWG туннель",
    // menu_setup_recovery
    "🚑  Настроить авто-восстановление",
    // menu_setup_dashboard
    "📊  Установить дашборд мониторинга",
    // menu_ipv6_hop
    "\xF0\x9F\x94\x84  Ротация IPv6",
    // menu_edit_config
    "\xE2\x9A\x99\xEF\xB8\x8F  Настроить конфигурацию",
    // menu_status
    "\xF0\x9F\x93\x8B  Показать статус",
    // menu_restart
    "\xE2\x86\xA9\xEF\xB8\x8F  Перезапустить прокси",
    // menu_uninstall
    "\xF0\x9F\x97\x91\xEF\xB8\x8F  Полностью удалить прокси",
    // menu_exit
    "\xF0\x9F\x9A\xAA  Выход",

    // ── Common ──
    // checking_root
    "Проверка прав root...",
    // error_not_root
    "Требуются права root. Запустите: sudo mtbuddy",
    // press_enter
    "Нажмите Enter для продолжения...",
    // yes
    "да",
    // no
    "нет",
    // done
    "готово",
    // failed
    "ошибка",
    // skipped
    "пропущено",
    // version_label
    "версия",
    // confirm_proceed
    "Продолжить?",
    // aborting
    "Отменено.",
    // restart_success
    "Прокси успешно перезапущен.",

    // ── Monitor ──
    // monitor_header
    "Настройка API мониторинга",
    // monitor_port_prompt
    "Порт API",
    // monitor_port_help
    "Порт для отдачи метрик Prometheus / API.",

    // ── Tunnel ──
    // tunnel_conf_prompt
    "Путь к конфигурации AmneziaWG",
    // tunnel_conf_help
    "Путь к .conf файлу от VPN-приложения или провайдера.",

    // ── Install ──
    // install_header
    "Установка MTProto Proxy",
    // install_port_prompt
    "Порт прокси",
    // install_port_help
    "Telegram клиенты будут подключаться на этот порт.\n443 рекомендуется — выглядит как обычный HTTPS трафик.",
    // install_domain_prompt
    "TLS домен для маскировки",
    // install_domain_help
    "Домен, под который прокси маскирует трафик.\nDPI видит подключение к этому сайту вместо Telegram.\nКороткие домены вроде wb.ru похожи на легитимный трафик.",
    // install_secret_prompt
    "Секрет прокси (32 hex символа)",
    // install_secret_help
    "Оставьте 'auto', чтобы сгенерировать надежный секрет автоматически.",
    // install_secret_generated
    "Секрет сгенерирован автоматически",
    // install_dpi_header
    "Модули обхода DPI",
    // install_dpi_tcpmss
    "TCPMSS clamping",
    // install_dpi_tcpmss_help
    "Фрагментирует ClientHello на маленькие пакеты для обхода пассивного DPI.",
    // install_dpi_masking
    "Nginx маскировка (zero-RTT)",
    // install_dpi_masking_help
    "Локальный Nginx отвечает на TLS пробы, устраняя fingerprint по таймингу.",
    // install_dpi_nfqws
    "nfqws TCP desync (Zapret)",
    // install_dpi_nfqws_help
    "Десинхронизация TCP на уровне ОС: фейковые пакеты + фрагментация.",
    // install_dpi_ipv6
    "Автоматическая ротация IPv6",
    // install_dpi_ipv6_help
    "Ротация IPv6 адреса при обнаружении блокировки. Нужен Cloudflare API.",
    // install_dpi_desync
    "Desync ServerHello",
    // install_dpi_desync_help
    "Фрагментирует ServerHello: 1 байт + 3мс задержка + остаток (обход пассивного DPI).",
    // install_dpi_drs
    "Dynamic Record Sizing (DRS)",
    // install_dpi_drs_help
    "Наращивание TLS записей 1369→16384 байт, имитируя браузер, обход анализа трафика.",
    // install_checking_deps
    "Установка системных зависимостей...",
    // install_resolving_tag
    "Определение последней версии...",
    // install_download_ok
    "Бинарник скачан",
    // install_downloading
    "Скачивание бинарника прокси...",
    // install_validating
    "Проверка совместимости бинарника...",
    // install_binary_ok
    "Бинарник установлен",
    // install_config_generated
    "Конфигурация создана с новым секретом",
    // install_config_exists
    "Конфигурация уже существует, сохраняем",
    // install_user_created
    "Создан системный пользователь 'mtproto'",
    // install_service_installed
    "Systemd сервис установлен и запущен",
    // install_firewall_ok
    "Порт открыт в файрволе",
    // install_tcpmss_ok
    "TCPMSS clamping применён",
    // install_success_header
    "MTProto Proxy успешно установлен!",
    // install_status_cmd
    "Статус:",
    // install_logs_cmd
    "Логи:",
    // install_config_path
    "Конфиг:",
    // install_connection_link
    "Ссылка для подключения:",
    // install_dpi_active
    "Обход DPI активен:",

    // ── Update ──
    // update_header
    "Обновление MTProto Proxy",
    // update_version_prompt
    "Версия",
    // update_version_help
    "Оставьте пустым для latest, или укажите (напр. v0.11.0)",
    // update_resolving_tag
    "Определение последней версии...",
    // update_tag_resolved
    "Последняя версия:",
    // update_downloading
    "Скачивание артефакта...",
    // update_download_ok
    "Артефакт скачан",
    // update_validating
    "Проверка совместимости...",
    // update_validation_ok
    "Бинарник совместим с этим CPU",
    // update_validation_fail
    "Бинарник несовместим с этим CPU (illegal instruction)",
    // update_backing_up
    "Резервная копия текущего бинарника...",
    // update_stopping
    "Остановка сервиса...",
    // update_installing
    "Установка нового бинарника...",
    // update_starting
    "Запуск сервиса...",
    // update_rollback
    "Откат к предыдущему бинарнику...",
    // update_success_header
    "Обновление завершено",
    // update_version_label
    "Версия:",
    // update_arch_label
    "Архитектура:",
    // update_artifact_label
    "Артефакт:",
    // update_backup_label
    "Резервная копия:",

    // ── Uninstall ──
    // uninstall_header
    "Удаление mtproto-proxy",
    // uninstall_warning
    "Это действие полностью удалит mtbuddy, прокси, nfqws и все связанные настройки. Вы уверены?",
    // uninstall_in_progress
    "Удаление компонентов",
    // uninstall_success
    "mtproto-proxy и все связанные компоненты успешно удалены.",

    // ── Errors ──
    // error_arch_unsupported
    "Неподдерживаемая архитектура",
    // error_no_release
    "Не удалось определить последнюю версию",
    // error_download_failed
    "Не удалось скачать артефакт",
    // error_binary_not_found
    "Бинарник не найден в артефакте",
    // error_service_failed
    "Сервис не запустился после обновления",
    // error_install_dir_missing
    "Директория установки не найдена: /opt/mtproto-proxy",
};

// ── Comptime validation ─────────────────────────────────────────

comptime {
    const num_keys = @typeInfo(S).@"enum".fields.len;
    if (en_strings.len != num_keys) {
        @compileError("en_strings length mismatch with S enum");
    }
    if (ru_strings.len != num_keys) {
        @compileError("ru_strings length mismatch with S enum");
    }
}
