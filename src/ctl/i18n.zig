//! Comptime bilingual string table for buddy.
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
    menu_setup_monitor,
    menu_ipv6_hop,
    menu_edit_config,
    menu_status,
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

    // ── Install ──
    install_header,
    install_port_prompt,
    install_port_help,
    install_domain_prompt,
    install_domain_help,
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
    install_checking_deps,
    install_installing_zig,
    install_zig_ok,
    install_cloning,
    install_building,
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
    // menu_setup_monitor
    "\xF0\x9F\x93\x8A  Setup monitoring",
    // menu_ipv6_hop
    "\xF0\x9F\x94\x84  IPv6 hopping",
    // menu_edit_config
    "\xE2\x9A\x99\xEF\xB8\x8F  Edit configuration",
    // menu_status
    "\xF0\x9F\x93\x8B  Show status",
    // menu_exit
    "\xF0\x9F\x9A\xAA  Exit",

    // ── Common ──
    // checking_root
    "Checking root privileges...",
    // error_not_root
    "This command requires root. Run: sudo buddy",
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
    // install_checking_deps
    "Installing system dependencies...",
    // install_installing_zig
    "Installing Zig",
    // install_zig_ok
    "Zig installed",
    // install_cloning
    "Cloning repository...",
    // install_building
    "Building mtproto-proxy...",
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
    "Update MTProto Proxy",
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
    // menu_setup_monitor
    "\xF0\x9F\x93\x8A  Настроить мониторинг",
    // menu_ipv6_hop
    "\xF0\x9F\x94\x84  Ротация IPv6",
    // menu_edit_config
    "\xE2\x9A\x99\xEF\xB8\x8F  Настроить конфигурацию",
    // menu_status
    "\xF0\x9F\x93\x8B  Показать статус",
    // menu_exit
    "\xF0\x9F\x9A\xAA  Выход",

    // ── Common ──
    // checking_root
    "Проверка прав root...",
    // error_not_root
    "Требуются права root. Запустите: sudo buddy",
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
    // install_checking_deps
    "Установка системных зависимостей...",
    // install_installing_zig
    "Установка Zig",
    // install_zig_ok
    "Zig установлен",
    // install_cloning
    "Клонирование репозитория...",
    // install_building
    "Сборка mtproto-proxy...",
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
