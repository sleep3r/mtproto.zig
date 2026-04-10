//! Install command for mtbuddy.
//!
//! Ports install.sh (296 lines of bash) into structured Zig code.
//! Supports both interactive TUI mode and non-interactive CLI mode.
//!
//! One-liner usage:
//!   sudo mtbuddy install --port 443 --domain wb.ru --yes
//!   sudo mtbuddy install --port 443 --domain wb.ru --secret <hex> --user myuser --yes

const std = @import("std");
const tui_mod = @import("tui.zig");
const i18n = @import("i18n.zig");
const sys = @import("sys.zig");
const toml = @import("toml.zig");
const masking = @import("masking.zig");
const nfqws = @import("nfqws.zig");

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;
const SummaryLine = tui_mod.SummaryLine;

const ZIG_VERSION = "0.15.2";
const INSTALL_DIR = "/opt/mtproto-proxy";
const REPO_URL = "https://github.com/sleep3r/mtproto.zig.git";
const SERVICE_NAME = "mtproto-proxy";

pub const InstallOpts = struct {
    port: u16 = 443,
    tls_domain: []const u8 = "wb.ru",
    max_connections: u32 = 512,
    enable_tcpmss: bool = true,
    enable_masking: bool = true,
    enable_nfqws: bool = true,
    enable_ipv6_hop: bool = false,
    enable_desync: bool = true,
    enable_drs: bool = false,
    /// Pre-set user secret (32-char hex). If null, auto-generated.
    secret: ?[32]u8 = null,
    /// User name for config.toml. If null, defaults to "user".
    user: ?[]const u8 = null,
    /// Skip confirmation prompt (non-interactive / one-liner mode).
    yes: bool = false,
    /// Zig release tag to install from (overrides default ZIG_VERSION).
    zig_tag: ?[]const u8 = null,
    /// Path to an existing config.toml to use.
    config_path: ?[]const u8 = null,
    /// Internal flags to track if user explicitly provided a value.
    port_provided: bool = false,
    domain_provided: bool = false,
};

/// Run install in CLI (non-interactive) mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.ArgIterator) !void {
    var opts = InstallOpts{};

    // Parse CLI flags
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port") or std.mem.eql(u8, arg, "-p")) {
            if (args.next()) |val| {
                opts.port = std.fmt.parseInt(u16, val, 10) catch 443;
                opts.port_provided = true;
            }
        } else if (std.mem.eql(u8, arg, "--domain") or std.mem.eql(u8, arg, "-d")) {
            if (args.next()) |val| {
                opts.tls_domain = val;
                opts.domain_provided = true;
            }
        } else if (std.mem.eql(u8, arg, "--config") or std.mem.eql(u8, arg, "-c")) {
            if (args.next()) |val| opts.config_path = val;
        } else if (std.mem.eql(u8, arg, "--max-connections")) {
            if (args.next()) |val| opts.max_connections = std.fmt.parseInt(u32, val, 10) catch 512;
        } else if (std.mem.eql(u8, arg, "--secret") or std.mem.eql(u8, arg, "-s")) {
            if (args.next()) |val| {
                if (val.len == 32) {
                    var sec: [32]u8 = undefined;
                    @memcpy(&sec, val[0..32]);
                    opts.secret = sec;
                } else {
                    ui.warn("--secret must be exactly 32 hex characters, ignoring");
                }
            }
        } else if (std.mem.eql(u8, arg, "--user") or std.mem.eql(u8, arg, "-u")) {
            if (args.next()) |val| opts.user = val;
        } else if (std.mem.eql(u8, arg, "--yes") or std.mem.eql(u8, arg, "-y")) {
            opts.yes = true;
        } else if (std.mem.eql(u8, arg, "--no-masking")) {
            opts.enable_masking = false;
        } else if (std.mem.eql(u8, arg, "--no-nfqws")) {
            opts.enable_nfqws = false;
        } else if (std.mem.eql(u8, arg, "--no-tcpmss")) {
            opts.enable_tcpmss = false;
        } else if (std.mem.eql(u8, arg, "--no-dpi")) {
            // Disable all DPI bypass modules at once
            opts.enable_masking = false;
            opts.enable_nfqws = false;
            opts.enable_tcpmss = false;
        } else if (std.mem.eql(u8, arg, "--ipv6-hop")) {
            opts.enable_ipv6_hop = true;
        } else if (std.mem.eql(u8, arg, "--zig-tag")) {
            if (args.next()) |val| opts.zig_tag = val;
        }
    }

    if (opts.config_path) |cfg_path| {
        if (!sys.fileExists(cfg_path)) {
            ui.fail("Specified config file does not exist");
            return;
        }
        var doc = toml.TomlDoc.load(allocator, cfg_path) catch {
            ui.fail("Failed to parse specified config file");
            return;
        };
        defer doc.deinit();

        if (!opts.port_provided) {
            if (doc.get("server", "port")) |p_str| {
                opts.port = std.fmt.parseInt(u16, p_str, 10) catch 443;
            }
        }
        if (!opts.domain_provided) {
            if (doc.get("censorship", "tls_domain")) |d_str| {
                opts.tls_domain = d_str;
            }
        }
    }

    // In non-interactive mode, print a compact summary of what will happen
    if (!opts.yes) {
        ui.writeRaw("\n");
        ui.print("  {s}⚡ mtbuddy install{s}\n\n", .{ Color.header, Color.reset });
        ui.print("  {s}Port:{s}     {d}\n", .{ Color.dim, Color.reset, opts.port });
        ui.print("  {s}Domain:{s}   {s}\n", .{ Color.dim, Color.reset, opts.tls_domain });
        ui.print("  {s}TCPMSS:{s}   {s}\n", .{ Color.dim, Color.reset, if (opts.enable_tcpmss) "enabled" else "disabled" });
        ui.print("  {s}Masking:{s}  {s}\n", .{ Color.dim, Color.reset, if (opts.enable_masking) "enabled" else "disabled" });
        ui.print("  {s}nfqws:{s}    {s}\n", .{ Color.dim, Color.reset, if (opts.enable_nfqws) "enabled" else "disabled" });
        ui.writeRaw("\n");

        if (!try ui.confirm("Proceed with installation?", true)) {
            ui.info(ui.str(.aborting));
            return;
        }
    }

    try execute(ui, allocator, opts);
}

/// Run install in interactive TUI mode.
pub fn runInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    var opts = InstallOpts{};

    ui.section(ui.str(.install_header));

    // Port
    var port_buf: [16]u8 = undefined;
    const port_str = try ui.input(
        ui.str(.install_port_prompt),
        ui.str(.install_port_help),
        "443",
        &port_buf,
    );
    opts.port = std.fmt.parseInt(u16, port_str, 10) catch 443;

    // TLS domain
    var domain_buf: [256]u8 = undefined;
    const domain = try ui.input(
        ui.str(.install_domain_prompt),
        ui.str(.install_domain_help),
        "wb.ru",
        &domain_buf,
    );
    opts.tls_domain = domain;

    // Secret
    var secret_hex: [32]u8 = undefined;
    var secret_buf: [256]u8 = undefined;
    while (true) {
        const sec_str = try ui.input(
            ui.str(.install_secret_prompt),
            ui.str(.install_secret_help),
            "auto",
            &secret_buf,
        );

        if (std.mem.eql(u8, sec_str, "auto") or sec_str.len == 0) {
            sys.generateSecret(&secret_hex);
            ui.writeRaw("\n");
            ui.print("  {s}🔐{s} {s}: {s}{s}{s}\n", .{
                Color.bright_yellow,
                Color.reset,
                ui.str(.install_secret_generated),
                Color.ok,
                &secret_hex,
                Color.reset,
            });
            break;
        } else if (sec_str.len == 32) {
            @memcpy(&secret_hex, sec_str[0..32]);
            break;
        } else {
            ui.print("  {s}✗ Secret must be exactly 32 hex characters, or 'auto'{s}\n", .{ Color.err, Color.reset });
        }
    }

    // DPI modules — checkbox selection
    const dpi_result = try ui.checkboxes(
        ui.str(.install_dpi_header),
        &.{
            ui.str(.install_dpi_tcpmss),
            ui.str(.install_dpi_masking),
            ui.str(.install_dpi_nfqws),
            ui.str(.install_dpi_desync),
            ui.str(.install_dpi_drs),
            ui.str(.install_dpi_ipv6),
        },
        &.{
            ui.str(.install_dpi_tcpmss_help),
            ui.str(.install_dpi_masking_help),
            ui.str(.install_dpi_nfqws_help),
            ui.str(.install_dpi_desync_help),
            ui.str(.install_dpi_drs_help),
            ui.str(.install_dpi_ipv6_help),
        },
        &.{ true, true, true, true, false, false },
    );

    opts.enable_tcpmss = (dpi_result & 1) != 0;
    opts.enable_masking = (dpi_result & 2) != 0;
    opts.enable_nfqws = (dpi_result & 4) != 0;
    opts.enable_desync = (dpi_result & 8) != 0;
    opts.enable_drs = (dpi_result & 16) != 0;
    opts.enable_ipv6_hop = (dpi_result & 32) != 0;
    opts.secret = secret_hex;
    opts.yes = true; // already confirmed via wizard

    // Confirm
    if (!try ui.confirm(ui.str(.confirm_proceed), true)) {
        ui.info(ui.str(.aborting));
        return;
    }

    try execute(ui, allocator, opts);
}

/// Execute the installation steps.
fn execute(ui: *Tui, allocator: std.mem.Allocator, opts: InstallOpts) !void {
    // ── Check root ──
    if (!sys.isRoot()) {
        ui.fail(ui.str(.error_not_root));
        return;
    }

    ui.writeRaw("\n");
    ui.rule();

    // ── Install dependencies ──
    {
        var sp = ui.spinner(ui.str(.install_checking_deps));
        sp.start();
        _ = sys.exec(allocator, &.{ "apt-get", "update", "-qq" }) catch {};
        _ = sys.exec(allocator, &.{
            "apt-get",  "install", "-y",
            "iptables", "xxd",     "git",
            "curl",     "openssl", "tar",
            "xz-utils",
        }) catch {};
        sp.stop(true, "");
    }

    // ── Install Zig ──
    const zig_ver = opts.zig_tag orelse ZIG_VERSION;
    const has_zig = blk: {
        const result = sys.exec(allocator, &.{ "zig", "version" }) catch break :blk false;
        defer result.deinit();
        const trimmed = std.mem.trim(u8, result.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
        break :blk std.mem.startsWith(u8, trimmed, zig_ver);
    };

    if (has_zig) {
        ui.stepOk(ui.str(.install_zig_ok), zig_ver);
    } else {
        var sp = ui.spinner(ui.str(.install_installing_zig));
        sp.start();

        const arch = sys.getArch() catch {
            sp.stop(false, "");
            ui.fail(ui.str(.error_arch_unsupported));
            return;
        };

        var zig_cmd_buf: [512]u8 = undefined;
        const zig_cmd = std.fmt.bufPrint(&zig_cmd_buf,
            \\cd /tmp && curl -sSfL -o zig.tar.xz https://ziglang.org/download/{[a]s}/zig-{[b]s}-linux-{[c]s}.tar.xz && tar xf zig.tar.xz && rm -rf /usr/local/zig && mv zig-{[b]s}-linux-{[c]s} /usr/local/zig && ln -sf /usr/local/zig/zig /usr/local/bin/zig && rm -f zig.tar.xz
        , .{ .a = zig_ver, .b = arch.toStr(), .c = zig_ver }) catch {
            sp.stop(false, "");
            return;
        };

        const dl_result = sys.exec(allocator, &.{ "bash", "-c", zig_cmd }) catch {
            sp.stop(false, "");
            return;
        };

        if (dl_result.exit_code != 0) {
            sp.stop(false, "");
            if (dl_result.stderr.len > 0) {
                ui.hint(dl_result.stderr[0..@min(dl_result.stderr.len, 200)]);
            }
            return;
        }
        sp.stop(true, zig_ver);
    }

    // ── Clone & build ──
    {
        var sp = ui.spinner(ui.str(.install_building));
        sp.start();
        var cmd_buf: [1024]u8 = undefined;
        const build_cmd = std.fmt.bufPrint(
            &cmd_buf,
            "TMPDIR=$(mktemp -d) && git clone --depth 1 {s} $TMPDIR 2>&1 && " ++
                "cd $TMPDIR && zig build -Doptimize=ReleaseFast 2>&1 && " ++
                "mkdir -p {s} && cp zig-out/bin/mtproto-proxy {s}/mtproto-proxy && " ++
                "chmod +x {s}/mtproto-proxy && " ++
                "cp $TMPDIR/deploy/*.sh {s}/ 2>/dev/null || true && " ++
                "cp $TMPDIR/deploy/mtproto-proxy.service /etc/systemd/system/ && " ++
                "chmod +x {s}/*.sh 2>/dev/null || true && rm -rf $TMPDIR",
            .{ REPO_URL, INSTALL_DIR, INSTALL_DIR, INSTALL_DIR, INSTALL_DIR, INSTALL_DIR },
        ) catch {
            sp.stop(false, "");
            return;
        };

        const build_result = sys.exec(allocator, &.{ "bash", "-c", build_cmd }) catch {
            sp.stop(false, "");
            return;
        };
        defer build_result.deinit();

        if (build_result.exit_code != 0) {
            sp.stop(false, "");
            if (build_result.stderr.len > 0) {
                ui.hint(build_result.stderr[0..@min(build_result.stderr.len, 200)]);
            }
            return;
        }
        sp.stop(true, "");
    }
    ui.ok(ui.str(.install_binary_ok));

    // ── Copy user config (if provided) ──
    if (opts.config_path) |cfg_path| {
        _ = sys.exec(allocator, &.{ "cp", cfg_path, INSTALL_DIR ++ "/config.toml" }) catch {};
    }

    // ── Generate config ──
    const config_path_buf = INSTALL_DIR ++ "/config.toml";
    if (!sys.fileExists(config_path_buf)) {
        var secret_hex: [32]u8 = undefined;
        if (opts.secret) |s| {
            secret_hex = s;
        } else {
            sys.generateSecret(&secret_hex);
        }

        const user_name = opts.user orelse "user";

        var doc = toml.TomlDoc.initEmpty(allocator);
        defer doc.deinit();

        try doc.addSection("server");
        var port_val_buf: [8]u8 = undefined;
        const port_val = std.fmt.bufPrint(&port_val_buf, "{d}", .{opts.port}) catch "443";
        try doc.addKv("port", port_val);
        try doc.addKv("max_connections", "512");
        try doc.addKv("idle_timeout_sec", "120");
        try doc.addKv("handshake_timeout_sec", "15");

        try doc.addSection("censorship");
        try doc.addKvStr("tls_domain", opts.tls_domain);
        try doc.addKv("mask", "true");
        try doc.addKv("desync", if (opts.enable_desync) "true" else "false");
        try doc.addKv("drs", if (opts.enable_drs) "true" else "false");
        try doc.addKv("fast_mode", "true");

        try doc.addSection("access.users");
        try doc.addKvStr(user_name, &secret_hex);

        try doc.save(config_path_buf);
        ui.ok(ui.str(.install_config_generated));
    } else {
        ui.ok(ui.str(.install_config_exists));
    }

    // ── Create system user ──
    if (!blk: {
        const r = sys.exec(allocator, &.{ "id", "-u", "mtproto" }) catch break :blk false;
        defer r.deinit();
        break :blk r.exit_code == 0;
    }) {
        _ = sys.exec(allocator, &.{
            "useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "mtproto",
        }) catch {};
        ui.ok(ui.str(.install_user_created));
    }

    _ = sys.exec(allocator, &.{ "chown", "-R", "mtproto:mtproto", INSTALL_DIR }) catch {};

    // ── Systemd service ──
    {
        var sp = ui.spinner(ui.str(.install_service_installed));
        sp.start();
        _ = sys.exec(allocator, &.{ "systemctl", "daemon-reload" }) catch {};
        _ = sys.exec(allocator, &.{ "systemctl", "enable", SERVICE_NAME }) catch {};
        _ = sys.exec(allocator, &.{ "systemctl", "restart", SERVICE_NAME }) catch {};
        sp.stop(true, "");
    }

    // ── Firewall ──
    if (sys.commandExists("ufw")) {
        var port_str_buf: [8]u8 = undefined;
        const port_rule = std.fmt.bufPrint(&port_str_buf, "{d}/tcp", .{opts.port}) catch "443/tcp";
        _ = sys.exec(allocator, &.{ "ufw", "allow", port_rule }) catch {};
        ui.ok(ui.str(.install_firewall_ok));
    }

    // ── TCPMSS clamping ──
    if (opts.enable_tcpmss) {
        var port_str_buf: [8]u8 = undefined;
        const port_str = std.fmt.bufPrint(&port_str_buf, "{d}", .{opts.port}) catch "443";

        _ = sys.exec(allocator, &.{
            "iptables", "-t",      "mangle",  "-A",     "OUTPUT",
            "-p",       "tcp",     "--sport", port_str, "--tcp-flags",
            "SYN,ACK",  "SYN,ACK", "-j",      "TCPMSS", "--set-mss",
            "88",
        }) catch {};
        _ = sys.exec(allocator, &.{
            "ip6tables", "-t",      "mangle",  "-A",     "OUTPUT",
            "-p",        "tcp",     "--sport", port_str, "--tcp-flags",
            "SYN,ACK",   "SYN,ACK", "-j",      "TCPMSS", "--set-mss",
            "88",
        }) catch {};
        _ = sys.exec(allocator, &.{
            "bash",                                                                                                        "-c",
            "mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4 && ip6tables-save > /etc/iptables/rules.v6",
        }) catch {};

        ui.ok(ui.str(.install_tcpmss_ok));
    }

    // ── Masking (via Zig module) ──
    if (opts.enable_masking) {
        masking.execute(ui, allocator, .{ .tls_domain = opts.tls_domain }) catch {
            ui.warn("Masking setup failed");
        };
    }

    // ── nfqws (via Zig module) ──
    if (opts.enable_nfqws) {
        nfqws.execute(ui, allocator, .{}) catch {
            ui.warn("nfqws setup failed");
        };
    }

    // ── Final restart ──
    _ = sys.exec(allocator, &.{ "chown", "-R", "mtproto:mtproto", INSTALL_DIR }) catch {};
    _ = sys.exec(allocator, &.{ "systemctl", "restart", SERVICE_NAME }) catch {};

    ui.rule();

    // ── Print summary ──
    var sp = ui.spinner("Detecting public IP");
    sp.start();
    const public_ip = sys.detectPublicIp(allocator) orelse "<SERVER_IP>";
    sp.stop(true, public_ip);

    // Read summary values from active config
    var summary_server: []const u8 = public_ip;
    var summary_server_buf: [256]u8 = undefined;
    var summary_port: u16 = opts.port;
    var summary_tls_domain: []const u8 = opts.tls_domain;
    var summary_tls_domain_buf: [256]u8 = undefined;
    var secret_from_cfg: []const u8 = "unknown";
    var secret_buf: [128]u8 = undefined;

    {
        var cfg_doc = toml.TomlDoc.load(allocator, config_path_buf) catch {
            printSummary(ui, allocator, public_ip, opts.port, secret_from_cfg, opts.tls_domain, opts, config_path_buf);
            return;
        };
        defer cfg_doc.deinit();

        if (cfg_doc.get("server", "public_ip")) |configured_server| {
            const trimmed = std.mem.trim(u8, configured_server, &[_]u8{ ' ', '\t' });
            if (trimmed.len > 0) {
                const copy_len = @min(trimmed.len, summary_server_buf.len);
                @memcpy(summary_server_buf[0..copy_len], trimmed[0..copy_len]);
                summary_server = summary_server_buf[0..copy_len];
            }
        }

        if (cfg_doc.get("server", "port")) |configured_port| {
            summary_port = std.fmt.parseInt(u16, configured_port, 10) catch summary_port;
        }

        if (cfg_doc.get("censorship", "tls_domain")) |configured_domain| {
            const trimmed = std.mem.trim(u8, configured_domain, &[_]u8{ ' ', '\t' });
            if (trimmed.len > 0) {
                const copy_len = @min(trimmed.len, summary_tls_domain_buf.len);
                @memcpy(summary_tls_domain_buf[0..copy_len], trimmed[0..copy_len]);
                summary_tls_domain = summary_tls_domain_buf[0..copy_len];
            }
        }

        const user_name = opts.user orelse "user";
        if (cfg_doc.get("access.users", user_name) orelse cfg_doc.get("access.users", "user")) |configured_secret| {
            const copy_len = @min(configured_secret.len, secret_buf.len);
            @memcpy(secret_buf[0..copy_len], configured_secret[0..copy_len]);
            secret_from_cfg = secret_buf[0..copy_len];
        }
    }

    printSummary(
        ui,
        allocator,
        summary_server,
        summary_port,
        secret_from_cfg,
        summary_tls_domain,
        opts,
        config_path_buf,
    );
}

fn buildEeSecret(secret: []const u8, tls_domain: []const u8, ee_buf: *[512]u8) []const u8 {
    var ee_pos: usize = 0;

    @memcpy(ee_buf[0..2], "ee");
    ee_pos = 2;

    var clean_secret = secret;
    if (clean_secret.len >= 2 and clean_secret[0] == '"' and clean_secret[clean_secret.len - 1] == '"') {
        clean_secret = clean_secret[1 .. clean_secret.len - 1];
    }

    const sec_len = @min(clean_secret.len, ee_buf.len - ee_pos);
    @memcpy(ee_buf[ee_pos..][0..sec_len], clean_secret[0..sec_len]);
    ee_pos += sec_len;

    var domain_hex_buf: [512]u8 = undefined;
    const domain_hex = sys.domainToHex(tls_domain, &domain_hex_buf);
    const dh_len = @min(domain_hex.len, ee_buf.len - ee_pos);
    @memcpy(ee_buf[ee_pos..][0..dh_len], domain_hex[0..dh_len]);
    ee_pos += dh_len;

    return ee_buf[0..ee_pos];
}

fn stripInlineComment(value: []const u8) []const u8 {
    var in_quotes = false;
    var comment_pos: ?usize = null;

    for (value, 0..) |c, ci| {
        if (c == '"') {
            in_quotes = !in_quotes;
        } else if (c == '#' and !in_quotes) {
            comment_pos = ci;
            break;
        }
    }

    if (comment_pos) |cp| {
        return std.mem.trim(u8, value[0..cp], &[_]u8{ ' ', '\t' });
    }
    return std.mem.trim(u8, value, &[_]u8{ ' ', '\t' });
}

fn isValidSecretHex(secret: []const u8) bool {
    if (secret.len != 32) return false;
    for (secret) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

fn printLinksFromConfig(
    ui: *Tui,
    allocator: std.mem.Allocator,
    public_ip: []const u8,
    port: u16,
    tls_domain: []const u8,
    config_path: []const u8,
) bool {
    var cfg_doc = toml.TomlDoc.load(allocator, config_path) catch return false;
    defer cfg_doc.deinit();

    var printed_any = false;
    var in_users_section = false;

    for (cfg_doc.lines.items) |line| {
        const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r' });
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        if (trimmed[0] == '[') {
            in_users_section = std.mem.eql(u8, trimmed, "[access.users]");
            continue;
        }
        if (!in_users_section) continue;

        const eq_pos = std.mem.indexOfScalar(u8, trimmed, '=') orelse continue;
        const user_name = std.mem.trim(u8, trimmed[0..eq_pos], &[_]u8{ ' ', '\t' });
        if (user_name.len == 0) continue;

        var secret_hex = std.mem.trim(u8, trimmed[eq_pos + 1 ..], &[_]u8{ ' ', '\t' });
        secret_hex = stripInlineComment(secret_hex);
        if (secret_hex.len >= 2 and secret_hex[0] == '"' and secret_hex[secret_hex.len - 1] == '"') {
            secret_hex = secret_hex[1 .. secret_hex.len - 1];
        }
        if (!isValidSecretHex(secret_hex)) continue;

        var ee_buf: [512]u8 = undefined;
        const ee_secret = buildEeSecret(secret_hex, tls_domain, &ee_buf);

        var link_buf: [512]u8 = undefined;
        const link = std.fmt.bufPrint(&link_buf, "tg://proxy?server={s}&port={d}&secret={s}", .{
            public_ip,
            port,
            ee_secret,
        }) catch continue;

        ui.print("  {s}│{s}  {s}{s}:{s} {s}{s}{s}\n", .{
            tui_mod.Color.gray,
            tui_mod.Color.reset,
            tui_mod.Color.dim,
            user_name,
            tui_mod.Color.reset,
            tui_mod.Color.white,
            link,
            tui_mod.Color.reset,
        });
        printed_any = true;
    }

    return printed_any;
}

fn printSummary(
    ui: *Tui,
    allocator: std.mem.Allocator,
    public_ip: []const u8,
    port: u16,
    secret: []const u8,
    tls_domain: []const u8,
    opts: InstallOpts,
    config_path: []const u8,
) void {
    var port_buf: [8]u8 = undefined;
    const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch "443";

    ui.summaryBox(ui.str(.install_success_header), &.{
        .{ .label = ui.str(.install_status_cmd), .value = "systemctl status mtproto-proxy" },
        .{ .label = ui.str(.install_logs_cmd), .value = "journalctl -u mtproto-proxy -f" },
        .{ .label = ui.str(.install_config_path), .value = INSTALL_DIR ++ "/config.toml" },
        .{ .label = "Server:", .value = public_ip },
        .{ .label = "Port:", .value = port_str },
        .{ .label = "", .style = .blank },
        .{ .label = ui.str(.install_dpi_active), .style = .highlight },
        .{
            .label = if (opts.enable_tcpmss) "TCPMSS=88 (ClientHello fragmentation)" else "",
            .style = if (opts.enable_tcpmss) .success else .blank,
        },
        .{
            .label = if (opts.enable_masking) "Local Nginx Masking (Zero-RTT)" else "",
            .style = if (opts.enable_masking) .success else .blank,
        },
        .{
            .label = if (opts.enable_nfqws) "nfqws TCP Desync (Zapret)" else "",
            .style = if (opts.enable_nfqws) .success else .blank,
        },
        .{
            .label = if (opts.enable_desync) "ServerHello desync (built-in)" else "",
            .style = if (opts.enable_desync) .success else .blank,
        },
        .{
            .label = if (opts.enable_drs) "Dynamic Record Sizing (built-in)" else "",
            .style = if (opts.enable_drs) .success else .blank,
        },
    });

    ui.writeRaw("\n");
    ui.print("  {s}╭─ {s}{s}\n", .{ tui_mod.Color.gray, tui_mod.Color.bold, ui.str(.install_connection_link) });

    if (!printLinksFromConfig(ui, allocator, public_ip, port, tls_domain, config_path)) {
        var ee_buf: [512]u8 = undefined;
        const ee_secret = buildEeSecret(secret, tls_domain, &ee_buf);

        var link_buf: [512]u8 = undefined;
        const link = std.fmt.bufPrint(&link_buf, "tg://proxy?server={s}&port={d}&secret={s}", .{
            public_ip,
            port,
            ee_secret,
        }) catch "error building link";

        ui.print("  {s}│{s}  {s}{s}{s}\n", .{ tui_mod.Color.gray, tui_mod.Color.reset, tui_mod.Color.white, link, tui_mod.Color.reset });
    }

    ui.print("  {s}╰─{s}\n", .{ tui_mod.Color.gray, tui_mod.Color.reset });
}
