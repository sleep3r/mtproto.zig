//! Install command for mtproto-ctl.
//!
//! Ports install.sh (296 lines of bash) into structured Zig code.
//! Supports both interactive TUI mode and non-interactive CLI mode.

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
    secret: ?[32]u8 = null,
};

/// Run install in CLI (non-interactive) mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.ArgIterator) !void {
    var opts = InstallOpts{};

    // Parse CLI flags
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |val| {
                opts.port = std.fmt.parseInt(u16, val, 10) catch 443;
            }
        } else if (std.mem.eql(u8, arg, "--domain")) {
            if (args.next()) |val| opts.tls_domain = val;
        } else if (std.mem.eql(u8, arg, "--max-connections")) {
            if (args.next()) |val| {
                opts.max_connections = std.fmt.parseInt(u32, val, 10) catch 512;
            }
        } else if (std.mem.eql(u8, arg, "--no-masking")) {
            opts.enable_masking = false;
        } else if (std.mem.eql(u8, arg, "--no-nfqws")) {
            opts.enable_nfqws = false;
        } else if (std.mem.eql(u8, arg, "--no-tcpmss")) {
            opts.enable_tcpmss = false;
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

    // Secret — auto-generated, just show it
    var secret_hex: [32]u8 = undefined;
    sys.generateSecret(&secret_hex);
    ui.print("\n  {s}🔐{s} {s}: {s}{s}{s}\n", .{
        Color.bright_yellow,
        Color.reset,
        ui.str(.install_secret_generated),
        Color.ok,
        &secret_hex,
        Color.reset,
    });

    // DPI modules — checkbox selection
    const dpi_result = try ui.checkboxes(
        ui.str(.install_dpi_header),
        &.{
            ui.str(.install_dpi_tcpmss),
            ui.str(.install_dpi_masking),
            ui.str(.install_dpi_nfqws),
            ui.str(.install_dpi_ipv6),
        },
        &.{
            ui.str(.install_dpi_tcpmss_help),
            ui.str(.install_dpi_masking_help),
            ui.str(.install_dpi_nfqws_help),
            ui.str(.install_dpi_ipv6_help),
        },
        &.{ true, true, true, false },
    );

    opts.enable_tcpmss = (dpi_result & 1) != 0;
    opts.enable_masking = (dpi_result & 2) != 0;
    opts.enable_nfqws = (dpi_result & 4) != 0;
    opts.enable_ipv6_hop = (dpi_result & 8) != 0;
    opts.secret = secret_hex;

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

    // ── Install dependencies ──
    ui.step(ui.str(.install_checking_deps));
    _ = sys.execForward(&.{
        "apt-get", "update", "-qq",
    }) catch {};
    _ = sys.execForward(&.{
        "apt-get", "install", "-y",
        "iptables", "xxd", "git", "curl", "openssl", "tar", "xz-utils",
    }) catch {};
    ui.ok(ui.str(.install_checking_deps));

    // ── Install Zig ──
    const has_zig = blk: {
        const result = sys.exec(allocator, &.{ "zig", "version" }) catch break :blk false;
        defer result.deinit();
        const trimmed = std.mem.trim(u8, result.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
        break :blk std.mem.startsWith(u8, trimmed, ZIG_VERSION);
    };

    if (has_zig) {
        ui.stepOk(ui.str(.install_zig_ok), ZIG_VERSION);
    } else {
        ui.step(ui.str(.install_installing_zig));

        const arch = sys.getArch() catch {
            ui.fail(ui.str(.error_arch_unsupported));
            return;
        };

        var zig_cmd_buf: [512]u8 = undefined;
        const zig_cmd = std.fmt.bufPrint(&zig_cmd_buf,
            \\cd /tmp && curl -sSfL -o zig.tar.xz https://ziglang.org/download/{[a]s}/zig-linux-{[b]s}-{[c]s}.tar.xz && tar xf zig.tar.xz && rm -rf /usr/local/zig && mv zig-linux-{[b]s}-{[c]s} /usr/local/zig && ln -sf /usr/local/zig/zig /usr/local/bin/zig && rm -f zig.tar.xz
        , .{ .a = ZIG_VERSION, .b = arch.toStr(), .c = ZIG_VERSION }) catch return;

        const dl_result = sys.execForward(&.{ "bash", "-c", zig_cmd }) catch {
            ui.fail(ui.str(.install_installing_zig));
            return;
        };

        if (dl_result != 0) {
            ui.fail(ui.str(.install_installing_zig));
            return;
        }
        ui.stepOk(ui.str(.install_zig_ok), ZIG_VERSION);
    }

    // ── Clone & build ──
    ui.step(ui.str(.install_building));
    var cmd_buf: [1024]u8 = undefined;
    const build_cmd = std.fmt.bufPrint(&cmd_buf, "TMPDIR=$(mktemp -d) && git clone --depth 1 {s} $TMPDIR && cd $TMPDIR && zig build -Doptimize=ReleaseFast && mkdir -p {s} && cp zig-out/bin/mtproto-proxy {s}/mtproto-proxy && chmod +x {s}/mtproto-proxy && cp $TMPDIR/deploy/*.sh {s}/ 2>/dev/null || true && cp $TMPDIR/deploy/mtproto-proxy.service /etc/systemd/system/ && chmod +x {s}/*.sh 2>/dev/null || true && rm -rf $TMPDIR", .{
        REPO_URL, INSTALL_DIR, INSTALL_DIR, INSTALL_DIR, INSTALL_DIR, INSTALL_DIR,
    }) catch return;

    const build_result = sys.execForward(&.{ "bash", "-c", build_cmd }) catch {
        ui.fail(ui.str(.install_building));
        return;
    };
    if (build_result != 0) {
        ui.fail(ui.str(.install_building));
        return;
    }
    ui.ok(ui.str(.install_binary_ok));

    // ── Generate config ──
    const config_path_buf = INSTALL_DIR ++ "/config.toml";
    if (!sys.fileExists(config_path_buf)) {
        var secret_hex: [32]u8 = undefined;
        if (opts.secret) |s| {
            secret_hex = s;
        } else {
            sys.generateSecret(&secret_hex);
        }

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
        try doc.addKv("fast_mode", "true");

        try doc.addSection("access.users");
        try doc.addKvStr("user", &secret_hex);

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
        _ = sys.execForward(&.{
            "useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "mtproto",
        }) catch {};
        ui.ok(ui.str(.install_user_created));
    }

    // Fix ownership
    _ = sys.execForward(&.{ "chown", "-R", "mtproto:mtproto", INSTALL_DIR }) catch {};

    // ── Systemd service ──
    _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};
    _ = sys.execForward(&.{ "systemctl", "enable", SERVICE_NAME }) catch {};
    _ = sys.execForward(&.{ "systemctl", "restart", SERVICE_NAME }) catch {};
    ui.ok(ui.str(.install_service_installed));

    // ── Firewall ──
    if (sys.commandExists("ufw")) {
        var port_str_buf: [8]u8 = undefined;
        const port_rule = std.fmt.bufPrint(&port_str_buf, "{d}/tcp", .{opts.port}) catch "443/tcp";
        _ = sys.execForward(&.{ "ufw", "allow", port_rule }) catch {};
        ui.ok(ui.str(.install_firewall_ok));
    }

    // ── TCPMSS clamping ──
    if (opts.enable_tcpmss) {
        var port_str_buf: [8]u8 = undefined;
        const port_str = std.fmt.bufPrint(&port_str_buf, "{d}", .{opts.port}) catch "443";

        // IPv4
        _ = sys.exec(allocator, &.{
            "iptables", "-t", "mangle", "-A", "OUTPUT",
            "-p", "tcp", "--sport", port_str,
            "--tcp-flags", "SYN,ACK", "SYN,ACK",
            "-j", "TCPMSS", "--set-mss", "88",
        }) catch {};

        // IPv6
        _ = sys.exec(allocator, &.{
            "ip6tables", "-t", "mangle", "-A", "OUTPUT",
            "-p", "tcp", "--sport", port_str,
            "--tcp-flags", "SYN,ACK", "SYN,ACK",
            "-j", "TCPMSS", "--set-mss", "88",
        }) catch {};

        // Persist rules
        _ = sys.exec(allocator, &.{ "bash", "-c", "mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4 && ip6tables-save > /etc/iptables/rules.v6" }) catch {};

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
    _ = sys.execForward(&.{ "chown", "-R", "mtproto:mtproto", INSTALL_DIR }) catch {};
    _ = sys.execForward(&.{ "systemctl", "restart", SERVICE_NAME }) catch {};

    // ── Print summary ──
    ui.step("Detecting public IP...");
    const public_ip = sys.detectPublicIp(allocator) orelse "<SERVER_IP>";

    // Build ee-secret
    var secret_from_cfg: []const u8 = "unknown";
    {
        var cfg_doc = toml.TomlDoc.load(allocator, config_path_buf) catch {
            secret_from_cfg = "unknown";
            printSummary(ui, public_ip, opts.port, secret_from_cfg, opts);
            return;
        };
        defer cfg_doc.deinit();
        secret_from_cfg = cfg_doc.get("access.users", "user") orelse "unknown";
    }

    printSummary(ui, public_ip, opts.port, secret_from_cfg, opts);
}

fn printSummary(ui: *Tui, public_ip: []const u8, port: u16, secret: []const u8, opts: InstallOpts) void {
    // Build ee-secret string
    var ee_buf: [512]u8 = undefined;
    var ee_pos: usize = 0;

    // "ee" prefix
    @memcpy(ee_buf[0..2], "ee");
    ee_pos = 2;

    // Secret hex (strip quotes if present)
    var clean_secret = secret;
    if (clean_secret.len >= 2 and clean_secret[0] == '"') {
        clean_secret = clean_secret[1 .. clean_secret.len - 1];
    }
    const sec_len = @min(clean_secret.len, ee_buf.len - ee_pos);
    @memcpy(ee_buf[ee_pos..][0..sec_len], clean_secret[0..sec_len]);
    ee_pos += sec_len;

    // Domain hex
    var domain_hex_buf: [512]u8 = undefined;
    const domain_hex = sys.domainToHex(opts.tls_domain, &domain_hex_buf);
    const dh_len = @min(domain_hex.len, ee_buf.len - ee_pos);
    @memcpy(ee_buf[ee_pos..][0..dh_len], domain_hex[0..dh_len]);
    ee_pos += dh_len;

    const ee_secret = ee_buf[0..ee_pos];

    // Print link
    var link_buf: [512]u8 = undefined;
    const link = std.fmt.bufPrint(&link_buf, "tg://proxy?server={s}&port={d}&secret={s}", .{
        public_ip, port, ee_secret,
    }) catch "error building link";

    ui.summaryBox(ui.str(.install_success_header), &.{
        .{ .label = ui.str(.install_status_cmd), .value = "systemctl status mtproto-proxy" },
        .{ .label = ui.str(.install_logs_cmd), .value = "journalctl -u mtproto-proxy -f" },
        .{ .label = ui.str(.install_config_path), .value = INSTALL_DIR ++ "/config.toml" },
        .{ .label = "", .style = .blank },
        .{ .label = ui.str(.install_connection_link), .style = .highlight, .value = link },
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
    });
}
