//! Install command for mtbuddy.
//!
//! Supports both interactive TUI mode and non-interactive CLI mode.
//! Downloads pre-built release artifacts from GitHub (same path as update).
//!
//! One-liner usage:
//!   sudo mtbuddy install --port 443 --domain rutube.ru --yes
//!   sudo mtbuddy install --port 443 --domain rutube.ru --secret <hex> --user myuser --yes

const std = @import("std");
const builtin = @import("builtin");
const tui_mod = @import("tui.zig");
const i18n = @import("i18n.zig");
const sys = @import("sys.zig");
const release = @import("release.zig");
const toml = @import("toml.zig");
const masking = @import("masking.zig");
const nfqws = @import("nfqws.zig");
const fronting_domain = @import("fronting_domain.zig");

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;
const SummaryLine = tui_mod.SummaryLine;

const INSTALL_DIR = release.INSTALL_DIR;
const SERVICE_NAME = release.SERVICE_NAME;

pub const InstallOpts = struct {
    port: u16 = 443,
    /// Public port to place into generated Telegram client links.
    public_port: ?u16 = null,
    /// Bind to a specific IP address instead of all interfaces.
    bind_address: ?[]const u8 = null,
    tls_domain: []const u8 = "rutube.ru",
    max_connections: u32 = 512,
    enable_tcpmss: bool = true,
    /// TCPMSS --set-mss value on the SYN,ACK: forces the client's ClientHello to be
    /// fragmented across TCP segments so the signatured extensions don't sit in one
    /// packet for a stateless JA4 extractor. Default 88 (the long-deployed value);
    /// configurable because 88 is itself anomalous vs the real ~1380 distribution —
    /// retune empirically (segment boundary before ALPN/sig_algs) per host/ISP.
    tcpmss_value: u16 = 88,
    enable_masking: bool = true,
    enable_nfqws: bool = true,
    enable_ipv6_hop: bool = false,
    enable_desync: bool = true,
    enable_drs: bool = false,
    /// Enable MiddleProxy (Telegram relay). Required for promo tags and
    /// non-Premium media loading.
    enable_middle_proxy: bool = false,
    /// Pre-set user secret (32-char hex). If null, auto-generated.
    secret: ?[32]u8 = null,
    /// User name for config.toml. If null, defaults to "user".
    user: ?[]const u8 = null,
    /// Skip confirmation prompt (non-interactive / one-liner mode).
    yes: bool = false,
    /// Release version to install (e.g. "v0.12.0"). If null, uses latest.
    version: ?[]const u8 = null,
    /// Allow unsigned release assets (disables minisign verification).
    insecure: bool = false,
    /// Path to an existing config.toml to use.
    config_path: ?[]const u8 = null,
    /// Internal flags to track if user explicitly provided a value.
    port_provided: bool = false,
    public_port_provided: bool = false,
    domain_provided: bool = false,
};

fn isInstallHelpFlag(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h");
}

fn shouldWarnIgnoredSecret(config_exists: bool, secret_provided: bool, config_path_provided: bool) bool {
    return config_exists and secret_provided and !config_path_provided;
}

fn shouldInstallMinisignPackage(signature_available: bool, insecure_mode: bool, minisign_on_path: bool) bool {
    return signature_available and !insecure_mode and !minisign_on_path;
}

// Pinned upstream minisign for hosts whose package manager has no minisign
// (e.g. Ubuntu 20.04 focal). Kept in sync with deploy/bootstrap.sh.
const minisign_bootstrap_version = "0.12";
const minisign_bootstrap_sha256 = "9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73";

/// Install the pinned upstream minisign binary when apt has no minisign package.
/// Mirrors deploy/bootstrap.sh: a SHA-256-verified tarball from the pinned
/// jedisct1/minisign release, extracted for this CPU arch. Silent (runs under the
/// deps spinner); returns true iff minisign is now resolvable on PATH.
fn installMinisignFromUpstream(allocator: std.mem.Allocator) bool {
    const arch_name: []const u8 = switch (builtin.cpu.arch) {
        .x86_64 => "x86_64",
        .aarch64 => "aarch64",
        else => return false,
    };
    // Do the whole download → verify → extract → install inside a private, owner-only
    // (0700, root) `mktemp -d` directory — like deploy/bootstrap.sh. Fixed /tmp paths
    // would let a local user pre-create or race-swap the archive/extracted binary
    // between the SHA check and `install`, substituting an attacker-controlled minisign
    // (the release-signature trust anchor). A 0700 root dir no other user can write to
    // closes both the symlink-clobber and the verify-vs-use TOCTOU.
    const tmpdir = blk: {
        const r = sys.exec(allocator, &.{ "mktemp", "-d", "/tmp/mtbuddy-minisign.XXXXXX" }) catch return false;
        defer r.deinit();
        if (r.exit_code != 0) break :blk null;
        const t = std.mem.trim(u8, r.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
        if (t.len == 0) break :blk null;
        break :blk allocator.dupe(u8, t) catch null;
    } orelse return false;
    defer {
        _ = sys.exec(allocator, &.{ "rm", "-rf", tmpdir }) catch {};
        allocator.free(tmpdir);
    }

    const archive = std.fmt.allocPrint(allocator, "{s}/minisign.tar.gz", .{tmpdir}) catch return false;
    defer allocator.free(archive);
    const url = "https://github.com/jedisct1/minisign/releases/download/" ++
        minisign_bootstrap_version ++ "/minisign-" ++ minisign_bootstrap_version ++ "-linux.tar.gz";

    {
        const r = sys.exec(allocator, &.{ "curl", "-fsSL", "--retry", "3", "--connect-timeout", "30", "-o", archive, url }) catch return false;
        defer r.deinit();
        if (r.exit_code != 0) return false;
    }
    // Verify SHA-256 before trusting the binary — minisign can't verify itself.
    {
        const r = sys.exec(allocator, &.{ "sha256sum", archive }) catch return false;
        defer r.deinit();
        if (r.exit_code != 0) return false;
        const trimmed = std.mem.trim(u8, r.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
        const end = std.mem.indexOfScalar(u8, trimmed, ' ') orelse trimmed.len;
        if (!std.mem.eql(u8, trimmed[0..end], minisign_bootstrap_sha256)) return false;
    }
    const member = std.fmt.allocPrint(allocator, "minisign-linux/{s}/minisign", .{arch_name}) catch return false;
    defer allocator.free(member);
    {
        const r = sys.exec(allocator, &.{ "tar", "xzf", archive, "-C", tmpdir, "--no-same-owner", member }) catch return false;
        defer r.deinit();
        if (r.exit_code != 0) return false;
    }
    const extracted = std.fmt.allocPrint(allocator, "{s}/minisign-linux/{s}/minisign", .{ tmpdir, arch_name }) catch return false;
    defer allocator.free(extracted);
    {
        const r = sys.exec(allocator, &.{ "install", "-m", "0755", extracted, "/usr/local/bin/minisign" }) catch return false;
        defer r.deinit();
        if (r.exit_code != 0) return false;
    }
    return sys.commandExists("minisign");
}

pub fn printInstallHelp(ui: *Tui) void {
    ui.writeRaw("\n");
    ui.writeRaw("  mtbuddy install [options]\n\n");
    ui.writeRaw("  Options:\n");
    ui.writeRaw("    --port, -p <port>          Listen port (default: 443)\n");
    ui.writeRaw("    --public-port <port>       Port shown in client links\n");
    ui.writeRaw("    --domain, -d <domain>      FakeTLS masking domain (default: rutube.ru)\n");
    ui.writeRaw("    --secret, -s <32-hex>      Initial user secret for a new config\n");
    ui.writeRaw("    --user, -u <name>          Initial user name for a new config\n");
    ui.writeRaw("    --config, -c <path>        Install using an existing config.toml\n");
    ui.writeRaw("    --max-connections <N>      Max concurrent client connections (default: 512)\n");
    ui.writeRaw("    --middle-proxy             Enable Telegram MiddleProxy relay\n");
    ui.writeRaw("    --no-dpi                   Disable masking, nfqws, and TCPMSS setup\n");
    ui.writeRaw("    --no-masking               Disable local masking setup\n");
    ui.writeRaw("    --no-nfqws                 Disable nfqws setup\n");
    ui.writeRaw("    --no-tcpmss                Disable TCPMSS setup\n");
    ui.writeRaw("    --tcpmss <n>               TCPMSS clamp value (default 88; forces ClientHello fragmentation)\n");
    ui.writeRaw("    --bind, -b <ip>            Bind proxy to a specific local address\n");
    ui.writeRaw("    --ipv6-hop                 Reminder to configure IPv6 auto-hopping (needs Cloudflare API; run `mtbuddy ipv6-hop`)\n");
    ui.writeRaw("    --version, -v <tag>        Install a specific release tag\n");
    ui.writeRaw("    --insecure                 Disable release signature verification\n");
    ui.writeRaw("    --yes, -y                  Run non-interactively\n");
    ui.writeRaw("    --help, -h                 Show this help\n\n");
    ui.writeRaw("  Note: --secret and --user only seed a new config. Existing configs are preserved.\n\n");
}

test "install - help flags are recognized before installation work" {
    try std.testing.expect(isInstallHelpFlag("--help"));
    try std.testing.expect(isInstallHelpFlag("-h"));
    try std.testing.expect(!isInstallHelpFlag("--yes"));
}

test "install - explicit secret warning only applies when existing config keeps old users" {
    try std.testing.expect(shouldWarnIgnoredSecret(true, true, false));
    try std.testing.expect(!shouldWarnIgnoredSecret(false, true, false));
    try std.testing.expect(!shouldWarnIgnoredSecret(true, false, false));
    try std.testing.expect(!shouldWarnIgnoredSecret(true, true, true));
}

test "install - skips apt minisign package when verifier is already on PATH" {
    try std.testing.expect(!shouldInstallMinisignPackage(true, false, true));
    try std.testing.expect(shouldInstallMinisignPackage(true, false, false));
    try std.testing.expect(!shouldInstallMinisignPackage(true, true, false));
    try std.testing.expect(!shouldInstallMinisignPackage(false, false, false));
}

/// Run install in CLI (non-interactive) mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    var opts = InstallOpts{};

    // Parse CLI flags
    while (args.next()) |arg| {
        if (isInstallHelpFlag(arg)) {
            printInstallHelp(ui);
            return;
        } else if (std.mem.eql(u8, arg, "--port") or std.mem.eql(u8, arg, "-p")) {
            if (args.next()) |val| {
                opts.port = std.fmt.parseInt(u16, val, 10) catch 443;
                opts.port_provided = true;
            }
        } else if (std.mem.eql(u8, arg, "--public-port")) {
            if (args.next()) |val| {
                const parsed = std.fmt.parseInt(u16, val, 10) catch 0;
                if (parsed > 0) {
                    opts.public_port = parsed;
                    opts.public_port_provided = true;
                } else {
                    ui.warn("--public-port must be a valid TCP port, ignoring");
                }
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
                if (isValidSecretHex(val)) {
                    var sec: [32]u8 = undefined;
                    @memcpy(&sec, val[0..32]);
                    opts.secret = sec;
                } else {
                    // Validate hex, not just length: a 32-char non-hex secret
                    // would be written verbatim and then fail to parse at proxy
                    // startup with a confusing error.
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
        } else if (std.mem.eql(u8, arg, "--tcpmss")) {
            if (args.next()) |val| {
                if (std.fmt.parseInt(u16, val, 10)) |n| {
                    if (n >= 40) opts.tcpmss_value = n else ui.warn("--tcpmss must be >= 40, keeping default 88");
                } else |_| {
                    ui.warn("--tcpmss must be a number, keeping default 88");
                }
            }
        } else if (std.mem.eql(u8, arg, "--no-dpi")) {
            // Disable all DPI bypass modules at once
            opts.enable_masking = false;
            opts.enable_nfqws = false;
            opts.enable_tcpmss = false;
        } else if (std.mem.eql(u8, arg, "--ipv6-hop")) {
            opts.enable_ipv6_hop = true;
        } else if (std.mem.eql(u8, arg, "--bind") or std.mem.eql(u8, arg, "-b")) {
            if (args.next()) |val| opts.bind_address = val;
        } else if (std.mem.eql(u8, arg, "--middle-proxy")) {
            opts.enable_middle_proxy = true;
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            opts.version = args.next();
        } else if (std.mem.eql(u8, arg, "--insecure")) {
            opts.insecure = true;
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
        if (!opts.public_port_provided) {
            if (doc.get("server", "public_port")) |p_str| {
                const parsed = std.fmt.parseInt(u16, p_str, 10) catch 0;
                if (parsed > 0) opts.public_port = parsed;
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
        if (opts.public_port) |public_port| {
            ui.print("  {s}Public:{s}   {d}\n", .{ Color.dim, Color.reset, public_port });
        }
        ui.print("  {s}Domain:{s}   {s}\n", .{ Color.dim, Color.reset, opts.tls_domain });
        ui.print("  {s}TCPMSS:{s}   {s}\n", .{ Color.dim, Color.reset, if (opts.enable_tcpmss) "enabled" else "disabled" });
        ui.print("  {s}Masking:{s}  {s}\n", .{ Color.dim, Color.reset, if (opts.enable_masking) "enabled" else "disabled" });
        ui.print("  {s}nfqws:{s}    {s}\n", .{ Color.dim, Color.reset, if (opts.enable_nfqws) "enabled" else "disabled" });
        ui.print("  {s}Middle:{s}   {s}\n", .{ Color.dim, Color.reset, if (opts.enable_middle_proxy) "enabled" else "disabled" });
        ui.writeRaw("\n");

        if (!try ui.confirm(localized(ui, "Proceed with installation?", "Начать установку?"), true)) {
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
        "rutube.ru",
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
            sys.generateSecret(&secret_hex) catch {
                ui.fail(ui.str(.install_secret_gen_failed));
                return;
            };
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
        } else if (isValidSecretHex(sec_str)) {
            @memcpy(&secret_hex, sec_str[0..32]);
            break;
        } else {
            ui.print("  {s}✗ {s}{s}\n", .{ Color.err, localized(ui, "Secret must be exactly 32 hex characters, or 'auto'", "Секрет должен быть ровно 32 hex-символа или 'auto'"), Color.reset });
        }
    }

    // Protection against blocking. Most people should just accept the recommended
    // defaults — so ask one friendly yes/no, and only reveal the six expert
    // checkboxes to those who deliberately choose "Advanced".
    const use_recommended = try ui.confirm(
        localized(ui, "Turn on recommended protection against blocking? (recommended)", "Включить рекомендуемую защиту от блокировок? (рекомендуется)"),
        true,
    );
    if (use_recommended) {
        // The shields that hide the proxy from blocking systems, on by default.
        opts.enable_tcpmss = true;
        opts.enable_masking = true;
        opts.enable_nfqws = true;
        opts.enable_desync = true;
        opts.enable_drs = false;
        opts.enable_ipv6_hop = false;
    } else {
        // Advanced: the granular six-checkbox view for people who want it.
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
    }
    opts.secret = secret_hex;

    // MiddleProxy toggle
    ui.writeRaw("\n");
    ui.print("  {s}╭─ {s}{s}{s}\n", .{ Color.gray, Color.bold, ui.str(.install_middle_proxy_prompt), Color.reset });
    // Print multi-line help with border
    {
        var help_lines = std.mem.splitScalar(u8, ui.str(.install_middle_proxy_help), '\n');
        while (help_lines.next()) |line| {
            ui.print("  {s}│{s}  {s}{s}{s}\n", .{
                Color.gray,  Color.reset,
                Color.dim,   line,
                Color.reset,
            });
        }
    }
    ui.print("  {s}╰─{s}\n", .{ Color.gray, Color.reset });
    opts.enable_middle_proxy = try ui.confirm(ui.str(.install_middle_proxy_prompt), false);

    if (!opts.enable_middle_proxy) {
        ui.warn(ui.str(.install_middle_proxy_warn));
    }

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

    // Warn NOW (before the link — which embeds tls_domain — is generated and frozen)
    // if the fronting domain is a poor FakeTLS mimicry target.
    _ = fronting_domain.warnIfPoorFrontingDomain(ui, allocator, opts.tls_domain);

    // ── Check port / masking collision ──
    // The masking Nginx binds to 127.0.0.1:8443. If the proxy listens on
    // the same port, its 0.0.0.0 bind will collide with Nginx and the
    // service won't start.
    const masking_port: u16 = std.fmt.parseInt(u16, masking.NGINX_PORT, 10) catch 8443;
    if (opts.enable_masking and opts.port == masking_port) {
        ui.fail("Port conflict: proxy port and masking port are both " ++ masking.NGINX_PORT ++ ".");
        ui.info("Choose a different proxy port (e.g. 443) or disable masking (--no-masking).");
        return;
    }

    const insecure_mode = opts.insecure or sys.envFlagSet("MTPROTO_INSECURE");
    const signature_available = release.signatureVerificationAvailable();
    if (!signature_available and !insecure_mode) {
        ui.fail("This mtbuddy build has no embedded minisign public key.");
        ui.info("Rebuild with -Dminisign_pubkey=<RW...> or use --insecure (or MTPROTO_INSECURE=1).");
        return;
    }
    if (insecure_mode) {
        ui.warn("INSECURE mode enabled: release signature verification is disabled.");
    }

    ui.writeRaw("\n");
    ui.rule();

    // ── Install dependencies ──
    {
        var sp = ui.spinner(ui.str(.install_checking_deps));
        sp.start();
        if (!sys.commandExists("apt-get")) {
            sp.stop(false, "");
            ui.fail("apt-get is required to install system dependencies");
            return;
        }
        if (!runRequiredWhileSpinning(ui, allocator, &.{ "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", "DPkg::Lock::Timeout=600", "update", "-qq" }, "apt-get update failed", &sp)) return;
        // minisign is acquired separately (below), not in this required base install:
        // not every supported release ships it in apt (e.g. Ubuntu 20.04 focal), and
        // bundling it here would abort the whole install on those hosts.
        const base_packages: []const []const u8 = &.{
            "env",                     "DEBIAN_FRONTEND=noninteractive",
            "apt-get",                 "-o",
            "DPkg::Lock::Timeout=600", "install",
            "-y",                      "--no-install-recommends",
            "iptables",                "xxd",
            "curl",                    "openssl",
            "tar",                     "passwd",
        };
        if (!runRequiredWhileSpinning(ui, allocator, base_packages, "Failed to install system dependencies", &sp)) return;
        // qrencode powers the optional terminal/dashboard QR; the feature degrades
        // gracefully without it (printQrCode no-ops), so install it best-effort and
        // never fail the whole install if it's unavailable.
        _ = sys.exec(allocator, &.{ "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", "DPkg::Lock::Timeout=600", "install", "-y", "--no-install-recommends", "qrencode" }) catch {};
        // Acquire minisign for release-signature verification: prefer the apt package,
        // fall back to the pinned, SHA-256-verified upstream binary when apt has none
        // (Ubuntu 20.04 focal) — matching the bootstrap, so a bare `mtbuddy install`
        // works there too.
        var minisign_fallback_failed = false;
        if (shouldInstallMinisignPackage(signature_available, insecure_mode, sys.commandExists("minisign"))) {
            _ = sys.exec(allocator, &.{ "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", "DPkg::Lock::Timeout=600", "install", "-y", "--no-install-recommends", "minisign" }) catch {};
            if (!sys.commandExists("minisign")) {
                minisign_fallback_failed = !installMinisignFromUpstream(allocator);
            }
        }
        if (signature_available and !insecure_mode and !sys.commandExists("minisign")) {
            sp.stop(false, "");
            ui.fail("minisign is required for release signature verification");
            if (minisign_fallback_failed) ui.info("apt has no minisign on this host and the pinned upstream fallback failed (check network / checksum), or re-run with --insecure.");
            return;
        }
        if (!requiredAccountToolsAvailable(ui)) {
            sp.stop(false, "");
            return;
        }
        sp.stop(true, "");
    }

    // ── Resolve release tag ──
    var tag = release.Tag{};
    {
        var sp = ui.spinner(ui.str(.install_resolving_tag));
        sp.start();
        if (!release.resolveTag(allocator, opts.version, &tag)) {
            sp.stop(false, "");
            ui.fail(ui.str(.error_no_release));
            return;
        }
        sp.stop(true, tag.slice());
    }

    // ── Download + validate proxy binary ──
    var artifact = release.Artifact{};
    defer release.cleanup(allocator, &artifact);
    {
        var sp = ui.spinner(ui.str(.install_downloading));
        sp.start();
        if (!release.downloadProxyArtifact(allocator, tag.slice(), "install", !insecure_mode, &artifact)) {
            sp.stop(false, "");
            ui.fail(ui.str(.error_download_failed));
            return;
        }
        sp.stop(true, artifact.asset_name);
    }

    // ── Install binary + service file ──
    {
        _ = sys.exec(allocator, &.{ "mkdir", "-p", INSTALL_DIR }) catch {};
        _ = sys.execForward(&.{
            "install",             "-m",                            "0755",
            artifact.binaryPath(), INSTALL_DIR ++ "/mtproto-proxy",
        }) catch {};
        release.writeServiceFile();
    }
    ui.ok(ui.str(.install_binary_ok));

    // ── Copy user config (if provided) ──
    if (opts.config_path) |cfg_path| {
        const cp = sys.exec(allocator, &.{ "cp", cfg_path, INSTALL_DIR ++ "/config.toml" }) catch {
            ui.fail("Failed to copy --config file into the install dir");
            return;
        };
        defer cp.deinit();
        if (cp.exit_code != 0) {
            // Do NOT fall through to generating a fresh config with a different
            // secret — that would silently discard the operator's intended users.
            ui.fail("Failed to copy --config file into the install dir");
            return;
        }
        // The supplied config holds secrets; restrict it (cp preserves source mode).
        _ = sys.exec(allocator, &.{ "chmod", "0640", INSTALL_DIR ++ "/config.toml" }) catch {};
    }

    // ── Generate config ──
    const config_path_buf = INSTALL_DIR ++ "/config.toml";
    if (!sys.fileExists(config_path_buf)) {
        var secret_hex: [32]u8 = undefined;
        if (opts.secret) |s| {
            secret_hex = s;
        } else {
            sys.generateSecret(&secret_hex) catch {
                ui.fail(ui.str(.install_secret_gen_failed));
                return;
            };
        }

        const user_name = opts.user orelse "user";

        var doc = toml.TomlDoc.initEmpty(allocator);
        defer doc.deinit();

        try doc.addSection("server");
        var port_val_buf: [8]u8 = undefined;
        const port_val = std.fmt.bufPrint(&port_val_buf, "{d}", .{opts.port}) catch "443";
        try doc.addKv("port", port_val);
        if (opts.public_port) |public_port| {
            var public_port_val_buf: [8]u8 = undefined;
            const public_port_val = std.fmt.bufPrint(&public_port_val_buf, "{d}", .{public_port}) catch "443";
            try doc.addKv("public_port", public_port_val);
        }
        if (opts.bind_address) |ba| {
            try doc.addKvStr("bind_address", ba);
        }
        var max_conn_buf: [16]u8 = undefined;
        const max_conn_val = std.fmt.bufPrint(&max_conn_buf, "{d}", .{opts.max_connections}) catch "512";
        try doc.addKv("max_connections", max_conn_val);
        try doc.addKv("idle_timeout_sec", "120");
        try doc.addKv("handshake_timeout_sec", "15");
        try doc.addKv("handshake_flood_guard_enabled", "false");
        try doc.addKv("handshake_flood_guard_threshold", "20");
        try doc.addKv("handshake_flood_guard_window_sec", "30");
        try doc.addKv("handshake_flood_guard_block_sec", "120");

        try doc.addSection("upstream");
        try doc.addKvStr("type", "direct");

        try doc.addSection("censorship");
        try doc.addKvStr("tls_domain", opts.tls_domain);
        try doc.addKv("mask", "true");
        try doc.addKv("desync", if (opts.enable_desync) "true" else "false");
        try doc.addKv("drs", if (opts.enable_drs) "true" else "false");
        try doc.addKv("fast_mode", "true");

        try doc.addSection("general");
        try doc.addKv("use_middle_proxy", if (opts.enable_middle_proxy) "true" else "false");

        try doc.addSection("access.users");
        try doc.addKvStr(user_name, &secret_hex);

        try doc.save(config_path_buf);
        ui.ok(ui.str(.install_config_generated));
    } else {
        ui.ok(ui.str(.install_config_exists));
        if (shouldWarnIgnoredSecret(true, opts.secret != null, opts.config_path != null)) {
            ui.warn(ui.str(.install_warn_secret_ignored));
        }
        if (opts.user != null and opts.config_path == null) {
            ui.warn(ui.str(.install_warn_user_ignored));
        }
    }

    // ── Create system user/group ──
    if (!ensureServiceUser(ui, allocator)) return;
    if (!runRequired(ui, allocator, &.{ "chown", "-R", "mtproto:mtproto", INSTALL_DIR }, "Failed to chown install directory")) return;

    // ── Systemd service ──
    {
        var sp = ui.spinner(ui.str(.install_service_installed));
        sp.start();
        if (!runRequiredWhileSpinning(ui, allocator, &.{ "systemctl", "daemon-reload" }, "systemctl daemon-reload failed", &sp)) return;
        if (!runRequiredWhileSpinning(ui, allocator, &.{ "systemctl", "enable", SERVICE_NAME }, "Failed to enable mtproto-proxy service", &sp)) return;
        if (!runRequiredWhileSpinning(ui, allocator, &.{ "systemctl", "restart", SERVICE_NAME }, "Failed to start mtproto-proxy service", &sp)) return;
        if (!sys.isServiceActive(SERVICE_NAME)) {
            sp.stop(false, "");
            ui.fail("mtproto-proxy service is not active after restart");
            printServiceStatus(ui, allocator);
            return;
        }
        sp.stop(true, "");
    }

    // The proxy is already live and usable here — show the link NOW, before the
    // optional (and slow, from-source) masking + zapret steps, so the "aha" moment
    // lands in seconds instead of after a multi-minute compile. The final summary
    // below reprints it together with the protection status.
    var resolved_server_buf: [256]u8 = undefined;
    const resolved_server = resolvePublicServer(ui, allocator, config_path_buf, &resolved_server_buf);
    {
        ui.writeRaw("\n");
        ui.ok(localized(ui, "Your proxy is LIVE — here's your link:", "Прокси ЗАПУЩЕН — вот ваша ссылка:"));
        ui.print("  {s}╭─{s}\n", .{ tui_mod.Color.gray, tui_mod.Color.reset });
        _ = printLinksFromConfig(ui, allocator, resolved_server, opts.public_port orelse opts.port, opts.tls_domain, config_path_buf, true);
        ui.print("  {s}╰─{s}\n", .{ tui_mod.Color.gray, tui_mod.Color.reset });
        if (opts.enable_masking or opts.enable_nfqws) {
            ui.info(localized(ui, "Now turning on extra anti-blocking protection — the link above already works...", "Теперь включаю дополнительную защиту от блокировок — ссылка выше уже работает..."));
        }
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
        var mss_str_buf: [8]u8 = undefined;
        const mss_str = std.fmt.bufPrint(&mss_str_buf, "{d}", .{opts.tcpmss_value}) catch "88";

        _ = sys.exec(allocator, &.{
            "iptables", "-t",      "mangle",  "-A",     "OUTPUT",
            "-p",       "tcp",     "--sport", port_str, "--tcp-flags",
            "SYN,ACK",  "SYN,ACK", "-j",      "TCPMSS", "--set-mss",
            mss_str,
        }) catch {};
        _ = sys.exec(allocator, &.{
            "ip6tables", "-t",      "mangle",  "-A",     "OUTPUT",
            "-p",        "tcp",     "--sport", port_str, "--tcp-flags",
            "SYN,ACK",   "SYN,ACK", "-j",      "TCPMSS", "--set-mss",
            mss_str,
        }) catch {};
        _ = sys.exec(allocator, &.{
            "bash",                                                                                                        "-c",
            "mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4 && ip6tables-save > /etc/iptables/rules.v6",
        }) catch {};

        ui.ok(ui.str(.install_tcpmss_ok));
    }

    // IPv6 auto-hopping cannot be configured here (it needs Cloudflare API
    // credentials). Surface a clear reminder instead of silently ignoring the
    // flag / wizard toggle, so the documented option is no longer a no-op.
    if (opts.enable_ipv6_hop) {
        ui.warn(ui.str(.install_warn_ipv6_hop_manual));
    }

    var summary_opts = opts;

    // ── Masking (via Zig module) ──
    if (opts.enable_masking) {
        masking.execute(ui, allocator, .{ .tls_domain = opts.tls_domain }) catch {
            ui.warn("Masking setup failed");
        };
        // Source of truth is the config (mask=true), not a local nginx site: the
        // secure real-domain-fronting path enables masking WITHOUT a local nginx,
        // and was previously mis-reported as "masking disabled".
        summary_opts.enable_masking = configMaskEnabled(allocator);
        if (!summary_opts.enable_masking) {
            ui.warn("Masking setup did not complete; final summary will show it disabled.");
        }
    }

    // ── nfqws (via Zig module) ──
    if (opts.enable_nfqws) {
        nfqws.execute(ui, allocator, .{}) catch {
            ui.warn("nfqws setup failed");
        };
        summary_opts.enable_nfqws = sys.fileExists("/opt/zapret/nfq/nfqws") and sys.isServiceActive("nfqws-mtproto");
        if (!summary_opts.enable_nfqws) {
            ui.warn("nfqws setup did not complete; final summary will show it disabled.");
        }
    }

    // ── Final restart ──
    if (!runRequired(ui, allocator, &.{ "chown", "-R", "mtproto:mtproto", INSTALL_DIR }, "Failed to chown install directory")) return;
    if (!runRequired(ui, allocator, &.{ "systemctl", "restart", SERVICE_NAME }, "Failed to restart mtproto-proxy after setup")) return;
    if (!sys.isServiceActive(SERVICE_NAME)) {
        ui.fail("mtproto-proxy service is not active after setup");
        printServiceStatus(ui, allocator);
        return;
    }

    ui.rule();

    // ── Print summary ──
    // The public server was already resolved once (resolved_server: configured
    // [server].public_ip preferred, else auto-detected) and reused here, so the
    // early link/QR and the summary agree and detection runs only once. The
    // SERVER_IP placeholder => printSummary warns the operator to replace it.
    const public_ip = resolved_server;

    // Read summary values from active config
    var summary_server: []const u8 = public_ip;
    var summary_server_buf: [256]u8 = undefined;
    var summary_port: u16 = opts.port;
    var summary_public_port: u16 = opts.public_port orelse opts.port;
    var summary_tls_domain: []const u8 = opts.tls_domain;
    var summary_tls_domain_buf: [256]u8 = undefined;
    var secret_from_cfg: []const u8 = "unknown";
    var secret_buf: [128]u8 = undefined;

    {
        var cfg_doc = toml.TomlDoc.load(allocator, config_path_buf) catch {
            printSummary(ui, allocator, public_ip, opts.port, opts.public_port orelse opts.port, secret_from_cfg, opts.tls_domain, summary_opts, config_path_buf);
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
            summary_public_port = summary_port;
        }

        if (cfg_doc.get("server", "public_port")) |configured_public_port| {
            const parsed = std.fmt.parseInt(u16, configured_public_port, 10) catch 0;
            if (parsed > 0) summary_public_port = parsed;
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
        summary_public_port,
        secret_from_cfg,
        summary_tls_domain,
        summary_opts,
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

fn buildDdSecret(secret: []const u8, dd_buf: []u8) []const u8 {
    var pos: usize = 0;
    @memcpy(dd_buf[pos..][0..2], "dd");
    pos += 2;

    var clean_secret = secret;
    if (clean_secret.len >= 2 and clean_secret[0] == '"' and clean_secret[clean_secret.len - 1] == '"') {
        clean_secret = clean_secret[1 .. clean_secret.len - 1];
    }

    const sec_len = @min(clean_secret.len, dd_buf.len - pos);
    @memcpy(dd_buf[pos..][0..sec_len], clean_secret[0..sec_len]);
    pos += sec_len;

    return dd_buf[0..pos];
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

fn encodeServerForProxyLink(server: []const u8, out: []u8) []const u8 {
    var required_len: usize = 0;
    for (server) |c| {
        required_len += if (c == ':' or c == '[' or c == ']') 3 else 1;
    }

    // Keep original value if it does not fit to avoid silent truncation.
    if (required_len > out.len) return server;

    var pos: usize = 0;
    for (server) |c| {
        if (c == ':') {
            @memcpy(out[pos..][0..3], "%3A");
            pos += 3;
        } else if (c == '[') {
            @memcpy(out[pos..][0..3], "%5B");
            pos += 3;
        } else if (c == ']') {
            @memcpy(out[pos..][0..3], "%5D");
            pos += 3;
        } else {
            out[pos] = c;
            pos += 1;
        }
    }
    return out[0..pos];
}

/// Render a scannable QR of `text` to the terminal via qrencode (UTF8 half-blocks).
/// Best-effort: a silent no-op when qrencode is unavailable. Lets the operator scan
/// the link straight from an SSH session onto a phone — or show it to a relative.
fn printQrCode(ui: *Tui, allocator: std.mem.Allocator, text: []const u8) void {
    if (!sys.commandExists("qrencode")) return;
    const r = sys.exec(allocator, &.{ "qrencode", "-t", "UTF8", "-m", "1", text }) catch return;
    defer r.deinit();
    if (r.stdout.len == 0) return;
    ui.writeRaw("\n");
    ui.hint(localized(ui, "Scan to connect a device:", "Отсканируйте, чтобы подключить устройство:"));
    ui.writeRaw(r.stdout);
}

fn printLinksFromConfig(
    ui: *Tui,
    allocator: std.mem.Allocator,
    public_ip: []const u8,
    port: u16,
    tls_domain: []const u8,
    config_path: []const u8,
    with_qr: bool,
) bool {
    var cfg_doc = toml.TomlDoc.load(allocator, config_path) catch return false;
    defer cfg_doc.deinit();
    var qr_done = false;

    // dd links only make sense when the operator enabled the dd transport
    // (fake_tls_only = false). With the secure default the proxy rejects dd, so
    // a dd link would be non-working and DPI-fingerprintable — don't print it.
    const dd_enabled = if (cfg_doc.get("censorship", "fake_tls_only")) |v|
        std.mem.eql(u8, std.mem.trim(u8, v, " \t\""), "false")
    else
        false;

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

        var encoded_ip_buf: [768]u8 = undefined;
        const safe_public_ip = encodeServerForProxyLink(public_ip, &encoded_ip_buf);

        var ee_link_buf: [512]u8 = undefined;
        const ee_link = std.fmt.bufPrint(&ee_link_buf, "tg://proxy?server={s}&port={d}&secret={s}", .{
            safe_public_ip,
            port,
            ee_secret,
        }) catch continue;
        // The t.me link is the one to SHARE — it renders a tappable "Connect proxy"
        // card in Telegram and opens from any browser/messenger; tg:// is the direct
        // app link.
        var tme_link_buf: [512]u8 = undefined;
        const tme_link = std.fmt.bufPrint(&tme_link_buf, "https://t.me/proxy?server={s}&port={d}&secret={s}", .{
            safe_public_ip,
            port,
            ee_secret,
        }) catch continue;

        ui.print("  {s}│{s}  {s}{s}{s}\n", .{
            tui_mod.Color.gray,  tui_mod.Color.reset,
            tui_mod.Color.white, user_name,
            tui_mod.Color.reset,
        });
        ui.print("  {s}│{s}    {s}{s}{s}\n", .{
            tui_mod.Color.gray,  tui_mod.Color.reset,
            tui_mod.Color.white, tme_link,
            tui_mod.Color.reset,
        });
        ui.print("  {s}│{s}    {s}{s}{s}\n", .{
            tui_mod.Color.gray,  tui_mod.Color.reset,
            tui_mod.Color.dim,   ee_link,
            tui_mod.Color.reset,
        });
        // A scannable QR of the share link for the first user — point a phone
        // camera at it to connect, no copy-paste. Best-effort (needs qrencode).
        if (with_qr and !qr_done) {
            printQrCode(ui, allocator, tme_link);
            qr_done = true;
        }
        if (dd_enabled) {
            var dd_buf: [128]u8 = undefined;
            const dd_secret = buildDdSecret(secret_hex, &dd_buf);
            var dd_link_buf: [512]u8 = undefined;
            const dd_link = std.fmt.bufPrint(&dd_link_buf, "tg://proxy?server={s}&port={d}&secret={s}", .{
                safe_public_ip,
                port,
                dd_secret,
            }) catch continue;
            ui.print("  {s}│{s}  {s}{s} dd:     {s} {s}{s}{s}\n", .{
                tui_mod.Color.gray,
                tui_mod.Color.reset,
                tui_mod.Color.dim,
                user_name,
                tui_mod.Color.reset,
                tui_mod.Color.white,
                dd_link,
                tui_mod.Color.reset,
            });
        }
        printed_any = true;
    }

    return printed_any;
}

fn printSummary(
    ui: *Tui,
    allocator: std.mem.Allocator,
    public_ip: []const u8,
    port: u16,
    public_port: u16,
    secret: []const u8,
    tls_domain: []const u8,
    opts: InstallOpts,
    config_path: []const u8,
) void {
    var port_buf: [8]u8 = undefined;
    const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch "443";
    var public_port_buf: [8]u8 = undefined;
    const public_port_str = std.fmt.bufPrint(&public_port_buf, "{d}", .{public_port}) catch "443";
    var tcpmss_label_buf: [56]u8 = undefined;
    const tcpmss_label = std.fmt.bufPrint(&tcpmss_label_buf, "TCPMSS={d} (ClientHello fragmentation)", .{opts.tcpmss_value}) catch "TCPMSS (ClientHello fragmentation)";

    ui.summaryBox(ui.str(.install_success_header), &.{
        .{ .label = ui.str(.install_status_cmd), .value = "systemctl status mtproto-proxy" },
        .{ .label = ui.str(.install_logs_cmd), .value = "journalctl -u mtproto-proxy -f" },
        .{ .label = ui.str(.install_config_path), .value = INSTALL_DIR ++ "/config.toml" },
        .{ .label = "Server:", .value = public_ip },
        .{ .label = "Port:", .value = port_str },
        .{
            .label = if (public_port != port) "Public Port:" else "",
            .value = public_port_str,
            .style = if (public_port != port) .label_value else .blank,
        },
        .{ .label = "", .style = .blank },
        .{ .label = ui.str(.install_dpi_active), .style = .highlight },
        .{
            .label = if (opts.enable_tcpmss) tcpmss_label else "",
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
        .{ .label = "", .style = .blank },
        .{
            .label = if (opts.enable_middle_proxy) "MiddleProxy (Telegram relay)" else "MiddleProxy: disabled",
            .style = if (opts.enable_middle_proxy) .success else .label_value,
        },
    });

    ui.writeRaw("\n");
    ui.print("  {s}╭─ {s}{s}\n", .{ tui_mod.Color.gray, tui_mod.Color.bold, ui.str(.install_connection_link) });

    if (!printLinksFromConfig(ui, allocator, public_ip, public_port, tls_domain, config_path, false)) {
        // Fallback when no config could be read. Fresh installs default to the
        // secure TLS-only posture (fake_tls_only = true), so only the FakeTLS
        // (ee) link is printed here. dd links are surfaced by printLinksFromConfig
        // only when the operator has explicitly enabled the dd transport.
        var ee_buf: [512]u8 = undefined;
        const ee_secret = buildEeSecret(secret, tls_domain, &ee_buf);

        var encoded_ip_buf: [768]u8 = undefined;
        const safe_public_ip = encodeServerForProxyLink(public_ip, &encoded_ip_buf);

        var ee_link_buf: [512]u8 = undefined;
        const ee_link = std.fmt.bufPrint(&ee_link_buf, "tg://proxy?server={s}&port={d}&secret={s}", .{
            safe_public_ip,
            public_port,
            ee_secret,
        }) catch "error building link";

        var tme_link_buf: [512]u8 = undefined;
        const tme_link = std.fmt.bufPrint(&tme_link_buf, "https://t.me/proxy?server={s}&port={d}&secret={s}", .{
            safe_public_ip,
            public_port,
            ee_secret,
        }) catch ee_link;
        ui.print("  {s}│{s}  {s}{s}{s}\n", .{ tui_mod.Color.gray, tui_mod.Color.reset, tui_mod.Color.white, tme_link, tui_mod.Color.reset });
        ui.print("  {s}│{s}  {s}{s}{s}\n", .{ tui_mod.Color.gray, tui_mod.Color.reset, tui_mod.Color.dim, ee_link, tui_mod.Color.reset });
    }

    ui.print("  {s}╰─{s}\n", .{ tui_mod.Color.gray, tui_mod.Color.reset });

    if (std.mem.indexOf(u8, public_ip, "SERVER_IP") != null) {
        ui.warn(localized(ui, "Couldn't auto-detect this server's public IP. In the links above, replace SERVER_IP with your VPS's IP address (e.g. 203.0.113.5).", "Не удалось определить публичный IP сервера. В ссылках выше замените SERVER_IP на IP-адрес вашего VPS (например, 203.0.113.5)."));
    }

    ui.writeRaw("\n");
    ui.hint(localized(ui, "Share with someone you love — send them the top (t.me) link with:", "Поделитесь с близким — отправьте ему верхнюю (t.me) ссылку со словами:"));
    ui.hint(localized(ui, "\"I set up a private door to Telegram for us. Tap this link, choose Connect, and Telegram will work again.\"", "«Я сделал для нас личный вход в Telegram. Нажми на ссылку, выбери «Подключить» — и Telegram снова заработает.»"));
    ui.writeRaw("\n");
    ui.hint(localized(ui, "Print these links again anytime: sudo mtbuddy links", "Показать эти ссылки снова в любой момент: sudo mtbuddy links"));
    ui.hint(localized(ui, "Runtime proxy logs intentionally hide secrets and links.", "Runtime-логи прокси намеренно скрывают секреты и ссылки."));
}

fn localized(ui: *const Tui, en: []const u8, ru: []const u8) []const u8 {
    return switch (ui.lang) {
        .en => en,
        .ru => ru,
    };
}

/// Resolve the public server address used in client links: a configured
/// [server].public_ip wins over auto-detection (matching main.zig/links.zig/the
/// summary). Computed once and reused for both the early "LIVE" link/QR and the
/// final summary so they encode the SAME address and detection runs only once.
fn resolvePublicServer(ui: *Tui, allocator: std.mem.Allocator, config_path: []const u8, out_buf: []u8) []const u8 {
    if (toml.TomlDoc.load(allocator, config_path)) |loaded| {
        var cfg_doc = loaded;
        defer cfg_doc.deinit();
        if (cfg_doc.get("server", "public_ip")) |configured| {
            const trimmed = std.mem.trim(u8, configured, &[_]u8{ ' ', '\t' });
            if (trimmed.len > 0) {
                const n = @min(trimmed.len, out_buf.len);
                @memcpy(out_buf[0..n], trimmed[0..n]);
                return out_buf[0..n];
            }
        }
    } else |_| {}
    var ip_sp = ui.spinner("Detecting public IP");
    ip_sp.start();
    const ip = sys.detectPublicIp(allocator) orelse "SERVER_IP";
    ip_sp.stop(true, ip);
    return ip;
}

pub fn ensureServiceUser(ui: *Tui, allocator: std.mem.Allocator) bool {
    const groupadd_candidates = &[_][]const u8{ "/usr/sbin/groupadd", "/sbin/groupadd" };
    const useradd_candidates = &[_][]const u8{ "/usr/sbin/useradd", "/sbin/useradd" };

    if (!commandAvailable("groupadd", groupadd_candidates)) {
        ui.fail("Missing required system command 'groupadd'");
        ui.info("Install Debian package 'passwd' and run the installer again.");
        return false;
    }
    if (!commandAvailable("useradd", useradd_candidates)) {
        ui.fail("Missing required system command 'useradd'");
        ui.info("Install Debian package 'passwd' and run the installer again.");
        return false;
    }

    const groupadd = sys.commandOrPath("groupadd", groupadd_candidates);
    const useradd = sys.commandOrPath("useradd", useradd_candidates);

    if (!groupExists(allocator, "mtproto")) {
        if (!runRequired(ui, allocator, &.{ groupadd, "--system", "mtproto" }, "Failed to create system group 'mtproto'")) return false;
    }

    if (!userExists(allocator, "mtproto")) {
        if (!runRequired(ui, allocator, &.{
            useradd,
            "--system",
            "--no-create-home",
            "--home-dir",
            INSTALL_DIR,
            "--shell",
            "/usr/sbin/nologin",
            "--gid",
            "mtproto",
            "mtproto",
        }, "Failed to create system user 'mtproto'")) return false;
        ui.ok(ui.str(.install_user_created));
    }

    if (!groupExists(allocator, "mtproto")) {
        ui.fail("System group 'mtproto' is missing");
        return false;
    }
    if (!userExists(allocator, "mtproto")) {
        ui.fail("System user 'mtproto' is missing");
        return false;
    }
    return true;
}

fn requiredAccountToolsAvailable(ui: *Tui) bool {
    if (!commandAvailable("groupadd", &.{ "/usr/sbin/groupadd", "/sbin/groupadd" })) {
        ui.fail("Missing required system command 'groupadd' after dependency install");
        ui.info("Debian package 'passwd' should provide it.");
        return false;
    }
    if (!commandAvailable("useradd", &.{ "/usr/sbin/useradd", "/sbin/useradd" })) {
        ui.fail("Missing required system command 'useradd' after dependency install");
        ui.info("Debian package 'passwd' should provide it.");
        return false;
    }
    return true;
}

fn commandAvailable(name: []const u8, candidates: []const []const u8) bool {
    if (sys.commandExists(name)) return true;
    for (candidates) |candidate| {
        if (sys.fileExists(candidate)) return true;
    }
    return false;
}

/// True when the installed config has masking enabled — via a local nginx backend
/// OR real-domain fronting to tls_domain:443 (the secure default when no
/// owned-domain cert is available, which never creates a local nginx site). The
/// config (`mask = true`) is the source of truth; probing for an nginx site would
/// wrongly report the real-domain-fronting path as "masking disabled".
fn configMaskEnabled(allocator: std.mem.Allocator) bool {
    var doc = toml.TomlDoc.load(allocator, INSTALL_DIR ++ "/config.toml") catch return false;
    defer doc.deinit();
    const v = doc.get("censorship", "mask") orelse return false;
    return std.mem.eql(u8, std.mem.trim(u8, v, " \t\"'"), "true");
}

fn userExists(allocator: std.mem.Allocator, name: []const u8) bool {
    const result = sys.exec(allocator, &.{ "id", "-u", name }) catch return false;
    defer result.deinit();
    return result.exit_code == 0;
}

fn groupExists(allocator: std.mem.Allocator, name: []const u8) bool {
    const result = sys.exec(allocator, &.{ "getent", "group", name }) catch return false;
    defer result.deinit();
    return result.exit_code == 0;
}

fn runRequired(ui: *Tui, allocator: std.mem.Allocator, argv: []const []const u8, failure_msg: []const u8) bool {
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

fn runRequiredWhileSpinning(
    ui: *Tui,
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    failure_msg: []const u8,
    sp: *tui_mod.Spinner,
) bool {
    const result = sys.exec(allocator, argv) catch |err| {
        sp.stop(false, "");
        ui.fail(failure_msg);
        ui.print("  {s}◆{s} Failed to spawn command: {s}\n", .{ Color.info, Color.reset, @errorName(err) });
        return false;
    };
    defer result.deinit();

    if (result.exit_code == 0) return true;

    sp.stop(false, "");
    ui.fail(failure_msg);
    printCommandOutput(ui, &result);
    return false;
}

fn printServiceStatus(ui: *Tui, allocator: std.mem.Allocator) void {
    const status = sys.exec(allocator, &.{ "systemctl", "status", SERVICE_NAME, "--no-pager", "-l" }) catch return;
    defer status.deinit();
    printCommandOutput(ui, &status);
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
