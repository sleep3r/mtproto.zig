//! Setup nfqws command for mtbuddy.
//!
//! Ports setup_nfqws.sh (258 lines bash) — installs zapret's nfqws
//! for OS-level TCP desync (fake packets + split to defeat stateful DPI).

const std = @import("std");
const tui_mod = @import("tui.zig");
const i18n = @import("i18n.zig");
const sys = @import("sys.zig");
const toml = @import("toml.zig");

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;
const SummaryLine = tui_mod.SummaryLine;

const ZAPRET_DIR = "/opt/zapret";
/// zapret is the DPI-bypass engine — it must track DPI evolution, so we clone the
/// LATEST release tag (resolved at install time), not a frozen commit and not raw
/// HEAD (which can be a broken mid-development commit). This is deliberately NOT a
/// supply-chain pin like uv / the Python deps: freezing the bypass engine freezes
/// the bypass. ZAPRET_FALLBACK_TAG is used only when the latest tag can't be
/// resolved (e.g. offline) so the install still succeeds with a known-good release.
const ZAPRET_FALLBACK_TAG = "v72.12";
const SERVICE_NAME = "nfqws-mtproto";
const NFQUEUE_NUM = "200";
const INSTALL_DIR = "/opt/mtproto-proxy";

pub const NfqwsOpts = struct {
    ttl: []const u8 = "6",
    remove: bool = false,
};

/// Run in CLI mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    var opts = NfqwsOpts{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--ttl")) {
            if (args.next()) |val| opts.ttl = val;
        } else if (std.mem.eql(u8, arg, "--remove") or std.mem.eql(u8, arg, "--uninstall")) {
            opts.remove = true;
        } else {
            ui.print("Unknown option: {s}\n", .{arg});
            return error.UnknownOption;
        }
    }
    try execute(ui, allocator, opts);
}

/// Run in interactive mode.
pub fn runInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    ui.section("nfqws TCP Desync (Zapret)");

    var ttl_buf: [8]u8 = undefined;
    const ttl = try ui.input(
        "Fake packet TTL",
        "Number of hops for fake packets. 4-8 works for most Russian ISPs.\nToo low = no effect, too high = breaks real connections.",
        "6",
        &ttl_buf,
    );

    if (!try ui.confirm(i18n.get(ui.lang, .confirm_proceed), true)) {
        ui.info(i18n.get(ui.lang, .aborting));
        return;
    }

    try execute(ui, allocator, .{ .ttl = ttl });
}

pub fn execute(ui: *Tui, allocator: std.mem.Allocator, opts: NfqwsOpts) !void {
    if (!sys.isRoot()) {
        ui.fail(i18n.get(ui.lang, .error_not_root));
        return;
    }

    // Read proxy port from config. Copy it into a stack buffer BEFORE deinit — toml.get()
    // returns a slice into the doc's heap lines, which deinit frees; the port is used far
    // below (iptables argv + the systemd unit), so an aliased slice would be a use-after-free.
    var port_buf: [16]u8 = undefined;
    var port: []const u8 = "443";
    {
        var doc = toml.TomlDoc.load(allocator, INSTALL_DIR ++ "/config.toml") catch null;
        if (doc) |*d| {
            defer d.deinit();
            const raw = d.get("server", "port") orelse "443";
            const number = try parsePort(raw);
            port = try std.fmt.bufPrint(&port_buf, "{d}", .{number});
        }
    }

    // ── Uninstall ──
    if (opts.remove) {
        const ipt = iptablesCommands();

        ui.step("Removing nfqws-mtproto...");
        _ = sys.execForward(&.{ "systemctl", "stop", SERVICE_NAME }) catch {};
        _ = sys.execForward(&.{ "systemctl", "disable", SERVICE_NAME }) catch {};
        _ = sys.exec(allocator, &.{ "rm", "-f", "/etc/systemd/system/" ++ SERVICE_NAME ++ ".service" }) catch {};
        _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};

        // Remove iptables rules from the LIVE ruleset only. We deliberately do NOT
        // iptables-save the whole firewall here: the unit is gone (so nothing re-adds the
        // rule on boot) and a full snapshot would freeze whatever transient state (Docker
        // NAT, fail2ban bans, operator rules) happens to be live into the boot ruleset.
        removeNfqwsRules(allocator, ipt.iptables);
        removeNfqwsRules(allocator, ipt.ip6tables);

        ui.ok("nfqws-mtproto removed");
        return;
    }

    // ── Install dependencies ──
    ui.step("Installing build dependencies...");
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
        "build-essential",
        "gcc",
        "g++",
        "cpp",
        "make",
        "binutils",
        "libc6-dev",
        "git",
        "libnetfilter-queue-dev",
        "libnfnetlink-dev",
        "libcap-dev",
        "iptables",
        "libmnl-dev",
        "zlib1g-dev",
    }, "Failed to install nfqws build dependencies")) return;
    ui.ok("Dependencies installed");

    const ipt = iptablesCommands();

    if (!try ensureZapret(ui, allocator)) return;

    // ── Configure iptables NFQUEUE ──
    ui.step("Setting up NFQUEUE rules...");
    removeNfqwsRules(allocator, ipt.iptables);
    removeNfqwsRules(allocator, ipt.ip6tables);

    // --queue-bypass: if nfqws is not attached (down/crashed/failed to start),
    // queued packets fall through to ACCEPT instead of the kernel default DROP.
    // Without it, a stopped nfqws silently blackholes ALL proxy egress on this port.
    //
    // `! -o lo` keeps loopback out of the queue. Desync exists to defeat DPI on the path
    // to the client; 127.0.0.1 never crosses a network, and the WEB relay dials the proxy
    // there, so without this exclusion every relayed byte takes a userspace round trip
    // through nfqws and the relay's streams crawl.
    if (!runLogged(ui, allocator, &.{
        ipt.iptables, "-t",             "mangle", "-A",      "OUTPUT",
        "!",          "-o",             "lo",     "-p",      "tcp",
        "--sport",    port,             "-j",     "NFQUEUE", "--queue-num",
        NFQUEUE_NUM,  "--queue-bypass",
    }, "Failed to apply IPv4 NFQUEUE rule")) return;
    if (!runLogged(ui, allocator, &.{
        ipt.ip6tables, "-t",             "mangle", "-A",      "OUTPUT",
        "!",           "-o",             "lo",     "-p",      "tcp",
        "--sport",     port,             "-j",     "NFQUEUE", "--queue-num",
        NFQUEUE_NUM,   "--queue-bypass",
    }, "IPv6 NFQUEUE rule unavailable; IPv6 desync is not enabled")) ui.warn("IPv4 may work, but IPv6 protection needs repair.");

    if (!nfqueueRuleExists(allocator, ipt.iptables, port)) {
        ui.fail("IPv4 NFQUEUE rule was not installed");
        return;
    }
    const ipv6_active = nfqueueRuleExists(allocator, ipt.ip6tables, port);
    if (!ipv6_active) ui.warn("IPv6 NFQUEUE verification failed; do not assume IPv6 traffic is protected.");

    // NOTE: we intentionally do NOT `iptables-save > /etc/iptables/rules.v4` here. The
    // systemd unit's ExecStartPre re-adds the NFQUEUE rule on every boot, so persisting it
    // is redundant — and a full-firewall snapshot would clobber any operator-curated
    // rules.v4 and freeze transient chains (Docker, fail2ban) into the boot ruleset.
    ui.ok(if (ipv6_active) "IPv4 and IPv6 NFQUEUE rules verified (queue " ++ NFQUEUE_NUM ++ ")" else "IPv4 NFQUEUE rule verified (IPv6 unavailable)");

    // ── Create systemd service ──
    ui.step("Creating systemd service...");
    var svc_buf: [3072]u8 = undefined;
    const svc_content = std.fmt.bufPrint(&svc_buf,
        \\[Unit]
        \\Description=nfqws TCP desync for MTProto proxy
        \\After=network.target
        \\Before=mtproto-proxy.service
        \\
        \\[Service]
        \\Type=simple
        \\ExecStartPre=-{[iptables]s} -t mangle -D OUTPUT -p tcp --sport {[port]s} -j NFQUEUE --queue-num {[queue]s} --queue-bypass
        \\ExecStartPre=-{[ip6tables]s} -t mangle -D OUTPUT -p tcp --sport {[port]s} -j NFQUEUE --queue-num {[queue]s} --queue-bypass
        \\ExecStartPre=-{[iptables]s} -t mangle -D OUTPUT ! -o lo -p tcp --sport {[port]s} -j NFQUEUE --queue-num {[queue]s} --queue-bypass
        \\ExecStartPre=-{[ip6tables]s} -t mangle -D OUTPUT ! -o lo -p tcp --sport {[port]s} -j NFQUEUE --queue-num {[queue]s} --queue-bypass
        \\ExecStartPre={[iptables]s} -t mangle -A OUTPUT ! -o lo -p tcp --sport {[port]s} -j NFQUEUE --queue-num {[queue]s} --queue-bypass
        \\ExecStartPre=-{[ip6tables]s} -t mangle -A OUTPUT ! -o lo -p tcp --sport {[port]s} -j NFQUEUE --queue-num {[queue]s} --queue-bypass
        \\ExecStart={[zapret_dir]s}/nfq/nfqws \
        \\    --qnum={[queue]s} \
        \\    --dpi-desync=fake,split2 \
        \\    --dpi-desync-ttl={[ttl]s} \
        \\    --dpi-desync-split-pos=1 \
        \\    --dpi-desync-fooling=md5sig
        \\Restart=always
        \\RestartSec=5
        \\CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
        \\AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
        \\NoNewPrivileges=true
        \\ProtectSystem=strict
        \\ProtectHome=true
        \\PrivateTmp=true
        \\
        \\[Install]
        \\WantedBy=multi-user.target
    , .{
        .iptables = ipt.iptables,
        .ip6tables = ipt.ip6tables,
        .port = port,
        .zapret_dir = ZAPRET_DIR,
        .queue = NFQUEUE_NUM,
        .ttl = opts.ttl,
    }) catch "";

    if (svc_content.len > 0) {
        sys.writeFile("/etc/systemd/system/" ++ SERVICE_NAME ++ ".service", svc_content) catch {
            ui.fail("Failed to write systemd service");
            return;
        };
    }

    _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};
    _ = sys.exec(allocator, &.{ "systemctl", "enable", SERVICE_NAME }) catch {};
    _ = sys.execForward(&.{ "systemctl", "restart", SERVICE_NAME }) catch {};

    if (sys.isServiceActive(SERVICE_NAME)) {
        ui.ok("nfqws service started");
    } else {
        ui.warn("nfqws may have failed to start");
    }

    // ── Summary ──
    ui.hint("After changing [server].port, rerun: sudo mtbuddy setup nfqws (the unit records the current port).");
    ui.summaryBox("nfqws TCP Desync Configured", &.{
        .{ .label = "Binary:", .value = ZAPRET_DIR ++ "/nfq/nfqws" },
        .{ .label = "Service:", .value = SERVICE_NAME },
        .{ .label = "Queue:", .value = "NFQUEUE #" ++ NFQUEUE_NUM },
        .{ .label = "TTL:", .value = opts.ttl },
        .{ .label = "", .style = .blank },
        .{ .label = "Strategy: fake + split2", .style = .highlight },
        .{ .label = "Fake TLS → DPI sees valid handshake", .style = .success },
        .{ .label = "Split at byte 1 → DPI can't reassemble", .style = .success },
        .{ .label = "MD5sig fooling → fake never reaches client", .style = .success },
    });
}

const IptablesCommands = struct {
    iptables: []const u8,
    ip6tables: []const u8,
};

fn iptablesCommands() IptablesCommands {
    return .{
        .iptables = sys.commandOrPath("iptables", &.{ "/usr/sbin/iptables", "/sbin/iptables" }),
        .ip6tables = sys.commandOrPath("ip6tables", &.{ "/usr/sbin/ip6tables", "/sbin/ip6tables" }),
    };
}

const ZapretRef = struct { tag: []const u8, sha: []const u8 };

fn parsePort(raw: []const u8) !u16 {
    if (raw.len == 0) return error.InvalidPort;
    for (raw) |c| if (!std.ascii.isDigit(c)) return error.InvalidPort;
    const port = std.fmt.parseInt(u16, raw, 10) catch return error.InvalidPort;
    if (port == 0) return error.InvalidPort;
    return port;
}

test "nfqws port validation rejects truncation and command tokens" {
    try std.testing.expectEqual(@as(u16, 443), try parsePort("00443"));
    for ([_][]const u8{ "", "0", "65536", "443 --jump ACCEPT", "12345678901234567890", "+443" }) |text| try std.testing.expectError(error.InvalidPort, parsePort(text));
}

fn ensureZapret(ui: *Tui, allocator: std.mem.Allocator) !bool {
    var tag_buf: [64]u8 = undefined;
    var sha_buf: [64]u8 = undefined;
    const ref = resolveLatestZapretTag(allocator, &tag_buf, &sha_buf);
    const installed = sys.fileExists(ZAPRET_DIR ++ "/nfq/nfqws");
    if (installed and ref == null) {
        ui.warn("Could not resolve the current zapret release; keeping the installed binary.");
        return true;
    }
    const tag = if (ref) |r| r.tag else ZAPRET_FALLBACK_TAG;
    const version = if (ref) |r| r.sha else tag;
    const previous = sys.readFileAllocAbsolute(allocator, ZAPRET_DIR ++ "/nfq/nfqws.version", 128);
    defer if (previous) |v| allocator.free(v);
    if (installed and previous != null and std.mem.eql(u8, std.mem.trim(u8, previous.?, " \r\n"), version)) return true;

    const cc = chooseWorkingCCompiler(ui, allocator) orelse return false;
    const temporary = try sys.exec(allocator, &.{ "mktemp", "-d", "/opt/zapret-build.XXXXXXXX" });
    defer temporary.deinit();
    if (temporary.exit_code != 0) return error.StagingDirectoryFailed;
    const stage = std.mem.trim(u8, temporary.stdout, " \r\n");
    if (!std.mem.startsWith(u8, stage, "/opt/zapret-build.") or std.mem.indexOfScalar(u8, stage[18..], '/') != null) return error.InvalidStagingDirectory;
    defer sys.execSilent(allocator, &.{ "rm", "-rf", "--", stage });
    if (!runLogged(ui, allocator, &.{ "git", "clone", "--branch", tag, "--depth", "1", "https://github.com/bol-van/zapret.git", stage }, "Failed to clone zapret release")) return false;
    if (ref) |r| {
        // Compare tag objects, not HEAD: annotated tag objects have their own SHA.
        const tag_ref = try std.fmt.allocPrint(allocator, "refs/tags/{s}", .{tag});
        defer allocator.free(tag_ref);
        const rev = try sys.exec(allocator, &.{ "git", "-C", stage, "rev-parse", tag_ref });
        defer rev.deinit();
        if (rev.exit_code != 0 or !std.mem.eql(u8, std.mem.trim(u8, rev.stdout, " \r\n"), r.sha)) return error.ReleaseTagMismatch;
    }
    const source = try std.fmt.allocPrint(allocator, "{s}/nfq", .{stage});
    defer allocator.free(source);
    const compiler = try std.fmt.allocPrint(allocator, "CC={s}", .{cc});
    defer allocator.free(compiler);
    if (!runLogged(ui, allocator, &.{ "make", "-C", source, compiler }, "nfqws build failed; installed binary retained")) return false;
    const binary = try std.fmt.allocPrint(allocator, "{s}/nfqws", .{source});
    defer allocator.free(binary);
    if (!runLogged(ui, allocator, &.{ "mkdir", "-p", ZAPRET_DIR ++ "/nfq" }, "Could not create nfqws install directory")) return false;
    if (!runLogged(ui, allocator, &.{ "install", "-m", "755", binary, ZAPRET_DIR ++ "/nfq/nfqws.new" }, "Could not stage nfqws binary")) return false;
    try std.Io.Dir.renameAbsolute(ZAPRET_DIR ++ "/nfq/nfqws.new", ZAPRET_DIR ++ "/nfq/nfqws", std.Io.Threaded.global_single_threaded.io());
    try sys.writeFile(ZAPRET_DIR ++ "/nfq/nfqws.version", version);
    ui.ok("nfqws release built and installed atomically");
    return true;
}

/// Resolve the newest zapret release tag (highest vX.Y) AND the commit it points
/// to, from the remote without the GitHub API (works wherever `git clone` does).
/// Returns slices into the caller buffers, or null if the remote is unreachable /
/// no tag found (caller then falls back to a known-good tag, unverified). The tag
/// is passed to `git clone --branch` as a distinct argv element (no shell) and is
/// sanity-checked to a vX.Y string; the SHA lets the caller verify the clone
/// landed on exactly the commit the remote advertised for that tag. This is a
/// freshness-preserving consistency check, NOT a frozen pin or signature check.
fn resolveLatestZapretTag(allocator: std.mem.Allocator, tag_buf: []u8, sha_buf: []u8) ?ZapretRef {
    const r = sys.exec(allocator, &.{
        "bash",                                                                                                "-c",
        "git ls-remote --tags --refs --sort=-v:refname https://github.com/bol-van/zapret.git 'v*' | head -n1",
    }) catch return null;
    defer r.deinit();
    if (r.exit_code != 0) return null;
    // Output line: "<40-hex-sha>\trefs/tags/<tag>".
    const line = std.mem.trim(u8, r.stdout, " \t\r\n");
    const tab = std.mem.indexOfScalar(u8, line, '\t') orelse return null;
    const sha = line[0..tab];
    if (sha.len < 7 or sha.len > sha_buf.len) return null;
    for (sha) |ch| {
        if (!((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f'))) return null;
    }
    const marker = "refs/tags/";
    const idx = std.mem.indexOf(u8, line, marker) orelse return null;
    const tag = line[idx + marker.len ..];
    if (tag.len == 0 or tag.len > tag_buf.len or tag[0] != 'v') return null;
    for (tag) |ch| {
        if (!((ch >= '0' and ch <= '9') or ch == '.' or ch == 'v')) return null;
    }
    @memcpy(tag_buf[0..tag.len], tag);
    @memcpy(sha_buf[0..sha.len], sha);
    return .{ .tag = tag_buf[0..tag.len], .sha = sha_buf[0..sha.len] };
}

fn chooseWorkingCCompiler(ui: *Tui, allocator: std.mem.Allocator) ?[]const u8 {
    if (sys.fileExists("/usr/bin/gcc")) return "/usr/bin/gcc";
    if (sys.commandExists("gcc")) return "gcc";

    ui.warn("GCC not found after dependency install; reinstalling GCC toolchain...");
    if (!repairGccToolchain(ui, allocator)) return null;

    if (sys.fileExists("/usr/bin/gcc")) return "/usr/bin/gcc";
    if (sys.commandExists("gcc")) return "gcc";

    ui.fail("GCC is required to build nfqws but was not found");
    ui.info("On Debian install it with: apt-get install gcc build-essential");
    return null;
}

fn repairGccToolchain(ui: *Tui, allocator: std.mem.Allocator) bool {
    _ = sys.exec(allocator, &.{ "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", "DPkg::Lock::Timeout=600", "update", "-qq" }) catch {};

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
        "--reinstall",
        "-y",
        "build-essential",
        "gcc",
        "g++",
        "cpp",
        "make",
        "binutils",
        "libc6-dev",
    }, "Failed to reinstall GCC toolchain")) return false;

    reinstallVersionedGccPackages(ui, allocator);
    return true;
}

fn reinstallVersionedGccPackages(ui: *Tui, allocator: std.mem.Allocator) void {
    const result = sys.exec(allocator, &.{ "gcc", "-dumpversion" }) catch return;
    defer result.deinit();
    if (result.exit_code != 0) return;

    const version = std.mem.trim(u8, result.stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
    var dot_pos = std.mem.indexOfScalar(u8, version, '.') orelse version.len;
    if (dot_pos == 0) return;
    dot_pos = @min(dot_pos, 8);
    const major = version[0..dot_pos];
    for (major) |c| {
        if (!std.ascii.isDigit(c)) return;
    }

    var gcc_pkg_buf: [32]u8 = undefined;
    var cpp_pkg_buf: [32]u8 = undefined;
    const gcc_pkg = std.fmt.bufPrint(&gcc_pkg_buf, "gcc-{s}", .{major}) catch return;
    const cpp_pkg = std.fmt.bufPrint(&cpp_pkg_buf, "cpp-{s}", .{major}) catch return;

    const reinstall = sys.exec(allocator, &.{
        "env",
        "DEBIAN_FRONTEND=noninteractive",
        "apt-get",
        "-o",
        "DPkg::Lock::Timeout=600",
        "install",
        "--reinstall",
        "-y",
        gcc_pkg,
        cpp_pkg,
    }) catch return;
    defer reinstall.deinit();
    if (reinstall.exit_code != 0) {
        ui.warn("Versioned GCC package reinstall was skipped");
    }
}

fn removeNfqwsRules(allocator: std.mem.Allocator, ipt: []const u8) void {
    // Remove any existing NFQUEUE rules for our queue number
    var cmd_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(
        &cmd_buf,
        "{s} -t mangle -S OUTPUT 2>/dev/null | grep 'NFQUEUE --queue-num {s}' | while read -r line; do rule=$(echo \"$line\" | sed 's/-A /-D /'); {s} -t mangle $rule 2>/dev/null || true; done",
        .{ ipt, NFQUEUE_NUM, ipt },
    ) catch return;
    _ = sys.exec(allocator, &.{ "bash", "-c", cmd }) catch {};
}

fn nfqueueRuleExists(allocator: std.mem.Allocator, ipt: []const u8, port: []const u8) bool {
    const result = sys.exec(allocator, &.{ ipt, "-t", "mangle", "-C", "OUTPUT", "!", "-o", "lo", "-p", "tcp", "--sport", port, "-j", "NFQUEUE", "--queue-num", NFQUEUE_NUM, "--queue-bypass" }) catch return false;
    defer result.deinit();
    return result.exit_code == 0;
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

/// Rewrite an existing unit so its NFQUEUE rules skip loopback.
///
/// Returns null when the text already carries the exclusion (nothing to do). The caller
/// owns the result. Each rewritten append is preceded by a matching delete so a restart
/// cannot stack duplicates, and the pre-existing deletes are left alone: they are what
/// removes the old loopback-inclusive rule from a host upgrading into this.
fn rewriteUnitForLoopback(allocator: std.mem.Allocator, unit: []const u8) !?[]u8 {
    if (std.mem.indexOf(u8, unit, "! -o lo") != null) return null;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var lines = std.mem.splitScalar(u8, unit, '\n');
    var first = true;
    while (lines.next()) |line| {
        if (!first) try out.append(allocator, '\n');
        first = false;

        const is_append = std.mem.startsWith(u8, line, "ExecStartPre=") and
            std.mem.indexOf(u8, line, "-A OUTPUT -p tcp") != null and
            std.mem.indexOf(u8, line, "NFQUEUE") != null;
        if (!is_append) {
            try out.appendSlice(allocator, line);
            continue;
        }

        const body = line["ExecStartPre=".len..];
        const cmd = if (body.len > 0 and body[0] == '-') body[1..] else body;

        // The idempotency delete for the new spelling, always failure-tolerant.
        try out.appendSlice(allocator, "ExecStartPre=-");
        try appendWithExclusion(allocator, &out, cmd, "-D OUTPUT");
        try out.append(allocator, '\n');

        try out.appendSlice(allocator, "ExecStartPre=");
        if (body.len > 0 and body[0] == '-') try out.append(allocator, '-');
        try appendWithExclusion(allocator, &out, cmd, "-A OUTPUT");
    }
    return try out.toOwnedSlice(allocator);
}

fn appendWithExclusion(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    cmd: []const u8,
    verb: []const u8,
) !void {
    const at = std.mem.indexOf(u8, cmd, "-A OUTPUT ").?;
    try out.appendSlice(allocator, cmd[0..at]);
    try out.appendSlice(allocator, verb);
    try out.appendSlice(allocator, " ! -o lo ");
    try out.appendSlice(allocator, cmd[at + "-A OUTPUT ".len ..]);
}

/// `mtbuddy update` path. A host installed before the exclusion still queues every
/// loopback packet to nfqws, which throttles the WEB relay's hop to the proxy to a crawl.
/// Repair it in place: the unit is ours, and a restart re-applies both spellings' deletes
/// before appending the corrected rule.
pub fn refreshLoopbackExclusion(ui: *Tui, allocator: std.mem.Allocator) void {
    const path = "/etc/systemd/system/" ++ SERVICE_NAME ++ ".service";
    if (!sys.fileExists(path)) return;

    const unit = sys.readFileAllocAbsolute(allocator, path, 64 * 1024) orelse return;
    defer allocator.free(unit);

    const rewritten = (rewriteUnitForLoopback(allocator, unit) catch return) orelse return;
    defer allocator.free(rewritten);

    sys.writeFile(path, rewritten) catch return;
    _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};
    _ = sys.execForward(&.{ "systemctl", "restart", SERVICE_NAME }) catch {};
    ui.ok("nfqws desync no longer queues loopback traffic");
}

test "rewriteUnitForLoopback adds the exclusion and keeps the rules idempotent" {
    const before =
        \\[Service]
        \\ExecStartPre=-/usr/sbin/iptables -t mangle -D OUTPUT -p tcp --sport 443 -j NFQUEUE --queue-num 200 --queue-bypass
        \\ExecStartPre=/usr/sbin/iptables -t mangle -A OUTPUT -p tcp --sport 443 -j NFQUEUE --queue-num 200 --queue-bypass
        \\ExecStart=/opt/zapret/nfq/nfqws --qnum=200
    ;
    const out = (try rewriteUnitForLoopback(std.testing.allocator, before)).?;
    defer std.testing.allocator.free(out);

    // The append now skips loopback...
    try std.testing.expect(std.mem.indexOf(u8, out, "ExecStartPre=/usr/sbin/iptables -t mangle -A OUTPUT ! -o lo -p tcp --sport 443 -j NFQUEUE --queue-num 200 --queue-bypass") != null);
    // ...preceded by a failure-tolerant delete of that same spelling, or a restart would
    // stack a second copy every time.
    try std.testing.expect(std.mem.indexOf(u8, out, "ExecStartPre=-/usr/sbin/iptables -t mangle -D OUTPUT ! -o lo -p tcp --sport 443 -j NFQUEUE --queue-num 200 --queue-bypass") != null);
    // The original delete survives: it is what clears the old rule on an upgrading host.
    try std.testing.expect(std.mem.indexOf(u8, out, "ExecStartPre=-/usr/sbin/iptables -t mangle -D OUTPUT -p tcp --sport 443") != null);
    // Nothing else is touched.
    try std.testing.expect(std.mem.indexOf(u8, out, "ExecStart=/opt/zapret/nfq/nfqws --qnum=200") != null);
    // No loopback-inclusive append is left behind.
    try std.testing.expect(std.mem.indexOf(u8, out, "-A OUTPUT -p tcp") == null);

    // Already-current units are left alone.
    try std.testing.expect((try rewriteUnitForLoopback(std.testing.allocator, out)) == null);
}
