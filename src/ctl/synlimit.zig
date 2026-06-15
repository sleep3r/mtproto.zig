//! Setup syn-limit command for mtbuddy.
//!
//! Installs an OPTIONAL kernel-level per-source-IP inbound SYN rate-limiter on the
//! proxy port, via iptables `-m hashlimit`. This drops abusive first-SYN bursts in
//! the kernel BEFORE accept(), complementing (not replacing) the in-proxy flood
//! guards which only act after accept() and default OFF anyway.
//!
//! Idea borrowed from MTproxy-reanimation (which does the same with nftables for
//! Telemt/MTProxyMax). We use iptables `hashlimit` to match our existing iptables
//! stack (TCPMSS, nfqws) — no new nftables dependency — and we run it as a SEPARATE
//! systemd oneshot unit so CAP_NET_ADMIN never has to be granted to mtproto-proxy.
//!
//! Default OFF and gated behind a loud CGNAT/VPN warning: like the in-proxy guards,
//! a per-IP SYN limiter false-positives when many real users share one egress IP.

const std = @import("std");
const tui_mod = @import("tui.zig");
const sys = @import("sys.zig");
const toml = @import("toml.zig");

const Tui = tui_mod.Tui;
const Color = tui_mod.Color;

const INSTALL_DIR = "/opt/mtproto-proxy";
const SERVICE_NAME = "mtproto-syn-limit";
const SCRIPT_PATH = "/usr/local/sbin/mtproto-syn-limit.sh";
const UNIT_PATH = "/etc/systemd/system/" ++ SERVICE_NAME ++ ".service";
const CHAIN = "MTPROTO_SYNLIMIT";

/// Token-bucket presets, mirroring MTproxy-reanimation's hard/medium/soft. Rates use
/// the iptables `<n>/second` syntax. `soft` is the default when enabling because the
/// stricter presets false-positive behind carrier-grade NAT / shared VPN egress.
pub const Preset = enum {
    soft,
    medium,
    hard,

    pub fn rate(self: Preset) []const u8 {
        return switch (self) {
            .soft => "2/second",
            .medium => "1/second",
            .hard => "1/second",
        };
    }

    pub fn burst(self: Preset) []const u8 {
        return switch (self) {
            .soft => "5",
            .medium => "3",
            .hard => "1",
        };
    }
};

pub const Action = enum { status, apply, remove };

pub const SynLimitOpts = struct {
    action: Action = .status,
    rate: []const u8 = "2/second",
    burst: []const u8 = "5",
};

/// Run in CLI mode.
pub fn run(ui: *Tui, allocator: std.mem.Allocator, args: *std.process.Args.Iterator) !void {
    // Default action is .status; any apply/remove flag below overrides it.
    var opts = SynLimitOpts{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--remove") or std.mem.eql(u8, arg, "--uninstall") or std.mem.eql(u8, arg, "--disable")) {
            opts.action = .remove;
        } else if (std.mem.eql(u8, arg, "--status")) {
            opts.action = .status;
        } else if (std.mem.eql(u8, arg, "--preset")) {
            const val = args.next() orelse continue;
            const preset = parsePreset(val) orelse {
                ui.fail("Unknown preset (expected: soft, medium, hard)");
                return;
            };
            opts.rate = preset.rate();
            opts.burst = preset.burst();
            opts.action = .apply;
        } else if (std.mem.eql(u8, arg, "--rate")) {
            const val = args.next() orelse continue;
            if (!isValidRate(val)) {
                ui.fail("Invalid --rate (expected like 2/second, 1/minute)");
                return;
            }
            opts.rate = val;
            opts.action = .apply;
        } else if (std.mem.eql(u8, arg, "--burst")) {
            const val = args.next() orelse continue;
            if (!isValidNumber(val)) {
                ui.fail("Invalid --burst (expected a positive integer)");
                return;
            }
            opts.burst = val;
            opts.action = .apply;
        }
    }
    try execute(ui, allocator, opts);
}

/// Run in interactive mode.
pub fn runInteractive(ui: *Tui, allocator: std.mem.Allocator) !void {
    ui.section(tr(ui, "Kernel SYN rate-limit (anti-flood)", "Ограничение SYN на уровне ядра (анти-флуд)"));

    ui.print("  {s}{s}{s}\n", .{ Color.dim, tr(ui,
        "Drops abusive first-SYN bursts per source IP in the kernel, before they",
        "Дропает абьюзные SYN-всплески по каждому IP-источнику в ядре, до того как они"), Color.reset });
    ui.print("  {s}{s}{s}\n\n", .{ Color.dim, tr(ui,
        "ever reach the proxy. Complements the in-proxy guards (which run after accept).",
        "достигнут прокси. Дополняет защиту внутри прокси (которая работает после accept)."), Color.reset });

    // The same NAT/VPN false-positive that keeps the in-proxy flood guard OFF by default.
    ui.warn(tr(ui,
        "Per-IP limit: behind carrier-NAT / shared VPN egress many real users share one IP",
        "Лимит на IP: за carrier-NAT / общим VPN-выходом много реальных пользователей делят один IP"));
    ui.print("  {s}{s}{s}\n\n", .{ Color.dim, tr(ui,
        "and can be throttled together. Leave it off unless you see a SYN flood.",
        "и могут быть зарезаны вместе. Оставьте выключенным, если нет SYN-флуда."), Color.reset });

    printStatus(ui, allocator);
    ui.writeRaw("\n");

    const items = [_][]const u8{
        tr(ui, "Enable — Soft (2/s, burst 5) — recommended", "Включить — Мягкий (2/с, burst 5) — рекомендуется"),
        tr(ui, "Enable — Medium (1/s, burst 3)", "Включить — Средний (1/с, burst 3)"),
        tr(ui, "Enable — Hard (1/s, burst 1)", "Включить — Жёсткий (1/с, burst 1)"),
        tr(ui, "Disable / remove", "Отключить / удалить"),
    };
    const idx = ui.menu(tr(ui, "SYN rate-limit", "Ограничение SYN"), &items) catch |e| switch (e) {
        error.GoBack => return,
        else => return e,
    };

    switch (idx) {
        0, 1, 2 => {
            const preset: Preset = switch (idx) {
                0 => .soft,
                1 => .medium,
                else => .hard,
            };
            if (!try ui.confirm(tr(ui, "Apply this SYN rate-limit now?", "Применить это ограничение SYN сейчас?"), true)) {
                ui.info(tr(ui, "Aborted", "Отменено"));
                return;
            }
            try execute(ui, allocator, .{ .action = .apply, .rate = preset.rate(), .burst = preset.burst() });
        },
        else => try execute(ui, allocator, .{ .action = .remove }),
    }
}

pub fn execute(ui: *Tui, allocator: std.mem.Allocator, opts: SynLimitOpts) !void {
    if (opts.action == .status) {
        ui.section(tr(ui, "Kernel SYN rate-limit", "Ограничение SYN на уровне ядра"));
        printStatus(ui, allocator);
        if (!sys.isServiceActive(SERVICE_NAME)) {
            ui.writeRaw("\n");
            ui.hint(tr(ui, "Enable: mtbuddy setup syn-limit --preset soft", "Включить: mtbuddy setup syn-limit --preset soft"));
        }
        return;
    }

    if (!sys.isRoot()) {
        ui.fail(tr(ui, "This action requires root.", "Это действие требует root."));
        return;
    }

    const ipt = iptablesCommands();

    // ── Remove ──
    if (opts.action == .remove) {
        ui.step(tr(ui, "Removing kernel SYN rate-limit...", "Удаление ограничения SYN на уровне ядра..."));
        _ = sys.execForward(&.{ "systemctl", "stop", SERVICE_NAME }) catch {};
        _ = sys.execForward(&.{ "systemctl", "disable", SERVICE_NAME }) catch {};
        sys.execSilent(allocator, &.{ "rm", "-f", UNIT_PATH });
        _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};
        // Belt-and-suspenders: clear live rules regardless of whether the unit's
        // ExecStop ran (port may have changed since apply, so delete every jump by
        // listing INPUT and replaying as deletes — robust to a changed --dport).
        flushChain(allocator, ipt.iptables);
        flushChain(allocator, ipt.ip6tables);
        sys.execSilent(allocator, &.{ "rm", "-f", SCRIPT_PATH });
        ui.ok(tr(ui, "Kernel SYN rate-limit removed", "Ограничение SYN на уровне ядра удалено"));
        return;
    }

    // ── Apply ──
    // Read the proxy port from config. Copy it into a stack buffer BEFORE deinit() —
    // toml.get() aliases the doc's heap, which deinit frees (same caveat as nfqws).
    var port_buf: [16]u8 = undefined;
    var port: []const u8 = "443";
    var proxy_protocol = false;
    {
        var doc = toml.TomlDoc.load(allocator, INSTALL_DIR ++ "/config.toml") catch null;
        if (doc) |*d| {
            defer d.deinit();
            const raw = d.get("server", "port") orelse "443";
            const n = @min(raw.len, port_buf.len);
            @memcpy(port_buf[0..n], raw[0..n]);
            port = port_buf[0..n];
            if (d.get("server", "accept_proxy_protocol")) |v| {
                proxy_protocol = std.mem.indexOf(u8, v, "true") != null;
            }
        }
    }
    if (!isValidNumber(port)) {
        ui.fail(tr(ui, "Could not read a valid proxy port from config.toml", "Не удалось прочитать корректный порт прокси из config.toml"));
        return;
    }

    // A PROXY-protocol front means the kernel sees the load balancer's IP, not the
    // client's — the limiter would throttle the LB. Warn loudly (don't refuse: for a
    // single trusted LB the operator may still want a global cap).
    if (proxy_protocol) {
        ui.warn(tr(ui,
            "accept_proxy_protocol is ON: the kernel sees your load balancer's IP, not real clients.",
            "accept_proxy_protocol включён: ядро видит IP балансировщика, а не реальных клиентов."));
        ui.print("  {s}{s}{s}\n", .{ Color.dim, tr(ui,
            "The per-IP SYN limiter will throttle the LB. Only enable if you understand this.",
            "Лимитер SYN per-IP будет резать балансировщик. Включайте, только если понимаете это."), Color.reset });
    }

    ui.step(tr(ui, "Installing kernel SYN rate-limit...", "Установка ограничения SYN на уровне ядра..."));

    // Generate the apply/flush script and the systemd oneshot unit.
    var script_buf: [2048]u8 = undefined;
    const script = renderScript(&script_buf, .{
        .port = port,
        .rate = opts.rate,
        .burst = opts.burst,
        .iptables = ipt.iptables,
        .ip6tables = ipt.ip6tables,
    }) catch {
        ui.fail(tr(ui, "Failed to render SYN-limit script", "Не удалось сформировать скрипт ограничения SYN"));
        return;
    };
    sys.writeFileMode(SCRIPT_PATH, script, 0o755) catch {
        ui.fail(tr(ui, "Failed to write SYN-limit script", "Не удалось записать скрипт ограничения SYN"));
        return;
    };
    sys.writeFile(UNIT_PATH, unitContent()) catch {
        ui.fail(tr(ui, "Failed to write systemd unit", "Не удалось записать systemd unit"));
        return;
    };

    _ = sys.execForward(&.{ "systemctl", "daemon-reload" }) catch {};
    sys.execSilent(allocator, &.{ "systemctl", "enable", SERVICE_NAME });
    _ = sys.execForward(&.{ "systemctl", "restart", SERVICE_NAME }) catch {};

    // Verify the rule actually landed: if xt_hashlimit is missing the script's strict
    // IPv4 lines fail and the oneshot is marked failed — surface that instead of a
    // silent no-op that looks installed.
    if (!sys.isServiceActive(SERVICE_NAME) or !chainHasDrop(allocator, ipt.iptables)) {
        ui.fail(tr(ui, "SYN rate-limit did not apply (is the hashlimit iptables module available?)", "Ограничение SYN не применилось (доступен ли модуль iptables hashlimit?)"));
        ui.hint("journalctl -u " ++ SERVICE_NAME ++ " --no-pager -n 20");
        return;
    }

    ui.ok(tr(ui, "Kernel SYN rate-limit active", "Ограничение SYN на уровне ядра активно"));
    ui.summaryBox(tr(ui, "Inbound SYN rate-limit", "Ограничение входящих SYN"), &.{
        .{ .label = tr(ui, "Port:", "Порт:"), .value = port, .style = .label_value },
        .{ .label = tr(ui, "Rate:", "Частота:"), .value = opts.rate, .style = .label_value },
        .{ .label = tr(ui, "Burst:", "Burst:"), .value = opts.burst, .style = .label_value },
        .{ .label = tr(ui, "Service:", "Сервис:"), .value = SERVICE_NAME, .style = .label_value },
        .{ .label = "", .value = "", .style = .blank },
        .{ .label = tr(ui, "Per source-IP, dropped pre-accept() in the kernel", "По каждому IP-источнику, дроп до accept() в ядре"), .style = .success },
        .{ .label = tr(ui, "Re-run after changing the proxy port", "Перезапустите после смены порта прокси"), .style = .highlight },
    });
}

/// Print a one-line status (+ drop counter when active). Used by `setup syn-limit`
/// and by `mtbuddy status`.
pub fn printStatus(ui: *Tui, allocator: std.mem.Allocator) void {
    if (sys.isServiceActive(SERVICE_NAME)) {
        const drops = dropCount(allocator);
        if (drops) |d| {
            var buf: [96]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "{s} ({s} {s})", .{
                tr(ui, "Kernel SYN rate-limit is active", "Ограничение SYN на уровне ядра активно"),
                d,
                tr(ui, "SYNs dropped", "SYN дропнуто"),
            }) catch tr(ui, "Kernel SYN rate-limit is active", "Ограничение SYN на уровне ядра активно");
            ui.ok(msg);
            allocator.free(d);
        } else {
            ui.ok(tr(ui, "Kernel SYN rate-limit is active", "Ограничение SYN на уровне ядра активно"));
        }
    } else {
        ui.info(tr(ui, "Kernel SYN rate-limit is not installed", "Ограничение SYN на уровне ядра не установлено"));
    }
}

// ── Rendering (pure, testable) ──

const ScriptParams = struct {
    port: []const u8,
    rate: []const u8,
    burst: []const u8,
    iptables: []const u8,
    ip6tables: []const u8,
};

/// Render the apply/flush shell script. Deliberately uses only `for`/`[ ]`/`if`
/// constructs with NO `{`/`}` so it can be produced with std.fmt (which would treat
/// braces as placeholders). The strict IPv4 lines carry no `|| true` so a missing
/// hashlimit module fails the systemd oneshot instead of silently no-op'ing; IPv6 is
/// best-effort (hosts without IPv6 must not fail the unit).
pub fn renderScript(buf: []u8, p: ScriptParams) ![]const u8 {
    return std.fmt.bufPrint(buf,
        \\#!/bin/sh
        \\# Generated by mtbuddy — MTProto proxy inbound SYN rate-limiter.
        \\# Drops first-SYN packets exceeding RATE per source IP (token bucket of BURST).
        \\# Managed by the {[svc]s}.service systemd unit. Do not edit by hand.
        \\set -u
        \\CHAIN={[chain]s}
        \\PORT={[port]s}
        \\RATE={[rate]s}
        \\BURST={[burst]s}
        \\IPT={[iptables]s}
        \\IP6T={[ip6tables]s}
        \\MODE="$1"
        \\
        \\# Idempotent reset: drop the jump, flush + delete the chain (both families).
        \\for T in "$IPT" "$IP6T"; do
        \\    "$T" -D INPUT -p tcp --dport "$PORT" --syn -j "$CHAIN" 2>/dev/null || true
        \\    "$T" -F "$CHAIN" 2>/dev/null || true
        \\    "$T" -X "$CHAIN" 2>/dev/null || true
        \\done
        \\
        \\[ "$MODE" = flush ] && exit 0
        \\
        \\# IPv4 (required — a failure here fails the unit so the operator notices).
        \\"$IPT" -N "$CHAIN" 2>/dev/null || true
        \\"$IPT" -A "$CHAIN" -m hashlimit --hashlimit-name mtproto_syn --hashlimit-mode srcip --hashlimit-above "$RATE" --hashlimit-burst "$BURST" --hashlimit-htable-expire 60000 -j DROP
        \\"$IPT" -A "$CHAIN" -j RETURN
        \\"$IPT" -I INPUT -p tcp --dport "$PORT" --syn -j "$CHAIN"
        \\
        \\# IPv6 (best-effort — hosts without IPv6 must not fail the unit).
        \\"$IP6T" -N "$CHAIN" 2>/dev/null || true
        \\"$IP6T" -A "$CHAIN" -m hashlimit --hashlimit-name mtproto_syn --hashlimit-mode srcip --hashlimit-above "$RATE" --hashlimit-burst "$BURST" --hashlimit-htable-expire 60000 -j DROP 2>/dev/null || true
        \\"$IP6T" -A "$CHAIN" -j RETURN 2>/dev/null || true
        \\"$IP6T" -I INPUT -p tcp --dport "$PORT" --syn -j "$CHAIN" 2>/dev/null || true
        \\exit 0
        \\
    , .{
        .svc = SERVICE_NAME,
        .chain = CHAIN,
        .port = p.port,
        .rate = p.rate,
        .burst = p.burst,
        .iptables = p.iptables,
        .ip6tables = p.ip6tables,
    });
}

fn unitContent() []const u8 {
    return "[Unit]\n" ++
        "Description=MTProto proxy inbound SYN rate-limiter\n" ++
        "After=network.target\n" ++
        "Before=mtproto-proxy.service\n" ++
        "\n" ++
        "[Service]\n" ++
        "Type=oneshot\n" ++
        "RemainAfterExit=yes\n" ++
        "ExecStart=/bin/sh " ++ SCRIPT_PATH ++ " apply\n" ++
        "ExecStop=/bin/sh " ++ SCRIPT_PATH ++ " flush\n" ++
        "\n" ++
        "[Install]\n" ++
        "WantedBy=multi-user.target\n";
}

// ── Helpers ──

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

/// Delete every INPUT jump to our chain (robust to a changed --dport), then flush +
/// delete the chain. Mirrors uninstall.zig's TCPMSS list-replay-delete approach.
fn flushChain(allocator: std.mem.Allocator, ipt: []const u8) void {
    var cmd_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(
        &cmd_buf,
        "{s} -S INPUT 2>/dev/null | grep -- '-j {s}' | while read -r line; do rule=$(printf '%s' \"$line\" | sed 's/^-A /-D /'); {s} $rule 2>/dev/null || true; done; {s} -F {s} 2>/dev/null || true; {s} -X {s} 2>/dev/null || true",
        .{ ipt, CHAIN, ipt, ipt, CHAIN, ipt, CHAIN },
    ) catch return;
    sys.execSilent(allocator, &.{ "bash", "-c", cmd });
}

fn chainHasDrop(allocator: std.mem.Allocator, ipt: []const u8) bool {
    const result = sys.exec(allocator, &.{ ipt, "-nL", CHAIN }) catch return false;
    defer result.deinit();
    if (result.exit_code != 0) return false;
    return std.mem.indexOf(u8, result.stdout, "DROP") != null;
}

/// Sum the DROP rule's packet counter from `iptables -nvxL CHAIN`. Returns an owned
/// slice (caller frees) or null when unavailable.
fn dropCount(allocator: std.mem.Allocator) ?[]const u8 {
    const ipt = iptablesCommands().iptables;
    const result = sys.exec(allocator, &.{ ipt, "-nvxL", CHAIN }) catch return null;
    defer result.deinit();
    if (result.exit_code != 0) return null;
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, "DROP") == null) continue;
        var tok = std.mem.tokenizeAny(u8, line, " \t");
        const pkts = tok.next() orelse continue;
        if (!isValidNumber(pkts)) continue;
        return allocator.dupe(u8, pkts) catch null;
    }
    return null;
}

fn parsePreset(s: []const u8) ?Preset {
    if (std.mem.eql(u8, s, "soft")) return .soft;
    if (std.mem.eql(u8, s, "medium")) return .medium;
    if (std.mem.eql(u8, s, "hard")) return .hard;
    return null;
}

fn isValidNumber(s: []const u8) bool {
    if (s.len == 0 or s.len > 6) return false;
    for (s) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

/// Validate an iptables hashlimit rate string like "2/second" / "1/minute". Strict
/// because it is baked verbatim into a generated shell script.
fn isValidRate(s: []const u8) bool {
    const slash = std.mem.indexOfScalar(u8, s, '/') orelse return false;
    const num = s[0..slash];
    const unit = s[slash + 1 ..];
    if (!isValidNumber(num)) return false;
    return std.mem.eql(u8, unit, "second") or
        std.mem.eql(u8, unit, "minute") or
        std.mem.eql(u8, unit, "hour") or
        std.mem.eql(u8, unit, "day");
}

fn tr(ui: *Tui, en: []const u8, ru: []const u8) []const u8 {
    return if (ui.lang == .ru) ru else en;
}

test "preset rate/burst" {
    try std.testing.expectEqualStrings("2/second", Preset.soft.rate());
    try std.testing.expectEqualStrings("5", Preset.soft.burst());
    try std.testing.expectEqualStrings("1/second", Preset.hard.rate());
    try std.testing.expectEqualStrings("1", Preset.hard.burst());
}

test "rate/number validation" {
    try std.testing.expect(isValidRate("2/second"));
    try std.testing.expect(isValidRate("10/minute"));
    try std.testing.expect(!isValidRate("2/fortnight"));
    try std.testing.expect(!isValidRate("/second"));
    try std.testing.expect(!isValidRate("2"));
    try std.testing.expect(!isValidRate("2/second; rm -rf"));
    try std.testing.expect(isValidNumber("443"));
    try std.testing.expect(!isValidNumber(""));
    try std.testing.expect(!isValidNumber("44a"));
    try std.testing.expect(!isValidNumber("1234567"));
}

test "renderScript bakes params and stays brace-free for std.fmt" {
    var buf: [2048]u8 = undefined;
    const out = try renderScript(&buf, .{
        .port = "443",
        .rate = "2/second",
        .burst = "5",
        .iptables = "/usr/sbin/iptables",
        .ip6tables = "/usr/sbin/ip6tables",
    });
    try std.testing.expect(std.mem.indexOf(u8, out, "PORT=443") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "--hashlimit-above \"$RATE\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "RATE=2/second") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "BURST=5") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "CHAIN=MTPROTO_SYNLIMIT") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "-I INPUT -p tcp --dport \"$PORT\" --syn -j \"$CHAIN\"") != null);
    // No raw curly braces should survive into the generated script.
    try std.testing.expect(std.mem.indexOfScalar(u8, out, '{') == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, out, '}') == null);
}
