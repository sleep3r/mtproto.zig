const std = @import("std");
const tui_mod = @import("tui.zig");
const sys = @import("sys.zig");

const Tui = tui_mod.Tui;

pub const FrontingVerdict = enum {
    single_round_x25519,
    reachable_without_x25519,
    not_reached,
};

pub const FrontingCheckResult = enum {
    skipped,
    ok,
    not_reached,
    mismatch,
};

pub fn classifyOpenSslOutput(output: []const u8) FrontingVerdict {
    if (std.mem.indexOf(u8, output, "Server Temp Key") != null) return .single_round_x25519;
    if (std.mem.indexOf(u8, output, "CONNECTED") != null) return .reachable_without_x25519;
    return .not_reached;
}

/// Best-effort warning if `domain` is a poor FakeTLS fronting target. Our 3-record
/// ServerHello (single x25519 key_share, no HelloRetryRequest) cannot mimic a domain
/// whose genuine TLS 1.3 prefers a non-x25519 group / does an HRR — e.g. wb.ru and
/// mail.ru pick secp521r1 and reject an x25519-only hello — producing a passive
/// ServerHello mismatch.
pub fn warnIfPoorFrontingDomain(ui: *Tui, allocator: std.mem.Allocator, domain: []const u8) FrontingCheckResult {
    if (!isSafeFrontingDomain(domain)) return .skipped;
    if (!sys.commandExists("openssl")) return .skipped;

    ui.step("Checking fronting-domain TLS suitability...");
    var cmd_buf: [512]u8 = undefined;
    // Offer ONLY X25519 in a TLS 1.3 hello and capture the output (stderr merged,
    // since OpenSSL splits these differently across versions). A domain that
    // negotiates it in a single round prints "Server Temp Key: X25519..."; one
    // that does an HRR / rejects x25519 still prints "CONNECTED" but no temp key.
    // NOTE: the group MUST be uppercase "X25519" — OpenSSL 1.1.1 rejects lowercase.
    const cmd = std.fmt.bufPrint(
        &cmd_buf,
        "echo | timeout 10 openssl s_client -connect {s}:443 -servername {s} -groups X25519 -tls1_3 2>&1",
        .{ domain, domain },
    ) catch return .skipped;
    const r = sys.exec(allocator, &.{ "bash", "-c", cmd }) catch return .skipped;
    defer r.deinit();

    return warnFromVerdict(ui, domain, classifyOpenSslOutput(r.stdout));
}

fn warnFromVerdict(ui: *Tui, domain: []const u8, verdict: FrontingVerdict) FrontingCheckResult {
    switch (verdict) {
        .single_round_x25519 => return .ok,
        .not_reached => {
            var b: [320]u8 = undefined;
            if (std.fmt.bufPrint(&b, "Couldn't reach '{s}:443' from here to verify its TLS — skipping (connectivity, not a bad domain).", .{domain}) catch null) |m| ui.info(m);
            return .not_reached;
        },
        .reachable_without_x25519 => {
            var ex_buf: [128]u8 = undefined;
            const examples = frontingExamples(domain, &ex_buf);
            ui.warn("This fronting domain doesn't negotiate single-round x25519.");
            var msg_buf: [320]u8 = undefined;
            if (std.fmt.bufPrint(&msg_buf, "  '{s}' does a HelloRetryRequest or rejects x25519 (like wb.ru) — our FakeTLS ServerHello can't match it, so a passive observer sees a mismatch.", .{domain}) catch null) |m| ui.warn(m);
            var hint_buf: [320]u8 = undefined;
            if (std.fmt.bufPrint(&hint_buf, "  Prefer a single-round-x25519 domain (e.g. {s}). tls_domain is IMMUTABLE once links are shared — choose now.", .{examples}) catch null) |m| ui.hint(m);
            return .mismatch;
        },
    }
}

fn isSafeFrontingDomain(domain: []const u8) bool {
    if (domain.len == 0 or domain.len > 253) return false;
    for (domain) |c| {
        const ok = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or c == '.' or c == '-';
        if (!ok) return false;
    }
    return true;
}

/// Comma-separated recommended single-round-x25519 fronting domains, excluding
/// `current` so we never suggest the very domain that just failed the check.
fn frontingExamples(current: []const u8, buf: []u8) []const u8 {
    const candidates = [_][]const u8{ "rutube.ru", "ozon.ru", "vk.com", "yandex.ru" };
    var w: usize = 0;
    for (candidates) |c| {
        if (std.ascii.eqlIgnoreCase(c, current)) continue;
        const piece = std.fmt.bufPrint(buf[w..], "{s}{s}", .{ if (w == 0) "" else ", ", c }) catch break;
        w += piece.len;
    }
    return buf[0..w];
}

test "classifyOpenSslOutput detects single-round x25519" {
    const out =
        \\CONNECTED(00000003)
        \\Server Temp Key: X25519, 253 bits
    ;
    try std.testing.expectEqual(FrontingVerdict.single_round_x25519, classifyOpenSslOutput(out));
}

test "classifyOpenSslOutput detects reachable domain without x25519 temp key" {
    const out =
        \\CONNECTED(00000003)
        \\SSL-Session:
    ;
    try std.testing.expectEqual(FrontingVerdict.reachable_without_x25519, classifyOpenSslOutput(out));
}

test "classifyOpenSslOutput detects domain that was not reached" {
    const out = "connect:errno=110\n";
    try std.testing.expectEqual(FrontingVerdict.not_reached, classifyOpenSslOutput(out));
}

test "frontingExamples excludes the current domain" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("ozon.ru, vk.com, yandex.ru", frontingExamples("rutube.ru", &buf));
    try std.testing.expectEqualStrings("ozon.ru, vk.com, yandex.ru", frontingExamples("RuTube.RU", &buf));
    try std.testing.expectEqualStrings("rutube.ru, ozon.ru, vk.com, yandex.ru", frontingExamples("example.com", &buf));
}
