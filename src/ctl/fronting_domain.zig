const std = @import("std");
const tui_mod = @import("tui.zig");
const sys = @import("sys.zig");

const Tui = tui_mod.Tui;

pub const FrontingVerdict = enum {
    /// Negotiates X25519MLKEM768 (post-quantum hybrid, group 0x11ec) in a single
    /// round — the ideal target. Our FakeTLS mimics it via the 0x11ec key_share echo.
    pq_capable,
    /// Reachable and does single-round x25519, but declines the X25519MLKEM768 offer.
    /// Since the June-2026 TSPU rollout a classical-x25519-only domain is a passive
    /// marker that blocks iOS clients (see THREAT_MODEL.md).
    single_round_x25519,
    /// Reachable but does an HRR / prefers a non-x25519 group (e.g. wb.ru, mail.ru →
    /// secp521r1). Our single-round ServerHello can't match it at all.
    reachable_without_x25519,
    not_reached,
};

pub const FrontingCheckResult = enum {
    skipped,
    ok,
    not_reached,
    mismatch,
};

/// Classify an `openssl s_client` transcript. Assumes the hello offered
/// `X25519MLKEM768:X25519`, so a printed "Server Temp Key" is one of those two
/// groups: X25519MLKEM768 → post-quantum (good), otherwise x25519 (the iOS marker).
/// A domain that HRRs / rejects both never prints a temp key.
pub fn classifyOpenSslOutput(output: []const u8) FrontingVerdict {
    if (std.mem.indexOf(u8, output, "Server Temp Key") != null) {
        // OpenSSL 3.5+ prints the hybrid group as "X25519MLKEM768".
        if (std.mem.indexOf(u8, output, "MLKEM") != null) return .pq_capable;
        return .single_round_x25519;
    }
    if (std.mem.indexOf(u8, output, "CONNECTED") != null) return .reachable_without_x25519;
    return .not_reached;
}

/// Best-effort warning if `domain` is a poor FakeTLS fronting target. Two things can
/// make it poor:
///   1. It negotiates only classical x25519, not X25519MLKEM768. Since June 2026 the
///      TSPU flags this as a passive marker and blocks iOS clients (and everyone on
///      their NAT IP). A genuinely post-quantum domain (0x11ec) is the safe target,
///      and our 3-record FakeTLS mimics it via the 0x11ec ServerHello key_share echo.
///   2. It does a HelloRetryRequest / prefers a non-x25519 group (e.g. wb.ru, mail.ru
///      pick secp521r1) — our single ServerHello can't replicate that at all.
pub fn warnIfPoorFrontingDomain(ui: *Tui, allocator: std.mem.Allocator, domain: []const u8) FrontingCheckResult {
    if (!isSafeFrontingDomain(domain)) return .skipped;
    if (!sys.commandExists("openssl")) return .skipped;

    ui.step("Checking fronting-domain TLS suitability...");

    // Probe as a modern client would: offer the post-quantum hybrid first, then plain
    // x25519. A PQ-capable server answers X25519MLKEM768; an x25519-only server still
    // connects and answers x25519 (the marked case). stderr is merged since OpenSSL
    // splits it differently across versions. Groups MUST be uppercase (OpenSSL 1.1.1
    // rejects lowercase).
    const verdict = runOpensslProbe(allocator, domain, "X25519MLKEM768:X25519") orelse .not_reached;
    if (verdict != .not_reached) return warnFromVerdict(ui, domain, verdict);

    // The modern probe didn't connect. Distinguish "domain unreachable" from "local
    // OpenSSL predates 3.5 / the domain rejected the hybrid offer" with a legacy
    // x25519-only probe — the same check we shipped before PQ existed.
    const legacy = runOpensslProbe(allocator, domain, "X25519") orelse .not_reached;
    if (legacy == .not_reached) return warnFromVerdict(ui, domain, .not_reached);

    var b: [360]u8 = undefined;
    if (std.fmt.bufPrint(&b, "Couldn't test X25519MLKEM768 for '{s}' (the domain rejected the hybrid offer, or this host's OpenSSL predates 3.5). It does single-round x25519 — since June 2026 that alone can mark iOS. Verify PQ support with @Sni_checker_bot.", .{domain}) catch null) |m| ui.info(m);
    return .not_reached;
}

/// Run one `openssl s_client` probe with the given `-groups` list. Returns null only
/// if the command couldn't be launched.
fn runOpensslProbe(allocator: std.mem.Allocator, domain: []const u8, groups: []const u8) ?FrontingVerdict {
    var cmd_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(
        &cmd_buf,
        "echo | timeout 10 openssl s_client -connect {s}:443 -servername {s} -groups {s} -tls1_3 2>&1",
        .{ domain, domain, groups },
    ) catch return null;
    const r = sys.exec(allocator, &.{ "bash", "-c", cmd }) catch return null;
    defer r.deinit();
    return classifyOpenSslOutput(r.stdout);
}

fn warnFromVerdict(ui: *Tui, domain: []const u8, verdict: FrontingVerdict) FrontingCheckResult {
    switch (verdict) {
        .pq_capable => {
            var b: [256]u8 = undefined;
            if (std.fmt.bufPrint(&b, "'{s}' negotiates X25519MLKEM768 (post-quantum) — a good fronting target, no iOS marker.", .{domain}) catch null) |m| ui.ok(m);
            return .ok;
        },
        .not_reached => {
            var b: [320]u8 = undefined;
            if (std.fmt.bufPrint(&b, "Couldn't reach '{s}:443' from here to verify its TLS — skipping (connectivity, not a bad domain).", .{domain}) catch null) |m| ui.info(m);
            return .not_reached;
        },
        .single_round_x25519 => {
            ui.warn("This fronting domain negotiates only classical x25519, not X25519MLKEM768.");
            var msg_buf: [360]u8 = undefined;
            if (std.fmt.bufPrint(&msg_buf, "  Since the June-2026 TSPU rollout a non-PQ domain is a passive marker: iOS clients (and everyone sharing their NAT IP) fronting '{s}' get blocked.", .{domain}) catch null) |m| ui.warn(m);
            ui.hint("  Prefer a domain that negotiates X25519MLKEM768 in one round. Verify: openssl s_client -groups X25519MLKEM768 -connect <domain>:443 (OpenSSL 3.5+), or @Sni_checker_bot. tls_domain is IMMUTABLE once links ship — choose now.");
            return .mismatch;
        },
        .reachable_without_x25519 => {
            var msg_buf: [360]u8 = undefined;
            if (std.fmt.bufPrint(&msg_buf, "  '{s}' does a HelloRetryRequest or prefers a non-x25519 group (like wb.ru/mail.ru → secp521r1) — our single-round FakeTLS ServerHello can't match it, so a passive observer sees a mismatch.", .{domain}) catch null) |m| ui.warn(m);
            ui.hint("  Prefer a domain that negotiates X25519MLKEM768 (or plain x25519) in one round. tls_domain is IMMUTABLE once links are shared — choose now.");
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

test "classifyOpenSslOutput detects post-quantum X25519MLKEM768" {
    const out =
        \\CONNECTED(00000003)
        \\Server Temp Key: X25519MLKEM768, 253 bits
    ;
    try std.testing.expectEqual(FrontingVerdict.pq_capable, classifyOpenSslOutput(out));
}

test "classifyOpenSslOutput flags a classical-x25519-only domain" {
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
