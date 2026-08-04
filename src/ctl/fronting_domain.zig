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
/// `X25519MLKEM768:X25519`, so a successfully negotiated group is one of those two:
/// X25519MLKEM768 → post-quantum (good), plain x25519 → the iOS marker. A domain
/// that HRRs / shares neither group negotiates nothing at all.
///
/// Two output shapes have to be handled, because they differ by OpenSSL build:
///   - "Server Temp Key: <group>"        — the classic line.
///   - "Negotiated TLS1.3 group: <group>" — OpenSSL 3.5.x (verified on 3.5.5 /
///     Ubuntu 26.04) prints this and, for an ML-KEM hybrid, no "Server Temp Key".
///
/// The *value* is what matters, not the presence of the line: when the server shares
/// no group with our offer, OpenSSL still prints the line but completes it with
/// "<NULL>" and the handshake yields "Cipher is (NONE)". Verified live: wb.ru and
/// mail.ru (which prefer secp521r1) both report "Negotiated TLS1.3 group: <NULL>".
/// Keying off the line's presence alone would mislabel those as single-round x25519.
pub fn classifyOpenSslOutput(output: []const u8) FrontingVerdict {
    if (lineValue(output, "Negotiated TLS1.3 group:")) |group| {
        if (std.mem.indexOf(u8, group, "MLKEM") != null) return .pq_capable;
        if (std.ascii.indexOfIgnoreCase(group, "x25519") != null) return .single_round_x25519;
        // "<NULL>" (or a group we never offered): our single-round ServerHello can't
        // reproduce this handshake at all.
        return if (std.mem.indexOf(u8, output, "CONNECTED") != null)
            .reachable_without_x25519
        else
            .not_reached;
    }
    if (std.mem.indexOf(u8, output, "Server Temp Key") != null) {
        if (std.mem.indexOf(u8, output, "MLKEM") != null) return .pq_capable;
        return .single_round_x25519;
    }
    if (std.mem.indexOf(u8, output, "CONNECTED") != null) return .reachable_without_x25519;
    return .not_reached;
}

/// Text following `needle` up to the end of that line, trimmed. Null if absent.
fn lineValue(output: []const u8, needle: []const u8) ?[]const u8 {
    const start = std.mem.indexOf(u8, output, needle) orelse return null;
    const rest = output[start + needle.len ..];
    const line = rest[0 .. std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len];
    return std.mem.trim(u8, line, " \t\r");
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

test "classifyOpenSslOutput detects post-quantum via 'Negotiated TLS1.3 group' (no Server Temp Key line)" {
    // Verbatim shape from ozon.ru on OpenSSL 3.5.5 (Ubuntu 26.04): this build prints
    // no "Server Temp Key" for an ML-KEM hybrid, so matching only that line reported a
    // genuinely PQ-capable domain as reachable_without_x25519 — exactly backwards.
    const out =
        \\CONNECTED(00000003)
        \\Peer signing digest: SHA256
        \\Negotiated TLS1.3 group: X25519MLKEM768
        \\---
        \\New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    ;
    try std.testing.expectEqual(FrontingVerdict.pq_capable, classifyOpenSslOutput(out));
}

test "classifyOpenSslOutput flags classical x25519 via 'Negotiated TLS1.3 group'" {
    const out =
        \\CONNECTED(00000003)
        \\Negotiated TLS1.3 group: X25519
        \\---
    ;
    try std.testing.expectEqual(FrontingVerdict.single_round_x25519, classifyOpenSslOutput(out));
}

test "classifyOpenSslOutput treats a '<NULL>' negotiated group as no usable x25519" {
    // Verbatim shape from wb.ru / mail.ru on OpenSSL 3.5.5: they prefer secp521r1, share
    // no group with our offer, and the handshake yields no cipher — yet the line is still
    // printed. Presence alone must not be read as a successful x25519 negotiation.
    const out =
        \\CONNECTED(00000003)
        \\no peer certificate available
        \\Negotiated TLS1.3 group: <NULL>
        \\---
        \\New, (NONE), Cipher is (NONE)
    ;
    try std.testing.expectEqual(FrontingVerdict.reachable_without_x25519, classifyOpenSslOutput(out));
}
