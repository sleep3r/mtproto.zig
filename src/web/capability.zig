//! Bridge capability derivation and WEB-proxy hostname rules.
//!
//! Telegram Desktop never hands the MTProxy secret to JavaScript. Instead it derives a
//! domain-separated bearer token from `(hostname, secret)` and puts *that* in the page
//! URL it navigates the hidden WebView to:
//!
//!     context = "tdesktop-web-proxy-bridge-v1\n" + host
//!     bridge  = base64url-no-padding(HMAC-SHA256(key = secret_bytes, message = context))
//!     url     = "https://" + host + "/?bridge=" + bridge
//!
//! `secret_bytes` is the decoded MTProxy secret *including* its leading `dd` byte when
//! the link used the random-padding form — which ours always does, because tdesktop
//! rejects `ee` (FakeTLS) secrets for WEB proxies outright.
//!
//! Two things follow, and both are load-bearing for us:
//!
//!  1. Because we know every configured user secret, we can recompute the capability
//!     and learn *which user* is behind a bridge request without ever seeing the
//!     MTProto stream. Disabled/expired-user enforcement remains in the authenticated
//!     MTProto backend; capabilities are a startup snapshot, not live access policy.
//!  2. A visitor who cannot present a capability derived from a real secret never sees
//!     the bridge page at all — they get the ordinary cover site. An active prober
//!     without a valid user secret cannot distinguish this host from a plain website.
//!
//! Reference: tdesktop `Telegram/SourceFiles/mtproto/mtproto_proxy_data.cpp`
//! (`ComputeWebProxyBridgeCapability`, `NormalizeWebProxyHost`, `LastLabelIsNumeric`).

const std = @import("std");

/// Domain-separation prefix. The trailing newline is part of the context.
pub const context_prefix = "tdesktop-web-proxy-bridge-v1\n";

/// base64url of a 32-byte HMAC with padding omitted.
pub const capability_len: usize = 43;

/// tdesktop's `dd` random-padding secret marker. WEB links must use this form (or a
/// bare 16-byte secret); `ee` FakeTLS secrets are reported as `Status::Unsupported`.
pub const padded_marker: u8 = 0xdd;

/// Longest hostname `NormalizeWebProxyHost` will accept.
pub const max_host_len: usize = 253;

pub const Capability = [capability_len]u8;

/// Derive the bridge capability for `host` (already normalized) and raw `secret` bytes.
pub fn derive(host: []const u8, secret: []const u8) Capability {
    var mac_state = std.crypto.auth.hmac.sha2.HmacSha256.init(secret);
    mac_state.update(context_prefix);
    mac_state.update(host);
    var mac: [32]u8 = undefined;
    mac_state.final(&mac);

    var out: Capability = undefined;
    const encoded = std.base64.url_safe_no_pad.Encoder.encode(&out, &mac);
    std.debug.assert(encoded.len == capability_len);
    return out;
}

/// Derive the capability for a 16-byte user secret carried in a `dd…` WEB link.
pub fn deriveForPaddedSecret(host: []const u8, secret: [16]u8) Capability {
    var key: [17]u8 = undefined;
    key[0] = padded_marker;
    @memcpy(key[1..], &secret);
    return derive(host, &key);
}

/// Constant-time comparison of a presented capability against an expected one.
///
/// Presented capabilities come from an untrusted query string; comparing them in
/// constant time keeps the relay from leaking a per-user oracle through timing.
pub fn matches(presented: []const u8, expected: Capability) bool {
    if (presented.len != capability_len) return false;
    return std.crypto.timing_safe.eql([capability_len]u8, presented[0..capability_len].*, expected);
}

// ── hostname normalization ────────────────────────────────────────────────────

pub const HostError = error{
    /// Empty, or longer than 253 bytes.
    BadLength,
    /// Contains `:` `/` `?` `#` `@`, or a trailing dot.
    BadCharacters,
    /// Non-ASCII input. tdesktop maps Unicode hosts with whatever IDNA profile the Qt
    /// version it shipped uses, and the profiles disagree on deviation characters
    /// (`ß`, `ς`, ZWJ/ZWNJ) — a mismatch there silently changes the capability on some
    /// platforms. Operators must publish the ACE (`xn--…`) form, so we require it.
    NonAscii,
    /// A label was empty, over 63 bytes, hyphen-anchored, or held an illegal byte.
    BadLabel,
    /// Single-label name (no dot) — rejected by tdesktop.
    NotFullyQualified,
    /// An IP address or a WHATWG "ends in a number" shorthand (`127.1`, `0x7f.1`).
    IpLiteral,
};

/// Normalize and validate a WEB-proxy hostname exactly like `NormalizeWebProxyHost`,
/// writing the lowercase A-label form into `out` and returning that slice.
///
/// `out` must be at least `max_host_len` bytes.
pub fn normalizeHost(input: []const u8, out: []u8) HostError![]const u8 {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (trimmed.len == 0 or trimmed.len > max_host_len) return error.BadLength;
    if (trimmed[trimmed.len - 1] == '.') return error.BadCharacters;
    for (trimmed) |c| {
        switch (c) {
            ':', '/', '?', '#', '@' => return error.BadCharacters,
            else => {},
        }
        if (c >= 0x80) return error.NonAscii;
        if (c < 0x20 or c == 0x7f) return error.BadCharacters;
    }
    if (out.len < trimmed.len) return error.BadLength;

    for (trimmed, 0..) |c, i| out[i] = std.ascii.toLower(c);
    const host = out[0..trimmed.len];

    if (std.mem.indexOfScalar(u8, host, '.') == null) return error.NotFullyQualified;

    var labels = std.mem.splitScalar(u8, host, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return error.BadLabel;
        if (label[0] == '-' or label[label.len - 1] == '-') return error.BadLabel;
        for (label) |c| {
            const alnum = (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9');
            if (!alnum and c != '-') return error.BadLabel;
        }
    }

    if (lastLabelIsNumeric(host)) return error.IpLiteral;
    return host;
}

/// The WHATWG URL "ends in a number" rule: a final label of ASCII digits, or a
/// `0x`-prefixed hex label, means the host is really an IPv4 address in some
/// shorthand (`127.1`, `0x7f.1`, `0177.0.0.1`).
fn lastLabelIsNumeric(host: []const u8) bool {
    const dot = std.mem.lastIndexOfScalar(u8, host, '.');
    const label = if (dot) |d| host[d + 1 ..] else host;
    if (label.len == 0) return false;
    const hex = label.len >= 2 and label[0] == '0' and label[1] == 'x';
    const digits = if (hex) label[2..] else label;
    for (digits) |c| {
        const decimal = c >= '0' and c <= '9';
        const alpha = c >= 'a' and c <= 'f';
        if (!decimal and !(hex and alpha)) return false;
    }
    return true;
}

// ── tests ─────────────────────────────────────────────────────────────────────

test "bridge capability matches the normative tdesktop vectors" {
    // docs/web-proxy-plan.md §10, asserted in tdesktop's own debug build.
    const plain = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    try std.testing.expectEqualStrings(
        "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk",
        &derive("proxy.example.com", &plain),
    );
    try std.testing.expectEqualStrings(
        "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA",
        &deriveForPaddedSecret("proxy.example.com", plain),
    );
}

test "capability comparison is length-checked" {
    const secret = [_]u8{0xab} ** 16;
    const cap = deriveForPaddedSecret("proxy.example.com", secret);
    try std.testing.expect(matches(&cap, cap));
    try std.testing.expect(!matches(cap[0 .. capability_len - 1], cap));
    try std.testing.expect(!matches("", cap));
    var wrong = cap;
    wrong[0] = if (wrong[0] == 'A') 'B' else 'A';
    try std.testing.expect(!matches(&wrong, cap));
}

test "host normalization accepts and lowercases a real hostname" {
    var buf: [max_host_len]u8 = undefined;
    try std.testing.expectEqualStrings(
        "proxy.example.com",
        try normalizeHost(" Proxy.Example.COM ", &buf),
    );
    try std.testing.expectEqualStrings(
        "xn--strae-oqa.example",
        try normalizeHost("xn--strae-oqa.example", &buf),
    );
}

test "host normalization rejects what tdesktop rejects" {
    var buf: [max_host_len]u8 = undefined;
    try std.testing.expectError(error.NotFullyQualified, normalizeHost("localhost", &buf));
    try std.testing.expectError(error.IpLiteral, normalizeHost("127.0.0.1", &buf));
    try std.testing.expectError(error.IpLiteral, normalizeHost("127.1", &buf));
    try std.testing.expectError(error.IpLiteral, normalizeHost("0x7f.1", &buf));
    try std.testing.expectError(error.IpLiteral, normalizeHost("0177.0.0.1", &buf));
    try std.testing.expectError(error.IpLiteral, normalizeHost("1.2.3", &buf));
    try std.testing.expectError(error.BadCharacters, normalizeHost("site.example:443", &buf));
    try std.testing.expectError(error.BadCharacters, normalizeHost("site.example.", &buf));
    try std.testing.expectError(error.BadCharacters, normalizeHost("https://site.example", &buf));
    try std.testing.expectError(error.BadLabel, normalizeHost("site..example", &buf));
    try std.testing.expectError(error.BadLabel, normalizeHost("-site.example", &buf));
    try std.testing.expectError(error.BadLabel, normalizeHost("site-.example", &buf));
    try std.testing.expectError(error.BadLength, normalizeHost("   ", &buf));
    try std.testing.expectError(error.NonAscii, normalizeHost("bücher.example", &buf));
}

test "host normalization keeps a hex-looking label that is not last" {
    var buf: [max_host_len]u8 = undefined;
    try std.testing.expectEqualStrings("0x7f.example", try normalizeHost("0x7f.example", &buf));
}

test "capability changes with the hostname" {
    const secret = [_]u8{0x11} ** 16;
    const a = deriveForPaddedSecret("a.example", secret);
    const b = deriveForPaddedSecret("b.example", secret);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}
