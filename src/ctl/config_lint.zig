//! Diagnostics for common TOML mistakes accepted by the legacy runtime parser.
//! This is a compatibility lint for mtbuddy, not a replacement TOML parser.
const std = @import("std");

pub const Problem = enum { unquoted_string, duplicate_section, duplicate_key, unterminated_string };
pub const Diagnostic = struct {
    line: usize,
    column: usize,
    problem: Problem,

    // Never include source values: these can contain passwords or user secrets.
    pub fn message(self: Diagnostic) []const u8 {
        return switch (self.problem) {
            .unquoted_string => "String value needs quotes. Use key = \"value\" (for example, public_ip = \"proxy.example.com\").",
            .duplicate_section => "Duplicate section. Move its settings into the existing section and remove the repeated header.",
            .duplicate_key => "Duplicate key. Keep only one definition of this key in the section.",
            .unterminated_string => "Unterminated string. Add the matching closing quote.",
        };
    }
};

pub fn check(allocator: std.mem.Allocator, content: []const u8) !?Diagnostic {
    var sections = std.StringHashMap(void).init(allocator);
    defer sections.deinit();
    var keys = std.StringHashMap(void).init(allocator);
    defer keys.deinit();
    var section: []const u8 = "";
    var lines = std.mem.splitScalar(u8, content, '\n');
    var line_number: usize = 0;
    while (lines.next()) |raw| {
        line_number += 1;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const column = @intFromPtr(line.ptr) - @intFromPtr(raw.ptr) + 1;
        const end = commentStart(line) orelse return .{ .line = line_number, .column = column, .problem = .unterminated_string };
        const text = std.mem.trimEnd(u8, line[0..end], " \t\r");
        if (text.len == 0) continue;
        if (text[0] == '[' and text[text.len - 1] == ']') {
            // Arrays of tables are outside the proxy's line-oriented config format.
            if (std.mem.startsWith(u8, text, "[[")) continue;
            section = std.mem.trim(u8, text[1 .. text.len - 1], " \t");
            const entry = try sections.getOrPut(section);
            if (entry.found_existing) return .{ .line = line_number, .column = column, .problem = .duplicate_section };
            keys.clearRetainingCapacity();
            continue;
        }
        const eq = std.mem.indexOfScalar(u8, text, '=') orelse continue;
        var key = std.mem.trim(u8, text[0..eq], " \t");
        if (key.len >= 2 and (key[0] == '"' or key[0] == '\'') and key[key.len - 1] == key[0]) key = key[1 .. key.len - 1];
        const entry = try keys.getOrPut(key);
        if (entry.found_existing) return .{ .line = line_number, .column = column, .problem = .duplicate_key };
        const value = std.mem.trim(u8, text[eq + 1 ..], " \t");
        if (value.len > 0 and value[0] != '"' and value[0] != '\'' and stringSetting(section, key)) {
            return .{ .line = line_number, .column = @intFromPtr(value.ptr) - @intFromPtr(raw.ptr) + 1, .problem = .unquoted_string };
        }
    }
    return null;
}

// Locate comments without mistaking a quoted # or an escaped quote for syntax.
fn commentStart(line: []const u8) ?usize {
    var quote: u8 = 0;
    var escaped = false;
    for (line, 0..) |c, i| {
        if (escaped) {
            escaped = false;
        } else if (quote == '"' and c == '\\') {
            escaped = true;
        } else if (quote != 0 and c == quote) {
            quote = 0;
        } else if (quote == 0) {
            if (c == '#') return i;
            if (c == '"' or c == '\'') quote = c;
        }
    }
    return if (quote == 0) line.len else null;
}

fn oneOf(value: []const u8, choices: []const []const u8) bool {
    for (choices) |choice| if (std.mem.eql(u8, value, choice)) return true;
    return false;
}

// Only schema-defined strings: do not guess types for unknown extension keys,
// dates, numbers or arrays. The runtime still supplies semantic validation.
fn stringSetting(section: []const u8, key: []const u8) bool {
    if (oneOf(section, &.{ "access.users", "access.disabled_users" })) return true;
    if (std.mem.eql(u8, section, "server")) return oneOf(key, &.{ "public_ip", "bind_address", "clock_sync_url", "tag", "middle_proxy_nat_ip", "log_level" });
    if (std.mem.eql(u8, section, "general")) return std.mem.eql(u8, key, "ad_tag");
    if (std.mem.eql(u8, section, "censorship")) return oneOf(key, &.{ "tls_domain", "mask_target", "unknown_sni_action" });
    if (oneOf(section, &.{ "metrics", "monitor" })) return std.mem.eql(u8, key, "host");
    if (std.mem.eql(u8, section, "web")) return oneOf(key, &.{ "domain", "listen", "host", "backend", "mask_backend", "cert", "key", "mode", "ws_path", "client_ip_header" });
    if (std.mem.eql(u8, section, "upstream")) return std.mem.eql(u8, key, "type");
    if (oneOf(section, &.{ "upstream.socks5", "upstream.http" })) return oneOf(key, &.{ "host", "username", "password" });
    if (std.mem.eql(u8, section, "upstream.tunnel")) return oneOf(key, &.{ "interface", "pinned_interface" });
    return false;
}

test "doctor catches unquoted public_ip with source location" {
    const issue = (try check(std.testing.allocator, "# config\n[server]\n  public_ip = tg.domain.ru\n")).?;
    try std.testing.expectEqual(Problem.unquoted_string, issue.problem);
    try std.testing.expectEqual(@as(usize, 3), issue.line);
    try std.testing.expectEqual(@as(usize, 15), issue.column);
}

test "doctor catches repeated sections and keys" {
    const cases = [_]struct { text: []const u8, problem: Problem }{
        .{ .text = "[server]\nport = 443\n[server] # again\n", .problem = .duplicate_section },
        .{ .text = "[server]\npublic_ip = 'a.example'\npublic_ip = 'b.example'\n", .problem = .duplicate_key },
        .{ .text = "[access.users]\nalice = '0123456789abcdef0123456789abcdef'\n\"alice\" = 'fedcba9876543210fedcba9876543210'\n", .problem = .duplicate_key },
    };
    for (cases) |case| {
        const issue = (try check(std.testing.allocator, case.text)).?;
        try std.testing.expectEqual(case.problem, issue.problem);
        try std.testing.expectEqual(@as(usize, 3), issue.line);
    }
}

test "doctor checks string settings beyond public_ip" {
    for ([_][]const u8{
        "[censorship]\ntls_domain = google.com\n",
        "[upstream.socks5]\npassword = private-secret\n",
        "[access.users]\nalice = 0123456789abcdef0123456789abcdef\n",
        "[metrics]\nhost = 127.0.0.1\n",
        "[web]\ncert = /etc/cert.pem\n",
    }) |content| {
        try std.testing.expectEqual(Problem.unquoted_string, (try check(std.testing.allocator, content)).?.problem);
    }
}

test "doctor accepts valid quoted strings comments arrays and separate table keys" {
    const content =
        \\[server] # main
        \\public_ip = "tg.domain.ru" # public address
        \\port = 443
        \\[upstream.socks5]
        \\host = 'localhost'
        \\port = 1080
        \\password = "a\"#;b" # comment
        \\[upstream.tunnel]
        \\interfaces = ["awg0", "wg0"]
        \\[upstream]
        \\type = "auto"
        \\allow_direct_fallback = false
    ;
    try std.testing.expectEqual(@as(?Diagnostic, null), try check(std.testing.allocator, content));
}

test "doctor locates unterminated strings without returning their contents" {
    const issue = (try check(std.testing.allocator, "[upstream.socks5]\npassword = \"private-secret\n")).?;
    try std.testing.expectEqual(Problem.unterminated_string, issue.problem);
    try std.testing.expectEqual(@as(usize, 2), issue.line);
}

test "doctor accepts TOML local dates for user expirations" {
    try std.testing.expectEqual(@as(?Diagnostic, null), try check(std.testing.allocator, "[access.user_expirations]\nalice = 2026-12-31\n"));
}
