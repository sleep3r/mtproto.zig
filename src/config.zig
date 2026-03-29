//! Configuration loading for MTProto proxy.
//!
//! Parses a simplified TOML config with user secrets and server settings.
//! Format is compatible with the Rust telemt config.toml.

const std = @import("std");

pub const Config = struct {
    port: u16 = 443,
    tls_domain: []const u8 = "google.com",
    users: std.StringHashMap([16]u8),
    /// Whether to mask bad clients (forward to tls_domain)
    mask: bool = true,
    /// Fast mode: skip S2C encryption by passing client keys to DC directly
    fast_mode: bool = false,

    pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !Config {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();
        const content = try file.readToEndAlloc(allocator, 1024 * 1024);
        defer allocator.free(content);
        return parse(allocator, content);
    }

    pub fn parse(allocator: std.mem.Allocator, content: []const u8) !Config {
        var cfg = Config{
            .users = std.StringHashMap([16]u8).init(allocator),
        };

        var lines = std.mem.splitScalar(u8, content, '\n');
        var in_users_section = false;
        var in_censorship_section = false;
        var in_server_section = false;

        while (lines.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, &[_]u8{ ' ', '\t', '\r' });

            // Skip empty lines and comments
            if (line.len == 0 or line[0] == '#') continue;

            // Section headers
            if (line[0] == '[') {
                in_users_section = std.mem.eql(u8, line, "[access.users]");
                in_censorship_section = std.mem.eql(u8, line, "[censorship]");
                in_server_section = std.mem.eql(u8, line, "[server]");
                continue;
            }

            // Key = value parsing
            if (std.mem.indexOfScalar(u8, line, '=')) |eq_pos| {
                const key = std.mem.trim(u8, line[0..eq_pos], &[_]u8{ ' ', '\t' });
                var value = std.mem.trim(u8, line[eq_pos + 1 ..], &[_]u8{ ' ', '\t' });

                // Strip quotes from value
                if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                    value = value[1 .. value.len - 1];
                }

                if (in_users_section) {
                    // Parse user secret (32 hex chars = 16 bytes)
                    if (value.len != 32) continue;
                    var secret: [16]u8 = undefined;
                    _ = std.fmt.hexToBytes(&secret, value) catch continue;
                    const name = try allocator.dupe(u8, key);
                    try cfg.users.put(name, secret);
                } else if (in_server_section) {
                    if (std.mem.eql(u8, key, "port")) {
                        cfg.port = std.fmt.parseInt(u16, value, 10) catch 443;
                    } else if (std.mem.eql(u8, key, "fast_mode")) {
                        cfg.fast_mode = std.mem.eql(u8, value, "true");
                    }
                } else if (in_censorship_section) {
                    if (std.mem.eql(u8, key, "tls_domain")) {
                        cfg.tls_domain = try allocator.dupe(u8, value);
                    } else if (std.mem.eql(u8, key, "mask")) {
                        cfg.mask = std.mem.eql(u8, value, "true");
                    }
                }
            }
        }

        return cfg;
    }

    pub fn deinit(self: *const Config, allocator: std.mem.Allocator) void {
        var users = @constCast(&self.users);
        var it = users.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        users.deinit();
        // Free tls_domain if it was allocated (not the default)
        if (!std.mem.eql(u8, self.tls_domain, "google.com")) {
            allocator.free(self.tls_domain);
        }
    }

    /// Get user secrets as a flat slice for handshake validation.
    pub fn getUserSecrets(self: *const Config, allocator: std.mem.Allocator) ![]const struct { name: []const u8, secret: [16]u8 } {
        const Entry = struct { name: []const u8, secret: [16]u8 };
        var list = std.ArrayList(Entry).init(allocator);
        var it = @constCast(&self.users).iterator();
        while (it.next()) |entry| {
            try list.append(.{
                .name = entry.key_ptr.*,
                .secret = entry.value_ptr.*,
            });
        }
        return try list.toOwnedSlice();
    }
};

// ============= Tests =============

test "parse config" {
    const content =
        \\[server]
        \\port = 8443
        \\fast_mode = false
        \\
        \\[censorship]
        \\tls_domain = "example.com"
        \\mask = true
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
        \\bob = "ffeeddccbbaa99887766554433221100"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 8443), cfg.port);
    try std.testing.expectEqualStrings("example.com", cfg.tls_domain);
    try std.testing.expect(cfg.mask);
    try std.testing.expect(!cfg.fast_mode);
    try std.testing.expectEqual(@as(usize, 2), cfg.users.count());

    const alice_secret = cfg.users.get("alice").?;
    try std.testing.expectEqual(@as(u8, 0x00), alice_secret[0]);
    try std.testing.expectEqual(@as(u8, 0xff), alice_secret[15]);
}
