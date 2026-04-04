//! Configuration loading for MTProto proxy.
//!
//! Parses a simplified TOML config with user secrets and server settings.
//! Format is compatible with the Rust telemt config.toml.

const std = @import("std");

pub const Config = struct {
    pub const UserSecret = struct { name: []const u8, secret: [16]u8 };

    /// Route regular DC traffic via Telegram MiddleProxy transport.
    /// Mirrors telemt's [general].use_middle_proxy behavior.
    use_middle_proxy: bool = false,
    port: u16 = 443,
    /// TCP listen(2) backlog for client-facing sockets
    backlog: u32 = 4096,
    /// Hard cap for concurrently handled client connections
    max_connections: u32 = 65535,
    /// Per-connection thread stack size in KiB (minimum 256)
    thread_stack_kb: u32 = 256,
    /// Pre-handshake idle timeout: wait for first client byte
    idle_timeout_sec: u32 = 300,
    /// Handshake read timeout after first byte arrives
    handshake_timeout_sec: u32 = 60,
    tag: ?[16]u8 = null,
    tls_domain: []const u8 = "google.com",
    users: std.StringHashMap([16]u8),
    /// Whether to mask bad clients (forward to tls_domain)
    mask: bool = true,
    /// Test-only hook to override the mask port
    mask_port: u16 = 443,
    /// TCP desync: split ServerHello into 1-byte + rest to evade DPI
    desync: bool = true,
    /// Dynamic Record Sizing: ramp TLS records from 1369→16384 bytes
    drs: bool = false,
    /// Fast mode: skip S2C encryption by passing client keys to DC directly
    fast_mode: bool = false,
    /// Per-connection MiddleProxy stream buffers size, in KiB (applies to 4 buffers)
    middleproxy_buffer_kb: u32 = 256,
    /// Test-only hook to redirect upstream connections locally
    datacenter_override: ?std.net.Address = null,

    pub fn middleProxyBufferBytes(self: *const Config) usize {
        return @as(usize, self.middleproxy_buffer_kb) * 1024;
    }

    pub fn threadStackBytes(self: *const Config) usize {
        return @as(usize, self.thread_stack_kb) * 1024;
    }

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
        var in_general_section = false;
        var server_tag_set = false;

        while (lines.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, &[_]u8{ ' ', '\t', '\r' });

            // Skip empty lines and comments
            if (line.len == 0 or line[0] == '#') continue;

            // Section headers
            if (line[0] == '[') {
                in_users_section = std.mem.eql(u8, line, "[access.users]");
                in_censorship_section = std.mem.eql(u8, line, "[censorship]");
                in_server_section = std.mem.eql(u8, line, "[server]");
                in_general_section = std.mem.eql(u8, line, "[general]");
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
                } else if (in_general_section) {
                    if (std.mem.eql(u8, key, "use_middle_proxy")) {
                        cfg.use_middle_proxy = std.mem.eql(u8, value, "true");
                    } else if (std.mem.eql(u8, key, "fast_mode")) {
                        // telemt compatibility: [general].fast_mode
                        cfg.fast_mode = std.mem.eql(u8, value, "true");
                    } else if (std.mem.eql(u8, key, "ad_tag")) {
                        // telemt compatibility: [general].ad_tag
                        // If [server].tag is present and valid, it has priority.
                        if (!server_tag_set and value.len == 32) {
                            var tag: [16]u8 = undefined;
                            if (std.fmt.hexToBytes(&tag, value)) |_| {
                                cfg.tag = tag;
                            } else |_| {}
                        }
                    }
                } else if (in_server_section) {
                    if (std.mem.eql(u8, key, "port")) {
                        cfg.port = std.fmt.parseInt(u16, value, 10) catch 443;
                    } else if (std.mem.eql(u8, key, "backlog")) {
                        cfg.backlog = std.fmt.parseInt(u32, value, 10) catch 4096;
                    } else if (std.mem.eql(u8, key, "max_connections")) {
                        const parsed = std.fmt.parseInt(u32, value, 10) catch cfg.max_connections;
                        cfg.max_connections = @max(@as(u32, 32), parsed);
                    } else if (std.mem.eql(u8, key, "thread_stack_kb")) {
                        const parsed = std.fmt.parseInt(u32, value, 10) catch cfg.thread_stack_kb;
                        cfg.thread_stack_kb = @max(@as(u32, 256), parsed);
                    } else if (std.mem.eql(u8, key, "idle_timeout_sec")) {
                        const parsed = std.fmt.parseInt(u32, value, 10) catch cfg.idle_timeout_sec;
                        cfg.idle_timeout_sec = @max(@as(u32, 5), parsed);
                    } else if (std.mem.eql(u8, key, "handshake_timeout_sec")) {
                        const parsed = std.fmt.parseInt(u32, value, 10) catch cfg.handshake_timeout_sec;
                        cfg.handshake_timeout_sec = @max(@as(u32, 5), parsed);
                    } else if (std.mem.eql(u8, key, "tag")) {
                        if (value.len == 32) {
                            var tag: [16]u8 = undefined;
                            if (std.fmt.hexToBytes(&tag, value)) |_| {
                                cfg.tag = tag;
                                server_tag_set = true;
                            } else |_| {}
                        }
                    } else if (std.mem.eql(u8, key, "fast_mode")) {
                        cfg.fast_mode = std.mem.eql(u8, value, "true");
                    } else if (std.mem.eql(u8, key, "middleproxy_buffer_kb")) {
                        const parsed = std.fmt.parseInt(u32, value, 10) catch cfg.middleproxy_buffer_kb;
                        cfg.middleproxy_buffer_kb = @max(@as(u32, 64), parsed);
                    }
                } else if (in_censorship_section) {
                    if (std.mem.eql(u8, key, "tls_domain")) {
                        cfg.tls_domain = try allocator.dupe(u8, value);
                    } else if (std.mem.eql(u8, key, "mask")) {
                        cfg.mask = std.mem.eql(u8, value, "true");
                    } else if (std.mem.eql(u8, key, "mask_port")) {
                        cfg.mask_port = std.fmt.parseInt(u16, value, 10) catch 443;
                    } else if (std.mem.eql(u8, key, "desync")) {
                        cfg.desync = std.mem.eql(u8, value, "true");
                    } else if (std.mem.eql(u8, key, "drs")) {
                        cfg.drs = std.mem.eql(u8, value, "true");
                    } else if (std.mem.eql(u8, key, "fast_mode")) {
                        cfg.fast_mode = std.mem.eql(u8, value, "true");
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
    pub fn getUserSecrets(self: *const Config, allocator: std.mem.Allocator) ![]const UserSecret {
        var list: std.ArrayList(UserSecret) = .empty;
        var it = @constCast(&self.users).iterator();
        while (it.next()) |entry| {
            try list.append(allocator, .{
                .name = entry.key_ptr.*,
                .secret = entry.value_ptr.*,
            });
        }
        return try list.toOwnedSlice(allocator);
    }
};

// ============= Tests =============

test "parse config - valid complete" {
    const content =
        \\[general]
        \\use_middle_proxy = true
        \\
        \\[server]
        \\port = 8443
        \\backlog = 8192
        \\max_connections = 6000
        \\thread_stack_kb = 320
        \\idle_timeout_sec = 180
        \\handshake_timeout_sec = 30
        \\fast_mode = true
        \\
        \\[censorship]
        \\tls_domain = "example.com"
        \\mask = true
        \\desync = true
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
        \\bob = "ffeeddccbbaa99887766554433221100"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 8443), cfg.port);
    try std.testing.expectEqual(@as(u32, 8192), cfg.backlog);
    try std.testing.expectEqual(@as(u32, 6000), cfg.max_connections);
    try std.testing.expectEqual(@as(u32, 320), cfg.thread_stack_kb);
    try std.testing.expectEqual(@as(u32, 180), cfg.idle_timeout_sec);
    try std.testing.expectEqual(@as(u32, 30), cfg.handshake_timeout_sec);
    try std.testing.expectEqualStrings("example.com", cfg.tls_domain);
    try std.testing.expect(cfg.use_middle_proxy);
    try std.testing.expect(cfg.mask);
    try std.testing.expect(cfg.desync);
    try std.testing.expect(cfg.fast_mode);
    try std.testing.expectEqual(@as(usize, 2), cfg.users.count());

    const alice_secret = cfg.users.get("alice").?;
    try std.testing.expectEqual([_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, alice_secret);
}

test "parse config - missing fields defaults" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 443), cfg.port);
    try std.testing.expectEqual(@as(u32, 4096), cfg.backlog); // Default is 4096
    try std.testing.expectEqual(@as(u32, 65535), cfg.max_connections);
    try std.testing.expectEqual(@as(u32, 256), cfg.thread_stack_kb);
    try std.testing.expectEqual(@as(u32, 300), cfg.idle_timeout_sec);
    try std.testing.expectEqual(@as(u32, 60), cfg.handshake_timeout_sec);
    try std.testing.expectEqualStrings("google.com", cfg.tls_domain);
    try std.testing.expect(!cfg.use_middle_proxy); // Default is false
    try std.testing.expect(cfg.mask); // Default is true
    try std.testing.expect(cfg.desync); // Default is true
    try std.testing.expect(!cfg.fast_mode); // Default is false
    try std.testing.expectEqual(@as(u32, 256), cfg.middleproxy_buffer_kb);
    try std.testing.expectEqual(@as(usize, 256 * 1024), cfg.middleProxyBufferBytes());
    try std.testing.expectEqual(@as(usize, 1), cfg.users.count());
}

test "parse config - middleproxy buffer size" {
    const content =
        \\[server]
        \\middleproxy_buffer_kb = 192
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 192), cfg.middleproxy_buffer_kb);
    try std.testing.expectEqual(@as(usize, 192 * 1024), cfg.middleProxyBufferBytes());
}

test "parse config - middleproxy buffer lower bound" {
    const content =
        \\[server]
        \\middleproxy_buffer_kb = 16
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 64), cfg.middleproxy_buffer_kb);
}

test "parse config - server runtime tunables lower bounds" {
    const content =
        \\[server]
        \\max_connections = 1
        \\thread_stack_kb = 16
        \\idle_timeout_sec = 1
        \\handshake_timeout_sec = 1
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 32), cfg.max_connections);
    try std.testing.expectEqual(@as(u32, 256), cfg.thread_stack_kb);
    try std.testing.expectEqual(@as(u32, 5), cfg.idle_timeout_sec);
    try std.testing.expectEqual(@as(u32, 5), cfg.handshake_timeout_sec);
}

test "parse config - spaces and tabs" {
    const content =
        \\[server]
        \\  port   =   9999   
        \\[censorship]
        \\  tls_domain= "test.com"  
        \\[access.users]
        \\  user  = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 9999), cfg.port);
    try std.testing.expectEqualStrings("test.com", cfg.tls_domain);
    try std.testing.expect(cfg.users.contains("user"));
}

test "parse config - invalid hex secret skipped" {
    const content =
        \\[access.users]
        \\valid = "00112233445566778899aabbccddeeff"
        \\invalid_len = "001122"
        \\invalid_hex = "zz112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), cfg.users.count());
    try std.testing.expect(cfg.users.contains("valid"));
}

test "parse config - getUserSecrets" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;
    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    const secrets = try cfg.getUserSecrets(std.testing.allocator);
    defer std.testing.allocator.free(secrets);

    try std.testing.expectEqual(@as(usize, 1), secrets.len);
    try std.testing.expectEqualStrings("alice", secrets[0].name);
}

test "parse config - tag parsing" {
    const content =
        \\[server]
        \\port = 443
        \\tag = 1234567890abcdef1234567890abcdef
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.tag != null);
    const expected_tag = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    try std.testing.expectEqual(expected_tag, cfg.tag.?);
}

test "parse config - tag default null" {
    const content =
        \\[server]
        \\port = 443
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.tag == null);
}

test "parse config - invalid tag ignored" {
    const content =
        \\[server]
        \\tag = tooshort
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.tag == null);
}

test "parse config - general ad_tag alias" {
    const content =
        \\[general]
        \\ad_tag = "1234567890abcdef1234567890abcdef"
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.tag != null);
    const expected_tag = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    try std.testing.expectEqual(expected_tag, cfg.tag.?);
}

test "parse config - server tag overrides general ad_tag" {
    const content =
        \\[general]
        \\ad_tag = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        \\
        \\[server]
        \\tag = "1234567890abcdef1234567890abcdef"
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.tag != null);
    const expected_tag = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    try std.testing.expectEqual(expected_tag, cfg.tag.?);
}
