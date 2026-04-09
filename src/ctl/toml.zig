//! TOML reader/writer with format preservation for mtbuddy.
//!
//! Unlike src/config.zig (read-only parser for the proxy runtime),
//! this module preserves original formatting, comments, and whitespace
//! when modifying values — essential for a config management tool.

const std = @import("std");

pub const TomlDoc = struct {
    lines: std.ArrayListUnmanaged([]const u8) = .{},
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn load(allocator: std.mem.Allocator, path: []const u8) !Self {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();
        const content = try file.readToEndAlloc(allocator, 1024 * 1024);
        defer allocator.free(content);

        var doc = Self{
            .allocator = allocator,
        };

        var line_iter = std.mem.splitScalar(u8, content, '\n');
        while (line_iter.next()) |line| {
            try doc.lines.append(allocator, try allocator.dupe(u8, line));
        }

        return doc;
    }

    pub fn deinit(self: *Self) void {
        for (self.lines.items) |line| {
            self.allocator.free(line);
        }
        self.lines.deinit(self.allocator);
    }

    /// Save the document back to a file.
    pub fn save(self: *Self, path: []const u8) !void {
        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        for (self.lines.items, 0..) |line, idx| {
            try file.writeAll(line);
            if (idx < self.lines.items.len - 1) {
                try file.writeAll("\n");
            }
        }
    }

    /// Get a value by [section].key. Returns null if not found.
    pub fn get(self: *Self, section_name: []const u8, key: []const u8) ?[]const u8 {
        var in_section = false;
        const target_header = sectionHeader(section_name);

        for (self.lines.items) |line| {
            const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r' });

            // Track sections
            if (trimmed.len > 0 and trimmed[0] == '[') {
                in_section = std.mem.eql(u8, trimmed, target_header);
                continue;
            }

            if (!in_section) continue;
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            // Parse key = value
            if (parseKeyValue(trimmed)) |kv| {
                if (std.mem.eql(u8, kv.key, key)) {
                    return kv.value;
                }
            }
        }

        return null;
    }

    /// Set a value in [section].key, creating section/key if needed.
    pub fn set(self: *Self, section_name: []const u8, key: []const u8, value: []const u8) !void {
        const target_header = sectionHeader(section_name);
        var in_section = false;
        var section_end: ?usize = null;

        for (self.lines.items, 0..) |line, idx| {
            const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r' });

            if (trimmed.len > 0 and trimmed[0] == '[') {
                if (in_section) {
                    // We just left our target section without finding the key
                    section_end = idx;
                    break;
                }
                in_section = std.mem.eql(u8, trimmed, target_header);
                continue;
            }

            if (!in_section) continue;
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            if (parseKeyValue(trimmed)) |kv| {
                if (std.mem.eql(u8, kv.key, key)) {
                    // Replace existing line
                    self.allocator.free(self.lines.items[idx]);
                    self.lines.items[idx] = try formatKv(self.allocator, key, value);
                    return;
                }
            }
        }

        // Key not found in section
        if (section_end) |end_idx| {
            // Insert before the next section header
            try self.lines.insert(self.allocator, end_idx, try formatKv(self.allocator, key, value));
        } else if (in_section) {
            // Section exists but key not found; append at end of file
            try self.lines.append(self.allocator, try formatKv(self.allocator, key, value));
        } else {
            // Section doesn't exist — create it
            try self.lines.append(self.allocator, try self.allocator.dupe(u8, ""));
            try self.lines.append(self.allocator, try self.allocator.dupe(u8, target_header));
            try self.lines.append(self.allocator, try formatKv(self.allocator, key, value));
        }
    }

    /// Build a TOML document from scratch.
    pub fn initEmpty(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
        };
    }

    /// Add a section header.
    pub fn addSection(self: *Self, section_name: []const u8) !void {
        if (self.lines.items.len > 0) {
            try self.lines.append(self.allocator, try self.allocator.dupe(u8, ""));
        }
        try self.lines.append(self.allocator, try self.allocator.dupe(u8, sectionHeader(section_name)));
    }

    /// Add a key-value pair (must call addSection first).
    pub fn addKv(self: *Self, key: []const u8, value: []const u8) !void {
        try self.lines.append(self.allocator, try formatKv(self.allocator, key, value));
    }

    /// Add a key-value pair with a quoted string value.
    pub fn addKvStr(self: *Self, key: []const u8, value: []const u8) !void {
        var buf: [512]u8 = undefined;
        const formatted = std.fmt.bufPrint(&buf, "{s} = \"{s}\"", .{ key, value }) catch return;
        try self.lines.append(self.allocator, try self.allocator.dupe(u8, formatted));
    }

    /// Render the full document as a string.
    pub fn render(self: *Self, allocator: std.mem.Allocator) ![]const u8 {
        var total_len: usize = 0;
        for (self.lines.items, 0..) |line, idx| {
            total_len += line.len;
            if (idx < self.lines.items.len - 1) total_len += 1; // newline
        }

        const result = try allocator.alloc(u8, total_len);
        var pos: usize = 0;
        for (self.lines.items, 0..) |line, idx| {
            @memcpy(result[pos..][0..line.len], line);
            pos += line.len;
            if (idx < self.lines.items.len - 1) {
                result[pos] = '\n';
                pos += 1;
            }
        }

        return result;
    }
};

// ── Helpers ─────────────────────────────────────────────────────

fn sectionHeader(name: []const u8) []const u8 {
    // Return comptime-known section headers for known section names
    if (std.mem.eql(u8, name, "server")) return "[server]";
    if (std.mem.eql(u8, name, "censorship")) return "[censorship]";
    if (std.mem.eql(u8, name, "general")) return "[general]";
    if (std.mem.eql(u8, name, "access.users")) return "[access.users]";
    if (std.mem.eql(u8, name, "access.direct_users")) return "[access.direct_users]";
    // Fallback: just return the name (caller is responsible for brackets)
    return name;
}

const KeyValue = struct {
    key: []const u8,
    value: []const u8,
};

fn parseKeyValue(line: []const u8) ?KeyValue {
    const eq_pos = std.mem.indexOfScalar(u8, line, '=') orelse return null;
    const raw_key = std.mem.trim(u8, line[0..eq_pos], &[_]u8{ ' ', '\t' });
    var raw_value = std.mem.trim(u8, line[eq_pos + 1 ..], &[_]u8{ ' ', '\t' });

    // Strip inline comment (find first # NOT inside quotes)
    var in_quotes = false;
    var comment_pos: ?usize = null;
    for (raw_value, 0..) |c, ci| {
        if (c == '"') {
            in_quotes = !in_quotes;
        } else if (c == '#' and !in_quotes) {
            comment_pos = ci;
            break;
        }
    }
    if (comment_pos) |cp| {
        raw_value = std.mem.trim(u8, raw_value[0..cp], &[_]u8{ ' ', '\t' });
    }

    // Strip quotes
    if (raw_value.len >= 2 and raw_value[0] == '"' and raw_value[raw_value.len - 1] == '"') {
        raw_value = raw_value[1 .. raw_value.len - 1];
    }

    return .{ .key = raw_key, .value = raw_value };
}

fn formatKv(allocator: std.mem.Allocator, key: []const u8, value: []const u8) ![]const u8 {
    var buf: [512]u8 = undefined;
    const formatted = std.fmt.bufPrint(&buf, "{s} = {s}", .{ key, value }) catch return error.OutOfMemory;
    return try allocator.dupe(u8, formatted);
}
