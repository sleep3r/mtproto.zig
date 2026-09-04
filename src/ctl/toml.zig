//! TOML reader/writer with format preservation for mtbuddy.
//!
//! Unlike src/config.zig (read-only parser for the proxy runtime),
//! this module preserves original formatting, comments, and whitespace
//! when modifying values — essential for a config management tool.

const std = @import("std");

pub const TomlDoc = struct {
    lines: std.ArrayListUnmanaged([]const u8) = .empty,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn load(allocator: std.mem.Allocator, path: []const u8) !Self {
        const io = std.Io.Threaded.global_single_threaded.io();
        const content = try std.Io.Dir.cwd().readFileAlloc(
            io,
            path,
            allocator,
            .limited(1024 * 1024),
        );
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
    ///
    /// Staged through `<path>.tmp` + rename(2) rather than written in place: `createFile`
    /// truncates the destination before the first byte lands, so an ENOSPC, an EIO or a
    /// kill mid-write left config.toml empty or half-written. That file is the ONLY copy of
    /// the `[access.users]` secrets — losing it kills every distributed link. rename is
    /// atomic within a filesystem, so a reader (or a crash) sees either the whole old file
    /// or the whole new one, a failed write leaves the original untouched, and the previous
    /// contents are kept one deep in `<path>.bak`.
    pub fn save(self: *Self, path: []const u8) !void {
        const io = std.Io.Threaded.global_single_threaded.io();
        const dir = std.Io.Dir.cwd();

        // Render before touching the filesystem: an allocation failure must not be able to
        // happen with the destination already replaced.
        var rendered: std.ArrayListUnmanaged(u8) = .empty;
        defer rendered.deinit(self.allocator);
        var last = self.lines.items.len;
        while (last > 0 and self.lines.items[last - 1].len == 0) last -= 1;
        for (self.lines.items[0..last]) |line| {
            try rendered.appendSlice(self.allocator, line);
            try rendered.append(self.allocator, '\n');
        }

        const tmp_path = try std.fmt.allocPrint(self.allocator, "{s}.tmp", .{path});
        defer self.allocator.free(tmp_path);

        // Read the current contents now, while they still exist, so the .bak below is the
        // document this save replaces and not the one it wrote.
        const previous: ?[]u8 = dir.readFileAlloc(io, path, self.allocator, .limited(1024 * 1024)) catch null;
        defer if (previous) |old| self.allocator.free(old);

        {
            errdefer dir.deleteFile(io, tmp_path) catch {};

            var file = try dir.createFile(io, tmp_path, .{
                .permissions = std.Io.File.Permissions.fromMode(0o640),
            });
            defer file.close(io);
            // config.toml carries [access.users] secrets and the FakeTLS identity.
            // Keep it 0640 (owner+group only) so unprivileged local accounts (e.g. the
            // www-data user this tool installs for masking) cannot read the proxy secrets.
            // createFile only sets the mode on creation, so also fchmod in case a stale
            // world-readable .tmp was left behind by an older build.
            file.setPermissions(io, std.Io.File.Permissions.fromMode(0o640)) catch {};
            // rename() installs a NEW inode, so the destination's owner has to be carried
            // over explicitly. The proxy runs as User=mtproto and reads config.toml 0640 —
            // a root:root replacement would make the service fail to start, and most
            // save() call sites do not chown afterwards.
            if (fileOwner(path)) |owner| file.setOwner(io, owner.uid, owner.gid) catch {};

            try file.writeStreamingAll(io, rendered.items);
            // Durability before the rename: without the fsync the directory entry can be
            // committed while the data is still in the page cache, and a host reset then
            // leaves a 0-length config.toml — exactly the loss the rename is here to avoid.
            try file.sync(io);
        }

        try dir.rename(tmp_path, dir, path, io);

        // Best-effort second copy. rename() rules out a torn write, but not mtbuddy itself
        // writing a document that dropped a user; one undo is cheap.
        if (previous) |old| {
            var bak_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const bak_path = std.fmt.bufPrint(&bak_buf, "{s}.bak", .{path}) catch return;
            dir.writeFile(io, .{
                .sub_path = bak_path,
                .data = old,
                .flags = .{ .permissions = std.Io.File.Permissions.fromMode(0o640) },
            }) catch {};
        }
    }

    /// Get a value by [section].key. Returns null if not found.
    /// Borrowed value: copy it before changing this document. Surrounding quotes are removed.
    pub fn get(self: *Self, section_name: []const u8, key: []const u8) ?[]const u8 {
        var in_section = false;
        var hdr_buf: [128]u8 = undefined;
        const target_header = sectionHeader(section_name, &hdr_buf);

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

    /// Write a raw TOML literal. Use setString for text. Invalidates borrowed get() values.
    pub fn setString(self: *Self, section_name: []const u8, key: []const u8, value: []const u8) !void {
        var encoded: std.Io.Writer.Allocating = .init(self.allocator);
        defer encoded.deinit();
        try std.json.Stringify.value(value, .{}, &encoded.writer);
        try self.set(section_name, key, encoded.written());
    }

    /// Set a raw TOML literal in [section].key, creating section/key if needed.
    pub fn set(self: *Self, section_name: []const u8, key: []const u8, value: []const u8) !void {
        var hdr_buf: [128]u8 = undefined;
        const target_header = sectionHeader(section_name, &hdr_buf);
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
                    const replacement = try formatKv(self.allocator, key, value);
                    self.allocator.free(self.lines.items[idx]);
                    self.lines.items[idx] = replacement;
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
        var hdr_buf: [128]u8 = undefined;
        try self.lines.append(self.allocator, try self.allocator.dupe(u8, sectionHeader(section_name, &hdr_buf)));
    }

    /// Add a key-value pair (must call addSection first).
    pub fn addKv(self: *Self, key: []const u8, value: []const u8) !void {
        try self.lines.append(self.allocator, try formatKv(self.allocator, key, value));
    }

    /// Add a key-value pair with a quoted string value.
    pub fn addKvStr(self: *Self, key: []const u8, value: []const u8) !void {
        var output: std.Io.Writer.Allocating = .init(self.allocator);
        defer output.deinit();
        try output.writer.print("{s} = ", .{key});
        // JSON string escaping is also valid for TOML basic strings.
        try std.json.Stringify.value(value, .{}, &output.writer);
        const owned = try self.allocator.dupe(u8, output.written());
        errdefer self.allocator.free(owned);
        try self.lines.append(self.allocator, owned);
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

/// Return the bracketed `[name]` form into `buf` (already-bracketed names pass through).
/// Previously unknown names were returned WITHOUT brackets, so e.g. doc.set("upstream.xray",
/// …) wrote a bracket-less `upstream.xray` line — invalid TOML that get() could never read
/// back and that duplicated on every write. Bracketing any name fixes all three.
fn sectionHeader(name: []const u8, buf: []u8) []const u8 {
    if (name.len > 0 and name[0] == '[') return name;
    return std.fmt.bufPrint(buf, "[{s}]", .{name}) catch name;
}

const Owner = struct {
    uid: std.posix.uid_t,
    gid: std.posix.gid_t,
};

/// Owner of an existing file, so `save()` can put it back on the replacement it renames
/// into place. Linux is mtbuddy's runtime target; on a dev host the owner is left alone
/// (everything there already belongs to the developer).
fn fileOwner(path: []const u8) ?Owner {
    if (@import("builtin").os.tag != .linux) return null;

    const path_z = std.posix.toPosixPath(path) catch return null;
    var stx: std.os.linux.Statx = undefined;
    const rc = std.os.linux.statx(std.os.linux.AT.FDCWD, &path_z, 0, .{ .UID = true, .GID = true }, &stx);
    if (std.os.linux.errno(rc) != .SUCCESS) return null;
    if (!stx.mask.UID or !stx.mask.GID) return null;
    return .{ .uid = stx.uid, .gid = stx.gid };
}

const KeyValue = struct {
    key: []const u8,
    value: []const u8,
};

fn parseKeyValue(line: []const u8) ?KeyValue {
    const eq_pos = std.mem.indexOfScalar(u8, line, '=') orelse return null;
    const raw_key = std.mem.trim(u8, line[0..eq_pos], &[_]u8{ ' ', '\t' });
    var raw_value = std.mem.trim(u8, line[eq_pos + 1 ..], &[_]u8{ ' ', '\t' });

    // Strip inline comment (find first # NOT inside quotes).
    //
    // Mirror the escape-aware logic from the runtime parser in src/config.zig
    // so that values containing escaped quotes (e.g. `"a \" b"`) don't
    // prematurely toggle the in_quotes state and truncate at a later `#`,
    // corrupting config.toml when mtbuddy rewrites it.
    var in_quotes = false;
    var escaped = false;
    var comment_pos: ?usize = null;
    for (raw_value, 0..) |c, ci| {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (in_quotes and c == '\\') {
            escaped = true;
            continue;
        }
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

/// Allocates rather than formatting through a fixed buffer: a 512-byte ceiling here
/// silently turned any longer value into error.OutOfMemory at the call site. That is not
/// theoretical — `[upstream.xray] links` holds the whole share-link array on one line, and
/// three VLESS-Reality links already exceed it, so a three-endpoint `setup egress` pool
/// failed to write ANY of its config.toml keys (including `[upstream] type = tunnel`).
fn formatKv(allocator: std.mem.Allocator, key: []const u8, value: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{s} = {s}", .{ key, value });
}

test "parseKeyValue: escaped quote does not truncate at a following '#'" {
    // Regression: the previous naive parser toggled in_quotes on every '"'
    // (even escaped ones), so `"a \" # b"` was read as `a \` + comment,
    // corrupting config.toml on save.
    const kv = parseKeyValue("secret = \"abc \\\" # def\"") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("secret", kv.key);
    try std.testing.expectEqualStrings("abc \\\" # def", kv.value);
}

test "parseKeyValue: inline comment stripped when outside quotes" {
    const kv = parseKeyValue("port = 443 # bind port") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("port", kv.key);
    try std.testing.expectEqualStrings("443", kv.value);
}

test "parseKeyValue: quoted '#' preserved" {
    const kv = parseKeyValue("secret = \"abc#def\"") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("abc#def", kv.value);
}

test "setString writes escaped TOML literals and set accepts an aliased value" {
    var doc = TomlDoc{ .allocator = std.testing.allocator };
    defer doc.deinit();
    try doc.setString("upstream", "type", "tunnel");
    try std.testing.expectEqualStrings("type = \"tunnel\"", doc.lines.items[2]);
    try doc.setString("upstream", "password", "quote\" and newline\n");
    try std.testing.expectEqualStrings("password = \"quote\\\" and newline\\n\"", doc.lines.items[3]);
    try doc.setString("upstream", "type", doc.get("upstream", "type").?);
    try std.testing.expectEqualStrings("tunnel", doc.get("upstream", "type").?);
}

test "set/get round-trips a dotted (non-allowlisted) section with brackets" {
    var doc = TomlDoc.initEmpty(std.testing.allocator);
    defer doc.deinit();

    try doc.set("upstream.xray", "links", "[\"vless://x\"]");
    // The written header must be valid bracketed TOML, and get() must read it back.
    const rendered = try doc.render(std.testing.allocator);
    defer std.testing.allocator.free(rendered);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "[upstream.xray]") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\nupstream.xray\n") == null);

    const v = doc.get("upstream.xray", "links") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("[\"vless://x\"]", v);

    // A second set must update in place, not duplicate the malformed header.
    try doc.set("upstream.xray", "links", "[]");
    var count: usize = 0;
    for (doc.lines.items) |line| {
        if (std.mem.eql(u8, std.mem.trim(u8, line, " \t\r"), "[upstream.xray]")) count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), count);
}

test "TomlDoc.set survives a value longer than the old fixed buffer" {
    // Regression: formatKv used a [512]u8 and reported error.OutOfMemory above it, which
    // aborted wireUpstreamTunnel for any egress pool of three or more share links.
    const a = std.testing.allocator;
    var doc = TomlDoc.initEmpty(a);
    defer doc.deinit();

    var long: std.ArrayListUnmanaged(u8) = .empty;
    defer long.deinit(a);
    try long.append(a, '[');
    for (0..3) |i| {
        if (i != 0) try long.append(a, ',');
        try long.append(a, '"');
        try long.appendSlice(a, "vless://95e0edb9-4a0b-4312-a71f-1d4b8b6db79b@154.59.110.32:443" ++
            "?type=tcp&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ++
            "&sni=www.microsoft.com&sid=0123456789abcdef&flow=xtls-rprx-vision#endpoint");
        try long.append(a, '"');
    }
    try long.append(a, ']');
    try std.testing.expect(long.items.len > 512);

    try doc.set("upstream.xray", "links", long.items);

    const rendered = try doc.render(a);
    defer a.free(rendered);
    try std.testing.expect(std.mem.indexOf(u8, rendered, long.items) != null);

    // And it is readable back in one piece.
    const read_back = doc.get("upstream.xray", "links") orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings(long.items, read_back);
}

test "TomlDoc.save keeps the replaced document in <path>.bak" {
    const a = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/config.toml", .{tmp.sub_path});

    const original = "[server]\nport = 443\n";
    try tmp.dir.writeFile(io, .{ .sub_path = "config.toml", .data = original });

    var doc = try TomlDoc.load(a, path);
    defer doc.deinit();
    try doc.set("server", "port", "8443");
    try doc.save(path);

    const saved = try tmp.dir.readFileAlloc(io, "config.toml", a, .limited(4096));
    defer a.free(saved);
    try std.testing.expect(std.mem.indexOf(u8, saved, "port = 8443") != null);

    const bak = try tmp.dir.readFileAlloc(io, "config.toml.bak", a, .limited(4096));
    defer a.free(bak);
    try std.testing.expectEqualStrings(original, bak);

    // A successful save must not leave the staging file behind.
    if (tmp.dir.access(io, "config.toml.tmp", .{})) |_| {
        return error.TestUnexpectedResult;
    } else |_| {}
}

test "TomlDoc.save leaves the destination intact when the staged write fails" {
    // Regression: save() opened the destination itself with createFile, which truncates it
    // to zero before a single byte of the new document is written — an ENOSPC or a kill in
    // that window destroyed the only copy of the [access.users] secrets.
    const a = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/config.toml", .{tmp.sub_path});

    const original = "[access.users]\nalice = \"deadbeef\"\n";
    try tmp.dir.writeFile(io, .{ .sub_path = "config.toml", .data = original });

    var doc = try TomlDoc.load(a, path);
    defer doc.deinit();
    try doc.set("access.users", "alice", "\"c0ffee\"");

    // A directory sitting on the staging path makes the write fail at exactly the point
    // where the old code had already emptied config.toml.
    try tmp.dir.createDir(io, "config.toml.tmp", .default_dir);
    if (doc.save(path)) |_| {
        return error.TestUnexpectedResult;
    } else |_| {}

    const survived = try tmp.dir.readFileAlloc(io, "config.toml", a, .limited(4096));
    defer a.free(survived);
    try std.testing.expectEqualStrings(original, survived);
}
