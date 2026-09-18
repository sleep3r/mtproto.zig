//! Operator-owned static public files, loaded once so the network loop never reads disk.
const std = @import("std");
const io = std.Io.Threaded.global_single_threaded.io();
const Entry = struct { path: []u8, body: []u8, mime: []const u8, etag: [64]u8 };
pub const Site = struct {
    entries: std.ArrayList(Entry) = .empty,
    pub fn deinit(self: *Site, a: std.mem.Allocator) void {
        for (self.entries.items) |entry| {
            a.free(entry.path);
            a.free(entry.body);
        }
        self.entries.deinit(a);
    }
    pub fn load(a: std.mem.Allocator, path: ?[]const u8) !Site {
        if (path == null) return .{};
        var dir = try std.Io.Dir.cwd().openDir(io, path.?, .{ .iterate = true });
        defer dir.close(io);
        return fromDir(a, dir);
    }
    pub fn fromDir(a: std.mem.Allocator, dir: std.Io.Dir) !Site {
        var opened = try dir.openDir(io, ".", .{ .iterate = true });
        defer opened.close(io);
        var walker = try opened.walk(a);
        defer {
            while (walker.inner.stack.items.len > 1) walker.leave(io);
            walker.deinit();
        }
        var self = Site{};
        errdefer self.deinit(a);
        var bytes: usize = 0;
        while (try walker.next(io)) |file| {
            if (file.kind == .directory) {
                if (file.depth() > 8 or file.basename[0] == '.') walker.leave(io);
                continue;
            }
            if (file.kind != .file) continue;
            if (self.entries.items.len >= 256 or file.path.len > 1024) return error.PublicSiteTooLarge;
            // Dotfiles and symlinks are never public. The walker does not follow symlinks.
            var parts = std.mem.splitScalar(u8, file.path, '/');
            var hidden = false;
            while (parts.next()) |part| {
                if (part.len > 0 and part[0] == '.') hidden = true;
            }
            if (hidden) continue;
            const body = try file.dir.readFileAlloc(io, file.basename, a, .limited(2 * 1024 * 1024));
            errdefer a.free(body);
            bytes += body.len;
            if (bytes > 16 * 1024 * 1024) return error.PublicSiteTooLarge;
            const name = try a.dupe(u8, file.path);
            errdefer a.free(name);
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(body, &digest, .{});
            try self.entries.append(a, .{ .path = name, .body = body, .mime = mime(file.path), .etag = std.fmt.bytesToHex(digest, .lower) });
        }
        return self;
    }
    pub fn find(self: *const Site, target: []const u8) ?*const Entry {
        if (target.len == 0 or target[0] != '/') return null;
        const path = if (std.mem.eql(u8, target, "/")) "index.html" else target[1..];
        for (self.entries.items) |*entry| {
            if (std.mem.eql(u8, path, entry.path)) return entry;
        }
        return null;
    }
};

test "public files retain operator bytes and exact routes without generated cover" {
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.writeFile(io, .{ .sub_path = "index.html", .data = "My real website" });
    try dir.dir.writeFile(io, .{ .sub_path = "style.css", .data = "body{}" });
    var site = try Site.fromDir(std.testing.allocator, dir.dir);
    defer site.deinit(std.testing.allocator);
    try std.testing.expect(site.find("/") != null);
    try std.testing.expectEqualStrings("My real website", site.find("/").?.body);
    try std.testing.expectEqualStrings("text/css; charset=utf-8", site.find("/style.css").?.mime);
    try std.testing.expect(site.find("/missing") == null);
    try std.testing.expect(site.find("/../index.html") == null);
    try std.testing.expect(site.find("/%2e%2e/index.html") == null);
}

test "no configured public directory creates no deployment fingerprint" {
    var site = try Site.load(std.testing.allocator, null);
    defer site.deinit(std.testing.allocator);
    try std.testing.expect(site.find("/") == null);
}

fn mime(path: []const u8) []const u8 {
    const ext = std.fs.path.extension(path);
    const types = .{
        .{ ".html", "text/html; charset=utf-8" },     .{ ".css", "text/css; charset=utf-8" },
        .{ ".js", "text/javascript; charset=utf-8" }, .{ ".json", "application/json" },
        .{ ".txt", "text/plain; charset=utf-8" },     .{ ".svg", "image/svg+xml" },
        .{ ".png", "image/png" },                     .{ ".jpg", "image/jpeg" },
        .{ ".jpeg", "image/jpeg" },                   .{ ".ico", "image/x-icon" },
        .{ ".webp", "image/webp" },                   .{ ".woff2", "font/woff2" },
    };
    inline for (types) |pair| {
        if (std.ascii.eqlIgnoreCase(ext, pair[0])) return pair[1];
    }
    return "application/octet-stream";
}
