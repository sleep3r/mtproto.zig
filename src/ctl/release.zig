//! Shared GitHub Releases helpers for install and update commands.
//!
//! Centralises tag resolution, artifact download with architecture-aware
//! candidate selection, binary validation, and temp-directory cleanup.
//! Used by both install.zig and update.zig to avoid duplication.

const std = @import("std");
const sys = @import("sys.zig");

// ── Shared constants ────────────────────────────────────────────

pub const REPO_OWNER = "sleep3r";
pub const REPO_NAME = "mtproto.zig";
pub const INSTALL_DIR = "/opt/mtproto-proxy";
pub const SERVICE_NAME = "mtproto-proxy";
pub const SERVICE_FILE = "/etc/systemd/system/mtproto-proxy.service";

const RELEASES_API = "https://api.github.com/repos/" ++ REPO_OWNER ++ "/" ++ REPO_NAME ++ "/releases/latest";
const RAW_BASE = "https://raw.githubusercontent.com/" ++ REPO_OWNER ++ "/" ++ REPO_NAME ++ "/";

// ── Result types ────────────────────────────────────────────────

/// Storage for a resolved release tag (e.g. "v0.12.0").
pub const Tag = struct {
    buf: [64]u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const Tag) []const u8 {
        return self.buf[0..self.len];
    }
};

/// Paths produced during artifact download. Owns all buffer storage.
pub const Artifact = struct {
    /// Temp extraction directory (e.g. "/tmp/mtproto-install-v0.12.0").
    extract_dir_buf: [128]u8 = undefined,
    extract_dir_len: usize = 0,
    /// Full path to the validated binary inside extract_dir.
    binary_path_buf: [256]u8 = undefined,
    binary_path_len: usize = 0,
    /// Path to the downloaded .tar.gz file.
    dl_path_buf: [256]u8 = undefined,
    dl_path_len: usize = 0,
    /// Name of the selected release asset (comptime-known string literal).
    asset_name: []const u8 = "",

    pub fn extractDir(self: *const Artifact) []const u8 {
        return self.extract_dir_buf[0..self.extract_dir_len];
    }

    pub fn binaryPath(self: *const Artifact) []const u8 {
        return self.binary_path_buf[0..self.binary_path_len];
    }

    pub fn dlPath(self: *const Artifact) []const u8 {
        return self.dl_path_buf[0..self.dl_path_len];
    }
};

// ── Public API ──────────────────────────────────────────────────

/// Resolve a release tag: normalise provided version or fetch latest.
/// Returns true on success (tag is populated), false on failure.
pub fn resolveTag(
    allocator: std.mem.Allocator,
    version: ?[]const u8,
    tag: *Tag,
) bool {
    if (version) |v| {
        if (v.len == 0) return resolveLatest(allocator, tag);
        if (v[0] != 'v') {
            tag.buf[0] = 'v';
            const n = @min(v.len, tag.buf.len - 1);
            @memcpy(tag.buf[1..][0..n], v[0..n]);
            tag.len = n + 1;
        } else {
            const n = @min(v.len, tag.buf.len);
            @memcpy(tag.buf[0..n], v[0..n]);
            tag.len = n;
        }
        return true;
    }
    return resolveLatest(allocator, tag);
}

/// Download, extract, and validate a proxy binary from GitHub Releases.
///
/// Detects CPU architecture and tries optimised builds first (x86_64_v3),
/// falling back to the base build. Validates the downloaded binary can
/// execute on this CPU (catches SIGILL from unsupported instructions).
///
/// `label` is used in the temp directory name (e.g. "install", "update").
/// Returns true on success (artifact is populated), false on failure.
pub fn downloadProxyArtifact(
    allocator: std.mem.Allocator,
    tag: []const u8,
    label: []const u8,
    artifact: *Artifact,
) bool {
    // ── Detect architecture ──
    const arch = sys.getArch() catch return false;
    const supports_v3 = if (arch == .x86_64) sys.supportsV3(allocator) else false;

    // ── Build candidate list ──
    const candidates: []const []const u8 = if (supports_v3)
        &[_][]const u8{ "mtproto-proxy-linux-x86_64_v3", "mtproto-proxy-linux-x86_64" }
    else if (arch == .aarch64)
        &[_][]const u8{"mtproto-proxy-linux-aarch64"}
    else
        &[_][]const u8{"mtproto-proxy-linux-x86_64"};

    // ── Prepare extraction directory ──
    const extract_dir = std.fmt.bufPrint(
        &artifact.extract_dir_buf,
        "/tmp/mtproto-{s}-{s}",
        .{ label, tag },
    ) catch return false;
    artifact.extract_dir_len = extract_dir.len;

    _ = sys.exec(allocator, &.{ "rm", "-rf", extract_dir }) catch {};
    _ = sys.exec(allocator, &.{ "mkdir", "-p", extract_dir }) catch {};

    // ── Try each candidate ──
    for (candidates) |candidate| {
        var url_buf: [512]u8 = undefined;
        const url = std.fmt.bufPrint(
            &url_buf,
            "https://github.com/{s}/{s}/releases/download/{s}/{s}.tar.gz",
            .{ REPO_OWNER, REPO_NAME, tag, candidate },
        ) catch continue;

        const dl_path = std.fmt.bufPrint(
            &artifact.dl_path_buf,
            "/tmp/{s}.tar.gz",
            .{candidate},
        ) catch continue;
        artifact.dl_path_len = dl_path.len;

        // Download
        const dl = sys.exec(allocator, &.{ "curl", "-fsSL", url, "-o", dl_path }) catch continue;
        defer dl.deinit();
        if (dl.exit_code != 0) continue;

        // Extract
        const tar_exit = sys.execForward(&.{ "tar", "-xzf", dl_path, "-C", extract_dir }) catch continue;
        if (tar_exit != 0) continue;

        // Locate binary
        const bin_path = std.fmt.bufPrint(
            &artifact.binary_path_buf,
            "{s}/{s}",
            .{ extract_dir, candidate },
        ) catch continue;
        artifact.binary_path_len = bin_path.len;

        if (!sys.fileExists(bin_path)) continue;

        // Validate — run with a nonexistent config to check for SIGILL (exit 132)
        const check = sys.exec(allocator, &.{
            bin_path,
            "/tmp/.mtproto-release-check-nonexistent.toml",
        }) catch continue;
        defer check.deinit();

        if (check.exit_code == 132) continue;

        // ── Success ──
        artifact.asset_name = candidate;
        return true;
    }

    return false;
}

/// Download the mtbuddy binary for the same platform as a proxy artifact.
/// Returns the path to the extracted buddy binary, or null if unavailable.
pub fn downloadBuddyArtifact(
    allocator: std.mem.Allocator,
    tag: []const u8,
    proxy_asset: []const u8,
    extract_dir: []const u8,
    out_buf: *[256]u8,
) ?[]const u8 {
    // Derive buddy name: "mtproto-proxy-linux-x86_64_v3" → "mtbuddy-linux-x86_64_v3"
    const prefix = "mtproto-proxy";
    const idx = std.mem.indexOf(u8, proxy_asset, prefix) orelse return null;
    const suffix = proxy_asset[idx + prefix.len ..];

    var name_buf: [128]u8 = undefined;
    const buddy_name = std.fmt.bufPrint(&name_buf, "mtbuddy{s}", .{suffix}) catch return null;

    var url_buf: [512]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://github.com/{s}/{s}/releases/download/{s}/{s}.tar.gz",
        .{ REPO_OWNER, REPO_NAME, tag, buddy_name },
    ) catch return null;

    const dl = sys.exec(allocator, &.{ "curl", "-fsSL", url, "-o", "/tmp/mtbuddy.tar.gz" }) catch return null;
    defer dl.deinit();
    if (dl.exit_code != 0) return null;

    const tar_exit = sys.execForward(&.{ "tar", "-xzf", "/tmp/mtbuddy.tar.gz", "-C", extract_dir }) catch return null;
    if (tar_exit != 0) return null;

    const bin_path = std.fmt.bufPrint(out_buf, "{s}/{s}", .{ extract_dir, buddy_name }) catch return null;
    if (!sys.fileExists(bin_path)) return null;

    return bin_path;
}

/// Download the systemd service file from the repository at the given tag.
pub fn downloadServiceFile(allocator: std.mem.Allocator, tag: []const u8) void {
    var url_buf: [512]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "{s}{s}/deploy/mtproto-proxy.service",
        .{ RAW_BASE, tag },
    ) catch return;
    _ = sys.exec(allocator, &.{ "curl", "-fsSL", url, "-o", SERVICE_FILE }) catch {};
}

/// Remove temporary files created during download.
pub fn cleanup(allocator: std.mem.Allocator, artifact: *const Artifact) void {
    if (artifact.extract_dir_len > 0) {
        _ = sys.exec(allocator, &.{ "rm", "-rf", artifact.extractDir() }) catch {};
    }
    if (artifact.dl_path_len > 0) {
        _ = sys.exec(allocator, &.{ "rm", "-f", artifact.dlPath() }) catch {};
    }
    // Clean up buddy tarball if it was downloaded
    _ = sys.exec(allocator, &.{ "rm", "-f", "/tmp/mtbuddy.tar.gz" }) catch {};
}

// ── Helpers ─────────────────────────────────────────────────────

fn resolveLatest(allocator: std.mem.Allocator, tag: *Tag) bool {
    const result = sys.exec(allocator, &.{ "curl", "-fsSL", RELEASES_API }) catch return false;
    defer result.deinit();

    const parsed = extractTagName(result.stdout) orelse return false;
    const n = @min(parsed.len, tag.buf.len);
    @memcpy(tag.buf[0..n], parsed[0..n]);
    tag.len = n;
    return true;
}

/// Extract "tag_name" value from a GitHub API JSON response.
pub fn extractTagName(json: []const u8) ?[]const u8 {
    const needle = "\"tag_name\"";
    const idx = std.mem.indexOf(u8, json, needle) orelse return null;

    // Skip to the opening quote of the value
    var pos = idx + needle.len;
    while (pos < json.len and json[pos] != '"') : (pos += 1) {}
    if (pos >= json.len) return null;
    pos += 1; // skip opening quote

    // Read until closing quote
    const start = pos;
    while (pos < json.len and json[pos] != '"') : (pos += 1) {}
    if (pos >= json.len) return null;

    return json[start..pos];
}
