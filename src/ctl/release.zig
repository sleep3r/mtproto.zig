//! Shared GitHub Releases helpers for install and update commands.
//!
//! Centralises tag resolution, artifact download with architecture-aware
//! candidate selection, checksum verification, binary validation, and
//! temp-directory cleanup.
//! Used by both install.zig and update.zig to avoid duplication.

const std = @import("std");
const sys = @import("sys.zig");
const build_options = @import("build_options");

// ── Shared constants ────────────────────────────────────────────

pub const REPO_OWNER = "sleep3r";
pub const REPO_NAME = "mtproto.zig";
pub const INSTALL_DIR = "/opt/mtproto-proxy";
pub const SERVICE_NAME = "mtproto-proxy";
pub const SERVICE_FILE = "/etc/systemd/system/mtproto-proxy.service";

const RELEASES_API = "https://api.github.com/repos/" ++ REPO_OWNER ++ "/" ++ REPO_NAME ++ "/releases/latest";
const MINISIGN_PUBKEY = build_options.minisign_pubkey;

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
        if (v.len == 0 or std.mem.eql(u8, v, "latest")) return resolveLatest(allocator, tag);
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
    verify_signatures: bool,
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
    const mk = sys.exec(allocator, &.{ "mkdir", "-p", extract_dir }) catch return false;
    defer mk.deinit();
    if (mk.exit_code != 0) return false;

    // ── Try each candidate ──
    for (candidates) |candidate| {
        var tar_name_buf: [192]u8 = undefined;
        const tar_name = std.fmt.bufPrint(&tar_name_buf, "{s}.tar.gz", .{candidate}) catch continue;

        const dl_path = std.fmt.bufPrint(
            &artifact.dl_path_buf,
            "{s}/{s}",
            .{ extract_dir, tar_name },
        ) catch continue;
        artifact.dl_path_len = dl_path.len;

        // Download + checksum verify
        if (!downloadReleaseFile(allocator, tag, tar_name, dl_path)) continue;
        if (!verifyReleaseChecksum(allocator, tag, tar_name, dl_path, extract_dir, verify_signatures)) continue;

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

        // Guarantee executable bit (paranoid umask can strip +x from tar)
        _ = sys.exec(allocator, &.{ "chmod", "+x", bin_path }) catch {};

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
    verify_signatures: bool,
    out_buf: *[256]u8,
) ?[]const u8 {
    // Derive buddy name: "mtproto-proxy-linux-x86_64_v3" → "mtbuddy-linux-x86_64_v3"
    const prefix = "mtproto-proxy";
    const idx = std.mem.indexOf(u8, proxy_asset, prefix) orelse return null;
    const suffix = proxy_asset[idx + prefix.len ..];

    var name_buf: [128]u8 = undefined;
    const buddy_name = std.fmt.bufPrint(&name_buf, "mtbuddy{s}", .{suffix}) catch return null;

    var tar_name_buf: [192]u8 = undefined;
    const tar_name = std.fmt.bufPrint(&tar_name_buf, "{s}.tar.gz", .{buddy_name}) catch return null;

    var dl_path_buf: [320]u8 = undefined;
    const dl_path = std.fmt.bufPrint(&dl_path_buf, "{s}/{s}", .{ extract_dir, tar_name }) catch return null;
    if (!downloadReleaseFile(allocator, tag, tar_name, dl_path)) return null;
    if (!verifyReleaseChecksum(allocator, tag, tar_name, dl_path, extract_dir, verify_signatures)) return null;

    const tar_exit = sys.execForward(&.{ "tar", "-xzf", dl_path, "-C", extract_dir }) catch return null;
    if (tar_exit != 0) return null;

    const bin_path = std.fmt.bufPrint(out_buf, "{s}/{s}", .{ extract_dir, buddy_name }) catch return null;
    if (!sys.fileExists(bin_path)) return null;

    return bin_path;
}

/// Write the systemd service file from embedded content.
/// Avoids network dependency on raw.githubusercontent.com which may be
/// throttled or blocked on some hosting providers.
pub fn writeServiceFile() void {
    const content =
        \\[Unit]
        \\Description=MTProto Proxy (Zig)
        \\Documentation=https://github.com/sleep3r/mtproto.zig
        \\After=network-online.target
        \\Wants=network-online.target
        \\
        \\[Service]
        \\Type=simple
        \\User=mtproto
        \\Group=mtproto
        \\WorkingDirectory=/opt/mtproto-proxy
        \\ExecStart=/opt/mtproto-proxy/mtproto-proxy /opt/mtproto-proxy/config.toml
        \\ExecReload=/bin/kill -HUP $MAINPID
        \\KillSignal=SIGTERM
        \\TimeoutStopSec=25
        \\Restart=always
        \\RestartSec=3
        \\
        \\# Security hardening
        \\NoNewPrivileges=yes
        \\ProtectSystem=strict
        \\ProtectHome=yes
        \\PrivateTmp=yes
        \\ReadOnlyPaths=/opt/mtproto-proxy
        \\
        \\# Allow binding to privileged ports (443)
        \\AmbientCapabilities=CAP_NET_BIND_SERVICE
        \\CapabilityBoundingSet=CAP_NET_BIND_SERVICE
        \\
        \\# Limits
        \\LimitNOFILE=131582
        \\TasksMax=65535
        \\
        \\[Install]
        \\WantedBy=multi-user.target
        \\
    ;
    sys.writeFile(SERVICE_FILE, content) catch {};
}

/// Remove temporary files created during download.
pub fn cleanup(allocator: std.mem.Allocator, artifact: *const Artifact) void {
    if (artifact.extract_dir_len > 0) {
        _ = sys.exec(allocator, &.{ "rm", "-rf", artifact.extractDir() }) catch {};
    }
    if (artifact.dl_path_len > 0) {
        _ = sys.exec(allocator, &.{ "rm", "-f", artifact.dlPath() }) catch {};
    }
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

fn downloadReleaseFile(
    allocator: std.mem.Allocator,
    tag: []const u8,
    file_name: []const u8,
    out_path: []const u8,
) bool {
    var url_buf: [512]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://github.com/{s}/{s}/releases/download/{s}/{s}",
        .{ REPO_OWNER, REPO_NAME, tag, file_name },
    ) catch return false;

    const modes = [_]CurlMode{
        .{},
        .{ .force_ipv4 = true },
        .{ .http1 = true },
        .{ .force_ipv4 = true, .http1 = true },
    };
    for (modes) |mode| {
        _ = sys.exec(allocator, &.{ "rm", "-f", out_path }) catch {};
        if (curlDownloadToPath(allocator, url, out_path, mode)) return true;
    }
    _ = sys.exec(allocator, &.{ "rm", "-f", out_path }) catch {};
    return false;
}

const CurlMode = struct {
    force_ipv4: bool = false,
    http1: bool = false,
};

fn curlDownloadToPath(
    allocator: std.mem.Allocator,
    url: []const u8,
    out_path: []const u8,
    mode: CurlMode,
) bool {
    var argv: [32][]const u8 = undefined;
    var n: usize = 0;

    argv[n] = "curl";
    n += 1;
    if (mode.force_ipv4) {
        argv[n] = "-4";
        n += 1;
    }
    if (mode.http1) {
        argv[n] = "--http1.1";
        n += 1;
    }

    const common = [_][]const u8{
        "-fsSL",
        "--connect-timeout",
        "8",
        "--max-time",
        "120",
        "--retry",
        "1",
        "--retry-delay",
        "1",
        "--speed-time",
        "30",
        "--speed-limit",
        "1",
        url,
        "-o",
        out_path,
    };
    for (common) |arg| {
        argv[n] = arg;
        n += 1;
    }

    const dl = sys.exec(allocator, argv[0..n]) catch return false;
    defer dl.deinit();
    return dl.exit_code == 0 and fileIsNonEmpty(allocator, out_path);
}

fn fileIsNonEmpty(allocator: std.mem.Allocator, path: []const u8) bool {
    const r = sys.exec(allocator, &.{ "test", "-s", path }) catch return false;
    defer r.deinit();
    return r.exit_code == 0;
}

fn verifyReleaseChecksum(
    allocator: std.mem.Allocator,
    tag: []const u8,
    tar_name: []const u8,
    tar_path: []const u8,
    work_dir: []const u8,
    verify_signatures: bool,
) bool {
    if (verify_signatures and !hasEmbeddedMinisignPubkey()) return false;

    var checksum_name_buf: [224]u8 = undefined;
    const checksum_name = std.fmt.bufPrint(&checksum_name_buf, "{s}.sha256", .{tar_name}) catch return false;

    var checksum_path_buf: [320]u8 = undefined;
    const checksum_path = std.fmt.bufPrint(&checksum_path_buf, "{s}/{s}", .{ work_dir, checksum_name }) catch return false;
    if (!downloadReleaseFile(allocator, tag, checksum_name, checksum_path)) return false;
    if (verify_signatures) {
        var sig_name_buf: [256]u8 = undefined;
        const sig_name = std.fmt.bufPrint(&sig_name_buf, "{s}.minisig", .{checksum_name}) catch return false;

        var sig_path_buf: [352]u8 = undefined;
        const sig_path = std.fmt.bufPrint(&sig_path_buf, "{s}/{s}", .{ work_dir, sig_name }) catch return false;
        if (!downloadReleaseFile(allocator, tag, sig_name, sig_path)) return false;
        if (!verifyMinisignSignature(allocator, checksum_path, sig_path)) return false;
    }

    var expected_buf: [64]u8 = undefined;
    if (!readExpectedSha256(allocator, checksum_path, &expected_buf)) return false;
    var actual_buf: [64]u8 = undefined;
    if (!computeSha256Hex(allocator, tar_path, &actual_buf)) return false;
    return std.ascii.eqlIgnoreCase(expected_buf[0..], actual_buf[0..]);
}

fn hasEmbeddedMinisignPubkey() bool {
    return MINISIGN_PUBKEY.len > 0 and std.mem.startsWith(u8, MINISIGN_PUBKEY, "RW");
}

pub fn signatureVerificationAvailable() bool {
    return hasEmbeddedMinisignPubkey();
}

fn verifyMinisignSignature(
    allocator: std.mem.Allocator,
    message_path: []const u8,
    signature_path: []const u8,
) bool {
    if (!sys.commandExists("minisign")) return false;
    const res = sys.exec(allocator, &.{
        "minisign",
        "-V",
        "-q",
        "-m",
        message_path,
        "-x",
        signature_path,
        "-P",
        MINISIGN_PUBKEY,
    }) catch return false;
    defer res.deinit();
    return res.exit_code == 0;
}

fn readExpectedSha256(allocator: std.mem.Allocator, checksum_path: []const u8, out: *[64]u8) bool {
    const r = sys.exec(allocator, &.{ "cat", checksum_path }) catch return false;
    defer r.deinit();
    if (r.exit_code != 0) return false;

    var lines = std.mem.splitScalar(u8, r.stdout, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r' });
        if (trimmed.len < 64) continue;
        const hash = trimmed[0..64];
        if (!isHexString(hash)) continue;
        @memcpy(out[0..], hash);
        return true;
    }
    return false;
}

fn computeSha256Hex(allocator: std.mem.Allocator, file_path: []const u8, out: *[64]u8) bool {
    if (readShaOutput(allocator, &.{ "sha256sum", file_path }, out)) return true;
    if (readShaOutput(allocator, &.{ "shasum", "-a", "256", file_path }, out)) return true;
    return false;
}

fn readShaOutput(allocator: std.mem.Allocator, argv: []const []const u8, out: *[64]u8) bool {
    const r = sys.exec(allocator, argv) catch return false;
    defer r.deinit();
    if (r.exit_code != 0) return false;

    var tokens = std.mem.tokenizeAny(u8, r.stdout, " \t\r\n");
    const first = tokens.next() orelse return false;
    if (first.len != 64 or !isHexString(first)) return false;
    @memcpy(out[0..], first[0..64]);
    return true;
}

fn isHexString(s: []const u8) bool {
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
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
