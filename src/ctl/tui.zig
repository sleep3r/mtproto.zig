//! TUI rendering engine for mtproto-ctl.
//!
//! Provides styled terminal output components:
//! banner, menus, confirmations, text input, spinners, status lines,
//! and summary boxes — all in black & yellow (Zig brand colors).
//!
//! No external dependencies — uses only std.io and ANSI escape codes.

const std = @import("std");
const i18n = @import("i18n.zig");

// ── ANSI Color Constants (Zig brand: black + yellow) ────────────

pub const Color = struct {
    pub const reset = "\x1b[0m";
    pub const bold = "\x1b[1m";
    pub const dim = "\x1b[2m";
    pub const italic = "\x1b[3m";

    // Primary palette — Zig yellow/amber
    pub const yellow = "\x1b[33m";
    pub const bright_yellow = "\x1b[93m";

    // Semantic
    pub const ok = "\x1b[32m"; // green
    pub const err = "\x1b[31m"; // red
    pub const info = "\x1b[36m"; // cyan
    pub const white = "\x1b[97m";

    // Composed styles
    pub const header = bold ++ bright_yellow;
    pub const accent = bold ++ white;
    pub const muted = dim;
    pub const success = bold ++ ok;
    pub const danger = bold ++ err;
};

pub const Tui = struct {
    out: std.fs.File,
    in: std.fs.File,
    lang: i18n.Lang,
    is_tty: bool,
    line_buf: [1024]u8 = undefined,

    const Self = @This();

    pub fn init(lang: i18n.Lang) Self {
        const out = std.fs.File.stdout();
        const in = std.fs.File.stdin();
        return .{
            .out = out,
            .in = in,
            .lang = lang,
            .is_tty = out.isTty(),
        };
    }

    // ── Low-level output ────────────────────────────────────

    /// Write raw bytes to stdout.
    pub fn writeRaw(self: *Self, bytes: []const u8) void {
        _ = self.out.write(bytes) catch {};
    }

    /// Write formatted output to stdout.
    pub fn print(self: *Self, comptime fmt: []const u8, args: anytype) void {
        var buf: [8192]u8 = undefined;
        const slice = std.fmt.bufPrint(&buf, fmt, args) catch return;
        self.writeRaw(slice);
    }

    // ── Localized helpers ───────────────────────────────────

    /// Get a localized string.
    pub fn str(self: *Self, key: i18n.S) []const u8 {
        return i18n.get(self.lang, key);
    }

    // ── Status lines ────────────────────────────────────────

    /// Print: ✓ message
    pub fn ok(self: *Self, msg: []const u8) void {
        self.print("  {s}✓{s} {s}\n", .{ Color.ok, Color.reset, msg });
    }

    /// Print: ✗ message
    pub fn fail(self: *Self, msg: []const u8) void {
        self.print("  {s}✗{s} {s}\n", .{ Color.err, Color.reset, msg });
    }

    /// Print: ▸ message
    pub fn info(self: *Self, msg: []const u8) void {
        self.print("  {s}▸{s} {s}\n", .{ Color.bright_yellow, Color.reset, msg });
    }

    /// Print: ⚠ message
    pub fn warn(self: *Self, msg: []const u8) void {
        self.print("  {s}⚠{s} {s}\n", .{ Color.err, Color.reset, msg });
    }

    /// Print a step with formatted detail: ▸ label... detail
    pub fn step(self: *Self, label: []const u8) void {
        self.print("  {s}▸{s} {s}...\n", .{ Color.bright_yellow, Color.reset, label });
    }

    /// Print a completed step: ✓ label (detail)
    pub fn stepOk(self: *Self, label: []const u8, detail: []const u8) void {
        if (detail.len > 0) {
            self.print("  {s}✓{s} {s} {s}({s}){s}\n", .{
                Color.ok, Color.reset, label, Color.dim, detail, Color.reset,
            });
        } else {
            self.ok(label);
        }
    }

    // ── Banner ──────────────────────────────────────────────

    pub fn banner(self: *Self, version: []const u8) void {
        self.writeRaw("\n");
        self.writeRaw(Color.header);
        self.writeRaw("   ╔══════════════════════════════════════════╗\n");
        self.writeRaw("   ║                                          ║\n");
        self.writeRaw("   ║   ⚡ mtproto.zig                         ║\n");
        self.writeRaw("   ║   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ║\n");
        self.writeRaw(Color.reset);
        self.print(
            "   {s}║{s}   installer & control panel  {s}v{s}{s}",
            .{ Color.header, Color.reset, Color.dim, version, Color.reset },
        );
        // Pad to box width
        const ver_len = version.len + 1; // "v" + version
        const pad_needed = if (ver_len < 10) 10 - ver_len else 0;
        var pad_buf: [16]u8 = undefined;
        @memset(pad_buf[0..pad_needed], ' ');
        self.writeRaw(pad_buf[0..pad_needed]);
        self.writeRaw(Color.header ++ "║\n");
        self.writeRaw("   ║                                          ║\n");
        self.writeRaw("   ╚══════════════════════════════════════════╝\n");
        self.writeRaw(Color.reset ++ "\n");
    }

    // ── Menu ────────────────────────────────────────────────

    /// Show a numbered menu, return the 0-based index of the selected item.
    pub fn menu(self: *Self, title: []const u8, items: []const []const u8) !usize {
        self.print("\n  {s}{s}{s}\n", .{ Color.header, title, Color.reset });

        for (items, 0..) |item, idx| {
            self.print("  {s}│{s}  [{s}{d}{s}] {s}\n", .{
                Color.bright_yellow,
                Color.reset,
                Color.accent,
                idx + 1,
                Color.reset,
                item,
            });
        }

        while (true) {
            self.print("  {s}└─{s} {s}▸{s} ", .{
                Color.bright_yellow, Color.reset, Color.bright_yellow, Color.reset,
            });

            const choice = self.readLine() catch return error.InputError;
            const trimmed = std.mem.trim(u8, choice, &[_]u8{ ' ', '\t', '\r', '\n' });

            if (trimmed.len == 0) continue;

            const num = std.fmt.parseInt(usize, trimmed, 10) catch continue;
            if (num >= 1 and num <= items.len) {
                return num - 1;
            }
        }
    }

    // ── Confirm ─────────────────────────────────────────────

    /// Ask a yes/no question. Returns the boolean answer.
    pub fn confirm(self: *Self, prompt: []const u8, default: bool) !bool {
        const hint = if (default) "[Y/n]" else "[y/N]";
        self.print("\n  {s}{s}{s} {s} ", .{
            Color.accent, prompt, Color.reset, hint,
        });

        const line = self.readLine() catch return default;
        const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r', '\n' });

        if (trimmed.len == 0) return default;

        const first = std.ascii.toLower(trimmed[0]);
        if (first == 'y' or first == 'd') return true; // y, yes, да
        if (first == 'n') return false;
        // Russian: д = 0xd0 0xb4 (UTF-8)
        if (trimmed.len >= 2 and trimmed[0] == 0xd0 and trimmed[1] == 0xb4) return true;
        // Russian: н = 0xd0 0xbd
        if (trimmed.len >= 2 and trimmed[0] == 0xd0 and trimmed[1] == 0xbd) return false;

        return default;
    }

    // ── Text Input ──────────────────────────────────────────

    /// Prompt for text input with a default value.
    /// Returns a slice into the provided buffer.
    pub fn input(self: *Self, prompt: []const u8, help: ?[]const u8, default: ?[]const u8, buf: []u8) ![]const u8 {
        self.writeRaw("\n");
        self.print("  {s}{s}{s}\n", .{ Color.accent, prompt, Color.reset });

        if (help) |h| {
            // Print help lines with dim indent
            var lines = std.mem.splitScalar(u8, h, '\n');
            while (lines.next()) |line| {
                self.print("  {s}│{s}  {s}{s}{s}\n", .{
                    Color.bright_yellow, Color.reset,
                    Color.dim, line, Color.reset,
                });
            }
        }

        if (default) |d| {
            self.print("  {s}└─{s} [{s}{s}{s}]: ", .{
                Color.bright_yellow, Color.reset,
                Color.dim, d, Color.reset,
            });
        } else {
            self.print("  {s}└─{s} ", .{ Color.bright_yellow, Color.reset });
        }

        const line = self.readLine() catch return default orelse error.InputError;
        const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r', '\n' });

        if (trimmed.len == 0) {
            if (default) |d| {
                @memcpy(buf[0..d.len], d);
                return buf[0..d.len];
            }
            return error.InputError;
        }

        const len = @min(trimmed.len, buf.len);
        @memcpy(buf[0..len], trimmed[0..len]);
        return buf[0..len];
    }

    // ── Checkbox (toggle list) ──────────────────────────────

    /// Show a list of toggleable items. Returns a bitmask of selected items.
    /// `defaults` is the initial state (true = checked).
    pub fn checkboxes(
        self: *Self,
        title: []const u8,
        items: []const []const u8,
        helps: []const []const u8,
        defaults: []const bool,
    ) !u32 {
        var selected: u32 = 0;
        for (defaults, 0..) |d, idx| {
            if (d) selected |= @as(u32, 1) << @intCast(idx);
        }

        while (true) {
            self.print("\n  {s}{s}{s}\n", .{ Color.header, title, Color.reset });

            for (items, 0..) |item, idx| {
                const checked = (selected & (@as(u32, 1) << @intCast(idx))) != 0;
                const mark = if (checked) Color.ok ++ "✅" else "◻️ ";
                self.print("  {s}│{s}  [{s}{d}{s}] {s}{s} {s}{s}\n", .{
                    Color.bright_yellow,
                    Color.reset,
                    Color.accent,
                    idx + 1,
                    Color.reset,
                    mark,
                    Color.reset,
                    item,
                    Color.reset,
                });
                if (idx < helps.len) {
                    self.print("  {s}│{s}      {s}{s}{s}\n", .{
                        Color.bright_yellow,
                        Color.reset,
                        Color.dim,
                        helps[idx],
                        Color.reset,
                    });
                }
            }

            self.print(
                "  {s}└─{s} Enter=confirm, number=toggle: ",
                .{ Color.bright_yellow, Color.reset },
            );

            const line = self.readLine() catch return selected;
            const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r', '\n' });

            if (trimmed.len == 0) return selected;

            const num = std.fmt.parseInt(usize, trimmed, 10) catch continue;
            if (num >= 1 and num <= items.len) {
                selected ^= @as(u32, 1) << @intCast(num - 1);
            }
        }
    }

    // ── Summary Box ─────────────────────────────────────────

    /// Print a bordered summary box (for final output).
    pub fn summaryBox(self: *Self, title: []const u8, lines: []const SummaryLine) void {
        self.writeRaw("\n");
        self.writeRaw("  " ++ Color.header);
        self.writeRaw("══════════════════════════════════════════════════\n");
        self.print("  {s}  {s}{s}\n", .{ Color.header, title, Color.reset });
        self.writeRaw("  " ++ Color.bright_yellow);
        self.writeRaw("══════════════════════════════════════════════════\n");
        self.writeRaw(Color.reset);
        self.writeRaw("\n");

        for (lines) |line| {
            switch (line.style) {
                .label_value => {
                    self.print("  {s}{s}{s}  {s}\n", .{
                        Color.dim, line.label, Color.reset, line.value,
                    });
                },
                .highlight => {
                    self.print("  {s}{s}{s}\n", .{ Color.accent, line.label, Color.reset });
                    if (line.value.len > 0) {
                        self.print("  {s}{s}{s}\n", .{ Color.bright_yellow, line.value, Color.reset });
                    }
                },
                .success => {
                    self.print("  {s}✓{s} {s}\n", .{ Color.ok, Color.reset, line.label });
                },
                .blank => {
                    self.writeRaw("\n");
                },
            }
        }
        self.writeRaw("\n");
    }

    // ── Section Header ──────────────────────────────────────

    pub fn section(self: *Self, title: []const u8) void {
        self.writeRaw("\n");
        self.print(
            "  {s}───{s} {s}{s}{s} {s}──────────────────────────────────{s}\n",
            .{ Color.dim, Color.reset, Color.header, title, Color.reset, Color.dim, Color.reset },
        );
    }

    // ── Line reading ────────────────────────────────────────

    fn readLine(self: *Self) ![]const u8 {
        var pos: usize = 0;
        while (pos < self.line_buf.len) {
            var byte: [1]u8 = undefined;
            const n = self.in.read(&byte) catch return error.InputError;
            if (n == 0) {
                // EOF
                if (pos == 0) return error.EndOfStream;
                return self.line_buf[0..pos];
            }
            if (byte[0] == '\n') {
                return self.line_buf[0..pos];
            }
            self.line_buf[pos] = byte[0];
            pos += 1;
        }
        // Buffer full — drain remaining input until newline
        while (true) {
            var byte: [1]u8 = undefined;
            const n = self.in.read(&byte) catch break;
            if (n == 0 or byte[0] == '\n') break;
        }
        return self.line_buf[0..pos];
    }
};

// ── Summary line types ──────────────────────────────────────────

pub const SummaryLine = struct {
    label: []const u8,
    value: []const u8 = "",
    style: Style = .label_value,

    pub const Style = enum {
        label_value,
        highlight,
        success,
        blank,
    };
};
