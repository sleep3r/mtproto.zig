//! TUI rendering engine for buddy.
//!
//! Provides styled terminal output components:
//! banner, menus, confirmations, text input, spinners, status lines,
//! and summary boxes — all in black & yellow (Zig brand colors).
//!
//! No external dependencies — uses only std.io and ANSI escape codes.

const std = @import("std");
const i18n = @import("i18n.zig");

pub const Key = enum {
    up,
    down,
    left,
    right,
    enter,
    space,
    ctrl_c,
    escape,
    backspace,
    char,
};

pub const KeyEvent = struct {
    key: Key,
    ch: u8 = 0,
};

// ── ANSI Color Constants (Zig brand: black + yellow) ───────────────────────

pub const Color = struct {
    pub const reset = "\x1b[0m";
    pub const bold = "\x1b[1m";
    pub const dim = "\x1b[2m";
    pub const italic = "\x1b[3m";

    // Primary palette — Zig yellow/amber
    pub const yellow = "\x1b[33m";
    pub const bright_yellow = "\x1b[93m";
    pub const gray = "\x1b[90m";

    // Semantic
    pub const ok = "\x1b[32m"; // green
    pub const err = "\x1b[31m"; // red
    pub const info = "\x1b[36m"; // cyan
    pub const white = "\x1b[97m";

    // Invert selection
    pub const invert = "\x1b[7m";
    pub const selected = "\x1b[43;30m"; // Yellow bg, black text

    // Composed styles
    pub const header = bold ++ bright_yellow;
    pub const accent = bold ++ white;
    pub const muted = dim;
    pub const success = bold ++ ok;
    pub const danger = bold ++ err;

    // Hide/show cursor
    pub const cursor_hide = "\x1b[?25l";
    pub const cursor_show = "\x1b[?25h";
};

// ── Braille spinner frames ──────────────────────────────────────────────────

const SPINNER_FRAMES = [_][]const u8{
    "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏",
};

// ── Spinner state (thread-safe write via atomic, rendered in main thread) ──

pub const Spinner = struct {
    tui: *Tui,
    label: []const u8,
    frame: usize = 0,
    active: bool = false,
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    success_label: ?[]const u8 = null,

    const Self = @This();

    pub fn start(self: *Self) void {
        if (!self.tui.is_tty) {
            self.tui.print("  {s}…{s} {s}\n", .{ Color.bright_yellow, Color.reset, self.label });
            return;
        }
        self.active = true;
        self.done.store(false, .release);
        self.tui.writeRaw(Color.cursor_hide);
        // Print initial frame immediately
        self.tui.print("  {s}{s}{s} {s}", .{
            Color.bright_yellow, SPINNER_FRAMES[0], Color.reset, self.label,
        });
        self.thread = std.Thread.spawn(.{}, spinLoop, .{self}) catch null;
    }

    pub fn stop(self: *Self, succeeded: bool, detail: []const u8) void {
        if (!self.tui.is_tty) {
            if (succeeded) {
                if (detail.len > 0) {
                    self.tui.print("  {s}✔{s} {s} {s}({s}){s}\n", .{
                        Color.ok, Color.reset, self.label, Color.dim, detail, Color.reset,
                    });
                } else {
                    self.tui.print("  {s}✔{s} {s}\n", .{ Color.ok, Color.reset, self.label });
                }
            } else {
                self.tui.print("  {s}✖{s} {s}\n", .{ Color.err, Color.reset, self.label });
            }
            return;
        }

        self.done.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        self.active = false;

        // Clear spinner line and replace with final status
        self.tui.writeRaw("\r\x1b[2K");
        if (succeeded) {
            if (detail.len > 0) {
                self.tui.print("  {s}✔{s} {s} {s}({s}){s}\n", .{
                    Color.ok, Color.reset, self.label, Color.dim, detail, Color.reset,
                });
            } else {
                self.tui.print("  {s}✔{s} {s}\n", .{ Color.ok, Color.reset, self.label });
            }
        } else {
            self.tui.print("  {s}✖{s} {s}\n", .{ Color.err, Color.reset, self.label });
        }
        self.tui.writeRaw(Color.cursor_show);
    }

    fn spinLoop(self: *Self) void {
        var frame: usize = 0;
        while (!self.done.load(.acquire)) {
            frame = (frame + 1) % SPINNER_FRAMES.len;
            self.tui.print("\r  {s}{s}{s} {s}", .{
                Color.bright_yellow, SPINNER_FRAMES[frame], Color.reset, self.label,
            });
            std.Thread.sleep(80 * std.time.ns_per_ms);
        }
    }
};

pub const Tui = struct {
    out: std.fs.File,
    in: std.fs.File,
    lang: i18n.Lang,
    is_tty: bool,
    line_buf: [1024]u8 = undefined,
    orig_termios: ?std.posix.termios = null,

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

    // ── Raw Mode Lifecycle ─────────────────────────────────────────────────

    pub fn enterRawMode(self: *Self) void {
        if (!self.is_tty) return;
        const current = std.posix.tcgetattr(self.in.handle) catch return;
        self.orig_termios = current;

        var raw = current;
        raw.lflag.ECHO = false;
        raw.lflag.ICANON = false;
        raw.lflag.ISIG = false;

        raw.cc[@intFromEnum(std.posix.V.MIN)] = 1;
        raw.cc[@intFromEnum(std.posix.V.TIME)] = 0;

        std.posix.tcsetattr(self.in.handle, .FLUSH, raw) catch {};
    }

    pub fn exitRawMode(self: *Self) void {
        if (self.orig_termios) |orig| {
            std.posix.tcsetattr(self.in.handle, .FLUSH, orig) catch {};
            self.orig_termios = null;
        }
    }

    pub fn readKey(self: *Self) !KeyEvent {
        var byte: [1]u8 = undefined;
        const n = try self.in.read(&byte);
        if (n == 0) return error.EndOfStream;
        const c = byte[0];

        if (c == 3) return .{ .key = .ctrl_c };
        if (c == '\r' or c == '\n') return .{ .key = .enter };
        if (c == ' ') return .{ .key = .space };
        if (c == 127 or c == 8) return .{ .key = .backspace };

        if (c == '\x1b') {
            var fds = [_]std.posix.pollfd{
                .{ .fd = self.in.handle, .events = std.posix.POLL.IN, .revents = 0 },
            };
            const p = std.posix.poll(&fds, 0) catch 0;
            if (p == 0) return .{ .key = .escape };

            var seq: [2]u8 = undefined;
            const seq_n = self.in.read(&seq) catch 0;
            if (seq_n < 2) return .{ .key = .escape };
            if (seq[0] == '[') {
                if (seq[1] == 'A') return .{ .key = .up };
                if (seq[1] == 'B') return .{ .key = .down };
                if (seq[1] == 'C') return .{ .key = .right };
                if (seq[1] == 'D') return .{ .key = .left };
            }
            return .{ .key = .escape };
        }
        return .{ .key = .char, .ch = c };
    }

    // ── Low-level output ───────────────────────────────────────────────────

    /// Move cursor up N lines
    pub fn cursorUp(self: *Self, n: usize) void {
        self.print("\x1b[{d}A", .{n});
    }

    /// Clear current line and move to beginning
    pub fn clearLine(self: *Self) void {
        self.writeRaw("\x1b[2K\r");
    }

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

    // ── Localized helpers ──────────────────────────────────────────────────

    /// Get a localized string.
    pub fn str(self: *Self, key: i18n.S) []const u8 {
        return i18n.get(self.lang, key);
    }

    // ── Spinner factory ────────────────────────────────────────────────────

    /// Create and immediately start a spinner for a task label.
    pub fn spinner(self: *Self, label: []const u8) Spinner {
        var s = Spinner{ .tui = self, .label = label };
        s.start();
        return s;
    }

    // ── Status lines ───────────────────────────────────────────────────────

    pub fn ok(self: *Self, msg: []const u8) void {
        self.print("  {s}✔{s} {s}\n", .{ Color.ok, Color.reset, msg });
    }

    pub fn fail(self: *Self, msg: []const u8) void {
        self.print("  {s}✖{s} {s}\n", .{ Color.err, Color.reset, msg });
    }

    pub fn info(self: *Self, msg: []const u8) void {
        self.print("  {s}◆{s} {s}\n", .{ Color.info, Color.reset, msg });
    }

    pub fn warn(self: *Self, msg: []const u8) void {
        self.print("  {s}⚠{s}  {s}\n", .{ Color.bright_yellow, Color.reset, msg });
    }

    pub fn step(self: *Self, label: []const u8) void {
        self.print("  {s}●{s} {s}...\n", .{ Color.bright_yellow, Color.reset, label });
    }

    pub fn stepOk(self: *Self, label: []const u8, detail: []const u8) void {
        if (detail.len > 0) {
            self.print("  {s}✔{s} {s} {s}({s}){s}\n", .{
                Color.ok, Color.reset, label, Color.dim, detail, Color.reset,
            });
        } else {
            self.ok(label);
        }
    }

    /// Print a dimmed hint line (indented, no decoration).
    pub fn hint(self: *Self, msg: []const u8) void {
        self.print("     {s}{s}{s}\n", .{ Color.dim, msg, Color.reset });
    }

    // ── Banner ─────────────────────────────────────────────────────────────

    pub fn banner(self: *Self, version: []const u8) void {
        self.writeRaw("\n");
        // Top border
        self.print("{s}  ╭──────────────────────────────────────────────────╮{s}\n", .{ Color.gray, Color.reset });
        self.print("{s}  │{s}                                                  {s}│{s}\n", .{ Color.gray, Color.reset, Color.gray, Color.reset });

        // Logo line — "⚡ mtproto.zig" centered in 50 chars interior
        self.print("{s}  │{s}         {s}⚡  m t p r o t o . z i g{s}           {s}│{s}\n", .{
            Color.gray,   Color.reset,
            Color.header, Color.reset,
            Color.gray,   Color.reset,
        });

        self.print("{s}  │{s}                                                  {s}│{s}\n", .{ Color.gray, Color.reset, Color.gray, Color.reset });

        // Subtitle
        self.print("{s}  │{s}       {s}installer & control panel{s}               {s}│{s}\n", .{
            Color.gray,               Color.reset,
            Color.dim ++ Color.white, Color.reset,
            Color.gray,               Color.reset,
        });

        // Version pill
        var ver_buf: [64]u8 = undefined;
        const ver_label = std.fmt.bufPrint(&ver_buf, "v{s}", .{version}) catch "vX.X";
        const ver_len = ver_label.len;
        const interior = 50;
        const pad_total = if (ver_len + 2 < interior) interior - ver_len - 2 else 0;
        const pad_l = pad_total / 2;
        const pad_r = pad_total - pad_l;
        var pad_buf: [64]u8 = undefined;
        @memset(pad_buf[0..@min(pad_l + pad_r, pad_buf.len)], ' ');

        self.print("{s}  │{s}{s}{s}{s}{s}{s}  {s}│{s}\n", .{
            Color.gray,        Color.reset,
            pad_buf[0..pad_l], Color.dim,
            ver_label,         Color.reset,
            pad_buf[0..pad_r], Color.gray,
            Color.reset,
        });

        self.print("{s}  │{s}                                                  {s}│{s}\n", .{ Color.gray, Color.reset, Color.gray, Color.reset });
        self.print("{s}  ╰──────────────────────────────────────────────────╯{s}\n", .{ Color.gray, Color.reset });
        self.writeRaw("\n");
    }

    // ── Menu ───────────────────────────────────────────────────────────────

    /// Show a numbered menu, return the 0-based index of the selected item.
    pub fn menu(self: *Self, title: []const u8, items: []const []const u8) !usize {
        self.print("\n  {s}╭─ {s}{s}{s}\n", .{ Color.gray, Color.bold, title, Color.reset });
        self.print("  {s}│{s}\n", .{ Color.gray, Color.reset });

        var selected: usize = 0;

        const draw = struct {
            fn apply(tui: *Self, s_items: []const []const u8, s_sel: usize) void {
                for (s_items, 0..) |item, idx| {
                    tui.clearLine();
                    if (idx == s_sel) {
                        tui.print("  {s}│{s}  {s}❯{s} {s}{s}{s}\n", .{
                            Color.gray,          Color.reset,
                            Color.bright_yellow, Color.reset,
                            Color.selected,      item,
                            Color.reset,
                        });
                    } else {
                        tui.print("  {s}│{s}    {s}\n", .{ Color.gray, Color.reset, item });
                    }
                }
                tui.clearLine();
                tui.print("  {s}╰─❯{s} {s}↑↓ navigate  Enter select{s}\n", .{
                    Color.gray, Color.reset, Color.dim, Color.reset,
                });
            }
        }.apply;

        draw(self, items, selected);

        self.enterRawMode();
        defer self.exitRawMode();

        while (true) {
            const ev = self.readKey() catch continue;
            var changed = false;

            if (ev.key == .up and selected > 0) {
                selected -= 1;
                changed = true;
            } else if (ev.key == .down and selected < items.len - 1) {
                selected += 1;
                changed = true;
            } else if (ev.key == .enter) {
                self.print("\n", .{});
                return selected;
            } else if (ev.key == .ctrl_c) {
                return error.InputError;
            }

            if (changed) {
                self.cursorUp(items.len + 1);
                draw(self, items, selected);
            }
        }
    }

    // ── Confirm ────────────────────────────────────────────────────────────

    /// Ask a yes/no question. Returns the boolean answer.
    pub fn confirm(self: *Self, prompt: []const u8, default: bool) !bool {
        const hint_str = if (default)
            Color.bright_yellow ++ "Y" ++ Color.dim ++ "/n" ++ Color.reset
        else
            Color.dim ++ "y/" ++ Color.reset ++ Color.bright_yellow ++ "N" ++ Color.reset;
        self.print("\n  {s}╭─ {s}{s}\n", .{ Color.gray, prompt, Color.reset });
        self.print("  {s}╰─❯{s} {s}  ", .{ Color.gray, Color.reset, hint_str });

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

    // ── Text Input ─────────────────────────────────────────────────────────

    /// Prompt for text input with an optional default value.
    /// Returns a slice into the provided buffer.
    pub fn input(self: *Self, prompt: []const u8, help: ?[]const u8, default: ?[]const u8, buf: []u8) ![]const u8 {
        self.writeRaw("\n");
        self.print("  {s}╭─ {s}{s}{s}\n", .{ Color.gray, Color.bold, prompt, Color.reset });

        if (help) |h| {
            var lines = std.mem.splitScalar(u8, h, '\n');
            while (lines.next()) |line| {
                self.print("  {s}│{s}  {s}{s}{s}\n", .{
                    Color.gray,  Color.reset,
                    Color.dim,   line,
                    Color.reset,
                });
            }
        }

        if (default) |d| {
            self.print("  {s}╰─❯{s} {s}[{s}]{s} ", .{
                Color.gray,  Color.reset,
                Color.dim,   d,
                Color.reset,
            });
        } else {
            self.print("  {s}╰─❯{s} ", .{ Color.gray, Color.reset });
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

    // ── Checkbox (toggle list) ─────────────────────────────────────────────

    /// Show a list of toggleable items. Returns a bitmask of selected items.
    pub fn checkboxes(
        self: *Self,
        title: []const u8,
        items: []const []const u8,
        helps: []const []const u8,
        defaults: []const bool,
    ) !u32 {
        var state: u32 = 0;
        for (defaults, 0..) |d, idx| {
            if (d) state |= @as(u32, 1) << @intCast(idx);
        }

        self.print("\n  {s}╭─ {s}{s}{s}\n", .{ Color.gray, Color.bold, title, Color.reset });
        self.print("  {s}│{s}\n", .{ Color.gray, Color.reset });

        var selected: usize = 0;

        const draw = struct {
            fn apply(tui: *Self, s_items: []const []const u8, s_helps: []const []const u8, s_state: u32, s_sel: usize) void {
                for (s_items, 0..) |item, idx| {
                    tui.clearLine();
                    const checked = (s_state & (@as(u32, 1) << @intCast(idx))) != 0;
                    const mark = if (checked) Color.ok ++ "▣" ++ Color.reset else Color.dim ++ "□" ++ Color.reset;

                    if (idx == s_sel) {
                        tui.print("  {s}│{s}  {s}❯{s} [{s}] {s}{s}{s}\n", .{
                            Color.gray,          Color.reset,
                            Color.bright_yellow, Color.reset,
                            mark,                Color.selected,
                            item,                Color.reset,
                        });
                    } else {
                        tui.print("  {s}│{s}    [{s}] {s}\n", .{
                            Color.gray, Color.reset, mark, item,
                        });
                    }
                    if (idx < s_helps.len) {
                        tui.clearLine();
                        tui.print("  {s}│{s}       {s}{s}{s}\n", .{
                            Color.gray,  Color.reset,
                            Color.dim,   s_helps[idx],
                            Color.reset,
                        });
                        tui.print("  {s}│{s}\n", .{ Color.gray, Color.reset });
                    }
                }
                tui.clearLine();
                tui.print("  {s}╰─❯{s} {s}↑↓ navigate  Space toggle  Enter confirm{s}\n", .{
                    Color.gray, Color.reset, Color.dim, Color.reset,
                });
            }
        }.apply;

        draw(self, items, helps, state, selected);

        self.enterRawMode();
        defer self.exitRawMode();

        while (true) {
            const ev = self.readKey() catch continue;
            var changed = false;

            if (ev.key == .up and selected > 0) {
                selected -= 1;
                changed = true;
            } else if (ev.key == .down and selected < items.len - 1) {
                selected += 1;
                changed = true;
            } else if (ev.key == .space) {
                state ^= @as(u32, 1) << @intCast(selected);
                changed = true;
            } else if (ev.key == .enter) {
                self.print("\n", .{});
                return state;
            } else if (ev.key == .ctrl_c) {
                return state;
            }

            if (changed) {
                var lines_up: usize = 1; // footer
                for (0..items.len) |idx| {
                    lines_up += 1; // item line
                    if (idx < helps.len) lines_up += 2; // help + spacer
                }
                self.cursorUp(lines_up);
                draw(self, items, helps, state, selected);
            }
        }
    }

    // ── Summary Box ────────────────────────────────────────────────────────

    /// Print a bordered summary box (for final output).
    pub fn summaryBox(self: *Self, title: []const u8, lines: []const SummaryLine) void {
        self.writeRaw("\n");
        self.print("  {s}╭──────────────────────────────────────────────────╮{s}\n", .{ Color.gray, Color.reset });

        // Title line
        const title_len = std.unicode.utf8CountCodepoints(title) catch title.len;
        const box_interior = 48;
        const title_pad = if (title_len + 2 < box_interior) box_interior - title_len - 2 else 0;
        var title_pad_buf: [64]u8 = undefined;
        @memset(title_pad_buf[0..title_pad], ' ');

        self.print("  {s}│{s} {s}{s}{s}{s}{s}│{s}\n", .{
            Color.gray,   Color.reset,
            Color.header, title,
            Color.reset,  title_pad_buf[0..title_pad],
            Color.gray,   Color.reset,
        });
        self.print("  {s}├──────────────────────────────────────────────────┤{s}\n", .{ Color.gray, Color.reset });
        self.print("  {s}│{s}                                                  {s}│{s}\n", .{ Color.gray, Color.reset, Color.gray, Color.reset });

        for (lines) |line| {
            switch (line.style) {
                .label_value => {
                    const l_len = std.unicode.utf8CountCodepoints(line.label) catch line.label.len;
                    const lp = if (l_len < 12) 12 - l_len else 0;
                    var l_pad: [16]u8 = undefined;
                    @memset(l_pad[0..lp], ' ');

                    const v_len = std.unicode.utf8CountCodepoints(line.value) catch line.value.len;
                    const used = 4 + l_len + lp + v_len; // "  " prefix + label + pad + value
                    const r_pad_len = if (used < box_interior) box_interior - used else 0;
                    const rp = @min(r_pad_len, 64);
                    var r_pad: [64]u8 = undefined;
                    @memset(r_pad[0..rp], ' ');

                    self.print("  {s}│{s}  {s}{s}{s}{s}{s}{s}{s}{s}{s}│{s}\n", .{
                        Color.gray,  Color.reset,
                        Color.dim,   line.label,
                        Color.reset, l_pad[0..lp],
                        Color.white, line.value,
                        Color.reset, r_pad[0..rp],
                        Color.gray,  Color.reset,
                    });
                },
                .highlight => {
                    const text = if (line.value.len > 0) line.value else line.label;
                    const t_len = std.unicode.utf8CountCodepoints(text) catch text.len;
                    const rp = if (t_len + 2 < box_interior) box_interior - t_len - 2 else 0;
                    var r_pad: [64]u8 = undefined;
                    @memset(r_pad[0..@min(rp, r_pad.len)], ' ');
                    self.print("  {s}│{s}  {s}{s}{s}{s}{s}│{s}\n", .{
                        Color.gray,          Color.reset,
                        Color.bright_yellow, text,
                        Color.reset,         r_pad[0..@min(rp, r_pad.len)],
                        Color.gray,          Color.reset,
                    });
                },
                .success => {
                    const text = line.label;
                    const t_len = std.unicode.utf8CountCodepoints(text) catch text.len;
                    const rp = if (t_len + 4 < box_interior) box_interior - t_len - 4 else 0;
                    var r_pad: [64]u8 = undefined;
                    @memset(r_pad[0..@min(rp, r_pad.len)], ' ');
                    self.print("  {s}│{s}  {s}✔{s} {s}{s}{s}│{s}\n", .{
                        Color.gray, Color.reset,
                        Color.ok,   Color.reset,
                        text,       r_pad[0..@min(rp, r_pad.len)],
                        Color.gray, Color.reset,
                    });
                },
                .blank => {
                    self.print("  {s}│{s}                                                  {s}│{s}\n", .{
                        Color.gray, Color.reset, Color.gray, Color.reset,
                    });
                },
                .code => {
                    const text = if (line.value.len > 0) line.value else line.label;
                    const t_len = std.unicode.utf8CountCodepoints(text) catch text.len;
                    const rp = if (t_len + 4 < box_interior) box_interior - t_len - 4 else 0;
                    var r_pad: [64]u8 = undefined;
                    @memset(r_pad[0..@min(rp, r_pad.len)], ' ');
                    self.print("  {s}│{s}  {s}{s}{s}{s}{s}│{s}\n", .{
                        Color.gray,  Color.reset,
                        Color.info,  text,
                        Color.reset, r_pad[0..@min(rp, r_pad.len)],
                        Color.gray,  Color.reset,
                    });
                },
            }
        }

        self.print("  {s}│{s}                                                  {s}│{s}\n", .{
            Color.gray, Color.reset, Color.gray, Color.reset,
        });
        self.print("  {s}╰──────────────────────────────────────────────────╯{s}\n\n", .{
            Color.gray, Color.reset,
        });
    }

    // ── Section Header ─────────────────────────────────────────────────────

    pub fn section(self: *Self, title: []const u8) void {
        self.writeRaw("\n");
        const title_len = std.unicode.utf8CountCodepoints(title) catch title.len;
        const inner = 36;
        const pad = if (title_len + 1 < inner) inner - title_len - 1 else 0;
        var pad_buf: [64]u8 = undefined;
        @memset(pad_buf[0..pad], ' ');

        self.print("  {s}╭────────────────────────────────────────╮{s}\n", .{ Color.gray, Color.reset });
        self.print("  {s}│{s} {s}⚙  {s}{s}{s}{s}{s}│{s}\n", .{
            Color.gray,      Color.reset,
            Color.bold,      Color.bright_yellow,
            title,           Color.reset,
            pad_buf[0..pad], Color.gray,
            Color.reset,
        });
        self.print("  {s}╰────────────────────────────────────────╯{s}\n", .{ Color.gray, Color.reset });
    }

    // ── Progress block ─────────────────────────────────────────────────────

    /// Print a labeled progress block header (before a series of steps).
    pub fn progressHeader(self: *Self, label: []const u8, total: usize) void {
        self.print("\n  {s}┌─{s} {s}{s}{s} {s}({d} steps){s}\n", .{
            Color.gray,  Color.reset,
            Color.bold,  label,
            Color.reset, Color.dim,
            total,       Color.reset,
        });
    }

    /// Print a horizontal rule.
    pub fn rule(self: *Self) void {
        self.print("  {s}─────────────────────────────────────────────────{s}\n", .{
            Color.gray, Color.reset,
        });
    }

    // ── Line reading ───────────────────────────────────────────────────────

    fn readLine(self: *Self) ![]const u8 {
        var pos: usize = 0;
        while (pos < self.line_buf.len) {
            var byte: [1]u8 = undefined;
            const n = self.in.read(&byte) catch return error.InputError;
            if (n == 0) {
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

// ── Summary line types ──────────────────────────────────────────────────────

pub const SummaryLine = struct {
    label: []const u8,
    value: []const u8 = "",
    style: Style = .label_value,

    pub const Style = enum {
        label_value,
        highlight,
        success,
        blank,
        code,
    };
};
