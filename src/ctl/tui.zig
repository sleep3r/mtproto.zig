//! TUI rendering engine for mtbuddy.
//!
//! Provides styled terminal output components:
//! banner, menus, confirmations, text input, spinners, status lines,
//! and summary boxes — all in black & yellow (Zig brand colors).
//!
//! No external dependencies — uses only std.io and ANSI escape codes.

const std = @import("std");
const i18n = @import("i18n.zig");
const linux_io = @import("linux_io");

fn sleepMs(ms: u64) void {
    const req: std.posix.timespec = .{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * std.time.ns_per_ms),
    };
    _ = std.os.linux.nanosleep(&req, null);
}

fn isTty(fd: std.posix.fd_t) bool {
    var ws: std.posix.winsize = .{ .row = 0, .col = 0, .xpixel = 0, .ypixel = 0 };
    const rc = std.posix.system.ioctl(fd, std.posix.T.IOCGWINSZ, @intFromPtr(&ws));
    return std.posix.errno(rc) == .SUCCESS;
}

// ── Terminal geometry helpers (used by draw closures) ──────────────────────

/// Calculate physical terminal rows for a line of `visible_len` characters.
fn physicalRows(visible_len: usize, width: u16) usize {
    if (visible_len == 0 or width == 0) return 1;
    return (visible_len + width - 1) / width;
}

/// Approximate terminal display width (columns) of a UTF-8 string. Counts double-width
/// CJK/emoji as 2 and zero-width combining marks / variation selectors / ZWJ as 0 — a
/// plain codepoint count mis-sizes exactly the menu items that start with an emoji, which
/// then breaks the redraw row accounting (physicalRows) that depends on this.
fn codepointWidth(cp: u21) usize {
    if (cp == 0x200d) return 0; // ZWJ
    if ((cp >= 0x0300 and cp <= 0x036f) or // combining diacritical marks
        (cp >= 0x1ab0 and cp <= 0x1aff) or
        (cp >= 0x1dc0 and cp <= 0x1dff) or
        (cp >= 0x20d0 and cp <= 0x20ff) or
        (cp >= 0xfe00 and cp <= 0xfe0f)) return 0; // variation selectors
    if ((cp >= 0x1100 and cp <= 0x115f) or // Hangul Jamo
        (cp >= 0x2e80 and cp <= 0xa4cf) or // CJK
        (cp >= 0xac00 and cp <= 0xd7a3) or // Hangul syllables
        (cp >= 0xf900 and cp <= 0xfaff) or // CJK compat ideographs
        (cp >= 0xfe30 and cp <= 0xfe4f) or // CJK compat forms
        (cp >= 0xff00 and cp <= 0xff60) or // fullwidth forms
        (cp >= 0xffe0 and cp <= 0xffe6) or
        (cp >= 0x1f300 and cp <= 0x1faff) or // emoji & pictographs
        (cp >= 0x20000 and cp <= 0x3fffd)) return 2; // CJK extension planes
    return 1;
}

/// Sum the display columns of `s`. Falls back to byte count on invalid UTF-8.
fn visibleLen(s: []const u8) usize {
    const view = std.unicode.Utf8View.init(s) catch return s.len;
    var it = view.iterator();
    var width: usize = 0;
    while (it.nextCodepoint()) |cp| width += codepointWidth(cp);
    return width;
}

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
    "⠋",
    "⠙",
    "⠹",
    "⠸",
    "⠼",
    "⠴",
    "⠦",
    "⠧",
    "⠇",
    "⠏",
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
        g_term_out_fd = self.tui.out_fd;
        g_term_cursor_hidden = true;
        installTerminalSignalHandlers();
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
        g_term_cursor_hidden = false;
        self.tui.writeRaw(Color.cursor_show);
    }

    fn spinLoop(self: *Self) void {
        var frame: usize = 0;
        while (!self.done.load(.acquire)) {
            frame = (frame + 1) % SPINNER_FRAMES.len;
            self.tui.print("\r  {s}{s}{s} {s}", .{
                Color.bright_yellow, SPINNER_FRAMES[frame], Color.reset, self.label,
            });
            sleepMs(80);
        }
    }
};

// ── Terminal restoration on fatal signals ──────────────────────────────────
// Raw mode (ECHO/ICANON off) and a hidden cursor must be undone if the process is killed
// by SIGTERM/SIGHUP mid-interaction — `defer self.exitRawMode()` does NOT run on a signal,
// leaving the shell with echo off (user must blind-type `reset`). We stash the active
// termios/fds in file scope so a small handler can restore them, then re-raise the signal.
var g_term_orig: ?std.posix.termios = null;
var g_term_in_fd: std.posix.fd_t = -1;
var g_term_out_fd: std.posix.fd_t = -1;
var g_term_cursor_hidden: bool = false;
var g_term_handlers_installed: bool = false;

fn restoreTerminalGlobal() void {
    if (g_term_orig) |orig| {
        std.posix.tcsetattr(g_term_in_fd, .FLUSH, orig) catch {};
    }
    if (g_term_cursor_hidden and g_term_out_fd >= 0) {
        linux_io.writeAllFd(g_term_out_fd, Color.cursor_show);
    }
}

fn onFatalSignal(sig: std.posix.SIG) callconv(.c) void {
    restoreTerminalGlobal();
    // Reset to default disposition and re-raise so the exit status reflects the signal.
    var dfl = std.posix.Sigaction{
        .handler = .{ .handler = std.posix.SIG.DFL },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(sig, &dfl, null);
    std.posix.raise(sig) catch std.process.exit(1);
}

fn installTerminalSignalHandlers() void {
    if (g_term_handlers_installed) return;
    g_term_handlers_installed = true;
    const act = std.posix.Sigaction{
        .handler = .{ .handler = onFatalSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);
    std.posix.sigaction(std.posix.SIG.HUP, &act, null);
}

pub const Tui = struct {
    out_fd: std.posix.fd_t,
    in_fd: std.posix.fd_t,
    lang: i18n.Lang,
    is_tty: bool,
    line_buf: [16 * 1024]u8 = undefined,
    orig_termios: ?std.posix.termios = null,

    const Self = @This();

    pub fn init(lang: i18n.Lang) Self {
        const out_fd = std.posix.STDOUT_FILENO;
        const in_fd = std.posix.STDIN_FILENO;
        return .{
            .out_fd = out_fd,
            .in_fd = in_fd,
            .lang = lang,
            .is_tty = isTty(out_fd),
        };
    }

    // ── Raw Mode Lifecycle ─────────────────────────────────────────────────

    pub fn enterRawMode(self: *Self) void {
        if (!self.is_tty) return;
        const current = std.posix.tcgetattr(self.in_fd) catch return;
        self.orig_termios = current;

        // Publish to file scope so a SIGTERM/SIGHUP handler can restore the terminal.
        g_term_orig = current;
        g_term_in_fd = self.in_fd;
        g_term_out_fd = self.out_fd;
        installTerminalSignalHandlers();

        var raw = current;
        raw.lflag.ECHO = false;
        raw.lflag.ICANON = false;
        raw.lflag.ISIG = false;

        raw.cc[@intFromEnum(std.posix.V.MIN)] = 1;
        raw.cc[@intFromEnum(std.posix.V.TIME)] = 0;

        std.posix.tcsetattr(self.in_fd, .FLUSH, raw) catch {};
    }

    pub fn exitRawMode(self: *Self) void {
        if (self.orig_termios) |orig| {
            std.posix.tcsetattr(self.in_fd, .FLUSH, orig) catch {};
            self.orig_termios = null;
            g_term_orig = null;
        }
    }

    pub fn readKey(self: *Self) !KeyEvent {
        var byte: [1]u8 = undefined;
        const n = try std.posix.read(self.in_fd, &byte);
        if (n == 0) return error.EndOfStream;
        const c = byte[0];

        if (c == 3) return .{ .key = .ctrl_c };
        if (c == '\r' or c == '\n') return .{ .key = .enter };
        if (c == ' ') return .{ .key = .space };
        if (c == 127 or c == 8) return .{ .key = .backspace };

        if (c == '\x1b') {
            // Disambiguate a lone ESC from a CSI/SS3 sequence whose bytes may arrive in a
            // separate read (common over SSH, where ESC and "[A" land in different packets).
            // A short poll timeout — not poll(0) — gives the rest of the sequence time to
            // arrive instead of misreporting .escape and leaking "[A" as stray .char events.
            const intro = self.readByteTimeout(50) orelse return .{ .key = .escape };
            if (intro != '[' and intro != 'O') return .{ .key = .escape };

            var final = self.readByteTimeout(50) orelse return .{ .key = .escape };
            // Drain CSI parameter bytes (0x30-0x3F) until a final byte (0x40-0x7E) so longer
            // sequences (Delete = ESC [ 3 ~, modified arrows ESC [ 1 ; 5 A) are fully
            // consumed rather than leaving trailing bytes behind.
            while (final >= 0x30 and final <= 0x3F) {
                final = self.readByteTimeout(50) orelse break;
            }
            return switch (final) {
                'A' => .{ .key = .up },
                'B' => .{ .key = .down },
                'C' => .{ .key = .right },
                'D' => .{ .key = .left },
                else => .{ .key = .escape },
            };
        }
        return .{ .key = .char, .ch = c };
    }

    /// Poll `in_fd` for up to `timeout_ms` and read a single byte; null on timeout/EOF/error.
    fn readByteTimeout(self: *Self, timeout_ms: i32) ?u8 {
        var fds = [_]std.posix.pollfd{
            .{ .fd = self.in_fd, .events = std.posix.POLL.IN, .revents = 0 },
        };
        const p = std.posix.poll(&fds, timeout_ms) catch return null;
        if (p == 0) return null;
        var byte: [1]u8 = undefined;
        const n = std.posix.read(self.in_fd, &byte) catch return null;
        if (n == 0) return null;
        return byte[0];
    }

    // ── Low-level output ───────────────────────────────────────────────────

    /// Move cursor up N physical rows
    pub fn cursorUp(self: *Self, n: usize) void {
        if (n == 0) return;
        self.print("\x1b[{d}A", .{n});
    }

    /// Query terminal width via ioctl. Falls back to 80.
    pub fn getTermWidth(self: *Self) u16 {
        if (!self.is_tty) return 80;
        var ws: std.posix.winsize = .{ .row = 0, .col = 0, .xpixel = 0, .ypixel = 0 };
        const rc = std.posix.system.ioctl(self.out_fd, std.posix.T.IOCGWINSZ, @intFromPtr(&ws));
        if (std.posix.errno(rc) == .SUCCESS and ws.col > 0) return ws.col;
        return 80;
    }

    /// Clear current line and move to beginning
    pub fn clearLine(self: *Self) void {
        self.writeRaw("\x1b[2K\r");
    }

    /// Write raw bytes to stdout.
    pub fn writeRaw(self: *Self, bytes: []const u8) void {
        linux_io.writeAllFd(self.out_fd, bytes);
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

    /// Create a spinner for a task label. MUST call .start() on the returned instance.
    pub fn spinner(self: *Self, label: []const u8) Spinner {
        return Spinner{ .tui = self, .label = label };
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
        self.print("{s}  │{s}            {s}⚡  m t p r o t o . z i g{s}             {s}│{s}\n", .{
            Color.gray,   Color.reset,
            Color.header, Color.reset,
            Color.gray,   Color.reset,
        });

        self.print("{s}  │{s}                                                  {s}│{s}\n", .{ Color.gray, Color.reset, Color.gray, Color.reset });

        // Subtitle
        self.print("{s}  │{s}            {s}installer & control panel{s}             {s}│{s}\n", .{
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
            fn apply(tui: *Self, s_items: []const []const u8, s_sel: usize, width: u16) usize {
                var lines: usize = 0;
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
                    const vis = 7 + visibleLen(item); // "  │  ❯ " = 7 visible chars
                    lines += physicalRows(vis, width);
                }
                tui.clearLine();
                const nav_hint = i18n.get(tui.lang, .tui_nav_hint_menu);
                tui.print("  {s}╰─❯{s} {s}{s}{s}\n", .{
                    Color.gray, Color.reset, Color.dim, nav_hint, Color.reset,
                });
                // "  ╰─❯ " prefix is 6 display columns; use the localized hint's real width.
                lines += physicalRows(6 + visibleLen(nav_hint), width);
                return lines;
            }
        }.apply;

        var drawn_lines = draw(self, items, selected, self.getTermWidth());

        self.enterRawMode();
        defer self.exitRawMode();

        while (true) {
            // EOF on stdin (e.g. `mtbuddy < /dev/null`, piped/scripted input) must abort
            // the interactive flow — `catch continue` here re-read EOF forever, pinning a
            // CPU core. Only transient read errors retry.
            const ev = self.readKey() catch |err| switch (err) {
                error.EndOfStream => return error.EndOfStream,
                else => continue,
            };
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
            } else if (ev.key == .escape or ev.key == .left) {
                self.print("\n", .{});
                return error.GoBack;
            } else if (ev.key == .ctrl_c) {
                self.print("\n\n  {s}{s}{s}\n", .{ Color.dim, i18n.get(self.lang, .tui_exited), Color.reset });
                self.exitRawMode();
                std.process.exit(0);
            }

            if (changed) {
                self.cursorUp(drawn_lines);
                self.writeRaw("\x1b[J");
                drawn_lines = draw(self, items, selected, self.getTermWidth());
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

        const line = self.readLineOrBack() catch |err| switch (err) {
            error.GoBack => return error.GoBack,
            else => return default,
        };
        const trimmed = std.mem.trim(u8, line, &[_]u8{ ' ', '\t', '\r', '\n' });

        if (trimmed.len == 0) return default;

        const first = std.ascii.toLower(trimmed[0]);
        if (first == 'y' or first == 'd') return true; // y, yes, да
        if (first == 'n') return false;
        // Russian, both cases: д=0xd0 0xb4 / Д=0xd0 0x94 ; н=0xd0 0xbd / Н=0xd0 0x9d.
        // Without the capital forms, typing «Нет» at a default-yes prompt fell through to
        // `return default` (== yes) — the action proceeded despite an explicit refusal.
        if (trimmed.len >= 2 and trimmed[0] == 0xd0) {
            if (trimmed[1] == 0xb4 or trimmed[1] == 0x94) return true; // д/Д
            if (trimmed[1] == 0xbd or trimmed[1] == 0x9d) return false; // н/Н
        }

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

        const line = self.readLineOrBack() catch |err| switch (err) {
            error.GoBack => return error.GoBack,
            else => return default orelse error.InputError,
        };
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

        var selected: usize = 0;

        const draw = struct {
            /// Draw checklist and return the exact number of physical terminal rows emitted.
            fn apply(tui: *Self, s_items: []const []const u8, s_helps: []const []const u8, s_state: u32, s_sel: usize, width: u16) usize {
                var lines: usize = 0;

                // Separator
                tui.clearLine();
                tui.print("  {s}│{s}\n", .{ Color.gray, Color.reset });
                lines += 1;

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
                    // "  │  ❯ [▣] " = 11 visible columns + item text
                    lines += physicalRows(11 + visibleLen(item), width);

                    if (idx < s_helps.len) {
                        // Split on explicit \n to maintain left border on each line
                        var it = std.mem.splitScalar(u8, s_helps[idx], '\n');
                        while (it.next()) |line| {
                            tui.clearLine();
                            tui.print("  {s}│{s}       {s}{s}{s}\n", .{
                                Color.gray,  Color.reset,
                                Color.dim,   line,
                                Color.reset,
                            });
                            // "  │       " = 10 visible columns + help text
                            lines += physicalRows(10 + visibleLen(line), width);
                        }
                        tui.clearLine();
                        tui.print("  {s}│{s}\n", .{ Color.gray, Color.reset });
                        lines += 1;
                    }
                }
                tui.clearLine();
                const nav_hint = i18n.get(tui.lang, .tui_nav_hint_checkbox);
                tui.print("  {s}╰─❯{s} {s}{s}{s}\n", .{
                    Color.gray, Color.reset, Color.dim, nav_hint, Color.reset,
                });
                lines += physicalRows(6 + visibleLen(nav_hint), width); // localized footer width

                return lines;
            }
        }.apply;

        // Initial draw, capturing the exact physical line count
        var drawn_lines = draw(self, items, helps, state, selected, self.getTermWidth());

        self.enterRawMode();
        defer self.exitRawMode();

        while (true) {
            // See menu(): abort on stdin EOF instead of spinning at 100% CPU.
            const ev = self.readKey() catch |err| switch (err) {
                error.EndOfStream => return error.EndOfStream,
                else => continue,
            };
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
                self.print("\n\n  {s}{s}{s}\n", .{ Color.dim, i18n.get(self.lang, .tui_exited), Color.reset });
                self.exitRawMode();
                std.process.exit(0);
            }

            if (changed) {
                // Move up exactly the physical rows we emitted previously
                self.cursorUp(drawn_lines);
                // Clear stale text (handles terminal resize wider)
                self.writeRaw("\x1b[J");
                // Re-evaluate width and redraw
                drawn_lines = draw(self, items, helps, state, selected, self.getTermWidth());
            }
        }
    }

    // ── Summary Box ────────────────────────────────────────────────────────

    /// Print a bordered summary box (for final output).
    pub fn summaryBox(self: *Self, title: []const u8, lines: []const SummaryLine) void {
        self.writeRaw("\n");
        self.print("  {s}╭──────────────────────────────────────────────────────────────────╮{s}\n", .{ Color.gray, Color.reset });

        // Title line
        const title_len = std.unicode.utf8CountCodepoints(title) catch title.len;
        const box_interior = 66;
        const title_pad = if (title_len + 1 < box_interior) box_interior - title_len - 1 else 0;
        var title_pad_buf: [64]u8 = undefined;
        @memset(title_pad_buf[0..title_pad], ' ');

        self.print("  {s}│{s} {s}{s}{s}{s}{s}│{s}\n", .{
            Color.gray,   Color.reset,
            Color.header, title,
            Color.reset,  title_pad_buf[0..title_pad],
            Color.gray,   Color.reset,
        });
        self.print("  {s}├──────────────────────────────────────────────────────────────────┤{s}\n", .{ Color.gray, Color.reset });
        self.print("  {s}│{s}                                                                  {s}│{s}\n", .{ Color.gray, Color.reset, Color.gray, Color.reset });

        for (lines) |line| {
            switch (line.style) {
                .label_value => {
                    const l_len = std.unicode.utf8CountCodepoints(line.label) catch line.label.len;
                    const lp = if (l_len < 12) 12 - l_len else 0;
                    var l_pad: [16]u8 = undefined;
                    @memset(l_pad[0..lp], ' ');

                    const v_len = std.unicode.utf8CountCodepoints(line.value) catch line.value.len;
                    const used = 2 + l_len + lp + v_len; // "  " prefix + label + pad + value
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
                    self.print("  {s}│{s}                                                                  {s}│{s}\n", .{
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

        self.print("  {s}│{s}                                                                  {s}│{s}\n", .{
            Color.gray, Color.reset, Color.gray, Color.reset,
        });
        self.print("  {s}╰──────────────────────────────────────────────────────────────────╯{s}\n\n", .{
            Color.gray, Color.reset,
        });
    }

    // ── Section Header ─────────────────────────────────────────────────────

    pub fn section(self: *Self, title: []const u8) void {
        self.writeRaw("\n");

        var clean_title = title;
        if (std.mem.indexOf(u8, title, "  ")) |idx| {
            clean_title = title[idx + 2 ..];
        }

        const title_len = std.unicode.utf8CountCodepoints(clean_title) catch clean_title.len;
        const inner = 66;
        const pad = if (title_len + 4 < inner) inner - title_len - 4 else 0;
        var pad_buf: [64]u8 = undefined;
        @memset(pad_buf[0..@min(pad, pad_buf.len)], ' ');

        self.print("  {s}╭──────────────────────────────────────────────────────────────────╮{s}\n", .{ Color.gray, Color.reset });
        self.print("  {s}│{s} {s}⚙  {s}{s}{s}{s}{s}│{s}\n", .{
            Color.gray,                         Color.reset,
            Color.bold,                         Color.bright_yellow,
            clean_title,                        Color.reset,
            pad_buf[0..@min(pad, pad_buf.len)], Color.gray,
            Color.reset,
        });
        self.print("  {s}╰──────────────────────────────────────────────────────────────────╯{s}\n", .{ Color.gray, Color.reset });
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
            const n = std.posix.read(self.in_fd, &byte) catch return error.InputError;
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
            const n = std.posix.read(self.in_fd, &byte) catch break;
            if (n == 0 or byte[0] == '\n') break;
        }
        return self.line_buf[0..pos];
    }

    /// Read a line for a prompt, but return error.GoBack if the user presses Esc/← at the
    /// empty prompt (the natural "I want to step back" moment). TTY input stays in raw mode
    /// until Enter so every byte lives in one editable buffer. Switching to cooked mode after
    /// the first byte would make that byte invisible to terminal Backspace and FLUSH the rest
    /// of a paste while restoring termios (#378). Non-TTY input has no "back" — it reads a
    /// normal cooked line.
    fn readLineOrBack(self: *Self) ![]const u8 {
        if (!self.is_tty) return self.readLine();

        self.enterRawMode();
        defer self.exitRawMode();

        var pos: usize = 0;
        while (true) {
            const ev = self.readKey() catch |err| {
                if (err == error.EndOfStream and pos > 0) return self.line_buf[0..pos];
                return err;
            };
            switch (ev.key) {
                .escape, .left => {
                    if (pos == 0) return error.GoBack;
                },
                .ctrl_c => {
                    self.exitRawMode();
                    self.print("\n\n  {s}{s}{s}\n", .{ Color.dim, i18n.get(self.lang, .tui_exited), Color.reset });
                    std.process.exit(0);
                },
                .enter => {
                    self.writeRaw("\n");
                    return self.line_buf[0..pos];
                },
                .char => {
                    if (pos < self.line_buf.len) {
                        self.line_buf[pos] = ev.ch;
                        pos += 1;
                        self.writeRaw(&[_]u8{ev.ch});
                    }
                },
                .space => {
                    if (pos < self.line_buf.len) {
                        self.line_buf[pos] = ' ';
                        pos += 1;
                        self.writeRaw(" ");
                    }
                },
                .backspace => {
                    if (pos == 0) continue;

                    // Remove one complete UTF-8 codepoint, not just its last continuation
                    // byte. VPN links are ASCII, but input() is shared by localized prompts.
                    var start = pos - 1;
                    while (start > 0 and self.line_buf[start] & 0xc0 == 0x80) {
                        start -= 1;
                    }
                    const columns = @max(visibleLen(self.line_buf[start..pos]), 1);
                    pos = start;
                    for (0..columns) |_| self.writeRaw("\x08 \x08");
                },
                else => {}, // Up/down/right do not edit a simple line prompt.
            }
        }
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

test "visibleLen counts display columns: ASCII=1, emoji/CJK=2, combining/VS=0" {

    try std.testing.expectEqual(@as(usize, 5), visibleLen("hello"));

    // Emoji is double-width.

    try std.testing.expectEqual(@as(usize, 2), visibleLen("\xF0\x9F\x9A\x80")); // 🚀 U+1F680

    // CJK is double-width.

    try std.testing.expectEqual(@as(usize, 4), visibleLen("\xE4\xBD\xA0\xE5\xA5\xBD")); // 你好

    // Variation selector (U+FE0F) is zero-width.

    try std.testing.expectEqual(@as(usize, 1), visibleLen("\xE2\x9C\x94\xEF\xB8\x8F")); // ✔️

}

fn expectRawPromptInput(input: []const u8, expected: []const u8) !void {
    const input_pipe = try std.Io.Threaded.pipe2(.{});
    defer std.Io.Threaded.closeFd(input_pipe[0]);
    defer std.Io.Threaded.closeFd(input_pipe[1]);

    const output_pipe = try std.Io.Threaded.pipe2(.{});
    defer std.Io.Threaded.closeFd(output_pipe[0]);
    defer std.Io.Threaded.closeFd(output_pipe[1]);

    var written: usize = 0;
    while (written < input.len) {
        const rc = std.posix.system.write(input_pipe[1], input[written..].ptr, input.len - written);
        switch (std.posix.errno(rc)) {
            .SUCCESS => written += @intCast(rc),
            .INTR => continue,
            else => return error.TestInputWriteFailed,
        }
    }

    var ui: Tui = .{
        .out_fd = output_pipe[1],
        .in_fd = input_pipe[0],
        .lang = .en,
        .is_tty = true,
    };
    const line = try ui.readLineOrBack();
    try std.testing.expectEqualStrings(expected, line);
}

test "raw prompt backspace can erase the first pasted byte" {
    // Regression for #378: the old raw-to-cooked handoff kept the first byte in an
    // application-only seed. Terminal backspace could not erase it, so pasting the
    // link again produced `vvpn://...`.
    try expectRawPromptInput("v\x7fvpn://example\n", "vpn://example");
}

test "raw prompt backspace erases a complete UTF-8 codepoint" {
    try expectRawPromptInput("\xD0\x94\x7fX\n", "X"); // Д, Backspace, X
}
