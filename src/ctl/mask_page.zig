//! Generated placeholder page used by the masking installer.
//!
//! Each installation receives stable hostname-independent variation from a random seed,
//! avoiding a byte-identical default page across deployments.

const std = @import("std");

const cover_tail = "\n</body></html>";

const CoverText = struct {
    title: []const u8,
    heading: []const u8,
    body: []const u8,
};

const cover_texts = [_]CoverText{
    .{ .title = "Welcome", .heading = "Welcome", .body = "This server is up and running. There is no content at this address yet." },
    .{ .title = "Coming soon", .heading = "Coming soon", .body = "This site has not been published yet. Please check back later." },
    .{ .title = "Placeholder", .heading = "Placeholder page", .body = "The site for this domain has not been set up." },
    .{ .title = "Under construction", .heading = "Under construction", .body = "This page is still being worked on. Thanks for your patience." },
    .{ .title = "Maintenance", .heading = "Down for maintenance", .body = "The site is temporarily offline while some changes are made." },
    .{ .title = "New site", .heading = "It works!", .body = "The web server is installed and working. Replace this page with your own." },
    .{ .title = "Parked domain", .heading = "Domain parked", .body = "No website has been configured for this address." },
    .{ .title = "Index", .heading = "Nothing here yet", .body = "This address serves no content at the moment." },
};

const Palette = struct {
    bg: []const u8,
    fg: []const u8,
    muted: []const u8,
    dark_bg: []const u8,
    dark_fg: []const u8,
    dark_muted: []const u8,
};

const palettes = [_]Palette{
    .{ .bg = "#fbfbfc", .fg = "#1c1e21", .muted = "#6b7280", .dark_bg = "#0f1115", .dark_fg = "#e7e9ee", .dark_muted = "#9aa1ad" },
    .{ .bg = "#ffffff", .fg = "#222222", .muted = "#767676", .dark_bg = "#121212", .dark_fg = "#ededed", .dark_muted = "#a0a0a0" },
    .{ .bg = "#f7f6f3", .fg = "#2b2a27", .muted = "#7a776f", .dark_bg = "#1a1917", .dark_fg = "#e8e6e1", .dark_muted = "#a5a29a" },
    .{ .bg = "#f4f6f8", .fg = "#1f2933", .muted = "#69707d", .dark_bg = "#141a20", .dark_fg = "#e3e8ee", .dark_muted = "#95a0ad" },
    .{ .bg = "#fdfdfb", .fg = "#33322e", .muted = "#77756d", .dark_bg = "#17171a", .dark_fg = "#eceaea", .dark_muted = "#9c9a9a" },
    .{ .bg = "#f5f5f5", .fg = "#111111", .muted = "#666666", .dark_bg = "#101010", .dark_fg = "#f0f0f0", .dark_muted = "#909090" },
};

const font_stacks = [_][]const u8{
    "-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,Helvetica,Arial,sans-serif",
    "system-ui,-apple-system,\"Segoe UI\",Roboto,Arial,sans-serif",
    "\"Helvetica Neue\",Helvetica,Arial,sans-serif",
    "Georgia,\"Times New Roman\",Times,serif",
};

const line_heights = [_][]const u8{ "1.45", "1.5", "1.55", "1.6" };
const heading_sizes = [_][]const u8{ "1.125rem", "1.25rem", "1.375rem", "1.5rem" };
const paddings = [_][]const u8{ "1.5rem", "2rem", "2.5rem" };
const cover_label = "mtproto.zig web cover page v1\n";

pub fn renderCover(allocator: std.mem.Allocator, seed_value: []const u8) ![]u8 {
    var seed: [32]u8 = undefined;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(cover_label);
    hasher.update(seed_value);
    hasher.final(&seed);

    const text = cover_texts[seed[0] % cover_texts.len];
    const palette = palettes[seed[1] % palettes.len];
    const font = font_stacks[seed[2] % font_stacks.len];
    const base_px: u8 = 15 + seed[3] % 3;
    const line_height = line_heights[seed[4] % line_heights.len];
    const width_rem: u8 = 28 + seed[5] % 7;
    const padding = paddings[seed[6] % paddings.len];
    const heading_size = heading_sizes[seed[7] % heading_sizes.len];
    const layout = if (seed[8] & 1 == 0)
        "min-height:100vh;display:grid;place-items:center;"
    else
        "padding:4rem 1rem;";
    const align_rule = if (seed[9] & 1 == 0) "text-align:center" else "text-align:left";
    const robots = if (seed[10] & 1 == 0) "<meta name=\"robots\" content=\"noindex,nofollow\">\n" else "";

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.print(allocator,
        \\<!doctype html>
        \\<html lang="en"><head>
        \\<meta charset="utf-8">
        \\<meta name="viewport" content="width=device-width,initial-scale=1">
        \\{s}<title>{s}</title>
        \\<style>
        \\:root{{color-scheme:light dark}}
        \\body{{margin:0;{s}
        \\font:{d}px/{s} {s};
        \\background:{s};color:{s}}}
        \\main{{width:min({d}rem,calc(100% - 3rem));margin:0 auto;padding:{s};{s}}}
        \\h1{{margin:0 0 .5rem;font-size:{s};font-weight:600;letter-spacing:-.01em}}
        \\p{{margin:0;color:{s};font-size:.9375rem}}
        \\@media (prefers-color-scheme:dark){{body{{background:{s};color:{s}}}p{{color:{s}}}}}
        \\</style>
        \\</head><body>
        \\<main><h1>{s}</h1><p>{s}</p></main>
        \\</body></html>
    , .{
        robots,          text.title,
        layout,          base_px,
        line_height,     font,
        palette.bg,      palette.fg,
        width_rem,       padding,
        align_rule,      heading_size,
        palette.muted,   palette.dark_bg,
        palette.dark_fg, palette.dark_muted,
        text.heading,    text.body,
    });
    return out.toOwnedSlice(allocator);
}

test "mask page varies by seed without revealing it" {
    const allocator = std.testing.allocator;
    const one = try renderCover(allocator, "relay.example.com");
    defer allocator.free(one);
    const two = try renderCover(allocator, "other.example.org");
    defer allocator.free(two);

    try std.testing.expect(!std.mem.eql(u8, one, two));
    try std.testing.expect(!std.mem.containsAtLeast(u8, one, 1, "relay.example.com"));
    try std.testing.expect(!std.mem.containsAtLeast(u8, two, 1, "other.example.org"));
    const again = try renderCover(allocator, "relay.example.com");
    defer allocator.free(again);
    try std.testing.expectEqualStrings(one, again);

    for ([_][]const u8{ one, two }) |html| {
        try std.testing.expect(std.mem.startsWith(u8, html, "<!doctype html>"));
        try std.testing.expect(std.mem.endsWith(u8, html, cover_tail));
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, html, "<main>"));
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, html, "</body>"));
        try std.testing.expect(!std.mem.containsAtLeast(u8, html, 1, "http://"));
        try std.testing.expect(!std.mem.containsAtLeast(u8, html, 1, "https://"));
    }
}
