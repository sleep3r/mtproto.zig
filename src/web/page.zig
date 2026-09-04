//! The two pages the relay serves: an ordinary cover site, and the bridge.
//!
//! ## Why they look identical
//!
//! Telegram Desktop only ever navigates to `https://<host>/?bridge=<capability>`, and
//! that capability is `HMAC-SHA256(user secret)` — so a visitor who cannot present one
//! derived from a configured user secret never receives the bridge at all. Both
//! responses therefore render the *same* visible page; the bridge response merely adds
//! an inline script. An active prober without a valid secret sees a plain website, and
//! a curious human who opens the bridge link sees the same plain website too.
//!
//! ## Why the cover page is generated, not a constant
//!
//! It used to be one comptime string, which meant every mtproto.zig relay on earth
//! answered `GET /` with byte-identical HTML: one SHA-256 of the body — or one grep for
//! "This host serves static content only." — turned the list of relay domains anybody
//! can lift out of CT logs into a list of confirmed deployments, no secret and no
//! behavioural probing needed. `renderCover` picks the wording, the palette, the type
//! and the layout from a hash of the relay's own hostname instead, so there is no
//! cross-deployment signature left to match. Its only input is the hostname the visitor
//! already typed, so nothing about the operator or their users can reach the page.
//!
//! ## What the bridge script may use
//!
//! It runs inside `lib_webview`'s restricted profile, whose document-start lock script
//! `undefined`s storage, workers, WebAssembly, WebRTC, WebTransport, media capture and
//! more, and installs a `<meta>` CSP that permits only inline script plus connections to
//! this exact origin. So the script below is deliberately ES5-ish, allocation-light, and
//! uses nothing but `WebSocket`, `postMessage`, `setInterval` and the DOM.
//!
//! ## The two client transports it must speak
//!
//! * **Hidden WebView** (the normal path): tdesktop injects a frozen `TelegramWebProxy`
//!   object at document start and puts a nonce in `#android=`. We must set `onmessage`
//!   *before* announcing ourselves with `tproxy-android-init`, because HELLO follows
//!   immediately. Binary arrives as `ArrayBuffer`, control as a JSON string, and our own
//!   control messages go back as JSON strings.
//! * **System-browser fallback**: tdesktop's loopback page frames us and posts
//!   `{t:'tproxy-init',v:1}` with a `MessagePort`. There, control messages are plain
//!   objects, not JSON strings.
//!
//! The handler must never throw: tdesktop's injected bridge turns an exception into
//! `send('f')`, which fails the whole carrier. Every entry point is wrapped.
//!
//! References: tdesktop `web_proxy_webview.cpp` (`BridgeScript`, `handleControl`) and
//! `web_proxy_transport.cpp` (`Transport::Private::page`).

const std = @import("std");

/// The closing tags every cover page ends with. `renderBridge` splits here to inject the
/// bridge script, so a generated page that does not end exactly like this is rejected.
const cover_tail = "\n</body></html>";

/// One placeholder site's words. Deliberately unremarkable and interchangeable: a domain
/// that serves a small static placeholder is the least interesting thing on the internet,
/// and there are millions of these pages already.
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

/// Domain separation for the page seed, so the digest can never collide with any other
/// use of the hostname (the bridge capability HMACs the same string under a user secret).
const cover_label = "mtproto.zig web cover page v1\n";

/// Render this deployment's cover page.
///
/// Everything visible is selected from a hash of `domain`: the same host always gets the
/// same page (so it looks like a site, not like something regenerating itself), and two
/// hosts get different ones (so no single body hash or grep string identifies a relay).
/// The domain itself never appears in the output — the page must say nothing the visitor
/// did not already know.
pub fn renderCover(allocator: std.mem.Allocator, domain: []const u8) ![]u8 {
    var seed: [32]u8 = undefined;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(cover_label);
    hasher.update(domain);
    hasher.final(&seed);

    const text = cover_texts[seed[0] % cover_texts.len];
    const palette = palettes[seed[1] % palettes.len];
    const font = font_stacks[seed[2] % font_stacks.len];
    const base_px: u8 = 15 + seed[3] % 3;
    const line_height = line_heights[seed[4] % line_heights.len];
    const width_rem: u8 = 28 + seed[5] % 7;
    const padding = paddings[seed[6] % paddings.len];
    const heading_size = heading_sizes[seed[7] % heading_sizes.len];
    // A placeholder is as often pinned to the top of the page as centred in it.
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

const script_head =
    \\
    \\<script>
    \\(function(){"use strict";
    \\var WS_PATH=
;

const script_body =
    \\;
    \\var CAP=null,NONCE=null,client=null,ws=null,wsReady=false,adopted=false;
    \\var toClient=[],toRelay=[],preAdopt=[],attempts=0,dead=false,up=0,down=0,lastUp=0,lastDown=0;
    \\try{var m=/[?&]bridge=([A-Za-z0-9_-]{43})(?:&|$)/.exec(location.search);if(m)CAP=m[1];
    \\// The nonce is base64url, which needs no escaping, but decode once anyway so a
    \\// platform that percent-encodes the fragment still matches what the client expects.
    \\var hash=location.hash||"";
    \\if(hash.indexOf("#android=")===0){
    \\ var raw=hash.slice(9);
    \\ try{raw=decodeURIComponent(raw)}catch(e){}
    \\ if(raw.length&&raw.length<=128)NONCE=raw;
    \\}}catch(e){}
    \\
    \\function control(obj){
    \\ if(!client)return;
    \\ try{client.control(obj)}catch(e){}
    \\}
    \\function status(state){control({t:"status",state:state})}
    \\function fail(){
    \\ if(dead)return;dead=true;status("failed");
    \\ try{if(ws)ws.close(1000)}catch(e){}
    \\ ws=null;wsReady=false;
    \\}
    \\function toClientDeliver(buf){
    \\ if(dead)return;
    \\ if(!client){toClient.push(buf);return}
    \\ try{client.binary(buf);adopted=true}catch(e){fail()}
    \\}
    \\function flushToClient(){
    \\ while(client&&toClient.length){toClientDeliver(toClient.shift())}
    \\}
    \\function toRelaySend(buf){
    \\ if(dead)return;
    \\ // Until the carrier is adopted the only thing the client has sent is HELLO, and a
    \\ // reconnect would land on a fresh relay session that never received it — so keep a
    \\ // copy and replay it. After adoption a reconnect is not attempted at all.
    \\ if(!adopted&&preAdopt.indexOf(buf)<0)preAdopt.push(buf);
    \\ if(!wsReady){toRelay.push(buf);return}
    \\ try{up+=buf.byteLength;ws.send(buf)}catch(e){fail()}
    \\}
    \\function flushToRelay(){
    \\ while(wsReady&&toRelay.length){toRelaySend(toRelay.shift())}
    \\}
    \\
    \\function connect(){
    \\ if(dead||ws||!CAP)return;
    \\ status(attempts?"reconnecting":"connecting");
    \\ var scheme="wss://";
    \\ var socket;
    \\ try{socket=new WebSocket(scheme+location.host+WS_PATH+"?b="+CAP)}catch(e){fail();return}
    \\ ws=socket;socket.binaryType="arraybuffer";
    \\ socket.onopen=function(){
    \\  if(ws!==socket)return;
    \\  wsReady=true;
    \\  if(attempts){toRelay=preAdopt.slice()}
    \\  flushToRelay();status("connected");
    \\ };
    \\ socket.onmessage=function(ev){
    \\  if(ws!==socket)return;
    \\  var d=ev.data;if(!(d instanceof ArrayBuffer)||!d.byteLength)return;
    \\  down+=d.byteLength;toClientDeliver(d);
    \\ };
    \\ socket.onerror=function(){};
    \\ socket.onclose=function(){
    \\  if(ws!==socket)return;
    \\  ws=null;wsReady=false;
    \\  // Once the client has adopted this carrier its logical sockets live in the relay
    \\  // session we just lost; no session is migrated across carriers, so reconnecting
    \\  // here would hand the client a second WELCOME and it would drop us anyway.
    \\  if(adopted||dead){fail();return}
    \\  if(attempts>=2){fail();return}
    \\  attempts++;setTimeout(connect,attempts*1000);
    \\ };
    \\}
    \\
    \\function clientControl(text){
    \\ var obj=null;try{obj=JSON.parse(text)}catch(e){return}
    \\ if(obj&&obj.t==="close")fail();
    \\}
    \\function useNative(bridge){
    \\ if(client)return;
    \\ client={
    \\  binary:function(buf){bridge.postMessage(buf)},
    \\  control:function(obj){bridge.postMessage(JSON.stringify(obj))}
    \\ };
    \\ bridge.onmessage=function(ev){
    \\  try{
    \\   var d=ev.data;
    \\   if(typeof d==="string"){clientControl(d);return}
    \\   if(d instanceof ArrayBuffer&&d.byteLength)toRelaySend(d);
    \\  }catch(e){}
    \\ };
    \\ // Announce only after onmessage is live: HELLO follows this message immediately.
    \\ control({t:"tproxy-android-init",v:1,nonce:NONCE});
    \\ flushToClient();connect();
    \\}
    \\function useParentPort(port){
    \\ if(client)return;
    \\ client={
    \\  binary:function(buf){port.postMessage(buf,[buf])},
    \\  control:function(obj){port.postMessage(obj)}
    \\ };
    \\ port.onmessage=function(ev){
    \\  try{
    \\   var d=ev.data;
    \\   if(d instanceof ArrayBuffer){if(d.byteLength)toRelaySend(d);return}
    \\   if(d&&d.t==="close")fail();
    \\  }catch(e){}
    \\ };
    \\ try{port.start()}catch(e){}
    \\ flushToClient();connect();
    \\}
    \\
    \\addEventListener("message",function(ev){
    \\ try{
    \\  var d=ev.data;
    \\  if(!d||d.t!=="tproxy-init"||d.v!==1)return;
    \\  if(!ev.ports||!ev.ports.length)return;
    \\  var o=ev.origin||"";
    \\  if(o.indexOf("http://127.0.0.1:")!==0)return;
    \\  useParentPort(ev.ports[0]);
    \\ }catch(e){}
    \\});
    \\
    \\setInterval(function(){
    \\ if(!client)return;
    \\ var du=up-lastUp,dd=down-lastDown;
    \\ if(!du&&!dd)return;
    \\ lastUp=up;lastDown=down;
    \\ control({t:"traffic",up:du,down:dd});
    \\},1000);
    \\
    \\if(CAP){
    \\ var native=null;try{native=window.TelegramWebProxy}catch(e){}
    \\ if(native&&NONCE)useNative(native);
    \\ // Otherwise we are the framed fallback and wait for the parent's tproxy-init.
    \\ // Scrub the capability out of the visible URL once it has been read. tdesktop
    \\ // accepts the scrubbed https://host/ form as a message source.
    \\ try{history.replaceState(null,"",location.pathname)}catch(e){}
    \\}
    \\})();
    \\</script>
    \\
    \\</body></html>
;

/// Render the bridge page: this deployment's own `cover` page with `ws_path` baked into
/// the injected script. Serving a *different* visible page to a capability holder would
/// undo the whole point of the cover, so the bridge is always built from it.
///
/// The page is otherwise byte-identical for every user: the capability is read from
/// `location.search` by the script rather than templated into the body, so the response
/// carries no per-user bytes at all.
pub fn renderBridge(allocator: std.mem.Allocator, cover: []const u8, ws_path: []const u8) ![]u8 {
    if (ws_path.len == 0 or ws_path[0] != '/' or std.mem.startsWith(u8, ws_path, "//") or std.mem.indexOfAny(u8, ws_path, "?#\\") != null) return error.InvalidWsPath;
    if (!std.mem.endsWith(u8, cover, cover_tail)) return error.InvalidCoverPage;
    const cover_head = cover[0 .. cover.len - cover_tail.len];

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, cover_head);
    try out.appendSlice(allocator, script_head);
    try appendJsString(allocator, &out, ws_path);
    try out.appendSlice(allocator, script_body);
    return out.toOwnedSlice(allocator);
}

test "bridge rejects non-origin websocket paths" {
    for ([_][]const u8{ "", "socket", "//other.test/socket", "/socket?x=1", "/socket#fragment", "/a\\b" }) |path| {
        try std.testing.expectError(error.InvalidWsPath, renderBridge(std.testing.allocator, "", path));
    }
}

/// Append `value` as a double-quoted JavaScript string literal, escaping everything that
/// could end the literal or the surrounding `<script>` element.
fn appendJsString(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: []const u8) !void {
    try out.append(allocator, '"');
    for (value) |c| {
        switch (c) {
            '"', '\\' => {
                try out.append(allocator, '\\');
                try out.append(allocator, c);
            },
            '<', '>', '&' => try out.print(allocator, "\\u{x:0>4}", .{c}),
            '\r', '\n' => return error.InvalidWebSocketPath,
            else => {
                if (c < 0x20 or c == 0x7f) return error.InvalidWebSocketPath;
                try out.append(allocator, c);
            },
        }
    }
    try out.append(allocator, '"');
}

// ── tests ─────────────────────────────────────────────────────────────────────

test "the cover page differs between deployments and leaks nothing about them" {
    const allocator = std.testing.allocator;
    const one = try renderCover(allocator, "relay.example.com");
    defer allocator.free(one);
    const two = try renderCover(allocator, "other.example.org");
    defer allocator.free(two);

    // The whole point: no single body hash and no single grep string identifies a relay.
    try std.testing.expect(!std.mem.eql(u8, one, two));
    // The visitor already knows the hostname, but the page must not repeat it — nor
    // anything else about the deployment.
    try std.testing.expect(!std.mem.containsAtLeast(u8, one, 1, "relay.example.com"));
    try std.testing.expect(!std.mem.containsAtLeast(u8, two, 1, "other.example.org"));
    // Stable for a given host: a site whose text changed on every fetch would itself be
    // the tell, and the relay renders this page once at startup anyway.
    const again = try renderCover(allocator, "relay.example.com");
    defer allocator.free(again);
    try std.testing.expectEqualStrings(one, again);

    for ([_][]const u8{ one, two }) |html| {
        try std.testing.expect(std.mem.startsWith(u8, html, "<!doctype html>"));
        try std.testing.expect(std.mem.endsWith(u8, html, cover_tail));
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, html, "<main>"));
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, html, "</body>"));
        // Everything is inline: an external reference would be a request the cover page
        // makes and a plain website's placeholder would not.
        try std.testing.expect(!std.mem.containsAtLeast(u8, html, 1, "http://"));
        try std.testing.expect(!std.mem.containsAtLeast(u8, html, 1, "https://"));
    }
}

test "bridge page embeds the websocket path in this deployment's own cover page" {
    const allocator = std.testing.allocator;
    const cover = try renderCover(allocator, "relay.example.com");
    defer allocator.free(cover);
    const html = try renderBridge(allocator, cover, "/api/v1/socket");
    defer allocator.free(html);

    // A capability holder must see exactly what a prober sees, plus the script.
    try std.testing.expect(std.mem.startsWith(u8, html, cover[0 .. cover.len - cover_tail.len]));
    try std.testing.expect(std.mem.containsAtLeast(u8, html, 1, "var WS_PATH=\"/api/v1/socket\";"));
    try std.testing.expect(std.mem.endsWith(u8, html, "</body></html>"));
    try std.testing.expect(std.mem.containsAtLeast(u8, html, 1, "tproxy-android-init"));
    try std.testing.expect(std.mem.containsAtLeast(u8, html, 1, "tproxy-init"));

    // The script has to land inside the document, so a cover page that does not end in
    // the closing tags is refused rather than silently appended to.
    try std.testing.expectError(
        error.InvalidCoverPage,
        renderBridge(allocator, "<!doctype html><html></html>", "/s"),
    );
}

test "the bridge page carries no per-user bytes" {
    // The capability must be read from location.search at runtime, never templated in.
    const allocator = std.testing.allocator;
    const cover = try renderCover(allocator, "relay.example.com");
    defer allocator.free(cover);
    const html = try renderBridge(allocator, cover, "/s");
    defer allocator.free(html);
    try std.testing.expect(std.mem.containsAtLeast(u8, html, 1, "location.search"));
}

test "a path that could break out of the script literal is refused" {
    const allocator = std.testing.allocator;
    const cover = try renderCover(allocator, "relay.example.com");
    defer allocator.free(cover);
    try std.testing.expectError(
        error.InvalidWebSocketPath,
        renderBridge(allocator, cover, "/a\nb"),
    );
    const escaped = try renderBridge(allocator, cover, "/a<b>c&d\"e");
    defer allocator.free(escaped);
    try std.testing.expect(!std.mem.containsAtLeast(u8, escaped, 1, "<b>"));
    try std.testing.expect(std.mem.containsAtLeast(u8, escaped, 1, "\\u003c"));
    try std.testing.expect(std.mem.containsAtLeast(u8, escaped, 1, "\\\""));
}
