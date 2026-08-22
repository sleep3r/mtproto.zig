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

/// Visible markup, shared by both responses. Deliberately unremarkable: a domain that
/// serves a small static placeholder is the least interesting thing on the internet.
pub const cover_body =
    \\<!doctype html>
    \\<html lang="en"><head>
    \\<meta charset="utf-8">
    \\<meta name="viewport" content="width=device-width,initial-scale=1">
    \\<meta name="robots" content="noindex,nofollow">
    \\<title>Static Host</title>
    \\<style>
    \\:root{color-scheme:light dark}
    \\body{margin:0;min-height:100vh;display:grid;place-items:center;
    \\font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    \\background:#fbfbfc;color:#1c1e21}
    \\main{width:min(32rem,calc(100% - 3rem));padding:2rem;text-align:center}
    \\h1{margin:0 0 .5rem;font-size:1.25rem;font-weight:600;letter-spacing:-.01em}
    \\p{margin:0;color:#6b7280;font-size:.9375rem}
    \\@media (prefers-color-scheme:dark){body{background:#0f1115;color:#e7e9ee}p{color:#9aa1ad}}
    \\</style>
    \\</head><body>
    \\<main><h1>Nothing to see here</h1><p>This host serves static content only.</p></main>
    \\</body></html>
;

/// Everything before the injected `<script>` block — `cover_body` minus its trailing tags.
const cover_head = cover_body[0 .. cover_body.len - "\n</body></html>".len];

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
    \\ var scheme=location.protocol==="http:"?"ws://":"wss://";
    \\ var socket;
    \\ try{socket=new WebSocket(scheme+location.host+WS_PATH+"?b="+CAP)}catch(e){fail();return}
    \\ ws=socket;socket.binaryType="arraybuffer";
    \\ socket.onopen=function(){
    \\  if(ws!==socket)return;
    \\  wsReady=true;
    \\  if(attempts){toRelay=preAdopt.concat(toRelay)}
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
    \\  if(o.indexOf("http://127.0.0.1:")!==0&&o.indexOf("http://[::1]:")!==0)return;
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

/// Render the bridge page with `ws_path` baked into its script.
///
/// The page is otherwise byte-identical for every user: the capability is read from
/// `location.search` by the script rather than templated into the body, so the response
/// carries no per-user bytes at all.
pub fn renderBridge(allocator: std.mem.Allocator, ws_path: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, cover_head);
    try out.appendSlice(allocator, script_head);
    try appendJsString(allocator, &out, ws_path);
    try out.appendSlice(allocator, script_body);
    return out.toOwnedSlice(allocator);
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

test "cover head is the cover body without its closing tags" {
    try std.testing.expect(std.mem.startsWith(u8, cover_body, cover_head));
    try std.testing.expect(std.mem.endsWith(u8, cover_body, "</body></html>"));
    try std.testing.expect(!std.mem.containsAtLeast(u8, cover_head, 1, "</body>"));
}

test "bridge page embeds the websocket path and closes its tags" {
    const html = try renderBridge(std.testing.allocator, "/api/v1/socket");
    defer std.testing.allocator.free(html);
    try std.testing.expect(std.mem.containsAtLeast(u8, html, 1, "var WS_PATH=\"/api/v1/socket\";"));
    try std.testing.expect(std.mem.endsWith(u8, html, "</body></html>"));
    try std.testing.expect(std.mem.containsAtLeast(u8, html, 1, "tproxy-android-init"));
    try std.testing.expect(std.mem.containsAtLeast(u8, html, 1, "tproxy-init"));
}

test "the bridge page carries no per-user bytes" {
    // The capability must be read from location.search at runtime, never templated in.
    const html = try renderBridge(std.testing.allocator, "/s");
    defer std.testing.allocator.free(html);
    try std.testing.expect(std.mem.containsAtLeast(u8, html, 1, "location.search"));
}

test "a path that could break out of the script literal is refused" {
    try std.testing.expectError(
        error.InvalidWebSocketPath,
        renderBridge(std.testing.allocator, "/a\nb"),
    );
    const escaped = try renderBridge(std.testing.allocator, "/a<b>c&d\"e");
    defer std.testing.allocator.free(escaped);
    try std.testing.expect(!std.mem.containsAtLeast(u8, escaped, 1, "<b>"));
    try std.testing.expect(std.mem.containsAtLeast(u8, escaped, 1, "\\u003c"));
    try std.testing.expect(std.mem.containsAtLeast(u8, escaped, 1, "\\\""));
}
