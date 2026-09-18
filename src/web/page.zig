//! HTML generation for the authenticated browser bridge.
//!
//! The public response is owned by the configured site directory. The bridge is a
//! minimal script-only document with no styles or external dependencies, so public
//! markup, closing tags, and resources cannot change the carrier protocol.
//!
//! ## What the bridge script may use
//!
//! It runs inside `lib_webview`'s restricted profile. The relay supplies a short-lived
//! carrier bearer and CSP nonce to `renderSessionBridge`; the bearer is sent only as the
//! WebSocket subprotocol and never copied into the WebSocket URL. The script is
//! deliberately ES5-ish and uses a small browser API surface.
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

const bridge_document_head =
    \\<!doctype html>
    \\<html lang="en"><head>
    \\<meta charset="utf-8">
    \\<meta name="viewport" content="width=device-width,initial-scale=1">
    \\<meta name="tproxy-token" content="
;

const bridge_path_meta =
    \\">
    \\<meta name="tproxy-ws-path" content="
;

const bridge_script_open =
    \\">
    \\<title>Connection</title>
    \\</head><body>
    \\<script nonce="
;

const bridge_script_vars =
    \\">
    \\(function(){"use strict";
    \\var WS_PATH=
;

const bridge_token_var =
    \\,TOKEN=
;

const bridge_script_body =
    \\;
    \\var QUEUE_BYTES=33554432,QUEUE_ITEMS=16384,MAX_FRAME=1048576,MAX_FRAMES=4096;
    \\var client=null,nativeBridge=null,ws=null,wsReady=false,adopted=false,dead=false;
    \\// Keep bounded pre-WELCOME payload references for retry. Browser send() only
    \\// queues bytes locally; it does not prove the relay parsed HELLO. If it did parse
    \\// HELLO, the relay consumes the token and correctly rejects the retry.
    \\var replay=[],replayBytes=0,replayItems=0,sendIndex=0,attempts=0,retryTimer=0,pumpTimer=0;
    \\// socketQueue holds remaining payload bytes per WebSocket message. Its head index
    \\// avoids front-removal copies; bufferedAmount deltas retire whole or partial heads.
    \\var socketQueue=[],socketHead=0,socketItems=0,socketBytes=0;
    \\var up=0,down=0,lastUp=0,lastDown=0;
    \\var match=/^#android=([A-Za-z0-9_-]{43})$/.exec(location.hash||""),androidNonce=match?match[1]:null;
    \\function control(value){if(client&&!dead)try{client.control(value)}catch(e){}}
    \\function status(value){control({t:"status",state:value})}
    \\function clearReplay(){replay.length=0;replayBytes=0;replayItems=0;sendIndex=0}
    \\function clearSocketQueue(){socketQueue.length=0;socketHead=0;socketItems=0;socketBytes=0}
    \\function rawBuffered(){
    \\ if(!ws||!wsReady)return 0;
    \\ var value=Number(ws.bufferedAmount);return isFinite(value)&&value>0?value:0;
    \\}
    \\function compactSocketQueue(){
    \\ if(socketHead===socketQueue.length){clearSocketQueue();return}
    \\ if(socketHead>=1024&&socketHead*2>=socketQueue.length){socketQueue=socketQueue.slice(socketHead);socketHead=0}
    \\}
    \\function reconcileSocketQueue(){
    \\ var transmitted=socketBytes-rawBuffered();
    \\ if(transmitted<=0)return;
    \\ if(transmitted>socketBytes)transmitted=socketBytes;
    \\ while(transmitted>0&&socketHead<socketQueue.length){
    \\  var remaining=socketQueue[socketHead];
    \\  if(transmitted<remaining){socketQueue[socketHead]=remaining-transmitted;socketBytes-=transmitted;transmitted=0;break}
    \\  transmitted-=remaining;socketBytes-=remaining;socketItems--;socketHead++;
    \\ }
    \\ compactSocketQueue();
    \\}
    \\function recordSocketMessage(bytes){socketQueue.push(bytes);socketItems++;socketBytes+=bytes}
    \\function finish(report){
    \\ if(dead)return;
    \\ if(report)status("failed");
    \\ dead=true;wsReady=false;
    \\ if(retryTimer)try{clearTimeout(retryTimer)}catch(e){}
    \\ if(pumpTimer)try{clearTimeout(pumpTimer)}catch(e){}
    \\ retryTimer=0;pumpTimer=0;clearReplay();clearSocketQueue();
    \\ var socket=ws;ws=null;if(socket)try{socket.close(1000)}catch(e){}
    \\ if(nativeBridge)try{nativeBridge.onmessage=null}catch(e){}
    \\ if(client)try{client.close()}catch(e){}
    \\ client=null;nativeBridge=null;
    \\}
    \\function fail(){finish(true)}
    \\function knownType(value){return value===1||value===2||value===3||value===4||value===5||value===6||value===16||value===17||value===18||value===19||value===31}
    \\function splitFrames(value){
    \\ var view=new DataView(value),result=[],offset=0;
    \\ while(offset<value.byteLength){
    \\  if(value.byteLength-offset<8||result.length>=MAX_FRAMES)throw new Error("invalid frame batch");
    \\  var type=view.getUint8(offset),size=view.getUint32(offset+4),end=offset+8+size;
    \\  if(!knownType(type)||size>MAX_FRAME||end>value.byteLength)throw new Error("invalid frame");
    \\  result.push({type:type,id:(view.getUint8(offset+1)<<16)|(view.getUint8(offset+2)<<8)|view.getUint8(offset+3),size:size,data:value.slice(offset,end)});
    \\  offset=end;
    \\ }
    \\ if(!result.length)throw new Error("empty frame batch");
    \\ return result;
    \\}
    \\function deliver(value){
    \\ var frames;
    \\ try{frames=splitFrames(value)}catch(e){fail();return}
    \\ reconcileSocketQueue();
    \\ if(!adopted){
    \\  if(frames.length!==1||frames[0].type!==17||frames[0].id!==0||frames[0].size!==0){fail();return}
    \\  adopted=true;clearReplay();
    \\ }
    \\ down+=value.byteLength;
    \\ try{
    \\  if(client.native)for(var i=0;i<frames.length;i++)client.binary(frames[i].data);
    \\  else client.binary(value);
    \\ }catch(e){fail()}
    \\}
    \\function schedulePump(){
    \\ if(!pumpTimer)pumpTimer=setTimeout(function(){pumpTimer=0;pump()},10);
    \\}
    \\function pump(){
    \\ if(dead||adopted||!wsReady)return;
    \\ while(sendIndex<replay.length){
    \\  reconcileSocketQueue();
    \\  if(replayItems+socketItems>=QUEUE_ITEMS){schedulePump();return}
    \\  var value=replay[sendIndex],held=replayBytes+rawBuffered();
    \\  if(value.byteLength>QUEUE_BYTES-held){schedulePump();return}
    \\  try{ws.send(value)}catch(e){fail();return}
    \\  recordSocketMessage(value.byteLength);up+=value.byteLength;sendIndex++;
    \\ }
    \\}
    \\function send(value){
    \\ if(dead||!(value instanceof ArrayBuffer)||!value.byteLength)return;
    \\ reconcileSocketQueue();
    \\ if(adopted){
    \\  if(socketItems>=QUEUE_ITEMS||value.byteLength>QUEUE_BYTES-rawBuffered()){fail();return}
    \\  try{ws.send(value);recordSocketMessage(value.byteLength);up+=value.byteLength}catch(e){fail()}
    \\  return;
    \\ }
    \\ if(replayItems+socketItems>=QUEUE_ITEMS||value.byteLength>QUEUE_BYTES-replayBytes-rawBuffered()){fail();return}
    \\ replay.push(value);replayBytes+=value.byteLength;replayItems++;pump();
    \\}
    \\function connect(){
    \\ if(dead||ws)return;
    \\ status(attempts?"reconnecting":"connecting");
    \\ var socket;
    \\ try{socket=new WebSocket("wss://"+location.host+WS_PATH,"tproxy-v1."+TOKEN)}catch(e){fail();return}
    \\ ws=socket;socket.binaryType="arraybuffer";
    \\ socket.onopen=function(){if(ws!==socket||dead)return;wsReady=true;sendIndex=0;pump();status("connected")};
    \\ socket.onmessage=function(event){if(ws!==socket||dead)return;var value;try{value=event.data}catch(e){fail();return}if(!(value instanceof ArrayBuffer)||!value.byteLength){fail();return}deliver(value)};
    \\ socket.onerror=function(){};
    \\ socket.onclose=function(){
    \\  if(ws!==socket)return;ws=null;wsReady=false;clearSocketQueue();
    \\  if(dead)return;
    \\  if(adopted||attempts>=2){fail();return}
    \\  attempts++;retryTimer=setTimeout(function(){retryTimer=0;connect()},attempts*1000);
    \\ };
    \\}
    \\function clientControl(text){var value=null;try{value=JSON.parse(text)}catch(e){return}if(value&&value.t==="close")finish(false)}
    \\function useNative(bridge){
    \\ if(client||dead)return;nativeBridge=bridge;
    \\ client={native:true,binary:function(value){bridge.postMessage(value)},control:function(value){bridge.postMessage(JSON.stringify(value))},close:function(){bridge.onmessage=null}};
    \\ bridge.onmessage=function(event){try{var value=event.data;if(typeof value==="string"){clientControl(value);return}send(value)}catch(e){}};
    \\ control({t:"tproxy-android-init",v:1,nonce:androidNonce});connect();
    \\}
    \\function useParentPort(port){
    \\ if(client||dead)return;
    \\ client={native:false,binary:function(value){port.postMessage(value,[value])},control:function(value){port.postMessage(value)},close:function(){port.onmessage=null;if(port.close)port.close()}};
    \\ port.onmessage=function(event){try{var value=event.data;if(value instanceof ArrayBuffer){send(value);return}if(value&&value.t==="close")finish(false)}catch(e){}};
    \\ try{port.start()}catch(e){}connect();
    \\}
    \\addEventListener("message",function(event){
    \\ try{
    \\  if(client||dead||event.source!==parent||event.data===null||typeof event.data!=="object")return;
    \\  var keys=Object.keys(event.data).sort();
    \\  if(keys.length!==2||keys[0]!=="t"||keys[1]!=="v"||event.data.t!=="tproxy-init"||event.data.v!==1||!event.ports||event.ports.length!==1)return;
    \\  var source=new URL(event.origin);
    \\  if(source.protocol!=="http:"||source.hostname!=="127.0.0.1"||!source.port||source.origin!==event.origin)return;
    \\  useParentPort(event.ports[0]);
    \\ }catch(e){}
    \\});
    \\addEventListener("pagehide",function(){finish(false)},{once:true});
    \\setInterval(function(){if(!client||dead)return;var du=up-lastUp,dd=down-lastDown;if(!du&&!dd)return;lastUp=up;lastDown=down;control({t:"traffic",up:du,down:dd})},1000);
    \\var native=null;try{native=window.TelegramWebProxy}catch(e){}
    \\if(native&&typeof native.postMessage==="function"&&androidNonce)useNative(native);
    \\try{history.replaceState(null,"",location.pathname)}catch(e){}
    \\})();
    \\</script>
    \\</body></html>
;

/// Render a self-contained bridge document for one short-lived carrier token.
/// `nonce` is also returned in the page's CSP by the relay and is limited to base64url
/// so it can be embedded in the script attribute without HTML parsing ambiguity.
pub fn renderSessionBridge(allocator: std.mem.Allocator, ws_path: []const u8, token: []const u8, nonce: []const u8) ![]u8 {
    try validateWsPath(ws_path);
    if (token.len != 43 or !isBase64Url(token)) return error.InvalidSessionToken;
    if (nonce.len == 0 or nonce.len > 128 or !isBase64Url(nonce)) return error.InvalidScriptNonce;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, bridge_document_head);
    try out.appendSlice(allocator, token);
    try out.appendSlice(allocator, bridge_path_meta);
    try appendHtmlAttribute(allocator, &out, ws_path);
    try out.appendSlice(allocator, bridge_script_open);
    try out.appendSlice(allocator, nonce);
    try out.appendSlice(allocator, bridge_script_vars);
    try appendJsString(allocator, &out, ws_path);
    try out.appendSlice(allocator, bridge_token_var);
    try appendJsString(allocator, &out, token);
    try out.appendSlice(allocator, bridge_script_body);
    return out.toOwnedSlice(allocator);
}

fn validateWsPath(ws_path: []const u8) !void {
    if (ws_path.len == 0 or ws_path[0] != '/' or std.mem.startsWith(u8, ws_path, "//") or std.mem.indexOfAny(u8, ws_path, "?#\\") != null) return error.InvalidWsPath;
    for (ws_path) |c| if (c < 0x20 or c == 0x7f) return error.InvalidWebSocketPath;
}

fn isBase64Url(value: []const u8) bool {
    for (value) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return false;
    return true;
}

fn appendHtmlAttribute(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: []const u8) !void {
    for (value) |c| switch (c) {
        '&' => try out.appendSlice(allocator, "&amp;"),
        '"' => try out.appendSlice(allocator, "&quot;"),
        '<' => try out.appendSlice(allocator, "&lt;"),
        '>' => try out.appendSlice(allocator, "&gt;"),
        else => try out.append(allocator, c),
    };
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

test "session bridge is a minimal standalone document with token metadata and nonce" {
    const allocator = std.testing.allocator;
    const token = "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT";
    const html = try renderSessionBridge(allocator, "/api/v1/socket", token, "nonce_123");
    defer allocator.free(html);

    try std.testing.expect(std.mem.startsWith(u8, html, "<!doctype html>"));
    try std.testing.expect(std.mem.endsWith(u8, html, "</body></html>"));
    try std.testing.expect(std.mem.containsAtLeast(u8, html, 1, "<meta name=\"tproxy-token\" content=\"" ++ token ++ "\">"));
    try std.testing.expect(std.mem.containsAtLeast(u8, html, 1, "<meta name=\"tproxy-ws-path\" content=\"/api/v1/socket\">"));
    try std.testing.expect(std.mem.containsAtLeast(u8, html, 1, "<script nonce=\"nonce_123\">"));
    try std.testing.expect(std.mem.containsAtLeast(u8, html, 1, "new WebSocket(\"wss://\"+location.host+WS_PATH,\"tproxy-v1.\"+TOKEN)"));
    try std.testing.expect(std.mem.containsAtLeast(u8, html, 1, "tproxy-android-init"));
    try std.testing.expect(std.mem.containsAtLeast(u8, html, 1, "tproxy-init"));
    try std.testing.expect(!std.mem.containsAtLeast(u8, html, 1, "<style"));
    try std.testing.expect(!std.mem.containsAtLeast(u8, html, 1, "location.search"));
}

test "session bridge validates all values embedded in markup" {
    const allocator = std.testing.allocator;
    const token = "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT";
    for ([_][]const u8{ "", "socket", "//other.test/socket", "/socket?x=1", "/socket#fragment", "/a\\b" }) |path| {
        try std.testing.expectError(error.InvalidWsPath, renderSessionBridge(allocator, path, token, "nonce"));
    }
    try std.testing.expectError(error.InvalidWebSocketPath, renderSessionBridge(allocator, "/a\nb", token, "nonce"));
    try std.testing.expectError(error.InvalidSessionToken, renderSessionBridge(allocator, "/s", "short", "nonce"));
    try std.testing.expectError(error.InvalidSessionToken, renderSessionBridge(allocator, "/s", "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", "nonce"));
    try std.testing.expectError(error.InvalidScriptNonce, renderSessionBridge(allocator, "/s", token, "bad nonce"));
}

test "session bridge escapes websocket path for HTML and JavaScript" {
    const allocator = std.testing.allocator;
    const escaped = try renderSessionBridge(
        allocator,
        "/a<b>c&d\"e",
        "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT",
        "nonce",
    );
    defer allocator.free(escaped);
    try std.testing.expect(!std.mem.containsAtLeast(u8, escaped, 1, "<b>"));
    try std.testing.expect(std.mem.containsAtLeast(u8, escaped, 1, "/a&lt;b&gt;c&amp;d&quot;e"));
    try std.testing.expect(std.mem.containsAtLeast(u8, escaped, 1, "\\u003c"));
    try std.testing.expect(std.mem.containsAtLeast(u8, escaped, 1, "\\\""));
}
