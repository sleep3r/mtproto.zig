// Drives the WEB proxy bridge page the way Telegram Desktop drives it.
//
// The page in src/web/page.zig runs inside tdesktop's hidden WebView (or, on the
// fallback path, inside a loopback-framed iframe) and is the one part of this project
// that never executes on the server. It is also the part with the least forgiving
// contract: the client's injected bridge turns any exception in the message handler into
// a dead carrier, and it drops the carrier unless the very first binary message it
// receives is exactly one WELCOME frame.
//
// So this harness is a stand-in for the client. It fakes just enough of a browser
// (WebSocket, timers, message events, location) plus the exact `TelegramWebProxy` and
// `tproxy-init` boundaries tdesktop implements, then asserts the handshake.
//
// Usage: node harness.js <path-to-extracted-bridge.js>
// Reference: tdesktop web_proxy_webview.cpp (BridgeScript, handleControl) and
// web_proxy_transport.cpp (Transport::Private::page).

'use strict';
const fs = require('fs');
const vm = require('vm');

const src = fs.readFileSync(process.argv[2], 'utf8');
const NONCE = 'N'.repeat(43);
const TOKEN = 'T'.repeat(43);

function frame(type, stream, payload) {
  const p = payload || Buffer.alloc(0);
  const b = Buffer.alloc(8 + p.length);
  b[0] = type;
  b.writeUIntBE(stream, 1, 3);
  b.writeUInt32BE(p.length, 4);
  p.copy(b, 8);
  return b;
}
const HELLO = frame(0x10, 0, Buffer.from([1]));
const WELCOME = frame(0x11, 0);
if (HELLO.toString('hex') !== process.argv[3] || WELCOME.toString('hex') !== process.argv[4]) {
  throw new Error('harness frame encoding differs from production frame.serialize');
}

/// A fresh page instance with a scripted browser around it.
function boot(opts) {
  const sockets = [];
  const timers = [];
  const listeners = {};
  const toClient = [];
  const parentWindow = {};
  let initReceiverReady = false;

  class FakeWebSocket {
    constructor(url, protocol) {
      if (opts.constructorThrows) throw new Error('WebSocket construction failed');
      this.url = url;
      this.protocol = protocol;
      this.readyState = 0;
      this.bufferedAmount = 0;
      this.sent = [];
      this.binaryType = 'blob';
      sockets.push(this);
    }
    send(b) {
      if (this.readyState !== 1) throw new Error('send on a socket that is not open');
      this.sent.push(Buffer.from(b));
      this.bufferedAmount += b.byteLength;
    }
    close() {
      this.readyState = 3;
      if (this.onclose) this.onclose();
    }
    drain(bytes) {
      this.bufferedAmount = bytes === undefined ? 0 : Math.max(0, this.bufferedAmount - bytes);
    }
    open() {
      this.readyState = 1;
      if (this.onopen) this.onopen();
    }
    deliver(buf) {
      this.bufferedAmount = 0;
      const data = this.binaryType === 'arraybuffer' ? new Uint8Array(buf).buffer : { blob: Buffer.from(buf) };
      if (this.onmessage) this.onmessage({ data });
    }
  }

  const bridge = {
    _receiver: null,
    postMessage(v) {
      toClient.push(v);
      if (typeof v === 'string' && JSON.parse(v).t === 'tproxy-android-init') {
        initReceiverReady = typeof this._receiver === 'function';
        if (opts.synchronousHello) this._receiver({ data: new Uint8Array(HELLO).buffer });
      }
    },
    get onmessage() { return this._receiver; },
    set onmessage(v) { this._receiver = v; },
  };

  const g = {
    WebSocket: FakeWebSocket,
    setInterval: () => 0,
    setTimeout: (fn, ms) => { const timer = { fn, ms, cancelled: false }; timers.push(timer); return timer; },
    clearTimeout: (timer) => { if (timer) timer.cancelled = true; },
    addEventListener: (type, fn) => { (listeners[type] = listeners[type] || []).push(fn); },
    location: {
      search: '?bridge=' + 'C'.repeat(43),
      hash: opts.native ? '#android=' + NONCE : '',
      host: 'relay.example.com',
      protocol: 'https:',
      pathname: '/',
    },
    history: { replaceState: () => {} },
    parent: parentWindow,
    ArrayBuffer,
    URL,
    console,
  };
  if (opts.native) g.TelegramWebProxy = bridge;
  g.window = g;

  vm.createContext(g);
  vm.runInContext(src, g);

  return {
    sockets,
    timers,
    listeners,
    toClient,
    bridge,
    parentWindow,
    initReceiverReady: () => initReceiverReady,
    runNextTimer: () => { let timer; do { timer = timers.shift(); } while (timer && timer.cancelled); if (!timer) throw new Error('no timer'); timer.fn(); },
    controls: () => toClient.filter(m => typeof m === 'string').map(JSON.parse),
    // `.map(Buffer.from)` would pass the index as a byteOffset — bind the arity.
    binaries: () => toClient.filter(m => m instanceof ArrayBuffer).map(m => Buffer.from(m)),
  };
}

const cases = {};

// The normal path: a hidden WebView with the injected bridge object.
cases['native handshake'] = (t) => {
  const p = boot({ native: true, synchronousHello: true });

  const init = p.controls()[0];
  t.eq(init && init.t, 'tproxy-android-init', 'first control message');
  t.eq(init.v, 1, 'init version');
  t.eq(init.nonce, NONCE, 'init nonce echoes the fragment');
  t.ok(p.initReceiverReady(), 'onmessage was live at the instant init was sent');

  t.eq(p.sockets.length, 1, 'exactly one carrier socket');
  t.eq(p.sockets[0].url, 'wss://relay.example.com/api/v1/socket', 'same-origin carrier url has no bearer');
  t.eq(p.sockets[0].protocol, 'tproxy-v1.' + TOKEN, 'short-lived bearer is in WebSocket subprotocol');

  // HELLO arrives before the socket opens, so it has to be queued rather than dropped.
  t.eq(p.sockets[0].sent.length, 0, 'nothing sent before the socket opened');
  p.sockets[0].open();
  t.eq(p.sockets[0].sent.length, 1, 'HELLO flushed on open');
  t.ok(p.sockets[0].sent[0].equals(HELLO), 'HELLO forwarded byte for byte');

  // The client requires the first binary message to hold exactly one WELCOME frame.
  const before = p.binaries().length;
  p.sockets[0].deliver(WELCOME);
  const delivered = p.binaries().slice(before);
  t.eq(delivered.length, 1, 'one binary message for WELCOME');
  t.ok(delivered[0].equals(WELCOME), 'WELCOME forwarded byte for byte');
};

// Once the client has adopted the carrier, its logical sockets live in a relay session
// that a reconnect cannot recover — and a second WELCOME would make it drop us anyway.
cases['no reconnect after adoption'] = (t) => {
  const p = boot({ native: true });
  p.bridge.onmessage({ data: new Uint8Array(HELLO).buffer });
  p.sockets[0].open();
  p.sockets[0].deliver(WELCOME);

  p.sockets[0].close();
  p.timers.forEach(timer => timer.fn());
  t.eq(p.sockets.length, 1, 'no reconnect attempted');
  t.ok(p.controls().some(c => c.t === 'status' && c.state === 'failed'), 'reported failed');
};

// Before adoption a retry is worth making — but the fresh relay session has never seen
// HELLO, so the page must replay it or the carrier can never complete.
cases['pre-adoption retry replays HELLO'] = (t) => {
  const p = boot({ native: true });
  p.bridge.onmessage({ data: new Uint8Array(HELLO).buffer });
  p.sockets[0].open();
  t.eq(p.sockets[0].sent.length, 1, 'HELLO sent on the first carrier');

  p.sockets[0].close();
  t.eq(p.timers.length, 1, 'a retry was scheduled');
  p.timers[0].fn();
  t.eq(p.sockets.length, 2, 'reconnected');
  p.sockets[1].open();
  t.eq(p.sockets[1].sent.length, 1, 'HELLO replayed on the new carrier');
  t.ok(p.sockets[1].sent[0].equals(HELLO), 'replayed HELLO is unchanged');
};

// The system-browser fallback: tdesktop's loopback page frames us and hands over a port.
cases['iframe fallback'] = (t) => {
  const p = boot({ native: false });
  t.eq(p.sockets.length, 0, 'no carrier before tproxy-init');

  const port = { onmessage: null, start() {}, posted: [], postMessage(v, transfer = []) { this.posted.push(structuredClone(v, { transfer })); } };
  const post = (origin, source = p.parentWindow, data = { t: 'tproxy-init', v: 1 }, ports = [port]) => p.listeners.message.forEach(fn =>
    fn({ data, origin, source, ports }));

  post('https://evil.example');
  t.eq(p.sockets.length, 0, 'tproxy-init from a foreign origin is ignored');

  post('http://127.0.0.1:54321', {}, { t: 'tproxy-init', v: 1 }, [port]);
  post('http://127.0.0.1:54321', p.parentWindow, { t: 'tproxy-init', v: 1, extra: true }, [port]);
  post('http://127.0.0.1:54321', p.parentWindow, { t: 'tproxy-init', v: 1 }, [port, port]);
  post('http://127.0.0.1:54321/', p.parentWindow, { t: 'tproxy-init', v: 1 }, [port]);
  t.eq(p.sockets.length, 0, 'non-exact fallback initialization is ignored');

  post('http://127.0.0.1:54321');
  t.eq(p.sockets.length, 1, 'carrier opened for the loopback parent');

  port.onmessage({ data: new Uint8Array(HELLO).buffer });
  p.sockets[0].open();
  t.ok(p.sockets[0].sent.length === 1 && p.sockets[0].sent[0].equals(HELLO), 'HELLO forwarded');

  p.sockets[0].deliver(WELCOME);
  const bins = port.posted.filter(m => m instanceof ArrayBuffer).map(m => Buffer.from(m));
  t.ok(bins.length === 1 && bins[0].equals(WELCOME), 'WELCOME returned through the port');

  // On this path control messages are objects, not JSON strings.
  const ctrl = port.posted.filter(m => m && m.t);
  t.ok(ctrl.every(m => typeof m === 'object'), 'control messages are objects here');
  t.ok(ctrl.some(m => m.t === 'status' && m.state === 'connected'), 'reported connected');
};

// An exception escaping the handler makes tdesktop fail the whole carrier, so every
// entry point has to swallow garbage instead.
cases['garbage never throws'] = (t) => {
  const p = boot({ native: true });
  for (const junk of ['not json', '{"t":', null, undefined, 42, {}, new Uint8Array(0).buffer]) {
    p.bridge.onmessage({ data: junk });
  }
  p.bridge.onmessage({ get data() { throw new Error('hostile getter'); } });
  p.bridge.onmessage(null);
  t.ok(true, 'handler survived garbage');
};

cases['native downlink batches become validated single frames'] = (t) => {
  const p = boot({ native: true });
  p.sockets[0].open();
  p.sockets[0].deliver(WELCOME);
  const ping = frame(0x05, 0, Buffer.from('x'));
  const bye = frame(0x1f, 0);
  p.sockets[0].deliver(Buffer.concat([ping, bye]));
  const bins = p.binaries();
  t.eq(bins.length, 3, 'native bridge receives one complete frame per message');
  t.ok(bins[0].equals(WELCOME), 'WELCOME remains its own first message');
  t.ok(bins[1].equals(ping) && bins[2].equals(bye), 'batch is split at frame boundaries');

  p.sockets[0].deliver(frame(0x05, 0, Buffer.from('bad')).subarray(0, 9));
  t.eq(p.binaries().length, 3, 'partial frame is not delivered');
  t.ok(p.controls().some(c => c.state === 'failed'), 'partial frame fails closed');

  const bad = boot({ native: true });
  bad.sockets[0].open();
  bad.sockets[0].deliver(Buffer.concat([WELCOME, bye]));
  t.eq(bad.binaries().length, 0, 'batched first WELCOME is rejected');
  t.ok(bad.controls().some(c => c.state === 'failed'), 'invalid first downlink fails closed');
};

cases['aggregate browser send buffer is capped at 32 MiB'] = (t) => {
  const p = boot({ native: true });
  p.sockets[0].open();
  p.sockets[0].deliver(WELCOME);
  const chunk = new ArrayBuffer(4 * 1024 * 1024);
  for (let i = 0; i < 8; i++) p.bridge.onmessage({ data: chunk });
  t.eq(p.sockets[0].sent.length, 8, '32 MiB aggregate is accepted');
  p.bridge.onmessage({ data: chunk });
  t.eq(p.sockets[0].sent.length, 8, 'payload beyond aggregate cap is not accepted');
  t.eq(p.sockets[0].readyState, 3, 'overflow closes the carrier');
  t.ok(p.controls().some(c => c.state === 'failed'), 'overflow reports failure');
};

cases['adopted stalled socket is capped at 16384 outstanding messages'] = (t) => {
  const p = boot({ native: true });
  p.sockets[0].open();
  p.sockets[0].deliver(WELCOME);
  const tiny = frame(0x06, 0);
  for (let i = 0; i < 16384; i++) p.bridge.onmessage({ data: new Uint8Array(tiny).buffer });
  t.eq(p.sockets[0].sent.length, 16384, 'outstanding item budget is accepted exactly');
  p.sockets[0].drain(4);
  p.bridge.onmessage({ data: new Uint8Array(tiny).buffer });
  t.eq(p.sockets[0].sent.length, 16384, 'partially drained head still counts as outstanding');
  t.eq(p.sockets[0].readyState, 3, 'outstanding item overflow closes the carrier');
};

cases['drained adopted socket has no lifetime message cap'] = (t) => {
  const p = boot({ native: true });
  p.sockets[0].open();
  p.sockets[0].deliver(WELCOME);
  const tiny = frame(0x06, 0);
  for (let i = 0; i < 20000; i++) {
    p.bridge.onmessage({ data: new Uint8Array(tiny).buffer });
    p.sockets[0].drain(tiny.length);
  }
  t.eq(p.sockets[0].sent.length, 20000, 'drained messages retire from the outstanding count');
  t.eq(p.sockets[0].readyState, 1, 'long-running drained carrier stays open');
  t.ok(!p.controls().some(c => c.state === 'failed'), 'normal lifetime traffic never exhausts item budget');
};

cases['pre-adoption queue item count is capped'] = (t) => {
  const p = boot({ native: true });
  const tiny = new ArrayBuffer(8);
  for (let i = 0; i < 16385; i++) p.bridge.onmessage({ data: tiny });
  t.eq(p.sockets[0].readyState, 3, 'the 16385th queued item closes the carrier');
  t.ok(p.controls().some(c => c.state === 'failed'), 'item overflow reports failure');
};

cases['pagehide promptly closes the carrier'] = (t) => {
  const p = boot({ native: true });
  p.listeners.pagehide.forEach(fn => fn({}));
  t.eq(p.sockets[0].readyState, 3, 'pagehide closes the websocket');

  const retry = boot({ native: true });
  retry.sockets[0].close();
  t.eq(retry.timers.length, 1, 'pre-adoption close scheduled a retry');
  retry.listeners.pagehide.forEach(fn => fn({}));
  t.ok(retry.timers.every(timer => timer.cancelled), 'pagehide cancels pending retry');
};

cases['failure before first open replays exactly one HELLO'] = (t) => {
  const p = boot({ native: true, synchronousHello: true });
  p.sockets[0].close();
  p.runNextTimer();
  p.sockets[1].open();
  t.eq(p.sockets[1].sent.length, 1, 'queued and replayed HELLO are deduplicated');
  t.ok(p.sockets[1].sent[0].equals(HELLO), 'HELLO survives failed connect');
};

cases['retry limit gives up after two retries'] = (t) => {
  const p = boot({ native: true });
  for (let i = 0; i < 2; i++) { p.sockets[i].close(); p.runNextTimer(); }
  p.sockets[2].close();
  t.eq(p.sockets.length, 3, 'only two replacement sockets');
  t.eq(p.timers.length, 0, 'no timer after retry exhaustion');
  t.ok(p.controls().some(c => c.state === 'failed'), 'retry exhaustion reported');
};

cases['client close and constructor failure terminate cleanly'] = (t) => {
  const p = boot({ native: true });
  p.bridge.onmessage({ data: JSON.stringify({ t: 'close' }) });
  t.eq(p.sockets[0].readyState, 3, 'client close shuts carrier');
  t.eq(p.timers.length, 0, 'client close never reconnects');
  const bad = boot({ native: true, constructorThrows: true });
  t.eq(bad.sockets.length, 0, 'failed constructor published no socket');
  t.ok(bad.controls().some(c => c.state === 'failed'), 'constructor failure reported');
};

cases['BYE bytes reach the adopted client before it closes'] = (t) => {
  const p = boot({ native: true });
  p.sockets[0].open();
  p.sockets[0].deliver(WELCOME);
  const bye = frame(0x1f, 0);
  p.sockets[0].deliver(bye);
  t.ok(p.binaries().at(-1).equals(bye), 'BYE delivered intact');
  p.bridge.onmessage({ data: JSON.stringify({ t: 'close' }) });
  t.eq(p.timers.length, 0, 'no reconnect after BYE/client close');
};

let failures = 0;
for (const [name, fn] of Object.entries(cases)) {
  const t = {
    ok(cond, what) { if (!cond) throw new Error(what); },
    eq(actual, expected, what) {
      if (actual !== expected) throw new Error(what + ': expected ' + expected + ', got ' + actual);
    },
  };
  try {
    fn(t);
    console.log('  ok   ' + name);
  } catch (err) {
    failures++;
    console.log('  FAIL ' + name + ' — ' + err.message);
  }
}

if (failures) {
  console.log('\n' + failures + ' bridge-page case(s) failed');
  process.exit(1);
}
console.log('\nall bridge-page cases passed');
