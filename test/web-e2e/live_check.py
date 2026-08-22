#!/usr/bin/env python3
"""Live checks against a DEPLOYED proxy, from the outside — the WEB proxy's only true
end-to-end test, since the relay, the masking hop and Telegram itself are all real here.

  python3 test/web-e2e/live_check.py <mode> [arg]      (env: HOST, CONFIG)

  baseline  FakeTLS probe: a valid tls-auth ClientHello for a configured user must get a
            ServerHello back; a dd handshake from the public internet must NOT be served
            (fake_tls_only). Run before and after deploying a binary.
  faketls   Full FakeTLS session for every user: req_pq_multi -> res_pq from Telegram.
  web       Full WEB proxy end-to-end: cover page, bridge page, capability gate, WSS
            HELLO/WELCOME/OPEN, then a real MTProto req_pq_multi through relay -> proxy ->
            Telegram DC and a res_pq back; plus the negatives.
  idle N    Hold one WEB session idle N seconds (default 210, longer than every timeout in
            the chain), answering the relay's PINGs, then prove it still carries MTProto.
  cap USER  Print the bridge capability for USER (debugging).

Needs: python3 >= 3.11, `cryptography`, `websockets` (+ `certifi` on macOS python.org
builds). Secrets are read from the config file and never printed.
"""
import asyncio, base64, hashlib, hmac, os, re, socket, ssl, struct, sys, time, tomllib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import websockets
try:
    import certifi
    SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except Exception:
    SSL_CTX = ssl.create_default_context()

CFG = os.environ.get("CONFIG", os.path.join(os.path.dirname(__file__), "..", "..", "config.toml"))
PORT = 443
WS_PATH = "/api/v1/socket"

with open(CFG, "rb") as f:
    cfg = tomllib.load(f)
USERS = cfg["access"]["users"]
TLS_DOMAIN = cfg["censorship"]["tls_domain"]
HOST = os.environ.get("HOST") or cfg.get("web", {}).get("domain") or cfg["server"].get("public_ip")
if not HOST: sys.exit("set HOST=<relay domain> (or [web].domain / [server].public_ip in the config)")
WS_PATH = cfg.get("web", {}).get("ws_path", WS_PATH)

def ok(m): print("  ok   " + m)
def fail(m): print("  FAIL " + m); sys.exit(1)

# ── FakeTLS ClientHello (tls-auth) ───────────────────────────────────────────
def build_tls_auth_client_hello(secret: bytes, hostname: str) -> bytes:
    host = hostname.encode()
    sni_list_len = 1 + 2 + len(host); sni_ext_len = 2 + sni_list_len; sv_len = 3
    body_len = 2+32+1+32+2+2+1+1+2+4+sni_ext_len+4+sv_len
    rec_len = 4 + body_len
    p = bytearray(5 + rec_len)
    p[0]=0x16; p[1]=3; p[2]=1; p[3:5]=struct.pack(">H", rec_len)
    p[5]=1; p[6]=(body_len>>16)&255; p[7]=(body_len>>8)&255; p[8]=body_len&255
    pos=9; p[pos:pos+2]=b"\x03\x03"; pos+=2
    rnd=pos; pos+=32
    p[pos]=0x20; pos+=1; p[pos:pos+32]=os.urandom(32); pos+=32
    p[pos:pos+2]=struct.pack(">H",2); pos+=2; p[pos:pos+2]=b"\x13\x01"; pos+=2
    p[pos]=1; pos+=1; p[pos]=0; pos+=1
    p[pos:pos+2]=struct.pack(">H",4+sni_ext_len+4+sv_len); pos+=2
    p[pos:pos+2]=b"\x00\x00"; pos+=2; p[pos:pos+2]=struct.pack(">H",sni_ext_len); pos+=2
    p[pos:pos+2]=struct.pack(">H",sni_list_len); pos+=2; p[pos]=0; pos+=1
    p[pos:pos+2]=struct.pack(">H",len(host)); pos+=2; p[pos:pos+len(host)]=host; pos+=len(host)
    p[pos:pos+2]=b"\x00\x2b"; pos+=2; p[pos:pos+2]=struct.pack(">H",sv_len); pos+=2
    p[pos]=2; pos+=1; p[pos:pos+2]=b"\x03\x04"; pos+=2
    assert pos==len(p)
    mi=bytearray(p)
    for i in range(rnd, rnd+32): mi[i]=0
    mac=bytearray(hmac.new(secret, mi, hashlib.sha256).digest())
    ts=struct.pack("<I", int(time.time()))
    for i in range(4): mac[28+i]^=ts[i]
    p[rnd:rnd+32]=mac
    return bytes(p)

# ── MTProxy obfuscation (client side) ────────────────────────────────────────
RESERVED_FIRST = {0xef}
RESERVED_4 = {b"HEAD", b"POST", b"GET ", b"OPTI", b"\xdd\xdd\xdd\xdd", b"\xee\xee\xee\xee", b"\x16\x03\x01\x02"}
class Obf:
    def __init__(self, secret: bytes, dc_idx: int, tag: bytes = b"\xdd\xdd\xdd\xdd"):
        while True:
            init = bytearray(os.urandom(64))
            if init[0] in RESERVED_FIRST or bytes(init[0:4]) in RESERVED_4 or bytes(init[4:8]) == b"\0\0\0\0":
                continue
            break
        init[56:60] = tag
        init[60:62] = struct.pack("<h", dc_idx)
        ek = hashlib.sha256(bytes(init[8:40]) + secret).digest(); eiv = bytes(init[40:56])
        rev = bytes(init[8:56])[::-1]
        dk = hashlib.sha256(rev[0:32] + secret).digest(); div = rev[32:48]
        self.enc = Cipher(algorithms.AES(ek), modes.CTR(eiv)).encryptor()
        self.dec = Cipher(algorithms.AES(dk), modes.CTR(div)).decryptor()
        encrypted = self.enc.update(bytes(init))
        self.first = bytes(init[0:56]) + encrypted[56:64]
    def send(self, plain: bytes) -> bytes: return self.enc.update(plain)
    def recv(self, data: bytes) -> bytes: return self.dec.update(data)

def padded_frame(payload: bytes) -> bytes:
    # Padded intermediate (dd) carries no padding-length field: the receiver recovers the
    # payload by truncating the declared length down to a multiple of 4. Payloads are
    # 4-aligned, so only 0..3 bytes of padding survive that; padding wider than 3 leaves
    # 4/8/12 bytes of garbage on the message. Keep this honest -- an over-padding client
    # hides the same bug on the server side, because an *unencrypted* req_pq is parsed by
    # length from its envelope and tolerates a garbage tail, while real encrypted traffic
    # fails its msg_key check.
    pad = os.urandom(os.urandom(1)[0] % 4)
    return struct.pack("<I", len(payload) + len(pad)) + payload + pad


def strip_padding(frame_body: bytes) -> bytes:
    """What a real client keeps from a padded-intermediate frame body."""
    return frame_body[: len(frame_body) - len(frame_body) % 4]


def check_server_padding(where: str, declared: int, payload: bytes):
    """Assert the proxy's own padding survives a real client's truncate-to-4.

    An unencrypted MTProto reply is exactly 20 + msg_len bytes, so any excess in the
    declared frame length is padding the proxy added. More than 3 bytes of it means a
    real client keeps 4/8/12 bytes of garbage and reports
    "bad SHA256 hash after aesDecrypt in message".
    """
    if len(payload) < 20:
        return
    real = 20 + struct.unpack("<I", payload[16:20])[0]
    pad = declared - real
    if pad < 0 or pad > 3:
        fail(f"{where}: proxy added {pad} bytes of padding on the dd transport "
             f"(declared {declared}, real {real}); only 0..3 survive truncate-to-4")

def req_pq_multi():
    nonce = os.urandom(16)
    body = struct.pack("<I", 0xbe7e8ef1) + nonce
    msg_id = (int(time.time()) << 32) & ~3
    msg = struct.pack("<q", 0) + struct.pack("<Q", msg_id) + struct.pack("<I", len(body)) + body
    return msg, nonce

def capability(host: str, secret: bytes) -> str:
    mac = hmac.new(b"\xdd" + secret, b"tdesktop-web-proxy-bridge-v1\n" + host.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode().rstrip("=")

def frame(t: int, sid: int, payload: bytes = b"") -> bytes:
    return bytes([t]) + sid.to_bytes(3, "big") + struct.pack(">I", len(payload)) + payload
def parse_frames(buf: bytes):
    out = []; i = 0
    while i + 8 <= len(buf):
        t = buf[i]; sid = int.from_bytes(buf[i+1:i+4], "big"); ln = struct.unpack(">I", buf[i+4:i+8])[0]
        out.append((t, sid, buf[i+8:i+8+ln])); i += 8 + ln
    assert i == len(buf), "partial trailing frame"
    return out

# ── checks ────────────────────────────────────────────────────────────────────
def baseline():
    name, secret_hex = next(iter(USERS.items()))
    secret = bytes.fromhex(secret_hex)
    s = socket.create_connection((HOST, PORT), timeout=8)
    s.sendall(build_tls_auth_client_hello(secret, TLS_DOMAIN))
    s.settimeout(6)
    data = b""
    try:
        while len(data) < 5:
            c = s.recv(4096)
            if not c: break
            data += c
    except (socket.timeout, ConnectionResetError): pass
    s.close()
    if len(data) >= 5 and data[0] == 0x16 and data[1:3] == b"\x03\x03":
        ok(f"FakeTLS: user '{name}' gets a ServerHello ({len(data)} bytes)")
    else:
        fail(f"FakeTLS: no ServerHello for '{name}' (got {data[:8].hex()})")

    # dd from the public internet must be masked/refused, never served
    o = Obf(secret, 2)
    s = socket.create_connection((HOST, PORT), timeout=8)
    s.sendall(o.first); msg, _ = req_pq_multi(); s.sendall(o.send(padded_frame(msg)))
    s.settimeout(5); got = b""; reset = False
    try:
        while True:
            c = s.recv(4096)
            if not c: break
            got += c
            if len(got) > 64: break
    except (socket.timeout, ConnectionResetError) as e:
        reset = isinstance(e, ConnectionResetError)
    s.close()
    served = False
    if got:
        plain = o.recv(got)
        served = len(plain) >= 12 and struct.unpack("<I", plain[0:4])[0] + 4 <= len(plain) + 16 and b"\x63\x24\x16\x05" in plain
    if served: fail("dd handshake from the INTERNET was served — fake_tls_only gate is open!")
    ok(f"dd from the internet is not served ({'RST' if reset else str(len(got))+' bytes back, not MTProto'})")

def tls_records(buf: bytes):
    """Split a byte stream into complete TLS records; returns (records, rest)."""
    out=[]; i=0
    while i+5 <= len(buf):
        ln = struct.unpack(">H", buf[i+3:i+5])[0]
        if i+5+ln > len(buf): break
        out.append((buf[i], buf[i+5:i+5+ln])); i += 5+ln
    return out, buf[i:]

def faketls_e2e(name: str, dc: int = 2):
    """FakeTLS ClientHello -> ServerHello flight -> CCS+AppData(obf init + req_pq) -> res_pq."""
    secret = bytes.fromhex(USERS[name])
    s = socket.create_connection((HOST, PORT), timeout=10)
    s.sendall(build_tls_auth_client_hello(secret, TLS_DOMAIN))
    s.settimeout(6); buf = b""
    # read the whole ServerHello flight: ServerHello(0x16) + CCS(0x14) + AppData(0x17 "cert")
    t0 = time.time()
    while time.time() - t0 < 6:
        try: c = s.recv(65536)
        except socket.timeout: break
        if not c: break
        buf += c
        recs, rest = tls_records(buf)
        if len(recs) >= 3 and not rest: break
    recs, rest = tls_records(buf)
    if len(recs) < 3 or recs[0][0] != 0x16: fail(f"FakeTLS {name}: bad ServerHello flight {[hex(r[0]) for r in recs]}")
    o = Obf(secret, dc)
    msg, nonce = req_pq_multi()
    app = o.first + o.send(padded_frame(msg))
    s.sendall(b"\x14\x03\x03\x00\x01\x01" + b"\x17\x03\x03" + struct.pack(">H", len(app)) + app)
    plain = b""; buf = b""; t0 = time.time()
    while time.time() - t0 < 15:
        try: c = s.recv(65536)
        except socket.timeout: continue
        if not c: break
        buf += c
        recs, buf = tls_records(buf)
        for (rt, payload) in recs:
            if rt == 0x17: plain += o.recv(payload)
        if len(plain) >= 4:
            ln = struct.unpack("<I", plain[0:4])[0]
            if len(plain) >= 4 + ln: break
    s.close()
    if len(plain) < 4: fail(f"FakeTLS {name}: no reply from Telegram")
    ln = struct.unpack("<I", plain[0:4])[0]; payload = plain[4:4+ln]
    check_server_padding(f"FakeTLS {name}", ln, payload)
    ctor = struct.unpack("<I", payload[20:24])[0]; echoed = payload[24:40]
    if ctor != 0x05162463 or echoed != nonce: fail(f"FakeTLS {name}: unexpected reply ctor={ctor:#x}")
    ok(f"FakeTLS {name}: req_pq_multi -> res_pq from DC{dc} ({int((time.time()-t0)*1000)} ms)")

def https_get(path: str):
    ctx = SSL_CTX
    s = ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=10), server_hostname=HOST)
    cert = s.getpeercert()
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode())
    data = b""
    while True:
        c = s.recv(65536)
        if not c: break
        data += c
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    status = head.split(b"\r\n")[0].decode()
    return status, head.decode(errors="replace"), body, cert

async def web():
    name, secret_hex = next(iter(USERS.items()))
    secret = bytes.fromhex(secret_hex)
    cap = capability(HOST, secret)

    st, head, body, cert = https_get("/")
    issuer = dict(x[0] for x in cert["issuer"])
    ok(f"TLS cert issuer: {issuer.get('organizationName')} / {issuer.get('commonName')}, CN={dict(x[0] for x in cert['subject']).get('commonName')}")
    if "200" not in st or b"TelegramWebProxy" in body: fail(f"cover page: {st}, bridge leaked={b'TelegramWebProxy' in body}")
    ok(f"cover page: {st}, {len(body)} bytes, no bridge script")

    st, head, body, _ = https_get("/?bridge=" + "A" * 43)
    if "200" not in st or b"TelegramWebProxy" in body: fail("bad capability leaked the bridge page")
    ok("bad capability -> same cover page")

    st, head, body, _ = https_get("/?bridge=" + cap)
    if "200" not in st or b"TelegramWebProxy" not in body or b"tproxy-init" not in body: fail(f"bridge page: {st}")
    csp = [l for l in head.split("\r\n") if l.lower().startswith("content-security-policy")]
    ok(f"bridge page for '{name}': {st}, {len(body)} bytes, CSP present={bool(csp)}")

    # WSS with a bad capability must look like any unknown path
    try:
        async with websockets.connect(f"wss://{HOST}{WS_PATH}?b=" + "A"*43, origin=f"https://{HOST}", open_timeout=10, ssl=SSL_CTX) as w:
            fail("websocket upgraded with a bad capability")
    except websockets.exceptions.InvalidStatus as e:
        ok(f"bad capability -> websocket refused with {e.response.status_code}")

    async with websockets.connect(f"wss://{HOST}{WS_PATH}?b={cap}", origin=f"https://{HOST}", open_timeout=10, max_size=2*1024*1024, ssl=SSL_CTX) as w:
        ok("websocket upgraded (101) for the real capability")
        await w.send(frame(0x10, 0, b"\x01"))
        m = await asyncio.wait_for(w.recv(), 10)
        if m != frame(0x11, 0): fail(f"expected WELCOME alone, got {m.hex()}")
        ok("HELLO -> WELCOME, alone in the first message")

        # One MTProto socket to DC2 through the relay
        await w.send(frame(0x01, 1))
        o = Obf(secret, 2)
        msg, nonce = req_pq_multi()
        await w.send(frame(0x02, 1, o.first + o.send(padded_frame(msg))))
        t0 = time.time(); plain = b""; got_frames = []
        while time.time() - t0 < 15:
            m = await asyncio.wait_for(w.recv(), 15)
            for (t, sid, pl) in parse_frames(m):
                got_frames.append((t, sid, len(pl)))
                if t == 0x03 and sid == 1: fail(f"relay CLOSEd stream 1 before answering (frames so far {got_frames})")
                if t == 0x02 and sid == 1: plain += o.recv(pl)
            if len(plain) >= 4:
                ln = struct.unpack("<I", plain[0:4])[0]
                if len(plain) >= 4 + ln: break
        if len(plain) < 4: fail(f"no DATA back from Telegram (frames: {got_frames})")
        ln = struct.unpack("<I", plain[0:4])[0]; payload = plain[4:4+ln]
        # unencrypted MTProto: auth_key_id(8) msg_id(8) len(4) body
        check_server_padding("WEB relay", ln, payload)
        ctor = struct.unpack("<I", payload[20:24])[0]; echoed = payload[24:40]
        if ctor != 0x05162463 or echoed != nonce: fail(f"unexpected reply ctor={ctor:#x} nonce_match={echoed==nonce}")
        ok(f"req_pq_multi -> res_pq from Telegram DC2 via relay (RTT {int((time.time()-t0)*1000)} ms, {len(plain)} bytes), nonce echoed")
        await w.send(frame(0x03, 1))
        ok("stream closed cleanly")
    print("\nall WEB checks passed")

async def idle(seconds: int = 210):
    """Hold one WEB session idle for longer than every timeout in the chain (relay silence 90s,
    proxy idle 120s), then prove it still carries MTProto.

    The relay probes only a *quiet* carrier, so whether any PING arrives depends on the
    client: a browser sends no WebSocket keepalive and will be probed, while this script's
    library does send one and so never looks quiet. Either way the invariant under test is
    the same — the carrier must survive and still work."""
    name, secret_hex = next(iter(USERS.items()))
    secret = bytes.fromhex(secret_hex); cap = capability(HOST, secret)
    async with websockets.connect(f"wss://{HOST}{WS_PATH}?b={cap}", origin=f"https://{HOST}", open_timeout=10, max_size=2*1024*1024, ssl=SSL_CTX) as w:
        await w.send(frame(0x10, 0, b"\x01"))
        m = await asyncio.wait_for(w.recv(), 10)
        if m != frame(0x11, 0): fail("no WELCOME")
        t0 = time.time(); pings = 0
        while time.time() - t0 < seconds:
            try:
                m = await asyncio.wait_for(w.recv(), 5)
            except asyncio.TimeoutError:
                continue          # silence is expected; the carrier must simply stay up
            for (t, sid, pl) in parse_frames(m):
                if t == 0x05 and sid == 0:
                    pings += 1
                    await w.send(frame(0x06, 0, pl))
                elif t == 0x1f:
                    fail(f"relay sent BYE after {int(time.time()-t0)}s")
                elif t != 0x04:
                    fail(f"unexpected frame {t:#x} on idle session")
        ok(f"idle session survived {int(time.time()-t0)}s ({pings} relay pings answered)")
        # still fully functional?
        await w.send(frame(0x01, 7))
        o = Obf(secret, 2); msg, nonce = req_pq_multi()
        await w.send(frame(0x02, 7, o.first + o.send(padded_frame(msg))))
        plain = b""; t1 = time.time()
        while time.time() - t1 < 15:
            m = await asyncio.wait_for(w.recv(), 15)
            for (t, sid, pl) in parse_frames(m):
                if t == 0x05: await w.send(frame(0x06, 0, pl)); continue
                if t == 0x03 and sid == 7: fail("stream 7 closed by relay")
                if t == 0x02 and sid == 7: plain += o.recv(pl)
            if len(plain) >= 4 and len(plain) >= 4 + struct.unpack("<I", plain[0:4])[0]: break
        ln = struct.unpack("<I", plain[0:4])[0]; payload = plain[4:4+ln]
        check_server_padding("WEB relay after idle", ln, payload)
        if struct.unpack("<I", payload[20:24])[0] != 0x05162463 or payload[24:40] != nonce: fail("bad res_pq after idle")
        ok(f"after {seconds}s idle: req_pq -> res_pq (DC2, user {name}) in {int((time.time()-t1)*1000)} ms")
        await w.send(frame(0x03, 7))
    print("\nidle check passed")

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "baseline"
    if mode == "baseline": baseline()
    elif mode == "web": asyncio.run(web())
    elif mode == "idle": asyncio.run(idle(int(sys.argv[2]) if len(sys.argv) > 2 else 210))
    elif mode == "faketls":
        for u in USERS: faketls_e2e(u)
    elif mode == "cap":
        print(capability(HOST, bytes.fromhex(USERS[sys.argv[2]])))
    else: fail(__doc__)
