"""Private mtbuddy helper. Credentials and ephemeral probe data arrive on stdin."""
import base64
import hashlib
from html.parser import HTMLParser
import http.client
import json
import os
import re
import signal
import socket
import ssl
import struct
import sys
import time


class ProbeError(Exception):
    pass


class BridgeMetadata(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = {}

    def handle_starttag(self, tag, attrs):
        if tag != "meta":
            return
        attrs = dict(attrs)
        name = attrs.get("name")
        if name in ("tproxy-token", "tproxy-ws-path"):
            if name in self.values:
                raise ProbeError("duplicate bridge metadata")
            self.values[name] = attrs.get("content", "")


def frame(kind, stream=0, payload=b""):
    return bytes([kind]) + stream.to_bytes(3, "big") + struct.pack(">I", len(payload)) + payload


def send_ws(sock, payload, opcode=2):
    mask = os.urandom(4)
    length = len(payload)
    header = bytes([0x80 | opcode, 0x80 | length]) if length < 126 else (
        b"\x82\xfe" + struct.pack(">H", length))
    sock.sendall(header + mask + bytes(value ^ mask[i % 4] for i, value in enumerate(payload)))


def receive_exact(sock, length, deadline):
    result = bytearray()
    while len(result) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError("probe deadline exceeded")
        sock.settimeout(remaining)
        part = sock.recv(length - len(result))
        if not part:
            raise ProbeError("connection closed")
        result.extend(part)
    return bytes(result)


def receive_ws(sock, deadline):
    while True:
        first, second = receive_exact(sock, 2, deadline)
        if first & 0x70 or not first & 0x80 or second & 0x80:
            raise ProbeError("invalid server websocket frame")
        length = second & 127
        if length == 126:
            length = struct.unpack(">H", receive_exact(sock, 2, deadline))[0]
        elif length == 127:
            length = struct.unpack(">Q", receive_exact(sock, 8, deadline))[0]
        opcode = first & 15
        if length > 1024 * 1024 + 8 or (opcode >= 8 and length > 125):
            raise ProbeError("oversized websocket frame")
        payload = receive_exact(sock, length, deadline)
        if opcode == 9:
            send_ws(sock, payload, 10)
        elif opcode == 10:
            continue
        elif opcode == 2:
            return payload
        else:
            raise ProbeError("websocket closed or returned nonbinary data")


def relay_frames(message):
    count = 0
    while message:
        count += 1
        if len(message) < 8 or count > 4096:
            raise ProbeError("invalid relay batch")
        kind, stream, length = message[0], int.from_bytes(message[1:4], "big"), int.from_bytes(message[4:8], "big")
        if length > 1024 * 1024 or len(message) < 8 + length:
            raise ProbeError("incomplete relay frame")
        yield kind, stream, message[8:8 + length]
        message = message[8 + length:]


def run(data, *, port=443, context=None, timeout=8):
    # Socket timeouts alone restart after each received byte. This private Linux
    # helper also bounds DNS, TLS, headers and a trickling bridge body together.
    def expired(_signum, _frame):
        raise ProbeError("probe deadline exceeded")

    started = time.monotonic()
    previous_handler = signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        return run_until(data, port, context, started + timeout)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL,
                            max(0.000001, previous_timer[0] - (time.monotonic() - started)),
                            previous_timer[1])


def run_until(data, port, context, deadline):
    context = context or ssl.create_default_context()
    domain = data["domain"]
    connection = http.client.HTTPSConnection(domain, port, timeout=8, context=context)
    try:
        connection.request("GET", "/?bridge=" + data["capability"], headers={"Connection": "close"})
        response = connection.getresponse()
        if response.status != 200:
            raise ProbeError("bridge request failed")
        body = response.read(2 * 1024 * 1024 + 1)
        if len(body) > 2 * 1024 * 1024:
            raise ProbeError("oversized bridge page")
    finally:
        connection.close()
    metadata = BridgeMetadata()
    metadata.feed(body.decode("utf-8", errors="strict"))
    token = metadata.values.get("tproxy-token", "")
    path = metadata.values.get("tproxy-ws-path", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token) or path != data["ws_path"]:
        raise ProbeError("authenticated bridge metadata is missing")
    protocol = "tproxy-v1." + token
    key = base64.b64encode(os.urandom(16)).decode()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProbeError("probe deadline exceeded")
    with socket.create_connection((domain, port), timeout=remaining) as raw:
        with context.wrap_socket(raw, server_hostname=domain) as sock:
            sock.sendall(("GET " + path + " HTTP/1.1\r\nHost: " + domain +
                "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
                "Origin: https://" + domain + "\r\nSec-WebSocket-Key: " + key +
                "\r\nSec-WebSocket-Protocol: " + protocol + "\r\n\r\n").encode())
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                if len(header) >= 16384:
                    raise ProbeError("oversized upgrade response")
                header.extend(receive_exact(sock, 1, deadline))
            lines = header.decode("ascii").split("\r\n")
            headers = {}
            for line in lines[1:]:
                if not line:
                    continue
                name, value = line.split(":", 1)
                name = name.lower()
                if name in headers:
                    raise ProbeError("duplicate upgrade header")
                headers[name] = value.strip()
            expected_accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            if (lines[0].split()[1] != "101" or headers.get("sec-websocket-accept") != expected_accept or
                    headers.get("sec-websocket-protocol") != protocol or headers.get("upgrade", "").lower() != "websocket" or
                    "upgrade" not in [part.strip() for part in headers.get("connection", "").lower().split(",")]):
                raise ProbeError("websocket upgrade was not authenticated")
            send_ws(sock, frame(0x10, payload=b"\x01"))
            if receive_ws(sock, deadline) != frame(0x11):
                raise ProbeError("missing WELCOME")
            send_ws(sock, frame(1, 1))
            send_ws(sock, frame(2, 1, bytes.fromhex(data["request"])))
            ciphertext = bytearray()
            keystream = bytes.fromhex(data["response_key"])
            nonce = bytes.fromhex(data["nonce"])
            while True:
                for kind, stream, payload in relay_frames(receive_ws(sock, deadline)):
                    if kind == 5 and stream == 0 and len(payload) <= 64:
                        send_ws(sock, frame(6, payload=payload))
                    elif kind == 4 and stream == 1 and len(payload) == 4 and int.from_bytes(payload, "big") > 0:
                        continue
                    elif kind == 2 and stream == 1 and payload:
                        ciphertext.extend(payload)
                    else:
                        raise ProbeError("backend closed or returned invalid relay data")
                if len(ciphertext) > len(keystream):
                    raise ProbeError("oversized backend reply")
                plain = bytes(value ^ keystream[i] for i, value in enumerate(ciphertext))
                if len(plain) < 4:
                    continue
                length = struct.unpack("<I", plain[:4])[0]
                if length < 40 or length > len(keystream) - 4:
                    raise ProbeError("invalid MTProto reply size")
                if len(plain) < length + 4:
                    continue
                payload = plain[4:4 + length]
                real_length = 20 + struct.unpack("<I", payload[16:20])[0]
                if (payload[:8] != b"\0" * 8 or not 0 <= length - real_length <= 3 or
                        payload[20:24] != struct.pack("<I", 0x05162463) or payload[24:40] != nonce):
                    raise ProbeError("backend did not return the expected res_pq")
                try:
                    send_ws(sock, frame(3, 1))
                except OSError:
                    pass  # A completed res_pq remains proof if the peer closes first.
                return


if __name__ == "__main__":
    try:
        run(json.load(sys.stdin))
    except Exception:
        # TLS/HTTP exception messages can contain the bridge URL; never print them.
        print("WEB_PROBE_FAILED")
        sys.exit(1)
    print("WEB_PROBE_OK")
