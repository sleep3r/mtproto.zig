"""Offline HTTPS/WSS fixtures for the installer gate; no Telegram connections."""
import base64
import hashlib
import importlib.util
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("web_probe", ROOT / "src/ctl/web_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def relay_frame(kind, stream=0, payload=b""):
    return bytes([kind]) + stream.to_bytes(3, "big") + struct.pack(">I", len(payload)) + payload


def send_ws(sock, message):
    sock.sendall(bytes([0x82, len(message)]) + message)


def receive_ws(sock):
    head = sock.recv(2)
    if len(head) != 2:
        raise EOFError()
    length = head[1] & 127
    if length == 126:
        length = struct.unpack(">H", sock.recv(2))[0]
    mask = sock.recv(4)
    payload = b""
    while len(payload) < length:
        payload += sock.recv(length - len(payload))
    return bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))


class ProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.cert = Path(cls.temp.name) / "cert.pem"
        cls.key = Path(cls.temp.name) / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                        "-keyout", str(cls.key), "-out", str(cls.cert)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def check_fixture(self, mode, trusted=True):
        nonce = bytes(range(16))
        data = dict(domain="localhost", capability="B" * 43, ws_path="/custom-socket",
                    request="00" * 108, response_key="00" * 512, nonce=nonce.hex())
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(2)
        port = listener.getsockname()[1]
        seen = []
        errors = []

        def serve():
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(self.cert, self.key)
            try:
                for index in range(1 if mode in ("static", "trickle") or not trusted else 2):
                    raw, _ = listener.accept()
                    with server_context.wrap_socket(raw, server_side=True) as conn:
                        conn.settimeout(2)
                        request = b""
                        while b"\r\n\r\n" not in request:
                            part = conn.recv(4096)
                            if not part:
                                raise EOFError()
                            request += part
                        seen.append(request.decode())
                        if index == 0:
                            if mode == "trickle":
                                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                                for _ in range(100):
                                    conn.sendall(b"x")
                                    time.sleep(0.02)
                                continue
                            body = b"<html>ordinary website</html>" if mode == "static" else (
                                b'<meta name="tproxy-token" content="' + b"A" * 43 +
                                b'"><meta name="tproxy-ws-path" content="/custom-socket">')
                            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() +
                                         b"\r\nConnection: close\r\n\r\n" + body)
                            continue
                        headers = dict(line.split(": ", 1) for line in request.decode().split("\r\n")[1:] if ": " in line)
                        accept = base64.b64encode(hashlib.sha1((headers["Sec-WebSocket-Key"] +
                            "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
                        protocol = "wrong" if mode == "protocol" else "tproxy-v1." + "A" * 43
                        conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                                     b"Sec-WebSocket-Accept: " + accept + b"\r\nSec-WebSocket-Protocol: " + protocol.encode() + b"\r\n\r\n")
                        if mode == "protocol":
                            continue
                        self.assertEqual(receive_ws(conn), relay_frame(0x10, payload=b"\x01"))
                        send_ws(conn, relay_frame(0x11))
                        self.assertEqual(receive_ws(conn), relay_frame(1, 1))
                        self.assertEqual(receive_ws(conn), relay_frame(2, 1, bytes.fromhex(data["request"])))
                        if mode == "dead":
                            send_ws(conn, relay_frame(3, 1))
                            continue
                        echoed = nonce if mode == "success" else b"x" * 16
                        # A structurally complete unencrypted res_pq with one key fingerprint.
                        body = struct.pack("<I", 0x05162463) + echoed + b"s" * 16 + b"\x01\x17\0\0" + struct.pack("<IIQ", 0x1cb5c415, 1, 123)
                        payload = b"\0" * 8 + struct.pack("<QI", 1, len(body)) + body
                        send_ws(conn, relay_frame(2, 1, struct.pack("<I", len(payload)) + payload))
            except (ssl.SSLError, EOFError, BrokenPipeError, ConnectionResetError):
                pass
            except Exception as exc:
                errors.append(exc)
            finally:
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        context = ssl.create_default_context(cafile=str(self.cert)) if trusted else None
        started = time.monotonic()
        try:
            if mode == "success" and trusted:
                probe.run(data, port=port, context=context)
            else:
                with self.assertRaises((probe.ProbeError, ssl.SSLError)):
                    if mode == "trickle":
                        probe.run(data, port=port, context=context, timeout=0.1)
                    else:
                        probe.run(data, port=port, context=context)
        finally:
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        if trusted:
            self.assertIn("GET /?bridge=" + "B" * 43 + " HTTP/1.1", seen[0])
        if mode == "trickle":
            self.assertLess(time.monotonic() - started, 0.5)
        if trusted and mode not in ("static", "trickle"):
            self.assertIn("GET /custom-socket HTTP/1.1", seen[1])
            self.assertIn("Sec-WebSocket-Protocol: tproxy-v1." + "A" * 43, seen[1])

    def test_ordinary_http_200_is_not_a_working_web_proxy(self):
        self.check_fixture("static")

    def test_welcome_with_a_dead_backend_is_rejected(self):
        self.check_fixture("dead")

    def test_nonce_matching_res_pq_proves_the_complete_path(self):
        self.check_fixture("success")

    def test_res_pq_for_another_nonce_is_rejected(self):
        self.check_fixture("nonce")

    def test_incorrect_websocket_subprotocol_is_rejected(self):
        self.check_fixture("protocol")

    def test_untrusted_certificate_is_rejected(self):
        self.check_fixture("success", trusted=False)

    def test_bridge_trickle_cannot_extend_the_absolute_deadline(self):
        self.check_fixture("trickle")


if __name__ == "__main__":
    unittest.main()
