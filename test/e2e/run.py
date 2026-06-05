#!/usr/bin/env python3
"""
End-to-end / integration harness for mtproto-proxy.

Runs real proxy process + fake upstream/mask servers and validates critical flows:
- fake Telegram DC path (via SOCKS5/HTTP CONNECT upstream tunnel)
- SOCKS5 success/failure
- HTTP CONNECT success/failure
- MiddleProxy handshake failure -> direct fallback
- mask fallback to local nginx target
- invalid TLS / invalid MTProto handshake handling
- replay attack rejection
- slowloris / partial ClientHello timeout
- connection churn (10k+)
- SIGTERM during active relay
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import random
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional


ROOT = Path(__file__).resolve().parents[2]
PROXY_BIN = ROOT / "zig-out/bin/mtproto-proxy"
ACTIVE_PROXY_BIN = PROXY_BIN
OBF_GEN = ROOT / "src/e2e_obf_handshake_gen.zig"
DEFAULT_SECRET_HEX = "00112233445566778899aabbccddeeff"
DEFAULT_TLS_DOMAIN = "google.com"

RPC_NONCE_REQ = bytes([0xAA, 0x87, 0xCB, 0x7A])
RPC_CRYPTO_AES = bytes([0x01, 0x00, 0x00, 0x00])
DEFAULT_MP_KEY_SEL = bytes([0xC4, 0xF9, 0xFA, 0xCA])  # first 4 bytes of default proxy_secret

TLS_RECORD_HANDSHAKE = 0x16
TLS_RECORD_CHANGE_CIPHER = 0x14
TLS_RECORD_APPLICATION = 0x17

_HANDSHAKE_CACHE: dict[tuple[str, int, str], bytes] = {}


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_for_listen(host: str, port: int, timeout_sec: float) -> bool:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            if s.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.03)
    return False


def wait_for_condition(predicate: Callable[[], bool], timeout_sec: float, interval_sec: float = 0.02) -> bool:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval_sec)
    return predicate()


def recv_exact(sock: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        out.extend(chunk)
    return bytes(out)


def recv_until(sock: socket.socket, marker: bytes, limit: int = 8192) -> bytes:
    buf = bytearray()
    while marker not in buf:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > limit:
            break
    return bytes(buf)


def build_tls_record(record_type: int, payload: bytes) -> bytes:
    return bytes([record_type, 0x03, 0x03]) + struct.pack(">H", len(payload)) + payload


def build_tls_auth_client_hello(secret: bytes, hostname: str) -> bytes:
    host = hostname.encode("ascii", errors="ignore") or b"www.google.com"

    sni_list_len = 1 + 2 + len(host)
    sni_ext_len = 2 + sni_list_len
    supported_versions_ext_len = 3

    body_len = (
        2
        + 32
        + 1
        + 32
        + 2
        + 2
        + 1
        + 1
        + 2
        + 4
        + sni_ext_len
        + 4
        + supported_versions_ext_len
    )

    record_payload_len = 4 + body_len
    packet = bytearray(5 + record_payload_len)

    packet[0] = TLS_RECORD_HANDSHAKE
    packet[1] = 0x03
    packet[2] = 0x01
    packet[3:5] = struct.pack(">H", record_payload_len)

    packet[5] = 0x01
    packet[6] = (body_len >> 16) & 0xFF
    packet[7] = (body_len >> 8) & 0xFF
    packet[8] = body_len & 0xFF

    pos = 9
    packet[pos : pos + 2] = b"\x03\x03"
    pos += 2

    random_pos = pos
    pos += 32

    packet[pos] = 0x20
    pos += 1
    packet[pos : pos + 32] = os.urandom(32)
    pos += 32

    packet[pos : pos + 2] = struct.pack(">H", 2)
    pos += 2
    packet[pos : pos + 2] = b"\x13\x01"
    pos += 2

    packet[pos] = 1
    pos += 1
    packet[pos] = 0
    pos += 1

    packet[pos : pos + 2] = struct.pack(">H", 4 + sni_ext_len + 4 + supported_versions_ext_len)
    pos += 2

    packet[pos : pos + 2] = b"\x00\x00"
    pos += 2
    packet[pos : pos + 2] = struct.pack(">H", sni_ext_len)
    pos += 2
    packet[pos : pos + 2] = struct.pack(">H", sni_list_len)
    pos += 2
    packet[pos] = 0
    pos += 1
    packet[pos : pos + 2] = struct.pack(">H", len(host))
    pos += 2
    packet[pos : pos + len(host)] = host
    pos += len(host)

    packet[pos : pos + 2] = b"\x00\x2b"
    pos += 2
    packet[pos : pos + 2] = struct.pack(">H", supported_versions_ext_len)
    pos += 2
    packet[pos] = 2
    pos += 1
    packet[pos : pos + 2] = b"\x03\x04"
    pos += 2

    if pos != len(packet):
        raise RuntimeError("tls-auth packet build mismatch")

    mac_input = bytearray(packet)
    for i in range(random_pos, random_pos + 32):
        mac_input[i] = 0

    mac = bytearray(hmac.new(secret, mac_input, hashlib.sha256).digest())
    ts = int(time.time())
    ts_bytes = struct.pack("<I", ts)
    mac[28] ^= ts_bytes[0]
    mac[29] ^= ts_bytes[1]
    mac[30] ^= ts_bytes[2]
    mac[31] ^= ts_bytes[3]
    packet[random_pos : random_pos + 32] = mac
    return bytes(packet)


def generate_obf_handshake(secret_hex: str, dc_idx: int, proto: str = "intermediate") -> bytes:
    key = (secret_hex, dc_idx, proto)
    if key in _HANDSHAKE_CACHE:
        return _HANDSHAKE_CACHE[key]

    cmd = ["zig", "run", str(OBF_GEN), "--", secret_hex, str(dc_idx), proto]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"obf handshake generator failed:\n{proc.stderr}\n{proc.stdout}")
    raw = proc.stdout.strip()
    if len(raw) != 128:
        raise RuntimeError(f"unexpected handshake hex length: {len(raw)}")
    hs = bytes.fromhex(raw)
    _HANDSHAKE_CACHE[key] = hs
    return hs


def read_proxy_records(sock: socket.socket, budget_sec: float = 0.7) -> bytes:
    sock.setblocking(False)
    deadline = time.time() + budget_sec
    out = bytearray()
    while time.time() < deadline:
        timeout = max(0.0, deadline - time.time())
        r, _, _ = select.select([sock], [], [], timeout)
        if not r:
            continue
        try:
            chunk = sock.recv(8192)
        except BlockingIOError:
            continue
        if not chunk:
            break
        out.extend(chunk)
        if len(out) >= 4096:
            break
    sock.setblocking(True)
    return bytes(out)


def perform_valid_client_handshake(sock: socket.socket, secret_hex: str, tls_domain: str, dc_idx: int = 1) -> None:
    secret = bytes.fromhex(secret_hex)
    hello = build_tls_auth_client_hello(secret, tls_domain)
    sock.sendall(hello)

    # ServerHello path is asynchronous; we only need to avoid leaving unread
    # backpressure for very small socket buffers.
    _ = read_proxy_records(sock, budget_sec=0.25)

    hs = generate_obf_handshake(secret_hex, dc_idx, "intermediate")
    sock.sendall(build_tls_record(TLS_RECORD_CHANGE_CIPHER, b"\x01"))
    sock.sendall(build_tls_record(TLS_RECORD_APPLICATION, hs))


def wait_socket_closed(sock: socket.socket, timeout_sec: float = 2.0) -> bool:
    deadline = time.time() + timeout_sec
    sock.setblocking(False)
    try:
        while time.time() < deadline:
            r, _, _ = select.select([sock], [], [], 0.05)
            if not r:
                continue
            try:
                data = sock.recv(1024)
            except ConnectionResetError:
                return True
            except (BlockingIOError, InterruptedError):
                continue
            if data == b"":
                return True
        return False
    finally:
        sock.setblocking(True)


def assert_socket_closed_soon(sock: socket.socket, timeout_sec: float = 2.0) -> None:
    if not wait_socket_closed(sock, timeout_sec):
        raise AssertionError("socket did not close in time")


@dataclass
class ProxyInstance:
    proc: subprocess.Popen[bytes]
    cfg_path: Path
    log_path: Path
    port: int
    workdir: Path

    def stop(self) -> None:
        if self.proc.poll() is not None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=3)

    def read_log_tail(self, max_lines: int = 80) -> str:
        if not self.log_path.exists():
            return ""
        lines = self.log_path.read_text(errors="replace").splitlines()
        return "\n".join(lines[-max_lines:])


def start_proxy(config_text: str, port: int) -> ProxyInstance:
    if not ACTIVE_PROXY_BIN.exists():
        raise RuntimeError(f"proxy binary not found: {ACTIVE_PROXY_BIN}; run `zig build` first")

    temp_dir = Path(tempfile.mkdtemp(prefix="mtproto-e2e-"))
    cfg_path = temp_dir / "config.toml"
    log_path = temp_dir / "proxy.log"
    cfg_path.write_text(config_text, encoding="utf-8")

    log_file = open(log_path, "wb")
    proc = subprocess.Popen(
        [str(ACTIVE_PROXY_BIN), str(cfg_path)],
        cwd=ROOT,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    log_file.close()

    if not wait_for_listen("127.0.0.1", port, timeout_sec=8.0):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        tail = log_path.read_text(errors="replace") if log_path.exists() else ""
        raise RuntimeError(f"proxy failed to listen on port {port}\n{tail}")

    return ProxyInstance(proc=proc, cfg_path=cfg_path, log_path=log_path, port=port, workdir=temp_dir)


class FakeSocks5Server:
    def __init__(self, mode: str = "success"):
        self.mode = mode
        self.port = free_port()
        self._sock: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._lock = threading.Lock()
        self.connect_targets: list[tuple[str, int]] = []
        self.tunnel_bytes = 0
        self.middleproxy_frame_seen = 0
        self.middleproxy_disconnects = 0

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen()
        self._sock.settimeout(0.2)
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=1.5)
        for t in self._threads:
            t.join(timeout=1.0)

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
            self._threads.append(t)
            t.start()

    def _handle_conn(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(3.0)
            try:
                hdr = recv_exact(conn, 2)
                if hdr[0] != 0x05:
                    return
                n_methods = hdr[1]
                _ = recv_exact(conn, n_methods)
                conn.sendall(b"\x05\x00")  # no-auth

                req = recv_exact(conn, 4)
                if req[0] != 0x05 or req[1] != 0x01:
                    return

                atyp = req[3]
                host = ""
                if atyp == 0x01:
                    rest = recv_exact(conn, 4 + 2)
                    host = ".".join(str(x) for x in rest[0:4])
                    port = struct.unpack(">H", rest[4:6])[0]
                elif atyp == 0x03:
                    dlen = recv_exact(conn, 1)[0]
                    rest = recv_exact(conn, dlen + 2)
                    host = rest[:dlen].decode("ascii", errors="replace")
                    port = struct.unpack(">H", rest[dlen : dlen + 2])[0]
                elif atyp == 0x04:
                    rest = recv_exact(conn, 16 + 2)
                    host = ":".join(f"{rest[i]:02x}{rest[i+1]:02x}" for i in range(0, 16, 2))
                    port = struct.unpack(">H", rest[16:18])[0]
                else:
                    return

                with self._lock:
                    self.connect_targets.append((host, port))

                if self.mode == "fail_connect":
                    conn.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                    return

                conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")

                if self.mode == "middleproxy_fallback" and port == 8888:
                    self._handle_middleproxy_then_drop(conn)
                    return

                self._tunnel_loop(conn)
            except (ConnectionError, OSError, TimeoutError):
                return

    def _read_plain_mp_frame(self, conn: socket.socket) -> tuple[int, bytes]:
        hdr = recv_exact(conn, 8)
        total_len, seq_no = struct.unpack("<Ii", hdr)
        if total_len < 12 or total_len > 65535:
            raise RuntimeError("bad mp frame length")
        body = recv_exact(conn, total_len - 8)
        payload = body[:-4]
        checksum = struct.unpack("<I", body[-4:])[0]
        calc = zlib.crc32(hdr + payload) & 0xFFFFFFFF
        if checksum != calc:
            raise RuntimeError("bad mp checksum")
        return seq_no, payload

    def _write_plain_mp_frame(self, conn: socket.socket, seq_no: int, payload: bytes) -> None:
        total_len = len(payload) + 12
        head = struct.pack("<Ii", total_len, seq_no)
        checksum = struct.pack("<I", zlib.crc32(head + payload) & 0xFFFFFFFF)
        conn.sendall(head + payload + checksum)

    def _handle_middleproxy_then_drop(self, conn: socket.socket) -> None:
        seq_no, payload = self._read_plain_mp_frame(conn)
        if seq_no != -2:
            return
        if len(payload) != 32 or payload[0:4] != RPC_NONCE_REQ:
            return

        ts = payload[12:16]
        nonce_srv = os.urandom(16)
        response_payload = RPC_NONCE_REQ + DEFAULT_MP_KEY_SEL + RPC_CRYPTO_AES + ts + nonce_srv
        self._write_plain_mp_frame(conn, -2, response_payload)

        # Proxy now sends encrypted rpc_handshake frame; we only need to consume
        # some bytes and then drop the socket so proxy executes MP->direct fallback.
        try:
            conn.settimeout(1.5)
            chunk = conn.recv(4096)
            if chunk:
                with self._lock:
                    self.middleproxy_frame_seen += len(chunk)
        except OSError:
            pass
        finally:
            with self._lock:
                self.middleproxy_disconnects += 1

    def _tunnel_loop(self, conn: socket.socket) -> None:
        conn.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data = conn.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if not data:
                return
            with self._lock:
                self.tunnel_bytes += len(data)


class FakeHttpConnectServer:
    def __init__(self, mode: str = "success"):
        self.mode = mode
        self.port = free_port()
        self._sock: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._lock = threading.Lock()
        self.connect_targets: list[tuple[str, int]] = []
        self.tunnel_bytes = 0

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen()
        self._sock.settimeout(0.2)
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=1.5)
        for t in self._threads:
            t.join(timeout=1.0)

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
            self._threads.append(t)
            t.start()

    def _handle_conn(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(3.0)
            try:
                req = recv_until(conn, b"\r\n\r\n", limit=8192)
                first_line = req.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
                parts = first_line.split(" ")
                host = ""
                port = 0
                if len(parts) >= 2 and ":" in parts[1]:
                    host, port_str = parts[1].rsplit(":", 1)
                    port = int(port_str)
                with self._lock:
                    self.connect_targets.append((host, port))

                if self.mode == "fail_connect":
                    conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    return

                conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                conn.settimeout(0.2)
                while not self._stop.is_set():
                    try:
                        data = conn.recv(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        return
                    if not data:
                        return
                    with self._lock:
                        self.tunnel_bytes += len(data)
            except OSError:
                return


class FakeMaskServer:
    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        self.port = free_port()
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.received = bytearray()

    def received_bytes(self) -> bytes:
        with self._lock:
            return bytes(self.received)

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen()
        self._sock.settimeout(0.2)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def _loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(0.2)
                deadline = time.time() + 2.0
                while time.time() < deadline and not self._stop.is_set():
                    try:
                        data = conn.recv(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not data:
                        break
                    with self._lock:
                        self.received.extend(data)
                        complete = b"\r\n\r\n" in self.received
                    if complete:
                        # Keep the relay path alive just enough for confirmation.
                        try:
                            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                        except OSError:
                            pass
                        break


def base_config(
    *,
    port: int,
    secret_hex: str = DEFAULT_SECRET_HEX,
    mask: bool = False,
    mask_target: Optional[str] = None,
    mask_port: Optional[int] = None,
    use_middle_proxy: bool = False,
    force_media_middle_proxy: bool = False,
    upstream_type: str = "auto",
    upstream_host: Optional[str] = None,
    upstream_port: Optional[int] = None,
    handshake_timeout_sec: int = 5,
    idle_timeout_sec: int = 30,
    graceful_shutdown_timeout_sec: int = 15,
    max_connections: int = 4096,
) -> str:
    lines: list[str] = []
    lines.append("[general]")
    lines.append(f"use_middle_proxy = {'true' if use_middle_proxy else 'false'}")
    lines.append(f"force_media_middle_proxy = {'true' if force_media_middle_proxy else 'false'}")
    lines.append("")

    lines.append("[server]")
    lines.append(f"port = {port}")
    lines.append(f"max_connections = {max_connections}")
    lines.append(f"idle_timeout_sec = {idle_timeout_sec}")
    lines.append(f"handshake_timeout_sec = {handshake_timeout_sec}")
    lines.append(f"graceful_shutdown_timeout_sec = {graceful_shutdown_timeout_sec}")
    lines.append('log_level = "warn"')
    lines.append("unsafe_override_limits = true")
    lines.append('middle_proxy_nat_ip = "127.0.0.1"')
    lines.append("")

    lines.append("[censorship]")
    lines.append(f'tls_domain = "{DEFAULT_TLS_DOMAIN}"')
    lines.append(f"mask = {'true' if mask else 'false'}")
    if mask_target is not None:
        lines.append(f'mask_target = "{mask_target}"')
    if mask_port is not None:
        lines.append(f"mask_port = {mask_port}")
    lines.append("desync = false")
    lines.append("fast_mode = false")
    lines.append("")

    lines.append("[upstream]")
    lines.append(f'type = "{upstream_type}"')
    lines.append("allow_direct_fallback = true")
    lines.append("")

    if upstream_type == "socks5":
        assert upstream_host is not None and upstream_port is not None
        lines.append("[upstream.socks5]")
        lines.append(f'host = "{upstream_host}"')
        lines.append(f"port = {upstream_port}")
        lines.append("")
    elif upstream_type == "http":
        assert upstream_host is not None and upstream_port is not None
        lines.append("[upstream.http]")
        lines.append(f'host = "{upstream_host}"')
        lines.append(f"port = {upstream_port}")
        lines.append("")

    lines.append("[access.users]")
    lines.append(f'user1 = "{secret_hex}"')
    lines.append("")
    return "\n".join(lines)


def scenario_fake_telegram_dc_via_socks5() -> None:
    socks = FakeSocks5Server(mode="success")
    socks.start()
    proxy_port = free_port()
    cfg = base_config(
        port=proxy_port,
        upstream_type="socks5",
        upstream_host="127.0.0.1",
        upstream_port=socks.port,
    )
    proxy = start_proxy(cfg, proxy_port)
    try:
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=2.0) as c:
            c.settimeout(2.0)
            perform_valid_client_handshake(c, DEFAULT_SECRET_HEX, DEFAULT_TLS_DOMAIN)
            # First payload triggers upstream connect path.
            c.sendall(build_tls_record(TLS_RECORD_APPLICATION, b"\x11" * 64))
            connected = wait_for_condition(lambda: len(socks.connect_targets) > 0, timeout_sec=2.0)
            assert connected, "SOCKS5 CONNECT was not attempted in time"
            # Send one more record after connect to reduce scheduling flakiness in CI.
            c.sendall(build_tls_record(TLS_RECORD_APPLICATION, b"\x12" * 128))
            forwarded = wait_for_condition(lambda: socks.tunnel_bytes > 0, timeout_sec=2.0)
            assert forwarded, "no C2S bytes reached fake DC tunnel"
        assert socks.tunnel_bytes > 0, "no C2S bytes reached fake DC tunnel"
        assert any(p == 443 for _, p in socks.connect_targets), f"no DC connect in {socks.connect_targets}"
    finally:
        proxy.stop()
        socks.stop()


def scenario_socks5_upstream_failure() -> None:
    socks = FakeSocks5Server(mode="fail_connect")
    socks.start()
    proxy_port = free_port()
    cfg = base_config(
        port=proxy_port,
        upstream_type="socks5",
        upstream_host="127.0.0.1",
        upstream_port=socks.port,
    )
    proxy = start_proxy(cfg, proxy_port)
    try:
        c = socket.create_connection(("127.0.0.1", proxy_port), timeout=2.0)
        c.settimeout(2.0)
        try:
            perform_valid_client_handshake(c, DEFAULT_SECRET_HEX, DEFAULT_TLS_DOMAIN)
            c.sendall(build_tls_record(TLS_RECORD_APPLICATION, b"\x22" * 64))
            assert_socket_closed_soon(c, timeout_sec=2.0)
        finally:
            c.close()
        assert len(socks.connect_targets) >= 1, "SOCKS5 CONNECT was not attempted"
    finally:
        proxy.stop()
        socks.stop()


def scenario_http_connect_success() -> None:
    http = FakeHttpConnectServer(mode="success")
    http.start()
    proxy_port = free_port()
    cfg = base_config(
        port=proxy_port,
        upstream_type="http",
        upstream_host="127.0.0.1",
        upstream_port=http.port,
    )
    proxy = start_proxy(cfg, proxy_port)
    try:
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=2.0) as c:
            c.settimeout(2.0)
            perform_valid_client_handshake(c, DEFAULT_SECRET_HEX, DEFAULT_TLS_DOMAIN)
            c.sendall(build_tls_record(TLS_RECORD_APPLICATION, b"\x33" * 64))
            connected = wait_for_condition(lambda: len(http.connect_targets) > 0, timeout_sec=2.0)
            assert connected, "HTTP CONNECT was not attempted in time"
            c.sendall(build_tls_record(TLS_RECORD_APPLICATION, b"\x34" * 128))
            forwarded = wait_for_condition(lambda: http.tunnel_bytes > 0, timeout_sec=2.0)
            assert forwarded, "no tunneled bytes through HTTP CONNECT"
        assert http.tunnel_bytes > 0, "no tunneled bytes through HTTP CONNECT"
        assert any(p == 443 for _, p in http.connect_targets), f"no DC connect in {http.connect_targets}"
    finally:
        proxy.stop()
        http.stop()


def scenario_http_connect_failure() -> None:
    http = FakeHttpConnectServer(mode="fail_connect")
    http.start()
    proxy_port = free_port()
    cfg = base_config(
        port=proxy_port,
        upstream_type="http",
        upstream_host="127.0.0.1",
        upstream_port=http.port,
    )
    proxy = start_proxy(cfg, proxy_port)
    try:
        c = socket.create_connection(("127.0.0.1", proxy_port), timeout=2.0)
        c.settimeout(2.0)
        try:
            perform_valid_client_handshake(c, DEFAULT_SECRET_HEX, DEFAULT_TLS_DOMAIN)
            assert_socket_closed_soon(c, timeout_sec=2.0)
        finally:
            c.close()
        assert len(http.connect_targets) >= 1, "HTTP CONNECT was not attempted"
    finally:
        proxy.stop()
        http.stop()


def scenario_middleproxy_fallback_to_direct() -> None:
    socks = FakeSocks5Server(mode="middleproxy_fallback")
    socks.start()
    proxy_port = free_port()
    cfg = base_config(
        port=proxy_port,
        use_middle_proxy=True,
        upstream_type="socks5",
        upstream_host="127.0.0.1",
        upstream_port=socks.port,
    )
    proxy = start_proxy(cfg, proxy_port)
    try:
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=2.0) as c:
            c.settimeout(2.0)
            perform_valid_client_handshake(c, DEFAULT_SECRET_HEX, DEFAULT_TLS_DOMAIN)
            c.sendall(build_tls_record(TLS_RECORD_APPLICATION, b"\x44" * 64))
            connected = wait_for_condition(lambda: len(socks.connect_targets) > 0, timeout_sec=3.0)
            assert connected, "middle-proxy SOCKS5 CONNECT was not attempted in time\n" + proxy.read_log_tail()
            c.sendall(build_tls_record(TLS_RECORD_APPLICATION, b"\x45" * 128))
            fallback = wait_for_condition(
                lambda: socks.middleproxy_disconnects >= 1 and any(p == 443 for _, p in socks.connect_targets),
                timeout_sec=3.0,
            )
            assert fallback, "middle-proxy fallback did not complete in time\n" + proxy.read_log_tail()
        ports = [p for _, p in socks.connect_targets]
        assert 8888 in ports, f"middle-proxy connect was not attempted: {ports}"
        assert 443 in ports, f"direct fallback connect was not attempted: {ports}"
        assert socks.middleproxy_disconnects >= 1, "middle-proxy fallback trigger did not happen"
    finally:
        proxy.stop()
        socks.stop()


def scenario_mask_fallback_local_nginx() -> None:
    mask = FakeMaskServer()
    mask.start()
    proxy_port = free_port()
    cfg = base_config(
        port=proxy_port,
        mask=True,
        mask_port=mask.port,
        upstream_type="auto",
    )
    proxy = start_proxy(cfg, proxy_port)
    try:
        payload = b"GET / HTTP/1.1\r\nHost: bad.example\r\n\r\n"
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=2.0) as c:
            c.settimeout(2.0)
            c.sendall(payload)
            _ = c.recv(1024)
        received = wait_for_condition(lambda: mask.received_bytes().startswith(payload), timeout_sec=2.0)
        assert received, f"mask target did not receive original bad client bytes: {mask.received_bytes()!r}"
    finally:
        proxy.stop()
        mask.stop()


def scenario_mask_fallback_custom_target() -> None:
    mask = FakeMaskServer(host="127.0.0.2")
    mask.start()
    proxy_port = free_port()
    cfg = base_config(
        port=proxy_port,
        mask=True,
        mask_target=mask.host,
        mask_port=mask.port,
        upstream_type="auto",
    )
    proxy = start_proxy(cfg, proxy_port)
    try:
        payload = b"GET / HTTP/1.1\r\nHost: custom-mask.example\r\n\r\n"
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=2.0) as c:
            c.settimeout(2.0)
            c.sendall(payload)
            try:
                _ = c.recv(1024)
            except (ConnectionResetError, TimeoutError, socket.timeout):
                pass
        received = wait_for_condition(lambda: mask.received_bytes().startswith(payload), timeout_sec=2.0)
        assert received, f"custom mask target did not receive original bad client bytes: {mask.received_bytes()!r}"
    finally:
        proxy.stop()
        mask.stop()


def scenario_invalid_tls_and_mtproto() -> None:
    socks = FakeSocks5Server(mode="success")
    socks.start()
    proxy_port = free_port()
    cfg = base_config(
        port=proxy_port,
        mask=False,
        upstream_type="socks5",
        upstream_host="127.0.0.1",
        upstream_port=socks.port,
        handshake_timeout_sec=1,
    )
    proxy = start_proxy(cfg, proxy_port)
    try:
        # Part 1: invalid full TLS header -> close. Use 5 bytes so the proxy
        # does not need to wait for the partial-header handshake timeout.
        c1 = socket.create_connection(("127.0.0.1", proxy_port), timeout=2.0)
        c1.settimeout(2.0)
        try:
            c1.sendall(b"NOPE!")
            assert_socket_closed_soon(c1, timeout_sec=1.5)
        finally:
            c1.close()

        # Part 2: valid tls-auth + invalid MTProto obfuscation handshake -> close
        c2 = socket.create_connection(("127.0.0.1", proxy_port), timeout=2.0)
        c2.settimeout(2.0)
        try:
            secret = bytes.fromhex(DEFAULT_SECRET_HEX)
            hello = build_tls_auth_client_hello(secret, DEFAULT_TLS_DOMAIN)
            c2.sendall(hello)
            _ = read_proxy_records(c2, budget_sec=0.2)
            c2.sendall(build_tls_record(TLS_RECORD_CHANGE_CIPHER, b"\x01"))
            c2.sendall(build_tls_record(TLS_RECORD_APPLICATION, b"\x00" * 64))
            assert_socket_closed_soon(c2, timeout_sec=2.0)
        finally:
            c2.close()

        # Invalid MTProto should not reach upstream connect.
        assert len(socks.connect_targets) == 0, f"unexpected upstream connect: {socks.connect_targets}"
    finally:
        proxy.stop()
        socks.stop()


def scenario_replay_attack_rejected() -> None:
    socks = FakeSocks5Server(mode="success")
    socks.start()
    proxy_port = free_port()
    cfg = base_config(
        port=proxy_port,
        mask=False,
        upstream_type="socks5",
        upstream_host="127.0.0.1",
        upstream_port=socks.port,
    )
    proxy = start_proxy(cfg, proxy_port)
    try:
        secret = bytes.fromhex(DEFAULT_SECRET_HEX)
        replay_hello = build_tls_auth_client_hello(secret, DEFAULT_TLS_DOMAIN)
        obf = generate_obf_handshake(DEFAULT_SECRET_HEX, 1, "intermediate")

        c1 = socket.create_connection(("127.0.0.1", proxy_port), timeout=2.0)
        c1.settimeout(2.0)
        c1.sendall(replay_hello)
        _ = read_proxy_records(c1, budget_sec=0.25)
        c1.sendall(build_tls_record(TLS_RECORD_CHANGE_CIPHER, b"\x01"))
        c1.sendall(build_tls_record(TLS_RECORD_APPLICATION, obf))
        time.sleep(0.4)

        c2 = socket.create_connection(("127.0.0.1", proxy_port), timeout=2.0)
        c2.settimeout(2.0)
        c2.sendall(replay_hello)
        assert_socket_closed_soon(c2, timeout_sec=2.0)
        c2.close()

        time.sleep(0.4)
        assert len(socks.connect_targets) == 1, f"replay should not create 2nd upstream connect: {socks.connect_targets}"
        c1.close()
    finally:
        proxy.stop()
        socks.stop()


def scenario_slowloris_partial_clienthello() -> None:
    proxy_port = free_port()
    cfg = base_config(
        port=proxy_port,
        mask=False,
        # Config clamps handshake_timeout_sec to a minimum of 5 seconds.
        handshake_timeout_sec=5,
        idle_timeout_sec=10,
        upstream_type="auto",
    )
    proxy = start_proxy(cfg, proxy_port)
    try:
        c = socket.create_connection(("127.0.0.1", proxy_port), timeout=2.0)
        c.settimeout(2.0)
        try:
            c.sendall(b"\x16\x03\x01")
            assert wait_socket_closed(c, timeout_sec=8.0), (
                "slowloris connection did not close after handshake timeout\n"
                + proxy.read_log_tail()
            )
        finally:
            c.close()
    finally:
        proxy.stop()


def scenario_connection_churn_10k() -> None:
    proxy_port = free_port()
    cfg = base_config(
        port=proxy_port,
        mask=False,
        upstream_type="auto",
        max_connections=8192,
        idle_timeout_sec=5,
        handshake_timeout_sec=5,
    )
    proxy = start_proxy(cfg, proxy_port)
    try:
        total = 10_000
        workers = 200
        lock = threading.Lock()
        idx = 0
        ok = 0
        fail = 0

        def worker() -> None:
            nonlocal idx, ok, fail
            while True:
                with lock:
                    if idx >= total:
                        return
                    idx += 1
                try:
                    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=0.35)
                    s.close()
                    with lock:
                        ok += 1
                except OSError:
                    with lock:
                        fail += 1

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
        start = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed = time.time() - start
        print(f"      churn: ok={ok} fail={fail} elapsed={elapsed:.2f}s")
        assert ok >= 9_500, f"too many churn failures: ok={ok} fail={fail}"
    finally:
        proxy.stop()


def scenario_sigterm_during_active_relay() -> None:
    socks = FakeSocks5Server(mode="success")
    socks.start()
    proxy_port = free_port()
    cfg = base_config(
        port=proxy_port,
        upstream_type="socks5",
        upstream_host="127.0.0.1",
        upstream_port=socks.port,
        mask=False,
        graceful_shutdown_timeout_sec=1,
    )
    proxy = start_proxy(cfg, proxy_port)
    try:
        c = socket.create_connection(("127.0.0.1", proxy_port), timeout=2.0)
        c.settimeout(2.0)
        perform_valid_client_handshake(c, DEFAULT_SECRET_HEX, DEFAULT_TLS_DOMAIN)

        stop_sender = threading.Event()

        def sender() -> None:
            payload = build_tls_record(TLS_RECORD_APPLICATION, b"\x55" * 128)
            while not stop_sender.is_set():
                try:
                    c.sendall(payload)
                except OSError:
                    return
                time.sleep(0.01)

        t = threading.Thread(target=sender, daemon=True)
        t.start()
        time.sleep(0.25)

        proxy.proc.send_signal(signal.SIGTERM)
        try:
            proxy.proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            raise AssertionError("proxy did not exit on SIGTERM with active relay")
        finally:
            stop_sender.set()
            t.join(timeout=1.0)
            c.close()

        assert proxy.proc.returncode is not None, "proxy return code is missing"
    finally:
        socks.stop()


SCENARIOS: dict[str, Callable[[], None]] = {
    "fake_telegram_dc_via_socks5": scenario_fake_telegram_dc_via_socks5,
    "socks5_upstream_failure": scenario_socks5_upstream_failure,
    "http_connect_success": scenario_http_connect_success,
    "http_connect_failure": scenario_http_connect_failure,
    "middleproxy_fallback_to_direct": scenario_middleproxy_fallback_to_direct,
    "mask_fallback_local_nginx": scenario_mask_fallback_local_nginx,
    "mask_fallback_custom_target": scenario_mask_fallback_custom_target,
    "invalid_tls_and_mtproto": scenario_invalid_tls_and_mtproto,
    "replay_attack_rejected": scenario_replay_attack_rejected,
    "slowloris_partial_clienthello": scenario_slowloris_partial_clienthello,
    "connection_churn_10k": scenario_connection_churn_10k,
    "sigterm_during_active_relay": scenario_sigterm_during_active_relay,
}


def main() -> int:
    parser = argparse.ArgumentParser(description="mtproto-proxy E2E harness")
    parser.add_argument(
        "--proxy-bin",
        default=str(PROXY_BIN),
        help="Path to mtproto-proxy binary (default: zig-out/bin/mtproto-proxy)",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        default=[],
        help="Run only selected scenario(s); repeatable",
    )
    parser.add_argument("--list", action="store_true", help="List available scenarios and exit")
    args = parser.parse_args()

    if args.list:
        for name in SCENARIOS:
            print(name)
        return 0

    selected = args.scenario if args.scenario else list(SCENARIOS.keys())
    unknown = [s for s in selected if s not in SCENARIOS]
    if unknown:
        print("Unknown scenarios:", ", ".join(unknown))
        return 2

    if sys.platform != "linux":
        print(f"skip: e2e harness requires Linux runtime (current: {sys.platform})")
        return 0

    global ACTIVE_PROXY_BIN
    ACTIVE_PROXY_BIN = Path(args.proxy_bin).resolve()

    if not ACTIVE_PROXY_BIN.exists():
        print(f"error: missing binary {ACTIVE_PROXY_BIN}. Run `zig build` first.")
        return 2

    print("== mtproto-proxy e2e ==")
    print(f"binary: {ACTIVE_PROXY_BIN}")
    print(f"scenarios: {len(selected)}")
    print("")

    passed = 0
    started = time.time()
    for name in selected:
        print(f"[RUN ] {name}")
        t0 = time.time()
        try:
            SCENARIOS[name]()
            dt = time.time() - t0
            print(f"[PASS] {name} ({dt:.2f}s)")
            passed += 1
        except Exception as exc:  # noqa: BLE001
            dt = time.time() - t0
            print(f"[FAIL] {name} ({dt:.2f}s): {exc}")
            traceback.print_exc()
            return 1

    total = time.time() - started
    print("")
    print(f"passed {passed}/{len(selected)} scenarios in {total:.2f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
