"""Security-regression tests for the dashboard API (server.py).

The dashboard is a root control plane reachable over the network, so its auth / Host-pin /
CSRF gates are the highest-value thing to keep covered. Run with:

    pip install fastapi httpx psutil pytest
    pytest src/ctl/dashboard_assets/test_server.py

The suite skips itself if the runtime deps aren't installed (e.g. minimal CI image).
"""

import base64
import os
import tempfile
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("psutil")

from fastapi.testclient import TestClient  # noqa: E402

_token_dir = tempfile.TemporaryDirectory(prefix="dashboard-test-token-")
os.environ["MTPROTO_DASHBOARD_TOKEN_FILE"] = str(Path(_token_dir.name) / "token")
import server  # noqa: E402

TOKEN = server.DASHBOARD_TOKEN


def _auth(token=TOKEN):
    return {"Authorization": "Basic " + base64.b64encode(f"x:{token}".encode()).decode()}


@pytest.fixture(scope="module", autouse=True)
def _cleanup_token():
    yield
    _token_dir.cleanup()


@pytest.fixture(autouse=True)
def _hermetic_host(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[server]\npublic_ip = "192.0.2.1"\n[access.users]\n', encoding="utf-8")
    monkeypatch.setattr(server, "_proxy_config_candidates", lambda: [cfg])
    monkeypatch.setattr(server.subprocess, "check_output", lambda *a, **kw: "")
    monkeypatch.setattr(server.subprocess, "run", lambda *a, **kw: server.subprocess.CompletedProcess(a[0], 0, "", ""))
    monkeypatch.setattr(server, "ensure_log_thread", lambda: None)
    monkeypatch.setattr(server, "_traffic_collection_paused", True)


@pytest.fixture
def client():
    # base_url host=localhost so the loopback Host-pin passes; tests set Origin/auth per case.
    return TestClient(server.app, base_url="http://localhost")


def test_unauthenticated_api_rejected(client):
    assert client.get("/api/stats").status_code == 401


@pytest.mark.parametrize("username", ["alice", "alice.phone"])
def test_traffic_collector_reads_metrics_and_keeps_database(monkeypatch, tmp_path, username):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    from traffic import TrafficHistory
    counts = [100, 200]
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            assert self.path == "/metrics"
            body = ("mtproto_start_time_seconds 123\n"
                    f'mtproto_user_client_to_upstream_bytes_total{{user="{username}"}} {counts[0]}\n'
                    f'mtproto_user_upstream_to_client_bytes_total{{user="{username}"}} {counts[1]}\n').encode()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'[metrics]\nenabled = true\nport = {http.server_port}\n[access.users]\n{username} = "' + 'a' * 32 + '"\n')
    monkeypatch.setattr(server, "_find_config_path", lambda: cfg)
    monkeypatch.setattr(server, "TrafficHistory", lambda path: TrafficHistory(tmp_path / "history.db"))
    monkeypatch.setattr(server, "_traffic_snapshot", {})
    try:
        server._traffic_sample()
        assert server._traffic_snapshot["available"]
        counts[:] = [150, 350]
        server._traffic_sample()
        assert server._traffic_snapshot["items"][username]["totals"]["30"] == 200
        assert 'a' * 32 not in (tmp_path / "history.db").read_bytes().decode(errors="replace")
        cfg.write_text(cfg.read_text().replace('a' * 32, 'A' * 32))
        counts[:] = [160, 360]
        server._traffic_sample()
        assert server._traffic_snapshot["items"][username]["totals"]["30"] == 220
        cfg.write_text('[metrics]\nenabled = false\n')
        server._traffic_sample()
        assert server._traffic_snapshot["error"] == "metrics_disabled"
        assert server._traffic_snapshot["items"][username]["totals"]["30"] == 220
    finally:
        http.shutdown()
        http.server_close()
        thread.join()


def test_authenticated_api_ok(client, monkeypatch):
    monkeypatch.setattr(server, "_unit_active", lambda unit: False)
    monkeypatch.setattr(server, "_unit_enabled", lambda unit: False)
    assert client.get("/api/stats", headers=_auth()).status_code == 200


def test_wrong_token_rejected(client):
    assert client.get("/api/stats", headers=_auth("not-the-token")).status_code == 401


def test_unicode_wrong_token_rejected(client):
    assert client.get("/api/stats", headers=_auth("неверный-пароль")).status_code == 401


def test_originless_mutation_requires_custom_header(client):
    assert client.post("/api/users/add", headers=_auth(), json={}).status_code == 403
    response = client.post("/api/users/add", headers={**_auth(), "X-Requested-With": "mtbuddy"}, json={})
    assert response.status_code not in (401, 403)


def test_failed_restart_is_reported(monkeypatch):
    def fail(*args, **kwargs):
        raise server.subprocess.CalledProcessError(1, args[0])
    monkeypatch.setattr(server.subprocess, "run", fail)
    with pytest.raises(server.HTTPException) as exc:
        server._restart_proxy()
    assert exc.value.status_code == 503


def test_dns_rebinding_host_rejected():
    # A non-loopback Host header is blocked before auth (DNS-rebinding defense).
    c = TestClient(server.app, base_url="http://evil.example.com")
    assert c.get("/api/stats", headers=_auth()).status_code == 403


def test_cross_origin_mutation_blocked(client):
    # A state-changing request carrying a cross-origin Origin header is a CSRF attempt → 403,
    # even with valid credentials (the Origin gate runs before the handler).
    r = client.post(
        "/api/users/add",
        headers={**_auth(), "Origin": "http://evil.example.com"},
        json={"name": "x"},
    )
    assert r.status_code == 403


def test_same_origin_mutation_allowed_through_guard(client):
    # A same-origin POST passes the CSRF/Host/auth gates (handler may still 4xx on bad body,
    # but it must NOT be the 401/403 the security middleware emits).
    r = client.post(
        "/api/users/add",
        headers={**_auth(), "Origin": "http://localhost"},
        json={},
    )
    assert r.status_code not in (401, 403)


def test_ws_ticket_roundtrip():
    # A freshly minted ticket validates; tampered / garbage / wrong-token tickets do not.
    t = server._make_ws_ticket()
    assert server._ws_ticket_ok(t)
    assert not server._ws_ticket_ok(t[:-1] + ("0" if t[-1] != "0" else "1"))
    assert not server._ws_ticket_ok("nope")
    assert not server._ws_ticket_ok("")
    assert not server._ws_ticket_ok(None)
    exp = t.split(".")[0]
    import hmac as _hmac
    import hashlib as _hashlib
    forged = exp + "." + _hmac.new(b"other-token", exp.encode(), _hashlib.sha256).hexdigest()
    assert not server._ws_ticket_ok(forged)


def test_expired_ticket_rejected(monkeypatch):
    ticket = server._make_ws_ticket()
    expiry = int(ticket.split(".")[0])
    monkeypatch.setattr(server.time, "time", lambda: expiry + 1)
    assert not server._ws_ticket_ok(ticket)


def test_static_assets_require_auth(client):
    assert client.get("/app.js").status_code == 401


def test_cross_origin_websocket_rejected(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/logs", headers={**_auth(), "Origin": "http://evil.example"}):
            pass


def test_qr_rejects_unrelated_url(client):
    assert client.get("/api/qr", params={"text": "https://evil.example"}, headers=_auth()).status_code == 400


def test_omitted_upstream_password_is_preserved(tmp_path, monkeypatch):
    cfg = tmp_path / "secret.toml"
    cfg.write_text('[upstream.socks5]\nhost = "old"\npassword = "private"\n')
    monkeypatch.setattr(server, "_find_config_path", lambda: cfg)
    assert server._set_upstream_proxy_target("socks5", "new", 1080, "user", None)
    assert 'password = "private"' in cfg.read_text()
    assert server._set_upstream_proxy_target("socks5", "new", 1080, "user", "")
    assert 'password = ""' in cfg.read_text()


def test_toml_rewrite_preserves_comment_and_quoted_hash():
    lines = ['[upstream.socks5]\n', 'password = "old#value"  # keep this\n']
    result = server._set_toml_key(lines, "[upstream.socks5]", "password", '"new"')
    assert result[1] == 'password = "new"  # keep this\n'


def test_invalid_runtime_config_exposes_error(tmp_path, monkeypatch):
    cfg = tmp_path / "broken.toml"
    cfg.write_text('[server]\nport = "unterminated\n')
    monkeypatch.setattr(server, "_proxy_config_candidates", lambda: [cfg])
    assert server._load_proxy_runtime_config().get("error")


def test_public_ip_rejects_invalid_literal(monkeypatch):
    monkeypatch.setattr(server, "_public_ip_cache", {"ts": 0, "ip": ""})
    monkeypatch.setattr(server.subprocess, "check_output", lambda *a, **kw: "999.999.999.999")
    assert server._detect_public_ip() == ""


def test_routing_status_never_contains_proxy_password(tmp_path, monkeypatch):
    cfg = tmp_path / "routing.toml"
    cfg.write_text('[upstream.socks5]\nhost = "127.0.0.1"\npassword = "never-export-this"\n')
    monkeypatch.setattr(server, "_proxy_config_candidates", lambda: [cfg])
    monkeypatch.setattr(server, "_routing_cache", {"ts": 0, "data": None})
    status = server._routing_status()
    assert status["upstream_socks5"]["password_set"] is True
    assert "password" not in status["upstream_socks5"]
    assert "never-export-this" not in server.json.dumps(status)


def test_config_cache_invalidates_when_file_changes(tmp_path, monkeypatch):
    cfg = tmp_path / "cached.toml"
    cfg.write_text('[server]\nport = 443\n')
    monkeypatch.setattr(server, "_proxy_config_candidates", lambda: [cfg])
    assert server._load_proxy_runtime_config()["port"] == 443
    cfg.write_text('[server]\nport = 8443\n')
    assert server._load_proxy_runtime_config()["port"] == 8443


def test_journal_shutdown_terminates_and_joins(monkeypatch):
    from unittest.mock import Mock
    proc = Mock()
    thread = Mock()
    monkeypatch.setattr(server, "_log_process", proc)
    monkeypatch.setattr(server, "_log_thread", thread)
    monkeypatch.setattr(server, "_log_thread_started", True)
    server.stop_log_thread()
    proc.terminate.assert_called_once()
    proc.wait.assert_called_once_with(timeout=2)
    thread.join.assert_called_once_with(timeout=3)
    assert not server._log_thread_started


def test_ws_ticket_endpoint_requires_auth(client):
    assert client.get("/api/ws-ticket").status_code == 401
    r = client.get("/api/ws-ticket", headers=_auth())
    assert r.status_code == 200
    assert server._ws_ticket_ok(r.json()["ticket"])


def test_ws_rejects_unauthenticated(client):
    # No Basic auth and no ticket → the handshake is closed before accept (Safari with neither
    # would see this; with a ticket it connects). TestClient raises when the server denies.
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/logs"):
            pass


def test_quoted_value_keeps_a_hash_and_a_semicolon(tmp_path, monkeypatch):
    # '#'/';' start a comment only OUTSIDE a quoted string — src/config.zig parses it that way,
    # so the proxy happily uses such a password while the dashboard used to truncate it at the
    # '#' (leaving an unbalanced '"s3cr'), pre-fill that into the Routing card and write the
    # mangled value back to config.toml on the next save.
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        '[upstream.socks5]\n'
        'host = "10.0.0.1"  # the egress box\n'
        'username = "u;1"\n'
        'password = "s3cr#t"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(server, "_proxy_config_candidates", lambda: [cfg])

    parsed = server._load_proxy_runtime_config()
    assert parsed["upstream_socks5_password"] == "s3cr#t"
    assert parsed["upstream_socks5_username"] == "u;1"
    # A genuine trailing comment is still stripped.
    assert parsed["upstream_socks5_host"] == "10.0.0.1"


def test_config_write_replaces_atomically_and_keeps_a_backup(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[access.users]\nuser1 = "aa"\n', encoding="utf-8")
    cfg.chmod(0o640)
    before_ino = cfg.stat().st_ino

    server._write_config_atomic(cfg, '[access.users]\nuser1 = "bb"\n')

    # Renamed into place, never truncated in place: a crash mid-write can then only leave the
    # old config, not a zero-length one whose user secrets exist nowhere else.
    assert cfg.stat().st_ino != before_ino
    assert cfg.read_text(encoding="utf-8") == '[access.users]\nuser1 = "bb"\n'
    assert (tmp_path / "config.toml.bak").read_text(encoding="utf-8") == '[access.users]\nuser1 = "aa"\n'
    assert not (tmp_path / "config.toml.tmp").exists()
    # Both files hold every user secret, so neither may end up at the umask's mode.
    assert cfg.stat().st_mode & 0o777 == 0o640
    assert (tmp_path / "config.toml.bak").stat().st_mode & 0o777 == 0o640


def test_config_mutator_uses_the_atomic_writer(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[general]\nuse_middle_proxy = false\n", encoding="utf-8")
    monkeypatch.setattr(server, "_proxy_config_candidates", lambda: [cfg])

    assert server._set_middle_proxy_enabled(True)
    assert "use_middle_proxy = true" in cfg.read_text(encoding="utf-8")
    # The .bak is what proves the mutator went through _write_config_atomic rather than the
    # truncating Path.write_text it used to call.
    assert (tmp_path / "config.toml.bak").read_text(encoding="utf-8") == (
        "[general]\nuse_middle_proxy = false\n"
    )


def test_logs_fanout_is_per_client_cursor():
    # Regression for the destructive-drain bug: two independent cursors over the same recent
    # ring must each see all entries (no stealing between concurrent /ws/logs viewers).
    server._recent_logs.clear()
    server._recent_base_seq = 0
    server._recent_logs.extend([{"m": "a"}, {"m": "b"}])
    a, cur_a = server._logs_since(0)
    b, cur_b = server._logs_since(0)
    assert a == b == [{"m": "a"}, {"m": "b"}]
    assert cur_a == cur_b == 2
    # A later append is visible to a client resuming from its cursor.
    server._recent_logs.append({"m": "c"})
    more, cur_a = server._logs_since(cur_a)
    assert more == [{"m": "c"}] and cur_a == 3


@pytest.mark.parametrize("content, line, hint", [
    ('[server]\n  public_ip = tg.domain.ru\n', 2, "quotes"),
    ('[server]\nport = 443\n[server]\n', 3, "section"),
    ('[server]\nport = 443\nport = 8443\n', 3, "key"),
    ('[upstream.socks5]\npassword = "private-secret\n', 2, "string"),
    ('[upstream.socks5]\npassword = "private-secret', 2, "string"),
    ('[server]\nport = 443\nport = 8443', 3, "key"),
])
def test_config_error_has_location_and_action_without_secret(tmp_path, monkeypatch, content, line, hint):
    cfg = tmp_path / "broken.toml"
    cfg.write_text(content)
    monkeypatch.setattr(server, "_proxy_config_candidates", lambda: [cfg])
    error = server._load_proxy_runtime_config()["error"]
    assert f"line {line}" in error
    assert hint in error.lower()
    assert "private-secret" not in error
    assert "mtbuddy config doctor" in error


def test_stats_keep_system_data_and_disable_config_panels_until_repaired(client, tmp_path, monkeypatch):
    cfg = tmp_path / "repair.toml"
    cfg.write_text('[server]\npublic_ip = tg.domain.ru\n')
    monkeypatch.setattr(server, "_proxy_config_candidates", lambda: [cfg])
    monkeypatch.setattr(server, "_proxy_stats", lambda: {"active": 7})
    # These operations depend on a valid config and must not probe defaults on failure.
    def unexpected():
        pytest.fail("config-dependent panel was evaluated for a broken config")
    with monkeypatch.context() as blocked:
        for name in ("_routing_status", "_masking_status", "_users_status", "_awg_status"):
            blocked.setattr(server, name, unexpected)
        response = client.get("/api/stats", headers=_auth())
        assert response.status_code == 200
        data = response.json()
        assert data["config_error"] and data["errors"]
        assert data["proxy"]["active"] == 7
        assert isinstance(data["cpu"], (float, int))
        assert data["mem_total"] > 0
        assert data["users"] is None and data["routing"] is None and data["masking"] is None
    cfg.write_text('[server]\npublic_ip = "tg.domain.ru"\n')
    assert server._load_proxy_runtime_config().get("error") is None
    response = client.get("/api/stats", headers=_auth())
    assert response.json()["config_error"] is None
    assert response.json()["users"] is not None


def test_bad_config_rejects_user_mutation_without_writing_or_restarting(client, tmp_path, monkeypatch):
    cfg = tmp_path / "broken.toml"
    content = '[server]\npublic_ip = tg.domain.ru\n[access.users]\n'
    cfg.write_text(content)
    monkeypatch.setattr(server, "_proxy_config_candidates", lambda: [cfg])
    monkeypatch.setattr(server, "_find_config_path", lambda: cfg)
    def unexpected_restart():
        raise AssertionError("broken configuration must not be restarted")
    monkeypatch.setattr(server, "_restart_proxy", unexpected_restart)
    response = client.post("/api/users/add", headers={**_auth(), "Origin": "http://localhost"}, json={"name": "alice"})
    assert response.status_code == 503
    assert "line 2" in response.json()["error"]
    assert cfg.read_text() == content


def test_config_error_does_not_guess_listener_port(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(server.psutil, "process_iter", lambda fields: [SimpleNamespace(info={
        "name": "mtproto-proxy", "create_time": server.time.time() - 60,
        "pid": 42, "memory_info": None, "cmdline": ["mtproto-proxy"],
    })])
    monkeypatch.setattr(server, "_load_proxy_runtime_config", lambda: {"error": "invalid config"})
    def unexpected_probe(port):
        raise AssertionError("must not guess a port from defaults")
    monkeypatch.setattr(server, "_proxy_listening", unexpected_probe)
    info = server._proxy_info()
    assert info["online"] and info["pid"] == 42
    assert info["listening"] is None and info["state"] == "unknown"


@pytest.fixture
def traffic_probe(tmp_path, monkeypatch):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import threading
    from types import SimpleNamespace
    from traffic import TrafficHistory
    state = SimpleNamespace(tx=100, requests=0, status=200, payload=None)
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state.requests += 1
            self.send_response(state.status)
            if state.status == 302:
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/redirected")
            self.end_headers()
            body = state.payload or (f'mtproto_start_time_seconds 123\n'
                f'mtproto_user_client_to_upstream_bytes_total{{user="alice"}} {state.tx}\n'
                'mtproto_user_upstream_to_client_bytes_total{user="alice"} 0\n').encode()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        def log_message(self, *args):
            pass
    http = HTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=http.serve_forever, daemon=True)
    worker.start()
    state.cfg = tmp_path / "config.toml"
    state.database = tmp_path / "history.db"
    def configure(enabled=True):
        state.cfg.write_text(f'[monitor]\ntraffic_history_enabled = {str(enabled).lower()}\n'
            f'[metrics]\nenabled = true\nport = {http.server_port}\n'
            '[access.users]\nalice = "0123456789abcdef0123456789abcdef"\n')
    state.configure = configure
    configure()
    monkeypatch.setattr(server, "_find_config_path", lambda: state.cfg)
    monkeypatch.setattr(server, "_proxy_config_candidates", lambda: [state.cfg])
    monkeypatch.setattr(server, "TrafficHistory", lambda _: TrafficHistory(state.database))
    monkeypatch.setattr(server, "_traffic_snapshot", {})
    yield state
    http.shutdown()
    http.server_close()
    worker.join()


def test_traffic_http_never_creates_tls_contexts(traffic_probe, monkeypatch):
    import ssl
    server._traffic_http_opener.cache_clear()
    def unexpected_context(*args, **kwargs):
        raise AssertionError("HTTP metrics must not allocate TLS certificate stores")
    monkeypatch.setattr(ssl, "_create_default_https_context", unexpected_context)
    for _ in range(3):
        server._traffic_sample()
        assert server._traffic_snapshot["available"]
    assert traffic_probe.requests == 3


def test_disabled_history_does_not_scrape_or_create_database(traffic_probe):
    traffic_probe.configure(False)
    server._traffic_sample()
    assert server._traffic_snapshot == {"available": False, "error": "history_disabled", "items": {}}
    assert traffic_probe.requests == 0
    assert not traffic_probe.database.exists()
    assert server.tomllib.loads(traffic_probe.cfg.read_text())["metrics"]["enabled"] is True


def test_history_pause_keeps_database_and_excludes_paused_bytes(traffic_probe):
    server._traffic_sample()
    traffic_probe.tx = 150
    server._traffic_sample()
    assert server._traffic_snapshot["items"]["alice"]["totals"]["30"] == 50
    before = traffic_probe.database.read_bytes()
    traffic_probe.configure(False)
    server._traffic_sample()
    assert traffic_probe.database.read_bytes() == before
    assert traffic_probe.requests == 2
    traffic_probe.tx = 1000
    traffic_probe.configure(True)
    server._traffic_sample()
    assert server._traffic_snapshot["items"]["alice"]["totals"]["30"] == 50
    traffic_probe.tx = 1025
    server._traffic_sample()
    assert server._traffic_snapshot["items"]["alice"]["totals"]["30"] == 75


def test_traffic_http_rejects_redirects(traffic_probe):
    traffic_probe.status = 302
    server._traffic_sample()
    assert server._traffic_snapshot["error"] == "metrics_unavailable"
    assert traffic_probe.requests == 1
    assert not traffic_probe.database.exists()


@pytest.mark.parametrize("value", ['"false"', '0', '[]'])
def test_invalid_history_flag_does_not_silently_enable_collection(traffic_probe, value):
    traffic_probe.cfg.write_text(traffic_probe.cfg.read_text().replace('traffic_history_enabled = true', f'traffic_history_enabled = {value}'))
    server._traffic_sample()
    assert server._traffic_snapshot["error"] == "history_config_invalid"
    assert traffic_probe.requests == 0
    assert not traffic_probe.database.exists()


def test_traffic_scrape_ignores_environment_proxies(traffic_probe, monkeypatch):
    for name in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:1")
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setenv("NO_PROXY", "")
    server._traffic_sample()
    assert server._traffic_snapshot["available"]
    assert traffic_probe.requests == 1


def test_traffic_scrape_keeps_response_size_limit(traffic_probe):
    traffic_probe.payload = b"x" * (4 * 1024 * 1024 + 1)
    server._traffic_sample()
    assert server._traffic_snapshot["error"] == "metrics_unavailable"
    assert not traffic_probe.database.exists()
