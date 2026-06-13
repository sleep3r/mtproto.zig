"""Security-regression tests for the dashboard API (server.py).

The dashboard is a root control plane reachable over the network, so its auth / Host-pin /
CSRF gates are the highest-value thing to keep covered. Run with:

    pip install fastapi httpx psutil pytest
    pytest src/ctl/dashboard_assets/test_server.py

The suite skips itself if the runtime deps aren't installed (e.g. minimal CI image).
"""

import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("psutil")

from fastapi.testclient import TestClient  # noqa: E402

import server  # noqa: E402

TOKEN = server.DASHBOARD_TOKEN


def _auth(token=TOKEN):
    return {"Authorization": "Basic " + base64.b64encode(f"x:{token}".encode()).decode()}


@pytest.fixture(scope="module", autouse=True)
def _cleanup_token():
    yield
    # Importing server.py creates a dashboard.token in the assets dir; remove it.
    try:
        server._DASHBOARD_TOKEN_FILE.unlink()
    except OSError:
        pass


@pytest.fixture
def client():
    # base_url host=localhost so the loopback Host-pin passes; tests set Origin/auth per case.
    return TestClient(server.app, base_url="http://localhost")


def test_unauthenticated_api_rejected(client):
    assert client.get("/api/stats").status_code == 401


def test_authenticated_api_ok(client):
    assert client.get("/api/stats", headers=_auth()).status_code == 200


def test_wrong_token_rejected(client):
    assert client.get("/api/stats", headers=_auth("not-the-token")).status_code == 401


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
