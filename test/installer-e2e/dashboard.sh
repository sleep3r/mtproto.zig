#!/usr/bin/env bash
# Runs inside the disposable systemd container, using the mtbuddy under test.
set -Eeuo pipefail

check_dashboard() {
  systemctl is-active --quiet mtproto-proxy
  systemctl is-enabled --quiet proxy-monitor
  /opt/mtproto-proxy/monitor/.venv/bin/python - <<'PY'
import base64
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
base = "http://127.0.0.1:61208"
for attempt in range(40):
    try:
        token = Path("/opt/mtproto-proxy/monitor/dashboard.token").read_text().strip()
        auth = "Basic " + base64.b64encode(("test:" + token).encode()).decode()
        try:
            opener.open(base + "/api/stats", timeout=10)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401, exc.code
        else:
            raise AssertionError("dashboard API does not require authentication")
        def get(path):
            request = urllib.request.Request(base + path, headers={"Authorization": auth})
            with opener.open(request, timeout=10) as response:
                assert response.status == 200
                return response.read()
        stats = json.loads(get("/api/stats"))
        assert "users" in stats and "traffic" in stats
        for path in ("/", "/app.js", "/style.css"):
            assert len(get(path)) > 100
        break
    except (OSError, ValueError):
        if attempt == 39:
            raise
        time.sleep(1)
print("dashboard service, authenticated API and static assets: OK")
PY
  systemctl is-active --quiet proxy-monitor
}

if [[ "${1:-}" == check ]]; then
  check_dashboard
  exit
fi

config_before="$(sha256sum /opt/mtproto-proxy/config.toml | cut -d " " -f1)"
test ! -e /opt/mtproto-proxy/monitor/bin/uv
mtbuddy setup dashboard
check_dashboard
uv_before="$(stat -c '%i:%Y' /opt/mtproto-proxy/monitor/bin/uv)"
token_before="$(sha256sum /opt/mtproto-proxy/monitor/dashboard.token | cut -d " " -f1)"

# Exercise real SQLite persistence through the installed module, not a mock.
/opt/mtproto-proxy/monitor/.venv/bin/python - <<'PY'
import sys
import time
sys.path.insert(0, "/opt/mtproto-proxy/monitor")
from traffic import TrafficHistory
history = TrafficHistory("/opt/mtproto-proxy/monitor/traffic.sqlite3")
now = int(time.time())
history.record(now - 30, "installer-test", {"installer-test": (0, 0)})
history.record(now, "installer-test", {"installer-test": (100, 50)})
assert history.totals(now, 30)["installer-test"] == 150
PY

mtbuddy setup dashboard
check_dashboard
test "$(stat -c '%i:%Y' /opt/mtproto-proxy/monitor/bin/uv)" = "$uv_before"
test "$(sha256sum /opt/mtproto-proxy/monitor/dashboard.token | cut -d " " -f1)" = "$token_before"
/opt/mtproto-proxy/monitor/.venv/bin/python - <<'PY'
import sqlite3
with sqlite3.connect("/opt/mtproto-proxy/monitor/traffic.sqlite3") as db:
    assert db.execute("SELECT SUM(bytes) FROM buckets WHERE identity = ?", ("installer-test",)).fetchone()[0] == 150
PY

mtbuddy setup dashboard --remove
test ! -e /opt/mtproto-proxy/monitor
test ! -e /etc/systemd/system/proxy-monitor.service
if systemctl is-active --quiet proxy-monitor; then
  echo "dashboard still running after removal" >&2
  exit 1
fi
systemctl is-active --quiet mtproto-proxy
mtbuddy setup dashboard
check_dashboard
test "$(sha256sum /opt/mtproto-proxy/config.toml | cut -d " " -f1)" = "$config_before"
echo "dashboard fresh install, redeploy, removal and reinstall: OK"
