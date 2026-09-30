"""Run the installed WEB health script against HTTP fixtures, without systemd."""
import http.server
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]


class StatusHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(int(self.path.rsplit("/", 1)[1]))
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args):
        pass


class WebHealthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / "src/ctl/recovery.zig").read_text()
        literal = source.split("const WEB_HEALTH_SCRIPT =\n", 1)[1].split("\n;", 1)[0]
        cls.script = "\n".join(line.strip()[2:] for line in literal.splitlines()) + "\n"
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), StatusHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def run_health(self, config='', local=200, public=200, local_error=0, public_error=0):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_file = root / "config.toml"
            config_file.write_text('[web]\nenabled = true\ndomain = "example.test"\n' + config)
            log = root / "calls"
            log.touch()

            def executable(name, body):
                path = root / name
                path.write_text("#!/bin/bash\nset -eu\n" + body + "\n")
                path.chmod(0o755)

            # Use the Debian/Ubuntu awk implementation on macOS when available.
            if shutil.which("mawk"):
                (root / "awk").symlink_to(shutil.which("mawk"))
            executable("systemctl", 'echo "systemctl $*" >> "$CALL_LOG"')
            executable("logger", 'echo "logger $*" >> "$CALL_LOG"')
            executable("sleep", ":")
            # Preserve curl's options and exit semantics; redirect just the destination
            # to a real local HTTP server. TLS/network failures are injected separately.
            executable("curl", '''args=("$@")
last=$((${#args[@]} - 1))
url=${args[$last]}
echo "curl $url" >> "$CALL_LOG"
case "$url" in
  http://*) code=$LOCAL_STATUS; error=$LOCAL_ERROR ;;
  https://*) code=$PUBLIC_STATUS; error=$PUBLIC_ERROR ;;
  *) exit 99 ;;
esac
[[ "$error" == 0 ]] || exit "$error"
args[$last]="$FIXTURE_URL/$code"
exec "$REAL_CURL" "${args[@]}"''')
            env = dict(os.environ, PATH=tmp + os.pathsep + os.environ["PATH"],
                       CALL_LOG=str(log), REAL_CURL=shutil.which("curl"),
                       FIXTURE_URL=f"http://127.0.0.1:{self.server.server_port}",
                       LOCAL_STATUS=str(local), PUBLIC_STATUS=str(public),
                       LOCAL_ERROR=str(local_error), PUBLIC_ERROR=str(public_error))
            script = self.script.replace("/opt/mtproto-proxy/config.toml", str(config_file))
            result = subprocess.run(["bash", "-c", script], env=env, capture_output=True,
                                    text=True, timeout=10)
            return result.returncode, log.read_text().splitlines(), result.stderr

    def assert_healthy(self, result, host="127.0.0.1", port=8081):
        status, calls, stderr = result
        self.assertEqual(status, 0, stderr + "\n" + "\n".join(calls))
        self.assertEqual([c for c in calls if c.startswith("curl ")],
                         [f"curl http://{host}:{port}/", "curl https://example.test/"])
        self.assertFalse(any(c.startswith("systemctl ") for c in calls))

    def test_documented_listen_key_and_legacy_host_alias(self):
        for key in ("listen", "host"):
            with self.subTest(key=key):
                self.assert_healthy(self.run_health(f'{key} = "172.17.0.1"\n'), "172.17.0.1")

    def test_aliases_follow_config_parser_last_assignment(self):
        for first, second in (("listen", "host"), ("host", "listen")):
            with self.subTest(last=second):
                config = f'{first} = "127.0.0.1"\n{second} = "172.17.0.1"\n'
                self.assert_healthy(self.run_health(config), "172.17.0.1")

    def test_default_wildcard_and_ipv6_addresses(self):
        self.assert_healthy(self.run_health())
        for bind, expected in (("0.0.0.0", "127.0.0.1"), ("::", "[::1]"),
                               ("::1", "[::1]"), ("2001:db8::1", "[2001:db8::1]")):
            with self.subTest(bind=bind):
                self.assert_healthy(self.run_health(f'listen = "{bind}"\nport = 8123\n'),
                                    expected, 8123)

    def test_local_http_status_does_not_restart_a_responsive_relay(self):
        for code in (200, 302, 403, 404, 500, 503):
            with self.subTest(code=code):
                self.assert_healthy(self.run_health(local=code))

    def test_public_404_is_expected_without_a_static_site(self):
        self.assert_healthy(self.run_health(local=404, public=404))

    def test_public_success_and_redirect_are_accepted(self):
        for code in (200, 204, 301, 302):
            with self.subTest(code=code):
                self.assert_healthy(self.run_health(public=code))

    def test_public_errors_report_failure_without_restarting_relay(self):
        for code, error in ((403, 0), (429, 0), (500, 0), (502, 0), (503, 0),
                            (200, 6), (200, 28), (200, 60)):
            with self.subTest(code=code, error=error):
                status, calls, _ = self.run_health(public=code, public_error=error)
                self.assertEqual(status, 1)
                self.assertFalse(any(c.startswith("systemctl ") for c in calls))
                self.assertTrue(any("public HTTPS path failed" in c for c in calls))

    def test_three_local_transport_failures_restart_only_relay(self):
        for error in (7, 18, 28, 52):
            with self.subTest(error=error):
                status, calls, _ = self.run_health(local_error=error)
                self.assertEqual(status, 1)
                self.assertEqual(calls.count("curl http://127.0.0.1:8081/"), 3)
                self.assertEqual([c for c in calls if c.startswith("systemctl ")],
                                 ["systemctl restart mtproto-web-relay.service"])
                self.assertFalse(any(c.startswith("curl https:") for c in calls))

    def test_disabled_web_does_not_probe_or_restart(self):
        status, calls, _ = self.run_health("enabled = false\n")
        self.assertEqual(status, 0)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
