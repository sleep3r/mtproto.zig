"""Offline regressions for measurement harnesses (no target/network required)."""
import errno
import unittest
from unittest.mock import patch, MagicMock

import capacity_connections_probe as capacity
import connection_stability_check as stability


class ProbeHelpers(unittest.TestCase):
    def test_incomplete_proc_stats_are_not_success(self):
        self.assertFalse(stability.has_stats(stability.ProcStats(1, None, 1, 1)))

    def test_fd_exhaustion_stops_idle_load(self):
        with patch.object(stability.socket, "create_connection", side_effect=OSError(errno.EMFILE, "fds")) as connect:
            sockets, failed = stability.open_idle_connections("localhost", 1, 10000, 1)
        self.assertEqual(sockets, [])
        self.assertEqual(connect.call_count, 1)
        self.assertGreater(failed, 0)

    def test_churn_gets_fresh_authenticated_payload(self):
        sock = MagicMock()
        sock.recv.return_value = b"\x16\x03\x03"
        sock.__enter__.return_value = sock
        factory = MagicMock(side_effect=[b"first", b"second"])
        with patch.object(stability.socket, "create_connection", return_value=sock):
            ok, fail, _ = stability.run_churn("localhost", 1, 2, 1, 1, factory)
        self.assertEqual((ok, fail), (2, 0))
        self.assertEqual(factory.call_count, 2)

    def test_tls_template_is_cached(self):
        capacity.build_realistic_client_hello.cache_clear()
        first = capacity.build_realistic_client_hello("example.com")
        self.assertIs(first, capacity.build_realistic_client_hello("example.com"))


if __name__ == "__main__":
    unittest.main()
