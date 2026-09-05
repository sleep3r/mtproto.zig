import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from traffic import TrafficHistory, parse_metrics


def test_history_survives_restart_and_counts_resets(tmp_path):
    path = tmp_path / "traffic.sqlite3"
    h = TrafficHistory(path)
    h.record(100, "boot1", {"alice": (1000, 2000)})
    h.record(160, "boot1", {"alice": (1100, 2300)})
    h = TrafficHistory(path)
    h.record(220, "boot1", {"alice": (1150, 2400)})
    assert h.totals(220, 7)["alice"] == 550
    h.record(280, "boot2", {"alice": (10, 20)})
    assert h.totals(280, 7)["alice"] == 580
    h.record(280, "boot2", {"alice": (10, 20)})
    assert h.totals(280, 7)["alice"] == 580


def test_windows_and_new_id_do_not_inherit_history(tmp_path):
    h = TrafficHistory(tmp_path / "history.db")
    h.record(0, "boot", {"old": (0, 0)})
    h.record(60, "boot", {"old": (100, 0)})
    h.record(10 * 86400, "boot", {"old": (900, 0), "new": (900, 0)})
    h.record(10 * 86400 + 60, "boot", {"old": (950, 0), "new": (900, 0)})
    assert h.totals(10 * 86400 + 60, 7)["old"] == 50
    assert h.totals(10 * 86400 + 60, 14)["old"] == 150
    assert h.totals(10 * 86400 + 60, 30).get("new", 0) == 0


def test_clock_rollback_and_retention(tmp_path):
    h = TrafficHistory(tmp_path / "history.db")
    h.record(100, "boot", {"a": (100, 0)})
    h.record(160, "boot", {"a": (120, 0)})
    h.record(140, "boot", {"a": (120, 0)})
    h.record(220, "boot", {"a": (125, 0)})
    assert h.totals(220, 7)["a"] == 25
    h.record(32 * 86400, "boot", {})
    assert h.totals(32 * 86400, 30) == {}
    assert h.starts() == {}


def test_metrics_parser_requires_both_directions_and_process_id():
    raw = '''mtproto_start_time_seconds 123
mtproto_user_client_to_upstream_bytes_total{user="a\\\"b"} 10
mtproto_user_upstream_to_client_bytes_total{user="a\\\"b"} 20
'''
    assert parse_metrics(raw) == ("123", {'a"b': (10, 20)})
    import pytest
    with pytest.raises(ValueError):
        parse_metrics(raw.splitlines()[1])
