"""Persistent minute buckets for user traffic; no secrets or proxy links on disk."""
import json
import re
import sqlite3
from contextlib import contextmanager

DAY = 86400


def parse_metrics(text):
    start = re.search(r"^mtproto_start_time_seconds (\d+)$", text, re.M)
    if not start:
        raise ValueError("Missing proxy start time")
    values = {}
    pattern = r'^mtproto_user_(client_to_upstream|upstream_to_client)_bytes_total\{user=("(?:[^"\\]|\\.)*")\} (\d+)$'
    for direction, label, value in re.findall(pattern, text, re.M):
        name = json.loads(label)
        values.setdefault(name, {})[direction] = int(value)
    if any(len(v) != 2 for v in values.values()):
        raise ValueError("Incomplete user counters")
    return start[1], {k: (v["client_to_upstream"], v["upstream_to_client"]) for k, v in values.items()}


class TrafficHistory:
    def __init__(self, path):
        self.path = str(path)
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS baseline (
                    identity TEXT PRIMARY KEY, process TEXT NOT NULL,
                    tx INTEGER NOT NULL, rx INTEGER NOT NULL, sampled INTEGER NOT NULL,
                    started INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS buckets (
                    identity TEXT NOT NULL, minute INTEGER NOT NULL, bytes INTEGER NOT NULL,
                    PRIMARY KEY(identity, minute));
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def record(self, now, process, counters):
        now = int(now)
        with self.connect() as db:
            for identity, (tx, rx) in counters.items():
                old = db.execute("SELECT process,tx,rx,sampled,started FROM baseline WHERE identity=?", (identity,)).fetchone()
                if old and now < old[3]:
                    continue  # clock moved backwards: do not count the same interval twice
                delta = 0
                # A long collection gap cannot be dated reliably. Do not assign
                # days of missed traffic to the current minute/window.
                if old and now - old[3] <= 300:
                    delta = sum(v if process != old[0] or v < before else v - before
                                for v, before in zip((tx, rx), old[1:3]))
                if delta:
                    db.execute("INSERT INTO buckets VALUES(?,?,?) ON CONFLICT(identity,minute) DO UPDATE SET bytes=bytes+excluded.bytes",
                               (identity, now // 60 * 60, delta))
                db.execute("INSERT OR REPLACE INTO baseline VALUES(?,?,?,?,?,?)",
                           (identity, process, tx, rx, now, old[4] if old else now))
            db.execute("DELETE FROM buckets WHERE minute < ?", (now - 30 * DAY - 60,))
            db.execute("DELETE FROM baseline WHERE sampled < ?", (now - 31 * DAY,))

    def totals(self, now, days):
        if days not in (7, 14, 30):
            raise ValueError("Unsupported traffic period")
        with self.connect() as db:
            return dict(db.execute("SELECT identity,SUM(bytes) FROM buckets WHERE minute >= ? AND minute <= ? GROUP BY identity",
                                   (int(now) - days * DAY, int(now))))

    def starts(self):
        with self.connect() as db:
            return dict(db.execute("SELECT identity,started FROM baseline"))
