import csv
import io
import tempfile
import unittest
from pathlib import Path

import pandas as pd
from fastapi.testclient import TestClient

from api.main import create_app
from src import analysis, database
from src.parser import EVENT_COLUMNS
from src.sessionizer import build_sessions


class TestThreatHunt(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "hunt.db"
        database.init_db(reset=True, db_path=self.db)
        events = pd.DataFrame([
            {"timestamp": "2026-01-01T00:00:01Z", "session": "session-a",
             "src_ip": "192.0.2.1", "eventid": "cowrie.login.failed", "username": "root"},
            {"timestamp": "2026-01-01T00:00:02Z", "session": "session-a",
             "src_ip": "192.0.2.1", "eventid": "cowrie.command.input",
             "username": "root", "command": "wget https://example.test/a"},
            {"timestamp": "2026-01-02T00:00:01Z", "session": "session-b",
             "src_ip": "192.0.2.1", "eventid": "cowrie.command.input", "command": "id"},
            {"timestamp": "2026-01-01T01:00:01Z", "session": "session-c",
             "src_ip": "198.51.100.2", "eventid": "cowrie.command.input", "username": "root",
             "command": "curl https://example.test/b"},
            {"timestamp": "2026-01-01T02:00:01Z", "session": "session-injection",
             "src_ip": "203.0.113.9", "eventid": "cowrie.command.input",
             "username": '=HYPERLINK("https://example.test")', "command": "=1+1"},
        ])
        events["timestamp"] = pd.to_datetime(events["timestamp"], utc=True)
        events = events.reindex(columns=EVENT_COLUMNS)
        database.load_events(events, db_path=self.db)
        database.load_sessions(build_sessions(events), db_path=self.db)
        analysis.save_table(
            "session_clusters",
            pd.DataFrame([
                {"session": "session-a", "behavior": "Command Activity"},
                {"session": "session-b", "behavior": "Command Activity"},
                {"session": "session-c", "behavior": "Other"},
                {"session": "session-injection", "behavior": "Command Activity"},
            ]),
            db_path=self.db,
        )
        self.client = TestClient(create_app(db_path=self.db))

    def tearDown(self):
        self.temp.cleanup()

    def test_combined_filters_require_all_criteria(self):
        response = self.client.get("/api/threat-hunt", params={
            "src_ip": "192.0.2.1", "username": "ROOT", "command": "WGET",
            "event_type": "cowrie.command.input", "risk_level": "Low",
            "start": "2026-01-01", "end": "2026-01-01",
            "behavior": "Command Activity",
        })
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["total"], 1)
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["items"][0]["command"], "wget https://example.test/a")
        self.assertEqual(result["items"][0]["risk_level"], "Low")
        self.assertIsNotNone(result["items"][0]["risk_score"])

    def test_date_boundaries_are_inclusive(self):
        response = self.client.get("/api/threat-hunt", params={
            "src_ip": "192.0.2.1", "start": "2026-01-01", "end": "2026-01-01",
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["total"], 2)
        self.assertTrue(all(item["timestamp"].startswith("2026-01-01") for item in response.json()["items"]))

    def test_pagination_is_bounded_and_reports_total(self):
        first = self.client.get("/api/threat-hunt", params={"limit": 2, "offset": 0}).json()
        second = self.client.get("/api/threat-hunt", params={"limit": 2, "offset": 2}).json()
        self.assertEqual(first["total"], 5)
        self.assertEqual(len(first["items"]), 2)
        self.assertTrue(first["has_more"])
        self.assertEqual(len(second["items"]), 2)
        self.assertEqual(second["offset"], 2)
        self.assertEqual(self.client.get("/api/threat-hunt", params={"limit": 101}).status_code, 422)

    def test_csv_exports_matching_records_and_prevents_formula_injection(self):
        response = self.client.get("/api/threat-hunt/export", params={
            "src_ip": "203.0.113.9", "event_type": "cowrie.command.input",
            "start": "2026-01-01", "end": "2026-01-01", "behavior": "Command Activity",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.headers["content-type"])
        rows = list(csv.reader(io.StringIO(response.text)))
        self.assertEqual(rows[0], [
            "timestamp", "src_ip", "event_type", "session_id", "username",
            "command", "risk_score", "risk_level",
        ])
        self.assertEqual(len(rows), 2)
        self.assertTrue(rows[1][4].startswith("'="))
        self.assertTrue(rows[1][5].startswith("'="))

    def test_empty_invalid_and_missing_fields(self):
        empty = self.client.get("/api/threat-hunt", params={"username": "not-present"}).json()
        self.assertEqual(empty["items"], [])
        self.assertEqual(empty["total"], 0)
        self.assertFalse(empty["has_more"])
        self.assertEqual(
            self.client.get("/api/threat-hunt", params={"event_type": "unsupported.event"}).status_code,
            422,
        )
        self.assertEqual(
            self.client.get("/api/threat-hunt", params={"start": "not-a-date"}).status_code,
            422,
        )
        self.assertEqual(
            self.client.get("/api/threat-hunt", params={"risk_level": "Critical"}).status_code,
            422,
        )
        # Events lacking optional username or command remain searchable and serialize as null.
        rows = self.client.get("/api/threat-hunt", params={"src_ip": "192.0.2.1"}).json()["items"]
        self.assertIsNone(rows[0]["command"])


if __name__ == "__main__":
    unittest.main()
