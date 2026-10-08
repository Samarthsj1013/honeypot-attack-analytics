"""Tests for clustering and risk scoring.
Run: python -m unittest discover -s tests
"""

import unittest

import numpy as np
import pandas as pd

from src import clustering
from src.analysis import compute_ip_risk


def make_sessions() -> pd.DataFrame:
    """60+ synthetic sessions: 30 scanners, 30 bots, 20 humans."""
    rng = np.random.RandomState(0)
    rows = []

    def add(
        sid,
        ip,
        kind,
        failed,
        succ,
        cmds,
        uu,
        up,
        dur,
        gap,
        events,
        dl,
    ):
        rows.append(
            {
                "session": sid,
                "src_ip": ip,
                "kind": kind,
                "n_events": events,
                "n_failed_logins": failed,
                "n_success_logins": succ,
                "n_commands": cmds,
                "n_unique_usernames": uu,
                "n_unique_passwords": up,
                "duration_sec": dur,
                "avg_gap_sec": gap,
                "login_success": int(succ > 0),
                "has_download_cmd": dl,
            }
        )

    for i in range(30):
        d = rng.uniform(0.1, 3)
        add(
            f"s{i}",
            f"10.0.0.{i}",
            "scanner",
            0,
            0,
            0,
            0,
            0,
            d,
            d,
            2,
            0,
        )

    for i in range(30):
        f = int(rng.randint(3, 16))
        add(
            f"b{i}",
            f"20.0.0.{i}",
            "bot",
            f,
            0,
            0,
            min(f, 8),
            min(f, 8),
            rng.uniform(3, 30),
            rng.uniform(0.2, 2),
            f + 2,
            0,
        )

    for i in range(20):
        c = int(rng.randint(3, 9))
        add(
            f"h{i}",
            f"30.0.0.{i}",
            "human",
            int(rng.randint(1, 4)),
            1,
            c,
            2,
            2,
            rng.uniform(40, 300),
            rng.uniform(5, 60),
            c + 5,
            1,
        )

    return pd.DataFrame(rows)


class TestClustering(unittest.TestCase):
    def test_clusters_separate_behaviors(self):
        sessions = make_sessions()
        assignments, info = clustering.cluster_sessions(
            sessions,
            n_clusters=3,
        )

        self.assertEqual(
            set(assignments["behavior"]),
            {
                clustering.HUMAN,
                clustering.BOT,
                clustering.SCANNER,
            },
        )
        self.assertGreater(info["silhouette"], 0)

        expected = {
            "scanner": clustering.SCANNER,
            "bot": clustering.BOT,
            "human": clustering.HUMAN,
        }

        merged = sessions.merge(
            assignments[["session", "behavior"]],
            on="session",
        )

        for kind, label in expected.items():
            group = merged[merged["kind"] == kind]
            share = (group["behavior"] == label).mean()
            self.assertGreaterEqual(
                share,
                0.9,
                f"{kind} sessions mislabeled",
            )

    def test_risk_scores(self):
        sessions = make_sessions()

        # Make one IP clearly dangerous:
        # many sessions, failures, success, and download activity.
        heavy = sessions[sessions["kind"] == "human"].head(1).copy()
        heavy = pd.concat([heavy] * 5, ignore_index=True)
        heavy["src_ip"] = "99.9.9.9"
        heavy["n_failed_logins"] = 40

        risk = compute_ip_risk(
            pd.concat([sessions, heavy], ignore_index=True)
        )

        top = risk.iloc[0]
        self.assertEqual(top["src_ip"], "99.9.9.9")
        self.assertEqual(top["risk_level"], "High")

        scanner = risk[risk["src_ip"] == "10.0.0.0"].iloc[0]
        self.assertEqual(scanner["risk_level"], "Low")

    def test_too_few_sessions_raises(self):
        tiny = make_sessions().head(2)

        with self.assertRaises(ValueError):
            clustering.cluster_sessions(
                tiny,
                n_clusters=3,
            )

    def test_risk_failed_login_points_and_cap(self):
        base = make_sessions().head(1).copy()
        base["src_ip"] = "192.0.2.10"
        base["login_success"] = 0
        base["n_commands"] = 0
        base["has_download_cmd"] = 0

        cases = [
            (0, 1.0),
            (100, 11.0),
            (500, 31.0),
            (1000, 31.0),
        ]

        for failed_logins, expected in cases:
            data = base.copy()
            data["n_failed_logins"] = failed_logins

            risk = compute_ip_risk(data).iloc[0]

            self.assertAlmostEqual(
                risk["risk_score"],
                expected,
                msg=(
                    "Unexpected score for "
                    f"{failed_logins} failed logins"
                ),
            )

    def test_risk_persistence_points_and_cap(self):
        base = make_sessions().head(1).copy()
        base["src_ip"] = "192.0.2.20"
        base["n_failed_logins"] = 0
        base["login_success"] = 0
        base["n_commands"] = 0
        base["has_download_cmd"] = 0

        twenty = pd.concat([base] * 20, ignore_index=True)
        twenty["session"] = [f"p{i}" for i in range(20)]

        risk = compute_ip_risk(twenty).iloc[0]
        self.assertEqual(risk["sessions"], 20)
        self.assertAlmostEqual(risk["risk_score"], 20.0)

        twenty_one = pd.concat([base] * 21, ignore_index=True)
        twenty_one["session"] = [f"p{i}" for i in range(21)]

        risk = compute_ip_risk(twenty_one).iloc[0]
        self.assertEqual(risk["sessions"], 21)
        self.assertAlmostEqual(risk["risk_score"], 20.0)

    def test_risk_successful_login_adds_25_points(self):
        data = make_sessions().head(1).copy()
        data["src_ip"] = "192.0.2.30"
        data["n_failed_logins"] = 0
        data["login_success"] = 1
        data["n_commands"] = 0
        data["has_download_cmd"] = 0

        risk = compute_ip_risk(data).iloc[0]

        # 1 persistence + 25 successful-login points.
        self.assertAlmostEqual(risk["risk_score"], 26.0)

    def test_risk_regular_command_adds_10_points(self):
        data = make_sessions().head(1).copy()
        data["src_ip"] = "192.0.2.40"
        data["n_failed_logins"] = 0
        data["login_success"] = 0
        data["n_commands"] = 1
        data["has_download_cmd"] = 0

        risk = compute_ip_risk(data).iloc[0]

        # 1 persistence + 10 regular-command points.
        self.assertAlmostEqual(risk["risk_score"], 11.0)

    def test_risk_download_command_adds_25_points(self):
        data = make_sessions().head(1).copy()
        data["src_ip"] = "192.0.2.50"
        data["n_failed_logins"] = 0
        data["login_success"] = 0
        data["n_commands"] = 1
        data["has_download_cmd"] = 1

        risk = compute_ip_risk(data).iloc[0]

        # 1 persistence + 25 download-command points.
        self.assertAlmostEqual(risk["risk_score"], 26.0)

    def test_risk_level_boundary_at_30(self):
        data = make_sessions().head(1).copy()
        data["src_ip"] = "192.0.2.60"
        data["n_failed_logins"] = 40
        data["login_success"] = 1
        data["n_commands"] = 0
        data["has_download_cmd"] = 0

        risk = compute_ip_risk(data).iloc[0]

        # 1 persistence + 4 failed-login points + 25 success = 30.
        self.assertAlmostEqual(risk["risk_score"], 30.0)
        self.assertEqual(risk["risk_level"], "Medium")

        below = data.copy()
        below["n_failed_logins"] = 39

        risk = compute_ip_risk(below).iloc[0]

        self.assertAlmostEqual(risk["risk_score"], 29.9)
        self.assertEqual(risk["risk_level"], "Low")

    def test_risk_level_boundary_at_60(self):
        rows = []
        base = make_sessions().head(1).copy()

        for i in range(20):
            row = base.copy()
            row["session"] = f"h{i}"
            row["src_ip"] = "192.0.2.71"
            row["n_failed_logins"] = 7 if i < 10 else 8
            row["login_success"] = 1
            row["n_commands"] = 0
            row["has_download_cmd"] = 0
            rows.append(row)

        data = pd.concat(rows, ignore_index=True)
        risk = compute_ip_risk(data).iloc[0]

        # 20 persistence + 15 failed-login + 25 success = 60.
        self.assertEqual(risk["sessions"], 20)
        self.assertEqual(risk["failed_logins"], 150)
        self.assertAlmostEqual(risk["risk_score"], 60.0)
        self.assertEqual(risk["risk_level"], "High")

        below = data.copy()
        below.loc[below.index[0], "n_failed_logins"] -= 1

        risk = compute_ip_risk(below).iloc[0]

        self.assertEqual(risk["failed_logins"], 149)
        self.assertAlmostEqual(risk["risk_score"], 59.9)
        self.assertEqual(risk["risk_level"], "Medium")

    def test_risk_score_is_capped_at_100(self):
        rows = []
        base = make_sessions().head(1).copy()

        for i in range(20):
            row = base.copy()
            row["session"] = f"c{i}"
            row["src_ip"] = "192.0.2.80"
            row["n_failed_logins"] = 50
            row["login_success"] = 1
            row["n_commands"] = 1
            row["has_download_cmd"] = 1
            rows.append(row)

        data = pd.concat(rows, ignore_index=True)
        risk = compute_ip_risk(data).iloc[0]

        self.assertAlmostEqual(risk["risk_score"], 100.0)
        self.assertEqual(risk["risk_level"], "High")


if __name__ == "__main__":
    unittest.main()
