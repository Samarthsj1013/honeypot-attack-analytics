"""Tests for clustering and risk scoring.
Run: python -m unittest discover -s tests"""
import unittest

import numpy as np
import pandas as pd

from src import clustering
from src.analysis import compute_ip_risk


def make_sessions() -> pd.DataFrame:
    """60+ synthetic sessions: 30 scanners, 30 bots, 20 humans."""
    rng = np.random.RandomState(0)
    rows = []

    def add(sid, ip, kind, failed, succ, cmds, uu, up, dur, gap, events, dl):
        rows.append({
            "session": sid, "src_ip": ip, "kind": kind,
            "n_events": events, "n_failed_logins": failed,
            "n_success_logins": succ, "n_commands": cmds,
            "n_unique_usernames": uu, "n_unique_passwords": up,
            "duration_sec": dur, "avg_gap_sec": gap,
            "login_success": int(succ > 0), "has_download_cmd": dl,
        })

    for i in range(30):
        d = rng.uniform(0.1, 3)
        add(f"s{i}", f"10.0.0.{i}", "scanner", 0, 0, 0, 0, 0, d, d, 2, 0)
    for i in range(30):
        f = int(rng.randint(3, 16))
        add(f"b{i}", f"20.0.0.{i}", "bot", f, 0, 0, min(f, 8), min(f, 8),
            rng.uniform(3, 30), rng.uniform(0.2, 2), f + 2, 0)
    for i in range(20):
        c = int(rng.randint(3, 9))
        add(f"h{i}", f"30.0.0.{i}", "human", int(rng.randint(1, 4)), 1, c, 2, 2,
            rng.uniform(40, 300), rng.uniform(5, 60), c + 5, 1)
    return pd.DataFrame(rows)


class TestClustering(unittest.TestCase):
    def test_clusters_separate_behaviors(self):
        sessions = make_sessions()
        assignments, info = clustering.cluster_sessions(sessions, n_clusters=3)

        self.assertEqual(set(assignments["behavior"]),
                         {clustering.HUMAN, clustering.BOT, clustering.SCANNER})
        self.assertGreater(info["silhouette"], 0)

        expected = {"scanner": clustering.SCANNER, "bot": clustering.BOT,
                    "human": clustering.HUMAN}
        merged = sessions.merge(assignments[["session", "behavior"]], on="session")
        for kind, label in expected.items():
            group = merged[merged["kind"] == kind]
            share = (group["behavior"] == label).mean()
            self.assertGreaterEqual(share, 0.9, f"{kind} sessions mislabeled")

    def test_risk_scores(self):
        sessions = make_sessions()
        # Make one IP clearly dangerous: many sessions, failures, success, download
        heavy = sessions[sessions["kind"] == "human"].head(1).copy()
        heavy = pd.concat([heavy] * 5, ignore_index=True)
        heavy["src_ip"] = "99.9.9.9"
        heavy["n_failed_logins"] = 40
        risk = compute_ip_risk(pd.concat([sessions, heavy], ignore_index=True))

        top = risk.iloc[0]
        self.assertEqual(top["src_ip"], "99.9.9.9")
        self.assertEqual(top["risk_level"], "High")

        scanner = risk[risk["src_ip"] == "10.0.0.0"].iloc[0]
        self.assertEqual(scanner["risk_level"], "Low")

    def test_too_few_sessions_raises(self):
        tiny = make_sessions().head(2)
        with self.assertRaises(ValueError):
            clustering.cluster_sessions(tiny, n_clusters=3)


if __name__ == "__main__":
    unittest.main()