import unittest

import pandas as pd

from src.similarity import WEIGHTS, compare_attackers


def session(ip, failed=0, success=0, commands=0, behavior="Login Activity"):
    return {
        "src_ip": ip, "n_failed_logins": failed, "login_success": success > 0,
        "n_success_logins": success, "n_commands": commands, "has_download_cmd": commands > 0,
        "n_events": failed + success + commands + 2, "duration_sec": 30.0,
        "avg_gap_sec": 3.0, "behavior": behavior,
    }


def event(ip, eventid, username=None, command=None, session_id=None, timestamp="2026-01-01T10:00:00Z"):
    return {"src_ip": ip, "session": session_id or f"s-{ip}", "eventid": eventid,
            "username": username, "command": command, "timestamp": timestamp}


class TestBehavioralSimilarity(unittest.TestCase):
    def setUp(self):
        self.sessions = pd.DataFrame([
            session("192.0.2.1", failed=4, success=1, commands=2),
            session("198.51.100.2", failed=3, success=1, commands=2),
            session("203.0.113.3", behavior="Unclustered"),
        ])
        self.events = pd.DataFrame([
            event("192.0.2.1", "cowrie.login.failed", "root", session_id="s-a"),
            event("192.0.2.1", "cowrie.login.failed", "admin", session_id="s-a"),
            event("192.0.2.1", "cowrie.login.success", "root", session_id="s-a"),
            event("192.0.2.1", "cowrie.command.input", command="curl https://example.test/x", session_id="s-a"),
            event("192.0.2.1", "cowrie.command.input", command="uname -a", session_id="s-a"),
            event("198.51.100.2", "cowrie.login.failed", "root", session_id="s-b"),
            event("198.51.100.2", "cowrie.login.failed", "root", session_id="s-b"),
            event("198.51.100.2", "cowrie.login.success", "root", session_id="s-b"),
            event("198.51.100.2", "cowrie.command.input", command="curl https://example.test/x", session_id="s-b"),
            event("198.51.100.2", "cowrie.command.input", command="uname -a", session_id="s-b"),
        ])
        self.risk = {
            "192.0.2.1": {"risk_score": 70, "risk_level": "High"},
            "198.51.100.2": {"risk_score": 40, "risk_level": "Medium"},
            "203.0.113.3": {"risk_score": 0, "risk_level": "Low"},
        }

    def test_component_weights_scores_and_shared_evidence(self):
        self.assertEqual(sum(WEIGHTS.values()), 100)
        first = compare_attackers("192.0.2.1", self.sessions, self.events, self.risk, limit=10)
        result = next(item for item in first if item["src_ip"] == "198.51.100.2")
        self.assertEqual(result["compared_src_ip"], "192.0.2.1")
        self.assertEqual(result["risk_level"], "Medium")
        self.assertIn("commands", result["components"])
        self.assertIn("authentication", result["components"])
        self.assertIn("mitre", result["components"])
        self.assertEqual(result["components"]["commands"]["score"], 100.0)
        command_evidence = result["components"]["commands"]["evidence"]
        self.assertEqual(command_evidence["shared_count"], 2)
        self.assertEqual(command_evidence["selected_unique_count"], 2)
        self.assertEqual(command_evidence["shared_examples"], ["curl https://example.test/x", "uname -a"])
        download_evidence = result["components"]["downloads"]["evidence"]
        self.assertEqual(download_evidence["shared_tools"], ["curl"])
        self.assertEqual(download_evidence["selected_examples"], ["curl https://example.test/x"])
        self.assertEqual(download_evidence["candidate_examples"], ["curl https://example.test/x"])
        auth_evidence = result["components"]["authentication"]["evidence"]
        self.assertEqual(auth_evidence["shared_usernames"], ["root"])
        self.assertEqual(auth_evidence["selected_failed_login_events"], 2)
        self.assertEqual(auth_evidence["candidate_successful_login_events"], 1)
        self.assertIn("T1059.004", result["components"]["mitre"]["evidence"]["shared_techniques"])
        self.assertAlmostEqual(sum(result["effective_weights_pct"].values()), 100.0)
        weighted = sum(
            component["score"] * component["weight"]
            for component in result["components"].values()
        ) / sum(component["weight"] for component in result["components"].values())
        self.assertAlmostEqual(result["similarity_pct"], weighted, places=1)
        self.assertEqual(result["comparison"]["shared_commands"], ["curl https://example.test/x", "uname -a"])
        self.assertIn("T1059.004", result["comparison"]["shared_techniques"])
        self.assertTrue(result["reasons"])

    def test_repeated_events_do_not_inflate_command_overlap(self):
        baseline = compare_attackers("192.0.2.1", self.sessions, self.events, self.risk, limit=10)
        repeated = pd.concat([
            self.events,
            pd.DataFrame([event("198.51.100.2", "cowrie.command.input", command="curl https://example.test/x", session_id="s-b") for _ in range(40)]),
        ], ignore_index=True)
        after = compare_attackers("192.0.2.1", self.sessions, repeated, self.risk, limit=10)
        a = next(row for row in baseline if row["src_ip"] == "198.51.100.2")
        b = next(row for row in after if row["src_ip"] == "198.51.100.2")
        self.assertEqual(a["components"]["commands"]["score"], b["components"]["commands"]["score"])
        self.assertEqual(a["components"]["commands"]["evidence"]["shared_count"], b["components"]["commands"]["evidence"]["shared_count"])
        self.assertEqual(a["similarity_pct"], b["similarity_pct"])

    def test_missing_evidence_is_not_scored_as_high_similarity(self):
        quiet_sessions = pd.DataFrame([
            session("192.0.2.1", behavior="Unclustered"),
            session("198.51.100.2", behavior="Unclustered"),
        ])
        result = compare_attackers("192.0.2.1", quiet_sessions, pd.DataFrame(), self.risk, limit=5)[0]
        self.assertEqual(result["similarity_category"], "Insufficient Evidence")
        self.assertEqual(result["similarity_pct"], 0)
        self.assertEqual(set(result["components"]), {"sessions"})
        self.assertIn("behavioral_dna", result["comparison"]["missing_components"])

    def test_self_exclusion_determinism_and_ordering(self):
        first = compare_attackers("192.0.2.1", self.sessions, self.events, self.risk, limit=10)
        second = compare_attackers("192.0.2.1", self.sessions, self.events.sample(frac=1, random_state=9), self.risk, limit=10)
        self.assertEqual(first, second)
        self.assertNotIn("192.0.2.1", [row["src_ip"] for row in first])
        self.assertEqual(first, sorted(first, key=lambda row: (-row["similarity_pct"], row["src_ip"])))

    def test_unknown_source_returns_none(self):
        self.assertIsNone(compare_attackers("203.0.113.250", self.sessions, self.events, self.risk))


if __name__ == "__main__":
    unittest.main()
