import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from api.main import create_app
from src import database


class TestAttackGraphAPI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "graph.db"
        database.init_db(reset=True, db_path=self.db)
        with database.get_connection(self.db) as connection:
            connection.execute("CREATE TABLE session_clusters (session TEXT, behavior TEXT)")
            connection.executemany(
                "INSERT INTO session_clusters VALUES (?, ?)",
                [("s-1", "Command Activity"), ("s-2", "Login Activity"), ("s-3", "Other")],
            )
            connection.executemany(
                "INSERT INTO events (timestamp, session, src_ip, eventid, username, command) VALUES (?, ?, ?, ?, ?, ?)",
                [
                    ("2026-01-01 10:00:00", "s-1", "192.0.2.1", "cowrie.login.failed", "root", None),
                    ("2026-01-01 10:00:01", "s-1", "192.0.2.1", "cowrie.login.failed", "admin", None),
                    ("2026-01-01 10:00:02", "s-1", "192.0.2.1", "cowrie.command.input", None, "uname -a"),
                    ("2026-01-01 10:00:03", "s-1", "192.0.2.1", "cowrie.command.input", None, "uname -a"),
                    ("2026-01-02 11:00:00", "s-2", "198.51.100.2", "cowrie.login.success", "root", None),
                    ("2026-01-03 12:00:00", "s-3", "203.0.113.3", "cowrie.session.connect", None, None),
                ],
            )
        self.client = TestClient(create_app(db_path=self.db))

    def tearDown(self):
        self.temp.cleanup()

    def test_nodes_edges_are_supported_unique_and_linked(self):
        response = self.client.get("/api/attack-graph")
        self.assertEqual(response.status_code, 200)
        graph = response.json()
        nodes = graph["nodes"]
        edges = graph["edges"]
        node_ids = {node["id"] for node in nodes}
        self.assertTrue({"source_ip", "session", "command", "alert", "technique"}.issubset(
            {node["type"] for node in nodes}
        ))
        self.assertEqual(len(node_ids), len(nodes))
        self.assertEqual(len({edge["id"] for edge in edges}), len(edges))
        self.assertTrue(all(edge["source"] in node_ids and edge["target"] in node_ids for edge in edges))
        self.assertTrue(any(edge["relationship"] == "recorded_session" for edge in edges))
        self.assertTrue(any(edge["relationship"] == "recorded_command" for edge in edges))
        self.assertTrue(any(edge["relationship"] == "alert_evidence" for edge in edges))
        self.assertTrue(any(edge["relationship"] == "mapped_command_evidence" for edge in edges))
        command_nodes = [node for node in nodes if node["type"] == "command" and node["label"] == "uname -a"]
        self.assertEqual(len(command_nodes), 1)
        self.assertEqual(command_nodes[0]["metadata"]["event_count"], 2)

    def test_date_behavior_and_focus_filters(self):
        filtered = self.client.get("/api/attack-graph", params={
            "start": "2026-01-02", "end": "2026-01-02", "behavior": "Login Activity",
        }).json()
        self.assertEqual({node["metadata"].get("source_ip") for node in filtered["nodes"] if node["type"] == "source_ip"}, {"198.51.100.2"})
        focused = self.client.get("/api/attack-graph", params={"session_id": "s-1"}).json()
        self.assertEqual({node["label"] for node in focused["nodes"] if node["type"] == "session"}, {"s-1"})
        self.assertEqual({node["label"] for node in focused["nodes"] if node["type"] == "source_ip"}, {"192.0.2.1"})
        empty = self.client.get("/api/attack-graph", params={"start": "2027-01-01"}).json()
        self.assertEqual(empty["nodes"], [])
        self.assertEqual(empty["edges"], [])

        invalid_ip = self.client.get("/api/attack-graph", params={"source_ip": "203.0.113.250"}).json()
        invalid_session = self.client.get("/api/attack-graph", params={"session_id": "not-a-recorded-session"}).json()
        self.assertEqual(invalid_ip["nodes"], [])
        self.assertEqual(invalid_session["nodes"], [])

    def test_focus_ip_outside_default_sample_returns_exact_alert_evidence(self):
        target_ip = "185.134.91.130"
        target_session = "f865b17290a7"
        with database.get_connection(self.db) as connection:
            connection.execute(
                "INSERT INTO session_clusters VALUES (?, ?)",
                (target_session, "Login Activity"),
            )
            connection.executemany(
                "INSERT INTO events (timestamp, session, src_ip, eventid, username, command) VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (f"2026-01-01 09:00:{second:02d}", target_session, target_ip,
                     "cowrie.login.failed", "root", None)
                    for second in range(14)
                ],
            )
            # Keep this source outside the default six-source recent sample.
            for index in range(7):
                ip = f"198.51.100.{100 + index}"
                session = f"recent-{index}"
                connection.execute(
                    "INSERT INTO session_clusters VALUES (?, ?)",
                    (session, "Other"),
                )
                connection.execute(
                    "INSERT INTO events (timestamp, session, src_ip, eventid) VALUES (?, ?, ?, ?)",
                    (f"2026-01-05 10:00:0{index}", session, ip, "cowrie.session.connect"),
                )

        default_graph = self.client.get("/api/attack-graph").json()
        self.assertNotIn(target_ip, {node["label"] for node in default_graph["nodes"] if node["type"] == "source_ip"})

        response = self.client.get("/api/attack-graph", params={
            "source_ip": target_ip, "start": "2026-01-01", "end": "2026-01-01",
            "behavior": "Login Activity",
        })
        self.assertEqual(response.status_code, 200)
        graph = response.json()
        nodes = {node["id"]: node for node in graph["nodes"]}
        self.assertIn(f"ip:{target_ip}", nodes)
        self.assertIn(f"session:{target_session}", nodes)
        alert = next(node for node in graph["nodes"] if node["type"] == "alert")
        self.assertEqual(alert["metadata"]["event_count"], 14)
        self.assertEqual(alert["metadata"]["source_ip"], target_ip)
        self.assertIn("technique:T1110.001", nodes)
        self.assertTrue(any(
            edge["relationship"] == "recorded_session"
            and edge["source"] == f"ip:{target_ip}"
            and edge["target"] == f"session:{target_session}"
            for edge in graph["edges"]
        ))
        self.assertTrue(any(
            edge["relationship"] == "alert_evidence"
            and edge["target"] == f"alert:{alert['metadata']['alert_id']}"
            for edge in graph["edges"]
        ))
        self.assertTrue(any(
            edge["relationship"] == "mapped_source_evidence"
            and edge["source"] == f"ip:{target_ip}"
            and edge["target"] == "technique:T1110.001"
            for edge in graph["edges"]
        ))

    def test_missing_command_and_node_limit_are_safe(self):
        graph = self.client.get("/api/attack-graph", params={"source_ip": "203.0.113.3", "limit": 1}).json()
        self.assertLessEqual(len(graph["nodes"]), 1)
        node_ids = {node["id"] for node in graph["nodes"]}
        self.assertTrue(all(edge["source"] in node_ids and edge["target"] in node_ids for edge in graph["edges"]))
        self.assertNotIn("command", {node["type"] for node in graph["nodes"]})

    def test_rejects_invalid_limit(self):
        self.assertEqual(self.client.get("/api/attack-graph", params={"limit": 201}).status_code, 422)


if __name__ == "__main__":
    unittest.main()
