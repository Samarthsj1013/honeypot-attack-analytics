"""
Parse Cowrie JSON-lines logs into a clean events DataFrame.

Handles bad lines gracefully: malformed JSON, missing keys, bad timestamps
and irrelevant event types are skipped and counted, never crash the pipeline.
"""
import json
from pathlib import Path

import pandas as pd

# Only the event types we analyze. Real Cowrie logs contain many others.
RELEVANT_EVENTS = {
    "cowrie.session.connect",
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.session.closed",
}

REQUIRED_KEYS = ("eventid", "timestamp", "session", "src_ip")

EVENT_COLUMNS = [
    "timestamp", "session", "src_ip", "eventid",
    "username", "password", "command", "duration", "src_port", "sensor",
]


def parse_log_file(path) -> tuple[pd.DataFrame, dict]:
    """
    Read a JSON-lines log file.

    Returns:
        (events_df, stats) where stats counts total/parsed/skipped lines.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    stats = {"total_lines": 0, "parsed_events": 0,
             "skipped_bad": 0, "skipped_irrelevant": 0}
    rows = []

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            stats["total_lines"] += 1

            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                stats["skipped_bad"] += 1
                continue

            if not isinstance(ev, dict) or not all(k in ev for k in REQUIRED_KEYS):
                stats["skipped_bad"] += 1
                continue

            if ev["eventid"] not in RELEVANT_EVENTS:
                stats["skipped_irrelevant"] += 1
                continue

            rows.append({
                "timestamp": ev["timestamp"],
                "session": ev["session"],
                "src_ip": ev["src_ip"],
                "eventid": ev["eventid"],
                "username": ev.get("username"),
                "password": ev.get("password"),
                "command": ev.get("input"),
                "duration": ev.get("duration"),
                "src_port": ev.get("src_port"),
                "sensor": ev.get("sensor"),
            })

    df = pd.DataFrame(rows, columns=EVENT_COLUMNS)

    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
        bad_ts = int(df["timestamp"].isna().sum())
        if bad_ts:
            df = df.dropna(subset=["timestamp"])
            stats["skipped_bad"] += bad_ts
        df["duration"] = pd.to_numeric(df["duration"], errors="coerce")
        df = df.sort_values("timestamp").reset_index(drop=True)

    stats["parsed_events"] = len(df)
    return df, stats