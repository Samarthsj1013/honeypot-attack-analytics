
"""Build a sanitized demo SQLite database for deployment."""

import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src import analysis, clustering, database
from src.geoip import enrich_ips
from src.parser import parse_log_file
from src.sessionizer import build_sessions

SAMPLE = ROOT / "data" / "sample" / "cowrie_sample.json"
OUTPUT = ROOT / "deploy" / "honeypot.sqlite3"
DEMO_PREFIX = "198.51.100."


def sanitize_columns(df):
    df = df.copy()

    replacements = {
        "username": "demo_username",
        "usernames": "demo_username",
        "password": "demo_password",
        "passwords": "demo_password",
        "command": "demo_command",
        "commands": "demo_command",
        "commands_list": "demo_command",
    }

    for column, replacement in replacements.items():
        if column in df.columns:
            df[column] = df[column].apply(
                lambda value: replacement
                if pd.notna(value) and str(value).strip()
                else value
            )

    return df


def remap_ips(events, sessions):
    unique_ips = sorted(
        set(events["src_ip"].dropna().astype(str))
        | set(sessions["src_ip"].dropna().astype(str))
    )

    if len(unique_ips) > 254:
        raise ValueError("Too many IPs for demo IP mapping.")

    ip_map = {
        original: f"{DEMO_PREFIX}{index}"
        for index, original in enumerate(unique_ips, start=1)
    }

    events = events.copy()
    sessions = sessions.copy()

    events["src_ip"] = events["src_ip"].astype(str).map(ip_map)
    sessions["src_ip"] = sessions["src_ip"].astype(str).map(ip_map)

    return events, sessions


def remap_sessions(events, sessions):
    original_ids = sorted(
        set(events["session"].dropna().astype(str))
        | set(sessions["session"].dropna().astype(str))
    )

    session_map = {
        original: f"demo-session-{index:05d}"
        for index, original in enumerate(original_ids, start=1)
    }

    for df in (events, sessions):
        df["session"] = df["session"].map(
            lambda value: session_map.get(str(value), "demo-session-unknown")
            if pd.notna(value)
            else value
        )

    return events, sessions


def main():
    if not SAMPLE.is_file():
        raise FileNotFoundError(f"Sample file not found: {SAMPLE}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    print("Reading sample events...")
    events, stats = parse_log_file(str(SAMPLE))

    if events.empty:
        raise ValueError("No events were parsed.")

    print(f"Parsed {len(events):,} events.")

    print("Building sessions...")
    sessions = build_sessions(events.copy())
    print(f"Built {len(sessions):,} sessions.")

    events, sessions = remap_ips(events, sessions)
    events = sanitize_columns(events)
    sessions = sanitize_columns(sessions)
    events, sessions = remap_sessions(events, sessions)

    print("Generating behavioral clusters...")
    assignments, cluster_info = clustering.cluster_sessions(sessions)

    if assignments.empty:
        raise ValueError("Clustering returned no session assignments.")

    assignments = sanitize_columns(assignments)

    # Generate risk using the existing project implementation.
    print("Generating IP risk scores...")
    risk = analysis.compute_ip_risk(sessions)

    if not isinstance(risk, pd.DataFrame):
        risk = pd.DataFrame(risk)

    # Use neutral demo geography; never publish actual geolocation.
    print("Creating neutral demo IP intelligence...")
    intel = pd.DataFrame({
        "src_ip": sorted(sessions["src_ip"].dropna().unique()),
    })
    intel["country"] = "Demo"
    intel["country_code"] = "DM"
    intel["city"] = "Demo"
    intel["latitude"] = None
    intel["longitude"] = None

    # Risk and clustering outputs can contain IP/session identifiers.
    # The input data has already been remapped, and command/credential
    # columns are sanitized before derived tables are written.
    if "src_ip" in risk.columns:
        risk["src_ip"] = risk["src_ip"].astype(str)

    if "session" in assignments.columns:
        assignments["session"] = assignments["session"].astype(str)

    temp_dir = Path(tempfile.mkdtemp(prefix="honeypot_demo_"))
    temp_db = temp_dir / "honeypot.db"
    staging = OUTPUT.with_name("honeypot_staging.db")

    try:
        print("Creating temporary database...")
        database.init_db(reset=True, db_path=temp_db)
        database.load_events(events, db_path=temp_db)
        database.load_sessions(sessions, db_path=temp_db)
        database.load_ip_intel(intel, db_path=temp_db)

        analysis.save_table(
            "session_clusters", assignments, db_path=temp_db
        )
        analysis.save_table("ip_risk", risk, db_path=temp_db)

        with sqlite3.connect(str(temp_db)) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }

            required = {
                "events", "sessions", "ip_intel",
                "session_clusters", "ip_risk",
            }
            missing = required - tables

            if missing:
                raise ValueError(
                    f"Missing required tables: {sorted(missing)}"
                )

            event_count = conn.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()[0]
            session_count = conn.execute(
                "SELECT COUNT(*) FROM sessions"
            ).fetchone()[0]
            cluster_count = conn.execute(
                "SELECT COUNT(*) FROM session_clusters"
            ).fetchone()[0]
            risk_count = conn.execute(
                "SELECT COUNT(*) FROM ip_risk"
            ).fetchone()[0]

            orphan_events = conn.execute("""
                SELECT COUNT(*)
                FROM events e
                LEFT JOIN sessions s ON e.session = s.session
                WHERE s.session IS NULL
            """).fetchone()[0]

            orphan_clusters = conn.execute("""
                SELECT COUNT(*)
                FROM session_clusters c
                LEFT JOIN sessions s ON c.session = s.session
                WHERE s.session IS NULL
            """).fetchone()[0]

            bad_ips = conn.execute("""
                SELECT COUNT(*) FROM events
                WHERE src_ip NOT LIKE '198.51.100.%'
            """).fetchone()[0]

            if orphan_events or orphan_clusters or bad_ips:
                raise ValueError(
                    "Database validation failed: "
                    f"orphan events={orphan_events}, "
                    f"orphan clusters={orphan_clusters}, "
                    f"non-demo IPs={bad_ips}"
                )

        print(f"Verified events: {event_count:,}")
        print(f"Verified sessions: {session_count:,}")
        print(f"Verified clusters: {cluster_count:,}")
        print(f"Verified risk records: {risk_count:,}")
        print(f"Cluster info: {cluster_info}")

        staging.unlink(missing_ok=True)
        source = sqlite3.connect(str(temp_db))
        destination = sqlite3.connect(str(staging))

        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()

        staging.replace(OUTPUT)

        print(f"\nDemo database created: {OUTPUT}")
        print("Geographic data is neutralized.")
        print("Review sensitive values before publishing.")

    finally:
        try:
            staging.unlink(missing_ok=True)
        except PermissionError:
            print(f"Could not remove staging file: {staging}")

        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
