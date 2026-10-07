"""
Run the ingestion pipeline: raw logs -> events.csv + sessions.csv

Usage:
    python run_ingest.py
"""
import sys

import config
from src.parser import parse_log_file
from src.sessionizer import build_sessions


def main() -> int:
    config.ensure_dirs()
    log_path = config.get_log_path()
    mode = "SAMPLE" if config.USE_SAMPLE_DATA else "REAL"
    print(f"[{mode}] Reading logs from: {log_path}")

    try:
        events, stats = parse_log_file(log_path)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        if config.USE_SAMPLE_DATA:
            print("Run `python generate_sample_logs.py` first.")
        return 1

    print("\n--- Parse stats ---")
    for key, value in stats.items():
        print(f"{key:>20}: {value}")

    if events.empty:
        print("\nNo usable events found. Nothing to save.")
        return 1

    sessions = build_sessions(events)

    events_path = config.PROCESSED_DIR / "events.csv"
    sessions_path = config.PROCESSED_DIR / "sessions.csv"
    events.to_csv(events_path, index=False)
    sessions.to_csv(sessions_path, index=False)

    print("\n--- Summary ---")
    print(f"Events:            {len(events)}")
    print(f"Sessions:          {len(sessions)}")
    print(f"Unique attacker IPs: {sessions['src_ip'].nunique()}")
    print(f"Sessions with successful login: {int(sessions['login_success'].sum())}")
    print(f"Time range: {events['timestamp'].min()} -> {events['timestamp'].max()}")

    logins = events[events["eventid"].isin(["cowrie.login.failed", "cowrie.login.success"])]
    print("\nTop 5 usernames tried:")
    print(logins["username"].value_counts().head(5).to_string())
    print("\nTop 5 passwords tried:")
    print(logins["password"].value_counts().head(5).to_string())

    print(f"\nSaved: {events_path}")
    print(f"Saved: {sessions_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())