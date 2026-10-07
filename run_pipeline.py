"""
Full pipeline: logs -> parse -> sessionize -> SQLite -> GeoIP enrichment.

Rebuilds the database from scratch each run.

Usage:
    python run_pipeline.py
"""
import sys

import config
from src import database, queries
from src.geoip import enrich_ips
from src.parser import parse_log_file
from src.sessionizer import build_sessions


def main() -> int:
    config.ensure_dirs()
    log_path = config.get_log_path()
    print(f"[{'SAMPLE' if config.USE_SAMPLE_DATA else 'REAL'}] Reading: {log_path}")

    try:
        events, stats = parse_log_file(log_path)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        if config.USE_SAMPLE_DATA:
            print("Run `python generate_sample_logs.py` first.")
        return 1

    if events.empty:
        print("No usable events found.")
        return 1

    print(f"Parsed {stats['parsed_events']} events "
          f"({stats['skipped_bad']} bad, {stats['skipped_irrelevant']} irrelevant skipped)")

    sessions = build_sessions(events)
    print(f"Built {len(sessions)} sessions")

    database.init_db(reset=True)
    database.load_events(events)
    database.load_sessions(sessions)
    print(f"Loaded events + sessions into {config.DB_PATH}")

    ip_intel, used_db = enrich_ips(sessions["src_ip"].unique())
    database.load_ip_intel(ip_intel)
    print(f"Enriched {len(ip_intel)} IPs "
          f"({'GeoIP database' if used_db else 'fallback: Unknown'})")

    print("\n--- Overview ---")
    print(queries.overview().T.to_string(header=False))
    print("\n--- Top 5 countries by sessions ---")
    print(queries.attacks_by_country(5).to_string(index=False))
    print("\n--- Top 5 attacker IPs ---")
    print(queries.top_attackers(5).to_string(index=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())