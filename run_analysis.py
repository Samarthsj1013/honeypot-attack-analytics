"""
Run clustering + risk scoring on the sessions in the database.

Run this AFTER run_pipeline.py, and again every time you re-run the pipeline
(the pipeline rebuilds events/sessions, so old cluster results go stale).

Usage:
    python run_analysis.py
"""
import sys

import config
from src import analysis, clustering, database


def main() -> int:
    if not config.DB_PATH.exists():
        print("ERROR: database not found. Run `python run_pipeline.py` first.")
        return 1

    sessions = database.query("SELECT * FROM sessions")
    if sessions.empty:
        print("ERROR: sessions table is empty. Re-run `python run_pipeline.py`.")
        return 1
    if len(sessions) < config.N_CLUSTERS:
        print(f"ERROR: need at least {config.N_CLUSTERS} sessions to cluster.")
        return 1

    assignments, info = clustering.cluster_sessions(sessions)
    profile = clustering.cluster_profile(sessions, assignments)
    risk = analysis.compute_ip_risk(sessions)

    analysis.save_table("session_clusters", assignments)
    analysis.save_table("ip_risk", risk)

    print(f"Clustered {len(assignments)} sessions into {config.N_CLUSTERS} groups")
    print(f"Silhouette score: {info['silhouette']:.3f}  (closer to 1 = cleaner separation)")

    print("\n--- Cluster profiles ---")
    print(profile.to_string())

    print("\n--- Risk levels (attacker IPs) ---")
    print(risk["risk_level"].value_counts().to_string())

    print("\n--- Top 5 riskiest IPs ---")
    print(risk.head(5).to_string(index=False))

    print("\n--- Top 5 username:password pairs ---")
    print(analysis.top_credential_pairs(5).to_string(index=False))

    print("\nSaved tables: session_clusters, ip_risk")
    return 0


if __name__ == "__main__":
    sys.exit(main())