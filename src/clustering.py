"""
KMeans clustering of attacker sessions by behavior.

KMeans only produces anonymous cluster ids (0, 1, 2). We name them using
simple, explainable rules on each cluster's average behavior:
  - most commands run        -> "Interactive / Human-like"
  - most failed logins (rest) -> "Brute-force Bot"
  - whatever is left          -> "Scanner / Recon"
Naming only works for k=3; other values fall back to "Cluster N".
"""
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler

import config
from src.features import prepare_features

HUMAN = "Interactive / Human-like"
BOT = "Brute-force Bot"
SCANNER = "Scanner / Recon"


def label_clusters(sessions: pd.DataFrame, cluster_ids, k: int) -> dict:
    """Map each cluster id to a readable behavior name."""
    df = sessions.assign(cluster_id=cluster_ids)
    means = df.groupby("cluster_id")[["n_commands", "n_failed_logins"]].mean()

    if k != 3 or len(means) != 3:
        return {c: f"Cluster {c}" for c in means.index}

    human = means["n_commands"].idxmax()
    rest = means.drop(index=human)
    bot = rest["n_failed_logins"].idxmax()
    scanner = next(c for c in rest.index if c != bot)
    return {human: HUMAN, bot: BOT, scanner: SCANNER}


def cluster_sessions(sessions: pd.DataFrame, n_clusters: int = None):
    """
    Cluster sessions.

    Returns:
        (assignments_df, info) where assignments_df has columns
        session, src_ip, cluster_id, behavior and info holds the silhouette
        score and the cluster-id -> label map.
    """
    k = n_clusters or config.N_CLUSTERS
    if len(sessions) < k:
        raise ValueError(f"Need at least {k} sessions to form {k} clusters "
                         f"(got {len(sessions)}).")

    X = StandardScaler().fit_transform(prepare_features(sessions))
    model = KMeans(n_clusters=k, n_init=10, random_state=config.RANDOM_STATE)
    ids = model.fit_predict(X)

    if len(set(ids)) > 1:
        sil = float(silhouette_score(X, ids, sample_size=min(5000, len(X)),
                                     random_state=config.RANDOM_STATE))
    else:
        sil = float("nan")

    labels = label_clusters(sessions, ids, k)
    out = sessions[["session", "src_ip"]].copy().reset_index(drop=True)
    out["cluster_id"] = ids
    out["behavior"] = out["cluster_id"].map(labels)
    return out, {"silhouette": sil, "labels": labels}


def cluster_profile(sessions: pd.DataFrame, assignments: pd.DataFrame) -> pd.DataFrame:
    """Average behavior per cluster, to sanity-check what each one represents."""
    merged = sessions.merge(assignments[["session", "behavior"]], on="session")
    prof = merged.groupby("behavior").agg(
        sessions=("session", "count"),
        avg_failed_logins=("n_failed_logins", "mean"),
        avg_commands=("n_commands", "mean"),
        avg_duration_sec=("duration_sec", "mean"),
        avg_gap_sec=("avg_gap_sec", "mean"),
        login_success_rate=("login_success", "mean"),
    )
    prof["share_pct"] = (prof["sessions"] / prof["sessions"].sum() * 100)
    return prof.round(2).sort_values("sessions", ascending=False)