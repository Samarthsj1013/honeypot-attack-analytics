"""Feature preparation for behavioral clustering."""
import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    "n_events",
    "n_failed_logins",
    "n_success_logins",
    "n_commands",
    "n_unique_usernames",
    "n_unique_passwords",
    "duration_sec",
    "avg_gap_sec",
]


def prepare_features(sessions: pd.DataFrame) -> pd.DataFrame:
    """
    Select behavioral columns and log-transform them.

    Counts and durations are heavily right-skewed (a few huge brute-force
    sessions), so log1p stops them from dominating the clustering.
    """
    feats = sessions[FEATURE_COLUMNS].astype(float).fillna(0).clip(lower=0)
    return np.log1p(feats)