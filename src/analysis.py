"""IP risk scoring, credential analysis and table-saving helpers."""
import numpy as np
import pandas as pd

from src import database


def compute_ip_risk(sessions: pd.DataFrame) -> pd.DataFrame:
    """
    Transparent 0-100 risk score per attacker IP (a heuristic, not a model):
      up to 30 pts : failed-login volume   (1 pt per 10 failed logins)
      up to 20 pts : persistence           (1 pt per session)
      25 pts       : any successful login
      25 pts       : ran a download command (wget/curl); 10 pts if other commands only
    Levels: High >= 60, Medium >= 30, otherwise Low.
    """
    g = sessions.groupby("src_ip")
    agg = pd.DataFrame({
        "sessions": g.size(),
        "failed_logins": g["n_failed_logins"].sum(),
        "successful_sessions": g["login_success"].sum().astype(int),
        "commands": g["n_commands"].sum(),
        "download_sessions": g["has_download_cmd"].sum().astype(int),
    })

    agg["risk_score"] = (
        np.minimum(30, agg["failed_logins"] / 10)
        + np.minimum(20, agg["sessions"])
        + np.where(agg["successful_sessions"] > 0, 25, 0)
        + np.where(agg["download_sessions"] > 0, 25,
                   np.where(agg["commands"] > 0, 10, 0))
    ).round(1)

    agg["risk_level"] = np.select(
        [agg["risk_score"] >= 60, agg["risk_score"] >= 30],
        ["High", "Medium"], default="Low",
    )
    return agg.reset_index().sort_values("risk_score", ascending=False).reset_index(drop=True)


def top_credential_pairs(n: int = 10, db_path=None) -> pd.DataFrame:
    """Most common username:password combinations tried."""
    return database.query("""
        SELECT username, password, COUNT(*) AS attempts
        FROM events
        WHERE eventid IN ('cowrie.login.failed', 'cowrie.login.success')
          AND username IS NOT NULL AND password IS NOT NULL
        GROUP BY username, password
        ORDER BY attempts DESC
        LIMIT ?
    """, (n,), db_path)


def save_table(name: str, df: pd.DataFrame, db_path=None) -> None:
    """Write a DataFrame to SQLite, replacing the table if it exists."""
    with database.get_connection(db_path) as conn:
        df.to_sql(name, conn, if_exists="replace", index=False)