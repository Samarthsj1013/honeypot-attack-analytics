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



def compute_attacker_dna(sessions: pd.DataFrame) -> pd.DataFrame:
    """Build a deterministic behavioral fingerprint for each attacker IP."""
    columns = [
        "src_ip", "sessions", "failed_logins", "successful_sessions",
        "commands", "download_sessions", "login_rate", "command_rate",
        "download_rate", "persistence", "activity", "fingerprint",
    ]
    if sessions.empty:
        return pd.DataFrame(columns=columns)

    g = sessions.groupby("src_ip")
    d = pd.DataFrame({
        "sessions": g.size(),
        "failed_logins": g["n_failed_logins"].sum(),
        "successful_sessions": g["login_success"].sum().astype(int),
        "commands": g["n_commands"].sum(),
        "download_sessions": g["has_download_cmd"].sum().astype(int),
    })

    d["login_rate"] = (
        d["successful_sessions"] / d["sessions"] * 100
    ).round(1)
    d["command_rate"] = (
        d["commands"] / d["sessions"] * 100
    ).round(1)
    d["download_rate"] = (
        d["download_sessions"] / d["sessions"] * 100
    ).round(1)

    max_sessions = max(float(d["sessions"].max()), 1.0)
    max_failed = max(float(d["failed_logins"].max()), 1.0)
    max_commands = max(float(d["commands"].max()), 1.0)

    d["persistence"] = (
        d["sessions"] / max_sessions * 100
    ).round(1)
    d["activity"] = (
        (
            d["failed_logins"] / max_failed * 50
            + d["commands"] / max_commands * 50
        ).clip(0, 100)
    ).round(1)

    def fingerprint(row):
        parts = []
        if row["failed_logins"] > 0:
            parts.append("BF")
        if row["successful_sessions"] > 0:
            parts.append("AUTH")
        if row["commands"] > 0:
            parts.append("CMD")
        if row["download_sessions"] > 0:
            parts.append("DL")
        if row["sessions"] >= max_sessions * 0.5:
            parts.append("PERSIST")
        return "-".join(parts) if parts else "QUIET"

    d["fingerprint"] = d.apply(fingerprint, axis=1)
    d.index.name = "src_ip"
    return d.reset_index()[columns]


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