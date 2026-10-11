"""IP risk scoring, credential analysis and table-saving helpers."""
import re

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
        "src_ip",
        "sessions",
        "failed_logins",
        "successful_sessions",
        "commands",
        "download_sessions",
        "login_rate",
        "command_rate",
        "download_rate",
        "persistence",
        "activity",
        "fingerprint",
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


def classify_attack_intent(sessions: pd.DataFrame) -> dict:
    """Apply deterministic intent rules to observed honeypot sessions."""
    empty_evidence = {
        "sessions": 0,
        "failed_login_events": 0,
        "sessions_with_failed_logins": 0,
        "successful_login_events": 0,
        "sessions_with_successful_logins": 0,
        "command_count": 0,
        "commands_observed": [],
        "download_tool_matches": [],
        "connection_only_sessions": 0,
        "recon_behavior_sessions": 0,
    }
    if sessions is None or sessions.empty:
        return {
            "classification": "Unknown / Insufficient Evidence",
            "evidence": empty_evidence,
            "explanation": "No honeypot sessions were available for this filter.",
            "inference_note": (
                "This is an inference from observed honeypot events. "
                "A successful honeypot login does not prove compromise of a real system."
            ),
        }

    def numeric_series(column: str) -> pd.Series:
        if column not in sessions:
            return pd.Series(0, index=sessions.index, dtype="int64")
        return pd.to_numeric(sessions[column], errors="coerce").fillna(0).clip(lower=0)

    failed_by_session = numeric_series("n_failed_logins")
    if "n_success_logins" in sessions:
        successful_by_session = numeric_series("n_success_logins")
    else:
        successful_by_session = numeric_series("login_success")

    if "n_commands" in sessions:
        command_counts = numeric_series("n_commands")
    elif "commands" in sessions:
        command_counts = sessions["commands"].fillna("").astype(str).map(
            lambda value: sum(
                1 for command in re.split(r"\s+;\s+", value) if command.strip()
            )
        )
    else:
        command_counts = pd.Series(0, index=sessions.index, dtype="int64")

    commands = set()
    if "commands" in sessions:
        for value in sessions["commands"].dropna().astype(str):
            commands.update(
                command.strip()
                for command in re.split(r"\s+;\s+", value)
                if command.strip()
            )
    commands_observed = sorted(commands)[:5]
    command_count = int(command_counts.sum())
    if command_count == 0 and commands:
        command_count = len(commands)

    download_pattern = re.compile(
        r"\b(wget|curl|ftp|tftp|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|"
        r"invoke-webrequest|iwr)\b",
        re.IGNORECASE,
    )
    download_tool_matches = sorted({
        match.group(0).lower()
        for command in commands
        for match in download_pattern.finditer(command)
    })

    behavior = (
        sessions["behavior"].fillna("Unclustered").astype(str)
        if "behavior" in sessions
        else pd.Series("Unclustered", index=sessions.index)
    )
    recon_behavior_sessions = int(
        behavior.str.contains(r"scanner|recon", case=False, regex=True).sum()
    )
    connection_only = (
        (failed_by_session == 0)
        & (successful_by_session == 0)
        & (command_counts == 0)
    )

    evidence = {
        "sessions": int(len(sessions)),
        "failed_login_events": int(failed_by_session.sum()),
        "sessions_with_failed_logins": int((failed_by_session > 0).sum()),
        "successful_login_events": int(successful_by_session.sum()),
        "sessions_with_successful_logins": int((successful_by_session > 0).sum()),
        "command_count": command_count,
        "commands_observed": commands_observed,
        "download_tool_matches": download_tool_matches,
        "connection_only_sessions": int(connection_only.sum()),
        "recon_behavior_sessions": recon_behavior_sessions,
    }

    if download_tool_matches:
        classification = "Payload Download Attempt"
        explanation = "A download-capable tool was observed in one or more honeypot commands."
    elif command_count > 0:
        classification = "Command Execution"
        explanation = "One or more commands were observed in the honeypot session data."
    elif evidence["successful_login_events"] > 0:
        classification = "Successful Login / Access Attempt"
        explanation = "A successful login event was recorded by the honeypot."
    elif evidence["failed_login_events"] >= 3:
        classification = "Credential Brute Force"
        explanation = "At least three failed login events were recorded."
    elif recon_behavior_sessions > 0 or evidence["connection_only_sessions"] >= 3:
        classification = "Reconnaissance / Scanning"
        explanation = (
            "The data contains a scanner/recon behavior label or repeated connection-only sessions."
        )
    else:
        classification = "Unknown / Insufficient Evidence"
        explanation = "Observed events do not meet the evidence threshold for an intent category."

    return {
        "classification": classification,
        "evidence": evidence,
        "explanation": explanation,
        "inference_note": (
            "This is an inference from observed honeypot events. "
            "A successful honeypot login does not prove compromise of a real system."
        ),
    }


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
