"""
Roll event-level data up into one row per attacker session.

The behavioral features here (login attempts, command counts, timing gaps)
are what the ML clustering will use later to separate scanners, bots and humans.
"""
import pandas as pd

SESSION_COLUMNS = [
    "session", "src_ip", "start_time", "end_time", "start_date", "start_hour",
    "duration_sec", "n_events", "n_failed_logins", "n_success_logins",
    "n_commands", "n_unique_usernames", "n_unique_passwords",
    "login_success", "avg_gap_sec", "has_download_cmd", "commands",
]

LOGIN_EVENTS = ("cowrie.login.failed", "cowrie.login.success")


def _count_by_session(events: pd.DataFrame, eventid: str) -> pd.Series:
    return events[events["eventid"] == eventid].groupby("session").size()


def build_sessions(events: pd.DataFrame) -> pd.DataFrame:
    """Build the session-level feature table from the events DataFrame."""
    if events.empty:
        return pd.DataFrame(columns=SESSION_COLUMNS)

    g = events.groupby("session")
    sessions = pd.DataFrame({
        "src_ip": g["src_ip"].first(),
        "start_time": g["timestamp"].min(),
        "end_time": g["timestamp"].max(),
        "n_events": g.size(),
    })

    # --- Login / command counts ---
    sessions["n_failed_logins"] = _count_by_session(events, "cowrie.login.failed")
    sessions["n_success_logins"] = _count_by_session(events, "cowrie.login.success")
    sessions["n_commands"] = _count_by_session(events, "cowrie.command.input")

    logins = events[events["eventid"].isin(LOGIN_EVENTS)]
    sessions["n_unique_usernames"] = logins.groupby("session")["username"].nunique()
    sessions["n_unique_passwords"] = logins.groupby("session")["password"].nunique()

    count_cols = ["n_failed_logins", "n_success_logins", "n_commands",
                  "n_unique_usernames", "n_unique_passwords"]
    sessions[count_cols] = sessions[count_cols].fillna(0).astype(int)
    sessions["login_success"] = sessions["n_success_logins"] > 0

    # --- Duration: prefer Cowrie's own value, fall back to first/last event ---
    closed = events[events["eventid"] == "cowrie.session.closed"]
    sessions["duration_sec"] = closed.groupby("session")["duration"].max()
    fallback = (sessions["end_time"] - sessions["start_time"]).dt.total_seconds()
    sessions["duration_sec"] = sessions["duration_sec"].fillna(fallback)

    # --- Timing: average gap between consecutive events (bots are fast) ---
    ordered = events.sort_values(["session", "timestamp"]).copy()
    ordered["gap"] = ordered.groupby("session")["timestamp"].diff().dt.total_seconds()
    sessions["avg_gap_sec"] = ordered.groupby("session")["gap"].mean().fillna(0)

    # --- Commands run in the session ---
    cmds = events[events["eventid"] == "cowrie.command.input"].dropna(subset=["command"])
    sessions["commands"] = cmds.groupby("session")["command"].agg(" ; ".join)
    sessions["commands"] = sessions["commands"].fillna("")
    sessions["has_download_cmd"] = sessions["commands"].str.contains(
        r"wget|curl", case=False, regex=True
    )

    # --- Time features for the timeline charts ---
    sessions["start_date"] = sessions["start_time"].dt.date
    sessions["start_hour"] = sessions["start_time"].dt.hour

    sessions.index.name = "session"
    sessions = sessions.reset_index()
    return sessions[SESSION_COLUMNS].sort_values("start_time").reset_index(drop=True)