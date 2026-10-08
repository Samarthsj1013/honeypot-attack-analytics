"""
Query layer for the API. Every public function returns plain, JSON-safe data
(no NaN, no numpy types) so FastAPI can serialize it directly.
"""
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

import config
from src import analysis, database

REQUIRED_TABLES = {"events", "sessions", "ip_intel", "session_clusters"}
BEHAVIOR_EXPR = "COALESCE(c.behavior, 'Unclustered')"
LOGIN_EVENTS = "('cowrie.login.failed', 'cowrie.login.success')"

# kind -> (events column, event-type condition). Fixed constants, never user input.
CREDENTIAL_KINDS = {
    "username": ("username", f"e.eventid IN {LOGIN_EVENTS}"),
    "password": ("password", f"e.eventid IN {LOGIN_EVENTS}"),
    "command": ("command", "e.eventid = 'cowrie.command.input'"),
}

RISK_COLUMNS = [
    "src_ip",
    "sessions",
    "failed_logins",
    "successful_sessions",
    "commands",
    "download_sessions",
    "risk_score",
    "risk_level",
]


@dataclass
class Filters:
    start: str | None = None            # "YYYY-MM-DD", inclusive
    end: str | None = None              # "YYYY-MM-DD", inclusive
    behaviors: list[str] | None = None  # None = all behaviors


def records(df: pd.DataFrame) -> list[dict]:
    """DataFrame -> list of dicts with NaN/NaT replaced by None."""
    if df.empty:
        return []
    return df.astype(object).where(df.notna(), None).to_dict("records")


def missing_tables(db_path=None) -> set:
    """Tables the API needs that are not in the database (all of them if no DB)."""
    path = Path(db_path) if db_path else config.DB_PATH

    if not path.exists():
        return set(REQUIRED_TABLES)

    present = set(
        database.query(
            "SELECT name FROM sqlite_master WHERE type='table'",
            db_path=db_path,
        )["name"]
    )

    return REQUIRED_TABLES - present


def _filters(f: Filters, ts_col: str) -> tuple[list[str], list]:
    """Build WHERE clauses + params for date range and behavior."""
    clauses, params = [], []

    if f.start:
        clauses.append(f"date({ts_col}) >= ?")
        params.append(f.start)

    if f.end:
        clauses.append(f"date({ts_col}) <= ?")
        params.append(f.end)

    if f.behaviors is not None:
        if f.behaviors:
            marks = ",".join("?" for _ in f.behaviors)
            clauses.append(f"{BEHAVIOR_EXPR} IN ({marks})")
            params.extend(f.behaviors)
        else:
            clauses.append("1 = 0")

    return clauses, params


def load_sessions(f: Filters, db_path=None) -> pd.DataFrame:
    """Filtered sessions joined with cluster label and GeoIP data."""
    clauses, params = _filters(f, "s.start_time")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    return database.query(
        f"""
        SELECT s.*,
               {BEHAVIOR_EXPR}                AS behavior,
               COALESCE(i.country, 'Unknown') AS country,
               i.city,
               i.latitude,
               i.longitude
        FROM sessions s
        LEFT JOIN session_clusters c ON s.session = c.session
        LEFT JOIN ip_intel i         ON s.src_ip = i.src_ip
        {where}
        """,
        tuple(params),
        db_path,
    )


def meta(db_path=None) -> dict:
    """Info the frontend needs to build its filters (ignores filters itself)."""
    rng = database.query(
        "SELECT MIN(date(start_time)) AS first_day, "
        "MAX(date(start_time)) AS last_day "
        "FROM sessions",
        db_path=db_path,
    ).iloc[0]

    behaviors = database.query(
        f"""
        SELECT DISTINCT {BEHAVIOR_EXPR} AS behavior
        FROM sessions s
        LEFT JOIN session_clusters c ON s.session = c.session
        ORDER BY behavior
        """,
        db_path=db_path,
    )["behavior"].tolist()

    geo = database.query(
        "SELECT COUNT(*) AS n FROM ip_intel WHERE latitude IS NOT NULL",
        db_path=db_path,
    ).iloc[0]["n"]

    return {
        "data_source": "sample" if config.USE_SAMPLE_DATA else "live",
        "first_day": rng["first_day"],
        "last_day": rng["last_day"],
        "behaviors": behaviors,
        "geo_available": bool(geo > 0),
    }


def event_count(f: Filters, db_path=None) -> int:
    clauses, params = _filters(f, "e.timestamp")

    where = (
        f"WHERE {' AND '.join(clauses)}"
        if clauses
        else ""
    )

    df = database.query(
        f"""
        SELECT COUNT(*) AS total_events
        FROM events e
        LEFT JOIN session_clusters c
            ON e.session = c.session
        {where}
        """,
        tuple(params),
        db_path,
    )

    if df.empty:
        return 0

    return int(df.iloc[0]["total_events"])


def risk_table(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=RISK_COLUMNS)

    return analysis.compute_ip_risk(df)


def overview(df: pd.DataFrame, total_events: int = 0) -> dict:
    if df.empty:
        return {
            "total_events": int(total_events),
            "sessions": 0,
            "unique_ips": 0,
            "failed_logins": 0,
            "successful_sessions": 0,
            "high_risk_ips": 0,
            "first_seen": None,
            "last_seen": None,
        }

    risk = risk_table(df)

    return {
        "total_events": int(total_events),
        "sessions": int(len(df)),
        "unique_ips": int(df["src_ip"].nunique()),
        "failed_logins": int(df["n_failed_logins"].sum()),
        "successful_sessions": int(df["login_success"].sum()),
        "high_risk_ips": int((risk["risk_level"] == "High").sum()),
        "first_seen": df["start_time"].min(),
        "last_seen": df["start_time"].max(),
    }


def timeline(df: pd.DataFrame) -> list[dict]:
    """Sessions per day, split by behavior."""
    if df.empty:
        return []

    d = (
        df.assign(day=df["start_time"].str[:10])
        .groupby(["day", "behavior"])
        .size()
        .reset_index(name="sessions")
        .sort_values(["day", "behavior"])
    )

    return records(d)


def hourly(df: pd.DataFrame) -> list[dict]:
    """Sessions per hour of day (UTC), always 24 rows."""
    counts = (
        df.groupby("start_hour").size()
        if not df.empty
        else pd.Series(dtype=int)
    )

    counts = counts.reindex(range(24), fill_value=0)

    return [
        {"hour": int(h), "sessions": int(n)}
        for h, n in counts.items()
    ]


def behaviors(df: pd.DataFrame) -> list[dict]:
    """Average behavior per cluster, plus each cluster's share of sessions."""
    if df.empty:
        return []

    prof = (
        df.groupby("behavior")
        .agg(
            sessions=("session", "count"),
            avg_failed_logins=("n_failed_logins", "mean"),
            avg_commands=("n_commands", "mean"),
            avg_duration_sec=("duration_sec", "mean"),
            avg_gap_sec=("avg_gap_sec", "mean"),
            login_success_rate=("login_success", "mean"),
        )
        .round(2)
    )

    prof["share_pct"] = (
        prof["sessions"] / prof["sessions"].sum() * 100
    ).round(1)

    return records(
        prof.sort_values("sessions", ascending=False).reset_index()
    )


def countries(df: pd.DataFrame, limit: int = 10) -> list[dict]:
    if df.empty:
        return []

    d = (
        df.groupby("country")
        .agg(
            sessions=("session", "count"),
            unique_ips=("src_ip", "nunique"),
            failed_logins=("n_failed_logins", "sum"),
        )
        .reset_index()
        .sort_values("sessions", ascending=False)
        .head(limit)
    )

    return records(d)


def map_points(df: pd.DataFrame) -> list[dict]:
    """One point per attacker IP with coordinates and backend risk data."""
    geo = df.dropna(subset=["latitude", "longitude"])

    if geo.empty:
        return []

    g = (
        geo.groupby("src_ip")
        .agg(
            country=("country", "first"),
            city=("city", "first"),
            latitude=("latitude", "first"),
            longitude=("longitude", "first"),
            sessions=("session", "count"),
            failed_logins=("n_failed_logins", "sum"),
        )
        .reset_index()
        .sort_values("sessions", ascending=False)
    )

    risk = risk_table(df)[
        ["src_ip", "risk_score", "risk_level"]
    ]

    g = g.merge(risk, on="src_ip", how="left")

    return records(g)


def attackers(df: pd.DataFrame, limit: int = 25) -> list[dict]:
    """Riskiest IPs first, with country."""
    risk = risk_table(df)

    if risk.empty:
        return []

    country = (
        df.groupby("src_ip")["country"]
        .first()
        .reset_index()
    )

    return records(
        risk.merge(country, on="src_ip", how="left").head(limit)
    )
def attacker_detail(src_ip: str, f: Filters, db_path=None) -> dict | None:
    """Detailed investigation profile for one attacker IP."""
    df = load_sessions(f, db_path)

    if df.empty:
        return None

    attacker = df[df["src_ip"] == src_ip].copy()

    if attacker.empty:
        return None

    risk = analysis.compute_ip_risk(attacker)

    if risk.empty:
        return None

    row = risk.iloc[0]

    behaviors = (
        attacker["behavior"]
        .dropna()
        .value_counts()
        .to_dict()
    )

    usernames = (
        attacker["username"]
        .dropna()
        .astype(str)
        .value_counts()
        .head(10)
        .index
        .tolist()
        if "username" in attacker.columns
        else []
    )

    passwords = (
        attacker["password"]
        .dropna()
        .astype(str)
        .value_counts()
        .head(10)
        .index
        .tolist()
        if "password" in attacker.columns
        else []
    )

    commands = (
        attacker["command"]
        .dropna()
        .astype(str)
        .value_counts()
        .head(10)
        .index
        .tolist()
        if "command" in attacker.columns
        else []
    )

    return {
        "src_ip": src_ip,
        "country": attacker["country"].iloc[0],
        "city": attacker["city"].iloc[0],
        "latitude": attacker["latitude"].iloc[0],
        "longitude": attacker["longitude"].iloc[0],

        "sessions": int(row["sessions"]),
        "failed_logins": int(row["failed_logins"]),
        "successful_sessions": int(row["successful_sessions"]),
        "commands": int(row["commands"]),
        "download_sessions": int(row["download_sessions"]),

        "risk_score": float(row["risk_score"]),
        "risk_level": row["risk_level"],

        "behaviors": behaviors,

        "usernames": usernames,
        "passwords": passwords,
        "commands_list": commands,

        "first_seen": attacker["start_time"].min(),
        "last_seen": attacker["start_time"].max(),
    }


def risk_levels(df: pd.DataFrame) -> list[dict]:
    risk = risk_table(df)

    counts = (
        risk["risk_level"].value_counts()
        if not risk.empty
        else pd.Series(dtype=int)
    ).reindex(
        ["High", "Medium", "Low"],
        fill_value=0,
    )

    return [
        {"risk_level": k, "ips": int(v)}
        for k, v in counts.items()
    ]


def top_values(
    f: Filters,
    kind: str,
    limit: int = 10,
    db_path=None,
) -> list[dict]:
    """Most common usernames / passwords / commands within the filters."""
    column, base = CREDENTIAL_KINDS[kind]

    clauses, params = _filters(f, "e.timestamp")

    where = " AND ".join(
        [base, f"e.{column} IS NOT NULL"] + clauses
    )

    df = database.query(
        f"""
        SELECT e.{column} AS value, COUNT(*) AS count
        FROM events e
        LEFT JOIN session_clusters c ON e.session = c.session
        WHERE {where}
        GROUP BY e.{column}
        ORDER BY count DESC, value
        LIMIT ?
        """,
        (*params, limit),
        db_path,
    )

    return records(df)