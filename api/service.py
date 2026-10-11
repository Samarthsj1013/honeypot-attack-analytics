"""

Query layer for the API. Every public function returns plain, JSON-safe data

(no NaN, no numpy types) so FastAPI can serialize it directly.

"""

from dataclasses import dataclass
from hashlib import sha256

from pathlib import Path

import pandas as pd

import config

from src import analysis, database
from src import mitre
from src import similarity

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

def source_intelligence(
    f: Filters,
    db_path=None,
    *,
    country: str | None = None,
    risk_level: str | None = None,
    limit: int = 100,
    offset: int = 0,
    sort_by: str = "total_events",
    sort_order: str = "desc",
) -> dict:
    """Aggregate event-backed source activity and filtered session risk."""
    sessions = load_sessions(f, db_path)
    risk = risk_table(sessions)
    risk_by_ip = {
        str(row["src_ip"]): {
            "risk_score": float(row["risk_score"]),
            "risk_level": str(row["risk_level"]),
            "sessions": int(row["sessions"]),
            "successful_sessions": int(row["successful_sessions"]),
        }
        for _, row in risk.iterrows()
    }

    clauses, params = _filters(f, "e.timestamp")
    clauses.append("e.src_ip IS NOT NULL")
    where = " AND ".join(clauses) if clauses else "1 = 1"
    event_rows = database.query(
        f"""
        SELECT e.src_ip,
               COALESCE(NULLIF(TRIM(i.country), ''), 'Unknown') AS country,
               i.city,
               COUNT(*) AS total_events,
               SUM(CASE WHEN e.eventid = 'cowrie.login.failed' THEN 1 ELSE 0 END) AS failed_logins,
               MAX(e.timestamp) AS last_seen,
               i.latitude, i.longitude
        FROM events e
        LEFT JOIN session_clusters c ON e.session = c.session
        LEFT JOIN ip_intel i ON e.src_ip = i.src_ip
        WHERE {where}
        GROUP BY e.src_ip
        """,
        tuple(params),
        db_path,
    )
    sources = records(event_rows)
    for item in sources:
        score = risk_by_ip.get(str(item["src_ip"]))
        item.update(score or {
            "risk_score": None,
            "risk_level": "Unknown",
            "sessions": 0,
            "successful_sessions": 0,
        })
    if country:
        sources = [item for item in sources if item["country"] == country]
    if risk_level:
        sources = [item for item in sources if item["risk_level"] == risk_level]
    sortable = {
        "src_ip": lambda item: str(item["src_ip"]),
        "country": lambda item: str(item["country"] or "Unknown").casefold(),
        "city": lambda item: str(item["city"] or "").casefold(),
        "total_events": lambda item: int(item["total_events"] or 0),
        "failed_logins": lambda item: int(item["failed_logins"] or 0),
        "successful_sessions": lambda item: int(item["successful_sessions"] or 0),
        "risk_score": lambda item: float(item["risk_score"] or 0),
        "last_seen": lambda item: str(item["last_seen"] or ""),
    }
    sorter = sortable.get(sort_by, sortable["total_events"])
    sources.sort(key=lambda item: (sorter(item), str(item["src_ip"])), reverse=sort_order == "desc")

    # Country aggregates derive from the same event rows and source filters.
    country_rows = {}
    for item in sources:
        aggregate = country_rows.setdefault(item["country"], {
            "country": item["country"], "unique_ips": 0, "total_events": 0,
            "failed_logins": 0, "high_risk_sources": 0,
        })
        aggregate["unique_ips"] += 1
        aggregate["total_events"] += int(item["total_events"] or 0)
        aggregate["failed_logins"] += int(item["failed_logins"] or 0)
        aggregate["high_risk_sources"] += int(item["risk_level"] == "High")
    country_list = sorted(country_rows.values(), key=lambda row: (-row["total_events"], row["country"].casefold()))

    source_total = len(sources)
    paged = sources[offset:offset + limit]
    map_points = [
        item for item in sources
        if item["latitude"] is not None and item["longitude"] is not None
    ]
    return {
        "overview": {
            "unique_source_ips": source_total,
            "total_attack_events": sum(int(item["total_events"] or 0) for item in sources),
            "countries_represented": len(country_rows),
            "high_risk_sources": sum(item["risk_level"] == "High" for item in sources),
        },
        "countries": country_list,
        "sources": paged,
        "map_points": map_points,
        "total_sources": source_total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(paged) < source_total,
    }


def technique_intelligence(
    f: Filters,
    db_path=None,
    *,
    technique_id: str | None = None,
    tactic: str | None = None,
    source_ip: str | None = None,
    limit: int = 25,
    offset: int = 0,
) -> dict:
    """Return filtered technique aggregates built only from stored events."""
    events = _technique_event_rows(f, db_path, source_ip)
    items = mitre.map_events(events)
    if technique_id and technique_id.strip():
        selected_id = technique_id.strip().upper()
        items = [item for item in items if item["technique_id"] == selected_id]
    if tactic:
        items = [item for item in items if item["tactic"] == tactic]
    summary = {
        "mapped_techniques": len(items),
        "observed_tactics": len({item["tactic"] for item in items}),
        "source_ips": len({source["src_ip"] for item in items for source in item["sources"]}),
        "matching_techniques": len(items),
    }
    total = len(items)
    page = items[offset:offset + limit]
    # Avoid shipping every source's full evidence with the ranked list. Details
    # are available through /api/mitre/techniques/{technique_id}.
    listing = [{key: value for key, value in item.items() if key != "sources"} for item in page]
    return {
        "summary": summary,
        "scope_note": mitre.SCOPE_NOTE,
        "items": listing,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(page) < total,
    }


def technique_detail(
    technique_id: str,
    f: Filters,
    db_path=None,
    *,
    source_ip: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict | None:
    """Return per-source evidence for one technique under active filters."""
    detail_items = mitre.map_events(_technique_event_rows(f, db_path, source_ip))
    selected = next(
        (item for item in detail_items if item["technique_id"] == technique_id.strip().upper()),
        None,
    )
    if selected is None:
        return None
    sources = selected["sources"]
    page = sources[offset:offset + limit]
    return {
        **{key: value for key, value in selected.items() if key != "sources"},
        "scope_note": mitre.SCOPE_NOTE,
        "sources": page,
        "total_sources": len(sources),
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(page) < len(sources),
    }


def _technique_event_rows(f: Filters, db_path=None, source_ip: str | None = None):
    clauses, params = ["e.eventid IN ('cowrie.login.failed', 'cowrie.command.input')"], []
    date_behavior_clauses, date_behavior_params = _filters(f, "e.timestamp")
    clauses.extend(date_behavior_clauses)
    params.extend(date_behavior_params)
    if source_ip and source_ip.strip():
        clauses.append("e.src_ip = ?")
        params.append(source_ip.strip())
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return database.query(
        f"""
        SELECT e.timestamp, e.session, e.src_ip, e.eventid, e.command
        FROM events e
        LEFT JOIN session_clusters c ON e.session = c.session
        {where}
        ORDER BY e.timestamp, e.id
        """,
        tuple(params),
        db_path,
    )

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

        .fillna("Unclustered")

        .value_counts()

        .to_dict()

    )

    def top_for_ip(

        column: str,

        event_condition: str,

        limit: int = 10,

    ) -> list[dict]:

        """Return event-level credentials/commands for this attacker."""

        clauses, params = _filters(f, "e.timestamp")

        where_parts = [

            "e.src_ip = ?",

            event_condition,

            f"e.{column} IS NOT NULL",

            *clauses,

        ]

        params = [src_ip, *params]

        where = " AND ".join(where_parts)

        result = database.query(

            f"""

            SELECT

                e.{column} AS value,

                COUNT(*) AS count

            FROM events e

            LEFT JOIN session_clusters c

                ON e.session = c.session

            WHERE {where}

            GROUP BY e.{column}

            ORDER BY count DESC, value

            LIMIT ?

            """,

            (*params, limit),

            db_path,

        )

        return records(result)

    usernames = top_for_ip(

        "username",

        f"e.eventid IN {LOGIN_EVENTS}",

    )

    passwords = top_for_ip(

        "password",

        f"e.eventid IN {LOGIN_EVENTS}",

    )

    commands_top = top_for_ip(

        "command",

        "e.eventid = 'cowrie.command.input'",

    )

    return {

        "src_ip": str(src_ip),

        "country": (

            attacker["country"].iloc[0]

            if "country" in attacker.columns

            else "Unknown"

        ),

        "city": (

            attacker["city"].iloc[0]

            if "city" in attacker.columns

            else None

        ),

        "latitude": (

            attacker["latitude"].iloc[0]

            if "latitude" in attacker.columns

            else None

        ),

        "longitude": (

            attacker["longitude"].iloc[0]

            if "longitude" in attacker.columns

            else None

        ),

        "behavior": (

            max(behaviors, key=behaviors.get)

            if behaviors

            else "Unclustered"

        ),

        "sessions": int(row["sessions"]),

        "failed_logins": int(row["failed_logins"]),

        "successful_sessions": int(row["successful_sessions"]),

        "commands": int(row["commands"]),

        "download_sessions": int(row["download_sessions"]),

        "risk_score": float(row["risk_score"]),

        "risk_level": str(row["risk_level"]),

        "behaviors": {

            str(key): int(value)

            for key, value in behaviors.items()

        },

        "usernames": usernames,

        "passwords": passwords,

        "commands_top": commands_top,

        "first_seen": str(attacker["start_time"].min()),

        "last_seen": str(attacker["start_time"].max()),

    }

def attacker_dna(src_ip: str, f: Filters, db_path=None) -> dict | None:
    df = load_sessions(f, db_path)
    if df.empty:
        return None

    if src_ip not in set(df["src_ip"].astype(str)):
        return None

    # Compute DNA across all attackers under the current filters so
    # persistence and activity are normalized relative to the full dataset.
    dna = analysis.compute_attacker_dna(df)
    if dna.empty:
        return None

    attacker_dna_row = dna[dna["src_ip"].astype(str) == str(src_ip)]
    if attacker_dna_row.empty:
        return None

    return records(attacker_dna_row)[0]

def attacker_intent(src_ip: str, f: Filters, db_path=None) -> dict | None:
    """Classify the selected attacker's intent from the currently filtered sessions."""
    df = load_sessions(f, db_path)
    attacker = df[df["src_ip"].astype(str) == str(src_ip)] if not df.empty else df
    if attacker.empty:
        return None
    return {
        "src_ip": str(src_ip),
        **analysis.classify_attack_intent(attacker),
    }


def attack_campaigns(f: Filters, db_path=None) -> list[dict]:
    """Return candidate campaigns detected within the active filters."""
    campaigns = analysis.correlate_attack_campaigns(load_sessions(f, db_path))
    return [{key: value for key, value in row.items() if key != "members"} for row in campaigns]


def attack_campaign_detail(campaign_id: str, f: Filters, db_path=None) -> dict | None:
    """Return one campaign and its member details within the active filters."""
    for campaign in analysis.correlate_attack_campaigns(load_sessions(f, db_path)):
        if campaign["campaign_id"] == campaign_id:
            return campaign
    return None


def attacker_timeline(
    src_ip: str,
    f: Filters,
    db_path=None,
    event_type: str | None = None,
) -> dict | None:
    """Return filtered event-level records for an attacker in chronological order."""
    clauses, params = _filters(f, "e.timestamp")
    where = ["e.src_ip = ?", "e.timestamp IS NOT NULL", *clauses]
    query = database.query(
        f"""
        SELECT e.id, e.timestamp, e.session, e.eventid, e.username,
               e.command, e.duration, e.src_port
        FROM events e
        LEFT JOIN session_clusters c ON e.session = c.session
        WHERE {" AND ".join(where)}
        ORDER BY e.timestamp, e.id
        """,
        (str(src_ip), *params),
        db_path,
    )
    if query.empty:
        return None
    result = analysis.reconstruct_incident_timeline(query, event_type)
    return {"src_ip": str(src_ip), **result}


def attacker_incident(src_ip: str, f: Filters, db_path=None) -> dict | None:
    """Return the evidence-only incident summary for the filtered event history."""
    timeline = attacker_timeline(src_ip, f, db_path)
    if timeline is None:
        return None
    return {
        "src_ip": timeline["src_ip"],
        "incident_summary": timeline["incident_summary"],
        "event_count": timeline["event_count"],
        "first_seen": timeline["incident_summary"]["first_seen"],
        "last_seen": timeline["incident_summary"]["last_seen"],
    }


THREAT_HUNT_COLUMNS = [
    "timestamp", "src_ip", "event_type", "session_id", "username",
    "command", "risk_score", "risk_level",
]


def threat_hunt(
    f: Filters,
    db_path=None,
    *,
    src_ip: str | None = None,
    username: str | None = None,
    command: str | None = None,
    event_type: str | None = None,
    risk_level: str | None = None,
    limit: int | None = 50,
    offset: int = 0,
) -> dict:
    """Search recorded events, optionally returning a bounded page."""
    src_ip = src_ip.strip() if src_ip and src_ip.strip() else None
    username = username.strip() if username and username.strip() else None
    command = command.strip() if command and command.strip() else None
    clauses, params = _filters(f, "e.timestamp")
    clauses.append("e.timestamp IS NOT NULL")
    if src_ip:
        clauses.append("e.src_ip = ?")
        params.append(src_ip)
    if username:
        clauses.append("instr(lower(COALESCE(e.username, '')), lower(?)) > 0")
        params.append(username)
    if command:
        clauses.append("instr(lower(COALESCE(e.command, '')), lower(?)) > 0")
        params.append(command)
    if event_type:
        clauses.append("e.eventid = ?")
        params.append(event_type)

    risk = risk_table(load_sessions(f, db_path))
    risk_by_ip = {
        str(row["src_ip"]): {
            "risk_score": float(row["risk_score"]),
            "risk_level": str(row["risk_level"]),
        }
        for _, row in risk.iterrows()
    }
    if risk_level:
        matching_ips = sorted(
            ip for ip, values in risk_by_ip.items() if values["risk_level"] == risk_level
        )
        if matching_ips:
            clauses.append(f"e.src_ip IN ({','.join('?' for _ in matching_ips)})")
            params.extend(matching_ips)
        else:
            clauses.append("1 = 0")

    where = " AND ".join(clauses) if clauses else "1 = 1"
    total_df = database.query(
        f"""
        SELECT COUNT(*) AS total
        FROM events e
        LEFT JOIN session_clusters c ON e.session = c.session
        WHERE {where}
        """,
        tuple(params),
        db_path,
    )
    total = int(total_df.iloc[0]["total"]) if not total_df.empty else 0
    paging = ""
    query_params = list(params)
    if limit is not None:
        paging = "LIMIT ? OFFSET ?"
        query_params.extend((limit, offset))
    rows = database.query(
        f"""
        SELECT e.timestamp, e.src_ip, e.eventid AS event_type,
               e.session AS session_id, e.username, e.command
        FROM events e
        LEFT JOIN session_clusters c ON e.session = c.session
        WHERE {where}
        ORDER BY e.timestamp, e.id
        {paging}
        """,
        tuple(query_params),
        db_path,
    )
    result = records(rows)
    for row in result:
        values = risk_by_ip.get(str(row["src_ip"]))
        row["risk_score"] = values["risk_score"] if values else None
        row["risk_level"] = values["risk_level"] if values else None
    return {
        "items": result,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(result) < total,
    }


def csv_safe_cell(value):
    """Prefix spreadsheet formula-like values so they are imported as text."""
    if value is None:
        return ""
    if not isinstance(value, str):
        return value
    probe = value.lstrip(" \t\r\n")
    if probe.startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
        return "'" + value
    return value


def threat_hunt_csv(f: Filters, db_path=None, **criteria) -> str:
    """Export every matching hunt result as formula-safe CSV."""
    results = threat_hunt(f, db_path, **criteria, limit=None)
    import csv
    from io import StringIO

    output = StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(THREAT_HUNT_COLUMNS)
    for item in results["items"]:
        writer.writerow([csv_safe_cell(item.get(column)) for column in THREAT_HUNT_COLUMNS])
    return output.getvalue()


def _filtered_threat_alerts(f: Filters, db_path=None) -> list[dict]:
    clauses, params = _filters(f, "e.timestamp")
    where = ["e.timestamp IS NOT NULL", *clauses]
    events = database.query(
        f"""
        SELECT e.id, e.timestamp, e.src_ip, e.session, e.eventid,
               e.username, e.command
        FROM events e
        LEFT JOIN session_clusters c ON e.session = c.session
        WHERE {" AND ".join(where)}
        ORDER BY e.timestamp, e.id
        """,
        tuple(params),
        db_path,
    )
    return analysis.generate_threat_alerts(events)


def threat_alerts(
    f: Filters,
    db_path=None,
    *,
    severity: str | None = None,
    rule_id: str | None = None,
    source_ip: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    alerts = _filtered_threat_alerts(f, db_path)
    if severity:
        alerts = [alert for alert in alerts if alert["severity"] == severity]
    if rule_id:
        alerts = [alert for alert in alerts if alert["rule_id"] == rule_id]
    if source_ip:
        alerts = [alert for alert in alerts if alert["source_ip"] == source_ip.strip()]
    return {
        "items": alerts[offset:offset + limit],
        "total": len(alerts),
        "limit": limit,
        "offset": offset,
        "has_more": offset + limit < len(alerts),
        "rule_catalog": analysis.ALERT_RULE_CATALOG,
    }


def threat_alert_detail(alert_id: str, f: Filters, db_path=None) -> dict | None:
    return next(
        (alert for alert in _filtered_threat_alerts(f, db_path)
         if alert["alert_id"] == alert_id),
        None,
    )


def attack_graph(
    f: Filters,
    db_path=None,
    *,
    source_ip: str | None = None,
    session_id: str | None = None,
    limit: int = 120,
) -> dict:
    """Build a compact, evidence-backed graph from filtered recorded events.

    The default scope uses the six most active sources and at most 30 recent
    sessions. A source or session focus narrows the query. Edges mean only:
    IP-to-session (recorded source), session-to-command (command recorded in
    session), session-to-alert (alert aggregates that session), IP-to-technique
    (existing mapper returned evidence for source), and command-to-technique
    (the existing mapper matched that exact observed command).
    """
    node_limit = max(1, min(int(limit), 200))
    clauses, params = _filters(f, "e.timestamp")
    clauses.append("e.timestamp IS NOT NULL")
    if session_id and session_id.strip():
        clauses.append("e.session = ?")
        params.append(session_id.strip())
    if source_ip and source_ip.strip():
        clauses.append("e.src_ip = ?")
        params.append(source_ip.strip())
    where = " AND ".join(clauses)

    # Choose a bounded, stable source set when no focus is selected.
    if not source_ip and not session_id:
        source_rows = database.query(
            f"""SELECT e.src_ip, COUNT(DISTINCT e.session) AS sessions,
                       MAX(e.timestamp) AS last_seen
                FROM events e
                LEFT JOIN session_clusters c ON e.session = c.session
                WHERE {where} AND e.src_ip IS NOT NULL
                GROUP BY e.src_ip
                ORDER BY sessions DESC, last_seen DESC, e.src_ip
                LIMIT 6""",
            tuple(params), db_path,
        )
        selected_ips = [str(value) for value in source_rows["src_ip"].tolist()]
        if not selected_ips:
            return {"nodes": [], "edges": [], "scope": {"source_ip": None, "session_id": None, "limit": node_limit}}
        marks = ",".join("?" for _ in selected_ips)
        clauses.append(f"e.src_ip IN ({marks})")
        params.extend(selected_ips)
        where = " AND ".join(clauses)

    session_cap = max(1, min(30, node_limit // 4))
    sessions = database.query(
        f"""SELECT e.session, e.src_ip, MAX(e.timestamp) AS last_seen,
                   COUNT(*) AS event_count
            FROM events e
            LEFT JOIN session_clusters c ON e.session = c.session
            WHERE {where} AND e.session IS NOT NULL AND e.session != ''
            GROUP BY e.session, e.src_ip
            ORDER BY last_seen DESC, e.session
            LIMIT ?""",
        (*params, session_cap), db_path,
    )
    session_values = [str(value) for value in sessions["session"].tolist()]
    if not session_values:
        return {"nodes": [], "edges": [], "scope": {"source_ip": source_ip, "session_id": session_id, "limit": node_limit}}
    marks = ",".join("?" for _ in session_values)
    event_clauses, event_params = _filters(f, "e.timestamp")
    event_clauses.append(f"e.session IN ({marks})")
    event_params.extend(session_values)
    if source_ip and source_ip.strip():
        event_clauses.append("e.src_ip = ?")
        event_params.append(source_ip.strip())
    event_rows = database.query(
        f"""SELECT e.id, e.timestamp, e.session, e.src_ip, e.eventid, e.command
            FROM events e
            LEFT JOIN session_clusters c ON e.session = c.session
            WHERE {' AND '.join(event_clauses)}
            ORDER BY e.timestamp, e.id
            LIMIT 5000""",
        tuple(event_params), db_path,
    )
    rows = records(event_rows)
    if not rows:
        return {"nodes": [], "edges": [], "scope": {"source_ip": source_ip, "session_id": session_id, "limit": node_limit}}

    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}

    def add_node(node_id: str, node_type: str, label: str, **metadata) -> bool:
        if node_id in nodes:
            return True
        if len(nodes) >= node_limit:
            return False
        nodes[node_id] = {"id": node_id, "type": node_type, "label": label, "metadata": metadata}
        return True

    def add_edge(source: str, target: str, relationship: str, **metadata) -> None:
        if source not in nodes or target not in nodes:
            return
        edge_id = f"{relationship}|{source}|{target}"
        edges.setdefault(edge_id, {"id": edge_id, "source": source, "target": target, "relationship": relationship, "metadata": metadata})

    source_ips = sorted({str(row["src_ip"]) for row in rows if row.get("src_ip")})
    for ip in source_ips:
        add_node(f"ip:{ip}", "source_ip", ip, source_ip=ip)
    session_evidence: dict[str, dict] = {}
    for row in rows:
        session = str(row.get("session") or "")
        if not session:
            continue
        item = session_evidence.setdefault(session, {
            "first_seen": None, "last_seen": None, "event_types": set(),
        })
        timestamp = row.get("timestamp")
        if timestamp:
            item["first_seen"] = min(item["first_seen"], timestamp) if item["first_seen"] else timestamp
            item["last_seen"] = max(item["last_seen"], timestamp) if item["last_seen"] else timestamp
        if row.get("eventid"):
            item["event_types"].add(str(row["eventid"]))
    session_ip: dict[str, str] = {}
    for item in records(sessions):
        session = str(item["session"])
        ip = str(item["src_ip"]) if item.get("src_ip") else None
        evidence = session_evidence.get(session, {})
        if not ip or not add_node(f"session:{session}", "session", session,
                                  session_id=session, source_ip=ip,
                                  first_seen=evidence.get("first_seen"),
                                  last_seen=evidence.get("last_seen") or item.get("last_seen"),
                                  event_count=int(item.get("event_count") or 0),
                                  event_types=sorted(evidence.get("event_types", set()))):
            continue
        session_ip[session] = ip
        add_edge(f"ip:{ip}", f"session:{session}", "recorded_session", explanation="The events table records this session under this source IP.")

    command_sessions: dict[str, set[str]] = {}
    command_evidence: dict[str, dict] = {}
    for row in rows:
        session = str(row.get("session") or "")
        command = row.get("command")
        if row.get("eventid") != "cowrie.command.input" or not isinstance(command, str) or not command.strip():
            continue
        command = command.strip()
        command_id = "command:" + sha256(command.encode("utf-8")).hexdigest()[:16]
        command_sessions.setdefault(command_id, set()).add(session)
        evidence = command_evidence.setdefault(command_id, {"command": command[:500], "event_count": 0, "first_seen": None, "last_seen": None})
        evidence["event_count"] += 1
        timestamp = row.get("timestamp")
        if timestamp:
            evidence["first_seen"] = min(filter(None, [evidence["first_seen"], timestamp])) if evidence["first_seen"] else timestamp
            evidence["last_seen"] = max(filter(None, [evidence["last_seen"], timestamp])) if evidence["last_seen"] else timestamp
    command_cap = max(1, node_limit // 4)
    selected_commands = sorted(command_evidence.items(), key=lambda pair: (-pair[1]["event_count"], pair[0]))[:command_cap]
    for command_id, evidence in selected_commands:
        if not add_node(command_id, "command", evidence["command"], **evidence):
            continue
        for session in sorted(command_sessions[command_id]):
            add_edge(f"session:{session}", command_id, "recorded_command", explanation="This exact command was recorded in this session.")

    # Reuse the existing alert rules and attach each alert only to sessions
    # explicitly listed in its evidence scope.
    alert_rows = pd.DataFrame(rows)
    generated_alerts = analysis.generate_threat_alerts(alert_rows)
    alert_cap = max(1, node_limit // 4)
    for alert in generated_alerts[:alert_cap]:
        alert_id = f"alert:{alert['alert_id']}"
        if not add_node(alert_id, "alert", alert["rule_name"], alert_id=alert["alert_id"],
                        source_ip=alert["source_ip"], severity=alert["severity"],
                        first_seen=alert["first_seen"], last_seen=alert["last_seen"],
                        event_count=alert["event_count"], rule_id=alert["rule_id"],
                        explanation=alert["severity_rationale"], evidence=alert["evidence"]):
            continue
        for session in alert["session_ids"]:
            add_edge(f"session:{session}", alert_id, "alert_evidence", explanation="This alert aggregates qualifying recorded events from this session.")

    # Existing ATT&CK mapper determines mappings. Source links are source-level
    # aggregates; command links are added only for exact observed examples.
    for technique in mitre.map_events(event_rows):
        technique_id = technique["technique_id"]
        tech_node = f"technique:{technique_id}"
        if not add_node(tech_node, "technique", f"{technique_id} · {technique['name']}",
                        technique_id=technique_id, name=technique["name"], tactic=technique["tactic"],
                        confidence=technique["confidence"], event_count=technique["event_count"],
                        first_seen=technique["first_seen"], last_seen=technique["last_seen"],
                        rationale=technique["rationale"], official_url=technique["official_url"]):
            continue
        for source in technique["sources"]:
            ip = str(source["src_ip"])
            add_edge(f"ip:{ip}", tech_node, "mapped_source_evidence", explanation="The existing ATT&CK mapper returned matching evidence for this source.", event_count=source["event_count"], session_ids=source["session_ids"])
            source_commands = set(source["evidence_examples"])
            for command_id, evidence in command_evidence.items():
                if evidence["command"] in source_commands:
                    add_edge(command_id, tech_node, "mapped_command_evidence", explanation="The existing ATT&CK rule matched this recorded command.")

    return {
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "scope": {"source_ip": source_ip, "session_id": session_id, "limit": node_limit,
                  "sessions_included": len(session_ip),
                  "truncated": (len(sessions) >= session_cap
                                or len(command_evidence) > command_cap
                                or len(generated_alerts) > alert_cap
                                or len(nodes) >= node_limit)},
        "relationship_notes": {
            "recorded_session": "Source IP to session recorded in the events table.",
            "recorded_command": "Session to exact command recorded in that session.",
            "alert_evidence": "Session to alert whose aggregated evidence includes that session.",
            "mapped_source_evidence": "Source IP to technique returned by the existing evidence mapper.",
            "mapped_command_evidence": "Exact observed command matched by the existing evidence mapper.",
        },
    }


def similar_attackers(
    src_ip: str,
    f: Filters,
    db_path=None,
    *,
    limit: int = 5,
    offset: int = 0,
    min_similarity: float = 0,
    risk_level: str | None = None,
    search: str | None = None,
    sort_by: str = "similarity",
    sort_order: str = "desc",
) -> list[dict] | None:
    """Rank other attackers using filtered aggregate and event evidence."""
    df = load_sessions(f, db_path)
    if df.empty or str(src_ip) not in set(df["src_ip"].astype(str)):
        return None
    risk_by_ip = risk_table(df).set_index("src_ip")
    risk_dict = {
        str(ip): {"risk_score": float(row["risk_score"]), "risk_level": str(row["risk_level"])}
        for ip, row in risk_by_ip.iterrows()
    }
    clauses, params = _filters(f, "e.timestamp")
    clauses.insert(0, "e.eventid IN ('cowrie.login.failed', 'cowrie.login.success', 'cowrie.command.input')")
    event_rows = database.query(
        f"""SELECT e.timestamp, e.session, e.src_ip, e.eventid, e.username, e.command
            FROM events e
            LEFT JOIN session_clusters c ON e.session = c.session
            WHERE {' AND '.join(clauses)}
            ORDER BY e.timestamp, e.id""",
        tuple(params), db_path,
    )
    return similarity.compare_attackers(
        str(src_ip), df, event_rows, risk_dict, limit=limit, offset=offset,
        min_similarity=min_similarity, risk_level=risk_level, search=search,
        sort_by=sort_by, sort_order=sort_order,
    )

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
