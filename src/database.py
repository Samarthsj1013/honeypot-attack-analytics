"""SQLite storage layer: schema, loading DataFrames, and a query helper."""
import sqlite3
from contextlib import contextmanager
from pathlib import Path

import pandas as pd

import config
from src.parser import EVENT_COLUMNS
from src.sessionizer import SESSION_COLUMNS

TS_FORMAT = "%Y-%m-%d %H:%M:%S"  # UTC; works with SQLite date()/strftime()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    session     TEXT NOT NULL,
    src_ip      TEXT NOT NULL,
    eventid     TEXT NOT NULL,
    username    TEXT,
    password    TEXT,
    command     TEXT,
    duration    REAL,
    src_port    INTEGER,
    sensor      TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    session             TEXT PRIMARY KEY,
    src_ip              TEXT NOT NULL,
    start_time          TEXT NOT NULL,
    end_time            TEXT NOT NULL,
    start_date          TEXT,
    start_hour          INTEGER,
    duration_sec        REAL,
    n_events            INTEGER,
    n_failed_logins     INTEGER,
    n_success_logins    INTEGER,
    n_commands          INTEGER,
    n_unique_usernames  INTEGER,
    n_unique_passwords  INTEGER,
    login_success       INTEGER,
    avg_gap_sec         REAL,
    has_download_cmd    INTEGER,
    commands            TEXT
);

CREATE TABLE IF NOT EXISTS ip_intel (
    src_ip        TEXT PRIMARY KEY,
    country       TEXT,
    country_code  TEXT,
    city          TEXT,
    latitude      REAL,
    longitude     REAL
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session);
CREATE INDEX IF NOT EXISTS idx_events_ip      ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_type    ON events(eventid);
CREATE INDEX IF NOT EXISTS idx_sessions_ip    ON sessions(src_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_start ON sessions(start_time);
"""


@contextmanager
def get_connection(db_path=None):
    """Open a SQLite connection, commit on success, always close."""
    path = Path(db_path) if db_path else config.DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(reset: bool = False, db_path=None) -> None:
    """Create tables. With reset=True, drop everything first (full rebuild)."""
    with get_connection(db_path) as conn:
        if reset:
            for table in ("events", "sessions", "ip_intel"):
                conn.execute(f"DROP TABLE IF EXISTS {table}")
        conn.executescript(SCHEMA)


def _append(table: str, df: pd.DataFrame, db_path=None) -> None:
    if df.empty:
        return
    with get_connection(db_path) as conn:
        df.to_sql(table, conn, if_exists="append", index=False, chunksize=1000)


def load_events(df: pd.DataFrame, db_path=None) -> None:
    out = df.copy()
    out["timestamp"] = out["timestamp"].dt.strftime(TS_FORMAT)
    _append("events", out[EVENT_COLUMNS], db_path)


def load_sessions(df: pd.DataFrame, db_path=None) -> None:
    out = df.copy()
    for col in ("start_time", "end_time"):
        out[col] = out[col].dt.strftime(TS_FORMAT)
    out["start_date"] = out["start_date"].astype(str)
    for col in ("login_success", "has_download_cmd"):
        out[col] = out[col].astype(int)
    _append("sessions", out[SESSION_COLUMNS], db_path)


def load_ip_intel(df: pd.DataFrame, db_path=None) -> None:
    _append("ip_intel", df, db_path)


def query(sql: str, params: tuple = (), db_path=None) -> pd.DataFrame:
    """Run a SELECT and return the result as a DataFrame."""
    with get_connection(db_path) as conn:
        return pd.read_sql_query(sql, conn, params=params)