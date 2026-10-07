"""SQL analytics queries. Each returns a DataFrame ready for charts/tables."""
import pandas as pd

from src.database import query

LOGIN_EVENTS = "('cowrie.login.failed', 'cowrie.login.success')"


def overview(db_path=None) -> pd.DataFrame:
    """One-row summary of the whole dataset."""
    return query("""
        SELECT
            (SELECT COUNT(*) FROM events)             AS total_events,
            COUNT(*)                                  AS total_sessions,
            COUNT(DISTINCT src_ip)                    AS unique_ips,
            COALESCE(SUM(n_failed_logins), 0)         AS failed_logins,
            COALESCE(SUM(login_success), 0)           AS successful_sessions,
            MIN(start_time)                           AS first_seen,
            MAX(start_time)                           AS last_seen
        FROM sessions
    """, db_path=db_path)


def top_usernames(n: int = 10, db_path=None) -> pd.DataFrame:
    return query(f"""
        SELECT username, COUNT(*) AS attempts
        FROM events
        WHERE eventid IN {LOGIN_EVENTS} AND username IS NOT NULL
        GROUP BY username
        ORDER BY attempts DESC
        LIMIT ?
    """, (n,), db_path)


def top_passwords(n: int = 10, db_path=None) -> pd.DataFrame:
    return query(f"""
        SELECT password, COUNT(*) AS attempts
        FROM events
        WHERE eventid IN {LOGIN_EVENTS} AND password IS NOT NULL
        GROUP BY password
        ORDER BY attempts DESC
        LIMIT ?
    """, (n,), db_path)


def top_commands(n: int = 10, db_path=None) -> pd.DataFrame:
    return query("""
        SELECT command, COUNT(*) AS times_run
        FROM events
        WHERE eventid = 'cowrie.command.input' AND command IS NOT NULL
        GROUP BY command
        ORDER BY times_run DESC
        LIMIT ?
    """, (n,), db_path)


def top_attackers(n: int = 10, db_path=None) -> pd.DataFrame:
    return query("""
        SELECT s.src_ip,
               COALESCE(i.country, 'Unknown') AS country,
               COUNT(*)                       AS sessions,
               SUM(s.n_failed_logins)         AS failed_logins,
               SUM(s.login_success)           AS successful_sessions
        FROM sessions s
        LEFT JOIN ip_intel i ON s.src_ip = i.src_ip
        GROUP BY s.src_ip
        ORDER BY sessions DESC
        LIMIT ?
    """, (n,), db_path)


def attacks_by_country(n: int = 10, db_path=None) -> pd.DataFrame:
    return query("""
        SELECT COALESCE(i.country, 'Unknown') AS country,
               COUNT(DISTINCT s.src_ip)       AS unique_ips,
               COUNT(*)                       AS sessions,
               SUM(s.n_failed_logins)         AS failed_logins
        FROM sessions s
        LEFT JOIN ip_intel i ON s.src_ip = i.src_ip
        GROUP BY country
        ORDER BY sessions DESC
        LIMIT ?
    """, (n,), db_path)


def attacks_by_day(db_path=None) -> pd.DataFrame:
    return query("""
        SELECT date(start_time)        AS day,
               COUNT(*)                AS sessions,
               SUM(n_failed_logins)    AS failed_logins
        FROM sessions
        GROUP BY day
        ORDER BY day
    """, db_path=db_path)


def attacks_by_hour(db_path=None) -> pd.DataFrame:
    return query("""
        SELECT start_hour AS hour, COUNT(*) AS sessions
        FROM sessions
        GROUP BY start_hour
        ORDER BY start_hour
    """, db_path=db_path)


def map_data(db_path=None) -> pd.DataFrame:
    """One row per attacker IP that has coordinates (for the attack map)."""
    return query("""
        SELECT i.src_ip, i.country, i.city, i.latitude, i.longitude,
               COUNT(*)               AS sessions,
               SUM(s.n_failed_logins) AS failed_logins
        FROM sessions s
        JOIN ip_intel i ON s.src_ip = i.src_ip
        WHERE i.latitude IS NOT NULL AND i.longitude IS NOT NULL
        GROUP BY i.src_ip
        ORDER BY sessions DESC
    """, db_path=db_path)