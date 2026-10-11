"""IP risk scoring, credential analysis and table-saving helpers."""
import re
from hashlib import sha256

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


def correlate_attack_campaigns(sessions: pd.DataFrame) -> list[dict]:
    """Group candidate campaigns from shared, observed session behavior.

    Geography and risk scores are excluded. A pair needs multiple shared
    command patterns, or corroborating behavior plus activity/timing evidence.
    """
    if sessions is None or sessions.empty or "src_ip" not in sessions:
        return []

    tool_pattern = re.compile(
        r"\b(wget|curl|ftp|tftp|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|"
        r"invoke-webrequest|iwr)\b", re.IGNORECASE
    )
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    url_pattern = re.compile(r"https?://\S+", re.IGNORECASE)
    token_pattern = re.compile(r"\b[a-f0-9]{12,}\b", re.IGNORECASE)

    profiles = {}
    for ip, rows in sessions.dropna(subset=["src_ip"]).groupby("src_ip", sort=True):
        ip = str(ip)
        commands, tools, raw_commands = set(), set(), set()
        for value in rows.get("commands", pd.Series(dtype=str)).dropna().astype(str):
            for command in re.split(r"\s+;\s+", value):
                command = " ".join(command.strip().lower().split())
                if not command:
                    continue
                raw_commands.add(command)
                tools.update(match.lower() for match in tool_pattern.findall(command))
                normalized = url_pattern.sub("<url>", command)
                normalized = ip_pattern.sub("<ip>", normalized)
                normalized = token_pattern.sub("<token>", normalized)
                commands.add(normalized)

        behaviors = set(
            rows.get("behavior", pd.Series(dtype=str)).dropna().astype(str).str.strip()
        ) - {"", "Unclustered"}

        def metric(column, aggregation):
            if column not in rows:
                return None
            values = pd.to_numeric(rows[column], errors="coerce").dropna()
            return float(aggregation(values)) if not values.empty else None

        times = pd.to_datetime(
            rows.get("start_time", pd.Series(dtype=object)), errors="coerce", utc=True
        ).dropna()
        profiles[ip] = {
            "commands": commands, "raw_commands": raw_commands, "tools": tools,
            "behaviors": behaviors,
            "activity": {
                "events_per_session": metric("n_events", lambda values: values.mean()),
                "commands_per_session": metric("n_commands", lambda values: values.mean()),
                "failed_logins_per_session": metric("n_failed_logins", lambda values: values.mean()),
                "median_duration_sec": metric("duration_sec", lambda values: values.median()),
                "mean_event_gap_sec": metric("avg_gap_sec", lambda values: values.mean()),
            },
            "rows": rows, "first_seen": times.min() if not times.empty else None,
            "last_seen": times.max() if not times.empty else None,
        }

    def activity_similarity(left, right):
        similarities, has_timing = [], False
        for key, a in left["activity"].items():
            b = right["activity"][key]
            if a is None or b is None:
                continue
            if a == 0 and b == 0:
                continue
            if key in {"median_duration_sec", "mean_event_gap_sec"}:
                has_timing = True
            scale = max(abs(a), abs(b), 1.0)
            similarities.append(max(0.0, 1.0 - abs(a - b) / scale))
        return has_timing and len(similarities) >= 2 and sum(similarities) / len(similarities) >= 0.8

    parents = {ip: ip for ip in profiles}

    def find(ip):
        while parents[ip] != ip:
            parents[ip] = parents[parents[ip]]
            ip = parents[ip]
        return ip

    pair_evidence = []
    ips = sorted(profiles)
    for index, ip in enumerate(ips):
        for other_ip in ips[index + 1:]:
            left, right = profiles[ip], profiles[other_ip]
            shared_commands = left["commands"] & right["commands"]
            shared_tools = left["tools"] & right["tools"]
            shared_behaviors = left["behaviors"] & right["behaviors"]
            similar_activity = activity_similarity(left, right)
            qualifies = (
                len(shared_commands) >= 2
                or (bool(shared_commands) and bool(shared_behaviors) and similar_activity)
                or (not shared_commands and bool(shared_tools) and bool(shared_behaviors) and similar_activity)
            )
            if not qualifies:
                continue
            pair_evidence.append((ip, other_ip, shared_commands, shared_tools, shared_behaviors, similar_activity))
            root_a, root_b = find(ip), find(other_ip)
            if root_a != root_b:
                parents[max(root_a, root_b)] = min(root_a, root_b)

    components = {}
    for ip in ips:
        components.setdefault(find(ip), []).append(ip)
    campaigns = []
    for members in components.values():
        if len(members) < 2:
            continue
        member_set = set(members)
        pairs = [pair for pair in pair_evidence if pair[0] in member_set and pair[1] in member_set]
        indicators = {}
        for ip, other_ip, shared_commands, shared_tools, shared_behaviors, similar_activity in pairs:
            for kind, values in (("command_pattern", shared_commands), ("download_tool", shared_tools),
                                 ("behavior", shared_behaviors)):
                for value in values:
                    item = indicators.setdefault((kind, value), {"ips": set(), "pairs": 0})
                    item["ips"].update((ip, other_ip))
                    item["pairs"] += 1
            if similar_activity:
                item = indicators.setdefault(("activity_timing", "Similar session activity and timing"),
                                             {"ips": set(), "pairs": 0})
                item["ips"].update((ip, other_ip))
                item["pairs"] += 1

        shared_indicators = [
            {"type": kind, "value": value, "attacker_count": len(item["ips"]), "pair_count": item["pairs"]}
            for (kind, value), item in sorted(indicators.items())
        ]
        evidence = []
        for item in shared_indicators:
            labels = {"command_pattern": "Shared command pattern observed",
                      "download_tool": "Shared download tool observed",
                      "behavior": "Shared behavior classification"}
            evidence.append(f"{labels.get(item['type'], item['value'])}: {item['value']}"
                            if item["type"] != "activity_timing" else item["value"])
        strong = sum(item["type"] == "command_pattern" for item in shared_indicators) >= 2
        timestamps = [profiles[ip][key] for ip in members for key in ("first_seen", "last_seen")
                      if profiles[ip][key] is not None]
        member_details = []
        for ip in members:
            profile = profiles[ip]
            member_details.append({
                "src_ip": ip, "sessions": int(len(profile["rows"])),
                "first_seen": profile["first_seen"].isoformat() if profile["first_seen"] is not None else None,
                "last_seen": profile["last_seen"].isoformat() if profile["last_seen"] is not None else None,
                "behaviors": sorted(profile["behaviors"]), "commands": sorted(profile["raw_commands"])[:5],
            })
        campaigns.append({
            "campaign_id": "campaign_" + sha256("|".join(members).encode("utf-8")).hexdigest()[:12],
            "label": "Candidate Campaign", "attacker_count": len(members), "member_ips": members,
            "first_seen": min(timestamps).isoformat() if timestamps else None,
            "last_seen": max(timestamps).isoformat() if timestamps else None,
            "shared_indicators": shared_indicators, "evidence": evidence,
            "explanation": (
                "These attackers are grouped because their filtered honeypot sessions share multiple "
                "behavioral indicators listed here. Shared behavior does not establish common ownership, "
                "coordination, or attribution."
            ),
            "confidence_level": "High" if strong else "Medium",
            "confidence_note": "Qualitative evidence strength reflects the variety of shared observed indicators.",
            "members": member_details,
        })
    return sorted(campaigns, key=lambda row: (row["first_seen"] or "", row["campaign_id"]))


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
