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


def reconstruct_incident_timeline(events: pd.DataFrame, event_type: str | None = None) -> dict:
    """Present stored Cowrie events in order, with an evidence-only summary."""
    labels = {
        "cowrie.session.connect": "Session Connected",
        "cowrie.login.failed": "Failed Honeypot Login",
        "cowrie.login.success": "Successful Honeypot Login",
        "cowrie.command.input": "Observed Command",
        "cowrie.session.closed": "Session Closed",
    }
    download_tools_pattern = re.compile(
        r"\b(wget|curl|ftp|tftp|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|"
        r"invoke-webrequest|iwr)\b", re.IGNORECASE
    )
    if events is None:
        events = pd.DataFrame()
    data = events.copy()
    if "eventid" not in data:
        data["eventid"] = None
    if "timestamp" not in data:
        data["timestamp"] = None
    if "id" not in data:
        data["id"] = range(len(data))

    data["_time"] = pd.to_datetime(data["timestamp"], errors="coerce", utc=True)
    data = data.sort_values(["_time", "id"], kind="stable", na_position="last")
    all_events = []
    for _, row in data.iterrows():
        event_id = str(row.get("eventid") or "")
        command = row.get("command")
        command = str(command).strip() if pd.notna(command) else ""
        matches = sorted({value.lower() for value in download_tools_pattern.findall(command)})
        evidence = {}
        for column, label in (("username", "username"), ("src_port", "source_port")):
            value = row.get(column)
            if pd.notna(value) and str(value).strip():
                evidence[label] = str(value)
        if command:
            evidence["command"] = command
        duration = row.get("duration")
        if pd.notna(duration):
            evidence["duration_seconds"] = float(duration)
        if matches:
            evidence["download_tools"] = matches
        timestamp = row["_time"]
        event_pk = row["id"]
        try:
            event_pk = int(event_pk) if pd.notna(event_pk) else None
        except (TypeError, ValueError):
            event_pk = None
        all_events.append({
            "id": event_pk,
            "timestamp": timestamp.isoformat() if pd.notna(timestamp) else None,
            "session": str(row.get("session")) if pd.notna(row.get("session")) else None,
            "eventid": event_id or None,
            "event_type": labels.get(event_id, event_id or "Unknown Event"),
            "event_type_filter": event_id or None,
            "is_download_activity": bool(matches),
            "evidence": evidence,
        })

    available = sorted({event["event_type_filter"] for event in all_events if event["event_type_filter"]})
    if any(event["is_download_activity"] for event in all_events):
        available.append("download_tool")
    if event_type == "download_tool":
        visible = [event for event in all_events if event["is_download_activity"]]
    elif event_type:
        visible = [event for event in all_events if event["event_type_filter"] == event_type]
    else:
        visible = all_events

    counts = {}
    for event in all_events:
        label = event["event_type"]
        counts[label] = counts.get(label, 0) + 1
    timestamps = [event["timestamp"] for event in all_events if event["timestamp"]]
    sessions = sorted({event["session"] for event in all_events if event["session"]})
    if not all_events:
        description = "No matching honeypot events were recorded for this attacker and date/behavior filters."
    else:
        description = (
            "Summary of recorded honeypot activity only; it does not establish attacker intent "
            "or compromise of a real system."
        )
    summary = {
        "scope": (
            "Includes all events matching the active date and behavior filters; "
            "independent of the event-type filter applied to the detailed timeline."
        ),
        "event_count": len(all_events),
        "session_count": len(sessions),
        "first_seen": timestamps[0] if timestamps else None,
        "last_seen": timestamps[-1] if timestamps else None,
        "event_counts": [
            {"event_type": label, "count": count}
            for label, count in sorted(counts.items())
        ],
        "description": description,
    }
    return {
        "timeline_level": "event",
        "timestamp_precision": "seconds",
        "events": visible,
        "available_event_types": available,
        "incident_summary": summary,
        "event_count": len(all_events),
    }


ALERT_COMMAND_RULES = (
    ("shell_or_network_execution", "Shell or Network Execution",
     re.compile(r"(?:/dev/tcp|\bnc\b.*\s-[ec]\b|\bbash\s+-i\b|\bsh\s+-i\b)", re.I), "High"),
    ("destructive_file_operation", "Destructive File Operation",
     re.compile(r"\brm\s+-[a-z]*r[a-z]*f\b|\bmkfs(?:\.|\s)|\bdd\s+if=", re.I), "High"),
    ("encoded_or_persistent_execution", "Encoded or Persistent Execution",
     re.compile(r"\bbase64\s+(?:-d|--decode)\b|\bchmod\s+\+x\b|\bnohup\b|\bcrontab\b", re.I), "Medium"),
)

ALERT_DOWNLOAD_TOOL_PATTERN = re.compile(
    r"\b(wget|curl|ftp|tftp|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|"
    r"invoke-webrequest|iwr)\b", re.I
)

ALERT_RULE_CATALOG = [
    {
        "rule_id": "repeated_failed_logins",
        "rule_name": "Repeated Failed Login Attempts",
        "criteria": "At least 5 failed-login events for the same source IP within one session.",
        "severity": "Medium at 5–9 events; High at 10 or more.",
    },
    {
        "rule_id": "successful_honeypot_login",
        "rule_name": "Successful Honeypot Login",
        "criteria": "One or more cowrie.login.success events in the same source-IP session.",
        "severity": "High.",
    },
    {
        "rule_id": "suspicious_command_pattern",
        "rule_name": "Suspicious Command Pattern",
        "criteria": "Observed command matches a listed shell/network, destructive, encoded, or persistence pattern.",
        "severity": "High for shell/network execution or destructive operations; Medium for encoded/persistent execution.",
    },
    {
        "rule_id": "download_tool_activity",
        "rule_name": "Download Tool Activity",
        "criteria": "Observed command contains wget, curl, ftp, tftp, certutil, bitsadmin, Invoke-WebRequest, or iwr.",
        "severity": "Medium.",
    },
]


def generate_threat_alerts(events: pd.DataFrame) -> list[dict]:
    """Aggregate deterministic alert findings by source IP, session, and rule.

    Five or more failed logins in one session create one alert (Medium for 5–9,
    High for 10+). Any successful honeypot login is High. Download-tool and
    suspicious-command matches are Medium unless the matched command pattern
    is explicitly categorized High above. These severities are triage levels,
    not proof of intent or real-system compromise.
    """
    if events is None or events.empty or "src_ip" not in events or "eventid" not in events:
        return []

    data = events.copy()
    for field in ("session", "timestamp", "username", "command"):
        if field not in data:
            data[field] = None
    if "id" not in data:
        data["id"] = range(len(data))
    data["_time"] = pd.to_datetime(data["timestamp"], errors="coerce", utc=True)
    data = data.dropna(subset=["src_ip"])
    if data.empty:
        return []

    grouped = {}
    for _, row in data.iterrows():
        source_ip = str(row["src_ip"]).strip()
        if not source_ip:
            continue
        session = str(row["session"]) if pd.notna(row["session"]) and str(row["session"]).strip() else None
        grouped.setdefault((source_ip, session), []).append(row)

    alerts = []
    for (source_ip, session), group in sorted(
        grouped.items(), key=lambda item: (item[0][0], item[0][1] or "")
    ):
        group.sort(key=lambda row: (
            row["_time"] if pd.notna(row["_time"]) else pd.Timestamp.max.tz_localize("UTC"),
            str(row.get("id", "")),
        ))

        def add_alert(rule_id, rule_name, severity, rationale, evidence_rows, evidence):
            if not evidence_rows:
                return
            times = [row["_time"] for row in evidence_rows if pd.notna(row["_time"])]
            event_counts = {}
            for event in evidence_rows:
                event_id = str(event.get("eventid") or "unknown")
                event_counts[event_id] = event_counts.get(event_id, 0) + 1
            session_ids = [session] if session else []
            stable_key = f"{rule_id}|{source_ip}|{session or 'unknown-session'}"
            alerts.append({
                "alert_id": "alert_" + sha256(stable_key.encode("utf-8")).hexdigest()[:16],
                "source_ip": source_ip,
                "session_ids": session_ids,
                "rule_id": rule_id,
                "rule_name": rule_name,
                "severity": severity,
                "first_seen": min(times).isoformat() if times else None,
                "last_seen": max(times).isoformat() if times else None,
                "event_count": len(evidence_rows),
                "supporting_event_counts": event_counts,
                "evidence": evidence,
                "severity_rationale": rationale,
                "assessment_note": (
                    "Severity is an inferred triage priority from recorded honeypot activity. "
                    "It does not establish attacker intent, attribution, or compromise of a real system."
                ),
            })

        failed = [row for row in group if row.get("eventid") == "cowrie.login.failed"]
        if len(failed) >= 5:
            severity = "High" if len(failed) >= 10 else "Medium"
            threshold = "10 or more" if severity == "High" else "5–9"
            usernames = sorted({
                str(row["username"]) for row in failed
                if pd.notna(row.get("username")) and str(row["username"]).strip()
            })
            add_alert(
                "repeated_failed_logins", "Repeated Failed Login Attempts", severity,
                f"{threshold} failed login events in one session.",
                failed,
                {"failed_login_count": len(failed), "usernames_observed": usernames},
            )

        successful = [row for row in group if row.get("eventid") == "cowrie.login.success"]
        if successful:
            usernames = sorted({
                str(row["username"]) for row in successful
                if pd.notna(row.get("username")) and str(row["username"]).strip()
            })
            add_alert(
                "successful_honeypot_login", "Successful Honeypot Login", "High",
                "At least one successful login event was recorded by the honeypot.",
                successful,
                {"successful_honeypot_login_count": len(successful), "usernames_observed": usernames},
            )

        commands = [
            row for row in group
            if row.get("eventid") == "cowrie.command.input"
            and pd.notna(row.get("command")) and str(row.get("command")).strip()
        ]
        download_rows, download_tools, download_commands = [], set(), set()
        suspicious_rows, suspicious_commands, suspicious_matches = {}, set(), {}
        suspicious_severity = "Medium"
        for row in commands:
            command_text = str(row["command"]).strip()
            found_tools = {match.lower() for match in ALERT_DOWNLOAD_TOOL_PATTERN.findall(command_text)}
            if found_tools:
                download_rows.append(row)
                download_tools.update(found_tools)
                download_commands.add(command_text)
            for rule_id, label, pattern, severity in ALERT_COMMAND_RULES:
                if pattern.search(command_text):
                    row_id = row.get("id")
                    suspicious_rows[row_id if pd.notna(row_id) else row.name] = row
                    suspicious_commands.add(command_text)
                    suspicious_matches.setdefault(label, set()).add(command_text)
                    if severity == "High":
                        suspicious_severity = "High"

        if suspicious_rows:
            add_alert(
                "suspicious_command_pattern", "Suspicious Command Pattern", suspicious_severity,
                "Observed command text matched one or more documented command patterns; "
                "High applies when a matched pattern is categorized High.",
                list(suspicious_rows.values()),
                {
                    "commands_observed": sorted(suspicious_commands),
                    "matched_patterns": [
                        {"pattern": label, "commands": sorted(values)}
                        for label, values in sorted(suspicious_matches.items())
                    ],
                },
            )
        if download_rows:
            add_alert(
                "download_tool_activity", "Download Tool Activity", "Medium",
                "Observed command text contains a recognized download-capable tool name.",
                download_rows,
                {"download_tools_observed": sorted(download_tools),
                 "commands_observed": sorted(download_commands)},
            )

    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    return sorted(
        alerts,
        key=lambda alert: (
            alert["first_seen"] or "", severity_order.get(alert["severity"], 3),
            alert["source_ip"], alert["rule_id"], alert["alert_id"],
        ),
    )


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
        if name == "session_clusters":
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_session_clusters_session "
                "ON session_clusters(session)"
            )
