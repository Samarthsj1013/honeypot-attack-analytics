"""Offline, evidence-backed mappings from Cowrie events to ATT&CK techniques.

This small catalog intentionally covers only behaviors that can be tied to
stored event IDs or specific observed command forms. It does not infer real
system compromise, successful transfer, attribution, or adversary intent.
Technique definitions and tactic names follow the official MITRE pages linked
in the catalog; the application has no runtime dependency on those pages.
"""

from collections import defaultdict
import re


CATALOG = {
    "T1110.001": {
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
        "rationale": (
            "Repeated cowrie.login.failed events are consistent with password-guessing "
            "behavior. They show failed attempts against this honeypot only."
        ),
        "confidence_rule": "High at 5 or more failed attempts across 2 or more sessions; otherwise Moderate.",
    },
    "T1059.004": {
        "name": "Unix Shell",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/004/",
        "rationale": (
            "A recorded cowrie.command.input event contains a submitted shell command. "
            "This establishes command submission to the honeypot, not execution on a real host."
        ),
        "confidence_rule": "High at 3 or more command events across 2 or more sessions; otherwise Moderate.",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1105/",
        "rationale": (
            "A recorded curl or wget command includes a URL, indicating an attempted "
            "remote-file transfer. The honeypot event does not prove that a transfer succeeded."
        ),
        "confidence_rule": "High at 2 or more URL-bearing transfer commands across 2 or more sessions; otherwise Moderate.",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1082/",
        "rationale": "The observed command specifically requests operating-system or host information.",
        "confidence_rule": "High at 2 or more matching commands across 2 or more sessions; otherwise Moderate.",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1083/",
        "rationale": "The observed command specifically lists or searches files and directories.",
        "confidence_rule": "High at 2 or more matching commands across 2 or more sessions; otherwise Moderate.",
    },
    "T1087.001": {
        "name": "Account Discovery: Local Account",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1087/001/",
        "rationale": "The observed command specifically enumerates local account or group information.",
        "confidence_rule": "High at 2 or more matching commands across 2 or more sessions; otherwise Moderate.",
    },
    "T1033": {
        "name": "System Owner/User Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1033/",
        "rationale": "The observed command specifically asks for the current or logged-in user identity.",
        "confidence_rule": "High at 2 or more matching commands across 2 or more sessions; otherwise Moderate.",
    },
}

SCOPE_NOTE = (
    "Successful honeypot logins are not mapped to Valid Accounts because acceptance "
    "by a honeypot does not establish use of valid credentials on a real system. "
    "Scheduled-task inspection alone is not mapped to scheduled-task execution."
)


COMMAND_RULES = {
    "T1082": re.compile(
        r"(?:^|[;&|]\s*)(?:uname\b|hostname\b|systeminfo\b|lscpu\b|"
        r"cat\s+/etc/(?:os-release|issue)\b|cat\s+/proc/version\b)", re.I,
    ),
    "T1083": re.compile(
        r"(?:^|[;&|]\s*)(?:ls|find|locate|tree|stat)\b", re.I,
    ),
    "T1087.001": re.compile(
        r"(?:^|[;&|]\s*)(?:groups\b|getent\s+(?:passwd|group)\b|"
        r"cat\s+/etc/passwd\b|grep\b[^;&|]*/etc/passwd\b)", re.I,
    ),
    "T1033": re.compile(
        r"(?:^|[;&|]\s*)(?:whoami\b|who\s+am\s+i\b|id\s+-un\b)", re.I,
    ),
}
TRANSFER_COMMAND = re.compile(
    r"(?:^|[;&|]\s*)(?:wget|curl)\b[^;&|]*(?:https?://|ftp://)\S+", re.I,
)


def _confidence(technique_id: str, event_count: int, session_count: int) -> str:
    if technique_id == "T1110.001":
        return "High" if event_count >= 5 and session_count >= 2 else "Moderate"
    if technique_id == "T1105":
        return "High" if event_count >= 2 and session_count >= 2 else "Moderate"
    return "High" if event_count >= 3 and session_count >= 2 else "Moderate"


def map_events(events) -> list[dict]:
    """Map stored event rows and return deterministic technique aggregates.

    ``events`` may be a pandas DataFrame or any iterable of row mappings. Only
    event IDs, timestamps, session IDs, source IPs, and observed commands are
    consulted; missing fields are safely ignored where necessary.
    """
    if events is None:
        return []
    if hasattr(events, "to_dict"):
        rows = events.to_dict("records")
    else:
        rows = list(events)

    by_source = defaultdict(list)
    for row in rows:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("src_ip") or "Unknown")
        by_source[ip].append(row)

    aggregates = {}

    def add(ip, technique_id, matched_rows, evidence_examples):
        if not matched_rows:
            return
        key = (technique_id, ip)
        entry = aggregates.setdefault(key, {
            "technique_id": technique_id,
            "src_ip": ip,
            "event_count": 0,
            "session_ids": set(),
            "event_types": set(),
            "timestamps": [],
            "evidence_examples": set(),
        })
        entry["event_count"] += len(matched_rows)
        for row in matched_rows:
            session = row.get("session")
            if session not in (None, ""):
                entry["session_ids"].add(str(session))
            eventid = row.get("eventid")
            if eventid:
                entry["event_types"].add(str(eventid))
            timestamp = row.get("timestamp")
            if timestamp not in (None, ""):
                entry["timestamps"].append(str(timestamp))
        entry["evidence_examples"].update(str(value)[:240] for value in evidence_examples if value)

    for ip, source_rows in by_source.items():
        failed = [row for row in source_rows if row.get("eventid") == "cowrie.login.failed"]
        if len(failed) >= 2:
            add(ip, "T1110.001", failed, ["cowrie.login.failed"])

        commands = [
            row for row in source_rows
            if row.get("eventid") == "cowrie.command.input"
            and isinstance(row.get("command"), str)
            and row["command"].strip()
        ]
        if commands:
            add(ip, "T1059.004", commands, [row["command"].strip() for row in commands])
            for technique_id, pattern in COMMAND_RULES.items():
                matched = [row for row in commands if pattern.search(row["command"].strip())]
                add(ip, technique_id, matched, [row["command"].strip() for row in matched])
            transfers = [row for row in commands if TRANSFER_COMMAND.search(row["command"].strip())]
            add(ip, "T1105", transfers, [row["command"].strip() for row in transfers])

    techniques = defaultdict(list)
    for (technique_id, ip), aggregate in aggregates.items():
        timestamps = sorted(aggregate.pop("timestamps"))
        sessions = sorted(aggregate.pop("session_ids"))
        examples = sorted(aggregate.pop("evidence_examples"))[:5]
        aggregate["session_ids"] = sessions
        aggregate["event_types"] = sorted(aggregate["event_types"])
        aggregate["evidence_examples"] = examples
        aggregate["first_seen"] = timestamps[0] if timestamps else None
        aggregate["last_seen"] = timestamps[-1] if timestamps else None
        aggregate["confidence"] = _confidence(technique_id, aggregate["event_count"], len(sessions))
        techniques[technique_id].append(aggregate)

    results = []
    for technique_id, sources in techniques.items():
        metadata = CATALOG[technique_id]
        sources.sort(key=lambda item: item["src_ip"])
        timestamps = [value for source in sources for value in (source["first_seen"], source["last_seen"]) if value]
        results.append({
            "technique_id": technique_id,
            "name": metadata["name"],
            "tactic": metadata["tactic"],
            "official_url": metadata["url"],
            "rationale": metadata["rationale"],
            "confidence_rule": metadata["confidence_rule"],
            "event_count": sum(source["event_count"] for source in sources),
            "source_count": len(sources),
            "confidence": "High" if any(source["confidence"] == "High" for source in sources) else "Moderate",
            "first_seen": min(timestamps) if timestamps else None,
            "last_seen": max(timestamps) if timestamps else None,
            "evidence_examples": sorted({example for source in sources for example in source["evidence_examples"]})[:8],
            "session_ids": sorted({session for source in sources for session in source["session_ids"]}),
            "sources": sources,
        })
    return sorted(results, key=lambda item: (-item["event_count"], -item["source_count"], item["technique_id"]))
