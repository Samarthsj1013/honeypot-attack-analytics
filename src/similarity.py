"""Explainable behavioral similarity for recorded honeypot activity.

Component weights are DNA 25, authentication 20, distinct commands 20,
ATT&CK overlap 15, session behavior 10, and download tools 10. Unavailable
components are removed and remaining weights are renormalized. Similarity
categories are Very High (85+), High (70+), Moderate (50+), Low (30+), and
Limited (under 30). Fewer than two comparable components produces an
Insufficient Evidence result; without direct shared evidence the result is
capped at 39. These scores describe observed behavioral overlap only.
"""

from collections import Counter
import math
import re

import pandas as pd

from src import analysis, mitre


WEIGHTS = {
    "behavioral_dna": 25,
    "authentication": 20,
    "commands": 20,
    "mitre": 15,
    "sessions": 10,
    "downloads": 10,
}
DNA_METRICS = ("login_rate", "command_rate", "download_rate", "persistence", "activity")
SESSION_METRICS = ("n_events", "duration_sec", "avg_gap_sec", "n_failed_logins", "n_commands", "login_success")
DOWNLOAD_TOOL_PATTERN = re.compile(
    r"\b(curl|wget|ftp|tftp|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|invoke-webrequest|iwr)\b",
    re.IGNORECASE,
)
TECHNIQUE_LABELS = {key: value["name"] for key, value in mitre.CATALOG.items()}


def _jaccard(left: set, right: set) -> float:
    union = left | right
    return 100.0 * len(left & right) / len(union) if union else 0.0


def _normalized_similarity(values: dict[str, float], left_ip: str, right_ip: str) -> float | None:
    if left_ip not in values or right_ip not in values:
        return None
    numeric = [float(value) for value in values.values() if pd.notna(value)]
    if not numeric:
        return None
    minimum, maximum = min(numeric), max(numeric)
    if maximum <= minimum:
        return 100.0
    return max(0.0, 100.0 * (1.0 - abs(values[left_ip] - values[right_ip]) / (maximum - minimum)))


def _mean_similarity(metric_values: dict[str, dict[str, float]], left_ip: str, right_ip: str) -> float | None:
    scores = [score for values in metric_values.values()
              if (score := _normalized_similarity(values, left_ip, right_ip)) is not None]
    return sum(scores) / len(scores) if scores else None


def compare_attackers(
    selected_ip: str,
    sessions: pd.DataFrame,
    events: pd.DataFrame,
    risk_by_ip: dict[str, dict],
    *,
    limit: int = 5,
    offset: int = 0,
    min_similarity: float = 0,
    risk_level: str | None = None,
    search: str | None = None,
    sort_by: str = "similarity",
    sort_order: str = "desc",
) -> list[dict] | None:
    """Return filtered comparisons, or ``None`` if the selected IP is absent."""
    if sessions is None or sessions.empty:
        return None
    source_column = sessions["src_ip"].astype(str)
    selected_ip = str(selected_ip)
    if selected_ip not in set(source_column):
        return None

    dna_frame = analysis.compute_attacker_dna(sessions)
    dna = {str(row["src_ip"]): row for row in dna_frame.to_dict("records")}
    metric_values = {
        metric: {str(row["src_ip"]): float(row[metric]) for row in dna_frame.to_dict("records")
                 if pd.notna(row.get(metric))}
        for metric in DNA_METRICS
    }

    source_events = events.copy() if isinstance(events, pd.DataFrame) else pd.DataFrame(events or [])
    for column in ("src_ip", "session", "eventid", "timestamp", "username", "command"):
        if column not in source_events:
            source_events[column] = None
    source_events = source_events[source_events["src_ip"].notna()].copy()
    source_events["src_ip"] = source_events["src_ip"].astype(str)

    profiles: dict[str, dict] = {}
    session_groups = sessions.assign(src_ip=source_column).groupby("src_ip", sort=True)
    for ip, group in session_groups:
        behavior_counts = (
            group["behavior"].fillna("Unclustered").astype(str).value_counts().to_dict()
            if "behavior" in group else {}
        )
        stats = {}
        for metric in SESSION_METRICS:
            column = metric
            if column in group:
                values = pd.to_numeric(group[column], errors="coerce").dropna()
                if len(values):
                    stats[metric] = float(values.mean())
        profiles[str(ip)] = {
            "sessions": int(len(group)),
            "behaviors": {str(key): int(value) for key, value in behavior_counts.items()},
            "stats": stats,
            "failed_login_events": 0,
            "successful_login_events": 0,
            "usernames": set(),
            "commands": Counter(),
            "download_tools": set(),
            "techniques": set(),
            "command_techniques": set(),
            "auth_event_types": set(),
        }

    auth_types = {"cowrie.login.failed", "cowrie.login.success"}
    for row in source_events.to_dict("records"):
        ip = str(row["src_ip"])
        if ip not in profiles:
            continue
        profile = profiles[ip]
        event_type = str(row.get("eventid") or "")
        if event_type in auth_types:
            profile["auth_event_types"].add(event_type)
            if event_type == "cowrie.login.failed":
                profile["failed_login_events"] += 1
            else:
                profile["successful_login_events"] += 1
            username = row.get("username")
            if isinstance(username, str) and username.strip():
                profile["usernames"].add(username.strip().casefold())
        if event_type == "cowrie.command.input":
            command = row.get("command")
            if isinstance(command, str) and command.strip():
                command = command.strip()
                profile["commands"][command] += 1
                profile["download_tools"].update(match.group(1).casefold() for match in DOWNLOAD_TOOL_PATTERN.finditer(command))

    mapped_techniques = mitre.map_events(source_events)
    for technique in mapped_techniques:
        for source in technique["sources"]:
            ip = str(source["src_ip"])
            if ip not in profiles:
                continue
            profiles[ip]["techniques"].add(technique["technique_id"])
            if technique["technique_id"] != "T1110.001":
                profiles[ip]["command_techniques"].add(technique["technique_id"])

    session_metric_values = {
        metric: {ip: profile["stats"][metric] for ip, profile in profiles.items() if metric in profile["stats"]}
        for metric in SESSION_METRICS
    }
    # Authentication rates are log-scaled before cross-population normalization,
    # so repeated events contribute evidence without dominating linearly.
    auth_rate_values = {}
    for metric in ("failed_login_events", "successful_login_events"):
        auth_rate_values[metric] = {
            ip: math.log1p(profile[metric] / max(profile["sessions"], 1))
            for ip, profile in profiles.items()
        }

    selected = profiles[selected_ip]
    selected_dna = dna[selected_ip]
    selected_tags = set(str(selected_dna["fingerprint"]).split("-")) - {"QUIET", "PERSIST"}
    results = []
    for candidate_ip in sorted(profiles):
        if candidate_ip == selected_ip:
            continue
        candidate = profiles[candidate_ip]
        candidate_dna = dna[candidate_ip]
        candidate_tags = set(str(candidate_dna["fingerprint"]).split("-")) - {"QUIET", "PERSIST"}
        component_scores: dict[str, float] = {}
        component_evidence: dict[str, dict] = {}

        # DNA uses existing rates, normalized within the filtered population,
        # plus overlap between the existing fingerprint activity indicators.
        if selected_tags and candidate_tags:
            metric_score = _mean_similarity(metric_values, selected_ip, candidate_ip)
            tag_score = _jaccard(selected_tags, candidate_tags)
            if metric_score is not None:
                component_scores["behavioral_dna"] = (metric_score + tag_score) / 2
                component_evidence["behavioral_dna"] = {
                    "shared_traits": sorted(selected_tags & candidate_tags),
                    "selected_traits": sorted(selected_tags),
                    "candidate_traits": sorted(candidate_tags),
                    "metric_similarity": round(metric_score, 1),
                }

        if selected["auth_event_types"] and candidate["auth_event_types"]:
            auth_metrics = [
                _normalized_similarity(auth_rate_values[metric], selected_ip, candidate_ip)
                for metric in ("failed_login_events", "successful_login_events")
            ]
            auth_scores = [score for score in auth_metrics if score is not None]
            shared_usernames = selected["usernames"] & candidate["usernames"]
            if selected["usernames"] and candidate["usernames"]:
                auth_scores.append(_jaccard(selected["usernames"], candidate["usernames"]))
            if auth_scores:
                component_scores["authentication"] = sum(auth_scores) / len(auth_scores)
                component_evidence["authentication"] = {
                    "shared_usernames": sorted(shared_usernames)[:12],
                    "selected_usernames": sorted(selected["usernames"])[:12],
                    "candidate_usernames": sorted(candidate["usernames"])[:12],
                    "shared_event_types": sorted(selected["auth_event_types"] & candidate["auth_event_types"]),
                    "selected_failed_login_events": selected["failed_login_events"],
                    "candidate_failed_login_events": candidate["failed_login_events"],
                    "selected_successful_login_events": selected["successful_login_events"],
                    "candidate_successful_login_events": candidate["successful_login_events"],
                }

        selected_commands = set(selected["commands"])
        candidate_commands = set(candidate["commands"])
        shared_commands = selected_commands & candidate_commands
        if selected_commands and candidate_commands:
            component_scores["commands"] = _jaccard(selected_commands, candidate_commands)
            component_evidence["commands"] = {
                "shared_count": len(shared_commands),
                "selected_unique_count": len(selected_commands),
                "candidate_unique_count": len(candidate_commands),
                "shared_examples": sorted(shared_commands)[:8],
                "selected_examples": sorted(selected_commands - candidate_commands)[:8],
                "candidate_examples": sorted(candidate_commands - selected_commands)[:8],
            }

        shared_techniques = selected["techniques"] & candidate["techniques"]
        if selected["techniques"] and candidate["techniques"]:
            component_scores["mitre"] = _jaccard(selected["techniques"], candidate["techniques"])
            component_evidence["mitre"] = {
                "shared_techniques": sorted(shared_techniques),
                "selected_techniques": sorted(selected["techniques"]),
                "candidate_techniques": sorted(candidate["techniques"]),
            }

        shared_behaviors = set(selected["behaviors"]) & set(candidate["behaviors"])
        session_scores = []
        if selected["behaviors"] and candidate["behaviors"]:
            session_scores.append(_jaccard(set(selected["behaviors"]), set(candidate["behaviors"])))
        session_metric_score = _mean_similarity(session_metric_values, selected_ip, candidate_ip)
        if session_metric_score is not None:
            session_scores.append(session_metric_score)
        if session_scores:
            component_scores["sessions"] = sum(session_scores) / len(session_scores)
            component_evidence["sessions"] = {
                "shared_behaviors": sorted(shared_behaviors),
                "selected": {"session_count": selected["sessions"], **selected["stats"]},
                "candidate": {"session_count": candidate["sessions"], **candidate["stats"]},
            }

        shared_download_tools = selected["download_tools"] & candidate["download_tools"]
        if selected["download_tools"] and candidate["download_tools"]:
            component_scores["downloads"] = _jaccard(selected["download_tools"], candidate["download_tools"])
            selected_download_examples = sorted(
                command for command in selected["commands"]
                if DOWNLOAD_TOOL_PATTERN.search(command)
            )[:8]
            candidate_download_examples = sorted(
                command for command in candidate["commands"]
                if DOWNLOAD_TOOL_PATTERN.search(command)
            )[:8]
            component_evidence["downloads"] = {
                "shared_tools": sorted(shared_download_tools),
                "selected_tools": sorted(selected["download_tools"]),
                "candidate_tools": sorted(candidate["download_tools"]),
                "selected_examples": selected_download_examples,
                "candidate_examples": candidate_download_examples,
            }

        shared_usernames = selected["usernames"] & candidate["usernames"]

        available_weights = {key: WEIGHTS[key] for key in component_scores}
        weight_total = sum(available_weights.values())
        weighted_score = (
            sum(component_scores[key] * available_weights[key] for key in component_scores) / weight_total
            if weight_total else 0.0
        )
        direct_overlap = bool(
            shared_commands or shared_techniques or shared_download_tools
            or shared_usernames or selected["auth_event_types"] & candidate["auth_event_types"]
        )
        sufficient = len(component_scores) >= 2 and bool(
            set(component_scores) & {"authentication", "commands", "mitre", "downloads"}
        )
        if not sufficient:
            weighted_score = 0.0
            category = "Insufficient Evidence"
        else:
            if not direct_overlap:
                weighted_score = min(weighted_score, 39.0)
            category = (
                "Very High" if weighted_score >= 85 else "High" if weighted_score >= 70
                else "Moderate" if weighted_score >= 50 else "Low" if weighted_score >= 30
                else "Limited"
            )

        reasons = []
        if shared_commands:
            reasons.append(f"{len(shared_commands)} distinct shared command(s)")
        if shared_techniques:
            reasons.append("shared mapped ATT&CK: " + ", ".join(sorted(shared_techniques)))
        if shared_usernames:
            reasons.append(f"shared attempted username(s): {', '.join(sorted(shared_usernames)[:4])}")
        if shared_download_tools:
            reasons.append("shared download tools: " + ", ".join(sorted(shared_download_tools)))
        if shared_behaviors:
            reasons.append("shared session behavior: " + ", ".join(sorted(shared_behaviors)))
        if not direct_overlap and sufficient:
            reasons.append("No direct shared command, authentication, ATT&CK, or download indicator; score capped at 39%.")
        if not sufficient:
            reasons.append("Insufficient comparable evidence for a behavioral similarity score.")

        risk = risk_by_ip.get(candidate_ip, {})
        explanation = (
            f"Weighted behavioral similarity from {len(component_scores)}/6 available components. "
            + ("Shared recorded indicators support the comparison." if direct_overlap else "Missing observations are not treated as evidence of difference.")
        )
        comparison = {
            "selected": _comparison_profile(selected_ip, selected, selected_dna, risk_by_ip.get(selected_ip, {})),
            "candidate": _comparison_profile(candidate_ip, candidate, candidate_dna, risk_by_ip.get(candidate_ip, {})),
            "shared_commands": sorted(shared_commands)[:8],
            "distinct_commands": {
                "selected": sorted(selected_commands - candidate_commands)[:8],
                "candidate": sorted(candidate_commands - selected_commands)[:8],
            },
            "shared_techniques": sorted(shared_techniques),
            "distinct_techniques": {
                "selected": sorted(selected["techniques"] - candidate["techniques"]),
                "candidate": sorted(candidate["techniques"] - selected["techniques"]),
            },
            "shared_command_categories": [TECHNIQUE_LABELS.get(key, key) for key in sorted(
                selected["command_techniques"] & candidate["command_techniques"]
            )],
            "shared_usernames": sorted(shared_usernames)[:12],
            "shared_auth_event_types": sorted(selected["auth_event_types"] & candidate["auth_event_types"]),
            "missing_components": [key for key in WEIGHTS if key not in component_scores],
        }
        effective_weights = {key: round(available_weights[key] / weight_total * 100, 1) for key in component_scores} if weight_total else {}
        result = {
            "src_ip": candidate_ip,
            "compared_src_ip": selected_ip,
            "similarity_pct": round(weighted_score, 1),
            "similarity_category": category,
            "risk_score": float(risk.get("risk_score", 0)),
            "risk_level": str(risk.get("risk_level", "Unknown")),
            "components": {
                key: {"score": round(component_scores[key], 1), "weight": WEIGHTS[key],
                      "effective_weight_pct": effective_weights[key], "evidence": component_evidence[key]}
                for key in WEIGHTS if key in component_scores
            },
            "available_components": list(component_scores),
            "effective_weights_pct": effective_weights,
            "evidence_coverage_pct": round(len(component_scores) / len(WEIGHTS) * 100, 1),
            "reasons": reasons,
            "explanation": explanation,
            "comparison": comparison,
        }
        if weighted_score < float(min_similarity):
            continue
        if risk_level and result["risk_level"] != risk_level:
            continue
        if search and search.strip().casefold() not in candidate_ip.casefold():
            continue
        results.append(result)

    sort_key = {
        "similarity": "similarity_pct",
        "risk_score": "risk_score",
        "sessions": "sessions",
    }.get(sort_by, "similarity_pct")

    def sort_value(row):
        if sort_key == "sessions":
            return int(row["comparison"]["candidate"]["sessions"])
        return float(row[sort_key])

    results.sort(key=lambda row: row["src_ip"])
    results.sort(key=sort_value, reverse=sort_order == "desc")
    return results[max(0, int(offset)):max(0, int(offset)) + max(1, int(limit))]


def _comparison_profile(ip: str, profile: dict, dna: dict, risk: dict) -> dict:
    return {
        "src_ip": ip,
        "fingerprint": str(dna.get("fingerprint") or "QUIET"),
        "risk_score": float(risk.get("risk_score", 0)),
        "risk_level": str(risk.get("risk_level", "Unknown")),
        "sessions": profile["sessions"],
        "failed_login_events": profile["failed_login_events"],
        "successful_login_events": profile["successful_login_events"],
        "auth_event_types": sorted(profile["auth_event_types"]),
        "usernames": sorted(profile["usernames"])[:12],
        "commands": sorted(profile["commands"])[:8],
        "command_count": len(profile["commands"]),
        "techniques": sorted(profile["techniques"]),
        "download_tools": sorted(profile["download_tools"]),
        "behaviors": profile["behaviors"],
        "session_statistics": profile["stats"],
    }
