import sqlite3
from pathlib import Path

p = Path("deploy/honeypot.sqlite3")
con = sqlite3.connect(str(p))

print("DATABASE:", p.resolve())
print("SIZE:", round(p.stat().st_size / 1024 / 1024, 2), "MB")

tables = [r[0] for r in con.execute(
    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
)]
print("\nTABLES:", tables)

for table in tables:
    count = con.execute(
        f'SELECT COUNT(*) FROM "{table}"'
    ).fetchone()[0]
    print(f"{table}: {count} rows")

print("\nIP PRIVACY CHECKS")
for table in ("events", "sessions", "ip_intel", "ip_risk"):
    if table not in tables:
        continue
    cols = [r[1] for r in con.execute(f'PRAGMA table_info("{table}")')]
    if "src_ip" in cols:
        bad = con.execute(
            f'SELECT COUNT(*) FROM "{table}" '
            "WHERE src_ip IS NOT NULL AND src_ip NOT LIKE '198.51.100.%'"
        ).fetchone()[0]
        print(f"{table}: non-demo IPs = {bad}")

print("\nSENSITIVE FIELD SAMPLES")
sensitive = {
    "username", "password", "command", "usernames",
    "passwords", "commands", "commands_list"
}
for table in tables:
    cols = [r[1] for r in con.execute(f'PRAGMA table_info("{table}")')]
    for col in cols:
        if col.lower() in sensitive:
            samples = con.execute(
                f'SELECT DISTINCT "{col}" FROM "{table}" '
                f'WHERE "{col}" IS NOT NULL LIMIT 5'
            ).fetchall()
            print(f"{table}.{col}: {samples}")

con.close()
