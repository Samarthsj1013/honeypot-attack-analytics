import sqlite3
from pathlib import Path

db = Path("deploy/honeypot.sqlite3")
con = sqlite3.connect(str(db))

print("TABLE-BY-TABLE AUDIT")
tables = [r[0] for r in con.execute(
    "SELECT name FROM sqlite_master WHERE type='table' "
    "AND name NOT LIKE 'sqlite_%' ORDER BY name"
)]

for table in tables:
    info = con.execute(f'PRAGMA table_info("{table}")').fetchall()
    columns = [r[1] for r in info]
    count = con.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
    print(f"\n{table}: {count} rows")
    print("Columns:", columns)

    for col in columns:
        low = col.lower()
        if any(term in low for term in (
            "password", "username", "command", "session", "src_ip",
            "ip_address", "latitude", "longitude"
        )):
            samples = con.execute(
                f'SELECT DISTINCT "{col}" FROM "{table}" '
                f'WHERE "{col}" IS NOT NULL LIMIT 3'
            ).fetchall()
            print(f"  {col} samples: {samples}")

con.close()
