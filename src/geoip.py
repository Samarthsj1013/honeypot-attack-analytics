"""
Enrich attacker IPs with country / city / coordinates using a local
MaxMind GeoLite2-City database (.mmdb file, see setup notes).

If the database file is missing, every IP is labeled "Unknown" so the rest of
the pipeline still runs. You just won't have map data until you add the file.
"""
from pathlib import Path

import pandas as pd

import config

GEO_COLUMNS = ["src_ip", "country", "country_code", "city", "latitude", "longitude"]


def _unknown(ip: str) -> dict:
    return {"src_ip": ip, "country": "Unknown", "country_code": None,
            "city": None, "latitude": None, "longitude": None}


def enrich_ips(ips, db_path=None) -> tuple[pd.DataFrame, bool]:
    """
    Look up each unique IP.

    Returns:
        (ip_intel_df, used_geoip_db) where used_geoip_db is False if the
        .mmdb file was missing and everything fell back to "Unknown".
    """
    unique_ips = sorted({str(ip) for ip in ips})
    path = Path(db_path) if db_path else config.GEOIP_DB_PATH

    if not path.exists():
        print(f"WARNING: GeoIP database not found at {path}")
        print("         All IPs will be labeled 'Unknown' (no attack map).")
        return pd.DataFrame([_unknown(ip) for ip in unique_ips], columns=GEO_COLUMNS), False

    import geoip2.database
    import geoip2.errors

    records = []
    with geoip2.database.Reader(str(path)) as reader:
        for ip in unique_ips:
            try:
                r = reader.city(ip)
                records.append({
                    "src_ip": ip,
                    "country": r.country.name or "Unknown",
                    "country_code": r.country.iso_code,
                    "city": r.city.name,
                    "latitude": r.location.latitude,
                    "longitude": r.location.longitude,
                })
            except (geoip2.errors.AddressNotFoundError, ValueError):
                records.append(_unknown(ip))

    return pd.DataFrame(records, columns=GEO_COLUMNS), True