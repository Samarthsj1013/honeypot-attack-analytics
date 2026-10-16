from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
SAMPLE_DIR = DATA_DIR / "sample"

RAW_LOG_FILE = RAW_DIR / "cowrie.json"
SAMPLE_LOG_FILE = SAMPLE_DIR / "cowrie_sample.json"
DB_PATH = Path(os.getenv("HONEYPOT_DB_PATH", str(PROCESSED_DIR / "honeypot.db")))
GEOIP_DB_PATH = DATA_DIR / "GeoLite2-City.mmdb"

USE_SAMPLE_DATA = True
SAMPLE_DAYS = 14
SAMPLE_SESSIONS = 1500
RANDOM_SEED = 42

N_CLUSTERS = 3
RANDOM_STATE = 42


def get_log_path() -> Path:
    return SAMPLE_LOG_FILE if USE_SAMPLE_DATA else RAW_LOG_FILE


def ensure_dirs() -> None:
    for directory in (RAW_DIR, PROCESSED_DIR, SAMPLE_DIR):
        directory.mkdir(parents=True, exist_ok=True)
