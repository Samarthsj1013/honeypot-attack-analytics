"""Central configuration for the Honeypot Attack Analytics project."""
from pathlib import Path

# ---------- Paths ----------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
SAMPLE_DIR = DATA_DIR / "sample"

RAW_LOG_FILE = RAW_DIR / "cowrie.json"            # real Cowrie logs (after deployment)
SAMPLE_LOG_FILE = SAMPLE_DIR / "cowrie_sample.json"  # simulated logs for local dev
DB_PATH = PROCESSED_DIR / "honeypot.db"
GEOIP_DB_PATH = DATA_DIR / "GeoLite2-City.mmdb"   # free download from MaxMind

# ---------- Data source toggle ----------
# True  -> use simulated sample logs (local development)
# False -> use real Cowrie logs from the honeypot
USE_SAMPLE_DATA = True

# ---------- Sample data generator ----------
SAMPLE_DAYS = 14
SAMPLE_SESSIONS = 1500
RANDOM_SEED = 42

# ---------- ML ----------
N_CLUSTERS = 3
RANDOM_STATE = 42


def get_log_path() -> Path:
    """Return the log file the pipeline should read, based on USE_SAMPLE_DATA."""
    return SAMPLE_LOG_FILE if USE_SAMPLE_DATA else RAW_LOG_FILE


def ensure_dirs() -> None:
    """Create data folders if they don't exist."""
    for d in (RAW_DIR, PROCESSED_DIR, SAMPLE_DIR):
        d.mkdir(parents=True, exist_ok=True)