"""Start the FastAPI server locally or on Render."""
import os
import shutil
from pathlib import Path

import uvicorn


if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent

    if os.getenv("RENDER"):
        seed = base_dir / "deploy" / "honeypot.sqlite3"
        runtime_db = Path("/tmp/honeypot.db")

        if not seed.is_file():
            raise FileNotFoundError(f"Database seed not found: {seed}")

        shutil.copy2(seed, runtime_db)
        os.environ["HONEYPOT_DB_PATH"] = str(runtime_db)

    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
    )
