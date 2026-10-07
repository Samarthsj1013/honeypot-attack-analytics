"""
Start the API server (development mode, auto-reload on code changes).

Binds to 127.0.0.1 only, so it is reachable from your own machine and nothing else.

Usage:
    python run_api.py
Then open http://127.0.0.1:8000/docs
"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=True)