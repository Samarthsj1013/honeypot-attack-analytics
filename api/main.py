"""
FastAPI app exposing the honeypot analytics as JSON.

Run from the project root:
    python run_api.py

Interactive docs:
    http://127.0.0.1:8000/docs
"""

from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from api import service
from api.service import Filters


ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]


def create_app(db_path=None) -> FastAPI:
    """App factory so tests can point the API at a temporary database."""
    app = FastAPI(
        title="Honeypot Attack Analytics API",
        version="1.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_methods=["GET"],
        allow_headers=["*"],
    )

    def get_filters(
        start: date | None = None,
        end: date | None = None,
        behavior: list[str] | None = Query(default=None),
    ) -> Filters:
        if start and end and start > end:
            raise HTTPException(
                status_code=422,
                detail="start must be on or before end",
            )

        return Filters(
            start.isoformat() if start else None,
            end.isoformat() if end else None,
            behavior,
        )

    def require_db() -> None:
        missing = service.missing_tables(db_path)

        if missing:
            raise HTTPException(
                status_code=503,
                detail=(
                    f"Missing tables: {', '.join(sorted(missing))}. "
                    "Run `python run_pipeline.py` then "
                    "`python run_analysis.py`."
                ),
            )

    @app.get("/health")
    def health() -> dict:
        missing = service.missing_tables(db_path)

        return {
            "status": "ok",
            "database_ready": not missing,
            "missing_tables": sorted(missing),
        }

    router = APIRouter(
        prefix="/api",
        dependencies=[Depends(require_db)],
    )

    @router.get("/meta")
    def meta() -> dict:
        return service.meta(db_path)

    @router.get("/overview")
    def overview(f: Filters = Depends(get_filters)) -> dict:
        sessions = service.load_sessions(f, db_path)
        total_events = service.event_count(f, db_path)

        return service.overview(
            sessions,
            total_events=total_events,
        )

    @router.get("/timeline")
    def timeline(
        f: Filters = Depends(get_filters),
    ) -> list[dict]:
        return service.timeline(
            service.load_sessions(f, db_path)
        )

    @router.get("/hourly")
    def hourly(
        f: Filters = Depends(get_filters),
    ) -> list[dict]:
        return service.hourly(
            service.load_sessions(f, db_path)
        )

    @router.get("/behaviors")
    def behaviors(
        f: Filters = Depends(get_filters),
    ) -> list[dict]:
        return service.behaviors(
            service.load_sessions(f, db_path)
        )

    @router.get("/countries")
    def countries(
        f: Filters = Depends(get_filters),
        limit: int = Query(10, ge=1, le=100),
    ) -> list[dict]:
        return service.countries(
            service.load_sessions(f, db_path),
            limit,
        )

    @router.get("/map")
    def map_points(
        f: Filters = Depends(get_filters),
    ) -> list[dict]:
        return service.map_points(
            service.load_sessions(f, db_path)
        )

    @router.get("/attackers")
    def attackers(
        f: Filters = Depends(get_filters),
        limit: int = Query(25, ge=1, le=500),
    ) -> list[dict]:
        return service.attackers(
            service.load_sessions(f, db_path),
            limit,
        )

    @router.get("/attackers/{src_ip}")
    def attacker_profile(
        src_ip: str,
        f: Filters = Depends(get_filters),
    ) -> dict:
        profile = service.attacker_detail(
            src_ip,
            f,
            db_path,
        )

        if profile is None:
            raise HTTPException(
                status_code=404,
                detail="Attacker IP not found for the current filters",
            )

        return profile

    @router.get("/attackers/{src_ip}/dna")
    def attacker_dna(
        src_ip: str,
        f: Filters = Depends(get_filters),
    ) -> dict:
        dna = service.attacker_dna(
            src_ip,
            f,
            db_path,
        )

        if dna is None:
            raise HTTPException(
                status_code=404,
                detail="Attacker IP not found for the current filters",
            )

        return dna

    @router.get("/risk-levels")
    def risk_levels(
        f: Filters = Depends(get_filters),
    ) -> list[dict]:
        return service.risk_levels(
            service.load_sessions(f, db_path)
        )

    @router.get("/credentials")
    def credentials(
        kind: Literal["username", "password", "command"],
        f: Filters = Depends(get_filters),
        limit: int = Query(10, ge=1, le=100),
    ) -> list[dict]:
        return service.top_values(
            f,
            kind,
            limit,
            db_path,
        )

    app.include_router(router)

    return app


app = create_app()