"""
FastAPI app exposing the honeypot analytics as JSON.

Run from the project root:
    python run_api.py

Interactive docs:
    http://127.0.0.1:8000/docs
"""

from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Response
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

    @router.get("/source-intelligence")
    def source_intelligence(
        f: Filters = Depends(get_filters),
        country: str | None = Query(default=None, max_length=120),
        risk_level: Literal["Low", "Medium", "High", "Unknown"] | None = None,
        limit: int = Query(25, ge=1, le=100),
        offset: int = Query(0, ge=0),
        sort_by: Literal[
            "src_ip", "country", "city", "total_events", "failed_logins",
            "successful_sessions", "risk_score", "last_seen",
        ] = "total_events",
        sort_order: Literal["asc", "desc"] = "desc",
    ) -> dict:
        return service.source_intelligence(
            f, db_path, country=country, risk_level=risk_level,
            limit=limit, offset=offset, sort_by=sort_by, sort_order=sort_order,
        )

    @router.get("/threat-hunt")
    def threat_hunt(
        f: Filters = Depends(get_filters),
        src_ip: str | None = Query(default=None, max_length=45),
        username: str | None = Query(default=None, max_length=256),
        command: str | None = Query(default=None, max_length=500),
        event_type: Literal[
            "cowrie.session.connect",
            "cowrie.login.failed",
            "cowrie.login.success",
            "cowrie.command.input",
            "cowrie.session.closed",
        ] | None = None,
        risk_level: Literal["Low", "Medium", "High"] | None = None,
        limit: int = Query(50, ge=1, le=100),
        offset: int = Query(0, ge=0),
    ) -> dict:
        return service.threat_hunt(
            f, db_path, src_ip=src_ip, username=username, command=command,
            event_type=event_type, risk_level=risk_level, limit=limit, offset=offset,
        )

    @router.get("/threat-hunt/export")
    def threat_hunt_export(
        f: Filters = Depends(get_filters),
        src_ip: str | None = Query(default=None, max_length=45),
        username: str | None = Query(default=None, max_length=256),
        command: str | None = Query(default=None, max_length=500),
        event_type: Literal[
            "cowrie.session.connect",
            "cowrie.login.failed",
            "cowrie.login.success",
            "cowrie.command.input",
            "cowrie.session.closed",
        ] | None = None,
        risk_level: Literal["Low", "Medium", "High"] | None = None,
    ) -> Response:
        csv_data = service.threat_hunt_csv(
            f, db_path, src_ip=src_ip, username=username, command=command,
            event_type=event_type, risk_level=risk_level,
        )
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="threat-hunt-results.csv"'},
        )

    @router.get("/alerts")
    def threat_alerts(
        f: Filters = Depends(get_filters),
        severity: Literal["High", "Medium"] | None = None,
        rule_id: Literal[
            "repeated_failed_logins",
            "successful_honeypot_login",
            "suspicious_command_pattern",
            "download_tool_activity",
        ] | None = None,
        source_ip: str | None = Query(default=None, max_length=45),
        limit: int = Query(50, ge=1, le=100),
        offset: int = Query(0, ge=0),
    ) -> dict:
        return service.threat_alerts(
            f, db_path, severity=severity, rule_id=rule_id,
            source_ip=source_ip, limit=limit, offset=offset,
        )

    @router.get("/alerts/{alert_id}")
    def threat_alert_detail(
        alert_id: str,
        f: Filters = Depends(get_filters),
    ) -> dict:
        alert = service.threat_alert_detail(alert_id, f, db_path)
        if alert is None:
            raise HTTPException(
                status_code=404,
                detail="Alert not found for the current date and behavior filters",
            )
        return alert

    @router.get("/campaigns")
    def attack_campaigns(
        f: Filters = Depends(get_filters),
    ) -> list[dict]:
        return service.attack_campaigns(f, db_path)

    @router.get("/campaigns/{campaign_id}")
    def attack_campaign_detail(
        campaign_id: str,
        f: Filters = Depends(get_filters),
    ) -> dict:
        campaign = service.attack_campaign_detail(campaign_id, f, db_path)
        if campaign is None:
            raise HTTPException(status_code=404, detail="Candidate campaign not found for the current filters")
        return campaign

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

    @router.get("/attackers/{src_ip}/similar")
    def similar_attackers(
        src_ip: str,
        f: Filters = Depends(get_filters),
    ) -> list[dict]:
        matches = service.similar_attackers(src_ip, f, db_path)
        if matches is None:
            raise HTTPException(
                status_code=404,
                detail="Attacker IP not found for the current filters",
            )
        return matches

    @router.get("/attackers/{src_ip}/intent")
    def attacker_intent(
        src_ip: str,
        f: Filters = Depends(get_filters),
    ) -> dict:
        intent = service.attacker_intent(src_ip, f, db_path)
        if intent is None:
            raise HTTPException(
                status_code=404,
                detail="Attacker IP not found for the current filters",
            )
        return intent

    @router.get("/attackers/{src_ip}/timeline")
    def attacker_timeline(
        src_ip: str,
        f: Filters = Depends(get_filters),
        event_type: str | None = None,
    ) -> dict:
        timeline = service.attacker_timeline(src_ip, f, db_path, event_type)
        if timeline is None:
            raise HTTPException(
                status_code=404,
                detail="Attacker events not found for the current filters",
            )
        return timeline

    @router.get("/attackers/{src_ip}/incident")
    def attacker_incident(
        src_ip: str,
        f: Filters = Depends(get_filters),
    ) -> dict:
        incident = service.attacker_incident(src_ip, f, db_path)
        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Attacker events not found for the current filters",
            )
        return incident

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
