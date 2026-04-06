from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request

from kaamo.blueteam.dashboards.soc_dashboard import SOCDashboard
from kaamo.blueteam.detection.rules_engine import RulesEngine
from kaamo.blueteam.forensics.collector import ForensicArtifact, ForensicsCollector
from kaamo.blueteam.response.playbooks import ResponsePlaybookModule
from kaamo.blueteam.dashboards.soc_dashboard import SOCDashboardModule
from kaamo.blueteam.service import (
    ArtifactRequest,
    BlueTeamService,
    CoverageRequest,
    DetectionProcessResponse,
    EventIngestRequest,
    EventIngestResponse,
)
from kaamo.blueteam.threat_intel.hunting import ThreatHuntingModule
from kaamo.blueteam.triage.ai_triage import AITriageEngine
from kaamo.blueteam.compliance.audit import ComplianceAuditModule
from kaamo.config import settings
from kaamo.db.postgres import MigrationRunner, PostgresDatabase
from kaamo.db.redis import RedisQueue
from kaamo.db.repositories import (
    AuditRepository,
    CoverageRepository,
    DetectionRepository,
    ForensicRepository,
    SecurityEventRepository,
)
from kaamo.inference.router import InferenceRouter
from kaamo.logging import configure_logging
from kaamo.security.auth import AuthenticatedActor, require_analyst, require_authentication
from kaamo.security.validation_bridge import DetectionCoverage, ValidationBridge

configure_logging()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    postgres = PostgresDatabase()
    await postgres.connect()
    if settings.run_migrations_on_startup:
        await MigrationRunner(postgres).migrate()
    redis_queue = RedisQueue()
    await redis_queue.connect()
    service = BlueTeamService(
        event_repo=SecurityEventRepository(postgres.pool),
        detection_repo=DetectionRepository(postgres.pool),
        audit_repo=AuditRepository(postgres.pool),
        forensic_repo=ForensicRepository(postgres.pool),
        coverage_repo=CoverageRepository(postgres.pool),
        queue=redis_queue,
        rules_engine=RulesEngine(),
        triage_engine=AITriageEngine(InferenceRouter()),
        playbook_module=ResponsePlaybookModule(),
        hunting_module=ThreatHuntingModule(),
        dashboard_module=SOCDashboardModule(),
        compliance_module=ComplianceAuditModule(),
        forensics_collector=ForensicsCollector(),
        validation_bridge=ValidationBridge(),
    )
    await service.initialize()
    stop_event = asyncio.Event()
    worker_tasks = [
        asyncio.create_task(service.run_detection_worker(stop_event))
        for _ in range(settings.detection_worker_concurrency)
    ]
    app.state.postgres = postgres
    app.state.redis_queue = redis_queue
    app.state.blueteam_service = service
    app.state.detection_worker_stop_event = stop_event
    app.state.detection_worker_tasks = worker_tasks
    try:
        yield
    finally:
        stop_event.set()
        await asyncio.gather(*worker_tasks, return_exceptions=True)
        await redis_queue.close()
        await postgres.close()


def create_app() -> FastAPI:
    app = FastAPI(title="Kaamo Daemon", version="2.0.0", lifespan=lifespan)

    @app.get("/healthz")
    async def healthcheck() -> dict[str, object]:
        return {
            "status": "ok",
            "mode": settings.mode,
            "workers": settings.detection_worker_concurrency,
        }

    @app.post("/api/v1/blueteam/events/ingest", response_model=EventIngestResponse)
    async def ingest_events(
        request_model: EventIngestRequest,
        request: Request,
        actor: AuthenticatedActor = Depends(require_analyst),
    ) -> EventIngestResponse:
        service: BlueTeamService = request.app.state.blueteam_service
        return await service.ingest_events(request_model, actor.actor)

    @app.post("/api/v1/blueteam/detections/process", response_model=DetectionProcessResponse)
    async def process_detections(
        request: Request,
        actor: AuthenticatedActor = Depends(require_analyst),
    ) -> DetectionProcessResponse:
        service: BlueTeamService = request.app.state.blueteam_service
        queued = await request.app.state.redis_queue.dequeue_detection(timeout_seconds=1)
        if queued is None:
            return DetectionProcessResponse(
                processed_event_ids=[],
                generated_alerts=[],
                generated_triage=[],
                recommended_playbooks=[],
                hunt_hypotheses=[],
            )
        return await service.process_detection_payload(queued, actor.actor)

    @app.get("/api/v1/blueteam/alerts")
    async def list_alerts(
        request: Request,
        actor: AuthenticatedActor = Depends(require_authentication),
        limit: int = 200,
    ) -> list[dict[str, object]]:
        del actor
        service: BlueTeamService = request.app.state.blueteam_service
        return await service.list_alerts(limit=limit)

    @app.get("/api/v1/blueteam/dashboard", response_model=SOCDashboard)
    async def get_dashboard(
        request: Request,
        actor: AuthenticatedActor = Depends(require_authentication),
    ) -> SOCDashboard:
        del actor
        service: BlueTeamService = request.app.state.blueteam_service
        return await service.build_dashboard()

    @app.post("/api/v1/blueteam/forensics/artifacts", response_model=ForensicArtifact)
    async def collect_forensic_artifact(
        request_model: ArtifactRequest,
        request: Request,
        actor: AuthenticatedActor = Depends(require_analyst),
    ) -> ForensicArtifact:
        service: BlueTeamService = request.app.state.blueteam_service
        return await service.collect_forensic_artifact(request_model, actor.actor)

    @app.post("/api/v1/blueteam/validation/coverage", response_model=list[DetectionCoverage])
    async def validate_coverage(
        request_model: CoverageRequest,
        request: Request,
        actor: AuthenticatedActor = Depends(require_analyst),
    ) -> list[DetectionCoverage]:
        service: BlueTeamService = request.app.state.blueteam_service
        return await service.validate_coverage(request_model, actor.actor)

    @app.get("/api/v1/blueteam/compliance/reports")
    async def compliance_reports(
        request: Request,
        actor: AuthenticatedActor = Depends(require_authentication),
    ) -> list[dict[str, object]]:
        del actor
        service: BlueTeamService = request.app.state.blueteam_service
        return await service.compliance_reports()

    return app


app = create_app()
