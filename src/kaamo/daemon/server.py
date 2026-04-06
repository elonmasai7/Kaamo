from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status

from kaamo.blueteam.dashboards.soc_dashboard import SOCDashboard
from kaamo.blueteam.detection.rules_engine import RulesEngine
from kaamo.blueteam.forensics.collector import ForensicArtifact, ForensicsCollector
from kaamo.blueteam.response.playbooks import ResponsePlaybookModule
from kaamo.blueteam.dashboards.soc_dashboard import SOCDashboardModule
from kaamo.blueteam.service import (
    ArtifactRequest,
    AlertRecord,
    BlueTeamService,
    CoverageRequest,
    DetectionProcessResponse,
    EvidenceTimelineEntry,
    EventIngestRequest,
    EventIngestResponse,
    FindingRecord,
    IncidentRecord,
    QueueMetricsResponse,
    ThreatHuntResponse,
)
from kaamo.blueteam.threat_intel.hunting import ThreatHuntingModule
from kaamo.blueteam.triage.ai_triage import AITriageEngine
from kaamo.blueteam.compliance.audit import ComplianceAuditModule
from kaamo.config import settings
from kaamo.db.postgres import MigrationRunner, PostgresDatabase
from kaamo.db.redis import RedisQueue
from kaamo.db.repositories import (
    AuditRepository,
    AuthRepository,
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

    @app.get("/api/v1/blueteam/alerts", response_model=list[AlertRecord])
    async def list_alerts(
        request: Request,
        actor: AuthenticatedActor = Depends(require_authentication),
        limit: int = 200,
    ) -> list[AlertRecord]:
        del actor
        service: BlueTeamService = request.app.state.blueteam_service
        return await service.list_alerts(limit=limit)

    @app.get("/api/v1/blueteam/incidents", response_model=list[IncidentRecord])
    async def list_incidents(
        request: Request,
        actor: AuthenticatedActor = Depends(require_authentication),
        limit: int = 200,
        severity: str | None = None,
        search: str | None = None,
        sort_by: str = "created_at",
        descending: bool = True,
    ) -> list[IncidentRecord]:
        del actor
        service: BlueTeamService = request.app.state.blueteam_service
        return await service.list_incidents(
            limit=limit,
            severity=severity,
            search=search,
            sort_by=sort_by,
            descending=descending,
        )

    @app.get("/api/v1/blueteam/findings", response_model=list[FindingRecord])
    async def list_findings(
        request: Request,
        actor: AuthenticatedActor = Depends(require_authentication),
        limit: int = 200,
    ) -> list[FindingRecord]:
        del actor
        service: BlueTeamService = request.app.state.blueteam_service
        return await service.list_findings(limit=limit)

    @app.get("/api/v1/blueteam/dashboard", response_model=SOCDashboard)
    async def get_dashboard(
        request: Request,
        actor: AuthenticatedActor = Depends(require_authentication),
    ) -> SOCDashboard:
        del actor
        service: BlueTeamService = request.app.state.blueteam_service
        return await service.build_dashboard()

    @app.get("/api/v1/blueteam/threat-hunting", response_model=ThreatHuntResponse)
    async def threat_hunting(
        request: Request,
        actor: AuthenticatedActor = Depends(require_authentication),
    ) -> ThreatHuntResponse:
        del actor
        service: BlueTeamService = request.app.state.blueteam_service
        return await service.threat_hunting_view()

    @app.post("/api/v1/blueteam/forensics/artifacts", response_model=ForensicArtifact)
    async def collect_forensic_artifact(
        request_model: ArtifactRequest,
        request: Request,
        actor: AuthenticatedActor = Depends(require_analyst),
    ) -> ForensicArtifact:
        service: BlueTeamService = request.app.state.blueteam_service
        return await service.collect_forensic_artifact(request_model, actor.actor)

    @app.get("/api/v1/blueteam/evidence/timeline", response_model=list[EvidenceTimelineEntry])
    async def evidence_timeline(
        request: Request,
        actor: AuthenticatedActor = Depends(require_authentication),
        limit: int = 200,
    ) -> list[EvidenceTimelineEntry]:
        del actor
        service: BlueTeamService = request.app.state.blueteam_service
        return await service.evidence_timeline(limit=limit)

    @app.post("/api/v1/blueteam/validation/coverage", response_model=list[DetectionCoverage])
    async def validate_coverage(
        request_model: CoverageRequest,
        request: Request,
        actor: AuthenticatedActor = Depends(require_analyst),
    ) -> list[DetectionCoverage]:
        service: BlueTeamService = request.app.state.blueteam_service
        return await service.validate_coverage(request_model, actor.actor)

    @app.get("/api/v1/blueteam/validation/coverage", response_model=list[DetectionCoverage])
    async def get_coverage(
        request: Request,
        actor: AuthenticatedActor = Depends(require_authentication),
        limit: int = 100,
    ) -> list[DetectionCoverage]:
        del actor
        service: BlueTeamService = request.app.state.blueteam_service
        return await service.coverage_view(limit=limit)

    @app.get("/api/v1/blueteam/queue-metrics", response_model=QueueMetricsResponse)
    async def queue_metrics(
        request: Request,
        actor: AuthenticatedActor = Depends(require_authentication),
    ) -> QueueMetricsResponse:
        del actor
        service: BlueTeamService = request.app.state.blueteam_service
        return await service.queue_metrics(settings.detection_worker_concurrency)

    @app.get("/api/v1/blueteam/compliance/reports")
    async def compliance_reports(
        request: Request,
        actor: AuthenticatedActor = Depends(require_authentication),
    ) -> list[dict[str, object]]:
        del actor
        service: BlueTeamService = request.app.state.blueteam_service
        return await service.compliance_reports()

    @app.websocket("/ws/v1/blueteam/alerts")
    async def live_alert_stream(
        websocket: WebSocket,
        token: str | None = Query(default=None),
    ) -> None:
        if token is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        auth_repo = AuthRepository(websocket.app.state.postgres.pool)
        principal = await auth_repo.validate_token(token)
        if principal is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        await websocket.accept()
        stream = websocket.app.state.redis_queue.subscribe_alerts()
        try:
            while True:
                payload = await stream.__anext__()
                await websocket.send_json(payload)
        except StopAsyncIteration:
            await websocket.close()
        except WebSocketDisconnect:
            return
        except Exception:
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR)

    return app


app = create_app()
