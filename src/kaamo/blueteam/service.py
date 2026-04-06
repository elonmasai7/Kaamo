from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field

from kaamo.audit import write_audit_log
from kaamo.blueteam.base import SecurityContext, SecurityEvent
from kaamo.blueteam.compliance.audit import ComplianceAuditModule
from kaamo.blueteam.dashboards.soc_dashboard import SOCDashboard, SOCDashboardModule
from kaamo.blueteam.detection.event_ingest import EventIngester, SupportedFormat, iter_records
from kaamo.blueteam.detection.rules_engine import DEFAULT_RULES, DetectionAlert, DetectionRule, RulesEngine
from kaamo.blueteam.forensics.collector import ForensicsCollector, ForensicArtifact
from kaamo.blueteam.response.playbooks import ResponsePlaybook, ResponsePlaybookModule
from kaamo.blueteam.threat_intel.hunting import HuntHypothesis, ThreatHuntingModule
from kaamo.blueteam.triage.ai_triage import AITriageEngine, TriageResult
from kaamo.db.redis import RedisQueue
from kaamo.db.repositories import (
    AuditRepository,
    CoverageRepository,
    DetectionRepository,
    ForensicRepository,
    SecurityEventRepository,
)
from kaamo.logging import get_logger
from kaamo.security.validation_bridge import DetectionCoverage, ValidationBridge

logger = get_logger(__name__)


class EventIngestRequest(BaseModel):
    source: str
    event_format: SupportedFormat
    records: list[str]


class EventIngestResponse(BaseModel):
    ingested: int
    deduplicated: int
    dropped: int
    queued_for_detection: int
    event_ids: list[str] = Field(default_factory=list)


class DetectionProcessResponse(BaseModel):
    processed_event_ids: list[str]
    generated_alerts: list[dict[str, Any]]
    generated_triage: list[TriageResult]
    recommended_playbooks: list[ResponsePlaybook]
    hunt_hypotheses: list[HuntHypothesis]


class CoverageRequest(BaseModel):
    attack_paths: list[dict[str, Any]]


class ArtifactRequest(BaseModel):
    source_host: str
    name: str
    content: str


class QueueMetricsResponse(BaseModel):
    queue_depth: int
    detection_workers: int


class AlertRecord(BaseModel):
    alert_id: str
    rule_id: str
    name: str
    severity: str
    event_ids: list[str]
    host: str | None = None
    user: str | None = None
    reason: str
    mitre: dict[str, Any]
    status: str
    created_at: str


class IncidentRecord(BaseModel):
    incident_id: str
    title: str
    severity: str
    host: str | None = None
    user: str | None = None
    reason: str
    status: str
    created_at: str
    priority_score: float
    likely_attack_stage: str
    confidence: float


class FindingRecord(BaseModel):
    finding_id: str
    title: str
    severity: str
    host: str | None = None
    summary: str
    likely_attack_stage: str
    priority_score: float
    created_at: str


class ThreatHuntResponse(BaseModel):
    hypotheses: list[HuntHypothesis]
    suspicious_hosts: list[dict[str, Any]]
    recent_anomalies: list[dict[str, Any]]


class EvidenceTimelineEntry(BaseModel):
    timestamp: str
    kind: str
    title: str
    details: dict[str, Any]


@dataclass(slots=True)
class BlueTeamService:
    event_repo: SecurityEventRepository
    detection_repo: DetectionRepository
    audit_repo: AuditRepository
    forensic_repo: ForensicRepository
    coverage_repo: CoverageRepository
    queue: RedisQueue
    rules_engine: RulesEngine
    triage_engine: AITriageEngine
    playbook_module: ResponsePlaybookModule
    hunting_module: ThreatHuntingModule
    dashboard_module: SOCDashboardModule
    compliance_module: ComplianceAuditModule
    forensics_collector: ForensicsCollector
    validation_bridge: ValidationBridge

    async def initialize(self) -> None:
        await self.detection_repo.sync_rules(DEFAULT_RULES)
        await self._audit("blueteam.initialize", "system", "blueteam-service", rules=len(DEFAULT_RULES))

    async def ingest_events(self, request: EventIngestRequest, actor: str) -> EventIngestResponse:
        ingester = EventIngester(batch_size=100)
        parsed_events = [
            event
            async for event in ingester.ingest_stream(
                iter_records(request.records),
                event_format=request.event_format,
                source=request.source,
            )
        ]
        if parsed_events:
            await self.event_repo.upsert_many(parsed_events)
            for event in parsed_events:
                await self.queue.enqueue_detection({"event_ids": [event.event_id]})
        await self._audit(
            "blueteam.events.ingest",
            actor,
            request.source,
            parsed=len(parsed_events),
            deduplicated=ingester.stats.deduplicated,
            dropped=ingester.stats.dropped,
        )
        return EventIngestResponse(
            ingested=len(parsed_events),
            deduplicated=ingester.stats.deduplicated,
            dropped=ingester.stats.dropped,
            queued_for_detection=len(parsed_events),
            event_ids=[event.event_id for event in parsed_events],
        )

    async def process_detection_payload(self, payload: dict[str, Any], actor: str = "worker") -> DetectionProcessResponse:
        event_ids = [str(event_id) for event_id in payload.get("event_ids", [])]
        events = await self.event_repo.fetch_by_ids(event_ids)
        rules = await self.detection_repo.list_enabled_rules()
        engine = self.rules_engine if rules == DEFAULT_RULES else RulesEngine(rules)
        alerts = engine.detect(events)
        await self.detection_repo.upsert_alerts(alerts)
        stored_alerts = await self.detection_repo.list_alerts(limit=max(len(alerts), 1))
        triage_results: list[TriageResult] = []
        playbooks: list[ResponsePlaybook] = []
        for alert in stored_alerts[: len(alerts)]:
            triage = await self.triage_engine.triage_alert(alert)
            triage_results.append(triage)
            playbook = self.playbook_module.recommend(alert)
            if playbook is not None:
                playbooks.append(playbook)
            await self.detection_repo.upsert_triage(alert["alert_id"], triage)
        hunt_context = SecurityContext(events=events, alerts=stored_alerts[: len(alerts)])
        hypotheses = self.hunting_module.generate_hypotheses(hunt_context)
        for alert in stored_alerts[: len(alerts)]:
            await self.queue.publish_alert(alert)
        await self._audit("blueteam.detections.process", actor, "detection-engine", alerts=len(alerts), events=len(events))
        return DetectionProcessResponse(
            processed_event_ids=event_ids,
            generated_alerts=stored_alerts[: len(alerts)],
            generated_triage=triage_results,
            recommended_playbooks=playbooks,
            hunt_hypotheses=hypotheses,
        )

    async def process_detection_queue_once(self) -> DetectionProcessResponse | None:
        payload = await self.queue.dequeue_detection(timeout_seconds=1)
        if payload is None:
            return None
        return await self.process_detection_payload(payload)

    async def run_detection_worker(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                await self.process_detection_queue_once()
            except Exception as exc:  # pragma: no cover - production safety
                logger.error("blueteam.worker.failure", error=str(exc))
                await asyncio.sleep(1)

    async def list_alerts(self, limit: int = 200) -> list[AlertRecord]:
        rows = await self.detection_repo.list_alerts(limit=limit)
        return [AlertRecord.model_validate(row) for row in rows]

    async def list_incidents(
        self,
        *,
        limit: int = 200,
        severity: str | None = None,
        search: str | None = None,
        sort_by: str = "created_at",
        descending: bool = True,
    ) -> list[IncidentRecord]:
        rows = await self.detection_repo.list_incidents(
            limit=limit,
            severity=severity,
            search=search,
            sort_by=sort_by,
            descending=descending,
        )
        return [IncidentRecord.model_validate(row) for row in rows]

    async def list_findings(self, limit: int = 200) -> list[FindingRecord]:
        rows = await self.detection_repo.list_findings(limit=limit)
        return [FindingRecord.model_validate(row) for row in rows]

    async def build_dashboard(self) -> SOCDashboard:
        alerts = [alert.model_dump(mode="json") for alert in await self.list_alerts(limit=500)]
        incidents = [incident.model_dump(mode="json") for incident in await self.list_incidents(limit=500)]
        dashboard = self.dashboard_module.build_dashboard(
            SecurityContext(
                alerts=alerts,
                metadata={
                    "incidents": incidents,
                    "coverage_gap_score": await self._latest_coverage_gap(),
                },
            )
        )
        await self._audit("blueteam.dashboard.view", "system", "soc-dashboard", alerts=len(alerts))
        return dashboard

    async def collect_forensic_artifact(self, request: ArtifactRequest, actor: str) -> ForensicArtifact:
        artifact = self.forensics_collector.collect_artifact(request.model_dump())
        await self.forensic_repo.upsert_artifact(artifact)
        await self._audit("blueteam.forensics.collect", actor, artifact.artifact_id, source_host=request.source_host)
        return artifact

    async def validate_coverage(self, request: CoverageRequest, actor: str) -> list[DetectionCoverage]:
        detections = [alert.model_dump(mode="json") for alert in await self.list_alerts(limit=1000)]
        coverage = self.validation_bridge.validate(request.attack_paths, detections)
        await self.coverage_repo.upsert_coverage(coverage)
        await self._audit("blueteam.coverage.validate", actor, "validation-bridge", attack_paths=len(request.attack_paths))
        return coverage

    async def compliance_reports(self) -> list[dict[str, Any]]:
        alerts = [alert.model_dump(mode="json") for alert in await self.list_alerts(limit=500)]
        reports = self.compliance_module.generate_reports(
            SecurityContext(
                alerts=alerts,
                metadata={"analyst_actions": len(alerts), "evidence_count": 0},
            )
        )
        return [report.model_dump(mode="json") for report in reports]

    async def threat_hunting_view(self) -> ThreatHuntResponse:
        events = await self.event_repo.fetch_recent(limit=500)
        alerts = [alert.model_dump(mode="json") for alert in await self.list_alerts(limit=200)]
        hypotheses = self.hunting_module.generate_hypotheses(SecurityContext(events=events, alerts=alerts))
        suspicious_hosts: dict[str, int] = {}
        for alert in alerts:
            host = str(alert.get("host") or "unknown")
            suspicious_hosts[host] = suspicious_hosts.get(host, 0) + 1
        recent_anomalies = [
            {
                "metric": "alert_density",
                "host": host,
                "observed_value": count,
            }
            for host, count in sorted(suspicious_hosts.items(), key=lambda item: item[1], reverse=True)[:10]
        ]
        return ThreatHuntResponse(
            hypotheses=hypotheses,
            suspicious_hosts=[
                {"host": host, "alert_count": count}
                for host, count in sorted(suspicious_hosts.items(), key=lambda item: item[1], reverse=True)[:10]
            ],
            recent_anomalies=recent_anomalies,
        )

    async def evidence_timeline(self, limit: int = 200) -> list[EvidenceTimelineEntry]:
        artifacts = await self.forensic_repo.list_artifacts(limit=limit)
        audits = await self.audit_repo.list_recent(limit=limit)
        entries = [
            EvidenceTimelineEntry(
                timestamp=artifact["collected_at"],
                kind="artifact",
                title=f"{artifact['artifact_id']} on {artifact['source_host']}",
                details=artifact,
            )
            for artifact in artifacts
        ] + [
            EvidenceTimelineEntry(
                timestamp=audit["occurred_at"],
                kind="audit",
                title=f"{audit['action']} by {audit['actor']}",
                details=audit,
            )
            for audit in audits
        ]
        return sorted(entries, key=lambda entry: entry.timestamp, reverse=True)[:limit]

    async def coverage_view(self, limit: int = 100) -> list[DetectionCoverage]:
        rows = await self.coverage_repo.list_recent(limit=limit)
        return [DetectionCoverage.model_validate(row) for row in rows]

    async def queue_metrics(self, detection_workers: int) -> QueueMetricsResponse:
        return QueueMetricsResponse(
            queue_depth=await self.queue.queue_depth(),
            detection_workers=detection_workers,
        )

    async def _latest_coverage_gap(self) -> float:
        alerts = await self.list_alerts(limit=500)
        if not alerts:
            return 0.0
        with_coverage = sum(1 for alert in alerts if alert.mitre)
        return round(1 - (with_coverage / len(alerts)), 4)

    async def _audit(self, action: str, actor: str, target: str, **metadata: Any) -> None:
        write_audit_log(action, actor, target, **metadata)
        await self.audit_repo.insert(action=action, actor=actor, target=target, metadata=metadata)
