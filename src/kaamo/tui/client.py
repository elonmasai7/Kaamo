from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any, cast
from urllib.parse import urlparse

import httpx
import websockets
from pydantic import BaseModel, ConfigDict

from kaamo.blueteam.dashboards.soc_dashboard import SOCDashboard
from kaamo.blueteam.service import (
    AlertRecord,
    EvidenceTimelineEntry,
    FindingRecord,
    IncidentRecord,
    QueueMetricsResponse,
    ThreatHuntResponse,
)
from kaamo.security.validation_bridge import DetectionCoverage


class DashboardSnapshot(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    dashboard: SOCDashboard
    alerts: list[AlertRecord]
    incidents: list[IncidentRecord]
    findings: list[FindingRecord]
    threat_hunt: ThreatHuntResponse
    evidence_timeline: list[EvidenceTimelineEntry]
    coverage: list[DetectionCoverage]
    queue_metrics: QueueMetricsResponse


class KaamoTuiClient:
    def __init__(
        self,
        *,
        token: str,
        base_url: str,
        uds_path: str | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._token = token
        self._base_url = base_url.rstrip("/")
        self._uds_path = uds_path
        self._timeout = timeout_seconds
        self._client: httpx.AsyncClient | None = None

    async def connect(self) -> None:
        if self._client is not None:
            return
        transport = httpx.AsyncHTTPTransport(uds=self._uds_path) if self._uds_path else None
        self._client = httpx.AsyncClient(
            base_url=self._base_url if not self._uds_path else "http://kaamod",
            timeout=self._timeout,
            transport=transport,
            headers={"Authorization": f"Bearer {self._token}"},
        )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def websocket_enabled(self) -> bool:
        return self._uds_path is None and self._base_url.startswith(("http://", "https://"))

    def websocket_url(self) -> str:
        parsed = urlparse(self._base_url)
        scheme = "wss" if parsed.scheme == "https" else "ws"
        host = parsed.netloc
        return f"{scheme}://{host}/ws/v1/blueteam/alerts?token={self._token}"

    async def fetch_dashboard_snapshot(self) -> DashboardSnapshot:
        results = await asyncio.gather(
            self.fetch_dashboard(),
            self.fetch_alerts(),
            self.fetch_incidents(),
            self.fetch_findings(),
            self.fetch_threat_hunt(),
            self.fetch_evidence_timeline(),
            self.fetch_coverage(),
            self.fetch_queue_metrics(),
        )
        dashboard = cast(SOCDashboard, results[0])
        alerts = cast(list[AlertRecord], results[1])
        incidents = cast(list[IncidentRecord], results[2])
        findings = cast(list[FindingRecord], results[3])
        threat_hunt = cast(ThreatHuntResponse, results[4])
        evidence = cast(list[EvidenceTimelineEntry], results[5])
        coverage = cast(list[DetectionCoverage], results[6])
        queue_metrics = cast(QueueMetricsResponse, results[7])
        return DashboardSnapshot(
            dashboard=dashboard,
            alerts=alerts,
            incidents=incidents,
            findings=findings,
            threat_hunt=threat_hunt,
            evidence_timeline=evidence,
            coverage=coverage,
            queue_metrics=queue_metrics,
        )

    async def fetch_dashboard(self) -> SOCDashboard:
        return SOCDashboard.model_validate(await self._get_json("/api/v1/blueteam/dashboard"))

    async def fetch_alerts(self) -> list[AlertRecord]:
        payload = await self._get_json("/api/v1/blueteam/alerts")
        return [AlertRecord.model_validate(item) for item in cast(list[dict[str, Any]], payload)]

    async def fetch_incidents(self) -> list[IncidentRecord]:
        payload = await self._get_json("/api/v1/blueteam/incidents")
        return [IncidentRecord.model_validate(item) for item in cast(list[dict[str, Any]], payload)]

    async def fetch_findings(self) -> list[FindingRecord]:
        payload = await self._get_json("/api/v1/blueteam/findings")
        return [FindingRecord.model_validate(item) for item in cast(list[dict[str, Any]], payload)]

    async def fetch_threat_hunt(self) -> ThreatHuntResponse:
        return ThreatHuntResponse.model_validate(await self._get_json("/api/v1/blueteam/threat-hunting"))

    async def fetch_evidence_timeline(self) -> list[EvidenceTimelineEntry]:
        payload = await self._get_json("/api/v1/blueteam/evidence/timeline")
        return [EvidenceTimelineEntry.model_validate(item) for item in cast(list[dict[str, Any]], payload)]

    async def fetch_coverage(self) -> list[DetectionCoverage]:
        payload = await self._get_json("/api/v1/blueteam/validation/coverage")
        return [DetectionCoverage.model_validate(item) for item in cast(list[dict[str, Any]], payload)]

    async def fetch_queue_metrics(self) -> QueueMetricsResponse:
        return QueueMetricsResponse.model_validate(await self._get_json("/api/v1/blueteam/queue-metrics"))

    async def stream_alerts(self, stop_event: asyncio.Event) -> AsyncIterator[AlertRecord]:
        if not self.websocket_enabled:
            return
        while not stop_event.is_set():
            try:
                async with websockets.connect(self.websocket_url(), open_timeout=self._timeout, close_timeout=self._timeout) as websocket:
                    async for message in websocket:
                        if stop_event.is_set():
                            return
                        yield AlertRecord.model_validate_json(message)
            except Exception:
                await asyncio.sleep(1.5)

    async def _get_json(self, path: str) -> Any:
        if self._client is None:
            raise RuntimeError("KaamoTuiClient.connect() must be called before making requests")
        response = await self._client.get(path)
        response.raise_for_status()
        return response.json()
