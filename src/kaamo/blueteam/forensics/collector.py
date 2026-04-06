from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from kaamo.audit import write_audit_log
from kaamo.blueteam.base import BlueTeamModule, ModuleResult, SecurityContext
from kaamo.config import settings


class ForensicArtifact(BaseModel):
    artifact_id: str
    source_host: str
    collected_at: datetime
    sha256: str
    evidence_path: str


class ForensicsCollector(BlueTeamModule):
    name = "forensics_collector"
    description = "Immutable forensic artifact preservation and indexing"

    def __init__(self, evidence_dir: Path | None = None) -> None:
        self._evidence_dir = evidence_dir or (settings.home_dir / "evidence")
        self._evidence_dir.mkdir(parents=True, exist_ok=True)

    async def analyze(self, context: SecurityContext) -> ModuleResult:
        payloads = context.metadata.get("forensic_payloads", [])
        artifacts = [self.collect_artifact(dict(item)) for item in payloads]
        write_audit_log("blueteam.forensics.analyze", "system", self.name, artifact_count=len(artifacts))
        return ModuleResult(
            module_name=self.name,
            summary=f"Preserved {len(artifacts)} forensic artifacts immutably.",
            findings=[artifact.model_dump(mode="json") for artifact in artifacts],
            metrics={"artifacts": float(len(artifacts))},
        )

    def collect_artifact(self, payload: dict[str, Any]) -> ForensicArtifact:
        source_host = str(payload.get("source_host", "unknown-host"))
        name = str(payload.get("name", "artifact"))
        content = str(payload.get("content", "")).encode("utf-8")
        digest = hashlib.sha256(content).hexdigest()
        path = self._evidence_dir / f"{digest}-{name}.txt"
        if not path.exists():
            path.write_bytes(content)
            path.chmod(0o400)
        artifact = ForensicArtifact(
            artifact_id=digest[:16],
            source_host=source_host,
            collected_at=datetime.now(UTC),
            sha256=digest,
            evidence_path=str(path),
        )
        write_audit_log("blueteam.forensics.collect", "system", artifact.artifact_id, source_host=source_host)
        return artifact

