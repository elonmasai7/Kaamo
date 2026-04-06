from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: datetime
    source: str
    host: str
    user: str | None = None
    event_type: str
    severity: str
    raw_payload: dict[str, Any]


class ModuleResult(BaseModel):
    module_name: str
    summary: str
    findings: list[dict[str, Any]] = Field(default_factory=list)
    metrics: dict[str, float] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class MITREMapping(BaseModel):
    technique_id: str
    tactic: str
    confidence: float


class SecurityContext(BaseModel):
    events: list[SecurityEvent] = Field(default_factory=list)
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    indicators_of_compromise: list[str] = Field(default_factory=list)
    attack_paths: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class BlueTeamModule(ABC):
    name: str
    description: str

    @abstractmethod
    async def analyze(self, context: SecurityContext) -> ModuleResult:
        raise NotImplementedError

