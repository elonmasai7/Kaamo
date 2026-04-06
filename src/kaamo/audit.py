from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from kaamo.logging import get_logger

logger = get_logger(__name__)


@dataclass(slots=True)
class AuditEvent:
    action: str
    actor: str
    target: str
    metadata: dict[str, Any]
    occurred_at: datetime


def write_audit_log(action: str, actor: str, target: str, **metadata: Any) -> AuditEvent:
    event = AuditEvent(
        action=action,
        actor=actor,
        target=target,
        metadata=metadata,
        occurred_at=datetime.now(UTC),
    )
    logger.info(
        "audit.event",
        action=event.action,
        actor=event.actor,
        target=event.target,
        metadata=event.metadata,
        occurred_at=event.occurred_at.isoformat(),
    )
    return event

