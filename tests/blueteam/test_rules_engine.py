from __future__ import annotations

from datetime import UTC, datetime, timedelta

from kaamo.blueteam.base import SecurityEvent
from kaamo.blueteam.detection.rules_engine import RulesEngine


def test_rules_engine_detects_failed_login_sequence() -> None:
    engine = RulesEngine()
    start = datetime(2026, 4, 7, 0, 0, tzinfo=UTC)
    events = []
    for index in range(5):
        events.append(
            SecurityEvent(
                event_id=f"fail-{index}",
                timestamp=start + timedelta(minutes=index),
                source="auth",
                host="srv-1",
                user="alice",
                event_type="login_fail",
                severity="medium",
                raw_payload={"source_ip": "10.0.0.5"},
            )
        )
    events.append(
        SecurityEvent(
            event_id="success-1",
            timestamp=start + timedelta(minutes=6),
            source="auth",
            host="srv-1",
            user="alice",
            event_type="login_success",
            severity="high",
            raw_payload={"source_ip": "203.0.113.10"},
        )
    )
    alerts = engine.detect(events)
    assert any(alert.name == "Brute Force To Success" for alert in alerts)

