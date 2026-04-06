from __future__ import annotations

import hashlib
import secrets
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import asyncpg

from kaamo.blueteam.base import SecurityEvent
from kaamo.blueteam.detection.rules_engine import DetectionAlert, DetectionRule
from kaamo.blueteam.forensics.collector import ForensicArtifact
from kaamo.blueteam.triage.ai_triage import TriageResult
from kaamo.security.validation_bridge import DetectionCoverage


class AuditRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def insert(
        self,
        *,
        action: str,
        actor: str,
        target: str,
        metadata: dict[str, Any],
    ) -> None:
        await self._pool.execute(
            """
            INSERT INTO audit_logs(action, actor, target, metadata, occurred_at)
            VALUES($1, $2, $3, $4::jsonb, NOW())
            """,
            action,
            actor,
            target,
            metadata,
        )

    async def list_recent(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = await self._pool.fetch(
            """
            SELECT action, actor, target, metadata, occurred_at
            FROM audit_logs
            ORDER BY occurred_at DESC
            LIMIT $1
            """,
            limit,
        )
        return [
            {
                "action": row["action"],
                "actor": row["actor"],
                "target": row["target"],
                "metadata": row["metadata"],
                "occurred_at": row["occurred_at"].isoformat(),
            }
            for row in rows
        ]


class SecurityEventRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def upsert_many(self, events: Sequence[SecurityEvent]) -> None:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.executemany(
                    """
                    INSERT INTO security_events(
                        event_id, timestamp, source, host, user_name, event_type, severity, raw_payload, ingested_at
                    )
                    VALUES($1, $2, $3, $4, $5, $6, $7, $8::jsonb, NOW())
                    ON CONFLICT (event_id) DO UPDATE SET
                        timestamp = EXCLUDED.timestamp,
                        source = EXCLUDED.source,
                        host = EXCLUDED.host,
                        user_name = EXCLUDED.user_name,
                        event_type = EXCLUDED.event_type,
                        severity = EXCLUDED.severity,
                        raw_payload = EXCLUDED.raw_payload
                    """,
                    [
                        (
                            event.event_id,
                            event.timestamp,
                            event.source,
                            event.host,
                            event.user,
                            event.event_type,
                            event.severity,
                            event.raw_payload,
                        )
                        for event in events
                    ],
                )

    async def fetch_by_ids(self, event_ids: Sequence[str]) -> list[SecurityEvent]:
        if not event_ids:
            return []
        rows = await self._pool.fetch(
            """
            SELECT event_id, timestamp, source, host, user_name, event_type, severity, raw_payload
            FROM security_events
            WHERE event_id = ANY($1::text[])
            ORDER BY timestamp ASC
            """,
            list(event_ids),
        )
        return [
            SecurityEvent(
                event_id=row["event_id"],
                timestamp=row["timestamp"],
                source=row["source"],
                host=row["host"],
                user=row["user_name"],
                event_type=row["event_type"],
                severity=row["severity"],
                raw_payload=row["raw_payload"],
            )
            for row in rows
        ]

    async def fetch_recent(self, limit: int = 500) -> list[SecurityEvent]:
        rows = await self._pool.fetch(
            """
            SELECT event_id, timestamp, source, host, user_name, event_type, severity, raw_payload
            FROM security_events
            ORDER BY timestamp DESC
            LIMIT $1
            """,
            limit,
        )
        return [
            SecurityEvent(
                event_id=row["event_id"],
                timestamp=row["timestamp"],
                source=row["source"],
                host=row["host"],
                user=row["user_name"],
                event_type=row["event_type"],
                severity=row["severity"],
                raw_payload=row["raw_payload"],
            )
            for row in rows
        ]


class DetectionRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def sync_rules(self, rules: Sequence[DetectionRule]) -> None:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.executemany(
                    """
                    INSERT INTO detection_rules(rule_id, name, condition, severity, enabled, updated_at)
                    VALUES($1, $2, $3, $4, $5, NOW())
                    ON CONFLICT (rule_id) DO UPDATE SET
                        name = EXCLUDED.name,
                        condition = EXCLUDED.condition,
                        severity = EXCLUDED.severity,
                        enabled = EXCLUDED.enabled,
                        updated_at = NOW()
                    """,
                    [
                        (rule.rule_id, rule.name, rule.condition, rule.severity, rule.enabled)
                        for rule in rules
                    ],
                )

    async def list_enabled_rules(self) -> list[DetectionRule]:
        rows = await self._pool.fetch(
            """
            SELECT rule_id, name, condition, severity, enabled
            FROM detection_rules
            WHERE enabled = TRUE
            ORDER BY rule_id
            """
        )
        return [DetectionRule(**dict(row)) for row in rows]

    async def upsert_alerts(self, alerts: Sequence[DetectionAlert]) -> None:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.executemany(
                    """
                    INSERT INTO detection_alerts(
                        alert_id, rule_id, name, severity, event_ids, host, user_name, reason,
                        mitre_technique_id, mitre_tactic, mitre_confidence, status, created_at
                    )
                    VALUES($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11, 'open', NOW())
                    ON CONFLICT (alert_id) DO UPDATE SET
                        severity = EXCLUDED.severity,
                        event_ids = EXCLUDED.event_ids,
                        host = EXCLUDED.host,
                        user_name = EXCLUDED.user_name,
                        reason = EXCLUDED.reason,
                        mitre_technique_id = EXCLUDED.mitre_technique_id,
                        mitre_tactic = EXCLUDED.mitre_tactic,
                        mitre_confidence = EXCLUDED.mitre_confidence
                    """,
                    [
                        (
                            self._alert_id(alert),
                            alert.rule_id,
                            alert.name,
                            alert.severity,
                            alert.event_ids,
                            alert.host,
                            alert.user,
                            alert.reason,
                            alert.mitre.technique_id if alert.mitre else None,
                            alert.mitre.tactic if alert.mitre else None,
                            alert.mitre.confidence if alert.mitre else None,
                        )
                        for alert in alerts
                    ],
                )

    async def list_alerts(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = await self._pool.fetch(
            """
            SELECT alert_id, rule_id, name, severity, event_ids, host, user_name, reason,
                   mitre_technique_id, mitre_tactic, mitre_confidence, status, created_at
            FROM detection_alerts
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )
        return [
            {
                "alert_id": row["alert_id"],
                "rule_id": row["rule_id"],
                "name": row["name"],
                "severity": row["severity"],
                "event_ids": row["event_ids"],
                "host": row["host"],
                "user": row["user_name"],
                "reason": row["reason"],
                "mitre": {
                    "technique_id": row["mitre_technique_id"],
                    "tactic": row["mitre_tactic"],
                    "confidence": row["mitre_confidence"],
                }
                if row["mitre_technique_id"] is not None
                else {},
                "status": row["status"],
                "created_at": row["created_at"].isoformat(),
            }
            for row in rows
        ]

    async def list_incidents(
        self,
        *,
        limit: int = 200,
        severity: str | None = None,
        search: str | None = None,
        sort_by: str = "created_at",
        descending: bool = True,
    ) -> list[dict[str, Any]]:
        allowed_sort_columns = {"created_at", "severity", "priority_score", "host"}
        order_column = sort_by if sort_by in allowed_sort_columns else "created_at"
        order_direction = "DESC" if descending else "ASC"
        clauses = ["1=1"]
        params: list[Any] = []
        if severity:
            params.append(severity)
            clauses.append(f"a.severity = ${len(params)}")
        if search:
            params.append(f"%{search.lower()}%")
            clauses.append(
                f"(LOWER(a.name) LIKE ${len(params)} OR LOWER(COALESCE(a.host, '')) LIKE ${len(params)} "
                f"OR LOWER(COALESCE(a.user_name, '')) LIKE ${len(params)} OR LOWER(a.reason) LIKE ${len(params)})"
            )
        params.append(limit)
        where_clause = " AND ".join(clauses)
        rows = await self._pool.fetch(
            f"""
            SELECT a.alert_id, a.name, a.severity, a.host, a.user_name, a.reason, a.status, a.created_at,
                   COALESCE(t.priority_score, 0.0) AS priority_score,
                   COALESCE(t.likely_attack_stage, 'untriaged') AS likely_attack_stage,
                   COALESCE(t.confidence, 0.0) AS confidence
            FROM detection_alerts AS a
            LEFT JOIN triage_results AS t ON t.alert_id = a.alert_id
            WHERE {where_clause}
            ORDER BY {order_column} {order_direction}
            LIMIT ${len(params)}
            """,
            *params,
        )
        return [
            {
                "incident_id": row["alert_id"],
                "title": row["name"],
                "severity": row["severity"],
                "host": row["host"],
                "user": row["user_name"],
                "reason": row["reason"],
                "status": row["status"],
                "created_at": row["created_at"].isoformat(),
                "priority_score": float(row["priority_score"]),
                "likely_attack_stage": row["likely_attack_stage"],
                "confidence": float(row["confidence"]),
            }
            for row in rows
        ]

    async def list_findings(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = await self._pool.fetch(
            """
            SELECT a.alert_id, a.name, a.severity, a.host, a.reason, a.created_at,
                   t.priority_score, t.likely_attack_stage
            FROM detection_alerts AS a
            LEFT JOIN triage_results AS t ON t.alert_id = a.alert_id
            ORDER BY a.created_at DESC
            LIMIT $1
            """,
            limit,
        )
        return [
            {
                "finding_id": row["alert_id"],
                "title": row["name"],
                "severity": row["severity"],
                "host": row["host"],
                "summary": row["reason"],
                "likely_attack_stage": row["likely_attack_stage"] or "untriaged",
                "priority_score": float(row["priority_score"] or 0.0),
                "created_at": row["created_at"].isoformat(),
            }
            for row in rows
        ]

    async def upsert_triage(self, alert_id: str, triage: TriageResult) -> None:
        await self._pool.execute(
            """
            INSERT INTO triage_results(
                alert_id, priority_score, likely_attack_stage, confidence, recommended_actions, created_at
            )
            VALUES($1, $2, $3, $4, $5::jsonb, NOW())
            ON CONFLICT (alert_id) DO UPDATE SET
                priority_score = EXCLUDED.priority_score,
                likely_attack_stage = EXCLUDED.likely_attack_stage,
                confidence = EXCLUDED.confidence,
                recommended_actions = EXCLUDED.recommended_actions,
                created_at = NOW()
            """,
            alert_id,
            triage.priority_score,
            triage.likely_attack_stage,
            triage.confidence,
            triage.recommended_actions,
        )

    @staticmethod
    def _alert_id(alert: DetectionAlert) -> str:
        digest = hashlib.sha256(
            f"{alert.rule_id}|{alert.host}|{alert.user}|{','.join(alert.event_ids)}|{alert.reason}".encode("utf-8")
        ).hexdigest()
        return digest[:24]


class ForensicRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def upsert_artifact(self, artifact: ForensicArtifact) -> None:
        await self._pool.execute(
            """
            INSERT INTO forensic_artifacts(
                artifact_id, source_host, collected_at, sha256, evidence_path
            )
            VALUES($1, $2, $3, $4, $5)
            ON CONFLICT (artifact_id) DO UPDATE SET
                source_host = EXCLUDED.source_host,
                collected_at = EXCLUDED.collected_at,
                sha256 = EXCLUDED.sha256,
                evidence_path = EXCLUDED.evidence_path
            """,
            artifact.artifact_id,
            artifact.source_host,
            artifact.collected_at,
            artifact.sha256,
            artifact.evidence_path,
        )

    async def list_artifacts(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = await self._pool.fetch(
            """
            SELECT artifact_id, source_host, collected_at, sha256, evidence_path
            FROM forensic_artifacts
            ORDER BY collected_at DESC
            LIMIT $1
            """,
            limit,
        )
        return [
            {
                "artifact_id": row["artifact_id"],
                "source_host": row["source_host"],
                "collected_at": row["collected_at"].isoformat(),
                "sha256": row["sha256"],
                "evidence_path": row["evidence_path"],
            }
            for row in rows
        ]


class CoverageRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def upsert_coverage(self, coverage: Sequence[DetectionCoverage]) -> None:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.executemany(
                    """
                    INSERT INTO detection_coverage(
                        attack_path_id, covered_steps, uncovered_steps, coverage_score, created_at
                    )
                    VALUES($1, $2, $3, $4, NOW())
                    ON CONFLICT (attack_path_id) DO UPDATE SET
                        covered_steps = EXCLUDED.covered_steps,
                        uncovered_steps = EXCLUDED.uncovered_steps,
                        coverage_score = EXCLUDED.coverage_score,
                        created_at = NOW()
                    """,
                    [
                        (
                            item.attack_path_id,
                            item.covered_steps,
                            item.uncovered_steps,
                            item.coverage_score,
                        )
                        for item in coverage
                    ],
                )

    async def list_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = await self._pool.fetch(
            """
            SELECT attack_path_id, covered_steps, uncovered_steps, coverage_score, created_at
            FROM detection_coverage
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )
        return [
            {
                "attack_path_id": row["attack_path_id"],
                "covered_steps": row["covered_steps"],
                "uncovered_steps": row["uncovered_steps"],
                "coverage_score": float(row["coverage_score"]),
                "created_at": row["created_at"].isoformat(),
            }
            for row in rows
        ]


class AuthRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def create_token(self, actor: str, role: str) -> tuple[str, str]:
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        token_id = secrets.token_hex(8)
        await self._pool.execute(
            """
            INSERT INTO api_tokens(token_id, token_hash, actor, role, created_at)
            VALUES($1, $2, $3, $4, NOW())
            """,
            token_id,
            token_hash,
            actor,
            role,
        )
        return token_id, token

    async def validate_token(self, token: str) -> dict[str, str] | None:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        row = await self._pool.fetchrow(
            """
            SELECT token_id, actor, role
            FROM api_tokens
            WHERE token_hash = $1
              AND revoked_at IS NULL
            """,
            token_hash,
        )
        if row is None:
            return None
        return {"token_id": row["token_id"], "actor": row["actor"], "role": row["role"]}
