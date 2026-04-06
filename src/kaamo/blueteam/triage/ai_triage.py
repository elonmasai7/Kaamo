from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from kaamo.audit import write_audit_log
from kaamo.blueteam.base import BlueTeamModule, ModuleResult, SecurityContext
from kaamo.inference.router import AgentSession, InferenceRouter


class TriageResult(BaseModel):
    priority_score: float
    likely_attack_stage: str
    confidence: float
    recommended_actions: list[str] = Field(default_factory=list)


MITRE_STAGE_MAP: dict[str, tuple[str, str, float]] = {
    "Suspicious Process Chain": ("execution", "T1059", 0.91),
    "Privilege Escalation": ("privilege-escalation", "T1068", 0.82),
    "Brute Force To Success": ("credential-access", "T1110", 0.93),
    "Lateral Movement Indicator": ("lateral-movement", "T1021", 0.88),
    "DNS Tunneling Suspicion": ("command-and-control", "T1071.004", 0.76),
    "Persistence Indicator": ("persistence", "T1053", 0.84),
}


class AITriageEngine(BlueTeamModule):
    name = "ai_triage"
    description = "Local AI-assisted analyst triage and prioritization"

    def __init__(self, inference_router: InferenceRouter | None = None) -> None:
        self._router = inference_router

    async def analyze(self, context: SecurityContext) -> ModuleResult:
        results = [await self.triage_alert(alert) for alert in context.alerts]
        write_audit_log("blueteam.ai_triage.analyze", "system", self.name, alert_count=len(results))
        return ModuleResult(
            module_name=self.name,
            summary=f"Triaged {len(results)} alerts for analyst review.",
            findings=[result.model_dump(mode="json") for result in results],
            metrics={"triaged_alerts": float(len(results))},
        )

    async def triage_alert(self, alert: dict[str, Any]) -> TriageResult:
        name = str(alert.get("name", "generic alert"))
        severity = str(alert.get("severity", "medium")).lower()
        stage, technique, confidence = MITRE_STAGE_MAP.get(name, ("investigation", "T1595", 0.55))
        priority_score = {
            "low": 0.25,
            "medium": 0.55,
            "high": 0.8,
            "critical": 0.95,
        }.get(severity, 0.5)
        recommended_actions = [
            f"Validate alert context and map to MITRE {technique}.",
            "Review host and user timeline for adjacent events.",
            "Preserve volatile evidence before containment recommendations.",
        ]
        if stage in {"lateral-movement", "command-and-control"}:
            recommended_actions.append("Prioritize scoping of peer hosts and outbound connections.")
        if self._router is not None:
            prompt = (
                "You are a SOC analyst assistant. Explain briefly why this alert fired and suggest next steps.\n"
                f"Alert: {alert}"
            )
            session = AgentSession(session_id="blueteam-triage", user_id="soc-analyst")
            explanation = []
            async for token in self._router.route(
                [{"role": "user", "content": prompt}],
                max_tokens=96,
                session=session,
                temperature=0.0,
            ):
                explanation.append(token)
            if explanation:
                recommended_actions.insert(0, "".join(explanation).strip())
        return TriageResult(
            priority_score=priority_score,
            likely_attack_stage=f"{stage} ({technique})",
            confidence=confidence,
            recommended_actions=recommended_actions,
        )

