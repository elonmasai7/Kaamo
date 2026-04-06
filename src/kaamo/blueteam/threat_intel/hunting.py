from __future__ import annotations

from collections import Counter, defaultdict

from pydantic import BaseModel, Field

from kaamo.audit import write_audit_log
from kaamo.blueteam.base import BlueTeamModule, ModuleResult, SecurityContext


class HuntHypothesis(BaseModel):
    hypothesis: str
    confidence: float
    supporting_events: list[str] = Field(default_factory=list)


class ThreatHuntingModule(BlueTeamModule):
    name = "threat_hunting"
    description = "Proactive threat hunting and analyst hypothesis generation"

    async def analyze(self, context: SecurityContext) -> ModuleResult:
        hypotheses = self.generate_hypotheses(context)
        write_audit_log("blueteam.threat_hunting.analyze", "system", self.name, hypothesis_count=len(hypotheses))
        return ModuleResult(
            module_name=self.name,
            summary=f"Generated {len(hypotheses)} hunt hypotheses from event telemetry.",
            findings=[hypothesis.model_dump(mode="json") for hypothesis in hypotheses],
            metrics={"hypotheses": float(len(hypotheses))},
        )

    def generate_hypotheses(self, context: SecurityContext) -> list[HuntHypothesis]:
        hypotheses: list[HuntHypothesis] = []
        failed_auth: defaultdict[str, list[str]] = defaultdict(list)
        rare_binaries: Counter[str] = Counter()
        new_services: list[str] = []
        for event in context.events:
            lower_type = event.event_type.lower()
            if "login_fail" in lower_type or ("login" in lower_type and "fail" in lower_type):
                failed_auth[event.host].append(event.event_id)
            binary = str(event.raw_payload.get("process_name") or "")
            if binary:
                rare_binaries[binary] += 1
            if "service" in lower_type and "install" in lower_type:
                new_services.append(event.event_id)
        for host, event_ids in failed_auth.items():
            if len(event_ids) >= 3:
                hypotheses.append(
                    HuntHypothesis(
                        hypothesis=f"Host {host} may be experiencing repeated authentication probing or password spraying.",
                        confidence=min(0.4 + (0.1 * len(event_ids)), 0.9),
                        supporting_events=event_ids[:10],
                    )
                )
        for binary, count in rare_binaries.items():
            if count == 1:
                matching = [
                    event.event_id
                    for event in context.events
                    if str(event.raw_payload.get("process_name") or "") == binary
                ]
                hypotheses.append(
                    HuntHypothesis(
                        hypothesis=f"Rare binary execution detected: {binary}. Validate legitimacy and signer trust.",
                        confidence=0.65,
                        supporting_events=matching,
                    )
                )
        if new_services:
            hypotheses.append(
                HuntHypothesis(
                    hypothesis="New service installation artifacts may indicate persistence or lateral tooling deployment.",
                    confidence=0.78,
                    supporting_events=new_services[:10],
                )
            )
        return hypotheses

