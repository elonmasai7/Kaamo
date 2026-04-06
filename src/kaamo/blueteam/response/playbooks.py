from __future__ import annotations

from pydantic import BaseModel, Field

from kaamo.audit import write_audit_log
from kaamo.blueteam.base import BlueTeamModule, ModuleResult, SecurityContext


class ResponsePlaybook(BaseModel):
    playbook_id: str
    title: str
    steps: list[str] = Field(default_factory=list)
    severity: str


PLAYBOOK_LIBRARY: dict[str, ResponsePlaybook] = {
    "Brute Force To Success": ResponsePlaybook(
        playbook_id="PB-001",
        title="Credential Abuse Investigation",
        severity="critical",
        steps=[
            "Validate authentication logs and geo/source-IP context.",
            "Recommend temporary user disablement if misuse is confirmed.",
            "Recommend token/session revocation and password reset.",
            "Preserve authentication and VPN evidence before containment.",
        ],
    ),
    "Suspicious Process Chain": ResponsePlaybook(
        playbook_id="PB-002",
        title="Suspicious Execution Chain Review",
        severity="high",
        steps=[
            "Capture process tree, command line, and network connections.",
            "Recommend host isolation only after volatile evidence capture.",
            "Recommend file quarantine for the staged payload if confirmed malicious.",
            "Escalate to incident response for scoping of similar hosts.",
        ],
    ),
    "Lateral Movement Indicator": ResponsePlaybook(
        playbook_id="PB-003",
        title="Lateral Movement Scoping",
        severity="critical",
        steps=[
            "Collect remote logon, service creation, and administrative share evidence.",
            "Recommend blocking the originating IP or account only after analyst validation.",
            "Prioritize peer-host scoping and privileged account review.",
            "Escalate to the incident response team immediately.",
        ],
    ),
}


class ResponsePlaybookModule(BlueTeamModule):
    name = "response_playbooks"
    description = "Analyst-safe response recommendations with no destructive automation"

    async def analyze(self, context: SecurityContext) -> ModuleResult:
        playbooks = [
            playbook
            for alert in context.alerts
            for playbook in [self.recommend(alert)]
            if playbook is not None
        ]
        write_audit_log("blueteam.response.analyze", "system", self.name, playbook_count=len(playbooks))
        return ModuleResult(
            module_name=self.name,
            summary=f"Prepared {len(playbooks)} response playbook recommendations.",
            findings=[playbook.model_dump(mode="json") for playbook in playbooks],
            metrics={"playbooks": float(len(playbooks))},
        )

    def recommend(self, alert: dict[str, object]) -> ResponsePlaybook | None:
        name = str(alert.get("name", ""))
        if name in PLAYBOOK_LIBRARY:
            return PLAYBOOK_LIBRARY[name]
        severity = str(alert.get("severity", "medium"))
        return ResponsePlaybook(
            playbook_id="PB-GENERIC",
            title=f"Analyst Validation for {name or 'Generic Alert'}",
            severity=severity,
            steps=[
                "Validate the alert against source telemetry and supporting context.",
                "Preserve evidence before recommending containment.",
                "Recommend least-destructive containment aligned to analyst confirmation.",
            ],
        )
