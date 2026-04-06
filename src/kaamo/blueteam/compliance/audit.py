from __future__ import annotations

from pydantic import BaseModel, Field

from kaamo.audit import write_audit_log
from kaamo.blueteam.base import BlueTeamModule, ModuleResult, SecurityContext


class ComplianceReport(BaseModel):
    framework: str
    status: str
    control_scores: dict[str, float] = Field(default_factory=dict)
    analyst_actions: int


class ComplianceAuditModule(BlueTeamModule):
    name = "compliance_audit"
    description = "Compliance-ready reporting for blue-team workflows"

    async def analyze(self, context: SecurityContext) -> ModuleResult:
        reports = self.generate_reports(context)
        write_audit_log("blueteam.compliance.analyze", "system", self.name, report_count=len(reports))
        return ModuleResult(
            module_name=self.name,
            summary=f"Generated {len(reports)} compliance report summaries.",
            findings=[report.model_dump(mode="json") for report in reports],
            metrics={"reports": float(len(reports))},
        )

    def generate_reports(self, context: SecurityContext) -> list[ComplianceReport]:
        analyst_actions = int(context.metadata.get("analyst_actions", len(context.alerts)))
        evidence_count = int(context.metadata.get("evidence_count", 0))
        detection_count = max(len(context.alerts), 1)
        control_score = min(1.0, evidence_count / detection_count)
        frameworks = ("ISO 27001", "SOC 2", "CIS Controls", "Internal Security Audit")
        reports: list[ComplianceReport] = []
        for framework in frameworks:
            reports.append(
                ComplianceReport(
                    framework=framework,
                    status="review-ready" if analyst_actions else "needs-attention",
                    control_scores={
                        "audit_logging": 1.0,
                        "evidence_preservation": round(control_score, 2),
                        "response_governance": 1.0 if analyst_actions else 0.4,
                    },
                    analyst_actions=analyst_actions,
                )
            )
        return reports

