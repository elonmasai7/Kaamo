from __future__ import annotations

from collections import Counter

from pydantic import BaseModel, Field

from kaamo.audit import write_audit_log
from kaamo.blueteam.base import BlueTeamModule, ModuleResult, SecurityContext


class DashboardWidget(BaseModel):
    title: str
    data: dict[str, object] = Field(default_factory=dict)


class SOCDashboard(BaseModel):
    widgets: list[DashboardWidget] = Field(default_factory=list)
    kpis: dict[str, float] = Field(default_factory=dict)


class SOCDashboardModule(BlueTeamModule):
    name = "soc_dashboard"
    description = "SOC-oriented summaries, queueing views, and KPI rollups"

    async def analyze(self, context: SecurityContext) -> ModuleResult:
        dashboard = self.build_dashboard(context)
        write_audit_log("blueteam.dashboard.analyze", "system", self.name, widget_count=len(dashboard.widgets))
        return ModuleResult(
            module_name=self.name,
            summary=f"Built SOC dashboard with {len(dashboard.widgets)} widgets.",
            findings=[widget.model_dump(mode="json") for widget in dashboard.widgets],
            metrics=dashboard.kpis,
        )

    def build_dashboard(self, context: SecurityContext) -> SOCDashboard:
        alerts = context.alerts
        severities = Counter(str(alert.get("severity", "medium")) for alert in alerts)
        risky_hosts = Counter(str(alert.get("host", "unknown")) for alert in alerts)
        mitre_coverage = Counter(str(alert.get("mitre", {}).get("technique_id", "unknown")) for alert in alerts)
        incidents = context.metadata.get("incidents", [])
        false_positive_rate = float(context.metadata.get("false_positive_rate", 0.0))
        mttd = self._mean_delta(incidents, "started_at", "detected_at")
        mttr = self._mean_delta(incidents, "detected_at", "responded_at")
        widgets = [
            DashboardWidget(title="active_alerts", data={"count": len(alerts)}),
            DashboardWidget(title="severity_heatmap", data=dict(severities)),
            DashboardWidget(title="mitre_coverage", data=dict(mitre_coverage)),
            DashboardWidget(title="top_risky_hosts", data=dict(risky_hosts.most_common(5))),
            DashboardWidget(title="response_queue", data={"queued": len(alerts)}),
            DashboardWidget(title="unresolved_incidents", data={"count": sum(1 for incident in incidents if not incident.get("resolved"))}),
            DashboardWidget(title="anomaly_trends", data=context.metadata.get("anomaly_trends", {})),
            DashboardWidget(title="detection_gap_score", data={"coverage_gap": float(context.metadata.get("coverage_gap_score", 0.0))}),
        ]
        return SOCDashboard(
            widgets=widgets,
            kpis={
                "mttd": mttd,
                "mttr": mttr,
                "false_positive_rate": false_positive_rate,
                "critical_incident_count": float(severities.get("critical", 0)),
                "analyst_queue_depth": float(len(alerts)),
            },
        )

    @staticmethod
    def _mean_delta(incidents: list[dict[str, object]], start_key: str, end_key: str) -> float:
        deltas: list[float] = []
        for incident in incidents:
            start = incident.get(start_key)
            end = incident.get(end_key)
            if isinstance(start, (int, float)) and isinstance(end, (int, float)) and end >= start:
                deltas.append(float(end - start))
        if not deltas:
            return 0.0
        return sum(deltas) / len(deltas)

