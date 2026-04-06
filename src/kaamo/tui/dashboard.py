from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Static

from kaamo.blueteam.dashboards.soc_dashboard import SOCDashboard
from kaamo.blueteam.service import AlertRecord, QueueMetricsResponse
from kaamo.tui.widgets.kpi_cards import KPICards
from kaamo.tui.widgets.live_alerts_table import LiveAlertsTable
from kaamo.tui.widgets.severity_chart import SeverityChart


class DashboardView(Vertical):
    def compose(self) -> ComposeResult:
        yield KPICards(id="dashboard-kpis")
        with Horizontal():
            yield SeverityChart(id="dashboard-severity")
            yield Static("", id="dashboard-queue")
        yield LiveAlertsTable(id="dashboard-alerts")

    def update_dashboard(self, dashboard: SOCDashboard, alerts: list[AlertRecord], queue_metrics: QueueMetricsResponse) -> None:
        coverage_gap_raw = dashboard.widgets[-1].data.get("coverage_gap", 0.0) if dashboard.widgets else 0.0
        coverage_gap = float(coverage_gap_raw) if isinstance(coverage_gap_raw, (int, float)) else 0.0
        kpis = {
            "active_incidents": str(int(dashboard.kpis.get("analyst_queue_depth", 0))),
            "critical_alerts": str(int(dashboard.kpis.get("critical_incident_count", 0))),
            "mttd": f"{dashboard.kpis.get('mttd', 0.0):.1f}s",
            "mttr": f"{dashboard.kpis.get('mttr', 0.0):.1f}s",
            "coverage": f"{max(0.0, 1.0 - coverage_gap) * 100:.1f}%",
        }
        self.query_one(KPICards).update_cards(kpis)
        self.query_one(SeverityChart).update_chart(alerts)
        self.query_one("#dashboard-queue", Static).update(
            f"Queue Depth\n{queue_metrics.queue_depth}\nWorkers\n{queue_metrics.detection_workers}"
        )
        self.query_one(LiveAlertsTable).set_alerts(alerts[:20])

    def selected_payload(self) -> dict[str, object] | None:
        record = self.query_one(LiveAlertsTable).selected_record()
        return record.model_dump(mode="json") if record is not None else None
