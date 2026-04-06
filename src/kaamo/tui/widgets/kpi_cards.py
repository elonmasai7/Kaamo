from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Grid
from textual.widgets import Static


class KPICards(Grid):
    def compose(self) -> ComposeResult:
        for widget_id in ("active_incidents", "critical_alerts", "mttd", "mttr", "coverage"):
            yield Static("", id=f"kpi-{widget_id}", classes="kpi-card")

    def update_cards(self, values: dict[str, str]) -> None:
        labels = {
            "active_incidents": "Active Incidents",
            "critical_alerts": "Critical Alerts",
            "mttd": "MTTD",
            "mttr": "MTTR",
            "coverage": "Detection Coverage",
        }
        for key, label in labels.items():
            self.query_one(f"#kpi-{key}", Static).update(f"{label}\n{values.get(key, '0')}")

