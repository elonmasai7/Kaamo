from __future__ import annotations

from collections import Counter

from textual.widgets import Static

from kaamo.blueteam.service import AlertRecord


class SeverityChart(Static):
    def update_chart(self, alerts: list[AlertRecord]) -> None:
        counts = Counter(alert.severity.upper() for alert in alerts)
        lines = ["Severity Heatmap"]
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = counts.get(severity, 0)
            lines.append(f"{severity:<8} {'#' * min(count, 40)} {count}")
        self.update("\n".join(lines))

