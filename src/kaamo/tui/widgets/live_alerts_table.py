from __future__ import annotations

from textual.widgets import DataTable

from kaamo.blueteam.service import AlertRecord


class LiveAlertsTable(DataTable[str]):
    def on_mount(self) -> None:
        self.cursor_type = "row"
        self.zebra_stripes = True
        self._records: list[AlertRecord] = []

    def configure(self) -> None:
        if self.columns:
            return
        self.add_columns("Severity", "Alert", "Host", "Stage", "Time")

    def set_alerts(self, alerts: list[AlertRecord]) -> None:
        self.configure()
        self.clear(columns=False)
        self._records = alerts
        for alert in alerts:
            stage = str(alert.mitre.get("technique_id", "n/a"))
            self.add_row(alert.severity.upper(), alert.name, alert.host or "-", stage, alert.created_at, key=alert.alert_id)

    def selected_record(self) -> AlertRecord | None:
        row_index = self.cursor_row
        if row_index < 0 or row_index >= len(self._records):
            return None
        return self._records[row_index]
