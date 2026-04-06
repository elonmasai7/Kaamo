from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Input, Select, Static

from kaamo.blueteam.service import AlertRecord
from kaamo.tui.widgets.live_alerts_table import LiveAlertsTable


class AlertsView(Vertical):
    def __init__(self, *, id: str | None = None, classes: str | None = None, disabled: bool = False) -> None:
        super().__init__(id=id, classes=classes, disabled=disabled)
        self._records: list[AlertRecord] = []
        self._visible_records: list[AlertRecord] = []
        self._search = ""
        self._severity = "all"

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Input(placeholder="Search alerts", id="alert-search")
            yield Select(
                options=[("All Severities", "all"), ("Critical", "critical"), ("High", "high"), ("Medium", "medium"), ("Low", "low")],
                value="all",
                id="alert-severity",
            )
        yield LiveAlertsTable(id="alerts-table")
        yield Static("", id="alerts-detail")

    def update_records(self, records: list[AlertRecord]) -> None:
        self._records = records
        self._apply_filters()

    def focus_search(self) -> None:
        self.query_one("#alert-search", Input).focus()

    def selected_payload(self) -> dict[str, object] | None:
        record = self.query_one(LiveAlertsTable).selected_record()
        return record.model_dump(mode="json") if record is not None else None

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "alert-search":
            self._search = event.value
            self._apply_filters()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "alert-severity":
            self._severity = str(event.value)
            self._apply_filters()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        del event
        record = self.query_one(LiveAlertsTable).selected_record()
        if record is None:
            return
        self.query_one("#alerts-detail", Static).update(
            f"{record.name}\nHost: {record.host or '-'}\nReason: {record.reason}\nMITRE: {record.mitre}"
        )

    def _apply_filters(self) -> None:
        filtered = self._records
        if self._severity != "all":
            filtered = [record for record in filtered if record.severity == self._severity]
        if self._search:
            needle = self._search.lower()
            filtered = [
                record
                for record in filtered
                if needle in record.name.lower()
                or needle in (record.host or "").lower()
                or needle in record.reason.lower()
            ]
        self._visible_records = filtered
        self.query_one(LiveAlertsTable).set_alerts(filtered)
