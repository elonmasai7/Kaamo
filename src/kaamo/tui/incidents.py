from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Input, Select, Static

from kaamo.blueteam.service import IncidentRecord


class IncidentsView(Vertical):
    def __init__(self, *, id: str | None = None, classes: str | None = None, disabled: bool = False) -> None:
        super().__init__(id=id, classes=classes, disabled=disabled)
        self._records: list[IncidentRecord] = []
        self._visible_records: list[IncidentRecord] = []
        self._search = ""
        self._severity = "all"
        self._sort_by = "created_at"

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Input(placeholder="Search incidents", id="incident-search")
            yield Select(
                options=[("All Severities", "all"), ("Critical", "critical"), ("High", "high"), ("Medium", "medium"), ("Low", "low")],
                value="all",
                id="incident-severity",
            )
            yield Select(
                options=[("Newest", "created_at"), ("Severity", "severity"), ("Priority", "priority_score"), ("Host", "host")],
                value="created_at",
                id="incident-sort",
            )
        table: DataTable[str] = DataTable(id="incident-table")
        table.cursor_type = "row"
        table.zebra_stripes = True
        yield table
        yield Static("", id="incident-detail")

    def on_mount(self) -> None:
        table = self.query_one("#incident-table", DataTable)
        if not table.columns:
            table.add_columns("Severity", "Title", "Host", "Priority", "Stage", "Time")

    def update_records(self, records: list[IncidentRecord]) -> None:
        self._records = records
        self._apply_filters()

    def focus_search(self) -> None:
        self.query_one("#incident-search", Input).focus()

    def selected_payload(self) -> dict[str, object] | None:
        row_index = self.query_one("#incident-table", DataTable).cursor_row
        if row_index < 0 or row_index >= len(self._visible_records):
            return None
        return self._visible_records[row_index].model_dump(mode="json")

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "incident-search":
            self._search = event.value
            self._apply_filters()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "incident-severity":
            self._severity = str(event.value)
        elif event.select.id == "incident-sort":
            self._sort_by = str(event.value)
        self._apply_filters()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        row_index = event.cursor_row
        if row_index < 0 or row_index >= len(self._visible_records):
            return
        record = self._visible_records[row_index]
        self.query_one("#incident-detail", Static).update(
            f"{record.title}\nHost: {record.host or '-'} User: {record.user or '-'}\n"
            f"Priority: {record.priority_score:.2f} Stage: {record.likely_attack_stage}\n{record.reason}"
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
                if needle in record.title.lower()
                or needle in (record.host or "").lower()
                or needle in (record.user or "").lower()
                or needle in record.reason.lower()
            ]
        if self._sort_by == "severity":
            severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            filtered = sorted(filtered, key=lambda record: severity_rank.get(record.severity, 9))
        elif self._sort_by == "priority_score":
            filtered = sorted(filtered, key=lambda record: record.priority_score, reverse=True)
        elif self._sort_by == "host":
            filtered = sorted(filtered, key=lambda record: record.host or "")
        else:
            filtered = sorted(filtered, key=lambda record: record.created_at, reverse=True)
        self._visible_records = filtered
        table = self.query_one("#incident-table", DataTable)
        table.clear(columns=False)
        for record in filtered:
            table.add_row(
                record.severity.upper(),
                record.title,
                record.host or "-",
                f"{record.priority_score:.2f}",
                record.likely_attack_stage,
                record.created_at,
            )
