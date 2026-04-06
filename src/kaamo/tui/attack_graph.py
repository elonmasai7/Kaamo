from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static

from kaamo.security.validation_bridge import DetectionCoverage


class AttackGraphView(Vertical):
    def __init__(self, *, id: str | None = None, classes: str | None = None, disabled: bool = False) -> None:
        super().__init__(id=id, classes=classes, disabled=disabled)
        self._records: list[DetectionCoverage] = []

    def compose(self) -> ComposeResult:
        table: DataTable[str] = DataTable(id="coverage-table")
        table.cursor_type = "row"
        table.zebra_stripes = True
        yield table
        yield Static("", id="coverage-detail")

    def on_mount(self) -> None:
        self.query_one("#coverage-table", DataTable).add_columns("Attack Path", "Covered", "Uncovered", "Score")

    def update_records(self, records: list[DetectionCoverage]) -> None:
        self._records = records
        table = self.query_one("#coverage-table", DataTable)
        table.clear(columns=False)
        for item in records:
            table.add_row(item.attack_path_id, str(item.covered_steps), str(item.uncovered_steps), f"{item.coverage_score:.2%}")

    def selected_payload(self) -> dict[str, object] | None:
        row_index = self.query_one("#coverage-table", DataTable).cursor_row
        if row_index < 0 or row_index >= len(self._records):
            return None
        return self._records[row_index].model_dump(mode="json")

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        row_index = event.cursor_row
        if row_index < 0 or row_index >= len(self._records):
            return
        record = self._records[row_index]
        self.query_one("#coverage-detail", Static).update(
            f"{record.attack_path_id}\nCovered: {record.covered_steps}  Uncovered: {record.uncovered_steps}\nScore: {record.coverage_score:.2%}"
        )
