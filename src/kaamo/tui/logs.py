from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Static

from kaamo.blueteam.service import EvidenceTimelineEntry
from kaamo.tui.widgets.timeline import TimelineTable


class LogsView(Vertical):
    def compose(self) -> ComposeResult:
        yield TimelineTable(id="evidence-table")
        yield Static("", id="evidence-detail")

    def update_entries(self, entries: list[EvidenceTimelineEntry]) -> None:
        self.query_one(TimelineTable).set_entries(entries)

    def selected_payload(self) -> dict[str, object] | None:
        record = self.query_one(TimelineTable).selected_record()
        return record.model_dump(mode="json") if record is not None else None

    def on_data_table_row_highlighted(self, event: TimelineTable.RowHighlighted) -> None:
        del event
        record = self.query_one(TimelineTable).selected_record()
        if record is None:
            return
        self.query_one("#evidence-detail", Static).update(
            f"{record.kind.upper()} {record.timestamp}\n{record.title}\n{record.details}"
        )
