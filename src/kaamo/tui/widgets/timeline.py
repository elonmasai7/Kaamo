from __future__ import annotations

from textual.widgets import DataTable

from kaamo.blueteam.service import EvidenceTimelineEntry


class TimelineTable(DataTable[str]):
    def on_mount(self) -> None:
        self.cursor_type = "row"
        self.zebra_stripes = True
        self._records: list[EvidenceTimelineEntry] = []

    def configure(self) -> None:
        if self.columns:
            return
        self.add_columns("Time", "Kind", "Title")

    def set_entries(self, entries: list[EvidenceTimelineEntry]) -> None:
        self.configure()
        self.clear(columns=False)
        self._records = entries
        for entry in entries:
            self.add_row(entry.timestamp, entry.kind, entry.title)

    def selected_record(self) -> EvidenceTimelineEntry | None:
        row_index = self.cursor_row
        if row_index < 0 or row_index >= len(self._records):
            return None
        return self._records[row_index]
