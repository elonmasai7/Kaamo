from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import ContentSwitcher, DataTable, Input, Static

from kaamo.blueteam.threat_intel.hunting import HuntHypothesis
from kaamo.blueteam.service import FindingRecord, ThreatHuntResponse


class FindingsView(Vertical):
    def __init__(self, *, id: str | None = None, classes: str | None = None, disabled: bool = False) -> None:
        super().__init__(id=id, classes=classes, disabled=disabled)
        self._findings: list[FindingRecord] = []
        self._visible_findings: list[FindingRecord] = []
        self._threat_hunt: ThreatHuntResponse | None = None
        self._search = ""

    def compose(self) -> ComposeResult:
        yield Input(placeholder="Search findings or hunt hypotheses", id="findings-search")
        with ContentSwitcher(initial="findings-pane", id="findings-switcher"):
            with Vertical(id="findings-pane"):
                findings_table: DataTable[str] = DataTable(id="findings-table")
                findings_table.cursor_type = "row"
                findings_table.zebra_stripes = True
                yield findings_table
            with Vertical(id="threat-pane"):
                with Horizontal():
                    suspicious_table: DataTable[str] = DataTable(id="hunt-hosts")
                    suspicious_table.cursor_type = "row"
                    suspicious_table.zebra_stripes = True
                    hypotheses_table: DataTable[str] = DataTable(id="hunt-hypotheses")
                    hypotheses_table.cursor_type = "row"
                    hypotheses_table.zebra_stripes = True
                    yield suspicious_table
                    yield hypotheses_table
                anomalies_table: DataTable[str] = DataTable(id="hunt-anomalies")
                anomalies_table.cursor_type = "row"
                anomalies_table.zebra_stripes = True
                yield anomalies_table
        yield Static("", id="findings-detail")

    def on_mount(self) -> None:
        self.query_one("#findings-table", DataTable).add_columns("Severity", "Title", "Host", "Stage", "Priority", "Time")
        self.query_one("#hunt-hosts", DataTable).add_columns("Host", "Alert Count")
        self.query_one("#hunt-hypotheses", DataTable).add_columns("Confidence", "Hypothesis")
        self.query_one("#hunt-anomalies", DataTable).add_columns("Metric", "Host", "Value")

    def show_findings_mode(self) -> None:
        self.query_one("#findings-switcher", ContentSwitcher).current = "findings-pane"

    def show_threat_mode(self) -> None:
        self.query_one("#findings-switcher", ContentSwitcher).current = "threat-pane"

    def focus_search(self) -> None:
        self.query_one("#findings-search", Input).focus()

    def update_findings(self, findings: list[FindingRecord]) -> None:
        self._findings = findings
        self._render_findings()

    def update_threat_hunt(self, threat_hunt: ThreatHuntResponse) -> None:
        self._threat_hunt = threat_hunt
        self._render_threat_hunt()

    def selected_payload(self) -> dict[str, object] | None:
        if self.query_one("#findings-switcher", ContentSwitcher).current == "findings-pane":
            row_index = self.query_one("#findings-table", DataTable).cursor_row
            if 0 <= row_index < len(self._visible_findings):
                return self._visible_findings[row_index].model_dump(mode="json")
            return None
        if self._threat_hunt is None:
            return None
        row_index = self.query_one("#hunt-hypotheses", DataTable).cursor_row
        if 0 <= row_index < len(self._threat_hunt.hypotheses):
            return self._threat_hunt.hypotheses[row_index].model_dump(mode="json")
        return None

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "findings-search":
            self._search = event.value
            self._render_findings()
            self._render_threat_hunt()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        del event
        payload = self.selected_payload()
        if payload is None:
            return
        self.query_one("#findings-detail", Static).update(str(payload))

    def _render_findings(self) -> None:
        filtered = self._findings
        if self._search:
            needle = self._search.lower()
            filtered = [
                item
                for item in filtered
                if needle in item.title.lower()
                or needle in (item.host or "").lower()
                or needle in item.summary.lower()
            ]
        self._visible_findings = filtered
        table = self.query_one("#findings-table", DataTable)
        table.clear(columns=False)
        for item in filtered:
            table.add_row(item.severity.upper(), item.title, item.host or "-", item.likely_attack_stage, f"{item.priority_score:.2f}", item.created_at)

    def _render_threat_hunt(self) -> None:
        if self._threat_hunt is None:
            return
        hosts: list[dict[str, object]] = list(self._threat_hunt.suspicious_hosts)
        hypotheses: list[HuntHypothesis] = list(self._threat_hunt.hypotheses)
        anomalies: list[dict[str, object]] = list(self._threat_hunt.recent_anomalies)
        if self._search:
            needle = self._search.lower()
            hosts = [item for item in hosts if needle in str(item).lower()]
            hypotheses = [item for item in hypotheses if needle in item.hypothesis.lower()]
            anomalies = [item for item in anomalies if needle in str(item).lower()]
        hosts_table = self.query_one("#hunt-hosts", DataTable)
        hosts_table.clear(columns=False)
        for host_item in hosts:
            hosts_table.add_row(str(host_item["host"]), str(host_item["alert_count"]))
        hypotheses_table = self.query_one("#hunt-hypotheses", DataTable)
        hypotheses_table.clear(columns=False)
        for hypothesis_item in hypotheses:
            hypotheses_table.add_row(f"{hypothesis_item.confidence:.2f}", hypothesis_item.hypothesis)
        anomalies_table = self.query_one("#hunt-anomalies", DataTable)
        anomalies_table.clear(columns=False)
        for anomaly_item in anomalies:
            anomalies_table.add_row(
                str(anomaly_item.get("metric", "-")),
                str(anomaly_item.get("host", "-")),
                str(anomaly_item.get("observed_value", "-")),
            )
