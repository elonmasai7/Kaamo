from __future__ import annotations

import asyncio

from textual.app import App, ComposeResult
from textual.widget import Widget
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import ContentSwitcher, Footer, Header, Input, Pretty, Static

from kaamo.blueteam.service import AlertRecord
from kaamo.tui.alerts import AlertsView
from kaamo.tui.attack_graph import AttackGraphView
from kaamo.tui.client import DashboardSnapshot, KaamoTuiClient
from kaamo.tui.dashboard import DashboardView
from kaamo.tui.findings import FindingsView
from kaamo.tui.incidents import IncidentsView
from kaamo.tui.keybindings import DASHBOARD_BINDINGS
from kaamo.tui.logs import LogsView


class SearchModal(ModalScreen[str | None]):
    def compose(self) -> ComposeResult:
        yield Input(placeholder="Search current view", id="search-input")

    def on_mount(self) -> None:
        self.query_one(Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)


class DetailModal(ModalScreen[None]):
    def __init__(self, payload: dict[str, object]) -> None:
        super().__init__()
        self._payload = payload

    def compose(self) -> ComposeResult:
        yield Pretty(self._payload)


class LiveAlertMessage(Message):
    def __init__(self, alert: AlertRecord) -> None:
        self.alert = alert
        super().__init__()


class KaamoDashboardApp(App[None]):
    CSS = """
    Screen {
        layout: vertical;
    }
    #error-banner {
        display: none;
        background: darkred;
        color: white;
        height: auto;
        padding: 0 1;
    }
    .kpi-card {
        border: round $panel;
        padding: 1;
        min-width: 18;
    }
    KPICards {
        grid-size: 5;
        grid-columns: 1fr 1fr 1fr 1fr 1fr;
        height: auto;
        margin: 1 0;
    }
    Input, Select {
        width: 1fr;
        margin-right: 1;
    }
    DataTable {
        height: 1fr;
    }
    #incident-detail, #alerts-detail, #findings-detail, #coverage-detail, #evidence-detail, #dashboard-queue {
        border: round $panel;
        padding: 1;
        height: 7;
    }
    """
    BINDINGS = list(DASHBOARD_BINDINGS)

    def __init__(
        self,
        *,
        client: KaamoTuiClient,
        refresh_interval: float = 3.0,
        low_resource: bool = False,
    ) -> None:
        super().__init__()
        self._client = client
        self._refresh_interval = 10.0 if low_resource else refresh_interval
        self._low_resource = low_resource
        self._stop_event = asyncio.Event()
        self._poll_task: asyncio.Task[None] | None = None
        self._stream_task: asyncio.Task[None] | None = None
        self._snapshot: DashboardSnapshot | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("", id="error-banner")
        with ContentSwitcher(initial="dashboard-view", id="main-switcher"):
            yield DashboardView(id="dashboard-view")
            yield IncidentsView(id="incidents-view")
            yield AlertsView(id="alerts-view")
            yield FindingsView(id="findings-view")
            yield AttackGraphView(id="attack-graph-view")
            yield LogsView(id="logs-view")
        yield Footer()

    async def on_mount(self) -> None:
        await self._client.connect()
        await self.action_refresh()
        self._poll_task = asyncio.create_task(self._poll_loop())
        if self._client.websocket_enabled and not self._low_resource:
            self._stream_task = asyncio.create_task(self._stream_loop())

    async def on_unmount(self) -> None:
        self._stop_event.set()
        if self._poll_task is not None:
            await asyncio.gather(self._poll_task, return_exceptions=True)
        if self._stream_task is not None:
            await asyncio.gather(self._stream_task, return_exceptions=True)
        await self._client.close()

    async def action_refresh(self) -> None:
        try:
            snapshot = await self._client.fetch_dashboard_snapshot()
        except Exception as exc:
            self._set_error(f"Degraded mode: {exc}")
            return
        self._snapshot = snapshot
        self._apply_snapshot(snapshot)
        self._set_error(None)

    def action_dashboard(self) -> None:
        self.query_one("#main-switcher", ContentSwitcher).current = "dashboard-view"

    def action_incidents(self) -> None:
        self.query_one("#main-switcher", ContentSwitcher).current = "incidents-view"

    def action_alerts(self) -> None:
        self.query_one("#main-switcher", ContentSwitcher).current = "alerts-view"

    def action_findings(self) -> None:
        self.query_one("#main-switcher", ContentSwitcher).current = "findings-view"
        self.query_one(FindingsView).show_findings_mode()

    def action_threat_hunting(self) -> None:
        self.query_one("#main-switcher", ContentSwitcher).current = "findings-view"
        self.query_one(FindingsView).show_threat_mode()

    def action_evidence(self) -> None:
        self.query_one("#main-switcher", ContentSwitcher).current = "logs-view"

    async def action_search(self) -> None:
        active = self._active_view()
        if hasattr(active, "focus_search"):
            active.focus_search()
            return
        query = await self.push_screen_wait(SearchModal())
        if query is None:
            return

    async def action_inspect(self) -> None:
        active = self._active_view()
        if hasattr(active, "selected_payload"):
            payload = active.selected_payload()
            if payload:
                await self.push_screen(DetailModal(payload))

    async def action_back(self) -> None:
        if len(self.screen_stack) > 1:
            self.pop_screen()

    async def on_live_alert_message(self, message: LiveAlertMessage) -> None:
        if self._snapshot is None:
            return
        existing = [alert for alert in self._snapshot.alerts if alert.alert_id != message.alert.alert_id]
        self._snapshot.alerts = [message.alert] + existing[:199]
        self.query_one(DashboardView).update_dashboard(
            self._snapshot.dashboard,
            self._snapshot.alerts,
            self._snapshot.queue_metrics,
        )
        self.query_one(AlertsView).update_records(self._snapshot.alerts)

    async def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            await asyncio.sleep(self._refresh_interval)
            if self._stop_event.is_set():
                break
            await self.action_refresh()

    async def _stream_loop(self) -> None:
        async for alert in self._client.stream_alerts(self._stop_event):
            self.post_message(LiveAlertMessage(alert))

    def _active_view(self) -> Widget:
        current = self.query_one("#main-switcher", ContentSwitcher).current
        return self.query_one(f"#{current}")

    def _apply_snapshot(self, snapshot: DashboardSnapshot) -> None:
        self.query_one(DashboardView).update_dashboard(snapshot.dashboard, snapshot.alerts, snapshot.queue_metrics)
        self.query_one(IncidentsView).update_records(snapshot.incidents)
        self.query_one(AlertsView).update_records(snapshot.alerts)
        findings_view = self.query_one(FindingsView)
        findings_view.update_findings(snapshot.findings)
        findings_view.update_threat_hunt(snapshot.threat_hunt)
        self.query_one(AttackGraphView).update_records(snapshot.coverage)
        self.query_one(LogsView).update_entries(snapshot.evidence_timeline)

    def _set_error(self, message: str | None) -> None:
        banner = self.query_one("#error-banner", Static)
        if message is None:
            banner.styles.display = "none"
            banner.update("")
            return
        banner.styles.display = "block"
        banner.update(message)
