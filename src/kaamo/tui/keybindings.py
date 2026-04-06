from __future__ import annotations

from typing import TypeAlias

from textual.binding import Binding

BindingSpec: TypeAlias = Binding | tuple[str, str] | tuple[str, str, str]

DASHBOARD_BINDINGS: list[BindingSpec] = [
    Binding("q", "quit", "Quit"),
    Binding("r", "refresh", "Refresh"),
    Binding("f", "findings", "Findings"),
    Binding("i", "incidents", "Incidents"),
    Binding("a", "alerts", "Alerts"),
    Binding("t", "threat_hunting", "Threat Hunting"),
    Binding("e", "evidence", "Evidence"),
    Binding("d", "dashboard", "Dashboard"),
    Binding("/", "search", "Search"),
    Binding("enter", "inspect", "Inspect"),
    Binding("escape", "back", "Back"),
]
