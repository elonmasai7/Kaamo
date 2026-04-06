from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import timedelta
from typing import Literal

from pydantic import BaseModel, Field

from kaamo.audit import write_audit_log
from kaamo.blueteam.base import BlueTeamModule, MITREMapping, ModuleResult, SecurityContext, SecurityEvent


class DetectionRule(BaseModel):
    rule_id: str
    name: str
    condition: str
    severity: Literal["low", "medium", "high", "critical"]
    enabled: bool = True


class DetectionAlert(BaseModel):
    rule_id: str
    name: str
    severity: Literal["low", "medium", "high", "critical"]
    event_ids: list[str] = Field(default_factory=list)
    host: str | None = None
    user: str | None = None
    reason: str
    mitre: MITREMapping | None = None


DEFAULT_RULES: list[DetectionRule] = [
    DetectionRule(rule_id="KAAMO-BT-001", name="IOC Detection", condition="match any IOC", severity="high"),
    DetectionRule(rule_id="KAAMO-BT-002", name="Brute Force To Success", condition="5 failed logins then success from new IP within 10m", severity="critical"),
    DetectionRule(rule_id="KAAMO-BT-003", name="Privilege Escalation", condition="sudo or admin escalation indicators", severity="high"),
    DetectionRule(rule_id="KAAMO-BT-004", name="Suspicious Process Chain", condition="command shell to downloader or PowerShell", severity="high"),
    DetectionRule(rule_id="KAAMO-BT-005", name="Lateral Movement Indicator", condition="remote exec, psexec, wmi, smb admin share", severity="critical"),
    DetectionRule(rule_id="KAAMO-BT-006", name="DNS Tunneling Suspicion", condition="long or frequent TXT/subdomain queries", severity="medium"),
    DetectionRule(rule_id="KAAMO-BT-007", name="Persistence Indicator", condition="autorun, cron, service install, scheduled task", severity="high"),
]


class RulesEngine(BlueTeamModule):
    name = "rules_engine"
    description = "Rule-based and correlation-driven threat detections"

    def __init__(self, rules: Iterable[DetectionRule] | None = None) -> None:
        self._rules = [rule for rule in (rules or DEFAULT_RULES) if rule.enabled]

    async def analyze(self, context: SecurityContext) -> ModuleResult:
        alerts = self.detect(context.events, context.indicators_of_compromise)
        write_audit_log("blueteam.rules_engine.analyze", "system", self.name, alert_count=len(alerts))
        return ModuleResult(
            module_name=self.name,
            summary=f"Generated {len(alerts)} detection alerts from {len(context.events)} events.",
            findings=[alert.model_dump(mode="json") for alert in alerts],
            metrics={"alerts": float(len(alerts)), "rules_enabled": float(len(self._rules))},
        )

    def detect(self, events: list[SecurityEvent], indicators_of_compromise: list[str] | None = None) -> list[DetectionAlert]:
        iocs = indicators_of_compromise or []
        alerts: list[DetectionAlert] = []
        alerts.extend(self._detect_iocs(events, iocs))
        alerts.extend(self._detect_brute_force(events))
        alerts.extend(self._detect_privilege_escalation(events))
        alerts.extend(self._detect_process_chain(events))
        alerts.extend(self._detect_lateral_movement(events))
        alerts.extend(self._detect_dns_tunneling(events))
        alerts.extend(self._detect_persistence(events))
        return alerts

    def _detect_iocs(self, events: list[SecurityEvent], iocs: list[str]) -> list[DetectionAlert]:
        if not iocs:
            return []
        alerts: list[DetectionAlert] = []
        for event in events:
            payload_text = json.dumps(event.raw_payload, sort_keys=True, default=str).lower()
            matches = [ioc for ioc in iocs if ioc.lower() in payload_text]
            if matches:
                alerts.append(
                    DetectionAlert(
                        rule_id="KAAMO-BT-001",
                        name="IOC Detection",
                        severity="high",
                        event_ids=[event.event_id],
                        host=event.host,
                        user=event.user,
                        reason=f"Matched IOCs: {', '.join(matches[:5])}",
                        mitre=MITREMapping(technique_id="T1588", tactic="resource-development", confidence=0.7),
                    )
                )
        return alerts

    def _detect_brute_force(self, events: list[SecurityEvent]) -> list[DetectionAlert]:
        grouped_failures: dict[tuple[str, str | None], list[SecurityEvent]] = defaultdict(list)
        successful_logins: list[SecurityEvent] = []
        for event in sorted(events, key=lambda item: item.timestamp):
            lower_type = event.event_type.lower()
            if "fail" in lower_type and "login" in lower_type:
                grouped_failures[(event.host, event.user)].append(event)
            elif "success" in lower_type and "login" in lower_type:
                successful_logins.append(event)
        alerts: list[DetectionAlert] = []
        for success in successful_logins:
            key = (success.host, success.user)
            failed = [
                event for event in grouped_failures.get(key, [])
                if success.timestamp - event.timestamp <= timedelta(minutes=10)
            ]
            ips = {str(event.raw_payload.get("source_ip")) for event in failed if event.raw_payload.get("source_ip")}
            success_ip = str(success.raw_payload.get("source_ip"))
            if len(failed) >= 5 and success_ip and success_ip not in ips:
                alerts.append(
                    DetectionAlert(
                        rule_id="KAAMO-BT-002",
                        name="Brute Force To Success",
                        severity="critical",
                        event_ids=[event.event_id for event in failed[-5:]] + [success.event_id],
                        host=success.host,
                        user=success.user,
                        reason="Observed 5 failed logins followed by a successful login from a new IP within 10 minutes.",
                        mitre=MITREMapping(technique_id="T1110", tactic="credential-access", confidence=0.93),
                    )
                )
        return alerts

    def _detect_privilege_escalation(self, events: list[SecurityEvent]) -> list[DetectionAlert]:
        patterns = ("sudo", "runas", "token_elevation", "admin", "privilege")
        alerts: list[DetectionAlert] = []
        for event in events:
            payload_text = json.dumps(event.raw_payload, sort_keys=True, default=str).lower()
            if any(pattern in event.event_type.lower() or pattern in payload_text for pattern in patterns):
                alerts.append(
                    DetectionAlert(
                        rule_id="KAAMO-BT-003",
                        name="Privilege Escalation",
                        severity="high",
                        event_ids=[event.event_id],
                        host=event.host,
                        user=event.user,
                        reason="Privilege escalation indicator observed in event metadata.",
                        mitre=MITREMapping(technique_id="T1068", tactic="privilege-escalation", confidence=0.82),
                    )
                )
        return alerts

    def _detect_process_chain(self, events: list[SecurityEvent]) -> list[DetectionAlert]:
        alerts: list[DetectionAlert] = []
        for event in events:
            parent = str(event.raw_payload.get("parent_process", "")).lower()
            child = str(event.raw_payload.get("process_name", "")).lower()
            command = str(event.raw_payload.get("command_line", "")).lower()
            suspicious = (
                ("powershell" in child and any(token in parent for token in ("cmd", "winword", "excel", "wscript")))
                or ("curl" in command and ("bash -c" in command or "sh -" in command))
                or ("wget" in command and "chmod +x" in command)
            )
            if suspicious:
                alerts.append(
                    DetectionAlert(
                        rule_id="KAAMO-BT-004",
                        name="Suspicious Process Chain",
                        severity="high",
                        event_ids=[event.event_id],
                        host=event.host,
                        user=event.user,
                        reason="Unusual parent/child process chain suggests script execution or payload staging.",
                        mitre=MITREMapping(technique_id="T1059", tactic="execution", confidence=0.91),
                    )
                )
        return alerts

    def _detect_lateral_movement(self, events: list[SecurityEvent]) -> list[DetectionAlert]:
        patterns = ("psexec", "wmic", "winrm", "remote service", "admin$", "smbexec", "ssh lateral")
        alerts: list[DetectionAlert] = []
        for event in events:
            payload_text = json.dumps(event.raw_payload, sort_keys=True, default=str).lower()
            if any(pattern in payload_text or pattern in event.event_type.lower() for pattern in patterns):
                alerts.append(
                    DetectionAlert(
                        rule_id="KAAMO-BT-005",
                        name="Lateral Movement Indicator",
                        severity="critical",
                        event_ids=[event.event_id],
                        host=event.host,
                        user=event.user,
                        reason="Remote execution or administrative share access detected.",
                        mitre=MITREMapping(technique_id="T1021", tactic="lateral-movement", confidence=0.88),
                    )
                )
        return alerts

    def _detect_dns_tunneling(self, events: list[SecurityEvent]) -> list[DetectionAlert]:
        dns_queries = [event for event in events if "dns" in event.event_type.lower()]
        query_counts: Counter[str] = Counter()
        alerts: list[DetectionAlert] = []
        for event in dns_queries:
            query = str(event.raw_payload.get("query") or event.raw_payload.get("domain") or "").lower()
            if not query:
                continue
            query_counts[event.host] += 1
            long_labels = any(len(label) >= 40 for label in query.split("."))
            suspicious_encoding = bool(re.search(r"[a-z0-9]{25,}", query))
            if long_labels or suspicious_encoding or query_counts[event.host] > 50:
                alerts.append(
                    DetectionAlert(
                        rule_id="KAAMO-BT-006",
                        name="DNS Tunneling Suspicion",
                        severity="medium",
                        event_ids=[event.event_id],
                        host=event.host,
                        user=event.user,
                        reason="Observed long or unusually dense DNS query patterns.",
                        mitre=MITREMapping(technique_id="T1071.004", tactic="command-and-control", confidence=0.76),
                    )
                )
        return alerts

    def _detect_persistence(self, events: list[SecurityEvent]) -> list[DetectionAlert]:
        patterns = ("scheduled task", "autorun", "startup", "service install", "cron", "launch agent")
        alerts: list[DetectionAlert] = []
        for event in events:
            payload_text = json.dumps(event.raw_payload, sort_keys=True, default=str).lower()
            if any(pattern in payload_text or pattern in event.event_type.lower() for pattern in patterns):
                alerts.append(
                    DetectionAlert(
                        rule_id="KAAMO-BT-007",
                        name="Persistence Indicator",
                        severity="high",
                        event_ids=[event.event_id],
                        host=event.host,
                        user=event.user,
                        reason="Observed a startup or scheduled execution persistence artifact.",
                        mitre=MITREMapping(technique_id="T1053", tactic="persistence", confidence=0.84),
                    )
                )
        return alerts

