from __future__ import annotations

import math
from collections import defaultdict, deque
from statistics import mean, pstdev

from pydantic import BaseModel

from kaamo.audit import write_audit_log
from kaamo.blueteam.base import BlueTeamModule, ModuleResult, SecurityContext


class AnomalyAlert(BaseModel):
    metric: str
    observed_value: float
    expected_range: tuple[float, float]
    anomaly_score: float


class BaselineTracker:
    def __init__(self, window_size: int = 30) -> None:
        self._history: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=window_size))

    def observe(self, metric: str, value: float) -> None:
        self._history[metric].append(value)

    def detect(self, metric: str, observed_value: float) -> AnomalyAlert | None:
        series = list(self._history.get(metric, []))
        if len(series) < 3:
            return None
        mu = mean(series)
        sigma = pstdev(series)
        low = min(series)
        high = max(series)
        if sigma == 0:
            sigma = max(abs(mu) * 0.05, 1.0)
        z_score = abs((observed_value - mu) / sigma)
        percentile_gap = 0.0
        if observed_value < low:
            percentile_gap = low - observed_value
        elif observed_value > high:
            percentile_gap = observed_value - high
        anomaly_score = round(z_score + math.log1p(percentile_gap), 4)
        if anomaly_score < 2.0:
            return None
        return AnomalyAlert(
            metric=metric,
            observed_value=observed_value,
            expected_range=(round(low, 4), round(high, 4)),
            anomaly_score=anomaly_score,
        )


class AnomalyDetectionModule(BlueTeamModule):
    name = "anomaly_detection"
    description = "Rolling-baseline anomaly detection for user and host behavior"

    def __init__(self, tracker: BaselineTracker | None = None) -> None:
        self._tracker = tracker or BaselineTracker()

    async def analyze(self, context: SecurityContext) -> ModuleResult:
        baseline = context.metadata.get("baseline_observations", {})
        for metric, values in baseline.items():
            for value in values:
                self._tracker.observe(metric, float(value))
        current = context.metadata.get("current_observations", {})
        alerts: list[AnomalyAlert] = []
        for metric, value in current.items():
            detected = self._tracker.detect(metric, float(value))
            if detected is not None:
                alerts.append(detected)
        write_audit_log("blueteam.anomaly.analyze", "system", self.name, anomaly_count=len(alerts))
        return ModuleResult(
            module_name=self.name,
            summary=f"Detected {len(alerts)} behavioral anomalies against rolling baselines.",
            findings=[alert.model_dump(mode="json") for alert in alerts],
            metrics={"anomalies": float(len(alerts))},
        )

