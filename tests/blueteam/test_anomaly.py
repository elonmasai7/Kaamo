from __future__ import annotations

from kaamo.blueteam.anomaly.baseline import BaselineTracker


def test_anomaly_tracker_flags_large_z_score() -> None:
    tracker = BaselineTracker(window_size=10)
    for value in (10, 12, 11, 13, 12, 11):
        tracker.observe("login_hour", float(value))
    alert = tracker.detect("login_hour", 42.0)
    assert alert is not None
    assert alert.metric == "login_hour"
    assert alert.anomaly_score >= 2.0

