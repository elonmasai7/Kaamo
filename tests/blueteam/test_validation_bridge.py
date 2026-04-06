from __future__ import annotations

from kaamo.security.validation_bridge import ValidationBridge


def test_validation_bridge_scores_attack_path_coverage() -> None:
    bridge = ValidationBridge()
    coverage = bridge.validate(
        attack_paths=[
            {
                "attack_path_id": "path-1",
                "steps": ["powershell", "scheduled task", "dns tunnel"],
            }
        ],
        detections=[
            {"name": "Suspicious Process Chain", "reason": "powershell spawned from winword"},
            {"name": "Persistence Indicator", "reason": "scheduled task created"},
        ],
    )
    assert coverage[0].attack_path_id == "path-1"
    assert coverage[0].covered_steps == 2
    assert coverage[0].uncovered_steps == 1

