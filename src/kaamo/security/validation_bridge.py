from __future__ import annotations

from pydantic import BaseModel

from kaamo.audit import write_audit_log


class DetectionCoverage(BaseModel):
    attack_path_id: str
    covered_steps: int
    uncovered_steps: int
    coverage_score: float


class ValidationBridge:
    def validate(
        self,
        attack_paths: list[dict[str, object]],
        detections: list[dict[str, object]],
    ) -> list[DetectionCoverage]:
        detection_text = " ".join(self._flatten_detection(det) for det in detections).lower()
        coverage: list[DetectionCoverage] = []
        for attack_path in attack_paths:
            attack_path_id = str(attack_path.get("attack_path_id", "unknown-path"))
            raw_steps = attack_path.get("steps", [])
            if not isinstance(raw_steps, list):
                raw_steps = []
            steps = [str(step).lower() for step in raw_steps]
            covered = sum(1 for step in steps if step and step in detection_text)
            uncovered = max(len(steps) - covered, 0)
            score = round((covered / len(steps)) if steps else 0.0, 4)
            coverage.append(
                DetectionCoverage(
                    attack_path_id=attack_path_id,
                    covered_steps=covered,
                    uncovered_steps=uncovered,
                    coverage_score=score,
                )
            )
        write_audit_log("security.validation_bridge.validate", "system", "validation_bridge", path_count=len(coverage))
        return coverage

    @staticmethod
    def _flatten_detection(detection: dict[str, object]) -> str:
        values = [str(value) for value in detection.values()]
        return " ".join(values)
