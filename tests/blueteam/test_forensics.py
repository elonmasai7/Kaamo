from __future__ import annotations

from pathlib import Path

from kaamo.blueteam.forensics.collector import ForensicsCollector


def test_forensics_collector_writes_immutable_artifact(tmp_path: Path) -> None:
    collector = ForensicsCollector(evidence_dir=tmp_path)
    artifact = collector.collect_artifact(
        {
            "source_host": "srv-1",
            "name": "process-tree",
            "content": "proc -> child",
        }
    )
    evidence_path = Path(artifact.evidence_path)
    assert evidence_path.exists()
    assert oct(evidence_path.stat().st_mode & 0o777) == "0o400"

