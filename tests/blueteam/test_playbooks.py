from __future__ import annotations

from kaamo.blueteam.response.playbooks import ResponsePlaybookModule


def test_playbook_module_recommends_non_destructive_steps() -> None:
    module = ResponsePlaybookModule()
    playbook = module.recommend({"name": "Suspicious Process Chain", "severity": "high"})
    assert playbook is not None
    assert playbook.title == "Suspicious Execution Chain Review"
    assert all("execute" not in step.lower() for step in playbook.steps)

