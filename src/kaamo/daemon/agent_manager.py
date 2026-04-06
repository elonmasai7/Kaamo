from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from kaamo.audit import write_audit_log
from kaamo.sandbox.docker_client import KaamoDockerClient, SandboxSpec


@dataclass(slots=True)
class AgentDefinition:
    agent_id: str
    image: str
    model_path: Path
    command: list[str] = field(default_factory=lambda: ["sleep", "infinity"])


class AgentManager:
    def __init__(self, docker_client: KaamoDockerClient | None = None) -> None:
        self._docker = docker_client or KaamoDockerClient()

    async def create(self, definition: AgentDefinition) -> dict[str, object]:
        config = self._docker.create_agent_container(
            SandboxSpec(
                image=definition.image,
                command=definition.command,
                model_mount=definition.model_path,
            )
        )
        write_audit_log("agent.create", "system", definition.agent_id, image=definition.image)
        return config

