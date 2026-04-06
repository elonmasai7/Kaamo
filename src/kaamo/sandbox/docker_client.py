from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kaamo.logging import get_logger
from kaamo.sandbox.network import hybrid_network_policy, offline_network_policy
from kaamo.sandbox.seccomp import generate_seccomp_profile

logger = get_logger(__name__)

try:
    import docker
except ImportError:  # pragma: no cover - optional dependency
    docker = None  # type: ignore[assignment]


@dataclass(slots=True)
class SandboxSpec:
    image: str
    command: list[str]
    model_mount: Path
    offline: bool = True
    cpu_limit: str = "1.0"
    memory_limit: str = "2g"


class KaamoDockerClient:
    def __init__(self) -> None:
        self._client = docker.from_env() if docker is not None else None

    def create_agent_container(self, spec: SandboxSpec) -> dict[str, Any]:
        security_opt = [f"seccomp={json.dumps(generate_seccomp_profile())}"]
        network_policy = offline_network_policy() if spec.offline else hybrid_network_policy(["api.nvidia.com"])
        config = {
            "image": spec.image,
            "command": spec.command,
            "read_only": True,
            "security_opt": security_opt,
            "network_disabled": spec.offline,
            "cap_drop": ["ALL"],
            "mem_limit": spec.memory_limit,
            "nano_cpus": int(float(spec.cpu_limit) * 1_000_000_000),
            "volumes": {
                str(spec.model_mount): {"bind": "/models", "mode": "ro"},
            },
            "labels": {"kaamo.agent": "true", "kaamo.network": network_policy["mode"]},
        }
        logger.info("sandbox.container.create", config=config)
        return config
