from __future__ import annotations

import json
from pathlib import Path

from kaamo._native.seccomp import load_profile_json


def generate_seccomp_profile() -> dict[str, object]:
    return json.loads(load_profile_json())


def write_seccomp_profile(path: Path) -> Path:
    path.write_text(json.dumps(generate_seccomp_profile(), indent=2), encoding="utf-8")
    return path

