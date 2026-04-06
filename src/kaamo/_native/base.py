from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import Final

from kaamo.config import settings

_CANDIDATES: Final[tuple[Path, ...]] = (
    settings.native_lib_path,
    Path.cwd() / "build" / "native" / "libkaamo.so",
    Path.cwd() / "build" / "native" / "libkaamo.dylib",
)


def load_native_library() -> ctypes.CDLL | None:
    override = os.environ.get("KAAMO_NATIVE_LIB")
    if override:
        candidate = Path(override)
        if candidate.exists():
            return ctypes.CDLL(str(candidate))
    for candidate in _CANDIDATES:
        if candidate.exists():
            return ctypes.CDLL(str(candidate))
    return None

