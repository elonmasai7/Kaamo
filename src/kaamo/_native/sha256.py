from __future__ import annotations

import ctypes
import hashlib
from pathlib import Path

from kaamo._native.base import load_native_library

_LIB = load_native_library()


def verify_file(path: Path, expected_sha256: str) -> bool:
    if _LIB is not None:
        _LIB.sha256_file_verify.restype = ctypes.c_int
        _LIB.sha256_file_verify.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        result = _LIB.sha256_file_verify(
            str(path).encode("utf-8"),
            expected_sha256.encode("utf-8"),
        )
        result_int = int(result)
        if result_int < 0:
            raise RuntimeError(f"Native SHA-256 verification failed with code {result_int}")
        return result_int == 1
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest() == expected_sha256
