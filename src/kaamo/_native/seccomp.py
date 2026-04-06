from __future__ import annotations

import ctypes

from kaamo._native.base import load_native_library

_LIB = load_native_library()


def load_profile_json() -> str:
    if _LIB is None:
        return (
            '{"defaultAction":"SCMP_ACT_ERRNO","syscalls":['
            '{"names":["read","write","close"],"action":"SCMP_ACT_ALLOW"}]}'
        )
    _LIB.seccomp_profile_size.restype = ctypes.c_size_t
    size = int(_LIB.seccomp_profile_size()) + 1
    buffer = ctypes.create_string_buffer(size)
    result = _LIB.seccomp_profile_copy(buffer, ctypes.c_size_t(size))
    if result != 0:
        raise RuntimeError("Unable to load seccomp profile from native library")
    return buffer.value.decode("utf-8")

