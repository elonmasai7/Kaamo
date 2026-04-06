from __future__ import annotations

import ctypes
import time
from collections.abc import MutableMapping

from kaamo._native.base import load_native_library

_LIB = load_native_library()


class NativeResponseCache:
    def __init__(self, capacity_entries: int = 512, max_value_size: int = 65536) -> None:
        self._fallback: MutableMapping[int, tuple[bytes, float]] = {}
        self._capacity_entries = capacity_entries
        self._max_value_size = max_value_size
        self._cache_ptr: ctypes.c_void_p | None = None
        if _LIB is not None:
            _LIB.cache_create.restype = ctypes.c_void_p
            _LIB.cache_create.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
            _LIB.cache_get.restype = ctypes.c_int
            _LIB.cache_get.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint64,
                ctypes.POINTER(ctypes.c_ubyte),
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_size_t),
            ]
            _LIB.cache_set.restype = ctypes.c_int
            _LIB.cache_set.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint64,
                ctypes.c_char_p,
                ctypes.c_size_t,
                ctypes.c_int64,
            ]
            self._cache_ptr = ctypes.c_void_p(
                _LIB.cache_create(capacity_entries, max_value_size)
            )

    def get(self, key: int) -> bytes | None:
        if self._cache_ptr is None or _LIB is None:
            item = self._fallback.get(key)
            if item is None:
                return None
            value, expires_at = item
            if expires_at < time.time():
                del self._fallback[key]
                return None
            return value
        buffer = (ctypes.c_ubyte * self._max_value_size)()
        out_len = ctypes.c_size_t()
        result = _LIB.cache_get(
            self._cache_ptr,
            ctypes.c_uint64(key),
            buffer,
            ctypes.c_size_t(self._max_value_size),
            ctypes.byref(out_len),
        )
        if result != 0:
            return None
        return bytes(buffer[: out_len.value])

    def set(self, key: int, value: bytes, ttl_ms: int) -> None:
        if self._cache_ptr is None or _LIB is None:
            self._fallback[key] = (value, time.time() + (ttl_ms / 1000))
            if len(self._fallback) > self._capacity_entries:
                oldest_key = next(iter(self._fallback))
                del self._fallback[oldest_key]
            return
        _LIB.cache_set(
            self._cache_ptr,
            ctypes.c_uint64(key),
            value,
            ctypes.c_size_t(len(value)),
            ctypes.c_int64(ttl_ms),
        )
