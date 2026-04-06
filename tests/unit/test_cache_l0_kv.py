from __future__ import annotations

import hashlib
import time

from kaamo._native.kv_cache import NativeKVCache
from kaamo.cache.kv_cache import GemmaKVCache


def test_prefix_cache_hit_and_miss() -> None:
    cache = GemmaKVCache()
    prefix_hash = hashlib.sha256(b"prefix").hexdigest()[:16]
    assert cache.get_prefix_state(prefix_hash) is None
    cache.set_prefix_state(prefix_hash, b"kv-state", ttl_s=60)
    assert cache.get_prefix_state(prefix_hash) == b"kv-state"


def test_native_kv_cache_ttl_expiry() -> None:
    cache = NativeKVCache(capacity_entries=4, max_kv_bytes_each=64)
    cache.set(7, b"data", ttl_ms=1)
    time.sleep(0.01)
    assert cache.get(7) is None

