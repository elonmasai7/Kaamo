from __future__ import annotations

import hashlib
import json
from typing import Any

from kaamo._native.kv_cache import NativeKVCache
from kaamo._native.cache import NativeResponseCache
from kaamo.cache.metrics import cache_hits_total, cache_misses_total


class GemmaKVCache:
    def __init__(self, max_entries: int = 1024, max_prefix_bytes: int = 262144) -> None:
        self._prefix = NativeKVCache(capacity_entries=max_entries, max_kv_bytes_each=max_prefix_bytes)
        self._responses = NativeResponseCache(capacity_entries=max_entries, max_value_size=65536)

    @staticmethod
    def _canonical_messages(messages: list[dict[str, Any]]) -> str:
        normalized = [
            {
                "role": message["role"].strip(),
                "content": " ".join(str(message["content"]).split()),
            }
            for message in messages
        ]
        return json.dumps(normalized, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

    def make_key(self, messages: list[dict[str, Any]], temperature: float = 0.7) -> str | None:
        if temperature > 0:
            return None
        canonical = self._canonical_messages(messages)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def make_prefix_hash(self, messages: list[dict[str, Any]]) -> int:
        canonical = self._canonical_messages(messages)
        digest = hashlib.sha256(canonical.encode("utf-8")).digest()
        return int.from_bytes(digest[:8], byteorder="big", signed=False)

    def get_prefix_state(self, prefix_hash: str) -> bytes | None:
        key = int(prefix_hash, 16)
        value = self._prefix.get(key)
        if value is None:
            cache_misses_total.labels(layer="l0_kv").inc()
        else:
            cache_hits_total.labels(layer="l0_kv").inc()
        return value

    def set_prefix_state(self, prefix_hash: str, kv_bytes: bytes, ttl_s: int = 7200) -> None:
        key = int(prefix_hash, 16)
        self._prefix.set(key, kv_bytes, ttl_s * 1000)

    def get(self, cache_key: str | None) -> str | None:
        if cache_key is None:
            return None
        key = int(cache_key[:16], 16)
        value = self._responses.get(key)
        if value is None:
            cache_misses_total.labels(layer="l1_resp").inc()
            return None
        cache_hits_total.labels(layer="l1_resp").inc()
        return value.decode("utf-8")

    def set(self, cache_key: str | None, value: str, ttl_s: int = 1800) -> None:
        if cache_key is None:
            return
        key = int(cache_key[:16], 16)
        self._responses.set(key, value.encode("utf-8"), ttl_s * 1000)

