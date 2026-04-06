from __future__ import annotations

from kaamo.cache.kv_cache import GemmaKVCache


def test_response_cache_only_when_temperature_is_zero() -> None:
    cache = GemmaKVCache()
    messages = [{"role": "user", "content": "hello"}]
    deterministic_key = cache.make_key(messages, temperature=0.0)
    nondeterministic_key = cache.make_key(messages, temperature=0.7)
    assert deterministic_key is not None
    assert nondeterministic_key is None
    cache.set(deterministic_key, "world", ttl_s=60)
    assert cache.get(deterministic_key) == "world"
    assert cache.get(nondeterministic_key) is None

