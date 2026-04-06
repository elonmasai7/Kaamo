from __future__ import annotations

try:
    from prometheus_client import Counter, Gauge, Histogram
except ImportError:  # pragma: no cover - fallback for minimal environments
    class _Metric:
        def labels(self, **kwargs):
            del kwargs
            return self

        def inc(self, amount: float = 1.0) -> None:
            del amount

        def observe(self, amount: float) -> None:
            del amount

        def set(self, amount: float) -> None:
            del amount

    def Counter(*args, **kwargs):  # type: ignore[misc]
        del args, kwargs
        return _Metric()

    def Gauge(*args, **kwargs):  # type: ignore[misc]
        del args, kwargs
        return _Metric()

    def Histogram(*args, **kwargs):  # type: ignore[misc]
        del args, kwargs
        return _Metric()

cache_hits_total = Counter(
    "kaamo_cache_hits_total",
    "Kaamo cache hits by layer",
    ["layer"],
)
cache_misses_total = Counter(
    "kaamo_cache_misses_total",
    "Kaamo cache misses by layer",
    ["layer"],
)
cache_evictions_total = Counter(
    "kaamo_cache_evictions_total",
    "Kaamo cache evictions by layer",
    ["layer"],
)
gemma_inference_duration_seconds = Histogram(
    "kaamo_gemma_inference_duration_seconds",
    "Gemma inference duration",
    ["variant", "quantization"],
)
gemma_tokens_per_second = Gauge(
    "kaamo_gemma_tokens_per_second",
    "Observed Gemma tokens per second",
    ["variant", "quantization", "backend"],
)
model_pool_queue_depth = Gauge(
    "kaamo_model_pool_queue_depth",
    "Current model pool queue depth",
)
model_pool_wait_seconds = Histogram(
    "kaamo_model_pool_wait_seconds",
    "Model pool wait time",
)
circuit_breaker_state = Gauge(
    "kaamo_circuit_breaker_state",
    "Circuit breaker state by backend",
    ["backend"],
)
