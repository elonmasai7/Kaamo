# Cache Design

Kaamo uses layered caching:

- L0: KV-prefix cache for prompt-prefix reuse
- L1: deterministic response cache for `temperature == 0`
- L2: Redis-backed shared state and rate-limit data
- L3: PostgreSQL-backed durable history

Every cache layer should emit hit and miss metrics. TTL-backed invalidation is the default rule for mutable state.

