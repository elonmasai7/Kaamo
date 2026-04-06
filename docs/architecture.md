# Architecture

Kaamo is split into four main planes:

1. Native plane: C17 cache, throttle, seccomp-profile, and SHA-256 helpers compiled into `libkaamo.so`.
2. Control plane: Python config, audit, logging, CLI, daemon, sandbox orchestration, and model management.
3. Inference plane: local Gemma via llama.cpp, optional NVIDIA fallback, a routing layer, queueing, and a small model pool.
4. Data plane: L0/L1 in-process cache, optional Redis/PostgreSQL integration, and audit/metrics emission.

The offline-first rule is enforced by design: business logic should only talk to `kaamo.inference.router`, and model loading should only happen after `kaamo.models.gemma_manager.verify_model`.

