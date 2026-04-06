# Kaamo

Kaamo is an offline-first, security-focused runtime for sandboxed AI agents. This repository scaffolds the native cache/security primitives, Python orchestration layers, model-management workflow, daemon surface, CLI entrypoints, and an initial test suite for secure local Gemma-based inference with optional NVIDIA fallback.

## What is included

- Native C17 slabs for response and KV-prefix caching
- Native SHA-256 file verification and seccomp profile export
- Pydantic settings, structured logging, audit logging, and secret helpers
- Gemma model download/verification flow with resume support
- Llama.cpp backend wrapper, NVIDIA backend wrapper, model pool, queue, and router
- Docker sandbox configuration helpers and FastAPI daemon skeleton
- CLI commands for agent lifecycle, model install/verify, and benchmarking
- Unit, integration, and load-test scaffolding

## Important security note

`src/kaamo/models/gemma_manager.py` intentionally refuses model verification until real official Gemma SHA-256 values are populated in `GEMMA3_MODELS`. That keeps the project secure-by-default instead of silently trusting downloaded model artifacts.

## Quick start

```bash
cmake -B build/native src/native -DCMAKE_BUILD_TYPE=Debug
cmake --build build/native --parallel
python3 -m pip install -e ".[dev]"
pytest
```

## Current state

This is a production-oriented scaffold, not a fully provisioned deployment bundle. Some integrations remain environment-dependent:

- `llama-cpp-python` and GPU acceleration are optional and not bundled here
- Docker, Redis, PostgreSQL, and seccomp enforcement need host-level provisioning
- Official Gemma SHA-256 hashes must be populated before real model downloads are enabled

