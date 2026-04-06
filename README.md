# Kaamo

Kaamo is an offline-first, security-focused runtime for sandboxed AI agents. The primary operator experience is terminal-first: a live SOC and purple-team dashboard runs directly inside Linux/macOS terminals and remote SSH sessions through `kaamo dashboard`.

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
- A real Gemma manifest with official SHA-256 values must exist before model download or verification is enabled

## Terminal Dashboard

Kaamo ships a live terminal dashboard built on Textual.

1. Apply the database schema:

```bash
kaamo db-migrate
```

2. Create an analyst token:

```bash
kaamo create-token analyst-user --role analyst
```

3. Start the daemon:

```bash
uvicorn kaamo.daemon.server:app --host 127.0.0.1 --port 8080
```

You can also bind the daemon to a Unix domain socket for local terminal sessions:

```bash
uvicorn kaamo.daemon.server:app --uds "$HOME/.kaamo/kaamod.sock"
```

4. Launch the terminal UI:

```bash
KAAMO_API_TOKEN="<token>" kaamo dashboard
```

Low-resource mode disables websocket streaming and lengthens refresh cadence:

```bash
KAAMO_API_TOKEN="<token>" kaamo dashboard --low-resource
```

Keybindings:

- `q` quit
- `r` refresh
- `f` findings
- `i` incidents
- `a` alerts
- `t` threat hunting
- `e` evidence
- `d` dashboard
- `/` search
- `enter` inspect current item
- `esc` back
