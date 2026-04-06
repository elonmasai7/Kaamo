# Gemma 3 Integration

Kaamo expects Gemma GGUF artifacts to live in `~/.kaamo/models/` with file mode `0600`. Downloads support resume via HTTP range requests and are validated with the native SHA-256 path before use.

The local backend uses the Gemma 3 turn template:

```text
<start_of_turn>user
message<end_of_turn>
<start_of_turn>model
```

Caching rules:

- Prefix state caching is intended for prompt-prefix reuse.
- Final response caching is only allowed when `temperature == 0`.
- Non-deterministic responses must always bypass the response cache.

