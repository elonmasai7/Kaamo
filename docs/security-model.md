# Security Model

Default posture:

- Offline mode disables network access for sandboxed agents.
- Containers are configured read-only, with all Linux capabilities dropped.
- The seccomp profile uses a deny-by-default shape and exposes only a narrow syscall set.
- Secrets are expected in keyring-backed storage instead of config files.
- Model verification is mandatory before a GGUF is used.

This scaffold exports the seccomp profile as JSON for Docker-style enforcement. Host-level iptables, cgroup, and Docker daemon policies still need to be applied in deployment.

