# Offline Setup

1. Build `libkaamo.so` with CMake.
2. Install the Python package and optional dependencies needed for your host.
3. Populate the official Gemma SHA-256 hashes in `src/kaamo/models/gemma_manager.py`.
4. Run `kaamo pull-model --variant auto` once while online.
5. Run `kaamo verify-model --variant auto` and confirm success.
6. Air-gap the host and start Kaamo in `KAAMO_MODE=offline`.

For offline validation, the recommended smoke test is to run the daemon or CLI inside an environment with networking disabled and confirm inference uses the local Gemma path only.

