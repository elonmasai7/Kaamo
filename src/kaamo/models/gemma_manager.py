from __future__ import annotations

import asyncio
import os
import stat
from collections.abc import Callable
from pathlib import Path

import httpx

from kaamo._native.sha256 import verify_file
from kaamo.config import settings
from kaamo.logging import get_logger
from kaamo.models.hardware import detect_hardware, recommend_config

logger = get_logger(__name__)

GEMMA3_MODELS: dict[str, dict[str, str | int]] = {
    "gemma-3-1b-it": {
        "url": "https://huggingface.co/bartowski/gemma-3-1b-it-GGUF/resolve/main/gemma-3-1b-it-Q4_K_M.gguf",
        "sha256": "REPLACE_WITH_OFFICIAL_SHA256",
        "size_bytes": 800_000_000,
    },
    "gemma-3-4b-it": {
        "url": "https://huggingface.co/bartowski/gemma-3-4b-it-GGUF/resolve/main/gemma-3-4b-it-Q4_K_M.gguf",
        "sha256": "REPLACE_WITH_OFFICIAL_SHA256",
        "size_bytes": 2_500_000_000,
    },
    "gemma-3-12b-it": {
        "url": "https://huggingface.co/bartowski/gemma-3-12b-it-GGUF/resolve/main/gemma-3-12b-it-Q4_K_M.gguf",
        "sha256": "REPLACE_WITH_OFFICIAL_SHA256",
        "size_bytes": 7_500_000_000,
    },
    "gemma-3-27b-it": {
        "url": "https://huggingface.co/bartowski/gemma-3-27b-it-GGUF/resolve/main/gemma-3-27b-it-Q4_K_M.gguf",
        "sha256": "REPLACE_WITH_OFFICIAL_SHA256",
        "size_bytes": 16_000_000_000,
    },
}

MODEL_STORE = settings.resolved_model_store


class ModelVerificationError(RuntimeError):
    pass


def _model_path(variant: str) -> Path:
    return MODEL_STORE / f"{variant}.gguf"


def verify_model(path: Path, expected_sha256: str) -> bool:
    if expected_sha256.startswith("REPLACE_"):
        raise ModelVerificationError("Official Gemma SHA-256 hash is not configured")
    return verify_file(path, expected_sha256)


async def download_model(
    variant: str,
    progress_callback: Callable[[int], None] | None = None,
) -> Path:
    if variant == "auto":
        variant = detect_best_variant()
    if variant not in GEMMA3_MODELS:
        raise KeyError(f"Unknown Gemma variant: {variant}")
    metadata = GEMMA3_MODELS[variant]
    MODEL_STORE.mkdir(parents=True, exist_ok=True)
    target = _model_path(variant)
    expected_sha256 = str(metadata["sha256"])
    if target.exists() and verify_model(target, expected_sha256):
        logger.info("model.download.cache_hit", variant=variant, path=str(target))
        return target

    headers: dict[str, str] = {}
    existing_size = target.stat().st_size if target.exists() else 0
    if existing_size > 0:
        headers["Range"] = f"bytes={existing_size}-"
    async with httpx.AsyncClient(timeout=None, follow_redirects=True) as client:
        async with client.stream("GET", str(metadata["url"]), headers=headers) as response:
            response.raise_for_status()
            mode = "ab" if existing_size > 0 and response.status_code == 206 else "wb"
            with target.open(mode) as handle:
                async for chunk in response.aiter_bytes():
                    handle.write(chunk)
                    if progress_callback is not None:
                        await asyncio.to_thread(progress_callback, len(chunk))
    target.chmod(stat.S_IRUSR | stat.S_IWUSR)
    if not verify_model(target, expected_sha256):
        raise ModelVerificationError(f"SHA-256 mismatch for {variant}")
    return target


def detect_best_variant() -> str:
    override = os.environ.get("KAAMO_GEMMA_MODEL")
    if override:
        return override
    hw = detect_hardware()
    return str(recommend_config(hw)["gemma_variant"])
