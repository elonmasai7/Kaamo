from __future__ import annotations

import asyncio
import re
import json
import os
import stat
from collections.abc import Callable
from pathlib import Path

import httpx
from pydantic import BaseModel, Field, HttpUrl

from kaamo._native.sha256 import verify_file
from kaamo.config import settings
from kaamo.logging import get_logger
from kaamo.models.hardware import detect_hardware, recommend_config

logger = get_logger(__name__)

MODEL_STORE = settings.resolved_model_store


class ModelVerificationError(RuntimeError):
    pass


class ModelManifestError(RuntimeError):
    pass


class GemmaModelEntry(BaseModel):
    variant: str
    url: HttpUrl
    sha256: str = Field(min_length=64, max_length=64)
    size_bytes: int = Field(gt=0)
    filename: str


class GemmaModelManifest(BaseModel):
    version: str
    models: list[GemmaModelEntry]

    def get(self, variant: str) -> GemmaModelEntry:
        for model in self.models:
            if model.variant == variant:
                return model
        raise KeyError(f"Variant {variant} is not present in the configured manifest")


def load_manifest(path: Path | None = None) -> GemmaModelManifest:
    manifest_path = path or settings.resolved_model_manifest
    if not manifest_path.exists():
        raise ModelManifestError(
            f"Gemma model manifest not found at {manifest_path}. "
            "Create a signed manifest with official variant URLs and SHA-256 values before use."
        )
    raw_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return GemmaModelManifest.model_validate(raw_manifest)


def _model_path(entry: GemmaModelEntry) -> Path:
    return MODEL_STORE / entry.filename


def verify_model(path: Path, expected_sha256: str) -> bool:
    if not path.exists():
        raise ModelVerificationError(f"Model file does not exist: {path}")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ModelVerificationError("Configured SHA-256 must be a 64-character lowercase hex string")
    return verify_file(path, expected_sha256)


def resolve_model_path(variant: str | None = None) -> Path:
    selected_variant = variant or detect_best_variant()
    manifest = load_manifest()
    entry = manifest.get(selected_variant)
    path = _model_path(entry)
    if not verify_model(path, entry.sha256):
        raise ModelVerificationError(f"Model verification failed for {selected_variant} at {path}")
    return path


async def download_model(
    variant: str,
    progress_callback: Callable[[int], None] | None = None,
) -> Path:
    if variant == "auto":
        variant = detect_best_variant()
    manifest = load_manifest()
    entry = manifest.get(variant)
    MODEL_STORE.mkdir(parents=True, exist_ok=True)
    target = _model_path(entry)
    if target.exists() and verify_model(target, entry.sha256):
        logger.info("model.download.cache_hit", variant=variant, path=str(target))
        return target

    headers: dict[str, str] = {}
    existing_size = target.stat().st_size if target.exists() else 0
    if existing_size > 0:
        headers["Range"] = f"bytes={existing_size}-"
    async with httpx.AsyncClient(timeout=None, follow_redirects=True) as client:
        async with client.stream("GET", str(entry.url), headers=headers) as response:
            response.raise_for_status()
            mode = "ab" if existing_size > 0 and response.status_code == 206 else "wb"
            with target.open(mode) as handle:
                async for chunk in response.aiter_bytes():
                    handle.write(chunk)
                    if progress_callback is not None:
                        await asyncio.to_thread(progress_callback, len(chunk))
    target.chmod(stat.S_IRUSR | stat.S_IWUSR)
    if not verify_model(target, entry.sha256):
        raise ModelVerificationError(f"SHA-256 mismatch for {variant}")
    return target


def detect_best_variant() -> str:
    override = os.environ.get("KAAMO_GEMMA_MODEL")
    if override:
        return override
    hw = detect_hardware()
    return str(recommend_config(hw)["gemma_variant"])
