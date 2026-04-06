from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

try:
    from pydantic import Field, computed_field
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:  # pragma: no cover - fallback for minimal environments
    from dataclasses import dataclass, field

    @dataclass(slots=True)
    class Settings:
        mode: Literal["offline", "hybrid", "online"] = os.environ.get("KAAMO_MODE", "offline")  # type: ignore[assignment]
        home_dir: Path = field(default_factory=lambda: Path.home() / ".kaamo")
        model_store: Path | None = None
        expected_concurrent_users: int = int(os.environ.get("KAAMO_EXPECTED_CONCURRENT_USERS", "1000"))
        gemma_model: str = os.environ.get("KAAMO_GEMMA_MODEL", "gemma-3-4b-it")
        gemma_pool_size: int = int(os.environ.get("KAAMO_GEMMA_POOL_SIZE", "2"))
        gemma_context_length: int = int(os.environ.get("KAAMO_GEMMA_CONTEXT_LENGTH", "8192"))
        gemma_temperature: float = float(os.environ.get("KAAMO_GEMMA_TEMPERATURE", "0.0"))
        gemma_max_tokens: int = int(os.environ.get("KAAMO_GEMMA_MAX_TOKENS", "512"))
        nvidia_api_base_url: str = os.environ.get("KAAMO_NVIDIA_API_BASE_URL", "https://integrate.api.nvidia.com/v1")
        nvidia_timeout_seconds: float = float(os.environ.get("KAAMO_NVIDIA_TIMEOUT_SECONDS", "30.0"))
        redis_url: str = os.environ.get("KAAMO_REDIS_URL", "redis://localhost:6379/0")
        postgres_dsn: str = os.environ.get("KAAMO_POSTGRES_DSN", "postgresql://localhost/kaamo")
        daemon_socket_path: Path = field(default_factory=lambda: Path.home() / ".kaamo" / "kaamod.sock")
        metrics_enabled: bool = os.environ.get("KAAMO_METRICS_ENABLED", "true").lower() == "true"
        debug_logging: bool = os.environ.get("KAAMO_DEBUG_LOGGING", "false").lower() == "true"

        @property
        def resolved_model_store(self) -> Path:
            return self.model_store or (self.home_dir / "models")

        @property
        def native_lib_path(self) -> Path:
            return self.home_dir / "lib" / "libkaamo.so"

else:

    class Settings(BaseSettings):
        model_config = SettingsConfigDict(env_prefix="KAAMO_", extra="ignore")

        mode: Literal["offline", "hybrid", "online"] = "offline"
        home_dir: Path = Field(default_factory=lambda: Path.home() / ".kaamo")
        model_store: Path | None = None
        expected_concurrent_users: int = 1000
        gemma_model: str = "gemma-3-4b-it"
        gemma_pool_size: int = 2
        gemma_context_length: int = 8192
        gemma_temperature: float = 0.0
        gemma_max_tokens: int = 512
        nvidia_api_base_url: str = "https://integrate.api.nvidia.com/v1"
        nvidia_timeout_seconds: float = 30.0
        redis_url: str = "redis://localhost:6379/0"
        postgres_dsn: str = "postgresql://localhost/kaamo"
        daemon_socket_path: Path = Field(default_factory=lambda: Path.home() / ".kaamo" / "kaamod.sock")
        metrics_enabled: bool = True
        debug_logging: bool = False

        @computed_field  # type: ignore[prop-decorator]
        @property
        def resolved_model_store(self) -> Path:
            return self.model_store or (self.home_dir / "models")

        @computed_field  # type: ignore[prop-decorator]
        @property
        def native_lib_path(self) -> Path:
            return self.home_dir / "lib" / "libkaamo.so"


settings = Settings()
