from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KAAMO_", extra="ignore")

    mode: Literal["offline", "hybrid", "online"] = "offline"
    home_dir: Path = Field(default_factory=lambda: Path.home() / ".kaamo")
    model_store: Path | None = None
    expected_concurrent_users: int = 1000
    gemma_model: str = "gemma-3-4b-it"
    gemma_model_manifest: Path | None = None
    gemma_pool_size: int = 2
    gemma_context_length: int = 8192
    gemma_temperature: float = 0.0
    gemma_max_tokens: int = 512
    nvidia_api_base_url: str = "https://integrate.api.nvidia.com/v1"
    nvidia_timeout_seconds: float = 30.0
    redis_url: str = "redis://localhost:6379/0"
    redis_detection_queue: str = "kaamo:queue:detection"
    postgres_dsn: str = "postgresql://localhost/kaamo"
    postgres_min_pool_size: int = 2
    postgres_max_pool_size: int = 20
    daemon_socket_path: Path = Field(default_factory=lambda: Path.home() / ".kaamo" / "kaamod.sock")
    metrics_enabled: bool = True
    debug_logging: bool = False
    api_host: str = "127.0.0.1"
    api_port: int = 8080
    detection_worker_concurrency: int = 2
    detection_worker_batch_size: int = 100
    run_migrations_on_startup: bool = True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def resolved_model_store(self) -> Path:
        return self.model_store or (self.home_dir / "models")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def resolved_model_manifest(self) -> Path:
        return self.gemma_model_manifest or (self.resolved_model_store / "manifest.json")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def native_lib_path(self) -> Path:
        return self.home_dir / "lib" / "libkaamo.so"


settings = Settings()
