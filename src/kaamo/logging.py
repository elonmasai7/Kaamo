from __future__ import annotations

import logging
import re
import sys
from typing import Any

try:
    import structlog
except ImportError:  # pragma: no cover - fallback for minimal environments
    structlog = None  # type: ignore[assignment]

_SECRET_PATTERN = re.compile(r"(key|token|secret|password|apikey)", re.IGNORECASE)


def _scrub_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: ("[REDACTED]" if _SECRET_PATTERN.search(str(key)) else _scrub_value(val))
            for key, val in value.items()
        }
    if isinstance(value, list):
        return [_scrub_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub_value(item) for item in value)
    return value


def configure_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(level=level, stream=sys.stdout, format="%(message)s")
    if structlog is None:
        return
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.add_log_level,
            lambda _logger, _name, event_dict: _scrub_value(event_dict),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


class _FallbackLogger:
    def __init__(self, name: str) -> None:
        self._logger = logging.getLogger(name)

    def debug(self, event: str, **kwargs: Any) -> None:
        self._logger.debug("%s %s", event, _scrub_value(kwargs))

    def info(self, event: str, **kwargs: Any) -> None:
        self._logger.info("%s %s", event, _scrub_value(kwargs))

    def warning(self, event: str, **kwargs: Any) -> None:
        self._logger.warning("%s %s", event, _scrub_value(kwargs))

    def error(self, event: str, **kwargs: Any) -> None:
        self._logger.error("%s %s", event, _scrub_value(kwargs))


def get_logger(name: str) -> Any:
    if structlog is None:
        return _FallbackLogger(name)
    return structlog.get_logger(name)
