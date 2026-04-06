from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Literal

from kaamo.cache.metrics import circuit_breaker_state

CircuitState = Literal["closed", "open", "half-open"]


@dataclass(slots=True)
class CircuitBreaker:
    failure_threshold: int = 3
    window_seconds: int = 60
    recovery_seconds: int = 30
    backend_name: str = "nvidia"
    failures: list[float] = field(default_factory=list)
    state: CircuitState = "closed"
    opened_at: float | None = None

    def allow_request(self) -> bool:
        self._trim_failures()
        if self.state == "open":
            assert self.opened_at is not None
            if (time.time() - self.opened_at) >= self.recovery_seconds:
                self.state = "half-open"
                circuit_breaker_state.labels(backend=self.backend_name).set(0.5)
                return True
            return False
        return True

    def record_success(self) -> None:
        self.failures.clear()
        self.state = "closed"
        self.opened_at = None
        circuit_breaker_state.labels(backend=self.backend_name).set(0)

    def record_failure(self) -> None:
        now = time.time()
        self.failures.append(now)
        self._trim_failures()
        if len(self.failures) >= self.failure_threshold:
            self.state = "open"
            self.opened_at = now
            circuit_breaker_state.labels(backend=self.backend_name).set(1)

    def _trim_failures(self) -> None:
        cutoff = time.time() - self.window_seconds
        self.failures = [failure for failure in self.failures if failure >= cutoff]

