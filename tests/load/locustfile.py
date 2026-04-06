from __future__ import annotations

from locust import HttpUser, between, task


class KaamoUser(HttpUser):
    wait_time = between(1, 2)

    @task
    def health(self) -> None:
        self.client.get("/healthz")

