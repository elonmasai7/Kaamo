from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
from collections import deque
from collections.abc import AsyncIterator, Iterable
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from kaamo.audit import write_audit_log
from kaamo.blueteam.base import BlueTeamModule, ModuleResult, SecurityContext, SecurityEvent

SupportedFormat = Literal["json", "csv", "ndjson", "cef", "leef", "syslog"]


class EventIngestStats(BaseModel):
    received: int = 0
    parsed: int = 0
    deduplicated: int = 0
    dropped: int = 0


class EventIngester:
    def __init__(
        self,
        *,
        queue_size: int = 1024,
        batch_size: int = 100,
        dedup_window: int = 4096,
    ) -> None:
        self._input_queue: asyncio.Queue[tuple[str, SupportedFormat, str]] = asyncio.Queue(maxsize=queue_size)
        self._output_queue: asyncio.Queue[SecurityEvent | None] = asyncio.Queue(maxsize=queue_size)
        self._batch_size = batch_size
        self._dedup_cache: deque[str] = deque(maxlen=dedup_window)
        self._dedup_index: set[str] = set()
        self._stats = EventIngestStats()

    async def ingest_stream(
        self,
        records: AsyncIterator[str],
        *,
        event_format: SupportedFormat,
        source: str,
    ) -> AsyncIterator[SecurityEvent]:
        producer = asyncio.create_task(self._produce(records, event_format, source))
        consumer = asyncio.create_task(self._consume())
        try:
            while True:
                event = await self._output_queue.get()
                if event is None:
                    break
                yield event
        finally:
            await producer
            await consumer

    async def _produce(
        self,
        records: AsyncIterator[str],
        event_format: SupportedFormat,
        source: str,
    ) -> None:
        async for record in records:
            await self._input_queue.put((record, event_format, source))
            self._stats.received += 1
        await self._input_queue.put(("", event_format, "__EOF__"))

    async def _consume(self) -> None:
        batch: list[tuple[str, SupportedFormat, str]] = []
        while True:
            record, event_format, source = await self._input_queue.get()
            if source == "__EOF__":
                break
            batch.append((record, event_format, source))
            if len(batch) >= self._batch_size:
                await self._flush_batch(batch)
                batch = []
        if batch:
            await self._flush_batch(batch)
        await self._output_queue.put(None)

    async def _flush_batch(self, batch: list[tuple[str, SupportedFormat, str]]) -> None:
        for record, event_format, source in batch:
            dedup_key = hashlib.sha256(f"{source}:{record}".encode("utf-8")).hexdigest()
            if dedup_key in self._dedup_index:
                self._stats.deduplicated += 1
                continue
            event = self._parse_record(record, event_format, source)
            if event is None:
                self._stats.dropped += 1
                continue
            self._remember_dedup_key(dedup_key)
            self._stats.parsed += 1
            await self._output_queue.put(event)

    def _remember_dedup_key(self, key: str) -> None:
        if len(self._dedup_cache) == self._dedup_cache.maxlen:
            old = self._dedup_cache.popleft()
            self._dedup_index.discard(old)
        self._dedup_cache.append(key)
        self._dedup_index.add(key)

    def _parse_record(self, record: str, event_format: SupportedFormat, source: str) -> SecurityEvent | None:
        record = record.strip()
        if not record:
            return None
        if event_format in {"json", "ndjson"}:
            payload = json.loads(record)
            return self._from_mapping(payload, source)
        if event_format == "csv":
            reader = csv.DictReader(io.StringIO(record))
            row = next(reader, None)
            return self._from_mapping(dict(row) if row else {}, source)
        if event_format in {"cef", "leef"}:
            payload = self._parse_kv_message(record, delimiter="|" if event_format == "cef" else "\t")
            return self._from_mapping(payload, source)
        payload = self._parse_syslog(record)
        return self._from_mapping(payload, source)

    def _from_mapping(self, payload: dict[str, Any], source: str) -> SecurityEvent:
        timestamp_raw = payload.get("timestamp") or payload.get("time") or datetime.now(UTC).isoformat()
        timestamp = self._parse_timestamp(str(timestamp_raw))
        host = str(payload.get("host") or payload.get("hostname") or "unknown-host")
        user = payload.get("user") or payload.get("username")
        event_type = str(payload.get("event_type") or payload.get("type") or payload.get("event") or "generic")
        severity = str(payload.get("severity") or payload.get("level") or "medium").lower()
        event_id_basis = json.dumps(payload, sort_keys=True, default=str)
        event_id = str(payload.get("event_id") or hashlib.sha256(event_id_basis.encode("utf-8")).hexdigest()[:16])
        return SecurityEvent(
            event_id=event_id,
            timestamp=timestamp,
            source=source,
            host=host,
            user=str(user) if user is not None else None,
            event_type=event_type,
            severity=severity,
            raw_payload=payload,
        )

    @staticmethod
    def _parse_timestamp(raw: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(UTC)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)

    @staticmethod
    def _parse_kv_message(record: str, delimiter: str) -> dict[str, Any]:
        parts = record.split(delimiter)
        payload: dict[str, Any] = {"raw": record}
        if len(parts) >= 2:
            payload["event_type"] = parts[0]
            payload["severity"] = parts[1]
        for fragment in parts[2:]:
            if "=" in fragment:
                key, value = fragment.split("=", maxsplit=1)
                payload[key.strip()] = value.strip()
        return payload

    @staticmethod
    def _parse_syslog(record: str) -> dict[str, Any]:
        parts = record.split()
        payload: dict[str, Any] = {"raw": record}
        if len(parts) >= 5:
            payload["timestamp"] = f"{parts[0]} {parts[1]} {parts[2]}"
            payload["host"] = parts[3]
            payload["event_type"] = parts[4].rstrip(":")
        return payload

    @property
    def stats(self) -> EventIngestStats:
        return self._stats


class EventIngestModule(BlueTeamModule):
    name = "event_ingest"
    description = "High-throughput security event ingestion and normalization"

    async def analyze(self, context: SecurityContext) -> ModuleResult:
        write_audit_log("blueteam.event_ingest.analyze", "system", self.name, event_count=len(context.events))
        return ModuleResult(
            module_name=self.name,
            summary=f"Normalized {len(context.events)} security events for downstream analysis.",
            findings=[event.model_dump(mode="json") for event in context.events[:50]],
            metrics={"normalized_events": float(len(context.events))},
        )


async def iter_records(records: Iterable[str]) -> AsyncIterator[str]:
    for record in records:
        yield record

