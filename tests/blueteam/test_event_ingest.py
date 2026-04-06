from __future__ import annotations

import asyncio

from kaamo.blueteam.detection.event_ingest import EventIngester


def test_event_ingest_normalizes_and_deduplicates() -> None:
    async def _run() -> list[object]:
        ingester = EventIngester(batch_size=2)

        async def records():
            yield '{"timestamp":"2026-04-07T00:00:00Z","host":"srv-1","user":"alice","event_type":"login_fail","severity":"high","source_ip":"10.0.0.8"}'
            yield '{"timestamp":"2026-04-07T00:00:00Z","host":"srv-1","user":"alice","event_type":"login_fail","severity":"high","source_ip":"10.0.0.8"}'

        return [event async for event in ingester.ingest_stream(records(), event_format="json", source="auth")]

    events = asyncio.run(_run())
    assert len(events) == 1
    assert events[0].host == "srv-1"
    assert events[0].event_type == "login_fail"

