"""telemetry_logger — small structured event logger for security research.

Public API:
    from telemetry_logger import Telemetry, Event

    tl = Telemetry(path="events.jsonl", index_db="events.sqlite")
    tl.log(Event(type="attack", source="honey-prompt",
                 actor_ip="1.2.3.4", payload={"input": "ignore previous"},
                 tags=["jailbreak"]))

Design goals:
- Append-only JSON-lines on disk (one event per line, easy to grep, rotate, ship)
- Optional SQLite index for fast querying by type/time/tags
- Optional HMAC chain for tamper-evidence (research-grade)
- Zero third-party dependencies at runtime (stdlib only)
- Safe to call from multiple threads in a single process

This package is intentionally NOT a SIEM. It's a teaching/research tool.
"""
from .core import Telemetry, Event, EventBatch

__all__ = ["Telemetry", "Event", "EventBatch"]
__version__ = "0.1.0"
