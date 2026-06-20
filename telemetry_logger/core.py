"""Core implementation of the telemetry logger.

Backends:
- "jsonl" (default): append each event as one JSON line to `path`.
- "sqlite": also write to a SQLite table `events` with columns
  (id, ts, type, source, actor_ip, payload_json, tags_csv, sig, prev_sig).
  Useful when you want to query for dashboards.

Tamper-evidence:
- If `hmac_key` is set, each event gets an HMAC-SHA256 signature over
  (prev_sig || canonical_json(event)). The signature is included in the
  JSON-line output and indexed in SQLite. You can later verify the chain
  with `verify_chain()`.

Thread-safety:
- A single `Telemetry` instance uses one lock for both backends.
  Multiple processes writing to the same path is NOT supported — use a
  syslog/HTTP collector for that.
"""
from __future__ import annotations

import contextlib
import dataclasses
import datetime as _dt
import hmac
import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional


# ---------------------------------------------------------------------------
# Event model
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class Event:
    """A single telemetry record.

    Fields:
        type: short string, e.g. "attack", "request", "info", "alert"
        source: which subsystem produced the event, e.g. "honey-prompt"
        payload: arbitrary JSON-serializable dict (input, matches, score, etc.)
        actor_ip: optional client IP for network-facing events
        tags: optional list of short strings for filtering
        ts: optional datetime; defaults to utcnow()
        meta: optional free-form extra metadata
    """
    type: str
    source: str
    payload: dict[str, Any] = dataclasses.field(default_factory=dict)
    actor_ip: Optional[str] = None
    tags: list[str] = dataclasses.field(default_factory=list)
    ts: _dt.datetime = dataclasses.field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc))
    meta: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "type": self.type,
            "source": self.source,
            "payload": self.payload,
            "actor_ip": self.actor_ip,
            "tags": list(self.tags),
            "ts": self.ts.astimezone(_dt.timezone.utc).isoformat(timespec="milliseconds"),
            "meta": self.meta,
        }
        return d


@dataclasses.dataclass
class EventBatch:
    """A container for events returned by queries."""
    events: list[dict[str, Any]]
    total: int

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self.events)

    def __len__(self) -> int:
        return len(self.events)


# ---------------------------------------------------------------------------
# JSONL helpers
# ---------------------------------------------------------------------------
def _canonical_json(event_dict: dict[str, Any]) -> bytes:
    """Stable JSON encoding for HMAC + hashing."""
    return json.dumps(event_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------
class Telemetry:
    """Append-only structured event logger.

    Args:
        path: path to JSONL file. Parent dirs are created if missing.
        index_db: optional path to SQLite index. If None, no index is built.
        hmac_key: optional bytes/str for tamper-evident signatures. Keep secret.
        rotate_bytes: optional size; if the JSONL file grows beyond this, it is
            renamed with a `.1` suffix and a fresh file started. Default 50 MiB.
        flush_every: force fsync every N events; 0 disables. Default 1.
    """

    def __init__(
        self,
        path: str | os.PathLike,
        index_db: Optional[str | os.PathLike] = None,
        hmac_key: Optional[bytes | str] = None,
        rotate_bytes: int = 50 * 1024 * 1024,
        flush_every: int = 1,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.rotate_bytes = rotate_bytes
        self.flush_every = flush_every
        self._lock = threading.Lock()
        self._last_sig: Optional[bytes] = self._load_last_sig()
        self._since_last_flush = 0
        self._hmac_key: Optional[bytes] = (
            hmac_key.encode("utf-8") if isinstance(hmac_key, str) else hmac_key
        )

        # SQLite index
        self._db: Optional[sqlite3.Connection] = None
        if index_db is not None:
            dbp = Path(index_db)
            dbp.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(dbp), check_same_thread=False)
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts          TEXT    NOT NULL,
                    type        TEXT    NOT NULL,
                    source      TEXT    NOT NULL,
                    actor_ip    TEXT,
                    payload_json TEXT NOT NULL,
                    tags_csv    TEXT NOT NULL,
                    sig         TEXT,
                    prev_sig    TEXT
                )
                """
            )
            self._db.execute("CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts)")
            self._db.execute("CREATE INDEX IF NOT EXISTS ix_events_type ON events(type)")
            self._db.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def log(self, event: Event) -> dict[str, Any]:
        """Append one event. Returns the canonical event dict (with sig)."""
        d = event.to_dict()
        sig = self._sign(d)
        d["sig"] = sig.hex() if sig else None
        line = json.dumps(d, ensure_ascii=False, separators=(",", ":"))

        with self._lock:
            self._maybe_rotate()
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
            self._since_last_flush += 1
            if self.flush_every and self._since_last_flush >= self.flush_every:
                self._since_last_flush = 0
                # fsync via reopening; cheap enough
                with self.path.open("a", encoding="utf-8") as f:
                    os.fsync(f.fileno())
            self._last_sig = sig
            self._write_index(d, sig)

        return d

    def log_many(self, events: Iterable[Event]) -> int:
        n = 0
        for e in events:
            self.log(e)
            n += 1
        return n

    def query(
        self,
        type: Optional[str] = None,
        source: Optional[str] = None,
        tag: Optional[str] = None,
        since: Optional[_dt.datetime] = None,
        until: Optional[_dt.datetime] = None,
        actor_ip: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> EventBatch:
        """Query events from the SQLite index. JSONL-only mode returns []."""
        if self._db is None:
            return EventBatch(events=[], total=0)

        clauses = []
        params: list[Any] = []
        if type:
            clauses.append("type = ?")
            params.append(type)
        if source:
            clauses.append("source = ?")
            params.append(source)
        if tag:
            clauses.append("tags_csv LIKE ?")
            params.append(f"%{tag}%")
        if since:
            clauses.append("ts >= ?")
            params.append(_iso(since))
        if until:
            clauses.append("ts <= ?")
            params.append(_iso(until))
        if actor_ip:
            clauses.append("actor_ip = ?")
            params.append(actor_ip)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        # Total
        cur = self._db.execute(f"SELECT COUNT(*) FROM events{where}", params)
        total = cur.fetchone()[0]
        # Page
        cur = self._db.execute(
            f"SELECT id, ts, type, source, actor_ip, payload_json, tags_csv, sig "
            f"FROM events{where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        )
        rows = cur.fetchall()
        events = [
            {
                "id": r[0],
                "ts": r[1],
                "type": r[2],
                "source": r[3],
                "actor_ip": r[4],
                "payload": json.loads(r[5]) if r[5] else {},
                "tags": [t for t in (r[6] or "").split(",") if t],
                "sig": r[7],
            }
            for r in rows
        ]
        return EventBatch(events=events, total=total)

    def verify_chain(self) -> tuple[bool, int]:
        """Walk the JSONL file end-to-end and verify HMAC chain (if enabled).

        Returns (ok, checked). If `hmac_key` was None, returns (True, 0).
        """
        if self._hmac_key is None:
            return (True, 0)
        prev: Optional[bytes] = None
        n = 0
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                sig_hex = d.pop("sig", None)
                sig = bytes.fromhex(sig_hex) if sig_hex else None
                # canonical JSON without 'sig'
                canon = _canonical_json(d)
                expected = hmac.new(self._hmac_key, prev or b"", hashlib.sha256).digest()
                # The signature we wrote was over prev||canonical_json(d)
                full = hmac.new(self._hmac_key, (prev or b"") + canon, hashlib.sha256).digest()
                if sig != full:
                    return (False, n)
                prev = sig
                n += 1
        return (True, n)

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _sign(self, d: dict[str, Any]) -> Optional[bytes]:
        if self._hmac_key is None:
            return None
        canon = _canonical_json(d)
        prev = self._last_sig or b""
        return hmac.new(self._hmac_key, prev + canon, hashlib.sha256).digest()

    def _write_index(self, d: dict[str, Any], sig: Optional[bytes]) -> None:
        if self._db is None:
            return
        self._db.execute(
            "INSERT INTO events(ts, type, source, actor_ip, payload_json, tags_csv, sig, prev_sig) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                d["ts"], d["type"], d["source"], d.get("actor_ip"),
                json.dumps(d["payload"], ensure_ascii=False),
                ",".join(d.get("tags") or []),
                sig.hex() if sig else None,
                self._last_sig.hex() if self._last_sig else None,
            ),
        )
        self._db.commit()

    def _maybe_rotate(self) -> None:
        if self.rotate_bytes <= 0 or not self.path.exists():
            return
        try:
            if self.path.stat().st_size < self.rotate_bytes:
                return
        except FileNotFoundError:
            return
        # Rename events.jsonl -> events.jsonl.1 (overwrite old)
        rotated = self.path.with_suffix(self.path.suffix + ".1")
        if rotated.exists():
            rotated.unlink()
        self.path.rename(rotated)
        # Reset chain — start fresh
        self._last_sig = None

    def _load_last_sig(self) -> Optional[bytes]:
        if not self.path.exists():
            return None
        try:
            last_line = None
            with self.path.open("rb") as f:
                # Read tail efficiently
                f.seek(0, os.SEEK_END)
                pos = f.tell()
                chunk = 64 * 1024
                while pos > 0:
                    read = min(chunk, pos)
                    pos -= read
                    f.seek(pos)
                    data = f.read(read)
                    if b"\n" in data:
                        # last non-empty line
                        lines = data.split(b"\n")
                        for ln in reversed(lines):
                            ln = ln.strip()
                            if ln:
                                last_line = ln
                                break
                        break
            if last_line is None:
                return None
            d = json.loads(last_line)
            sig = d.get("sig")
            return bytes.fromhex(sig) if sig else None
        except (OSError, ValueError, json.JSONDecodeError):
            return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _iso(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc).isoformat(timespec="milliseconds")


@contextlib.contextmanager
def open_telemetry(*args: Any, **kwargs: Any) -> Iterator[Telemetry]:
    tl = Telemetry(*args, **kwargs)
    try:
        yield tl
    finally:
        tl.close()
