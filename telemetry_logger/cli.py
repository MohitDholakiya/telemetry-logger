"""Tiny CLI for ad-hoc querying.

Usage:
    python -m telemetry_logger.cli query --db events.sqlite --type attack --since 1h
    python -m telemetry_logger.cli verify --path events.jsonl --key-file ./key
    python -m telemetry_logger.cli tail --path events.jsonl -n 20
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
from pathlib import Path

from .core import Telemetry


def _parse_since(s: str) -> _dt.datetime:
    s = s.strip().lower()
    now = _dt.datetime.now(_dt.timezone.utc)
    if s.endswith("h") and s[:-1].isdigit():
        return now - _dt.timedelta(hours=int(s[:-1]))
    if s.endswith("d") and s[:-1].isdigit():
        return now - _dt.timedelta(days=int(s[:-1]))
    if s.endswith("m") and s[:-1].isdigit():
        return now - _dt.timedelta(minutes=int(s[:-1]))
    # ISO fallback
    return _dt.datetime.fromisoformat(s)


def cmd_query(args: argparse.Namespace) -> int:
    tl = Telemetry(path=args.path or ":memory:", index_db=args.db)
    try:
        since = _parse_since(args.since) if args.since else None
        batch = tl.query(type=args.type, source=args.source, tag=args.tag,
                         since=since, actor_ip=args.actor_ip, limit=args.limit)
        if args.json:
            print(json.dumps(batch.events, indent=2, ensure_ascii=False))
        else:
            print(f"# total={batch.total} returned={len(batch.events)}")
            for e in batch.events:
                print(f"{e['ts']}  [{e['type']:8s}]  {e['source']:20s}  "
                      f"ip={e.get('actor_ip') or '-':15s}  tags={','.join(e.get('tags') or [])}")
        return 0
    finally:
        tl.close()


def cmd_verify(args: argparse.Namespace) -> int:
    key = None
    if args.key_file:
        key = Path(args.key_file).read_bytes().strip()
    elif args.key:
        key = args.key.encode("utf-8")
    tl = Telemetry(path=args.path, hmac_key=key)
    try:
        ok, n = tl.verify_chain()
        print(f"verified {n} events, chain_ok={ok}")
        return 0 if ok else 1
    finally:
        tl.close()


def cmd_tail(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        print(f"no such file: {path}", file=sys.stderr)
        return 1
    with path.open("r", encoding="utf-8") as f:
        lines = f.readlines()
    for line in lines[-args.n:]:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            ts = d.get("ts", "?")
            t = d.get("type", "?")
            s = d.get("source", "?")
            ip = d.get("actor_ip") or "-"
            tags = ",".join(d.get("tags") or [])
            print(f"{ts}  [{t:8s}]  {s:18s}  ip={ip:15s}  {tags}")
        except json.JSONDecodeError:
            print(line)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="telemetry-logger")
    sub = p.add_subparsers(dest="cmd", required=True)

    pq = sub.add_parser("query", help="Query the SQLite index")
    pq.add_argument("--db", required=True, help="path to SQLite index db")
    pq.add_argument("--path", help="path to JSONL (used for verify only)")
    pq.add_argument("--type")
    pq.add_argument("--source")
    pq.add_argument("--tag")
    pq.add_argument("--actor-ip")
    pq.add_argument("--since", help="relative (1h, 30m, 2d) or ISO")
    pq.add_argument("--limit", type=int, default=50)
    pq.add_argument("--json", action="store_true")
    pq.set_defaults(func=cmd_query)

    pv = sub.add_parser("verify", help="Walk JSONL and verify HMAC chain")
    pv.add_argument("--path", required=True)
    pv.add_argument("--key", help="HMAC key (string)")
    pv.add_argument("--key-file", help="path to HMAC key file")
    pv.set_defaults(func=cmd_verify)

    pt = sub.add_parser("tail", help="Show last N events from JSONL")
    pt.add_argument("--path", required=True)
    pt.add_argument("-n", type=int, default=20)
    pt.set_defaults(func=cmd_tail)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
