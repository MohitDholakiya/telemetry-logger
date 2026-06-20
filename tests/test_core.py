"""Tests for telemetry_logger.core. Pure stdlib, run with: python -m unittest."""
import datetime as dt
import json
import os
import tempfile
import unittest
from pathlib import Path

from telemetry_logger import Telemetry, Event
from telemetry_logger.core import _canonical_json


class TestBasic(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "events.jsonl"
        self.db = Path(self.tmp.name) / "events.sqlite"
        self.tl = Telemetry(path=self.path, index_db=self.db)

    def tearDown(self):
        self.tl.close()
        self.tmp.cleanup()

    def test_log_writes_one_line(self):
        self.tl.log(Event(type="info", source="t", payload={"k": "v"}))
        lines = self.path.read_text().splitlines()
        self.assertEqual(len(lines), 1)
        d = json.loads(lines[0])
        self.assertEqual(d["type"], "info")
        self.assertEqual(d["payload"], {"k": "v"})

    def test_log_appends(self):
        for i in range(5):
            self.tl.log(Event(type="info", source="t", payload={"i": i}))
        lines = self.path.read_text().splitlines()
        self.assertEqual(len(lines), 5)

    def test_query_by_type(self):
        self.tl.log(Event(type="info", source="t", payload={}))
        self.tl.log(Event(type="attack", source="t", payload={"x": 1}, tags=["jailbreak"]))
        self.tl.log(Event(type="attack", source="t", payload={"x": 2}, tags=["leak"]))
        b = self.tl.query(type="attack")
        self.assertEqual(b.total, 2)
        self.assertEqual(len(b), 2)

    def test_query_by_tag(self):
        self.tl.log(Event(type="attack", source="t", tags=["jailbreak"]))
        self.tl.log(Event(type="attack", source="t", tags=["exfil"]))
        b = self.tl.query(tag="jailbreak")
        self.assertEqual(b.total, 1)

    def test_query_by_since(self):
        old = Event(type="info", source="t",
                    ts=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2))
        new = Event(type="info", source="t")
        self.tl.log(old)
        self.tl.log(new)
        b = self.tl.query(since=dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1))
        self.assertEqual(b.total, 1)


class TestHMAC(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "events.jsonl"
        self.db = Path(self.tmp.name) / "events.sqlite"
        self.key = b"test-secret-key-1234567890"
        self.tl = Telemetry(path=self.path, index_db=self.db, hmac_key=self.key)

    def tearDown(self):
        self.tl.close()
        self.tmp.cleanup()

    def test_signature_present(self):
        d = self.tl.log(Event(type="info", source="t"))
        self.assertIsNotNone(d.get("sig"))

    def test_chain_verifies(self):
        for i in range(10):
            self.tl.log(Event(type="info", source="t", payload={"i": i}))
        ok, n = self.tl.verify_chain()
        self.assertTrue(ok)
        self.assertEqual(n, 10)

    def test_tamper_detected(self):
        self.tl.log(Event(type="info", source="t", payload={"v": 1}))
        self.tl.log(Event(type="info", source="t", payload={"v": 2}))
        self.tl.log(Event(type="info", source="t", payload={"v": 3}))
        # Tamper with the middle line
        lines = self.path.read_text().splitlines()
        d = json.loads(lines[1])
        d["payload"]["v"] = 999
        lines[1] = json.dumps(d, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n")
        ok, _ = self.tl.verify_chain()
        self.assertFalse(ok)


class TestRotation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "events.jsonl"

    def tearDown(self):
        self.tmp.cleanup()

    def test_rotate(self):
        # Force small rotation
        tl = Telemetry(path=self.path, rotate_bytes=200)
        try:
            for i in range(50):
                tl.log(Event(type="info", source="t", payload={"big": "x" * 50}))
            rotated = self.path.with_suffix(self.path.suffix + ".1")
            self.assertTrue(rotated.exists())
            self.assertLess(self.path.stat().st_size, 500)
        finally:
            tl.close()


class TestCanonical(unittest.TestCase):
    def test_canonical_is_stable(self):
        d1 = {"b": 2, "a": 1, "c": [3, 2, 1]}
        d2 = {"c": [3, 2, 1], "a": 1, "b": 2}
        self.assertEqual(_canonical_json(d1), _canonical_json(d2))


if __name__ == "__main__":
    unittest.main()
