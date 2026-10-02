import json
import tempfile
import unittest
from pathlib import Path
from otsec.core import MAX_IMPORT, Store


def observation(**changes):
    record = {"ts": 1700000000, "id.orig_h": "192.168.10.15", "id.resp_h": "192.168.10.20", "id.resp_p": 502, "service": "modbus"}
    record.update(changes)
    return json.dumps(record).encode()


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.db"
        self.store = Store(self.path)
        self.store.add_environment("lab", "lab", "192.168.10.0/24")
        self.store.add_environment("plant", "production", "192.168.10.0/24")

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_discovery_and_deduplication(self):
        self.assertEqual(self.store.import_zeek("lab", observation())["imported"], 1)
        self.assertEqual(self.store.import_zeek("lab", observation())["duplicates"], 1)
        self.assertEqual(self.store.snapshot()["counts"]["assets"], 2)
        self.assertEqual(self.store.snapshot()["counts"]["observations"], 1)

    def test_environment_isolation(self):
        for name in ("lab", "plant"):
            self.store.import_zeek(name, observation())
        self.assertEqual(self.store.snapshot()["counts"]["assets"], 4)

    def test_atomic_import(self):
        with self.assertRaises(ValueError):
            self.store.import_zeek("lab", observation() + b'\n{"ts":null}')
        self.assertEqual(self.store.snapshot()["counts"]["observations"], 0)
        self.assertEqual(self.store.snapshot()["counts"]["assets"], 0)

    def test_reject_invalid_observations(self):
        cases = [b"[]", b"bad-json", b"\xff", observation(ts=float("nan")), observation(ts=True), observation(**{"id.resp_p": -1}), observation(**{"id.resp_p": True}), observation(**{"id.orig_h": "bad"}), observation(service=""), observation(**{"id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2"}), b" " * (MAX_IMPORT + 1)]
        for case in cases:
            with self.subTest(case=case[:70]), self.assertRaises(ValueError):
                self.store.import_zeek("lab", case)
        self.assertEqual(self.store.snapshot()["counts"]["observations"], 0)

    def test_external_review_signal(self):
        self.store.import_zeek("lab", observation(**{"id.resp_h": "203.0.113.8"}))
        self.assertEqual(self.store.snapshot()["observations"][0]["external"], 1)
        self.assertEqual(self.store.snapshot()["counts"]["assets"], 1)

    def test_policy_and_no_execution(self):
        lab = self.store.plan("lab", "zaproxy", "scan", "192.168.10.20")
        plant = self.store.plan("plant", "zaproxy", "scan", "192.168.10.20")
        self.assertEqual(lab["state"], "proposed")
        self.assertEqual(plant["state"], "blocked-by-policy")
        self.assertFalse(lab["executed"])
        self.assertEqual(self.store.plan("plant", "custom", "remediate", "192.168.10.20")["state"], "proposed")

    def test_invalid_plans_leave_no_state(self):
        for args in [("zaproxy", "scan", "10.0.0.1"), ("zeek", "scan", "192.168.10.20"), ("unknown", "scan", "192.168.10.20"), ("custom", "shell", "192.168.10.20")]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.store.plan("lab", *args)
        self.assertEqual(self.store.snapshot()["counts"]["plans"], 0)

    def test_environment_validation(self):
        for args in [("", "lab", "10.0.0.0/24"), ("bad", "other", "10.0.0.0/24"), ("bad", "lab", "10.0.0.1/24"), ("lab", "lab", "10.0.0.0/24")]:
            with self.assertRaises(ValueError):
                self.store.add_environment(*args)

    def test_persistence_and_audit(self):
        self.store.import_zeek("lab", observation())
        self.store.plan("lab", "custom", "remediate", "192.168.10.20")
        self.store.close()
        self.store = Store(self.path)
        self.assertEqual(self.store.snapshot()["counts"]["plans"], 1)
        self.assertEqual(len(self.store.snapshot()["audit"]), 4)
