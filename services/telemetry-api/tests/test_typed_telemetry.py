import importlib
import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi import BackgroundTasks
from starlette.requests import Request


REPO_ROOT = Path(__file__).resolve().parents[3]


class TypedTelemetryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._cwd = Path.cwd()
        cls._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        os.chdir(cls._tmp.name)
        sys.path.insert(0, str(REPO_ROOT / "services" / "telemetry-api"))
        sys.path.insert(0, str(REPO_ROOT / "shared"))
        os.environ.pop("POSTURE_API_KEY", None)
        os.environ["POSTURE_TRIGGERS_EVALUATION"] = "true"
        os.environ["FORCE_EVALUATION_ON_EVERY_POSTURE"] = "true"
        os.environ["SKIP_EVALUATION_IF_POSTURE_HASH_UNCHANGED"] = "false"
        os.environ["INVENTORY_FULL_TRIGGERS_EVALUATION"] = "false"
        os.environ["INVENTORY_DELTA_TRIGGERS_EVALUATION"] = "false"
        os.environ["PROCESS_POSTURE_IN_BACKGROUND"] = "false"
        cls.main = importlib.import_module("app.main")
        cls.db_module = importlib.import_module("app.db")

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls._cwd)
        cls.db_module.engine.dispose()
        cls._tmp.cleanup()

    def setUp(self):
        self.evaluation_calls: list[str] = []
        self.main.trigger_posture_evaluation = lambda endpoint_id: self.evaluation_calls.append(endpoint_id)

    def _request(self, payload: dict) -> Request:
        body = json.dumps(payload).encode("utf-8")

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        return Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/telemetry/test",
                "headers": [(b"content-length", str(len(body)).encode("ascii"))],
                "client": ("127.0.0.1", 12345),
            },
            receive,
        )

    def _submit(self, payload_type: str, payload: dict) -> dict:
        db = self.db_module.SessionLocal()
        try:
            response = asyncio.run(
                self.main._submit_payload(
                    payload_type=payload_type,
                    request=self._request(payload),
                    background_tasks=BackgroundTasks(),
                    db=db,
                )
            )
            return response.model_dump(mode="json")
        finally:
            db.close()

    def _payload(self, endpoint_id: str) -> dict:
        return {
            "endpoint_id": endpoint_id,
            "hostname": endpoint_id,
            "collected_at": "2026-05-13T12:00:00Z",
            "network": {"ipv4": "10.10.10.10"},
            "os": {"name": "Windows", "version": "11", "build": "22631"},
            "agent": {"name": "test-agent", "interval_seconds": 3, "active_grace_multiplier": 3},
            "antivirus_products": [
                {
                    "name": "Microsoft Defender",
                    "identifier": "defender",
                    "real_time_protection_enabled": True,
                    "antivirus_enabled": True,
                }
            ],
            "services": [{"name": "WinDefend", "status": "Running"}],
            "processes": [{"name": "MsMpEng"}],
            "hotfixes": [{"id": "KB1"}],
        }

    def test_collector_config_defaults(self):
        config_path = REPO_ROOT / "endpoint-collector" / "powershell" / "collector.config.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))

        self.assertEqual(config["scheduling"]["heartbeat_interval_seconds"], 3)
        self.assertEqual(config["scheduling"]["posture_interval_seconds"], 3)
        self.assertEqual(config["scheduling"]["inventory_delta_interval_seconds"], 10)
        self.assertEqual(config["scheduling"]["inventory_full_interval_seconds"], 900)

    def test_heartbeat_updates_liveness_without_evaluation(self):
        body = self._submit(
            "heartbeat",
            {
                "endpoint_id": "heartbeat-pc",
                "hostname": "heartbeat-pc",
                "ip_address": "10.10.10.11",
                "agent": {"interval_seconds": 3},
            },
        )

        self.assertEqual(body["payload_type"], "heartbeat")
        self.assertIsNone(body["record_id"])
        self.assertFalse(body["evaluation_triggered"])
        self.assertEqual(self.evaluation_calls, [])

    def test_posture_snapshot_triggers_evaluation(self):
        body = self._submit("posture_snapshot", self._payload("posture-pc"))

        self.assertEqual(body["payload_type"], "posture_snapshot")
        self.assertTrue(body["evaluation_triggered"])
        self.assertEqual(self.evaluation_calls, ["posture-pc"])

    def test_inventory_full_does_not_trigger_evaluation_by_default(self):
        payload = self._payload("inventory-full-pc")
        payload.update({"baseline_id": "base-1", "sequence_number": 0, "current_hash": "hash-0"})

        body = self._submit("inventory_full", payload)

        self.assertEqual(body["payload_type"], "inventory_full")
        self.assertFalse(body["evaluation_triggered"])
        self.assertEqual(self.evaluation_calls, [])

    def test_inventory_delta_requires_resync_on_sequence_gap(self):
        full = self._payload("inventory-delta-pc")
        full.update({"baseline_id": "base-gap", "sequence_number": 0, "current_hash": "hash-0"})
        self._submit("inventory_full", full)

        delta = {
            "endpoint_id": "inventory-delta-pc",
            "hostname": "inventory-delta-pc",
            "ip_address": "10.10.10.12",
            "baseline_id": "base-gap",
            "sequence_number": 2,
            "previous_hash": "hash-0",
            "current_hash": "hash-2",
            "changes": {"services": {"added_updated": [], "removed": []}},
        }
        body = self._submit("inventory_delta", delta)

        self.assertTrue(body["resync_required"])
        self.assertEqual(body["reason"], "sequence_gap")

    def test_legacy_telemetry_still_works(self):
        body = self._submit("legacy", self._payload("legacy-pc"))

        self.assertEqual(body["payload_type"], "legacy")
        self.assertTrue(body["evaluation_triggered"])
        self.assertEqual(self.evaluation_calls, ["legacy-pc"])


if __name__ == "__main__":
    unittest.main()
