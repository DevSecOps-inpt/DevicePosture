import importlib
import asyncio
import gzip
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi import BackgroundTasks
from sqlalchemy import select
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

    def _request(self, payload: dict, *, gzip_body: bool = False, gzip_header_only: bool = False) -> Request:
        body = json.dumps(payload).encode("utf-8")
        headers = [(b"content-length", str(len(body)).encode("ascii"))]
        if gzip_body:
            body = gzip.compress(body)
            headers = [(b"content-length", str(len(body)).encode("ascii")), (b"content-encoding", b"gzip")]
        elif gzip_header_only:
            headers.append((b"content-encoding", b"gzip"))

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        return Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/telemetry/test",
                "headers": headers,
                "client": ("127.0.0.1", 12345),
            },
            receive,
        )

    def _submit(
        self,
        payload_type: str,
        payload: dict,
        *,
        gzip_body: bool = False,
        gzip_header_only: bool = False,
    ) -> dict:
        db = self.db_module.SessionLocal()
        try:
            response = asyncio.run(
                self.main._submit_payload(
                    payload_type=payload_type,
                    request=self._request(payload, gzip_body=gzip_body, gzip_header_only=gzip_header_only),
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

        self.assertEqual(body["status"], "accepted")
        self.assertEqual(body["payload_type"], "heartbeat")
        self.assertEqual(body["endpoint_ref"], "heartbeat-pc")
        self.assertIsNone(body["record_id"])
        self.assertFalse(body["evaluation_triggered"])
        self.assertEqual(self.evaluation_calls, [])

    def test_minimal_heartbeat_contract(self):
        body = self._submit(
            "heartbeat",
            {
                "payload_type": "heartbeat",
                "endpoint_ref": "minimal-heartbeat-pc",
                "hostname": "minimal-heartbeat-pc",
                "ip_address": "10.10.10.15",
                "heartbeat_interval_seconds": 3,
                "sequence_number": 1,
                "sent_at": "2026-05-13T12:00:00Z",
            },
        )

        self.assertEqual(body["status"], "accepted")
        self.assertEqual(body["payload_type"], "heartbeat")
        self.assertEqual(body["endpoint_ref"], "minimal-heartbeat-pc")
        self.assertFalse(body["evaluation_triggered"])

    def test_heartbeat_accepts_gzip_body(self):
        body = self._submit(
            "heartbeat",
            {
                "endpoint_id": "heartbeat-gzip-pc",
                "hostname": "heartbeat-gzip-pc",
                "ip_address": "10.10.10.13",
                "agent": {"interval_seconds": 3},
            },
            gzip_body=True,
        )

        self.assertEqual(body["payload_type"], "heartbeat")
        self.assertIsNone(body["record_id"])
        self.assertFalse(body["evaluation_triggered"])

    def test_heartbeat_accepts_plain_json_with_stale_gzip_header(self):
        body = self._submit(
            "heartbeat",
            {
                "endpoint_id": "heartbeat-stale-gzip-header-pc",
                "hostname": "heartbeat-stale-gzip-header-pc",
                "ip_address": "10.10.10.14",
                "agent": {"interval_seconds": 3},
            },
            gzip_header_only=True,
        )

        self.assertEqual(body["payload_type"], "heartbeat")
        self.assertIsNone(body["record_id"])
        self.assertFalse(body["evaluation_triggered"])

    def test_posture_snapshot_triggers_evaluation(self):
        body = self._submit("posture_snapshot", self._payload("posture-pc"))

        self.assertEqual(body["payload_type"], "posture_snapshot")
        self.assertTrue(body["evaluation_triggered"])
        self.assertEqual(self.evaluation_calls, ["posture-pc"])

    def test_minimal_posture_contract_triggers_evaluation(self):
        body = self._submit(
            "posture_snapshot",
            {
                "payload_type": "posture",
                "endpoint_ref": "minimal-posture-pc",
                "hostname": "minimal-posture-pc",
                "ip_address": "10.10.10.16",
                "posture_interval_seconds": 3,
                "sequence_number": 1,
                "sent_at": "2026-05-13T12:00:00Z",
                "posture": {
                    "system_info": {"name": "Windows", "version": "11", "build": "22631"},
                    "antivirus": [{"name": "Microsoft Defender", "antivirus_enabled": True}],
                    "required_services": [{"name": "WinDefend", "status": "Running"}],
                    "forbidden_processes_found": [],
                    "security_processes_found": [{"name": "MsMpEng"}],
                },
            },
        )

        self.assertEqual(body["status"], "accepted")
        self.assertEqual(body["payload_type"], "posture_snapshot")
        self.assertTrue(body["evaluation_triggered"])
        self.assertEqual(self.evaluation_calls, ["minimal-posture-pc"])

    def test_inventory_full_does_not_trigger_evaluation_by_default(self):
        payload = self._payload("inventory-full-pc")
        payload.update({"baseline_id": "base-1", "sequence_number": 0, "current_hash": "hash-0"})

        body = self._submit("inventory_full", payload)

        self.assertEqual(body["payload_type"], "inventory_full")
        self.assertFalse(body["evaluation_triggered"])
        self.assertEqual(self.evaluation_calls, [])

    def test_inventory_full_does_not_replace_latest_posture_record(self):
        posture_body = self._submit("posture_snapshot", self._payload("canonical-posture-pc"))
        inventory_payload = self._payload("canonical-posture-pc")
        inventory_payload.update(
            {
                "baseline_id": "base-canonical",
                "sequence_number": 0,
                "current_hash": "inventory-hash",
                "inventory": {"services": [], "processes": [], "hotfixes": [], "software": []},
            }
        )

        inventory_body = self._submit("inventory_full", inventory_payload)

        self.assertEqual(posture_body["record_id"], inventory_body["record_id"])
        db = self.db_module.SessionLocal()
        try:
            endpoint = db.scalar(select(self.main.Endpoint).where(self.main.Endpoint.endpoint_id == "canonical-posture-pc"))
            record = db.scalar(select(self.main.TelemetryRecord).where(self.main.TelemetryRecord.endpoint_ref == endpoint.id))
            self.assertEqual(record.telemetry_type, "posture_snapshot")
            self.assertEqual(record.raw_payload["extras"]["latest_inventory_payload_type"], "inventory_full")
        finally:
            db.close()

    def test_endpoint_summary_fields_are_owned_by_telemetry_type(self):
        self._submit(
            "heartbeat",
            {
                "endpoint_id": "field-owner-pc",
                "hostname": "field-owner-pc",
                "ip_address": "10.10.10.20",
                "heartbeat_interval_seconds": 3,
            },
        )
        self._submit(
            "posture_snapshot",
            {
                "endpoint_id": "field-owner-pc",
                "hostname": "field-owner-pc-renamed",
                "ip_address": "10.10.10.21",
                "posture": {"system_info": {"name": "Windows", "version": "11"}},
            },
        )

        db = self.db_module.SessionLocal()
        try:
            endpoint = db.scalar(select(self.main.Endpoint).where(self.main.Endpoint.endpoint_id == "field-owner-pc"))
            summary = self.main.build_endpoint_summary(endpoint)
            self.assertEqual(summary.last_ipv4, "10.10.10.20")
            self.assertIsNotNone(summary.last_heartbeat_at)
            self.assertIsNotNone(summary.last_posture_received_at)
            self.assertEqual(summary.expected_interval_seconds, 3)
        finally:
            db.close()

    def test_minimal_inventory_full_contract_does_not_trigger_evaluation(self):
        body = self._submit(
            "inventory_full",
            {
                "payload_type": "inventory_full",
                "endpoint_ref": "minimal-inventory-full-pc",
                "hostname": "minimal-inventory-full-pc",
                "ip_address": "10.10.10.17",
                "category": "all",
                "baseline_id": "base-minimal-full",
                "sequence_number": 1,
                "sent_at": "2026-05-13T12:00:00Z",
                "inventory": {"services": [], "processes": [], "hotfixes": [], "software": []},
            },
        )

        self.assertEqual(body["status"], "accepted")
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

    def test_minimal_inventory_delta_contract_returns_resync_without_generic_400(self):
        body = self._submit(
            "inventory_delta",
            {
                "payload_type": "inventory_delta",
                "endpoint_ref": "minimal-inventory-delta-pc",
                "category": "services",
                "baseline_id": "unknown-baseline",
                "sequence_number": 2,
                "previous_hash": "hash-1",
                "current_hash": "hash-2",
                "changes": {"added": [], "updated": [], "removed": []},
                "sent_at": "2026-05-13T12:00:00Z",
            },
        )

        self.assertEqual(body["status"], "resync_required")
        self.assertEqual(body["payload_type"], "inventory_delta")
        self.assertTrue(body["resync_required"])
        self.assertFalse(body["evaluation_triggered"])

    def test_legacy_telemetry_still_works(self):
        body = self._submit("legacy", self._payload("legacy-pc"))

        self.assertEqual(body["payload_type"], "legacy")
        self.assertTrue(body["evaluation_triggered"])
        self.assertEqual(self.evaluation_calls, ["legacy-pc"])


if __name__ == "__main__":
    unittest.main()
