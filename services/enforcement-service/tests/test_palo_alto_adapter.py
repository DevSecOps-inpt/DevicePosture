from __future__ import annotations

import unittest

from app.adapters.palo_alto import PaloAltoAdapter, PaloAltoXmlApiClient
from posture_shared.models.enforcement import EnforcementAction


class FakeResponse:
    def __init__(self, text: str, status_code: int = 200) -> None:
        self.text = text
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = list(responses)
        self.calls: list[dict] = []
        self.trust_env = False

    def post(self, url: str, data: dict, headers: dict, timeout: float, verify: bool) -> FakeResponse:
        self.calls.append(
            {
                "url": url,
                "data": data,
                "headers": headers,
                "timeout": timeout,
                "verify": verify,
            }
        )
        if not self.responses:
            raise AssertionError("No fake responses remaining")
        return self.responses.pop(0)


def success_response(body: str = "<result><msg>command succeeded</msg></result>") -> FakeResponse:
    return FakeResponse(f'<response status="success" code="20">{body}</response>')


class PaloAltoAdapterTests(unittest.TestCase):
    def test_build_settings_and_mapping_resolution(self) -> None:
        adapter = PaloAltoAdapter()
        settings = adapter.build_settings(
            {
                "base_url": "https://fw.example.local",
                "api_key": "secret",
                "verify_tls": False,
                "vsys": "vsys9",
                "group_mappings": [
                    {
                        "app_group_id": "ipgrp-123",
                        "app_group_display_name": "Quarantine",
                        "palo_tag_name": "dag-quarantine",
                        "palo_dag_name": "DAG-Quarantine",
                    }
                ],
            }
        )

        self.assertEqual(settings["base_url"], "https://fw.example.local")
        self.assertEqual(settings["vsys"], "vsys9")
        self.assertFalse(settings["verify_tls"])

        by_id = adapter.resolve_group_mapping(settings, group_name=None, group_id="ipgrp-123")
        by_name = adapter.resolve_group_mapping(settings, group_name="Quarantine", group_id=None)

        self.assertEqual(by_id["palo_tag_name"], "dag-quarantine")
        self.assertEqual(by_name["palo_dag_name"], "DAG-Quarantine")

    def test_execute_quarantine_registers_ip_tag(self) -> None:
        session = FakeSession([success_response()])
        client = PaloAltoXmlApiClient(
            base_url="https://fw.example.local",
            api_key="secret-key",
            verify_tls=True,
            timeout=5.0,
            retries=1,
            session=session,
        )
        adapter = PaloAltoAdapter()
        adapter._client = lambda settings: client  # type: ignore[method-assign]

        action = EnforcementAction(
            adapter="palo_alto",
            action="quarantine",
            endpoint_id="endpoint-1",
            ip_address="10.20.30.40",
            group_name="Quarantine",
            decision={
                "group_id": "ipgrp-123",
                "adapter_settings": {
                    "base_url": "https://fw.example.local",
                    "api_key": "secret-key",
                    "vsys": "vsys1",
                    "group_mappings": [
                        {
                            "app_group_id": "ipgrp-123",
                            "app_group_display_name": "Quarantine",
                            "palo_tag_name": "dag-quarantine",
                            "palo_dag_name": "DAG-Quarantine",
                        }
                    ],
                },
            },
        )

        result = adapter.execute(action)

        self.assertEqual(result.status, "success")
        self.assertEqual(result.details["palo_tag_name"], "dag-quarantine")
        self.assertEqual(len(session.calls), 1)
        self.assertEqual(session.calls[0]["headers"]["X-PAN-KEY"], "secret-key")
        self.assertEqual(session.calls[0]["data"]["type"], "user-id")
        self.assertEqual(session.calls[0]["data"]["vsys"], "vsys1")
        self.assertIn("<register>", session.calls[0]["data"]["cmd"])
        self.assertIn('ip="10.20.30.40"', session.calls[0]["data"]["cmd"])
        self.assertIn(">dag-quarantine</member>", session.calls[0]["data"]["cmd"])

    def test_move_ip_between_groups_unregisters_then_registers(self) -> None:
        session = FakeSession([success_response(), success_response()])
        client = PaloAltoXmlApiClient(
            base_url="https://fw.example.local",
            api_key="secret-key",
            verify_tls=False,
            timeout=5.0,
            retries=1,
            session=session,
        )
        adapter = PaloAltoAdapter()
        adapter._client = lambda settings: client  # type: ignore[method-assign]

        settings = adapter.build_settings(
            {
                "base_url": "https://fw.example.local",
                "api_key": "secret-key",
                "verify_tls": False,
                "vsys": "vsys1",
                "group_mappings": [
                    {
                        "app_group_id": "ipgrp-old",
                        "app_group_display_name": "Old Group",
                        "palo_tag_name": "old-tag",
                    },
                    {
                        "app_group_id": "ipgrp-new",
                        "app_group_display_name": "New Group",
                        "palo_tag_name": "new-tag",
                    },
                ],
            }
        )

        details = adapter.move_ip_between_groups(
            settings=settings,
            ip_address="10.0.0.10",
            old_group_name="Old Group",
            old_group_id="ipgrp-old",
            new_group_name="New Group",
            new_group_id="ipgrp-new",
        )

        self.assertEqual(details["operation"], "moved")
        self.assertEqual(len(session.calls), 2)
        self.assertIn("<unregister>", session.calls[0]["data"]["cmd"])
        self.assertIn(">old-tag</member>", session.calls[0]["data"]["cmd"])
        self.assertIn("<register>", session.calls[1]["data"]["cmd"])
        self.assertIn(">new-tag</member>", session.calls[1]["data"]["cmd"])


if __name__ == "__main__":
    unittest.main()
