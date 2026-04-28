import sys
import unittest
from pathlib import Path


SERVICE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVICE_ROOT.parents[1]
sys.path.insert(0, str(SERVICE_ROOT))
sys.path.insert(0, str(REPO_ROOT / "shared"))

from app.evaluators.allowed_antivirus import AllowedAntivirusEvaluator
from posture_shared.models.policy import PolicyCondition
from posture_shared.models.telemetry import AntivirusProduct, EndpointTelemetry, ServiceInfo


class AllowedAntivirusEvaluatorTests(unittest.TestCase):
    def _condition(self) -> PolicyCondition:
        return PolicyCondition(
            type="allowed_antivirus",
            field="antivirus.family",
            operator="exists in",
            value=["microsoft_defender"],
        )

    def _telemetry(self, *, real_time_enabled: bool) -> EndpointTelemetry:
        return EndpointTelemetry(
            endpoint_id="endpoint-1",
            hostname="host-1",
            services=[ServiceInfo(name="WinDefend", status="Running")],
            antivirus_products=[
                AntivirusProduct(
                    name="Microsoft Defender Antivirus",
                    identifier="microsoft defender antivirus",
                    real_time_protection_enabled=real_time_enabled,
                    antivirus_enabled=real_time_enabled,
                )
            ],
        )

    def test_family_condition_passes_when_family_is_active(self) -> None:
        reasons = AllowedAntivirusEvaluator().evaluate(
            self._telemetry(real_time_enabled=True),
            self._condition(),
        )

        self.assertEqual(reasons, [])

    def test_family_condition_fails_when_family_is_installed_but_disabled(self) -> None:
        reasons = AllowedAntivirusEvaluator().evaluate(
            self._telemetry(real_time_enabled=False),
            self._condition(),
        )

        self.assertEqual(len(reasons), 1)
        self.assertIn("Active families: []", reasons[0].message)
        self.assertIn("microsoft_defender", reasons[0].message)


if __name__ == "__main__":
    unittest.main()
