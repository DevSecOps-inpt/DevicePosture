import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from requests import RequestException


SERVICE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVICE_ROOT.parents[1]
sys.path.insert(0, str(SERVICE_ROOT))
sys.path.insert(0, str(REPO_ROOT / "shared"))

from app.main import forward_decisions
from posture_shared.models.evaluation import ComplianceDecision


class ForwardDecisionsTests(unittest.TestCase):
    def _decision(self, policy_id: int) -> ComplianceDecision:
        return ComplianceDecision(
            endpoint_id="endpoint-1",
            endpoint_ip="10.0.0.10",
            policy_id=policy_id,
            policy_name=f"policy-{policy_id}",
            compliant=False,
            recommended_action="quarantine",
            reasons=[],
            execution_plan={"actions": []},
        )

    def test_forward_decisions_continues_through_all_policy_decisions(self) -> None:
        calls: list[int | None] = []

        def fake_forward(decision: ComplianceDecision) -> dict:
            calls.append(decision.policy_id)
            if decision.policy_id == 1:
                raise RequestException("temporary enforcement failure")
            return {
                "execution_results": [
                    {"group_name": f"group-{decision.policy_id}", "status": "success"}
                ]
            }

        with patch("app.main.forward_decision", side_effect=fake_forward):
            forward_decisions([self._decision(1), self._decision(2)])

        self.assertEqual(calls, [1, 2])


if __name__ == "__main__":
    unittest.main()
