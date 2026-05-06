import sys
import unittest
from pathlib import Path


SERVICE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVICE_ROOT.parents[1]
sys.path.insert(0, str(SERVICE_ROOT))
sys.path.insert(0, str(REPO_ROOT / "shared"))

from app.evaluators.base import EvaluatorRegistry
from app.service import evaluate_telemetry
from posture_shared.models.policy import (
    PolicyExecutionAction,
    PolicyExecutionConfig,
    PolicyManagedGroup,
    PosturePolicy,
)
from posture_shared.models.telemetry import EndpointTelemetry


class ExecutionPlanTests(unittest.TestCase):
    def test_telemetry_policy_decision_carries_trigger_and_managed_groups(self) -> None:
        policy = PosturePolicy(
            id=7,
            name="Antivirus Policy",
            trigger_type="telemetry_received",
            managed_groups=[
                PolicyManagedGroup(group_id="ipgrp-av", group_name="missing_antivirus")
            ],
            execution=PolicyExecutionConfig(
                adapter="fortigate",
                object_group="missing_antivirus",
                on_compliant=[
                    PolicyExecutionAction(
                        action_type="object.remove_ip_from_group",
                        parameters={"group_id": "ipgrp-av", "group_name": "missing_antivirus"},
                    )
                ],
            ),
        )
        telemetry = EndpointTelemetry(endpoint_id="endpoint-1", hostname="PC-01")

        decision = evaluate_telemetry(telemetry, policy, EvaluatorRegistry())

        self.assertTrue(decision.compliant)
        self.assertEqual(decision.trigger_type, "telemetry_received")
        self.assertEqual(decision.execution_plan["trigger_type"], "telemetry_received")
        self.assertEqual(
            decision.execution_plan["managed_groups"],
            [{"group_id": "ipgrp-av", "group_name": "missing_antivirus"}],
        )


if __name__ == "__main__":
    unittest.main()
