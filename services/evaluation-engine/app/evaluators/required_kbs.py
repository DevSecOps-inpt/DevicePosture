import re

from posture_shared.interfaces.evaluators import EvaluatorPlugin
from posture_shared.models.evaluation import EvaluationReason
from posture_shared.models.policy import PolicyCondition
from posture_shared.models.telemetry import EndpointTelemetry

from app.evaluators.operators import evaluate_membership, normalize_list, normalize_operator


class RequiredKBsEvaluator(EvaluatorPlugin):
    condition_type = "required_kbs"

    def evaluate(
        self,
        telemetry: EndpointTelemetry,
        condition: PolicyCondition,
    ) -> list[EvaluationReason]:
        required = {item.upper() for item in normalize_list(condition.value)}
        if not required:
            return [
                EvaluationReason(
                    check_type=self.condition_type,
                    message="Required KB condition has no expected values configured",
                )
            ]
        present = {item.id.upper() for item in telemetry.hotfixes}
        operator = normalize_operator(condition.operator)

        if evaluate_membership(actual_values=present, expected_values=required, operator=operator):
            return []

        if operator == "does_not_exist_in":
            overlaps = sorted(present.intersection(required))
            return [
                EvaluationReason(
                    check_type=self.condition_type,
                    message=f"Disallowed KB patches detected: {', '.join(overlaps)}",
                )
            ]

        missing = []
        for expected in sorted(required):
            if "*" in expected:
                pattern = "^" + re.escape(expected).replace(r"\*", ".*") + "$"
                if not any(re.match(pattern, actual, flags=re.IGNORECASE) for actual in present):
                    missing.append(expected)
            elif expected not in present:
                missing.append(expected)
        return [
            EvaluationReason(
                check_type=self.condition_type,
                message=f"Required KB condition failed. Missing patches: {', '.join(missing)}",
            )
        ]
