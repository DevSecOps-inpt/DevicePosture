from posture_shared.interfaces.evaluators import EvaluatorPlugin
from posture_shared.models.evaluation import EvaluationReason
from posture_shared.models.policy import PolicyCondition
from posture_shared.models.telemetry import EndpointTelemetry

from app.evaluators.antivirus_families import detect_antivirus_families
from app.evaluators.operators import evaluate_membership, normalize_list, normalize_operator


class AllowedAntivirusEvaluator(EvaluatorPlugin):
    condition_type = "allowed_antivirus"

    def evaluate(
        self,
        telemetry: EndpointTelemetry,
        condition: PolicyCondition,
    ) -> list[EvaluationReason]:
        operator = normalize_operator(condition.operator)
        field = (condition.field or "antivirus.type").strip().lower()
        expected = {item.lower() for item in normalize_list(condition.value)}
        if not expected:
            return [
                EvaluationReason(
                    check_type=self.condition_type,
                    message="Antivirus condition has no expected values configured",
                )
            ]

        if field in {"antivirus.status", "av.status"}:
            actual_statuses = {
                (product.state or "unknown").strip().lower()
                for product in telemetry.antivirus_products
            }
            if detect_antivirus_families(telemetry):
                actual_statuses.add("running")
                actual_statuses.add("enabled")
            if evaluate_membership(actual_values=actual_statuses, expected_values=expected, operator=operator):
                return []
            return [
                EvaluationReason(
                    check_type=self.condition_type,
                    message=f"Antivirus status condition failed. Detected statuses: {sorted(actual_statuses)}",
                )
            ]

        if field in {"antivirus.family", "av.family"}:
            detected_families = detect_antivirus_families(telemetry)
            if evaluate_membership(
                actual_values=detected_families,
                expected_values=expected,
                operator=operator,
            ):
                return []
            return [
                EvaluationReason(
                    check_type=self.condition_type,
                    message=f"Antivirus family condition failed. Detected families: {sorted(detected_families)}",
                )
            ]

        # Default behavior: compare antivirus product identifiers/types.
        actual = {
            (product.identifier or product.name).strip().lower()
            for product in telemetry.antivirus_products
            if (product.identifier or product.name)
        }
        if evaluate_membership(actual_values=actual, expected_values=expected, operator=operator):
            return []
        return [
            EvaluationReason(
                check_type=self.condition_type,
                message=f"Antivirus type condition failed. Detected products: {sorted(actual)}",
            )
        ]
