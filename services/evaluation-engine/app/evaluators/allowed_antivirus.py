from posture_shared.interfaces.evaluators import EvaluatorPlugin
from posture_shared.models.evaluation import EvaluationReason
from posture_shared.models.policy import PolicyCondition
from posture_shared.models.telemetry import EndpointTelemetry

from app.evaluators.antivirus_families import (
    detect_active_antivirus_families,
    detect_antivirus_families,
    normalize_antivirus_family_value,
)
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

        installed_families = detect_antivirus_families(telemetry)
        active_families = detect_active_antivirus_families(telemetry)
        detected_products = {
            (product.identifier or product.name).strip().lower()
            for product in telemetry.antivirus_products
            if (product.identifier or product.name)
        }

        if field in {"antivirus.status", "av.status"}:
            actual_statuses: set[str] = set()
            if installed_families or detected_products:
                actual_statuses.add("installed")
            if active_families:
                actual_statuses.update({"running", "enabled", "active"})
            elif installed_families or detected_products:
                actual_statuses.update({"stopped", "disabled", "inactive", "not_running"})
            else:
                actual_statuses.add("not_installed")
            if evaluate_membership(actual_values=actual_statuses, expected_values=expected, operator=operator):
                return []
            return [
                EvaluationReason(
                    check_type=self.condition_type,
                    message=(
                        f"Antivirus status condition failed. Detected statuses: {sorted(actual_statuses)}. "
                        f"Active families: {sorted(active_families)}. Installed families: {sorted(installed_families)}"
                    ),
                )
            ]

        if field in {"antivirus.family", "av.family"}:
            expected_families = {normalize_antivirus_family_value(item) for item in expected}
            if evaluate_membership(
                actual_values=installed_families,
                expected_values=expected_families,
                operator=operator,
            ):
                return []
            return [
                EvaluationReason(
                    check_type=self.condition_type,
                    message=(
                        f"Antivirus family condition failed. Installed families: {sorted(installed_families)}. "
                        f"Active families: {sorted(active_families)}"
                    ),
                )
            ]

        # Default behavior: compare antivirus product identifiers/types.
        actual = detected_products | installed_families
        if evaluate_membership(actual_values=actual, expected_values=expected, operator=operator):
            return []
        return [
            EvaluationReason(
                check_type=self.condition_type,
                message=f"Antivirus type condition failed. Detected products: {sorted(actual)}",
            )
        ]
