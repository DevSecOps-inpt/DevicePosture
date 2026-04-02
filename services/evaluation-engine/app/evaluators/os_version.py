import re

from posture_shared.interfaces.evaluators import EvaluatorPlugin
from posture_shared.models.evaluation import EvaluationReason
from posture_shared.models.policy import PolicyCondition
from posture_shared.models.telemetry import EndpointTelemetry

from app.evaluators.operators import evaluate_membership, normalize_list, normalize_operator


def _parse_version_tokens(value: object) -> tuple[int, ...] | None:
    text = str(value or "").strip()
    if not text:
        return None
    numbers = re.findall(r"\d+", text)
    if not numbers:
        return None
    return tuple(int(item) for item in numbers)


def _evaluate_version(actual: tuple[int, ...], expected: tuple[int, ...], operator: str) -> bool:
    max_len = max(len(actual), len(expected))
    padded_actual = actual + (0,) * (max_len - len(actual))
    padded_expected = expected + (0,) * (max_len - len(expected))
    if operator == "greater_than":
        return padded_actual > padded_expected
    if operator == "greater_than_or_equal":
        return padded_actual >= padded_expected
    if operator == "less_than":
        return padded_actual < padded_expected
    if operator == "less_than_or_equal":
        return padded_actual <= padded_expected
    return padded_actual == padded_expected


class OSVersionEvaluator(EvaluatorPlugin):
    condition_type = "os_version"

    def evaluate(
        self,
        telemetry: EndpointTelemetry,
        condition: PolicyCondition,
    ) -> list[EvaluationReason]:
        operator = normalize_operator(condition.operator)
        field = (condition.field or "").strip().lower()
        raw_value = condition.value
        actual_name = (telemetry.os.name or "").strip()
        actual_build_raw = telemetry.os.build or telemetry.os.version or "0"
        try:
            actual_build = int(str(actual_build_raw).strip())
        except (TypeError, ValueError):
            actual_build = 0

        # Backward compatibility with older object-style conditions.
        if isinstance(raw_value, dict):
            name_value = raw_value.get("name")
            min_build_value = None
            for key in ("min_build", "build", "version", "value"):
                candidate = raw_value.get(key)
                if candidate is None:
                    continue
                try:
                    min_build_value = int(str(candidate).strip())
                    break
                except (TypeError, ValueError):
                    continue

            failures: list[EvaluationReason] = []
            if isinstance(name_value, str) and name_value.strip():
                if actual_name != name_value.strip():
                    failures.append(
                        EvaluationReason(
                            check_type=self.condition_type,
                            message=f"OS name '{actual_name}' does not match required '{name_value.strip()}'",
                        )
                    )
            if min_build_value is not None and actual_build < min_build_value:
                failures.append(
                    EvaluationReason(
                        check_type=self.condition_type,
                        message=f"OS build '{actual_build}' is below required minimum '{min_build_value}'",
                    )
                )
            return failures

        if field in {"os.name", "os"}:
            expected_names = {item.lower() for item in normalize_list(raw_value)}
            actual_values = {actual_name.lower()} if actual_name else set()
            if evaluate_membership(actual_values=actual_values, expected_values=expected_names, operator=operator):
                return []
            return [
                EvaluationReason(
                    check_type=self.condition_type,
                    message=f"OS name '{actual_name}' failed operator '{condition.operator}' against {sorted(expected_names)}",
                )
            ]

        if field in {"os.build", "os.version", "build", "version"}:
            expected_tokens = _parse_version_tokens(raw_value)
            actual_tokens = _parse_version_tokens(actual_build_raw)
            if expected_tokens is None or actual_tokens is None:
                return [
                    EvaluationReason(
                        check_type=self.condition_type,
                        message="OS version/build condition has an invalid value",
                    )
                ]
            numeric_operator = normalize_operator(condition.operator)
            if _evaluate_version(actual_tokens, expected_tokens, numeric_operator):
                return []
            expected_text = ".".join(str(item) for item in expected_tokens)
            actual_text = ".".join(str(item) for item in actual_tokens)
            return [
                EvaluationReason(
                    check_type=self.condition_type,
                    message=f"OS version/build '{actual_text}' failed operator '{condition.operator}' with expected '{expected_text}'",
                )
            ]

        # If field is unknown, fallback to old minimum build comparison for compatibility.
        try:
            min_build = int(str(raw_value).strip())
        except (TypeError, ValueError):
            return []
        if actual_build >= min_build:
            return []
        return [
            EvaluationReason(
                check_type=self.condition_type,
                message=f"OS build '{actual_build}' is below required minimum '{min_build}'",
            )
        ]
