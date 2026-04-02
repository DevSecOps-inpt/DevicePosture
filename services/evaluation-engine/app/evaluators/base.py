from posture_shared.interfaces.evaluators import EvaluatorPlugin
from posture_shared.models.evaluation import EvaluationReason
from posture_shared.models.policy import PolicyCondition
from posture_shared.models.telemetry import EndpointTelemetry


class EvaluatorRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, EvaluatorPlugin] = {}

    def register(self, plugin: EvaluatorPlugin) -> None:
        self._plugins[plugin.condition_type] = plugin

    def evaluate(
        self,
        telemetry: EndpointTelemetry,
        condition: PolicyCondition,
    ) -> list[EvaluationReason]:
        plugin = self._plugins.get(condition.type)
        if plugin is None:
            return [
                EvaluationReason(
                    check_type=condition.type,
                    message=f"No evaluator registered for condition type '{condition.type}'",
                )
            ]
        return plugin.evaluate(telemetry, condition)
