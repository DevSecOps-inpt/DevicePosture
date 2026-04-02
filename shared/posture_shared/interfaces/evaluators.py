from abc import ABC, abstractmethod

from posture_shared.models.evaluation import EvaluationReason
from posture_shared.models.policy import PolicyCondition
from posture_shared.models.telemetry import EndpointTelemetry


class EvaluatorPlugin(ABC):
    condition_type: str

    @abstractmethod
    def evaluate(
        self,
        telemetry: EndpointTelemetry,
        condition: PolicyCondition,
    ) -> list[EvaluationReason]:
        """Return an empty list when the condition passes."""
