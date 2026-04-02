from abc import ABC, abstractmethod

from posture_shared.models.enforcement import EnforcementAction, EnforcementResult


class EnforcementAdapter(ABC):
    name: str

    @abstractmethod
    def execute(self, action: EnforcementAction) -> EnforcementResult:
        """Execute an enforcement action and return the result."""
