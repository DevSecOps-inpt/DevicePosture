from posture_shared.interfaces.adapters import EnforcementAdapter
from posture_shared.models.enforcement import EnforcementAction, EnforcementResult


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, EnforcementAdapter] = {}

    def register(self, adapter: EnforcementAdapter) -> None:
        self._adapters[adapter.name] = adapter

    def execute(self, action: EnforcementAction) -> EnforcementResult:
        adapter = self._adapters.get(action.adapter)
        if adapter is None:
            return EnforcementResult(
                adapter=action.adapter,
                action=action.action,
                endpoint_id=action.endpoint_id,
                status="failed",
                details={"error": f"No adapter registered for '{action.adapter}'"},
            )
        return adapter.execute(action)
