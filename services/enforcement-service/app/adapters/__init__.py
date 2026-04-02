from app.adapters.base import AdapterRegistry
from app.adapters.fortigate import FortiGateAdapter


def build_registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register(FortiGateAdapter())
    return registry
