from app.adapters.base import AdapterRegistry
from app.adapters.fortigate import FortiGateAdapter
from app.adapters.palo_alto import PaloAltoAdapter


def build_registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register(FortiGateAdapter())
    registry.register(PaloAltoAdapter())
    return registry
