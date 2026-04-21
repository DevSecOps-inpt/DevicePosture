from app.adapters.base import AdapterRegistry
from app.adapters.fortigate import FortiGateAdapter
<<<<<<< HEAD
from app.adapters.palo_alto import PaloAltoAdapter
=======
from app.adapters.paloalto import PaloAltoAdapter
>>>>>>> origin/main


def build_registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register(FortiGateAdapter())
    registry.register(PaloAltoAdapter())
    return registry
