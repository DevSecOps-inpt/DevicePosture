from collectors.antivirus import AntivirusCollector
from collectors.hotfixes import HotfixCollector
from collectors.processes import ProcessCollector
from collectors.services import ServiceCollector
from collectors.system_info import SystemInfoCollector

COLLECTOR_REGISTRY = {
    "system_info": SystemInfoCollector,
    "hotfixes": HotfixCollector,
    "services": ServiceCollector,
    "processes": ProcessCollector,
    "antivirus": AntivirusCollector,
}


def build_collectors(enabled_names: list[str] | None = None) -> list:
    selected = enabled_names or list(COLLECTOR_REGISTRY.keys())
    collectors = []
    for name in selected:
        factory = COLLECTOR_REGISTRY.get(name)
        if factory is not None:
            collectors.append(factory())
    return collectors


__all__ = [
    "AntivirusCollector",
    "build_collectors",
    "HotfixCollector",
    "ProcessCollector",
    "ServiceCollector",
    "SystemInfoCollector",
]
