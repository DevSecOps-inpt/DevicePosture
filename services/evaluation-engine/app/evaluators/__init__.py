from app.evaluators.allowed_antivirus import AllowedAntivirusEvaluator
from app.evaluators.base import EvaluatorRegistry
from app.evaluators.os_version import OSVersionEvaluator
from app.evaluators.required_kbs import RequiredKBsEvaluator


def build_registry() -> EvaluatorRegistry:
    registry = EvaluatorRegistry()
    registry.register(OSVersionEvaluator())
    registry.register(RequiredKBsEvaluator())
    registry.register(AllowedAntivirusEvaluator())
    return registry
