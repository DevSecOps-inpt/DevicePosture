from posture_shared.models.evaluation import ComplianceDecision, EvaluationReason
from posture_shared.models.policy import PosturePolicy
from posture_shared.models.telemetry import EndpointTelemetry

from app.evaluators.base import EvaluatorRegistry


def resolve_decision_ip(telemetry: EndpointTelemetry) -> str | None:
    extras = telemetry.extras if isinstance(telemetry.extras, dict) else {}
    source_ip = extras.get("connection_source_ip")
    if isinstance(source_ip, str) and source_ip.strip():
        return source_ip.strip()
    return telemetry.network.ipv4


def build_execution_plan(policy: PosturePolicy | None, compliant: bool) -> dict:
    if policy is None or policy.execution is None:
        return {}

    actions = policy.execution.on_compliant if compliant else policy.execution.on_non_compliant
    enabled_actions = [
        action.model_dump(mode="json")
        for action in actions
        if action.enabled
    ]
    return {
        "adapter": policy.execution.adapter,
        "adapter_profile": policy.execution.adapter_profile,
        "object_group": policy.execution.object_group,
        "actions": enabled_actions,
        "execution_gate": policy.execution.execution_gate.model_dump(mode="json")
        if policy.execution.execution_gate
        else None,
    }


def evaluate_telemetry(
    telemetry: EndpointTelemetry,
    policy: PosturePolicy | None,
    registry: EvaluatorRegistry,
) -> ComplianceDecision:
    if policy is None:
        return ComplianceDecision(
            endpoint_id=telemetry.endpoint_id,
            endpoint_ip=resolve_decision_ip(telemetry),
            compliant=True,
            recommended_action="allow",
            reasons=[],
            telemetry_timestamp=telemetry.collected_at,
        )

    reasons: list[EvaluationReason] = []
    for condition in policy.conditions:
        reasons.extend(registry.evaluate(telemetry, condition))

    compliant = len(reasons) == 0
    return ComplianceDecision(
        endpoint_id=telemetry.endpoint_id,
        endpoint_ip=resolve_decision_ip(telemetry),
        policy_id=policy.id,
        policy_name=policy.name,
        compliant=compliant,
        recommended_action="allow" if compliant else policy.target_action,
        reasons=reasons,
        execution_plan=build_execution_plan(policy, compliant),
        telemetry_timestamp=telemetry.collected_at,
    )
