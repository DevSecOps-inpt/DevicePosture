from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

PolicyScope = Literal["posture", "lifecycle"]
LifecycleEventType = Literal[
    "telemetry_received",
    "inactive_to_active",
    "active_to_inactive",
    # Backward compatibility with older lifecycle labels.
    "first_seen",
    "repeat_seen",
]
PolicyExecutionActionType = Literal[
    "object.add_ip_to_group",
    "object.remove_ip_from_group",
    "adapter.add_ip_to_group",
    "adapter.remove_ip_from_group",
    "adapter.sync_group",
    "adapter.post_event",
    "http.get",
    "http.post",
]


class PolicyCondition(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str
    field: str
    operator: str
    value: Any


class PolicyExecutionAction(BaseModel):
    action_type: PolicyExecutionActionType
    enabled: bool = True
    parameters: dict[str, Any] = Field(default_factory=dict)


class PolicyExecutionConfig(BaseModel):
    adapter: str = "fortigate"
    adapter_profile: str | None = None
    object_group: str | None = None
    on_compliant: list[PolicyExecutionAction] = Field(default_factory=list)
    on_non_compliant: list[PolicyExecutionAction] = Field(default_factory=list)


class PosturePolicy(BaseModel):
    id: int | None = None
    name: str
    description: str | None = None
    policy_scope: PolicyScope = "posture"
    lifecycle_event_type: LifecycleEventType | None = None
    target_action: Literal["allow", "quarantine", "block"] = "quarantine"
    is_active: bool = True
    conditions: list[PolicyCondition] = Field(default_factory=list)
    execution: PolicyExecutionConfig | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PolicyAssignment(BaseModel):
    id: int | None = None
    policy_id: int
    assignment_type: Literal["endpoint", "group", "default"] = "endpoint"
    assignment_value: str
