from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from posture_shared.models.policy import (
    LifecycleEventType,
    PolicyAssignment,
    PolicyCondition,
    PolicyExecutionConfig,
    PolicyScope,
    PosturePolicy,
)


def _validate_policy_scope(
    policy_scope: PolicyScope,
    lifecycle_event_type: LifecycleEventType | None,
) -> tuple[PolicyScope, LifecycleEventType | None]:
    if policy_scope == "lifecycle" and lifecycle_event_type is None:
        raise ValueError("lifecycle_event_type is required when policy_scope is 'lifecycle'")
    if policy_scope == "posture":
        return "posture", None
    return policy_scope, lifecycle_event_type


class PolicyCreate(BaseModel):
    name: str
    description: str | None = None
    policy_scope: PolicyScope = "posture"
    lifecycle_event_type: LifecycleEventType | None = None
    target_action: str = "quarantine"
    is_active: bool = True
    conditions: list[PolicyCondition] = Field(default_factory=list)
    execution: PolicyExecutionConfig | None = None

    @model_validator(mode="after")
    def validate_scope(self) -> "PolicyCreate":
        scope, lifecycle_type = _validate_policy_scope(self.policy_scope, self.lifecycle_event_type)
        self.policy_scope = scope
        self.lifecycle_event_type = lifecycle_type
        return self


class PolicyUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    policy_scope: PolicyScope | None = None
    lifecycle_event_type: LifecycleEventType | None = None
    target_action: str | None = None
    is_active: bool | None = None
    conditions: list[PolicyCondition] | None = None
    execution: PolicyExecutionConfig | None = None


class PolicyResponse(PosturePolicy):
    model_config = ConfigDict(from_attributes=True)


class AssignmentCreate(BaseModel):
    assignment_type: str
    assignment_value: str


class AssignmentResponse(PolicyAssignment):
    model_config = ConfigDict(from_attributes=True)


class ConditionGroupCreate(BaseModel):
    name: str
    group_type: str
    description: str | None = None
    values: list[str] = Field(default_factory=list)


class ConditionGroupUpdate(BaseModel):
    name: str | None = None
    group_type: str | None = None
    description: str | None = None
    values: list[str] | None = None


class ConditionGroupResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    group_type: str
    description: str | None = None
    values: list[str]
    created_at: datetime
    updated_at: datetime
