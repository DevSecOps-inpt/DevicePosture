from datetime import datetime
from typing import Any, Literal

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
    supported_lifecycle_events = {"telemetry_received", "active_to_inactive"}
    if policy_scope == "lifecycle" and lifecycle_event_type is None:
        raise ValueError("lifecycle_event_type is required when policy_scope is 'lifecycle'")
    if policy_scope == "posture":
        return "posture", None
    if lifecycle_event_type not in supported_lifecycle_events:
        raise ValueError("lifecycle_event_type must be one of: telemetry_received, active_to_inactive")
    return policy_scope, lifecycle_event_type


class PolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    policy_scope: PolicyScope = "posture"
    lifecycle_event_type: LifecycleEventType | None = None
    target_action: Literal["allow", "quarantine", "block"] = "quarantine"
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
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    policy_scope: PolicyScope | None = None
    lifecycle_event_type: LifecycleEventType | None = None
    target_action: Literal["allow", "quarantine", "block"] | None = None
    is_active: bool | None = None
    conditions: list[PolicyCondition] | None = None
    execution: PolicyExecutionConfig | None = None


class PolicyResponse(PosturePolicy):
    model_config = ConfigDict(from_attributes=True)


class AssignmentCreate(BaseModel):
    assignment_type: Literal["endpoint", "group", "default"]
    assignment_value: str = Field(min_length=1, max_length=255)


class AssignmentResponse(PolicyAssignment):
    model_config = ConfigDict(from_attributes=True)


class ConditionGroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    group_type: str = Field(min_length=1, max_length=32)
    description: str | None = Field(default=None, max_length=500)
    values: list[str] = Field(default_factory=list, max_length=5000)


class ConditionGroupUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    group_type: str | None = Field(default=None, min_length=1, max_length=32)
    description: str | None = Field(default=None, max_length=500)
    values: list[str] | None = Field(default=None, max_length=5000)


class ConditionGroupResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    group_type: str
    description: str | None = None
    values: list[str]
    created_at: datetime
    updated_at: datetime


class EndpointAssignedPolicyResponse(BaseModel):
    policy_id: int
    policy_name: str
    policy_scope: PolicyScope
    lifecycle_event_type: LifecycleEventType | None = None
    assignment_type: Literal["endpoint", "group", "default"]
    assignment_value: str


AuthProtocol = Literal["local", "ldap", "radius", "oidc", "oauth2", "saml"]


class AuthProviderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    protocol: Literal["ldap", "radius", "oidc", "oauth2", "saml"]
    is_enabled: bool = False
    priority: int = Field(default=100, ge=0, le=10000)
    settings: dict[str, Any] = Field(default_factory=dict)


class AuthProviderUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    protocol: Literal["ldap", "radius", "oidc", "oauth2", "saml"] | None = None
    is_enabled: bool | None = None
    priority: int | None = Field(default=None, ge=0, le=10000)
    settings: dict[str, Any] | None = None


class AuthProviderResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    protocol: Literal["ldap", "radius", "oidc", "oauth2", "saml"]
    is_enabled: bool
    priority: int
    settings: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class DirectoryGroupResponse(BaseModel):
    id: int
    provider_id: int
    group_key: str
    group_name: str
    group_dn: str | None = None
    is_computer_group: bool = False
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DirectoryGroupSearchRequest(BaseModel):
    ldap_filter: str = Field(default="(objectClass=group)", min_length=1, max_length=1024)
    search: str | None = Field(default=None, max_length=255)
    search_base: str | None = Field(default=None, max_length=1024)
    limit: int = Field(default=200, ge=1, le=2000)
    computer_only: bool = False
    persist: bool = False


class DirectoryGroupSearchItem(BaseModel):
    id: int | None = None
    group_key: str
    group_name: str
    group_dn: str | None = None
    is_computer_group: bool = False
    already_cached: bool = False


class DirectoryGroupSearchResponse(BaseModel):
    provider_id: int
    provider_name: str
    search_filter: str
    search_base: str
    search: str | None = None
    matched_count: int
    imported_count: int
    items: list[DirectoryGroupSearchItem] = Field(default_factory=list)
    message: str


class ProviderConnectivityResult(BaseModel):
    ok: bool
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ProviderCredentialsTestRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class UserAccountCreate(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    full_name: str | None = Field(default=None, max_length=255)
    email: str | None = Field(default=None, max_length=255)
    is_active: bool = True
    auth_source: AuthProtocol = "local"
    external_provider_id: int | None = None
    password: str | None = Field(default=None, min_length=8, max_length=256)
    external_subject: str | None = Field(default=None, max_length=255)
    external_groups: list[str] = Field(default_factory=list, max_length=200)
    roles: list[str] = Field(default_factory=lambda: ["admin"], max_length=20)


class UserAccountUpdate(BaseModel):
    full_name: str | None = Field(default=None, max_length=255)
    email: str | None = Field(default=None, max_length=255)
    is_active: bool | None = None
    external_provider_id: int | None = None
    password: str | None = Field(default=None, min_length=8, max_length=256)
    external_subject: str | None = Field(default=None, max_length=255)
    external_groups: list[str] | None = Field(default=None, max_length=200)
    roles: list[str] | None = Field(default=None, max_length=20)


class UserAccountResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    full_name: str | None = None
    email: str | None = None
    is_active: bool
    auth_source: AuthProtocol
    external_provider_id: int | None = None
    external_subject: str | None = None
    external_groups: list[str]
    roles: list[str]
    created_at: datetime
    updated_at: datetime


class EndpointDomainVerificationRequest(BaseModel):
    endpoint_id: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=255)
    domain_name: str | None = Field(default=None, max_length=255)
    domain_dn: str | None = Field(default=None, max_length=1024)
    required_group_dns: list[str] = Field(default_factory=list, max_length=200)


class EndpointDomainVerificationResponse(BaseModel):
    ok: bool
    joined: bool
    in_tree: bool
    in_required_groups: bool
    provider_id: int
    provider_name: str
    endpoint_id: str
    hostname: str
    domain_name: str | None = None
    domain_dn: str | None = None
    computer_dn: str | None = None
    member_group_dns: list[str] = Field(default_factory=list)
    required_group_dns: list[str] = Field(default_factory=list)
    message: str


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class AuthSessionUser(BaseModel):
    username: str
    full_name: str | None = None
    auth_source: AuthProtocol
    roles: list[str] = Field(default_factory=list)


class LoginResponse(BaseModel):
    expires_at: datetime
    user: AuthSessionUser
