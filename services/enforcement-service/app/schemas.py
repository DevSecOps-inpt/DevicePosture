from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field


class AuditEvent(BaseModel):
    event_type: str
    endpoint_id: str | None = None
    payload: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AdapterConfigUpsert(BaseModel):
    adapter: str | None = None
    is_active: bool | None = None
    settings: dict | None = None


class AdapterConfigResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    adapter: str
    is_active: bool
    settings: dict
    created_at: datetime
    updated_at: datetime


class AdapterHealthResponse(BaseModel):
    name: str
    adapter: str
    is_active: bool
    status: str
    detail: str
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IpObjectCreate(BaseModel):
    name: str
    object_type: str
    value: str
    description: str | None = None


class IpObjectUpdate(BaseModel):
    name: str | None = None
    object_type: str | None = None
    value: str | None = None
    description: str | None = None


class IpObjectResponse(BaseModel):
    object_id: str
    name: str
    object_type: str
    value: str
    description: str | None = None
    managed_by: str
    created_at: datetime
    updated_at: datetime
    group_count: int = 0


class IpGroupCreate(BaseModel):
    name: str
    description: str | None = None


class IpGroupUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class IpGroupResponse(BaseModel):
    group_id: str
    name: str
    description: str | None = None
    created_at: datetime
    updated_at: datetime
    member_count: int = 0
    member_object_ids: list[str] = Field(default_factory=list)


class IpGroupMemberAddRequest(BaseModel):
    object_id: str


class IpAddressMembershipRequest(BaseModel):
    ip_address: str
    endpoint_id: str | None = None
    managed_by: str = "policy"
