from datetime import datetime, timezone
import ipaddress

from pydantic import BaseModel, ConfigDict, Field, field_validator


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
    name: str = Field(min_length=1, max_length=255)
    object_type: str
    value: str = Field(min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=500)

    @field_validator("object_type")
    @classmethod
    def validate_object_type(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"host", "cidr"}:
            raise ValueError("object_type must be 'host' or 'cidr'")
        return normalized

    @field_validator("value")
    @classmethod
    def validate_ip_value(cls, value: str, info) -> str:
        normalized = value.strip()
        object_type = info.data.get("object_type")
        if object_type == "host":
            ipaddress.ip_address(normalized)
        elif object_type == "cidr":
            ipaddress.ip_network(normalized, strict=False)
        return normalized


class IpObjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    object_type: str | None = None
    value: str | None = Field(default=None, min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=500)

    @field_validator("object_type")
    @classmethod
    def validate_optional_object_type(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if normalized not in {"host", "cidr"}:
            raise ValueError("object_type must be 'host' or 'cidr'")
        return normalized

    @field_validator("value")
    @classmethod
    def normalize_optional_value(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip()


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
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=500)


class IpGroupUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=500)


class IpGroupResponse(BaseModel):
    group_id: str
    name: str
    description: str | None = None
    created_at: datetime
    updated_at: datetime
    member_count: int = 0
    member_object_ids: list[str] = Field(default_factory=list)


class IpGroupMemberAddRequest(BaseModel):
    object_id: str = Field(min_length=1, max_length=128)


class IpAddressMembershipRequest(BaseModel):
    ip_address: str = Field(min_length=1, max_length=64)
    endpoint_id: str | None = Field(default=None, max_length=128)
    managed_by: str = Field(default="policy", max_length=32)

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        normalized = value.strip()
        ipaddress.ip_address(normalized)
        return normalized


class BackgroundJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    job_type: str
    status: str
    endpoint_id: str | None = None
    payload: dict
    result: dict
    error_message: str | None = None
    created_at: datetime
    updated_at: datetime
