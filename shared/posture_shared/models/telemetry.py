from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field


class NetworkInfo(BaseModel):
    ipv4: str | None = Field(default=None, max_length=64)


class OSInfo(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    version: str | None = Field(default=None, max_length=128)
    build: str | None = Field(default=None, max_length=64)


class HotfixInfo(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=256)
    installed_on: str | None = Field(default=None, max_length=64)


class ServiceInfo(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    display_name: str | None = Field(default=None, max_length=256)
    status: str | None = Field(default=None, max_length=64)
    start_type: str | None = Field(default=None, max_length=64)


class ProcessInfo(BaseModel):
    pid: int | None = None
    name: str = Field(min_length=1, max_length=256)


class AntivirusProduct(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    state: str | None = Field(default=None, max_length=64)
    identifier: str | None = Field(default=None, max_length=128)
    real_time_protection_enabled: bool | None = None
    antivirus_enabled: bool | None = None
    am_service_enabled: bool | None = None
    tamper_protection_source: str | None = Field(default=None, max_length=64)


class AgentRuntimeConfig(BaseModel):
    name: str | None = Field(default=None, max_length=128)
    interval_seconds: int | None = Field(default=None, ge=1)
    active_grace_multiplier: int = Field(default=3, ge=1)
    enabled_collectors: list[str] = Field(default_factory=list, max_length=100)
    transport_enabled: bool = True


class EndpointTelemetry(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: str = Field(default="1.0", max_length=16)
    collector_type: str = Field(default="unknown", max_length=64)
    endpoint_id: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=255)
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    network: NetworkInfo = Field(default_factory=NetworkInfo)
    os: OSInfo = Field(default_factory=OSInfo)
    hotfixes: list[HotfixInfo] = Field(default_factory=list, max_length=5000)
    services: list[ServiceInfo] = Field(default_factory=list, max_length=5000)
    processes: list[ProcessInfo] = Field(default_factory=list, max_length=10000)
    antivirus_products: list[AntivirusProduct] = Field(default_factory=list, max_length=200)
    agent: AgentRuntimeConfig = Field(default_factory=AgentRuntimeConfig)
    extras: dict = Field(default_factory=dict, max_length=200)
