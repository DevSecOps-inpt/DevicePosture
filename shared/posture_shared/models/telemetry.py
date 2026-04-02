from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field


class NetworkInfo(BaseModel):
    ipv4: str | None = None


class OSInfo(BaseModel):
    name: str | None = None
    version: str | None = None
    build: str | None = None


class HotfixInfo(BaseModel):
    id: str
    description: str | None = None
    installed_on: str | None = None


class ServiceInfo(BaseModel):
    name: str
    display_name: str | None = None
    status: str | None = None
    start_type: str | None = None


class ProcessInfo(BaseModel):
    pid: int | None = None
    name: str


class AntivirusProduct(BaseModel):
    name: str
    state: str | None = None
    identifier: str | None = None


class AgentRuntimeConfig(BaseModel):
    name: str | None = None
    interval_seconds: int | None = Field(default=None, ge=1)
    active_grace_multiplier: int = Field(default=3, ge=1)
    enabled_collectors: list[str] = Field(default_factory=list)
    transport_enabled: bool = True


class EndpointTelemetry(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: str = "1.0"
    collector_type: str = "unknown"
    endpoint_id: str
    hostname: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    network: NetworkInfo = Field(default_factory=NetworkInfo)
    os: OSInfo = Field(default_factory=OSInfo)
    hotfixes: list[HotfixInfo] = Field(default_factory=list)
    services: list[ServiceInfo] = Field(default_factory=list)
    processes: list[ProcessInfo] = Field(default_factory=list)
    antivirus_products: list[AntivirusProduct] = Field(default_factory=list)
    agent: AgentRuntimeConfig = Field(default_factory=AgentRuntimeConfig)
    extras: dict = Field(default_factory=dict)
