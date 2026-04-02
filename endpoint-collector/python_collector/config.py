from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AgentConfig:
    interval_seconds: int = 300
    log_level: str = "INFO"
    write_payload_file: str | None = None


@dataclass
class TransportConfig:
    enabled: bool = True
    url: str | None = None
    timeout_seconds: int = 10
    insecure_tls: bool = False
    token: str | None = None


@dataclass
class CollectorsConfig:
    enabled: list[str] = field(
        default_factory=lambda: [
            "system_info",
            "hotfixes",
            "services",
            "processes",
            "antivirus",
        ]
    )


@dataclass
class EndpointCollectorConfig:
    agent: AgentConfig = field(default_factory=AgentConfig)
    transport: TransportConfig = field(default_factory=TransportConfig)
    collectors: CollectorsConfig = field(default_factory=CollectorsConfig)


def _merge_dataclass(dataclass_type, values: dict | None):
    current = dataclass_type()
    if not values:
        return current

    for key, value in values.items():
        if hasattr(current, key):
            setattr(current, key, value)
    return current


def load_config(path: str | Path) -> EndpointCollectorConfig:
    raw = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    return EndpointCollectorConfig(
        agent=_merge_dataclass(AgentConfig, raw.get("agent")),
        transport=_merge_dataclass(TransportConfig, raw.get("transport")),
        collectors=_merge_dataclass(CollectorsConfig, raw.get("collectors")),
    )
