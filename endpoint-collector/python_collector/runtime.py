from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from collectors import build_collectors
from config import EndpointCollectorConfig
from http_client import post_json


def merge_payload(parts: list[dict]) -> dict:
    merged = {
        "schema_version": "1.0",
        "collector_type": "python-windows-agent",
        "endpoint_id": "unknown-endpoint",
        "hostname": "unknown-host",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "network": {"ipv4": None},
        "os": {"name": None, "version": None, "build": None},
        "hotfixes": [],
        "services": [],
        "processes": [],
        "antivirus_products": [],
        "extras": {},
    }
    for part in parts:
        for key, value in part.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key].update(value)
            else:
                merged[key] = value
    return merged


def collect_telemetry(config: EndpointCollectorConfig) -> dict:
    parts = []
    for module in build_collectors(config.collectors.enabled):
        try:
            parts.append(module.collect())
        except Exception as exc:
            extras = {"extras": {f"{module.name}_error": str(exc)}}
            parts.append(extras)
    return merge_payload(parts)


def maybe_write_payload(payload: dict, output_path: str | None) -> None:
    if not output_path:
        return
    Path(output_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def send_payload(payload: dict, config: EndpointCollectorConfig) -> tuple[int, str] | None:
    transport = config.transport
    if not transport.enabled or not transport.url:
        return None
    return post_json(
        url=transport.url,
        payload=payload,
        timeout=transport.timeout_seconds,
        token=transport.token,
        insecure=transport.insecure_tls,
    )
