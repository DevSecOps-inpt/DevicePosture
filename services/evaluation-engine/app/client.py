import requests

from app.config import (
    ENFORCEMENT_SERVICE_URL,
    FORWARD_DECISIONS,
    HTTP_TIMEOUT_SECONDS,
    POLICY_SERVICE_URL,
    TELEMETRY_API_URL,
)
from posture_shared.models.evaluation import ComplianceDecision
from posture_shared.models.policy import PosturePolicy
from posture_shared.models.telemetry import EndpointTelemetry


def fetch_latest_telemetry(endpoint_id: str) -> EndpointTelemetry:
    response = requests.get(
        f"{TELEMETRY_API_URL}/endpoints/{endpoint_id}/latest",
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    payload = response.json()["raw_payload"]
    return EndpointTelemetry.model_validate(payload)


def fetch_policy(endpoint_id: str) -> PosturePolicy | None:
    response = requests.get(
        f"{POLICY_SERVICE_URL}/policy-match/{endpoint_id}",
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    payload = response.json()
    if payload is None:
        return None
    return PosturePolicy.model_validate(payload)


def forward_decision(decision: ComplianceDecision) -> dict | None:
    if not FORWARD_DECISIONS:
        return None
    response = requests.post(
        f"{ENFORCEMENT_SERVICE_URL}/decisions",
        json=decision.model_dump(mode="json"),
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()
