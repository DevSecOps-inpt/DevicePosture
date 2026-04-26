import requests

from app.config import (
    ENFORCEMENT_SERVICE_URL,
    FORWARD_DECISIONS,
    HTTP_TIMEOUT_SECONDS,
    INTER_SERVICE_API_KEY,
    POLICY_SERVICE_URL,
    TELEMETRY_API_URL,
)
from posture_shared.models.evaluation import ComplianceDecision
from posture_shared.models.policy import PosturePolicy
from posture_shared.models.telemetry import EndpointTelemetry

_session = requests.Session()


def _auth_headers() -> dict[str, str]:
    if not INTER_SERVICE_API_KEY:
        return {}
    return {"X-API-Key": INTER_SERVICE_API_KEY}


def fetch_latest_telemetry(endpoint_id: str) -> EndpointTelemetry:
    response = _session.get(
        f"{TELEMETRY_API_URL}/endpoints/{endpoint_id}/latest",
        headers=_auth_headers(),
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    body = response.json()
    payload = body["raw_payload"]
    telemetry = EndpointTelemetry.model_validate(payload)
    source_ip = body.get("source_ip")
    if source_ip:
        enriched_extras = dict(telemetry.extras or {})
        enriched_extras["connection_source_ip"] = source_ip
        telemetry = telemetry.model_copy(update={"extras": enriched_extras})
    return telemetry


def fetch_policy(endpoint_id: str) -> PosturePolicy | None:
    response = _session.get(
        f"{POLICY_SERVICE_URL}/policy-match/{endpoint_id}",
        headers=_auth_headers(),
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    payload = response.json()
    if payload is None:
        return None
    return PosturePolicy.model_validate(payload)


def fetch_policies(endpoint_id: str) -> list[PosturePolicy]:
    response = _session.get(
        f"{POLICY_SERVICE_URL}/policy-matches/{endpoint_id}",
        headers=_auth_headers(),
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, list):
        return []
    return [PosturePolicy.model_validate(item) for item in payload if item is not None]


def forward_decision(decision: ComplianceDecision) -> dict | None:
    if not FORWARD_DECISIONS:
        return None
    response = _session.post(
        f"{ENFORCEMENT_SERVICE_URL}/decisions",
        headers=_auth_headers(),
        json=decision.model_dump(mode="json"),
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()
