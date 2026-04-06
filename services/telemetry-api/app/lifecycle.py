from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from urllib.error import URLError
from urllib.parse import quote_plus
from urllib.request import Request, urlopen

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.activity import compute_endpoint_activity
from app.models import Endpoint, EndpointLifecycleEvent, TelemetryRecord

EVENT_TELEMETRY_RECEIVED = "endpoint.telemetry_received"
EVENT_INACTIVE_TO_ACTIVE = "endpoint.inactive_to_active"
EVENT_ACTIVE_TO_INACTIVE = "endpoint.active_to_inactive"

# Backward-compatibility aliases for older labels.
EVENT_FIRST_SEEN = EVENT_TELEMETRY_RECEIVED
EVENT_REPEAT_SEEN = EVENT_TELEMETRY_RECEIVED

LIFECYCLE_POLICY_EVENT_MAP = {
    EVENT_TELEMETRY_RECEIVED: ["telemetry_received"],
    EVENT_INACTIVE_TO_ACTIVE: [],
    EVENT_ACTIVE_TO_INACTIVE: ["active_to_inactive"],
}

POLICY_SERVICE_URL = os.getenv("POLICY_SERVICE_URL", "http://127.0.0.1:8002")
POLICY_HTTP_TIMEOUT_SECONDS = float(os.getenv("POLICY_HTTP_TIMEOUT_SECONDS", "5"))
ENFORCEMENT_SERVICE_URL = os.getenv("ENFORCEMENT_SERVICE_URL", "http://127.0.0.1:8004")
ENFORCEMENT_HTTP_TIMEOUT_SECONDS = float(os.getenv("ENFORCEMENT_HTTP_TIMEOUT_SECONDS", "8"))
EVALUATION_ENGINE_URL = os.getenv("EVALUATION_ENGINE_URL", "http://127.0.0.1:8003")
EVALUATION_HTTP_TIMEOUT_SECONDS = float(os.getenv("EVALUATION_HTTP_TIMEOUT_SECONDS", "8"))


def _http_get_json(url: str, timeout: float) -> dict | None:
    request = Request(url, method="GET")
    with urlopen(request, timeout=timeout) as response:
        payload = response.read().decode("utf-8")
    if not payload:
        return None
    return json.loads(payload)


def _http_post_json(url: str, payload: dict, timeout: float) -> dict | None:
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        url=url,
        method="POST",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8")
    if not raw:
        return None
    return json.loads(raw)


def resolve_lifecycle_policy(
    *,
    endpoint_id: str,
    event_type: str,
    logger: logging.Logger,
) -> dict | None:
    lifecycle_event_types = LIFECYCLE_POLICY_EVENT_MAP.get(event_type)
    if lifecycle_event_types is None:
        return None

    for lifecycle_event_type in lifecycle_event_types:
        url = f"{POLICY_SERVICE_URL}/lifecycle-policy-match/{quote_plus(lifecycle_event_type)}/{quote_plus(endpoint_id)}"
        try:
            payload = _http_get_json(url, POLICY_HTTP_TIMEOUT_SECONDS)
        except URLError as exc:
            logger.warning("failed to resolve lifecycle policy endpoint_id=%s event_type=%s: %s", endpoint_id, event_type, exc)
            return None
        except json.JSONDecodeError:
            logger.warning(
                "failed to decode lifecycle policy response endpoint_id=%s event_type=%s",
                endpoint_id,
                event_type,
            )
            return None
        if payload is not None:
            return payload
    return None


def _build_lifecycle_execution_plan(policy: dict, compliant: bool) -> dict:
    execution = policy.get("execution")
    if not isinstance(execution, dict):
        return {}

    actions_key = "on_compliant" if compliant else "on_non_compliant"
    raw_actions = execution.get(actions_key)
    if not isinstance(raw_actions, list):
        return {}

    actions = [
        action
        for action in raw_actions
        if isinstance(action, dict) and action.get("enabled", True)
    ]
    if not actions:
        return {}

    return {
        "adapter": execution.get("adapter"),
        "adapter_profile": execution.get("adapter_profile"),
        "object_group": execution.get("object_group"),
        "actions": actions,
    }


def _evaluate_lifecycle_policy(
    *,
    endpoint: Endpoint,
    policy: dict,
    event_type: str,
    endpoint_ip: str | None,
    telemetry_payload: dict | None,
    logger: logging.Logger,
) -> dict:
    conditions = policy.get("conditions")
    has_conditions = isinstance(conditions, list) and len(conditions) > 0
    if not has_conditions:
        return {
            "endpoint_id": endpoint.endpoint_id,
            "endpoint_ip": endpoint_ip,
            "policy_id": policy.get("id"),
            "policy_name": policy.get("name"),
            "compliant": True,
            "recommended_action": "allow",
            "reasons": [
                {
                    "check_type": "lifecycle_event",
                    "message": f"Lifecycle policy matched for {event_type}",
                }
            ],
            "execution_plan": _build_lifecycle_execution_plan(policy, compliant=True),
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "telemetry_timestamp": endpoint.last_collected_at.isoformat() if endpoint.last_collected_at else None,
        }

    if not isinstance(telemetry_payload, dict):
        return {
            "endpoint_id": endpoint.endpoint_id,
            "endpoint_ip": endpoint_ip,
            "policy_id": policy.get("id"),
            "policy_name": policy.get("name"),
            "compliant": False,
            "recommended_action": policy.get("target_action") or "quarantine",
            "reasons": [
                {
                    "check_type": "lifecycle_event",
                    "message": "Lifecycle policy has conditions but no telemetry payload is available",
                }
            ],
            "execution_plan": _build_lifecycle_execution_plan(policy, compliant=False),
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "telemetry_timestamp": endpoint.last_collected_at.isoformat() if endpoint.last_collected_at else None,
        }

    url = f"{EVALUATION_ENGINE_URL}/evaluate-inline"
    enriched_telemetry_payload = dict(telemetry_payload)
    extras = enriched_telemetry_payload.get("extras")
    if not isinstance(extras, dict):
        extras = {}
    if endpoint_ip:
        extras["connection_source_ip"] = endpoint_ip
    enriched_telemetry_payload["extras"] = extras

    request_payload = {
        "telemetry": enriched_telemetry_payload,
        "policy": policy,
    }
    try:
        decision = _http_post_json(url, request_payload, EVALUATION_HTTP_TIMEOUT_SECONDS) or {}
    except URLError as exc:
        logger.warning(
            "failed to evaluate lifecycle policy endpoint_id=%s event_type=%s policy_id=%s: %s",
            endpoint.endpoint_id,
            event_type,
            policy.get("id"),
            exc,
        )
        raise
    except json.JSONDecodeError as exc:
        logger.warning(
            "failed to decode evaluation response endpoint_id=%s event_type=%s policy_id=%s",
            endpoint.endpoint_id,
            event_type,
            policy.get("id"),
        )
        raise URLError(str(exc)) from exc

    if not isinstance(decision, dict):
        raise URLError("Invalid evaluation response payload")
    execution_plan = decision.get("execution_plan")
    if not isinstance(execution_plan, dict):
        execution_plan = _build_lifecycle_execution_plan(policy, compliant=bool(decision.get("compliant")))
        decision["execution_plan"] = execution_plan
    return decision


def _execute_lifecycle_policy(
    *,
    decision_payload: dict | None,
    logger: logging.Logger,
) -> tuple[str, dict]:
    if decision_payload is None:
        return "skipped", {"reason": "no policy matched"}

    execution_plan = decision_payload.get("execution_plan")
    actions = execution_plan.get("actions", []) if isinstance(execution_plan, dict) else []
    if not isinstance(actions, list) or not actions:
        return "skipped", {"reason": "matched policy has no execution actions"}

    url = f"{ENFORCEMENT_SERVICE_URL}/decisions"
    try:
        response_payload = _http_post_json(url, decision_payload, ENFORCEMENT_HTTP_TIMEOUT_SECONDS)
        return "executed", response_payload or {}
    except URLError as exc:
        logger.warning(
            "failed to execute lifecycle policy endpoint_id=%s policy_id=%s: %s",
            decision_payload.get("endpoint_id"),
            decision_payload.get("policy_id"),
            exc,
        )
        return "failed", {"error": str(exc)}
    except json.JSONDecodeError:
        return "executed", {"warning": "enforcement response was not valid JSON"}


def create_lifecycle_event(
    *,
    db: Session,
    endpoint: Endpoint,
    event_type: str,
    previous_status: str | None,
    current_status: str | None,
    details: dict,
    telemetry_payload: dict | None,
    logger: logging.Logger,
) -> EndpointLifecycleEvent:
    policy = resolve_lifecycle_policy(
        endpoint_id=endpoint.endpoint_id,
        event_type=event_type,
        logger=logger,
    )
    policy_id = policy.get("id") if isinstance(policy, dict) else None
    policy_name = policy.get("name") if isinstance(policy, dict) else None
    endpoint_ip = details.get("endpoint_ip") if isinstance(details, dict) else None
    if not endpoint_ip and isinstance(details, dict):
        endpoint_ip = details.get("source_ip")
    if not endpoint_ip:
        endpoint_ip = endpoint.last_source_ip
    if not endpoint_ip:
        endpoint_ip = endpoint.last_ipv4

    evaluation_error: str | None = None
    decision_payload: dict | None = None
    if isinstance(policy, dict):
        try:
            decision_payload = _evaluate_lifecycle_policy(
                endpoint=endpoint,
                policy=policy,
                event_type=event_type,
                endpoint_ip=endpoint_ip,
                telemetry_payload=telemetry_payload,
                logger=logger,
            )
        except URLError as exc:
            evaluation_error = str(exc)

    execution_state = "failed" if evaluation_error else "pending"
    execution_result: dict = {}
    if evaluation_error:
        execution_result = {"error": f"policy evaluation failed: {evaluation_error}"}
    else:
        execution_state, execution_result = _execute_lifecycle_policy(
            decision_payload=decision_payload,
            logger=logger,
        )

    event_details = dict(details or {})
    if decision_payload:
        event_details["decision"] = {
            "compliant": bool(decision_payload.get("compliant")),
            "recommended_action": decision_payload.get("recommended_action"),
            "reason_count": len(decision_payload.get("reasons", [])) if isinstance(decision_payload.get("reasons"), list) else 0,
        }
    if execution_result:
        event_details["execution"] = execution_result

    event = EndpointLifecycleEvent(
        endpoint_ref=endpoint.id,
        endpoint_id=endpoint.endpoint_id,
        event_type=event_type,
        previous_status=previous_status,
        current_status=current_status,
        matched_policy_id=policy_id,
        matched_policy_name=policy_name,
        execution_state=execution_state,
        details=event_details,
    )
    db.add(event)
    logger.info(
        "lifecycle event endpoint_id=%s event_type=%s previous=%s current=%s policy_id=%s execution_state=%s",
        endpoint.endpoint_id,
        event_type,
        previous_status,
        current_status,
        policy_id,
        execution_state,
    )
    return event


def reconcile_inactive_transitions(*, db: Session, logger: logging.Logger) -> None:
    endpoints = db.scalars(select(Endpoint)).all()
    now = datetime.now(timezone.utc)
    has_changes = False

    for endpoint in endpoints:
        current_status, _, timeout_seconds, lag_seconds = compute_endpoint_activity(
            last_seen=endpoint.last_seen,
            expected_interval_seconds=endpoint.expected_interval_seconds,
            grace_multiplier=endpoint.activity_grace_multiplier,
            now=now,
        )
        previous_status = endpoint.last_activity_status or "unknown"
        if previous_status == "active" and current_status == "inactive":
            latest_record = db.scalar(
                select(TelemetryRecord)
                .where(TelemetryRecord.endpoint_ref == endpoint.id)
                .order_by(desc(TelemetryRecord.collected_at))
            )
            telemetry_payload = latest_record.raw_payload if latest_record else None
            create_lifecycle_event(
                db=db,
                endpoint=endpoint,
                event_type=EVENT_ACTIVE_TO_INACTIVE,
                previous_status=previous_status,
                current_status=current_status,
                details={
                    "expected_interval_seconds": endpoint.expected_interval_seconds,
                    "activity_grace_multiplier": endpoint.activity_grace_multiplier,
                    "activity_timeout_seconds": timeout_seconds,
                    "seconds_since_seen": lag_seconds,
                    "source_ip": endpoint.last_source_ip,
                    "reported_ipv4": endpoint.last_ipv4,
                    "endpoint_ip": endpoint.last_source_ip or endpoint.last_ipv4,
                },
                telemetry_payload=telemetry_payload,
                logger=logger,
            )
            has_changes = True

        if endpoint.last_activity_status != current_status:
            endpoint.last_activity_status = current_status
            has_changes = True

    if has_changes:
        db.commit()
