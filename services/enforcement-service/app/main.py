from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import requests
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.adapters import build_registry
from app.adapters.fortigate import FortiGateAdapter
from app.config import DEFAULT_ADAPTER, HTTP_TIMEOUT_SECONDS
from app.db import Base, engine, get_db
from app.models import (
    AdapterConfigModel,
    AuditEventModel,
    EnforcementRecordModel,
    IpGroupMemberModel,
    IpGroupModel,
    IpObjectModel,
)
from app.object_store import (
    add_object_to_group,
    ensure_ip_group,
    ensure_ip_object,
    find_group_by_name,
    find_ip_host_object,
    find_object_by_id,
    list_group_host_ips,
    remove_object_from_group,
)
from app.schemas import (
    AdapterHealthResponse,
    AdapterConfigResponse,
    AdapterConfigUpsert,
    AuditEvent,
    IpAddressMembershipRequest,
    IpGroupCreate,
    IpGroupMemberAddRequest,
    IpGroupResponse,
    IpGroupUpdate,
    IpObjectCreate,
    IpObjectResponse,
    IpObjectUpdate,
)
from posture_shared.models.enforcement import EnforcementAction, EnforcementResult
from posture_shared.models.evaluation import ComplianceDecision


Base.metadata.create_all(bind=engine)
app = FastAPI(title="enforcement-service", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
registry = build_registry()
fortigate_adapter = FortiGateAdapter()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def store_audit_event(db: Session, event_type: str, endpoint_id: str | None, payload: dict) -> None:
    db.add(AuditEventModel(event_type=event_type, endpoint_id=endpoint_id, payload=payload))


def _short_error_message(exc: Exception) -> str:
    text = str(exc).strip()
    if len(text) > 240:
        return f"{text[:237]}..."
    return text or "Unknown adapter error"


def probe_adapter_health(item: AdapterConfigModel) -> AdapterHealthResponse:
    if not item.is_active:
        return AdapterHealthResponse(
            name=item.name,
            adapter=item.adapter,
            is_active=False,
            status="disabled",
            detail="Profile is disabled",
        )

    if item.adapter == "fortigate":
        settings = fortigate_adapter.build_settings(adapter_settings=item.settings or {})
        # Health probes should be fast and non-blocking for the UI.
        # Do not let per-profile enforcement retry/timeout values stall the dashboard.
        settings["retries"] = 1
        settings["timeout"] = min(float(settings.get("timeout", 5.0)), 3.0)
        try:
            details = fortigate_adapter.check_connection(settings)
            version = details.get("version")
            detail = "Connected to FortiGate API"
            if version:
                detail = f"{detail} (version {version})"
            return AdapterHealthResponse(
                name=item.name,
                adapter=item.adapter,
                is_active=True,
                status="healthy",
                detail=detail,
            )
        except requests.RequestException as exc:
            detail = _short_error_message(exc)
            base_url = str(settings.get("base_url") or "")
            if base_url.startswith("https://"):
                http_settings = dict(settings)
                http_settings["base_url"] = base_url.replace("https://", "http://", 1)
                try:
                    http_details = fortigate_adapter.check_connection(http_settings)
                    detail = (
                        f"HTTPS failed, but HTTP works at {http_settings['base_url']}. "
                        f"Use base URL '{http_settings['base_url']}'. "
                        f"Detected FortiGate version {http_details.get('version') or 'unknown'}."
                    )
                except requests.RequestException:
                    pass
            return AdapterHealthResponse(
                name=item.name,
                adapter=item.adapter,
                is_active=True,
                status="error",
                detail=detail,
            )

    return AdapterHealthResponse(
        name=item.name,
        adapter=item.adapter,
        is_active=item.is_active,
        status="unknown",
        detail=f"No health probe implemented for adapter '{item.adapter}'",
    )


def to_ip_object_response(item: IpObjectModel) -> IpObjectResponse:
    return IpObjectResponse(
        object_id=item.object_id,
        name=item.name,
        object_type=item.object_type,
        value=item.value,
        description=item.description,
        managed_by=item.managed_by,
        created_at=item.created_at,
        updated_at=item.updated_at,
        group_count=len(item.memberships),
    )


def to_ip_group_response(item: IpGroupModel) -> IpGroupResponse:
    member_object_ids = [member.ip_object.object_id for member in item.members]
    return IpGroupResponse(
        group_id=item.group_id,
        name=item.name,
        description=item.description,
        created_at=item.created_at,
        updated_at=item.updated_at,
        member_count=len(member_object_ids),
        member_object_ids=member_object_ids,
    )


def resolve_adapter_settings(db: Session, adapter: str, adapter_profile: str | None) -> tuple[str | None, dict]:
    query = select(AdapterConfigModel).where(
        AdapterConfigModel.adapter == adapter,
        AdapterConfigModel.is_active.is_(True),
    )
    if adapter_profile:
        query = query.where(AdapterConfigModel.name == adapter_profile)
    query = query.order_by(AdapterConfigModel.id.asc())
    config = db.scalar(query)
    if config is None:
        return None, {}
    return config.name, config.settings or {}


def resolve_event_url(base_url: str, endpoint_path: str) -> str:
    path = endpoint_path.strip()
    if path.startswith("http://") or path.startswith("https://"):
        return path
    parsed = urlparse(base_url)
    if parsed.scheme and parsed.netloc:
        return f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    return path


def render_templates(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, str):
        rendered = value
        for key, item_value in context.items():
            rendered = rendered.replace(f"{{{key}}}", "" if item_value is None else str(item_value))
        return rendered
    if isinstance(value, dict):
        return {key: render_templates(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [render_templates(item, context) for item in value]
    return value


def persist_enforcement_result(db: Session, result: EnforcementResult) -> None:
    db.add(
        EnforcementRecordModel(
            endpoint_id=result.endpoint_id,
            adapter=result.adapter,
            action=result.action,
            status=result.status,
            details=result.details,
        )
    )


def execute_policy_plan(decision: ComplianceDecision, db: Session) -> list[dict]:
    plan = decision.execution_plan or {}
    actions = plan.get("actions", [])
    if not isinstance(actions, list) or not actions:
        return []

    adapter_name = str(plan.get("adapter") or DEFAULT_ADAPTER)
    adapter_profile = plan.get("adapter_profile")
    default_group_name = plan.get("object_group")
    context = {
        "endpoint_id": decision.endpoint_id,
        "endpoint_ip": decision.endpoint_ip or "",
        "policy_id": decision.policy_id or "",
        "policy_name": decision.policy_name or "",
        "object_group": default_group_name or "",
    }

    results: list[dict] = []

    for raw_action in actions:
        if not isinstance(raw_action, dict):
            continue
        if raw_action.get("enabled") is False:
            continue

        action_type = str(raw_action.get("action_type", "")).strip()
        parameters = raw_action.get("parameters", {})
        if not isinstance(parameters, dict):
            parameters = {}
        rendered_parameters = render_templates(parameters, context)
        group_name = rendered_parameters.get("group_name") or default_group_name

        if action_type == "object.add_ip_to_group":
            if not decision.endpoint_ip:
                results.append({"action_type": action_type, "status": "skipped", "message": "endpoint_ip is missing"})
                continue
            if not group_name:
                results.append({"action_type": action_type, "status": "failed", "message": "group_name is missing"})
                continue

            object_name = rendered_parameters.get("object_name") or f"endpoint-{decision.endpoint_id}"
            group = ensure_ip_group(db, group_name)
            ip_object = ensure_ip_object(
                db=db,
                name=str(object_name),
                object_type="host",
                value=decision.endpoint_ip,
                description=f"Auto-managed for endpoint {decision.endpoint_id}",
                managed_by="policy",
            )
            added = add_object_to_group(db=db, group=group, ip_object=ip_object)
            payload = {
                "action_type": action_type,
                "status": "success",
                "group_name": group.name,
                "object_id": ip_object.object_id,
                "operation": "added" if added else "already_present",
            }
            store_audit_event(db, "endpoint.policy_action.executed", decision.endpoint_id, payload)
            results.append(payload)
            continue

        if action_type == "object.remove_ip_from_group":
            if not decision.endpoint_ip:
                results.append({"action_type": action_type, "status": "skipped", "message": "endpoint_ip is missing"})
                continue
            if not group_name:
                results.append({"action_type": action_type, "status": "failed", "message": "group_name is missing"})
                continue

            group = find_group_by_name(db, str(group_name))
            if group is None:
                payload = {
                    "action_type": action_type,
                    "status": "skipped",
                    "group_name": group_name,
                    "message": "group not found",
                }
                store_audit_event(db, "endpoint.policy_action.executed", decision.endpoint_id, payload)
                results.append(payload)
                continue

            ip_object = find_ip_host_object(db, decision.endpoint_ip)
            if ip_object is None:
                payload = {
                    "action_type": action_type,
                    "status": "skipped",
                    "group_name": group_name,
                    "message": "ip object not found",
                }
                store_audit_event(db, "endpoint.policy_action.executed", decision.endpoint_id, payload)
                results.append(payload)
                continue

            removed = remove_object_from_group(db=db, group=group, ip_object=ip_object)
            payload = {
                "action_type": action_type,
                "status": "success",
                "group_name": group.name,
                "object_id": ip_object.object_id,
                "operation": "removed" if removed else "already_absent",
            }
            store_audit_event(db, "endpoint.policy_action.executed", decision.endpoint_id, payload)
            results.append(payload)
            continue

        if action_type in {"adapter.add_ip_to_group", "adapter.remove_ip_from_group", "adapter.sync_group"}:
            if not decision.endpoint_ip and action_type != "adapter.sync_group":
                results.append({"action_type": action_type, "status": "skipped", "message": "endpoint_ip is missing"})
                continue

            selected_adapter = str(rendered_parameters.get("adapter") or adapter_name)
            selected_profile = rendered_parameters.get("adapter_profile") or adapter_profile
            profile_name, settings = resolve_adapter_settings(db, selected_adapter, selected_profile)
            if profile_name is None and selected_profile:
                results.append(
                    {
                        "action_type": action_type,
                        "status": "failed",
                        "message": f"adapter profile '{selected_profile}' not found or inactive",
                    }
                )
                continue

            adapter_action = "quarantine"
            if action_type == "adapter.remove_ip_from_group":
                adapter_action = "remove_from_group"
            elif action_type == "adapter.sync_group":
                adapter_action = "sync_group"

            decision_payload: dict[str, Any] = {
                "policy_id": decision.policy_id,
                "policy_name": decision.policy_name,
                "adapter_settings": settings,
            }
            if adapter_action == "sync_group":
                if not group_name:
                    results.append({"action_type": action_type, "status": "failed", "message": "group_name is missing"})
                    continue
                group = find_group_by_name(db, str(group_name))
                decision_payload["group_ips"] = [] if group is None else list_group_host_ips(db, group)

            action = EnforcementAction(
                adapter=selected_adapter,
                action=adapter_action,
                endpoint_id=decision.endpoint_id,
                ip_address=decision.endpoint_ip or "0.0.0.0",
                group_name=str(group_name) if group_name else None,
                adapter_profile=profile_name,
                decision=decision_payload,
            )
            try:
                enforcement_result = registry.execute(action)
                persist_enforcement_result(db, enforcement_result)
                payload = {
                    "action_type": action_type,
                    "status": enforcement_result.status,
                    "adapter": selected_adapter,
                    "adapter_profile": profile_name,
                    "group_name": group_name,
                    "details": enforcement_result.details,
                }
            except Exception as exc:  # pragma: no cover - defensive guard
                payload = {
                    "action_type": action_type,
                    "status": "failed",
                    "adapter": selected_adapter,
                    "adapter_profile": profile_name,
                    "group_name": group_name,
                    "message": f"adapter execution crashed: {exc}",
                }
            store_audit_event(db, "endpoint.policy_action.executed", decision.endpoint_id, payload)
            results.append(payload)
            continue

        if action_type == "adapter.post_event":
            selected_adapter = str(rendered_parameters.get("adapter") or adapter_name)
            selected_profile = rendered_parameters.get("adapter_profile") or adapter_profile
            profile_name, settings = resolve_adapter_settings(db, selected_adapter, selected_profile)
            if profile_name is None and selected_profile:
                results.append(
                    {
                        "action_type": action_type,
                        "status": "failed",
                        "message": f"adapter profile '{selected_profile}' not found or inactive",
                    }
                )
                continue

            endpoint_path = str(rendered_parameters.get("path") or "").strip()
            if not endpoint_path:
                results.append({"action_type": action_type, "status": "failed", "message": "path is required"})
                continue

            base_url = str(settings.get("base_url") or "")
            target_url = resolve_event_url(base_url, endpoint_path)
            method = str(rendered_parameters.get("method") or "POST").upper()
            timeout = float(rendered_parameters.get("timeout_seconds", settings.get("timeout_seconds", HTTP_TIMEOUT_SECONDS)))
            headers = rendered_parameters.get("headers") if isinstance(rendered_parameters.get("headers"), dict) else {}
            token = settings.get("token")
            if token and "Authorization" not in headers:
                headers["Authorization"] = f"Bearer {token}"

            payload_body: dict[str, Any] = {
                "event": "policy.compliant" if decision.compliant else "policy.non_compliant",
                "endpoint_id": decision.endpoint_id,
                "endpoint_ip": decision.endpoint_ip,
                "policy_id": decision.policy_id,
                "policy_name": decision.policy_name,
                "recommended_action": decision.recommended_action,
                "reasons": [reason.model_dump(mode="json") for reason in decision.reasons],
            }
            extra_body = rendered_parameters.get("body")
            if isinstance(extra_body, dict):
                payload_body.update(extra_body)

            try:
                response = requests.request(
                    method=method,
                    url=target_url,
                    headers=headers,
                    json=payload_body,
                    timeout=timeout,
                )
                payload = {
                    "action_type": action_type,
                    "status": "success" if response.status_code < 400 else "failed",
                    "adapter": selected_adapter,
                    "adapter_profile": profile_name,
                    "url": target_url,
                    "http_status": response.status_code,
                    "response_excerpt": response.text[:500],
                }
                if response.status_code >= 400:
                    payload["message"] = "Adapter event POST returned an error status"
            except requests.RequestException as exc:
                payload = {
                    "action_type": action_type,
                    "status": "failed",
                    "adapter": selected_adapter,
                    "adapter_profile": profile_name,
                    "url": target_url,
                    "message": str(exc),
                }

            store_audit_event(db, "endpoint.policy_action.executed", decision.endpoint_id, payload)
            results.append(payload)
            continue

        if action_type in {"http.get", "http.post"}:
            url = rendered_parameters.get("url")
            if not url:
                results.append({"action_type": action_type, "status": "failed", "message": "url is required"})
                continue

            method = "GET" if action_type == "http.get" else "POST"
            headers = rendered_parameters.get("headers") if isinstance(rendered_parameters.get("headers"), dict) else {}
            body = rendered_parameters.get("body") if isinstance(rendered_parameters.get("body"), dict) else None
            timeout = float(rendered_parameters.get("timeout_seconds", HTTP_TIMEOUT_SECONDS))
            try:
                response = requests.request(
                    method=method,
                    url=str(url),
                    headers=headers,
                    json=body,
                    timeout=timeout,
                )
                payload = {
                    "action_type": action_type,
                    "status": "success" if response.status_code < 400 else "failed",
                    "http_status": response.status_code,
                    "url": url,
                    "response_excerpt": response.text[:500],
                }
                if response.status_code >= 400:
                    payload["message"] = "HTTP request returned an error status"
            except requests.RequestException as exc:
                payload = {
                    "action_type": action_type,
                    "status": "failed",
                    "url": url,
                    "message": str(exc),
                }

            store_audit_event(db, "endpoint.policy_action.executed", decision.endpoint_id, payload)
            results.append(payload)
            continue

        results.append(
            {
                "action_type": action_type,
                "status": "failed",
                "message": f"unsupported action_type '{action_type}'",
            }
        )

    return results


def fallback_quarantine(decision: ComplianceDecision, db: Session) -> EnforcementResult:
    if decision.endpoint_ip is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Compliance decision does not include an endpoint IP address",
        )

    action = EnforcementAction(
        adapter=DEFAULT_ADAPTER,
        action="quarantine",
        endpoint_id=decision.endpoint_id,
        ip_address=decision.endpoint_ip,
        decision=decision.model_dump(mode="json"),
    )
    result = registry.execute(action)
    persist_enforcement_result(db, result)
    event_type = "endpoint.quarantined" if result.status == "success" else "endpoint.quarantine_failed"
    store_audit_event(db, event_type, decision.endpoint_id, result.model_dump(mode="json"))
    return result


@app.get("/healthz")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/decisions")
def handle_decision(decision: ComplianceDecision, db: Session = Depends(get_db)) -> dict:
    store_audit_event(db, "endpoint.evaluated", decision.endpoint_id, decision.model_dump(mode="json"))
    if decision.compliant:
        store_audit_event(
            db,
            "endpoint.compliant",
            decision.endpoint_id,
            {"message": "Endpoint evaluated as compliant"},
        )
    else:
        store_audit_event(db, "endpoint.non_compliant", decision.endpoint_id, decision.model_dump(mode="json"))

    execution_results = execute_policy_plan(decision, db)
    action_taken = any(item.get("status") == "success" for item in execution_results)

    fallback_result: dict | None = None
    if (
        not decision.compliant
        and decision.recommended_action == "quarantine"
        and not execution_results
    ):
        result = fallback_quarantine(decision, db)
        action_taken = action_taken or result.status == "success"
        fallback_result = result.model_dump(mode="json")

    db.commit()
    response = {
        "status": "logged",
        "action_taken": action_taken,
        "execution_results": execution_results,
    }
    if fallback_result is not None:
        response["fallback_result"] = fallback_result
    return response


@app.post("/actions", response_model=EnforcementResult)
def run_action(action: EnforcementAction, db: Session = Depends(get_db)) -> EnforcementResult:
    result = registry.execute(action)
    persist_enforcement_result(db, result)
    store_audit_event(db, "endpoint.action.requested", action.endpoint_id, action.model_dump(mode="json"))
    db.commit()
    return result


@app.get("/enforcement/{endpoint_id}/latest", response_model=EnforcementResult)
def latest_enforcement(endpoint_id: str, db: Session = Depends(get_db)) -> EnforcementResult:
    record = db.scalar(
        select(EnforcementRecordModel)
        .where(EnforcementRecordModel.endpoint_id == endpoint_id)
        .order_by(desc(EnforcementRecordModel.created_at))
    )
    if record is None:
        raise HTTPException(status_code=404, detail="No enforcement record found")
    return EnforcementResult(
        adapter=record.adapter,
        action=record.action,
        endpoint_id=record.endpoint_id,
        status=record.status,
        details=record.details,
        completed_at=record.created_at,
    )


@app.get("/audit-events", response_model=list[AuditEvent])
def list_audit_events(db: Session = Depends(get_db)) -> list[AuditEvent]:
    events = db.scalars(select(AuditEventModel).order_by(desc(AuditEventModel.created_at)).limit(200)).all()
    return [
        AuditEvent(
            event_type=item.event_type,
            endpoint_id=item.endpoint_id,
            payload=item.payload,
            created_at=item.created_at,
        )
        for item in events
    ]


@app.get("/adapters", response_model=list[AdapterConfigResponse])
def list_adapters(db: Session = Depends(get_db)) -> list[AdapterConfigResponse]:
    items = db.scalars(select(AdapterConfigModel).order_by(AdapterConfigModel.name)).all()
    return [AdapterConfigResponse.model_validate(item) for item in items]


@app.get("/adapters/health", response_model=list[AdapterHealthResponse])
def list_adapter_health(db: Session = Depends(get_db)) -> list[AdapterHealthResponse]:
    items = db.scalars(select(AdapterConfigModel).order_by(AdapterConfigModel.name)).all()
    return [probe_adapter_health(item) for item in items]


@app.get("/adapters/{name}/health", response_model=AdapterHealthResponse)
def adapter_health(name: str, db: Session = Depends(get_db)) -> AdapterHealthResponse:
    item = db.scalar(select(AdapterConfigModel).where(AdapterConfigModel.name == name))
    if item is None:
        raise HTTPException(status_code=404, detail="Adapter config not found")
    return probe_adapter_health(item)


@app.put("/adapters/{name}", response_model=AdapterConfigResponse)
def upsert_adapter(
    name: str,
    payload: AdapterConfigUpsert,
    db: Session = Depends(get_db),
) -> AdapterConfigResponse:
    item = db.scalar(select(AdapterConfigModel).where(AdapterConfigModel.name == name))
    if item is None:
        item = AdapterConfigModel(
            name=name,
            adapter=payload.adapter or "fortigate",
            is_active=True if payload.is_active is None else payload.is_active,
            settings=payload.settings or {},
        )
        db.add(item)
        db.commit()
        db.refresh(item)
        return AdapterConfigResponse.model_validate(item)

    if payload.adapter is not None:
        item.adapter = payload.adapter
    if payload.is_active is not None:
        item.is_active = payload.is_active
    if payload.settings is not None:
        item.settings = payload.settings
    item.updated_at = utcnow()
    db.commit()
    db.refresh(item)
    return AdapterConfigResponse.model_validate(item)


@app.delete("/adapters/{name}", status_code=status.HTTP_204_NO_CONTENT)
def delete_adapter(name: str, db: Session = Depends(get_db)) -> None:
    item = db.scalar(select(AdapterConfigModel).where(AdapterConfigModel.name == name))
    if item is None:
        raise HTTPException(status_code=404, detail="Adapter config not found")
    db.delete(item)
    db.commit()


@app.get("/objects/ip-objects", response_model=list[IpObjectResponse])
def list_ip_objects(db: Session = Depends(get_db)) -> list[IpObjectResponse]:
    items = db.scalars(select(IpObjectModel).order_by(IpObjectModel.name)).all()
    return [to_ip_object_response(item) for item in items]


@app.post("/objects/ip-objects", response_model=IpObjectResponse, status_code=status.HTTP_201_CREATED)
def create_ip_object(payload: IpObjectCreate, db: Session = Depends(get_db)) -> IpObjectResponse:
    if payload.object_type not in {"host", "cidr"}:
        raise HTTPException(status_code=422, detail="object_type must be 'host' or 'cidr'")
    existing_name = db.scalar(select(IpObjectModel).where(IpObjectModel.name == payload.name.strip()))
    if existing_name is not None:
        raise HTTPException(status_code=409, detail="An IP object with this name already exists")

    item = IpObjectModel(
        object_id=f"ipobj-{uuid4().hex[:10]}",
        name=payload.name.strip(),
        object_type=payload.object_type,
        value=payload.value.strip(),
        description=payload.description,
        managed_by="manual",
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return to_ip_object_response(item)


@app.put("/objects/ip-objects/{object_id}", response_model=IpObjectResponse)
def update_ip_object(object_id: str, payload: IpObjectUpdate, db: Session = Depends(get_db)) -> IpObjectResponse:
    item = find_object_by_id(db, object_id)
    if item is None:
        raise HTTPException(status_code=404, detail="IP object not found")
    if payload.object_type and payload.object_type not in {"host", "cidr"}:
        raise HTTPException(status_code=422, detail="object_type must be 'host' or 'cidr'")

    if payload.name is not None:
        item.name = payload.name.strip()
    if payload.object_type is not None:
        item.object_type = payload.object_type
    if payload.value is not None:
        item.value = payload.value.strip()
    if payload.description is not None:
        item.description = payload.description
    item.updated_at = utcnow()
    db.commit()
    db.refresh(item)
    return to_ip_object_response(item)


@app.delete("/objects/ip-objects/{object_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_ip_object(object_id: str, db: Session = Depends(get_db)) -> None:
    item = find_object_by_id(db, object_id)
    if item is None:
        raise HTTPException(status_code=404, detail="IP object not found")
    db.delete(item)
    db.commit()


@app.get("/objects/ip-groups", response_model=list[IpGroupResponse])
def list_ip_groups(db: Session = Depends(get_db)) -> list[IpGroupResponse]:
    items = db.scalars(select(IpGroupModel).order_by(IpGroupModel.name)).all()
    return [to_ip_group_response(item) for item in items]


@app.post("/objects/ip-groups", response_model=IpGroupResponse, status_code=status.HTTP_201_CREATED)
def create_ip_group(payload: IpGroupCreate, db: Session = Depends(get_db)) -> IpGroupResponse:
    existing = find_group_by_name(db, payload.name.strip())
    if existing is not None:
        raise HTTPException(status_code=409, detail="An IP group with this name already exists")
    group = ensure_ip_group(db, payload.name.strip(), payload.description)
    db.commit()
    db.refresh(group)
    return to_ip_group_response(group)


@app.put("/objects/ip-groups/{group_id}", response_model=IpGroupResponse)
def update_ip_group(group_id: str, payload: IpGroupUpdate, db: Session = Depends(get_db)) -> IpGroupResponse:
    group = db.scalar(select(IpGroupModel).where(IpGroupModel.group_id == group_id))
    if group is None:
        raise HTTPException(status_code=404, detail="IP group not found")
    if payload.name is not None:
        group.name = payload.name.strip()
    if payload.description is not None:
        group.description = payload.description
    group.updated_at = utcnow()
    db.commit()
    db.refresh(group)
    return to_ip_group_response(group)


@app.delete("/objects/ip-groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_ip_group(group_id: str, db: Session = Depends(get_db)) -> None:
    group = db.scalar(select(IpGroupModel).where(IpGroupModel.group_id == group_id))
    if group is None:
        raise HTTPException(status_code=404, detail="IP group not found")
    db.delete(group)
    db.commit()


@app.post("/objects/ip-groups/{group_name}/members", response_model=IpGroupResponse)
def add_group_member(group_name: str, payload: IpGroupMemberAddRequest, db: Session = Depends(get_db)) -> IpGroupResponse:
    group = find_group_by_name(db, group_name)
    if group is None:
        raise HTTPException(status_code=404, detail="IP group not found")
    ip_object = find_object_by_id(db, payload.object_id)
    if ip_object is None:
        raise HTTPException(status_code=404, detail="IP object not found")
    add_object_to_group(db=db, group=group, ip_object=ip_object)
    db.commit()
    db.refresh(group)
    return to_ip_group_response(group)


@app.post("/objects/ip-groups/{group_name}/members/ip", response_model=IpGroupResponse)
def add_ip_address_to_group(group_name: str, payload: IpAddressMembershipRequest, db: Session = Depends(get_db)) -> IpGroupResponse:
    group = ensure_ip_group(db, group_name)
    object_name = f"endpoint-{payload.endpoint_id}" if payload.endpoint_id else f"ip-{payload.ip_address.replace('.', '-')}"
    ip_object = ensure_ip_object(
        db=db,
        name=object_name,
        object_type="host",
        value=payload.ip_address,
        description=f"Managed by {payload.managed_by}",
        managed_by=payload.managed_by,
    )
    add_object_to_group(db=db, group=group, ip_object=ip_object)
    db.commit()
    db.refresh(group)
    return to_ip_group_response(group)


@app.delete("/objects/ip-groups/{group_name}/members/ip/{ip_address}", response_model=IpGroupResponse)
def remove_ip_address_from_group(group_name: str, ip_address: str, db: Session = Depends(get_db)) -> IpGroupResponse:
    group = find_group_by_name(db, group_name)
    if group is None:
        raise HTTPException(status_code=404, detail="IP group not found")
    ip_object = find_ip_host_object(db, ip_address)
    if ip_object is not None:
        remove_object_from_group(db=db, group=group, ip_object=ip_object)
    db.commit()
    db.refresh(group)
    return to_ip_group_response(group)


@app.delete("/objects/ip-groups/{group_name}/members/{object_id}", response_model=IpGroupResponse)
def remove_group_member(group_name: str, object_id: str, db: Session = Depends(get_db)) -> IpGroupResponse:
    group = find_group_by_name(db, group_name)
    if group is None:
        raise HTTPException(status_code=404, detail="IP group not found")
    ip_object = find_object_by_id(db, object_id)
    if ip_object is None:
        raise HTTPException(status_code=404, detail="IP object not found")
    remove_object_from_group(db=db, group=group, ip_object=ip_object)
    db.commit()
    db.refresh(group)
    return to_ip_group_response(group)
