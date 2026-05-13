from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from datetime import datetime, timezone
import ipaddress
import logging
import os
import re
import threading
import time
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import requests
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import desc, select, text
from sqlalchemy.orm import Session, selectinload

from app.adapters import build_registry
from app.adapters.fortigate import FortiGateAdapter
from app.adapters.palo_alto import PaloAltoAdapter
from app.config import DEFAULT_ADAPTER, HTTP_CONNECT_TIMEOUT_SECONDS, HTTP_READ_TIMEOUT_SECONDS, HTTP_TIMEOUT_SECONDS
from app.config import (
    ADAPTER_TOKEN_MASK,
    ALLOW_POLICY_HTTP_ACTIONS,
    ALLOW_PRIVATE_HTTP_TARGETS,
    ASYNC_DECISION_EXECUTION,
    BACKGROUND_WORKERS,
    HTTP_CIRCUIT_BREAKER_COOLDOWN_SECONDS,
    HTTP_CIRCUIT_BREAKER_THRESHOLD,
    INTER_SERVICE_API_KEY,
    POLICY_HTTP_ALLOWED_HOSTS,
)
from app.db import Base, SessionLocal, engine, get_db
from app.models import (
    AdapterConfigModel,
    AuditEventModel,
    BackgroundJobModel,
    EnforcementRecordModel,
    IpGroupMemberModel,
    IpGroupModel,
    IpObjectModel,
)
from app.object_store import (
    add_object_to_group,
    ensure_ip_group,
    ensure_ip_object,
    find_group_by_id,
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
    BackgroundJobResponse,
    IpAddressMembershipRequest,
    EndpointCleanupRequest,
    IpGroupCreate,
    IpGroupMemberAddRequest,
    IpGroupResponse,
    IpGroupUpdate,
    ManualGroupMemberResponse,
    PolicyCleanupRequest,
    IpObjectCreate,
    IpObjectResponse,
    IpObjectUpdate,
)
from posture_shared.models.enforcement import EnforcementAction, EnforcementResult
from posture_shared.models.evaluation import ComplianceDecision
from posture_shared.security import parse_cors_origins, require_api_key


Base.metadata.create_all(bind=engine)


def ensure_performance_indexes() -> None:
    statements = [
        "CREATE INDEX IF NOT EXISTS idx_enforcement_records_endpoint_created ON enforcement_records(endpoint_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_audit_events_endpoint_created ON audit_events(endpoint_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_background_jobs_status_created ON background_jobs(status, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_adapter_configs_lookup ON adapter_configs(adapter, is_active, name)",
        "CREATE INDEX IF NOT EXISTS idx_ip_objects_type_value ON ip_objects(object_type, value)",
        "CREATE INDEX IF NOT EXISTS idx_ip_group_members_group_object ON ip_group_members(group_ref, object_ref)",
        "CREATE INDEX IF NOT EXISTS idx_ip_group_members_object_group ON ip_group_members(object_ref, group_ref)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


ensure_performance_indexes()

app = FastAPI(title="enforcement-service", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=parse_cors_origins(),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1200, compresslevel=6)
registry = build_registry()
fortigate_adapter = FortiGateAdapter()
palo_alto_adapter = PaloAltoAdapter()
executor = ThreadPoolExecutor(max_workers=max(1, BACKGROUND_WORKERS))
logger = logging.getLogger("enforcement-service")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)
POLICY_SERVICE_URL = os.getenv("POLICY_SERVICE_URL", "http://127.0.0.1:8002")
_circuit_breaker_lock = threading.Lock()
_circuit_breakers: dict[str, dict[str, float | int]] = {}
_request_rate_lock = threading.Lock()
_request_rate_state: dict[str, list[float]] = {}
_group_operation_locks_guard = threading.Lock()
_group_operation_locks: dict[str, threading.RLock] = {}
ENFORCEMENT_RATE_LIMIT_PER_MINUTE = 240
request_correlation_id: ContextVar[str] = ContextVar("request_correlation_id", default="")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _apply_rate_limit(identity: str) -> None:
    now = time.monotonic()
    with _request_rate_lock:
        history = _request_rate_state.setdefault(identity, [])
        history[:] = [item for item in history if now - item <= 60.0]
        if len(history) >= ENFORCEMENT_RATE_LIMIT_PER_MINUTE:
            raise HTTPException(status_code=429, detail="Too many requests")
        history.append(now)


def _group_operation_lock_key(*parts: str | None) -> str:
    normalized = [str(part or "").strip().lower() for part in parts if str(part or "").strip()]
    return "|".join(normalized) if normalized else "group|default"


def _get_group_operation_lock(*parts: str | None) -> threading.RLock:
    key = _group_operation_lock_key(*parts)
    with _group_operation_locks_guard:
        lock = _group_operation_locks.get(key)
        if lock is None:
            lock = threading.RLock()
            _group_operation_locks[key] = lock
        return lock


@app.middleware("http")
async def request_observability_middleware(request, call_next):
    request_id = request.headers.get("X-Request-ID", "").strip() or str(uuid4())
    context_token = request_correlation_id.set(request_id)
    started_at = time.perf_counter()
    try:
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - started_at) * 1000
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "request_id=%s method=%s path=%s status=%s duration_ms=%.2f",
            request_id,
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )
        return response
    finally:
        request_correlation_id.reset(context_token)


def sanitize_sensitive_payload(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            if key.lower() in SENSITIVE_SETTING_KEYS and item:
                sanitized[key] = ADAPTER_TOKEN_MASK
            else:
                sanitized[key] = sanitize_sensitive_payload(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_sensitive_payload(item) for item in value]
    return value


def store_audit_event(db: Session, event_type: str, endpoint_id: str | None, payload: dict) -> None:
    payload_with_correlation = dict(payload)
    payload_with_correlation.setdefault("correlation_id", request_correlation_id.get())
    db.add(
        AuditEventModel(
            event_type=event_type,
            endpoint_id=endpoint_id,
            payload=sanitize_sensitive_payload(payload_with_correlation),
        )
    )


def _inter_service_headers() -> dict[str, str]:
    if not INTER_SERVICE_API_KEY:
        return {}
    return {"X-API-Key": INTER_SERVICE_API_KEY}


def _short_error_message(exc: Exception) -> str:
    text = _redact_sensitive_error_text(str(exc).strip())
    if len(text) > 240:
        return f"{text[:237]}..."
    return text or "Unknown adapter error"


def _string_excerpt(value: Any, max_length: int = 600) -> str:
    rendered = str(value) if value is not None else ""
    if len(rendered) <= max_length:
        return rendered
    return f"{rendered[: max_length - 3]}..."


def log_policy_http_action_result(
    *,
    action_type: str,
    endpoint_id: str,
    method: str,
    url: str,
    status: str,
    http_status: int | None = None,
    request_body: Any = None,
    response_excerpt: str | None = None,
    error_message: str | None = None,
) -> None:
    sanitized_body = sanitize_sensitive_payload(request_body) if request_body is not None else None
    level = logging.INFO if status == "success" else logging.WARNING
    logger.log(
        level,
        "policy_http_action endpoint_id=%s action=%s method=%s url=%s status=%s http_status=%s error=%s request_body=%s response_excerpt=%s",
        endpoint_id,
        action_type,
        method,
        url,
        status,
        http_status if http_status is not None else "n/a",
        error_message or "",
        _string_excerpt(sanitized_body),
        _string_excerpt(response_excerpt or ""),
    )


SENSITIVE_SETTING_KEYS = {"token", "api_key", "apikey", "secret", "password"}
_SENSITIVE_ERROR_PATTERNS = [
    re.compile(r"([?&](?:key|token|api_key|apikey|password|secret)=)([^&\s]+)", flags=re.IGNORECASE),
    re.compile(r"((?:key|token|api_key|apikey|password|secret)\s*[=:]\s*)([^\s,;]+)", flags=re.IGNORECASE),
]


def _redact_sensitive_error_text(text: str) -> str:
    if not text:
        return text
    redacted = text
    for pattern in _SENSITIVE_ERROR_PATTERNS:
        redacted = pattern.sub(r"\1********", redacted)
    return redacted


def sanitize_adapter_settings(settings: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in settings.items():
        if key.lower() in SENSITIVE_SETTING_KEYS and value:
            sanitized[key] = ADAPTER_TOKEN_MASK
        else:
            sanitized[key] = value
    return sanitized


def normalize_adapter_name(adapter: str | None) -> str:
    normalized = str(adapter or "").strip().lower()
    aliases = {
        "paloalto": "palo_alto",
        "palo-alto": "palo_alto",
    }
    return aliases.get(normalized, normalized or "fortigate")


def preserve_sensitive_settings(current_settings: dict[str, Any], incoming_settings: dict[str, Any]) -> dict[str, Any]:
    merged_settings = {**current_settings, **incoming_settings}
    candidate_keys = {*(str(key) for key in current_settings.keys()), *(str(key) for key in incoming_settings.keys())}
    for key in candidate_keys:
        normalized_key = key.lower()
        if normalized_key not in SENSITIVE_SETTING_KEYS:
            continue
        incoming_value = incoming_settings.get(key)
        if isinstance(incoming_value, str) and (incoming_value.strip() == "" or incoming_value == ADAPTER_TOKEN_MASK):
            merged_settings[key] = current_settings.get(key, "")
    return merged_settings


def validate_palo_alto_settings(settings: dict[str, Any]) -> None:
    group_mappings = settings.get("group_mappings")
    if group_mappings is None:
        return
    if not isinstance(group_mappings, list):
        raise HTTPException(status_code=422, detail="settings.group_mappings must be a list")

    for index, mapping in enumerate(group_mappings):
        if not isinstance(mapping, dict):
            raise HTTPException(status_code=422, detail=f"settings.group_mappings[{index}] must be an object")

        app_group_id = str(mapping.get("app_group_id") or mapping.get("app_group_key") or "").strip()
        app_group_display_name = str(mapping.get("app_group_display_name") or "").strip()
        palo_tag_name = str(mapping.get("palo_tag_name") or "").strip()
        palo_dag_name = mapping.get("palo_dag_name")

        if not app_group_id and not app_group_display_name:
            raise HTTPException(
                status_code=422,
                detail=f"settings.group_mappings[{index}] must include app_group_id or app_group_display_name",
            )
        if not palo_tag_name:
            raise HTTPException(status_code=422, detail=f"settings.group_mappings[{index}] must include palo_tag_name")
        if palo_dag_name is not None and not isinstance(palo_dag_name, str):
            raise HTTPException(status_code=422, detail=f"settings.group_mappings[{index}].palo_dag_name must be a string")


def validate_adapter_settings(adapter: str, settings: dict[str, Any]) -> None:
    _validate_adapter_base_url(settings)
    if normalize_adapter_name(adapter) == "palo_alto":
        validate_palo_alto_settings(settings)


def _is_http_target_allowed(url: str) -> tuple[bool, str | None]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False, "Only http/https URLs are allowed for policy HTTP actions"

    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False, "Target URL host is missing"

    if POLICY_HTTP_ALLOWED_HOSTS and host not in POLICY_HTTP_ALLOWED_HOSTS:
        return False, f"Host '{host}' is not in POLICY_HTTP_ALLOWED_HOSTS"

    if ALLOW_PRIVATE_HTTP_TARGETS:
        return True, None

    blocked_hosts = {"localhost", "127.0.0.1", "::1"}
    if host in blocked_hosts:
        return False, "Loopback/localhost targets are blocked"

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Non-IP hostnames are allowed unless explicit allow-list is set.
        return True, None

    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return False, "Private or local network targets are blocked"
    return True, None


def _validate_adapter_base_url(settings: dict[str, Any]) -> None:
    base_url = str(settings.get("base_url") or "").strip()
    if not base_url:
        return
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=422, detail="settings.base_url must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=422, detail="settings.base_url must not include credentials")


def _circuit_key_for_url(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.scheme}://{host}:{port}"


def _adapter_circuit_key(adapter: str, adapter_profile: str | None) -> str:
    return f"adapter://{normalize_adapter_name(adapter)}/{str(adapter_profile or 'default').strip().lower()}"


def _fast_adapter_timeout() -> tuple[float, float]:
    return (min(HTTP_CONNECT_TIMEOUT_SECONDS, 3.0), min(HTTP_READ_TIMEOUT_SECONDS, 5.0))


def _circuit_is_open(key: str) -> tuple[bool, float]:
    now = time.time()
    with _circuit_breaker_lock:
        state = _circuit_breakers.get(key)
        if not state:
            return False, 0.0
        opened_until = float(state.get("opened_until", 0.0))
        if opened_until > now:
            return True, opened_until
        if opened_until > 0:
            state["opened_until"] = 0.0
            state["failures"] = 0
        return False, 0.0


def _circuit_mark_success(key: str) -> None:
    with _circuit_breaker_lock:
        state = _circuit_breakers.setdefault(key, {"failures": 0, "opened_until": 0.0})
        state["failures"] = 0
        state["opened_until"] = 0.0


def _circuit_mark_failure(key: str) -> None:
    now = time.time()
    with _circuit_breaker_lock:
        state = _circuit_breakers.setdefault(key, {"failures": 0, "opened_until": 0.0})
        failures = int(state.get("failures", 0)) + 1
        state["failures"] = failures
        if failures >= HTTP_CIRCUIT_BREAKER_THRESHOLD:
            state["opened_until"] = now + float(HTTP_CIRCUIT_BREAKER_COOLDOWN_SECONDS)


def probe_adapter_health(item: AdapterConfigModel) -> AdapterHealthResponse:
    adapter_name = normalize_adapter_name(item.adapter)
    if not item.is_active:
        return AdapterHealthResponse(
            name=item.name,
            adapter=adapter_name,
            is_active=False,
            status="disabled",
            detail="Profile is disabled",
        )

    if adapter_name == "fortigate":
        settings = fortigate_adapter.build_settings(adapter_settings=item.settings or {})
        # Health probes should be fast and non-blocking for the UI.
        # Do not let per-profile enforcement retry/timeout values stall the dashboard.
        settings["retries"] = 1
        settings["timeout"] = _fast_adapter_timeout()
        try:
            details = fortigate_adapter.check_connection(settings)
            version = details.get("version")
            detail = "Connected to FortiGate API"
            if version:
                detail = f"{detail} (version {version})"
            return AdapterHealthResponse(
                name=item.name,
                adapter=adapter_name,
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
                adapter=adapter_name,
                is_active=True,
                status="error",
                detail=detail,
            )

    if adapter_name == "palo_alto":
        settings = palo_alto_adapter.build_settings(adapter_settings=item.settings or {})
        settings["retries"] = 1
        settings["timeout"] = _fast_adapter_timeout()
        try:
            details = palo_alto_adapter.check_connection(settings)
            mapping_checks = details.get("mapping_checks", [])
            dag_failures = [
                mapping
                for mapping in mapping_checks
                if mapping.get("palo_dag_name") and mapping.get("dag_exists") is False
            ]
            detail = "Connected to PAN-OS XML API"
            if details.get("hostname"):
                detail = f"{detail} ({details['hostname']})"
            if details.get("sw_version"):
                detail = f"{detail}, PAN-OS {details['sw_version']}"
            if dag_failures:
                missing = ", ".join(str(item.get("palo_dag_name")) for item in dag_failures)
                return AdapterHealthResponse(
                    name=item.name,
                    adapter=adapter_name,
                    is_active=True,
                    status="error",
                    detail=f"{detail}. Missing configured DAGs in {details.get('vsys')}: {missing}",
                )
            mapped_count = len(mapping_checks)
            return AdapterHealthResponse(
                name=item.name,
                adapter=adapter_name,
                is_active=True,
                status="healthy",
                detail=f"{detail}. Validated {mapped_count} Palo Alto group mapping(s) in {details.get('vsys')}.",
            )
        except Exception as exc:
            detail = _short_error_message(exc)
            base_url = str(settings.get("base_url") or "")
            if base_url.startswith("https://"):
                http_settings = dict(settings)
                http_settings["base_url"] = base_url.replace("https://", "http://", 1)
                try:
                    http_details = palo_alto_adapter.check_connection(http_settings)
                    http_detail = "HTTP works for PAN-OS XML API"
                    if http_details.get("hostname"):
                        http_detail = f"{http_detail} ({http_details['hostname']})"
                    if http_details.get("sw_version"):
                        http_detail = f"{http_detail}, PAN-OS {http_details['sw_version']}"
                    return AdapterHealthResponse(
                        name=item.name,
                        adapter=adapter_name,
                        is_active=True,
                        status="error",
                        detail=(
                            f"HTTPS failed, but HTTP works at {http_settings['base_url']}. "
                            f"Use base URL '{http_settings['base_url']}'. {http_detail}."
                        ),
                    )
                except Exception:
                    if "connection reset" in detail.lower() or "connectionreseterror" in detail.lower():
                        detail = (
                            f"{detail}. The firewall reset the HTTPS connection; verify the PAN-OS "
                            "management protocol/port, or try an http:// base URL if HTTPS is disabled."
                        )
            return AdapterHealthResponse(
                name=item.name,
                adapter=adapter_name,
                is_active=True,
                status="error",
                detail=detail,
            )

    return AdapterHealthResponse(
        name=item.name,
        adapter=adapter_name,
        is_active=item.is_active,
        status="unknown",
        detail=f"No health probe implemented for adapter '{adapter_name}'",
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


def to_adapter_config_response(item: AdapterConfigModel) -> AdapterConfigResponse:
    return AdapterConfigResponse(
        id=item.id,
        name=item.name,
        adapter=normalize_adapter_name(item.adapter),
        is_active=item.is_active,
        settings=sanitize_adapter_settings(item.settings or {}),
        created_at=item.created_at,
        updated_at=item.updated_at,
    )


def resolve_adapter_settings(db: Session, adapter: str, adapter_profile: str | None) -> tuple[str | None, dict]:
    normalized_adapter = normalize_adapter_name(adapter)
    query = select(AdapterConfigModel).where(
        AdapterConfigModel.adapter == normalized_adapter,
        AdapterConfigModel.is_active.is_(True),
    )
    if adapter_profile:
        query = query.where(AdapterConfigModel.name == adapter_profile)
    query = query.order_by(AdapterConfigModel.id.asc())
    config = db.scalar(query)
    if config is None and adapter_profile:
        fallback = db.scalar(
            select(AdapterConfigModel)
            .where(
                AdapterConfigModel.name == adapter_profile,
                AdapterConfigModel.is_active.is_(True),
            )
            .order_by(AdapterConfigModel.id.asc())
        )
        if fallback is not None and normalize_adapter_name(fallback.adapter) == normalized_adapter:
            config = fallback
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


def resolve_group_reference(
    *,
    db: Session,
    group_name: str | None,
    group_id: str | None,
) -> IpGroupModel | None:
    if group_id:
        by_id = find_group_by_id(db, str(group_id).strip())
        if by_id is not None:
            return by_id
    if group_name:
        by_name = find_group_by_name(db, str(group_name).strip())
        if by_name is not None:
            return by_name
    return None


def resolve_group_identifier(db: Session, group_identifier: str) -> IpGroupModel | None:
    value = str(group_identifier or "").strip()
    if not value:
        return None
    return resolve_group_reference(db=db, group_name=value, group_id=value)


def build_policy_managed_warning(group: IpGroupModel) -> str | None:
    try:
        response = requests.get(
            f"{POLICY_SERVICE_URL.rstrip('/')}/managed-groups/by-group/{group.group_id}",
            headers=_inter_service_headers(),
            timeout=(1.0, 1.5),
        )
        if response.ok:
            managers = response.json()
            if isinstance(managers, list) and managers:
                names = [
                    str(item.get("policy_name"))
                    for item in managers
                    if isinstance(item, dict) and item.get("policy_name")
                ]
                if names:
                    return (
                        f"Group is managed by policy {', '.join(names)}. "
                        "Manual changes may be overwritten by the next evaluation."
                    )
    except Exception:
        logger.debug("policy-managed warning lookup failed group_id=%s", group.group_id, exc_info=True)

    # Fallback for older MVP databases that do not yet have policy_managed_groups populated.
    if group.name.upper().startswith(("NON_COMPLIANT", "QUARANTINE", "BLOCKED")):
        return (
            f"Group is likely managed by policy automation. Manual changes may be overwritten "
            f"by the next evaluation."
        )
    return None


def manual_member_response(
    *,
    group: IpGroupModel,
    ip_object: IpObjectModel | None,
    operation: str,
    warning: str | None = None,
) -> ManualGroupMemberResponse:
    return ManualGroupMemberResponse(
        operation=operation,
        group=to_ip_group_response(group),
        ip_object=to_ip_object_response(ip_object) if ip_object is not None else None,
        warning=warning,
    )


def _candidate_ip_objects_for_endpoint(
    *,
    db: Session,
    endpoint_id: str,
    ip_address: str | None = None,
) -> list[IpObjectModel]:
    candidates: list[IpObjectModel] = []
    seen: set[int] = set()

    def add_candidate(item: IpObjectModel | None) -> None:
        if item is None or item.id in seen:
            return
        seen.add(item.id)
        candidates.append(item)

    add_candidate(db.scalar(select(IpObjectModel).where(IpObjectModel.name == f"endpoint-{endpoint_id}")))
    if ip_address:
        add_candidate(find_ip_host_object(db, ip_address))
    return candidates


def _cleanup_endpoint_from_groups(
    *,
    db: Session,
    endpoint_id: str,
    ip_address: str | None,
    groups: list[IpGroupModel],
    event_type: str,
    reason: str | None = None,
    policy_id: int | None = None,
    policy_name: str | None = None,
) -> dict[str, Any]:
    candidates = _candidate_ip_objects_for_endpoint(db=db, endpoint_id=endpoint_id, ip_address=ip_address)
    results: list[dict[str, Any]] = []
    for group in groups:
        removed_any = False
        for ip_object in candidates:
            removed = remove_object_from_group(db=db, group=group, ip_object=ip_object)
            removed_any = removed_any or removed
            if removed:
                results.append(
                    {
                        "group_id": group.group_id,
                        "group_name": group.name,
                        "object_id": ip_object.object_id,
                        "ip_address": ip_object.value,
                        "operation": "removed",
                    }
                )
        if not removed_any:
            results.append(
                {
                    "group_id": group.group_id,
                    "group_name": group.name,
                    "operation": "already_absent",
                }
            )
    payload = {
        "endpoint_id": endpoint_id,
        "ip_address": ip_address,
        "policy_id": policy_id,
        "policy_name": policy_name,
        "reason": reason,
        "results": results,
    }
    store_audit_event(db, event_type, endpoint_id, payload)
    return payload


def action_adds_to_gate_group(
    *,
    actions: list[Any],
    context: dict[str, Any],
    default_group_name: str | None,
    gate_group_name: str,
) -> bool:
    normalized_gate_group = gate_group_name.strip().lower()
    if not normalized_gate_group:
        return False
    for raw_action in actions:
        if not isinstance(raw_action, dict) or raw_action.get("enabled") is False:
            continue
        action_type = str(raw_action.get("action_type") or "").strip()
        if action_type not in {"object.add_ip_to_group", "adapter.add_ip_to_group"}:
            continue
        parameters = raw_action.get("parameters", {})
        if not isinstance(parameters, dict):
            parameters = {}
        rendered_parameters = render_templates(parameters, context)
        target_group = str(rendered_parameters.get("group_name") or default_group_name or "").strip().lower()
        if target_group == normalized_gate_group:
            return True
    return False


def append_policy_action_result(
    *,
    db: Session,
    endpoint_id: str,
    results: list[dict],
    payload: dict,
    event_type: str | None = None,
) -> None:
    resolved_event_type = event_type
    if resolved_event_type is None:
        status_value = str(payload.get("status") or "").strip().lower()
        if status_value == "failed":
            resolved_event_type = "endpoint.policy_action.failed"
        elif status_value == "skipped":
            resolved_event_type = "endpoint.policy_action.skipped"
        else:
            resolved_event_type = "endpoint.policy_action.executed"

    payload = {**payload, "event_type": resolved_event_type}
    store_audit_event(db, resolved_event_type, endpoint_id, payload)
    logger.info(
        "policy_action endpoint_id=%s endpoint_ip=%s policy_id=%s policy_name=%s trigger_type=%s group_name=%s event_type=%s action_type=%s operation=%s status=%s reason=%s adapter=%s adapter_profile=%s details=%s",
        endpoint_id,
        payload.get("endpoint_ip"),
        payload.get("policy_id"),
        payload.get("policy_name"),
        payload.get("trigger_type"),
        payload.get("group_name"),
        resolved_event_type,
        payload.get("action_type"),
        payload.get("operation"),
        payload.get("status"),
        payload.get("reason") or payload.get("message"),
        payload.get("adapter"),
        payload.get("adapter_profile"),
        _string_excerpt(payload, 800),
    )
    results.append(payload)


def execute_policy_plan(decision: ComplianceDecision, db: Session) -> list[dict]:
    plan = decision.execution_plan or {}
    actions = plan.get("actions", [])
    if not isinstance(actions, list):
        actions = []
    actions = [action for action in actions if isinstance(action, dict) and action.get("enabled") is not False]

    def enabled_plan_actions(value: Any) -> list[dict]:
        if not isinstance(value, list):
            return []
        return [action for action in value if isinstance(action, dict) and action.get("enabled") is not False]

    on_compliant_actions = enabled_plan_actions(plan.get("on_compliant"))
    on_non_compliant_actions = enabled_plan_actions(plan.get("on_non_compliant"))

    adapter_name = str(plan.get("adapter") or DEFAULT_ADAPTER)
    adapter_profile = plan.get("adapter_profile")
    default_group_name = plan.get("object_group")
    trigger_type = str(plan.get("trigger_type") or decision.trigger_type or "telemetry_received")
    raw_managed_groups = plan.get("managed_groups")
    managed_group_refs: set[str] = set()
    if isinstance(raw_managed_groups, list):
        for item in raw_managed_groups:
            if isinstance(item, dict):
                for value in (item.get("group_id"), item.get("group_name"), item.get("name")):
                    if value and str(value).strip():
                        managed_group_refs.add(str(value).strip().casefold())
            elif item and str(item).strip():
                managed_group_refs.add(str(item).strip().casefold())
    if not managed_group_refs and default_group_name:
        managed_group_refs.add(str(default_group_name).strip().casefold())
    context = {
        "endpoint_id": decision.endpoint_id,
        "endpoint_ip": decision.endpoint_ip or "",
        "policy_id": decision.policy_id or "",
        "policy_name": decision.policy_name or "",
        "object_group": default_group_name or "",
    }
    results: list[dict] = []

    def append_result(payload: dict, event_type: str | None = None) -> None:
        operation = payload.get("operation")
        status_value = str(payload.get("status") or "").strip().lower()
        if not operation and status_value in {"skipped", "failed"}:
            operation = status_value
        enriched_payload = {
            "policy_id": decision.policy_id,
            "policy_name": decision.policy_name,
            "trigger_type": trigger_type,
            "endpoint_ip": decision.endpoint_ip,
            "compliant": decision.compliant,
            "operation": operation,
            "reason": payload.get("reason") or payload.get("message"),
            **payload,
        }
        append_policy_action_result(
            db=db,
            endpoint_id=decision.endpoint_id,
            results=results,
            payload=enriched_payload,
            event_type=event_type,
        )

    def group_is_managed(group_name: Any, group_id: Any = None, resolved_group: IpGroupModel | None = None) -> bool:
        if resolved_group is not None:
            candidates = {resolved_group.group_id, resolved_group.name}
        else:
            candidates = set()
        for value in (group_id, group_name):
            if value and str(value).strip():
                candidates.add(str(value).strip())
        return any(candidate.casefold() in managed_group_refs for candidate in candidates if candidate)

    def append_unmanaged_group_result(action_type: str, group_name: Any, group_id: Any = None) -> None:
        append_result(
            {
                "action_type": action_type,
                "status": "skipped",
                "group_name": str(group_name) if group_name else None,
                "group_id": str(group_id) if group_id else None,
                "message": "Policy is not allowed to manage this group",
            },
            event_type="endpoint.policy_action.skipped",
        )

    policy_branch_actions = [*on_compliant_actions, *on_non_compliant_actions]
    if not actions and not policy_branch_actions:
        return results

    execution_gate = plan.get("execution_gate") if isinstance(plan, dict) else None
    if isinstance(execution_gate, dict):
        ip_group_condition = execution_gate.get("ip_group_condition")
        if isinstance(ip_group_condition, dict) and ip_group_condition.get("enabled"):
            gate_group_name = str(ip_group_condition.get("group_name") or "").strip()
            gate_operator = str(ip_group_condition.get("operator") or "exists in").strip().lower()

            if not gate_group_name:
                payload = {
                    "action_type": "execution_gate.ip_group",
                    "status": "skipped",
                    "message": "Execution gate is enabled but group_name is missing",
                }
                append_result(payload, event_type="endpoint.policy_action.skipped")
                return results

            in_group = False
            group = resolve_group_reference(db=db, group_name=gate_group_name, group_id=None)
            if group is not None and decision.endpoint_ip:
                ip_object = find_ip_host_object(db, decision.endpoint_ip)
                if ip_object is not None:
                    membership = db.scalar(
                        select(IpGroupMemberModel).where(
                            IpGroupMemberModel.group_ref == group.id,
                            IpGroupMemberModel.object_ref == ip_object.id,
                        )
                    )
                    in_group = membership is not None

            gate_passed = in_group
            if gate_operator in {"does not exist in", "does_not_exist_in", "not_in"}:
                gate_passed = not in_group

            if not gate_passed:
                if gate_operator == "exists in" and action_adds_to_gate_group(
                    actions=[*actions, *policy_branch_actions],
                    context=context,
                    default_group_name=default_group_name,
                    gate_group_name=gate_group_name,
                ):
                    append_result(
                        {
                            "action_type": "execution_gate.ip_group",
                            "status": "bypassed",
                            "group_name": gate_group_name,
                            "operator": gate_operator,
                            "endpoint_ip": decision.endpoint_ip,
                            "message": (
                                "Execution gate checks the same group targeted by an add action; "
                                "continuing so policy-managed membership can be reconciled."
                            ),
                        },
                        event_type="endpoint.policy_action.executed",
                    )
                else:
                    payload = {
                        "action_type": "execution_gate.ip_group",
                        "status": "skipped",
                        "group_name": gate_group_name,
                        "operator": gate_operator,
                        "endpoint_ip": decision.endpoint_ip,
                        "message": "Execution gate condition did not match. Policy actions were skipped.",
                    }
                    append_result(payload, event_type="endpoint.policy_action.skipped")
                    return results

    def action_group_key(raw_action: dict) -> str | None:
        parameters = raw_action.get("parameters", {})
        if not isinstance(parameters, dict):
            parameters = {}
        rendered_parameters = render_templates(parameters, context)
        group_id = rendered_parameters.get("group_id")
        group_name = rendered_parameters.get("group_name") or default_group_name
        if group_id and str(group_id).strip():
            return f"id:{str(group_id).strip().casefold()}"
        if group_name and str(group_name).strip():
            return f"name:{str(group_name).strip().casefold()}"
        return None

    def reconcile_group_membership(raw_action: dict, desired_present: bool) -> str | None:
        action_type = str(raw_action.get("action_type", "")).strip()
        if action_type != "object.add_ip_to_group":
            return None
        parameters = raw_action.get("parameters", {})
        if not isinstance(parameters, dict):
            parameters = {}
        rendered_parameters = render_templates(parameters, context)
        group_name = rendered_parameters.get("group_name") or default_group_name
        group_id = rendered_parameters.get("group_id")
        action_key = action_group_key(raw_action)
        resolved_group = resolve_group_reference(
            db=db,
            group_name=str(group_name) if group_name else None,
            group_id=str(group_id) if group_id else None,
        )
        if resolved_group is not None:
            group_name = resolved_group.name

        def append_reconcile(payload: dict, event_suffix: str) -> None:
            append_result(payload, event_type=f"policy.group_reconcile.{event_suffix}")

        if not decision.endpoint_ip:
            append_reconcile(
                {
                    "action_type": "policy.group_reconcile",
                    "status": "failed",
                    "group_name": str(group_name) if group_name else None,
                    "group_id": str(group_id) if group_id else None,
                    "message": "endpoint_ip is missing",
                    "action_source": "policy_reconciliation",
                },
                "failed",
            )
            return action_key
        if not group_name:
            append_reconcile(
                {
                    "action_type": "policy.group_reconcile",
                    "status": "failed",
                    "message": "group_name is missing",
                    "action_source": "policy_reconciliation",
                },
                "failed",
            )
            return action_key
        if not group_is_managed(group_name, group_id, resolved_group):
            append_reconcile(
                {
                    "action_type": "policy.group_reconcile",
                    "status": "failed",
                    "group_name": str(group_name) if group_name else None,
                    "group_id": str(group_id) if group_id else None,
                    "message": "Policy is not allowed to manage this group",
                    "action_source": "policy_reconciliation",
                },
                "failed",
            )
            return action_key
        if desired_present and group_id and resolved_group is None:
            append_reconcile(
                {
                    "action_type": "policy.group_reconcile",
                    "status": "failed",
                    "group_name": str(group_name) if group_name else None,
                    "group_id": str(group_id),
                    "message": "group_id not found",
                    "action_source": "policy_reconciliation",
                },
                "failed",
            )
            return action_key

        object_name = str(rendered_parameters.get("object_name") or f"endpoint-{decision.endpoint_id}")
        with _get_group_operation_lock("policy-reconcile", str(group_name), decision.endpoint_ip):
            group = resolved_group
            ip_object = find_ip_host_object(db, decision.endpoint_ip)
            if desired_present:
                group = group if group is not None else ensure_ip_group(db, str(group_name))
                ip_object = ip_object or ensure_ip_object(
                    db=db,
                    name=object_name,
                    object_type="host",
                    value=decision.endpoint_ip,
                    description=f"Auto-managed for endpoint {decision.endpoint_id}",
                    managed_by="policy",
                )
                changed = add_object_to_group(db=db, group=group, ip_object=ip_object)
                operation = "added" if changed else "already_present"
            else:
                if group is None or ip_object is None:
                    operation = "already_absent"
                else:
                    changed = remove_object_from_group(db=db, group=group, ip_object=ip_object)
                    operation = "removed" if changed else "already_absent"

        append_reconcile(
            {
                "action_type": "policy.group_reconcile",
                "status": "success",
                "group_name": group.name if group is not None else str(group_name),
                "group_id": group.group_id if group is not None else (str(group_id) if group_id else None),
                "object_id": ip_object.object_id if ip_object is not None else None,
                "operation": operation,
                "action_source": "policy_reconciliation",
                "reasons": [
                    reason.model_dump(mode="json") if hasattr(reason, "model_dump") else reason
                    for reason in decision.reasons
                ],
            },
            operation,
        )
        return action_key

    desired_actions: dict[str, tuple[dict, bool]] = {}
    branch_order: list[tuple[list[dict], bool]]
    if decision.compliant:
        branch_order = [(on_non_compliant_actions, False), (on_compliant_actions, True)]
    else:
        branch_order = [(on_compliant_actions, False), (on_non_compliant_actions, True)]
    for branch_actions, desired_present in branch_order:
        for branch_action in branch_actions:
            if str(branch_action.get("action_type", "")).strip() != "object.add_ip_to_group":
                continue
            key = action_group_key(branch_action)
            if key is not None:
                desired_actions[key] = (branch_action, desired_present)

    reconciled_group_keys: set[str] = set()
    for key, (branch_action, desired_present) in desired_actions.items():
        reconciled_key = reconcile_group_membership(branch_action, desired_present)
        if reconciled_key is not None:
            reconciled_group_keys.add(reconciled_key)

    if not actions:
        return results

    for raw_action in actions:
        if not isinstance(raw_action, dict):
            continue
        if raw_action.get("enabled") is False:
            continue

        action_type = str(raw_action.get("action_type", "")).strip()
        if action_type in {"object.add_ip_to_group", "object.remove_ip_from_group"}:
            key = action_group_key(raw_action)
            if key in reconciled_group_keys:
                continue
        parameters = raw_action.get("parameters", {})
        if not isinstance(parameters, dict):
            parameters = {}
        rendered_parameters = render_templates(parameters, context)
        group_name = rendered_parameters.get("group_name") or default_group_name
        group_id = rendered_parameters.get("group_id")
        resolved_group = resolve_group_reference(
            db=db,
            group_name=str(group_name) if group_name else None,
            group_id=str(group_id) if group_id else None,
        )
        if resolved_group is not None:
            group_name = resolved_group.name
        if action_type in {
            "object.add_ip_to_group",
            "object.remove_ip_from_group",
            "adapter.add_ip_to_group",
            "adapter.remove_ip_from_group",
            "adapter.sync_group",
        } and not group_is_managed(group_name, group_id, resolved_group):
            append_unmanaged_group_result(action_type, group_name, group_id)
            continue

        if action_type == "object.add_ip_to_group":
            if not decision.endpoint_ip:
                append_result(
                    {"action_type": action_type, "status": "skipped", "message": "endpoint_ip is missing"},
                    event_type="endpoint.policy_action.skipped",
                )
                continue
            if not group_name:
                append_result({"action_type": action_type, "status": "failed", "message": "group_name is missing"})
                continue
            if group_id and resolved_group is None:
                append_result(
                    {
                        "action_type": action_type,
                        "status": "failed",
                        "group_id": group_id,
                        "message": "group_id not found",
                    }
                )
                continue

            object_name = str(rendered_parameters.get("object_name") or f"endpoint-{decision.endpoint_id}")
            with _get_group_operation_lock("object-group", str(group_name), decision.endpoint_ip):
                group = resolved_group if resolved_group is not None else ensure_ip_group(db, str(group_name))
                ip_object = ensure_ip_object(
                    db=db,
                    name=object_name,
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
                "group_id": group.group_id,
                "object_id": ip_object.object_id,
                "operation": "added" if added else "already_present",
            }
            append_result(payload)
            continue

        if action_type == "object.remove_ip_from_group":
            if not decision.endpoint_ip:
                append_result(
                    {"action_type": action_type, "status": "skipped", "message": "endpoint_ip is missing"},
                    event_type="endpoint.policy_action.skipped",
                )
                continue
            if not group_name:
                append_result({"action_type": action_type, "status": "failed", "message": "group_name is missing"})
                continue

            group = resolved_group
            if group is None:
                payload = {
                    "action_type": action_type,
                    "status": "skipped",
                    "group_name": group_name,
                    "message": "group not found",
                }
                append_result(payload)
                continue

            object_name = str(rendered_parameters.get("object_name") or f"endpoint-{decision.endpoint_id}")
            ip_object = db.scalar(
                select(IpObjectModel).where(
                    IpObjectModel.object_type == "host",
                    IpObjectModel.name == object_name,
                )
            )
            if ip_object is None:
                ip_object = find_ip_host_object(db, decision.endpoint_ip)
            if ip_object is None:
                payload = {
                    "action_type": action_type,
                    "status": "skipped",
                    "group_name": group_name,
                    "message": "ip object not found",
                }
                append_result(payload)
                continue

            with _get_group_operation_lock("object-group", str(group.name), decision.endpoint_ip):
                removed = remove_object_from_group(db=db, group=group, ip_object=ip_object)
                operation = "removed" if removed else "already_absent"
            payload = {
                "action_type": action_type,
                "status": "success",
                "group_name": group.name,
                "group_id": group.group_id,
                "object_id": ip_object.object_id,
                "operation": operation,
            }
            append_result(payload)
            continue

        if action_type in {"adapter.add_ip_to_group", "adapter.remove_ip_from_group", "adapter.sync_group"}:
            if not decision.endpoint_ip and action_type != "adapter.sync_group":
                append_result(
                    {"action_type": action_type, "status": "skipped", "message": "endpoint_ip is missing"},
                    event_type="endpoint.policy_action.skipped",
                )
                continue

            selected_adapter = normalize_adapter_name(str(rendered_parameters.get("adapter") or adapter_name))
            selected_profile = rendered_parameters.get("adapter_profile") or adapter_profile
            profile_name, settings = resolve_adapter_settings(db, selected_adapter, selected_profile)
            if profile_name is None and selected_profile:
                append_result(
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
                "group_id": resolved_group.group_id if resolved_group is not None else (str(group_id) if group_id else None),
            }
            lock = _get_group_operation_lock(
                "adapter-group",
                selected_adapter,
                str(profile_name or ""),
                str(group_name or ""),
            )
            with lock:
                if adapter_action == "sync_group":
                    if not group_name:
                        append_result(
                            {"action_type": action_type, "status": "failed", "message": "group_name is missing"}
                        )
                        continue
                    group = resolved_group or find_group_by_name(db, str(group_name))
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
                circuit_key = _adapter_circuit_key(selected_adapter, profile_name)
                is_open, opened_until = _circuit_is_open(circuit_key)
                if is_open:
                    append_result(
                        {
                            "action_type": action_type,
                            "status": "failed",
                            "adapter": selected_adapter,
                            "adapter_profile": profile_name,
                            "group_name": group_name,
                            "group_id": decision_payload.get("group_id"),
                            "message": f"Adapter circuit breaker is open until {datetime.fromtimestamp(opened_until, tz=timezone.utc).isoformat()}",
                        }
                    )
                    continue

                db.flush()
                db.commit()
                adapter_started_at = time.perf_counter()
                try:
                    enforcement_result = registry.execute(action)
                    adapter_duration_ms = (time.perf_counter() - adapter_started_at) * 1000
                    if enforcement_result.status == "success":
                        _circuit_mark_success(circuit_key)
                    else:
                        _circuit_mark_failure(circuit_key)
                    persist_enforcement_result(db, enforcement_result)
                    payload = {
                        "action_type": action_type,
                        "status": enforcement_result.status,
                        "adapter": selected_adapter,
                        "adapter_profile": profile_name,
                        "group_name": group_name,
                        "group_id": decision_payload.get("group_id"),
                        "operation": (
                            enforcement_result.details.get("operation")
                            if isinstance(enforcement_result.details, dict)
                            else None
                        ) or enforcement_result.status,
                        "adapter_duration_ms": round(adapter_duration_ms, 2),
                        "details": enforcement_result.details,
                    }
                except Exception as exc:  # pragma: no cover - defensive guard
                    adapter_duration_ms = (time.perf_counter() - adapter_started_at) * 1000
                    _circuit_mark_failure(circuit_key)
                    payload = {
                        "action_type": action_type,
                        "status": "failed",
                        "adapter": selected_adapter,
                        "adapter_profile": profile_name,
                        "group_name": group_name,
                        "group_id": decision_payload.get("group_id"),
                        "adapter_duration_ms": round(adapter_duration_ms, 2),
                        "message": f"adapter execution crashed: {exc}",
                    }
            append_result(payload)
            continue

        if action_type == "adapter.post_event":
            if not ALLOW_POLICY_HTTP_ACTIONS:
                payload = {
                    "action_type": action_type,
                    "status": "skipped",
                    "message": "Policy HTTP actions are disabled by server configuration",
                }
                append_policy_action_result(
                    db=db,
                    endpoint_id=decision.endpoint_id,
                    results=results,
                    payload=payload,
                    event_type="endpoint.policy_action.skipped",
                )
                continue

            selected_adapter = str(rendered_parameters.get("adapter") or adapter_name)
            selected_profile = rendered_parameters.get("adapter_profile") or adapter_profile
            profile_name, settings = resolve_adapter_settings(db, selected_adapter, selected_profile)
            if profile_name is None and selected_profile:
                append_policy_action_result(
                    db=db,
                    endpoint_id=decision.endpoint_id,
                    results=results,
                    payload={
                        "action_type": action_type,
                        "status": "failed",
                        "message": f"adapter profile '{selected_profile}' not found or inactive",
                    },
                )
                continue

            endpoint_path = str(rendered_parameters.get("path") or "").strip()
            if not endpoint_path:
                append_policy_action_result(
                    db=db,
                    endpoint_id=decision.endpoint_id,
                    results=results,
                    payload={"action_type": action_type, "status": "failed", "message": "path is required"},
                )
                continue

            base_url = str(settings.get("base_url") or "")
            target_url = resolve_event_url(base_url, endpoint_path)
            allowed, reason = _is_http_target_allowed(target_url)
            if not allowed:
                payload = {
                    "action_type": action_type,
                    "status": "failed",
                    "adapter": selected_adapter,
                    "adapter_profile": profile_name,
                    "url": target_url,
                    "message": reason,
                }
                append_result(payload)
                continue
            circuit_key = _circuit_key_for_url(target_url)
            is_open, opened_until = _circuit_is_open(circuit_key)
            if is_open:
                payload = {
                    "action_type": action_type,
                    "status": "failed",
                    "adapter": selected_adapter,
                    "adapter_profile": profile_name,
                    "url": target_url,
                    "message": f"Circuit breaker is open until {datetime.fromtimestamp(opened_until, tz=timezone.utc).isoformat()}",
                }
                append_result(payload)
                continue
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
                    "request_method": method,
                    "url": target_url,
                    "http_status": response.status_code,
                    "request_body_excerpt": _string_excerpt(sanitize_sensitive_payload(payload_body)),
                    "response_excerpt": response.text[:500],
                }
                if response.status_code >= 400:
                    payload["message"] = "Adapter event POST returned an error status"
                    _circuit_mark_failure(circuit_key)
                else:
                    _circuit_mark_success(circuit_key)
            except requests.RequestException as exc:
                _circuit_mark_failure(circuit_key)
                payload = {
                    "action_type": action_type,
                    "status": "failed",
                    "adapter": selected_adapter,
                    "adapter_profile": profile_name,
                    "request_method": method,
                    "url": target_url,
                    "request_body_excerpt": _string_excerpt(sanitize_sensitive_payload(payload_body)),
                    "message": str(exc),
                }

            log_policy_http_action_result(
                action_type=action_type,
                endpoint_id=decision.endpoint_id,
                method=method,
                url=target_url,
                status=payload.get("status", "failed"),
                http_status=payload.get("http_status"),
                request_body=payload_body,
                response_excerpt=payload.get("response_excerpt"),
                error_message=payload.get("message"),
            )
            append_result(payload)
            continue

        if action_type in {"http.get", "http.post"}:
            if not ALLOW_POLICY_HTTP_ACTIONS:
                payload = {
                    "action_type": action_type,
                    "status": "skipped",
                    "message": "Policy HTTP actions are disabled by server configuration",
                }
                append_policy_action_result(
                    db=db,
                    endpoint_id=decision.endpoint_id,
                    results=results,
                    payload=payload,
                    event_type="endpoint.policy_action.skipped",
                )
                continue

            url = rendered_parameters.get("url")
            if not url:
                append_policy_action_result(
                    db=db,
                    endpoint_id=decision.endpoint_id,
                    results=results,
                    payload={"action_type": action_type, "status": "failed", "message": "url is required"},
                )
                continue

            allowed, reason = _is_http_target_allowed(str(url))
            if not allowed:
                payload = {
                    "action_type": action_type,
                    "status": "failed",
                    "url": str(url),
                    "message": reason,
                }
                append_result(payload)
                continue
            target_url = str(url)
            circuit_key = _circuit_key_for_url(target_url)
            is_open, opened_until = _circuit_is_open(circuit_key)
            if is_open:
                payload = {
                    "action_type": action_type,
                    "status": "failed",
                    "url": target_url,
                    "message": f"Circuit breaker is open until {datetime.fromtimestamp(opened_until, tz=timezone.utc).isoformat()}",
                }
                append_result(payload)
                continue

            method = "GET" if action_type == "http.get" else "POST"
            headers = rendered_parameters.get("headers") if isinstance(rendered_parameters.get("headers"), dict) else {}
            body = rendered_parameters.get("body") if isinstance(rendered_parameters.get("body"), dict) else None
            timeout = float(rendered_parameters.get("timeout_seconds", HTTP_TIMEOUT_SECONDS))
            try:
                response = requests.request(
                    method=method,
                    url=target_url,
                    headers=headers,
                    json=body,
                    timeout=timeout,
                )
                payload = {
                    "action_type": action_type,
                    "status": "success" if response.status_code < 400 else "failed",
                    "request_method": method,
                    "http_status": response.status_code,
                    "url": url,
                    "request_body_excerpt": _string_excerpt(sanitize_sensitive_payload(body)),
                    "response_excerpt": response.text[:500],
                }
                if response.status_code >= 400:
                    payload["message"] = "HTTP request returned an error status"
                    _circuit_mark_failure(circuit_key)
                else:
                    _circuit_mark_success(circuit_key)
            except requests.RequestException as exc:
                _circuit_mark_failure(circuit_key)
                payload = {
                    "action_type": action_type,
                    "status": "failed",
                    "request_method": method,
                    "url": url,
                    "request_body_excerpt": _string_excerpt(sanitize_sensitive_payload(body)),
                    "message": str(exc),
                }

            log_policy_http_action_result(
                action_type=action_type,
                endpoint_id=decision.endpoint_id,
                method=method,
                url=target_url,
                status=payload.get("status", "failed"),
                http_status=payload.get("http_status"),
                request_body=body,
                response_excerpt=payload.get("response_excerpt"),
                error_message=payload.get("message"),
            )
            append_result(payload)
            continue

        append_policy_action_result(
            db=db,
            endpoint_id=decision.endpoint_id,
            results=results,
            payload={
                "action_type": action_type,
                "status": "failed",
                "message": f"unsupported action_type '{action_type}'",
            },
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
    started_at = time.perf_counter()
    try:
        result = registry.execute(action)
    except Exception as exc:  # pragma: no cover - defensive guard
        result = EnforcementResult(
            adapter=DEFAULT_ADAPTER,
            action="quarantine",
            endpoint_id=decision.endpoint_id,
            status="failed",
            details={"error": f"adapter execution crashed: {exc}"},
        )
    if isinstance(result.details, dict):
        result.details.setdefault("adapter_duration_ms", round((time.perf_counter() - started_at) * 1000, 2))
    persist_enforcement_result(db, result)
    event_type = "endpoint.quarantined" if result.status == "success" else "endpoint.quarantine_failed"
    store_audit_event(db, event_type, decision.endpoint_id, result.model_dump(mode="json"))
    return result


def to_background_job_response(item: BackgroundJobModel) -> BackgroundJobResponse:
    return BackgroundJobResponse(
        id=item.id,
        job_type=item.job_type,
        status=item.status,
        endpoint_id=item.endpoint_id,
        payload=item.payload or {},
        result=item.result or {},
        error_message=item.error_message,
        created_at=item.created_at,
        updated_at=item.updated_at,
    )


def process_decision_with_db(decision: ComplianceDecision, db: Session) -> dict:
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
        decision.policy_id is None
        and not decision.compliant
        and decision.recommended_action == "quarantine"
        and not execution_results
    ):
        result = fallback_quarantine(decision, db)
        action_taken = action_taken or result.status == "success"
        fallback_result = result.model_dump(mode="json")

    response = {
        "status": "logged",
        "action_taken": action_taken,
        "execution_results": execution_results,
    }
    if fallback_result is not None:
        response["fallback_result"] = fallback_result
    return response


def _background_process_decision(job_id: int, decision_payload: dict) -> None:
    db = SessionLocal()
    try:
        job = db.get(BackgroundJobModel, job_id)
        if job is None:
            return
        job.status = "running"
        job.updated_at = utcnow()
        db.commit()

        decision = ComplianceDecision.model_validate(decision_payload)
        result = process_decision_with_db(decision, db)
        job.status = "completed"
        job.result = result
        job.updated_at = utcnow()
        db.commit()
    except Exception as exc:  # pragma: no cover - defensive guard
        db.rollback()
        job = db.get(BackgroundJobModel, job_id)
        if job is not None:
            job.status = "failed"
            job.error_message = str(exc)
            job.updated_at = utcnow()
            db.commit()
        logger.exception("background decision job failed job_id=%s error=%s", job_id, exc)
    finally:
        db.close()


@app.get("/healthz")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/decisions")
def handle_decision(
    decision: ComplianceDecision,
    request: Request,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> dict:
    source_ip = request.client.host if request.client else "unknown"
    _apply_rate_limit(f"decision:{source_ip}")
    if ASYNC_DECISION_EXECUTION:
        job = BackgroundJobModel(
            job_type="decision",
            status="queued",
            endpoint_id=decision.endpoint_id,
            payload=decision.model_dump(mode="json"),
            result={},
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        executor.submit(_background_process_decision, job.id, job.payload)
        return {
            "status": "queued",
            "job_id": job.id,
            "action_taken": False,
            "execution_results": [],
        }

    response = process_decision_with_db(decision, db)
    db.commit()
    return response


@app.post("/actions", response_model=EnforcementResult)
def run_action(
    action: EnforcementAction,
    request: Request,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> EnforcementResult:
    source_ip = request.client.host if request.client else "unknown"
    _apply_rate_limit(f"action:{source_ip}")
    normalized_action = action.model_copy(update={"adapter": normalize_adapter_name(action.adapter)})
    profile_name, settings = resolve_adapter_settings(db, normalized_action.adapter, normalized_action.adapter_profile)
    merged_decision = dict(normalized_action.decision or {})
    if settings:
        merged_decision.setdefault("adapter_settings", settings)
    if profile_name and normalized_action.adapter_profile != profile_name:
        normalized_action = normalized_action.model_copy(update={"adapter_profile": profile_name})
    normalized_action = normalized_action.model_copy(update={"decision": merged_decision})

    circuit_key = _adapter_circuit_key(normalized_action.adapter, normalized_action.adapter_profile)
    is_open, opened_until = _circuit_is_open(circuit_key)
    started_at = time.perf_counter()
    if is_open:
        result = EnforcementResult(
            adapter=normalized_action.adapter,
            action=normalized_action.action,
            endpoint_id=normalized_action.endpoint_id,
            status="failed",
            details={
                "error": (
                    "Adapter circuit breaker is open until "
                    f"{datetime.fromtimestamp(opened_until, tz=timezone.utc).isoformat()}"
                ),
                "adapter_profile": normalized_action.adapter_profile,
            },
        )
    else:
        try:
            result = registry.execute(normalized_action)
            if result.status == "success":
                _circuit_mark_success(circuit_key)
            else:
                _circuit_mark_failure(circuit_key)
        except Exception as exc:  # pragma: no cover - defensive guard
            _circuit_mark_failure(circuit_key)
            result = EnforcementResult(
                adapter=normalized_action.adapter,
                action=normalized_action.action,
                endpoint_id=normalized_action.endpoint_id,
                status="failed",
                details={
                    "error": f"adapter execution crashed: {exc}",
                    "adapter_profile": normalized_action.adapter_profile,
                },
            )
    if isinstance(result.details, dict):
        result.details.setdefault("adapter_duration_ms", round((time.perf_counter() - started_at) * 1000, 2))
    persist_enforcement_result(db, result)
    store_audit_event(db, "endpoint.action.requested", normalized_action.endpoint_id, normalized_action.model_dump(mode="json"))
    db.commit()
    return result


@app.get("/enforcement/{endpoint_id}/latest", response_model=EnforcementResult)
def latest_enforcement(
    endpoint_id: str,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> EnforcementResult:
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


@app.get("/enforcement/latest-batch", response_model=dict[str, EnforcementResult | None])
def latest_enforcement_batch(
    endpoint_id: list[str] = Query(default=[]),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> dict[str, EnforcementResult | None]:
    endpoint_ids = [item.strip() for item in endpoint_id if item.strip()]
    response: dict[str, EnforcementResult | None] = {item: None for item in endpoint_ids}
    if not endpoint_ids:
        return response
    records = db.scalars(
        select(EnforcementRecordModel)
        .where(EnforcementRecordModel.endpoint_id.in_(endpoint_ids))
        .order_by(EnforcementRecordModel.endpoint_id, desc(EnforcementRecordModel.created_at), desc(EnforcementRecordModel.id))
    ).all()
    for record in records:
        if response.get(record.endpoint_id) is None:
            response[record.endpoint_id] = EnforcementResult(
                adapter=record.adapter,
                action=record.action,
                endpoint_id=record.endpoint_id,
                status=record.status,
                details=record.details,
                completed_at=record.created_at,
            )
    return response


@app.get("/jobs", response_model=list[BackgroundJobResponse])
def list_jobs(
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0, le=100000),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> list[BackgroundJobResponse]:
    items = db.scalars(
        select(BackgroundJobModel)
        .order_by(desc(BackgroundJobModel.created_at))
        .offset(offset)
        .limit(limit)
    ).all()
    return [to_background_job_response(item) for item in items]


@app.get("/jobs/{job_id}", response_model=BackgroundJobResponse)
def get_job(
    job_id: int,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> BackgroundJobResponse:
    item = db.get(BackgroundJobModel, job_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return to_background_job_response(item)


@app.get("/audit-events", response_model=list[AuditEvent])
def list_audit_events(
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0, le=100000),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> list[AuditEvent]:
    events = db.scalars(
        select(AuditEventModel).order_by(desc(AuditEventModel.created_at)).offset(offset).limit(limit)
    ).all()
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
def list_adapters(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=100000),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> list[AdapterConfigResponse]:
    started_at = time.perf_counter()
    items = db.scalars(select(AdapterConfigModel).order_by(AdapterConfigModel.name).offset(offset).limit(limit)).all()
    db_duration_ms = (time.perf_counter() - started_at) * 1000
    logger.info(
        "local_read path=/adapters db_duration_ms=%.2f row_count=%s limit=%s offset=%s",
        db_duration_ms,
        len(items),
        limit,
        offset,
    )
    return [to_adapter_config_response(item) for item in items]


@app.get("/adapters/health", response_model=list[AdapterHealthResponse])
def list_adapter_health(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=100000),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> list[AdapterHealthResponse]:
    items = db.scalars(select(AdapterConfigModel).order_by(AdapterConfigModel.name).offset(offset).limit(limit)).all()
    return [probe_adapter_health(item) for item in items]


@app.get("/adapters/{name}/health", response_model=AdapterHealthResponse)
def adapter_health(
    name: str,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> AdapterHealthResponse:
    item = db.scalar(select(AdapterConfigModel).where(AdapterConfigModel.name == name))
    if item is None:
        raise HTTPException(status_code=404, detail="Adapter config not found")
    return probe_adapter_health(item)


@app.put("/adapters/{name}", response_model=AdapterConfigResponse)
def upsert_adapter(
    name: str,
    payload: AdapterConfigUpsert,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> AdapterConfigResponse:
    item = db.scalar(select(AdapterConfigModel).where(AdapterConfigModel.name == name))
    incoming_settings = payload.settings or {}
    normalized_adapter = normalize_adapter_name(payload.adapter if payload.adapter is not None else item.adapter if item else "fortigate")

    if item is None:
        incoming_settings = preserve_sensitive_settings({}, incoming_settings)
        validate_adapter_settings(normalized_adapter, incoming_settings)
        item = AdapterConfigModel(
            name=name,
            adapter=normalized_adapter,
            is_active=True if payload.is_active is None else payload.is_active,
            settings=incoming_settings,
        )
        db.add(item)
        db.commit()
        db.refresh(item)
        return to_adapter_config_response(item)

    if payload.adapter is not None:
        item.adapter = normalized_adapter
    if payload.is_active is not None:
        item.is_active = payload.is_active
    if payload.settings is not None:
        current_settings = item.settings or {}
        merged_settings = preserve_sensitive_settings(current_settings, incoming_settings)
        validate_adapter_settings(item.adapter, merged_settings)
        item.settings = merged_settings
    item.updated_at = utcnow()
    db.commit()
    db.refresh(item)
    return to_adapter_config_response(item)


@app.delete("/adapters/{name}", status_code=status.HTTP_204_NO_CONTENT)
def delete_adapter(
    name: str,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> None:
    item = db.scalar(select(AdapterConfigModel).where(AdapterConfigModel.name == name))
    if item is None:
        raise HTTPException(status_code=404, detail="Adapter config not found")
    db.delete(item)
    db.commit()


@app.get("/objects/ip-objects", response_model=list[IpObjectResponse])
def list_ip_objects(
    limit: int = Query(default=200, ge=1, le=2000),
    offset: int = Query(default=0, ge=0, le=100000),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> list[IpObjectResponse]:
    started_at = time.perf_counter()
    items = db.scalars(
        select(IpObjectModel)
        .options(selectinload(IpObjectModel.memberships))
        .order_by(IpObjectModel.name)
        .offset(offset)
        .limit(limit)
    ).all()
    db_duration_ms = (time.perf_counter() - started_at) * 1000
    logger.info(
        "local_read path=/objects/ip-objects db_duration_ms=%.2f row_count=%s limit=%s offset=%s",
        db_duration_ms,
        len(items),
        limit,
        offset,
    )
    return [to_ip_object_response(item) for item in items]


@app.post("/objects/ip-objects", response_model=IpObjectResponse, status_code=status.HTTP_201_CREATED)
def create_ip_object(
    payload: IpObjectCreate,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> IpObjectResponse:
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
def update_ip_object(
    object_id: str,
    payload: IpObjectUpdate,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> IpObjectResponse:
    item = find_object_by_id(db, object_id)
    if item is None:
        raise HTTPException(status_code=404, detail="IP object not found")
    if payload.object_type and payload.object_type not in {"host", "cidr"}:
        raise HTTPException(status_code=422, detail="object_type must be 'host' or 'cidr'")

    effective_object_type = payload.object_type or item.object_type
    if payload.value is not None:
        try:
            if effective_object_type == "cidr":
                ipaddress.ip_network(payload.value, strict=False)
            else:
                ipaddress.ip_address(payload.value)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"Invalid IP value for object_type '{effective_object_type}'") from exc

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


@app.delete("/objects/ip-objects/{object_id}", response_model=dict)
def delete_ip_object(
    object_id: str,
    force: bool = Query(default=False),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> dict:
    item = find_object_by_id(db, object_id)
    if item is None:
        raise HTTPException(status_code=404, detail="IP object not found")

    memberships = db.scalars(
        select(IpGroupMemberModel)
        .options(selectinload(IpGroupMemberModel.group))
        .where(IpGroupMemberModel.object_ref == item.id)
    ).all()
    if memberships and not force:
        return JSONResponse(
            status_code=409,
            content={
                "detail": "Object is still a member of groups",
                "group_ids": [membership.group.group_id for membership in memberships],
                "group_names": [membership.group.name for membership in memberships],
                "hint": "Use force=true to remove memberships first",
            },
        )

    removed_memberships = [
        {
            "group_id": membership.group.group_id,
            "group_name": membership.group.name,
            "object_id": item.object_id,
            "ip_address": item.value,
        }
        for membership in memberships
    ]
    for membership in memberships:
        db.delete(membership)

    audit_payload = {
        "object_id": item.object_id,
        "object_name": item.name,
        "object_type": item.object_type,
        "ip_address": item.value,
        "operation": "deleted",
        "force": force,
        "removed_memberships": removed_memberships,
        "source": "admin",
    }
    store_audit_event(db, "object.manual_delete", None, audit_payload)
    db.delete(item)
    db.commit()
    return {
        "status": "success",
        "operation": "deleted",
        "object_id": object_id,
        "removed_memberships": removed_memberships,
    }


@app.get("/objects/ip-groups", response_model=list[IpGroupResponse])
def list_ip_groups(
    limit: int = Query(default=200, ge=1, le=2000),
    offset: int = Query(default=0, ge=0, le=100000),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> list[IpGroupResponse]:
    started_at = time.perf_counter()
    items = db.scalars(
        select(IpGroupModel)
        .options(selectinload(IpGroupModel.members).selectinload(IpGroupMemberModel.ip_object))
        .order_by(IpGroupModel.name)
        .offset(offset)
        .limit(limit)
    ).all()
    db_duration_ms = (time.perf_counter() - started_at) * 1000
    logger.info(
        "local_read path=/objects/ip-groups db_duration_ms=%.2f row_count=%s limit=%s offset=%s",
        db_duration_ms,
        len(items),
        limit,
        offset,
    )
    return [to_ip_group_response(item) for item in items]


@app.post("/objects/ip-groups", response_model=IpGroupResponse, status_code=status.HTTP_201_CREATED)
def create_ip_group(
    payload: IpGroupCreate,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> IpGroupResponse:
    existing = find_group_by_name(db, payload.name.strip())
    if existing is not None:
        raise HTTPException(status_code=409, detail="An IP group with this name already exists")
    group = ensure_ip_group(db, payload.name.strip(), payload.description)
    db.commit()
    db.refresh(group)
    return to_ip_group_response(group)
@app.put("/objects/ip-groups/{group_id}", response_model=IpGroupResponse)
def update_ip_group(
    group_id: str,
    payload: IpGroupUpdate,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> IpGroupResponse:
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
def delete_ip_group(
    group_id: str,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> None:
    group = db.scalar(select(IpGroupModel).where(IpGroupModel.group_id == group_id))
    if group is None:
        raise HTTPException(status_code=404, detail="IP group not found")
    db.delete(group)
    db.commit()


@app.post("/objects/ip-groups/{group_name}/members", response_model=ManualGroupMemberResponse)
def add_group_member(
    group_name: str,
    payload: IpGroupMemberAddRequest,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> ManualGroupMemberResponse:
    group = resolve_group_identifier(db, group_name)
    if group is None:
        raise HTTPException(status_code=404, detail="IP group not found")
    if payload.object_id:
        ip_object = find_object_by_id(db, payload.object_id)
        if ip_object is None:
            raise HTTPException(status_code=404, detail="IP object not found")
    else:
        assert payload.ip_address is not None
        object_name = (
            payload.name.strip()
            if payload.name and payload.name.strip()
            else f"endpoint-{payload.endpoint_id}" if payload.endpoint_id else f"ip-{payload.ip_address.replace('.', '-')}"
        )
        ip_object = ensure_ip_object(
            db=db,
            name=object_name,
            object_type="host",
            value=payload.ip_address,
            description=f"Manual group member for {group.name}",
            managed_by="manual",
        )
    added = add_object_to_group(db=db, group=group, ip_object=ip_object)
    operation = "added" if added else "already_present"
    warning = build_policy_managed_warning(group)
    store_audit_event(
        db,
        "object.group_member.manual_add",
        payload.endpoint_id,
        {
            "group_id": group.group_id,
            "group_name": group.name,
            "object_id": ip_object.object_id,
            "ip_address": ip_object.value,
            "operation": operation,
            "warning": warning,
            "source": "admin",
        },
    )
    db.commit()
    db.refresh(group)
    return manual_member_response(group=group, ip_object=ip_object, operation=operation, warning=warning)


@app.post("/objects/ip-groups/{group_name}/members/ip", response_model=IpGroupResponse)
def add_ip_address_to_group(
    group_name: str,
    payload: IpAddressMembershipRequest,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> IpGroupResponse:
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


@app.delete("/objects/ip-groups/{group_name}/members/ip/{ip_address}", response_model=ManualGroupMemberResponse)
def remove_ip_address_from_group(
    group_name: str,
    ip_address: str,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> ManualGroupMemberResponse:
    group = resolve_group_identifier(db, group_name)
    if group is None:
        raise HTTPException(status_code=404, detail="IP group not found")
    ip_object = find_ip_host_object(db, ip_address)
    operation = "already_absent"
    if ip_object is not None:
        removed = remove_object_from_group(db=db, group=group, ip_object=ip_object)
        operation = "removed" if removed else "already_absent"
    warning = build_policy_managed_warning(group)
    store_audit_event(
        db,
        "object.group_member.manual_remove",
        None,
        {
            "group_id": group.group_id,
            "group_name": group.name,
            "object_id": ip_object.object_id if ip_object else None,
            "ip_address": ip_address,
            "operation": operation,
            "warning": warning,
            "source": "admin",
        },
    )
    db.commit()
    db.refresh(group)
    return manual_member_response(group=group, ip_object=ip_object, operation=operation, warning=warning)


@app.delete("/objects/ip-groups/{group_name}/members/{object_id}", response_model=ManualGroupMemberResponse)
def remove_group_member(
    group_name: str,
    object_id: str,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> ManualGroupMemberResponse:
    group = resolve_group_identifier(db, group_name)
    if group is None:
        raise HTTPException(status_code=404, detail="IP group not found")
    ip_object = find_object_by_id(db, object_id)
    if ip_object is None:
        raise HTTPException(status_code=404, detail="IP object not found")
    removed = remove_object_from_group(db=db, group=group, ip_object=ip_object)
    operation = "removed" if removed else "already_absent"
    warning = build_policy_managed_warning(group)
    store_audit_event(
        db,
        "object.group_member.manual_remove",
        None,
        {
            "group_id": group.group_id,
            "group_name": group.name,
            "object_id": ip_object.object_id,
            "ip_address": ip_object.value,
            "operation": operation,
            "warning": warning,
            "source": "admin",
        },
    )
    db.commit()
    db.refresh(group)
    return manual_member_response(group=group, ip_object=ip_object, operation=operation, warning=warning)


@app.post("/objects/ip-groups/{group_id}/sync", response_model=dict)
def sync_ip_group(
    group_id: str,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> dict:
    group = resolve_group_identifier(db, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="IP group not found")
    payload = {
        "group_id": group.group_id,
        "group_name": group.name,
        "operation": "sync_requested",
        "message": "Manual sync is audited. Use policy adapter actions for firewall reconciliation in the MVP.",
    }
    store_audit_event(db, "object.group.manual_sync", None, payload)
    db.commit()
    return {"status": "accepted", **payload, "warning": build_policy_managed_warning(group)}


@app.post("/objects/policy-cleanup", response_model=dict)
def cleanup_policy_effects(
    payload: PolicyCleanupRequest,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> dict:
    groups: list[IpGroupModel] = []
    seen: set[int] = set()
    for group_ref in payload.groups:
        group = resolve_group_reference(db=db, group_name=group_ref.group_name, group_id=group_ref.group_id)
        if group is not None and group.id not in seen:
            seen.add(group.id)
            groups.append(group)
    result = _cleanup_endpoint_from_groups(
        db=db,
        endpoint_id=payload.endpoint_id,
        ip_address=payload.ip_address,
        groups=groups,
        event_type="policy.assignment.cleanup",
        reason=payload.reason,
        policy_id=payload.policy_id,
        policy_name=payload.policy_name,
    )
    db.commit()
    return {"status": "success", **result}


@app.post("/objects/endpoint-cleanup", response_model=dict)
def cleanup_endpoint_from_all_groups(
    payload: EndpointCleanupRequest,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> dict:
    groups = db.scalars(select(IpGroupModel).order_by(IpGroupModel.name)).all()
    result = _cleanup_endpoint_from_groups(
        db=db,
        endpoint_id=payload.endpoint_id,
        ip_address=payload.ip_address,
        groups=list(groups),
        event_type="endpoint.cleanup.group_memberships",
        reason=payload.reason,
    )
    db.commit()
    return {"status": "success", **result}
