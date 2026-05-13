import logging
import os
import threading
import time
import ipaddress
import json
import gzip
import hashlib
from collections import defaultdict, deque
from uuid import uuid4
from pathlib import Path
from datetime import datetime, timezone
from typing import Any
from urllib.error import URLError
from urllib.parse import quote_plus
from urllib.request import Request as UrlRequest, urlopen

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import ValidationError
from sqlalchemy import desc, inspect, select, text
from sqlalchemy.orm import Session

from app.activity import DEFAULT_ACTIVITY_GRACE_MULTIPLIER, build_endpoint_summary
from app.db import Base, engine, get_db
from app.lifecycle import (
    reconcile_inactive_transitions,
)
from app.models import Endpoint, EndpointLifecycleEvent, TelemetryRecord
from app.schemas import (
    EndpointSummary,
    LifecycleEventResponse,
    TelemetryIngestResponse,
    TelemetryRecordResponse,
    build_lifecycle_event_response,
    build_record_response,
)
from posture_shared.models.telemetry import EndpointTelemetry
from posture_shared.security import parse_cors_origins, require_api_key


def configure_logging() -> logging.Logger:
    logger = logging.getLogger("telemetry-api")
    if logger.handlers:
        return logger

    log_dir = Path(__file__).resolve().parents[1] / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "telemetry-api.log"

    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    logger.propagate = False
    logger.info("telemetry-api logging initialized at %s", log_path)
    return logger


logger = configure_logging()

HEARTBEAT_INTERVAL_SECONDS = int(os.getenv("HEARTBEAT_INTERVAL_SECONDS", "3"))
ACTIVITY_GRACE_MULTIPLIER = int(os.getenv("ACTIVITY_GRACE_MULTIPLIER", "3"))
ENDPOINT_INACTIVE_AFTER_SECONDS = int(
    os.getenv("ENDPOINT_INACTIVE_AFTER_SECONDS", str(HEARTBEAT_INTERVAL_SECONDS * ACTIVITY_GRACE_MULTIPLIER))
)
ACTIVITY_CHECK_INTERVAL_SECONDS = int(os.getenv("ACTIVITY_CHECK_INTERVAL_SECONDS", "3"))
STATUS_CHANGE_COOLDOWN_SECONDS = int(os.getenv("STATUS_CHANGE_COOLDOWN_SECONDS", "6"))
MAX_TELEMETRY_BODY_BYTES = int(os.getenv("MAX_TELEMETRY_BODY_BYTES", "10485760"))
ACCEPT_GZIP_TELEMETRY = os.getenv("ACCEPT_GZIP_TELEMETRY", "true").lower() == "true"
POSTURE_TRIGGERS_EVALUATION = os.getenv(
    "POSTURE_TRIGGERS_EVALUATION",
    os.getenv("EVALUATE_POSTURE_ON_TELEMETRY", "true"),
).lower() == "true"
FORCE_EVALUATION_ON_EVERY_POSTURE = os.getenv("FORCE_EVALUATION_ON_EVERY_POSTURE", "true").lower() == "true"
SKIP_EVALUATION_IF_POSTURE_HASH_UNCHANGED = os.getenv(
    "SKIP_EVALUATION_IF_POSTURE_HASH_UNCHANGED",
    "false",
).lower() == "true"
INVENTORY_FULL_TRIGGERS_EVALUATION = os.getenv("INVENTORY_FULL_TRIGGERS_EVALUATION", "false").lower() == "true"
INVENTORY_DELTA_TRIGGERS_EVALUATION = os.getenv("INVENTORY_DELTA_TRIGGERS_EVALUATION", "false").lower() == "true"
INVENTORY_RESYNC_ON_SEQUENCE_GAP = os.getenv("INVENTORY_RESYNC_ON_SEQUENCE_GAP", "true").lower() == "true"
INVENTORY_RESYNC_ON_HASH_MISMATCH = os.getenv("INVENTORY_RESYNC_ON_HASH_MISMATCH", "true").lower() == "true"
PROCESS_POSTURE_IN_BACKGROUND = os.getenv("PROCESS_POSTURE_IN_BACKGROUND", "true").lower() == "true"
PROCESS_INVENTORY_IN_BACKGROUND = os.getenv("PROCESS_INVENTORY_IN_BACKGROUND", "true").lower() == "true"
LOG_TELEMETRY_PAYLOAD_SIZE = os.getenv("LOG_TELEMETRY_PAYLOAD_SIZE", "true").lower() == "true"
LOG_TELEMETRY_PROCESSING_DURATION = os.getenv("LOG_TELEMETRY_PROCESSING_DURATION", "true").lower() == "true"
SLOW_TELEMETRY_WARNING_MS = float(os.getenv("SLOW_TELEMETRY_WARNING_MS", "1000"))
SLOW_EVALUATION_WARNING_MS = float(os.getenv("SLOW_EVALUATION_WARNING_MS", "3000"))
TELEMETRY_RATE_LIMIT_PER_MINUTE = int(os.getenv("TELEMETRY_RATE_LIMIT_PER_MINUTE", "120"))
EVALUATION_ENGINE_URL = os.getenv("EVALUATION_ENGINE_URL", "http://127.0.0.1:8003")
EVALUATION_HTTP_TIMEOUT_SECONDS = float(os.getenv("EVALUATION_HTTP_TIMEOUT_SECONDS", "8"))
INTER_SERVICE_API_KEY = os.getenv("POSTURE_API_KEY", "").strip()
_telemetry_rate_state: dict[str, deque[float]] = defaultdict(deque)
_telemetry_rate_lock = threading.Lock()

Base.metadata.create_all(bind=engine)


def ensure_endpoint_runtime_columns() -> None:
    inspector = inspect(engine)
    existing_columns = {column["name"] for column in inspector.get_columns("endpoints")}
    statements: list[str] = []
    if "last_collected_at" not in existing_columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN last_collected_at DATETIME")
    if "last_ipv4" not in existing_columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN last_ipv4 VARCHAR(64)")
    if "last_source_ip" not in existing_columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN last_source_ip VARCHAR(64)")
    if "last_heartbeat_at" not in existing_columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN last_heartbeat_at DATETIME")
    if "expected_interval_seconds" not in existing_columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN expected_interval_seconds INTEGER")
    if "activity_grace_multiplier" not in existing_columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN activity_grace_multiplier INTEGER")
    if "last_activity_status" not in existing_columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN last_activity_status VARCHAR(32)")
    if "inventory_baseline_id" not in existing_columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN inventory_baseline_id VARCHAR(128)")
    if "inventory_sequence_number" not in existing_columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN inventory_sequence_number INTEGER")
    if "inventory_current_hash" not in existing_columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN inventory_current_hash VARCHAR(128)")

    if statements:
        with engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))


ensure_endpoint_runtime_columns()


def ensure_performance_indexes() -> None:
    statements = [
        "CREATE INDEX IF NOT EXISTS idx_telemetry_records_endpoint_collected ON telemetry_records(endpoint_ref, collected_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_telemetry_records_endpoint_created ON telemetry_records(endpoint_ref, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_endpoint_lifecycle_endpoint_created ON endpoint_lifecycle_events(endpoint_id, created_at DESC)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


ensure_performance_indexes()


def enforce_latest_only_telemetry_records() -> None:
    with engine.begin() as connection:
        # Keep only the latest telemetry row per endpoint_ref.
        connection.execute(
            text(
                """
                DELETE FROM telemetry_records
                WHERE id NOT IN (
                    SELECT keeper.id
                    FROM telemetry_records AS keeper
                    WHERE keeper.id = (
                        SELECT candidate.id
                        FROM telemetry_records AS candidate
                        WHERE candidate.endpoint_ref = keeper.endpoint_ref
                        ORDER BY candidate.collected_at DESC, candidate.id DESC
                        LIMIT 1
                    )
                )
                """
            )
        )
        connection.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_telemetry_records_endpoint_ref ON telemetry_records(endpoint_ref)"
            )
        )


enforce_latest_only_telemetry_records()
logger.info("telemetry-api database initialized")

app = FastAPI(title="telemetry-api", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=parse_cors_origins(),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1200, compresslevel=6)


@app.middleware("http")
async def request_observability_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", "").strip() or str(uuid4())
    started_at = time.perf_counter()
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


@app.get("/healthz")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


def _apply_ingest_rate_limit(source_ip: str) -> None:
    now = time.monotonic()
    window_seconds = 60.0
    with _telemetry_rate_lock:
        bucket = _telemetry_rate_state[source_ip]
        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()
        if len(bucket) >= TELEMETRY_RATE_LIMIT_PER_MINUTE:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many telemetry requests from this source IP",
            )
        bucket.append(now)


def _inter_service_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if INTER_SERVICE_API_KEY:
        headers["X-API-Key"] = INTER_SERVICE_API_KEY
    return headers


def trigger_posture_evaluation(endpoint_id: str) -> None:
    if not POSTURE_TRIGGERS_EVALUATION:
        return
    url = f"{EVALUATION_ENGINE_URL.rstrip('/')}/evaluate-all/{quote_plus(endpoint_id)}"
    logger.info("triggering posture evaluation endpoint_id=%s url=%s", endpoint_id, url)
    request = UrlRequest(url=url, method="POST", data=b"{}", headers=_inter_service_headers())
    try:
        started_at = time.perf_counter()
        with urlopen(request, timeout=EVALUATION_HTTP_TIMEOUT_SECONDS) as response:
            raw = response.read().decode("utf-8")
        duration_ms = (time.perf_counter() - started_at) * 1000
        if duration_ms > SLOW_EVALUATION_WARNING_MS:
            logger.warning(
                "slow posture evaluation trigger endpoint_id=%s duration_ms=%.2f",
                endpoint_id,
                duration_ms,
            )
        evaluated_count = 0
        if raw:
            payload = json.loads(raw)
            if isinstance(payload, list):
                evaluated_count = len(payload)
        logger.info(
            "posture evaluation triggered endpoint_id=%s evaluated_policy_count=%s",
            endpoint_id,
            evaluated_count,
        )
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        logger.warning("failed to trigger posture evaluation endpoint_id=%s error=%s", endpoint_id, exc)


def _parse_first_valid_ip(raw_value: str | None) -> str | None:
    if not raw_value:
        return None
    candidates = [item.strip() for item in raw_value.split(",") if item.strip()]
    for candidate in candidates:
        token = candidate
        if token.lower().startswith("for="):
            token = token[4:]
        token = token.strip().strip('"').strip("[]")
        if ";" in token:
            token = token.split(";", 1)[0].strip()
        if token.count(":") > 1 and "]:" in candidate:
            token = token.split("]:", 1)[0]
        elif token.count(":") == 1 and token.rsplit(":", 1)[1].isdigit():
            token = token.rsplit(":", 1)[0]
        try:
            return str(ipaddress.ip_address(token))
        except ValueError:
            continue
    return None


def resolve_client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    parsed_forwarded_for = _parse_first_valid_ip(forwarded_for)
    if parsed_forwarded_for:
        return parsed_forwarded_for

    real_ip = request.headers.get("x-real-ip")
    parsed_real_ip = _parse_first_valid_ip(real_ip)
    if parsed_real_ip:
        return parsed_real_ip

    forwarded = request.headers.get("forwarded")
    parsed_forwarded = _parse_first_valid_ip(forwarded)
    if parsed_forwarded:
        return parsed_forwarded

    fallback = request.client.host if request.client else None
    if not fallback:
        return None
    try:
        return str(ipaddress.ip_address(fallback))
    except ValueError:
        return fallback


def _stable_hash(payload: Any) -> str:
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


async def _read_telemetry_body(request: Request) -> tuple[dict[str, Any], int]:
    content_length = request.headers.get("content-length", "").strip()
    if content_length:
        try:
            if int(content_length) > MAX_TELEMETRY_BODY_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="Telemetry payload is too large",
                )
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header")

    body = await request.body()
    if len(body) > MAX_TELEMETRY_BODY_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Telemetry payload is too large",
        )
    if request.headers.get("content-encoding", "").lower() == "gzip":
        if not ACCEPT_GZIP_TELEMETRY:
            raise HTTPException(status_code=415, detail="Gzip telemetry is disabled")
        try:
            body = gzip.decompress(body)
        except OSError as exc:
            # Some HTTP stacks or proxies may decompress the body but leave the
            # original Content-Encoding header in place. Accept it only if the
            # remaining body is valid JSON; otherwise keep the normal 400.
            try:
                json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise HTTPException(status_code=400, detail="Invalid gzip telemetry payload") from exc
            logger.warning("telemetry payload had gzip header but body was already plain JSON")
        if len(body) > MAX_TELEMETRY_BODY_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Telemetry payload is too large",
            )
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid telemetry JSON payload") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Telemetry payload must be a JSON object")
    return payload, len(body)


def _parse_collected_at(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)


def _payload_network_ipv4(payload: dict[str, Any]) -> str | None:
    network = payload.get("network")
    if isinstance(network, dict):
        value = network.get("ipv4")
        if value:
            return str(value)
    for key in ("ip_address", "current_ip", "ipv4"):
        if payload.get(key):
            return str(payload[key])
    return None


def _payload_agent_interval(payload: dict[str, Any], payload_type: str) -> int:
    agent = payload.get("agent")
    if isinstance(agent, dict) and agent.get("interval_seconds"):
        try:
            return max(1, int(agent["interval_seconds"]))
        except (TypeError, ValueError):
            pass
    if payload_type == "heartbeat":
        return HEARTBEAT_INTERVAL_SECONDS
    if payload_type == "posture_snapshot":
        return int(os.getenv("POSTURE_INTERVAL_SECONDS", str(HEARTBEAT_INTERVAL_SECONDS)))
    if payload_type == "inventory_delta":
        return int(os.getenv("INVENTORY_DELTA_INTERVAL_SECONDS", "10"))
    return int(os.getenv("INVENTORY_FULL_INTERVAL_SECONDS", "900"))


def _extract_endpoint_identity(payload: dict[str, Any]) -> tuple[str, str]:
    endpoint_id = (
        payload.get("endpoint_id")
        or payload.get("endpoint_ref")
        or payload.get("device_id")
        or payload.get("machine_guid")
    )
    if not endpoint_id:
        raise HTTPException(status_code=422, detail="Telemetry payload requires endpoint_id or endpoint_ref")
    hostname = payload.get("hostname") or payload.get("host_name") or str(endpoint_id)
    return str(endpoint_id), str(hostname)


def _normalize_endpoint_telemetry_payload(payload: dict[str, Any], payload_type: str) -> dict[str, Any]:
    endpoint_id, hostname = _extract_endpoint_identity(payload)
    normalized = dict(payload)
    normalized["schema_version"] = str(normalized.get("schema_version") or "1.0")
    normalized["collector_type"] = str(normalized.get("collector_type") or normalized.get("payload_type") or payload_type)
    normalized["endpoint_id"] = endpoint_id
    normalized["hostname"] = hostname
    normalized["collected_at"] = normalized.get("collected_at") or datetime.now(timezone.utc).isoformat()
    normalized["network"] = normalized.get("network") if isinstance(normalized.get("network"), dict) else {}
    normalized["network"]["ipv4"] = _payload_network_ipv4(payload)
    normalized["os"] = normalized.get("os") if isinstance(normalized.get("os"), dict) else {}
    normalized["hotfixes"] = normalized.get("hotfixes") if isinstance(normalized.get("hotfixes"), list) else []
    normalized["services"] = normalized.get("services") if isinstance(normalized.get("services"), list) else []
    normalized["processes"] = normalized.get("processes") if isinstance(normalized.get("processes"), list) else []
    normalized["antivirus_products"] = (
        normalized.get("antivirus_products") if isinstance(normalized.get("antivirus_products"), list) else []
    )
    normalized["agent"] = normalized.get("agent") if isinstance(normalized.get("agent"), dict) else {}
    normalized["agent"]["interval_seconds"] = _payload_agent_interval(payload, payload_type)
    normalized["agent"]["active_grace_multiplier"] = ACTIVITY_GRACE_MULTIPLIER
    normalized["extras"] = normalized.get("extras") if isinstance(normalized.get("extras"), dict) else {}
    normalized["extras"]["payload_type"] = payload_type
    return normalized


def _upsert_endpoint_liveness(
    *,
    db: Session,
    payload: dict[str, Any],
    payload_type: str,
    source_ip: str | None,
) -> tuple[Endpoint, bool, datetime]:
    endpoint_id, hostname = _extract_endpoint_identity(payload)
    collected_at = _parse_collected_at(payload.get("collected_at"))
    endpoint = db.scalar(select(Endpoint).where(Endpoint.endpoint_id == endpoint_id))
    created_endpoint = False
    if endpoint is None:
        endpoint = Endpoint(endpoint_id=endpoint_id, hostname=hostname)
        db.add(endpoint)
        db.flush()
        created_endpoint = True

    now = datetime.now(timezone.utc)
    endpoint.hostname = hostname
    endpoint.last_ipv4 = _payload_network_ipv4(payload)
    endpoint.last_source_ip = source_ip
    endpoint.last_seen = now
    endpoint.last_heartbeat_at = now
    endpoint.last_collected_at = collected_at
    endpoint.expected_interval_seconds = _payload_agent_interval(payload, payload_type)
    endpoint.activity_grace_multiplier = ACTIVITY_GRACE_MULTIPLIER
    endpoint.last_activity_status = "active"
    db.commit()
    db.refresh(endpoint)
    return endpoint, created_endpoint, now


def _store_latest_telemetry_record(
    *,
    db: Session,
    endpoint: Endpoint,
    telemetry: EndpointTelemetry,
    payload: dict[str, Any],
    payload_type: str,
    source_ip: str | None,
) -> TelemetryRecord:
    telemetry_payload = telemetry.model_dump(mode="json")
    telemetry_payload.update({"raw_input": payload, "payload_type": payload_type})
    extras = telemetry_payload.get("extras")
    if not isinstance(extras, dict):
        extras = {}
    if source_ip:
        extras["connection_source_ip"] = source_ip
    telemetry_payload["extras"] = extras

    record = db.scalar(select(TelemetryRecord).where(TelemetryRecord.endpoint_ref == endpoint.id))
    if record is None:
        record = TelemetryRecord(
            endpoint_ref=endpoint.id,
            collected_at=telemetry.collected_at,
            source_ip=source_ip,
            collector_type=telemetry.collector_type,
            telemetry_type=payload_type,
            core_ipv4=telemetry.network.ipv4,
            core_os_name=telemetry.os.name,
            core_os_version=telemetry.os.version,
            core_os_build=telemetry.os.build,
            raw_payload=telemetry_payload,
        )
        db.add(record)
    else:
        record.collected_at = telemetry.collected_at
        record.source_ip = source_ip
        record.collector_type = telemetry.collector_type
        record.telemetry_type = payload_type
        record.core_ipv4 = telemetry.network.ipv4
        record.core_os_name = telemetry.os.name
        record.core_os_version = telemetry.os.version
        record.core_os_build = telemetry.os.build
        record.raw_payload = telemetry_payload
        record.created_at = datetime.now(timezone.utc)
    db.flush()
    db.commit()
    db.refresh(record)
    return record


def _inventory_delta_resync_reason(endpoint: Endpoint, payload: dict[str, Any]) -> str | None:
    baseline_id = payload.get("baseline_id")
    sequence_number = payload.get("sequence_number")
    previous_hash = payload.get("previous_hash")
    if not baseline_id or baseline_id != endpoint.inventory_baseline_id:
        return "baseline_mismatch"
    try:
        sequence_number = int(sequence_number)
    except (TypeError, ValueError):
        return "invalid_sequence_number"
    expected_sequence = (endpoint.inventory_sequence_number or 0) + 1
    if INVENTORY_RESYNC_ON_SEQUENCE_GAP and sequence_number != expected_sequence:
        return "sequence_gap"
    if INVENTORY_RESYNC_ON_HASH_MISMATCH and previous_hash and endpoint.inventory_current_hash:
        if previous_hash != endpoint.inventory_current_hash:
            return "hash_mismatch"
    return None


async def _submit_payload(
    *,
    payload_type: str,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session,
) -> TelemetryIngestResponse:
    started_at = time.perf_counter()
    payload, payload_size = await _read_telemetry_body(request)
    source_ip = resolve_client_ip(request)
    if source_ip is not None:
        _apply_ingest_rate_limit(source_ip)
    endpoint_id, hostname = _extract_endpoint_identity(payload)
    reported_ipv4 = _payload_network_ipv4(payload)
    if LOG_TELEMETRY_PAYLOAD_SIZE:
        logger.info(
            "telemetry received payload_type=%s endpoint_id=%s hostname=%s source_ip=%s reported_ipv4=%s payload_bytes=%s",
            payload_type,
            endpoint_id,
            hostname,
            source_ip,
            reported_ipv4,
            payload_size,
        )

    endpoint, created_endpoint, stored_at = _upsert_endpoint_liveness(
        db=db,
        payload=payload,
        payload_type=payload_type,
        source_ip=source_ip,
    )

    if payload_type == "heartbeat":
        logger.info(
            "stored heartbeat endpoint_id=%s source_ip=%s created_endpoint=%s trigger_evaluation=false",
            endpoint.endpoint_id,
            source_ip,
            created_endpoint,
        )
        return TelemetryIngestResponse(
            endpoint_id=endpoint.endpoint_id,
            record_id=None,
            stored_at=stored_at,
            payload_type=payload_type,
            evaluation_triggered=False,
        )

    if payload_type == "inventory_delta":
        reason = _inventory_delta_resync_reason(endpoint, payload)
        if reason is not None:
            logger.warning(
                "inventory delta requires resync endpoint_id=%s reason=%s baseline_id=%s sequence_number=%s",
                endpoint.endpoint_id,
                reason,
                payload.get("baseline_id"),
                payload.get("sequence_number"),
            )
            return TelemetryIngestResponse(
                endpoint_id=endpoint.endpoint_id,
                record_id=None,
                stored_at=stored_at,
                payload_type=payload_type,
                evaluation_triggered=False,
                resync_required=True,
                reason=reason,
            )

    normalized_payload = _normalize_endpoint_telemetry_payload(payload, payload_type)
    try:
        telemetry = EndpointTelemetry.model_validate(normalized_payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    record = _store_latest_telemetry_record(
        db=db,
        endpoint=endpoint,
        telemetry=telemetry,
        payload=payload,
        payload_type=payload_type,
        source_ip=source_ip,
    )

    if payload_type == "inventory_full":
        endpoint.inventory_baseline_id = str(payload.get("baseline_id") or payload.get("baseline") or _stable_hash(payload))
        try:
            endpoint.inventory_sequence_number = int(payload.get("sequence_number") or 0)
        except (TypeError, ValueError):
            endpoint.inventory_sequence_number = 0
        endpoint.inventory_current_hash = str(payload.get("current_hash") or _stable_hash(payload))
        db.commit()
    elif payload_type == "inventory_delta":
        try:
            endpoint.inventory_sequence_number = int(payload.get("sequence_number"))
        except (TypeError, ValueError):
            endpoint.inventory_sequence_number = endpoint.inventory_sequence_number or 0
        endpoint.inventory_current_hash = str(payload.get("current_hash") or _stable_hash(payload))
        db.commit()

    evaluation_triggered = False
    trigger_evaluation = (
        (payload_type in {"legacy", "posture_snapshot"} and POSTURE_TRIGGERS_EVALUATION)
        or (payload_type == "inventory_full" and INVENTORY_FULL_TRIGGERS_EVALUATION)
        or (payload_type == "inventory_delta" and INVENTORY_DELTA_TRIGGERS_EVALUATION)
    )
    if payload_type == "posture_snapshot" and SKIP_EVALUATION_IF_POSTURE_HASH_UNCHANGED and not FORCE_EVALUATION_ON_EVERY_POSTURE:
        trigger_evaluation = False
    if trigger_evaluation:
        evaluation_triggered = True
        if PROCESS_POSTURE_IN_BACKGROUND:
            background_tasks.add_task(trigger_posture_evaluation, endpoint.endpoint_id)
        else:
            trigger_posture_evaluation(endpoint.endpoint_id)

    logger.info(
        "stored telemetry payload_type=%s endpoint_id=%s hostname=%s source_ip=%s record_id=%s interval=%s grace_multiplier=%s activity_timeout=%s created_endpoint=%s trigger_evaluation=%s",
        payload_type,
        endpoint.endpoint_id,
        endpoint.hostname,
        source_ip,
        record.id,
        telemetry.agent.interval_seconds,
        endpoint.activity_grace_multiplier,
        ENDPOINT_INACTIVE_AFTER_SECONDS
        if payload_type == "heartbeat"
        else (endpoint.expected_interval_seconds or 0) * (endpoint.activity_grace_multiplier or DEFAULT_ACTIVITY_GRACE_MULTIPLIER),
        created_endpoint,
        evaluation_triggered,
    )
    duration_ms = (time.perf_counter() - started_at) * 1000
    if LOG_TELEMETRY_PROCESSING_DURATION:
        log_method = logger.warning if duration_ms > SLOW_TELEMETRY_WARNING_MS else logger.info
        log_method(
            "telemetry processed payload_type=%s endpoint_id=%s duration_ms=%.2f",
            payload_type,
            endpoint.endpoint_id,
            duration_ms,
        )

    return TelemetryIngestResponse(
        endpoint_id=endpoint.endpoint_id,
        record_id=record.id,
        stored_at=record.created_at,
        payload_type=payload_type,
        evaluation_triggered=evaluation_triggered,
    )


@app.post("/telemetry", response_model=TelemetryIngestResponse, status_code=status.HTTP_201_CREATED)
async def submit_telemetry(
    request: Request,
    background_tasks: BackgroundTasks,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> TelemetryIngestResponse:
    return await _submit_payload(
        payload_type="legacy",
        request=request,
        background_tasks=background_tasks,
        db=db,
    )


@app.post("/telemetry/heartbeat", response_model=TelemetryIngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def submit_heartbeat(
    request: Request,
    background_tasks: BackgroundTasks,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> TelemetryIngestResponse:
    return await _submit_payload(
        payload_type="heartbeat",
        request=request,
        background_tasks=background_tasks,
        db=db,
    )


@app.post("/telemetry/posture", response_model=TelemetryIngestResponse, status_code=status.HTTP_201_CREATED)
async def submit_posture_snapshot(
    request: Request,
    background_tasks: BackgroundTasks,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> TelemetryIngestResponse:
    return await _submit_payload(
        payload_type="posture_snapshot",
        request=request,
        background_tasks=background_tasks,
        db=db,
    )


@app.post("/telemetry/inventory/full", response_model=TelemetryIngestResponse, status_code=status.HTTP_201_CREATED)
async def submit_inventory_full(
    request: Request,
    background_tasks: BackgroundTasks,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> TelemetryIngestResponse:
    return await _submit_payload(
        payload_type="inventory_full",
        request=request,
        background_tasks=background_tasks,
        db=db,
    )


@app.post("/telemetry/inventory/delta", response_model=TelemetryIngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def submit_inventory_delta(
    request: Request,
    background_tasks: BackgroundTasks,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> TelemetryIngestResponse:
    return await _submit_payload(
        payload_type="inventory_delta",
        request=request,
        background_tasks=background_tasks,
        db=db,
    )


@app.get("/endpoints", response_model=list[EndpointSummary])
def list_endpoints(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=100000),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> list[EndpointSummary]:
    reconcile_inactive_transitions(db=db, logger=logger)
    endpoints = db.scalars(select(Endpoint).order_by(desc(Endpoint.last_seen)).offset(offset).limit(limit)).all()
    summaries = [build_endpoint_summary(item) for item in endpoints]
    logger.info("listed %s endpoints", len(summaries))
    return summaries


@app.get("/endpoints/{endpoint_id}/latest", response_model=TelemetryRecordResponse)
def get_latest_telemetry(
    endpoint_id: str,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> TelemetryRecordResponse:
    endpoint = db.scalar(select(Endpoint).where(Endpoint.endpoint_id == endpoint_id))
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    record = db.scalar(select(TelemetryRecord).where(TelemetryRecord.endpoint_ref == endpoint.id))
    if record is None:
        raise HTTPException(status_code=404, detail="Telemetry not found")

    return build_record_response(record, endpoint)


def _trim_raw_payload(raw_payload: dict) -> dict:
    hotfixes = raw_payload.get("hotfixes")
    services = raw_payload.get("services")
    processes = raw_payload.get("processes")
    antivirus = raw_payload.get("antivirus_products")
    trimmed = dict(raw_payload)
    if "hotfixes" in trimmed:
        trimmed["hotfixes"] = []
    if "services" in trimmed:
        trimmed["services"] = []
    if "processes" in trimmed:
        trimmed["processes"] = []
    trimmed["hotfixes_count"] = len(hotfixes) if isinstance(hotfixes, list) else 0
    trimmed["services_count"] = len(services) if isinstance(services, list) else 0
    trimmed["processes_count"] = len(processes) if isinstance(processes, list) else 0
    trimmed["antivirus_count"] = len(antivirus) if isinstance(antivirus, list) else 0
    return trimmed


@app.get("/endpoints/latest-batch", response_model=list[TelemetryRecordResponse])
def get_latest_telemetry_batch(
    endpoint_id: list[str] = Query(default=[]),
    include_raw: bool = Query(default=False),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> list[TelemetryRecordResponse]:
    endpoint_ids = [item.strip() for item in endpoint_id if item.strip()]
    if not endpoint_ids:
        return []

    endpoints = db.scalars(select(Endpoint).where(Endpoint.endpoint_id.in_(endpoint_ids))).all()
    endpoint_by_ref = {item.id: item for item in endpoints}
    if not endpoint_by_ref:
        return []

    records = db.scalars(select(TelemetryRecord).where(TelemetryRecord.endpoint_ref.in_(list(endpoint_by_ref.keys())))).all()
    latest_by_endpoint_ref = {record.endpoint_ref: record for record in records}

    response_items: list[TelemetryRecordResponse] = []
    endpoint_order = {endpoint_id_value: index for index, endpoint_id_value in enumerate(endpoint_ids)}
    for endpoint_ref, record in latest_by_endpoint_ref.items():
        endpoint = endpoint_by_ref.get(endpoint_ref)
        if endpoint is None:
            continue
        raw_payload = record.raw_payload
        if not include_raw:
            raw_payload = _trim_raw_payload(raw_payload)
        response_items.append(
            TelemetryRecordResponse(
                id=record.id,
                endpoint_id=endpoint.endpoint_id,
                hostname=endpoint.hostname,
                collected_at=record.collected_at,
                source_ip=record.source_ip,
                collector_type=record.collector_type,
                telemetry_type=record.telemetry_type,
                core_ipv4=record.core_ipv4,
                core_os_name=record.core_os_name,
                core_os_version=record.core_os_version,
                core_os_build=record.core_os_build,
                raw_payload=raw_payload,
            )
        )
    response_items.sort(key=lambda item: endpoint_order.get(item.endpoint_id, 10_000_000))
    return response_items


@app.get("/endpoints/{endpoint_id}/history", response_model=list[TelemetryRecordResponse])
def get_telemetry_history(
    endpoint_id: str,
    limit: int = Query(default=20, ge=1, le=200),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> list[TelemetryRecordResponse]:
    endpoint = db.scalar(select(Endpoint).where(Endpoint.endpoint_id == endpoint_id))
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    records = db.scalars(select(TelemetryRecord).where(TelemetryRecord.endpoint_ref == endpoint.id).limit(limit)).all()
    return [build_record_response(record, endpoint) for record in records]


@app.get("/lifecycle-events", response_model=list[LifecycleEventResponse])
def list_lifecycle_events(
    endpoint_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> list[LifecycleEventResponse]:
    reconcile_inactive_transitions(db=db, logger=logger)
    query = select(EndpointLifecycleEvent).order_by(desc(EndpointLifecycleEvent.created_at)).limit(limit)
    if endpoint_id:
        query = query.where(EndpointLifecycleEvent.endpoint_id == endpoint_id)
    events = db.scalars(query).all()
    return [build_lifecycle_event_response(event) for event in events]
