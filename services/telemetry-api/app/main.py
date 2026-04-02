import logging
import os
import threading
import time
from collections import defaultdict, deque
from uuid import uuid4
from pathlib import Path
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from sqlalchemy import desc, inspect, select, text
from sqlalchemy.orm import Session

from app.activity import DEFAULT_ACTIVITY_GRACE_MULTIPLIER, build_endpoint_summary
from app.db import Base, engine, get_db
from app.lifecycle import (
    EVENT_INACTIVE_TO_ACTIVE,
    EVENT_TELEMETRY_RECEIVED,
    create_lifecycle_event,
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

MAX_TELEMETRY_BODY_BYTES = int(os.getenv("MAX_TELEMETRY_BODY_BYTES", "1048576"))
TELEMETRY_RATE_LIMIT_PER_MINUTE = int(os.getenv("TELEMETRY_RATE_LIMIT_PER_MINUTE", "120"))
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
    if "expected_interval_seconds" not in existing_columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN expected_interval_seconds INTEGER")
    if "activity_grace_multiplier" not in existing_columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN activity_grace_multiplier INTEGER")
    if "last_activity_status" not in existing_columns:
        statements.append("ALTER TABLE endpoints ADD COLUMN last_activity_status VARCHAR(32)")

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


@app.post("/telemetry", response_model=TelemetryIngestResponse, status_code=status.HTTP_201_CREATED)
def submit_telemetry(
    telemetry: EndpointTelemetry,
    request: Request,
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> TelemetryIngestResponse:
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

    source_ip = request.client.host if request.client else None
    if source_ip is not None:
        _apply_ingest_rate_limit(source_ip)

    endpoint = db.scalar(select(Endpoint).where(Endpoint.endpoint_id == telemetry.endpoint_id))
    created_endpoint = False
    previous_status = None
    if endpoint is None:
        endpoint = Endpoint(endpoint_id=telemetry.endpoint_id, hostname=telemetry.hostname)
        db.add(endpoint)
        db.flush()
        created_endpoint = True
        previous_status = "unknown"
    else:
        previous_status = endpoint.last_activity_status or "unknown"

    endpoint.hostname = telemetry.hostname
    endpoint.last_ipv4 = telemetry.network.ipv4
    endpoint.last_seen = datetime.now(timezone.utc)
    endpoint.last_collected_at = telemetry.collected_at
    endpoint.expected_interval_seconds = telemetry.agent.interval_seconds
    endpoint.activity_grace_multiplier = telemetry.agent.active_grace_multiplier or DEFAULT_ACTIVITY_GRACE_MULTIPLIER
    endpoint.last_activity_status = "active"

    record = TelemetryRecord(
        endpoint_ref=endpoint.id,
        collected_at=telemetry.collected_at,
        source_ip=source_ip,
        collector_type=telemetry.collector_type,
        telemetry_type="endpoint_posture",
        core_ipv4=telemetry.network.ipv4,
        core_os_name=telemetry.os.name,
        core_os_version=telemetry.os.version,
        core_os_build=telemetry.os.build,
        raw_payload=telemetry.model_dump(mode="json"),
    )
    db.add(record)
    db.flush()
    lifecycle_event_type = EVENT_TELEMETRY_RECEIVED
    common_event_details = {
        "record_id": record.id,
        "collector_type": telemetry.collector_type,
        "source_ip": source_ip,
        "endpoint_ip": telemetry.network.ipv4,
    }
    if previous_status == "inactive":
        create_lifecycle_event(
            db=db,
            endpoint=endpoint,
            event_type=EVENT_INACTIVE_TO_ACTIVE,
            previous_status=previous_status,
            current_status="active",
            details=common_event_details,
            telemetry_payload=record.raw_payload,
            logger=logger,
        )

    create_lifecycle_event(
        db=db,
        endpoint=endpoint,
        event_type=EVENT_TELEMETRY_RECEIVED,
        previous_status=previous_status,
        current_status="active",
        details=common_event_details,
        telemetry_payload=record.raw_payload,
        logger=logger,
    )
    db.commit()
    db.refresh(record)

    logger.info(
        "stored telemetry endpoint_id=%s hostname=%s source_ip=%s record_id=%s interval=%s grace_multiplier=%s activity_timeout=%s created_endpoint=%s lifecycle_event=%s",
        telemetry.endpoint_id,
        telemetry.hostname,
        source_ip,
        record.id,
        telemetry.agent.interval_seconds,
        endpoint.activity_grace_multiplier,
        (endpoint.expected_interval_seconds or 0) * (endpoint.activity_grace_multiplier or DEFAULT_ACTIVITY_GRACE_MULTIPLIER),
        created_endpoint,
        lifecycle_event_type,
    )

    return TelemetryIngestResponse(
        endpoint_id=telemetry.endpoint_id,
        record_id=record.id,
        stored_at=record.created_at,
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
    reconcile_inactive_transitions(db=db, logger=logger)
    endpoint = db.scalar(select(Endpoint).where(Endpoint.endpoint_id == endpoint_id))
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    record = db.scalar(
        select(TelemetryRecord)
        .where(TelemetryRecord.endpoint_ref == endpoint.id)
        .order_by(desc(TelemetryRecord.collected_at))
    )
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

    records = db.scalars(
        select(TelemetryRecord)
        .where(TelemetryRecord.endpoint_ref.in_(list(endpoint_by_ref.keys())))
        .order_by(TelemetryRecord.endpoint_ref, desc(TelemetryRecord.collected_at), desc(TelemetryRecord.id))
    ).all()
    latest_by_endpoint_ref: dict[int, TelemetryRecord] = {}
    for record in records:
        if record.endpoint_ref not in latest_by_endpoint_ref:
            latest_by_endpoint_ref[record.endpoint_ref] = record

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
    reconcile_inactive_transitions(db=db, logger=logger)
    endpoint = db.scalar(select(Endpoint).where(Endpoint.endpoint_id == endpoint_id))
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    records = db.scalars(
        select(TelemetryRecord)
        .where(TelemetryRecord.endpoint_ref == endpoint.id)
        .order_by(desc(TelemetryRecord.collected_at))
        .limit(limit)
    ).all()
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
