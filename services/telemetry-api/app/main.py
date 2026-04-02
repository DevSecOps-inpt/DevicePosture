import logging
from pathlib import Path
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
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
logger.info("telemetry-api database initialized")

app = FastAPI(title="telemetry-api", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/healthz")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/telemetry", response_model=TelemetryIngestResponse, status_code=status.HTTP_201_CREATED)
def submit_telemetry(
    telemetry: EndpointTelemetry,
    request: Request,
    db: Session = Depends(get_db),
) -> TelemetryIngestResponse:
    source_ip = request.client.host if request.client else None
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
def list_endpoints(db: Session = Depends(get_db)) -> list[EndpointSummary]:
    reconcile_inactive_transitions(db=db, logger=logger)
    endpoints = db.scalars(select(Endpoint).order_by(desc(Endpoint.last_seen))).all()
    summaries = [build_endpoint_summary(item) for item in endpoints]
    logger.info("listed %s endpoints", len(summaries))
    return summaries


@app.get("/endpoints/{endpoint_id}/latest", response_model=TelemetryRecordResponse)
def get_latest_telemetry(endpoint_id: str, db: Session = Depends(get_db)) -> TelemetryRecordResponse:
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


@app.get("/endpoints/{endpoint_id}/history", response_model=list[TelemetryRecordResponse])
def get_telemetry_history(
    endpoint_id: str,
    limit: int = Query(default=20, ge=1, le=200),
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
    db: Session = Depends(get_db),
) -> list[LifecycleEventResponse]:
    reconcile_inactive_transitions(db=db, logger=logger)
    query = select(EndpointLifecycleEvent).order_by(desc(EndpointLifecycleEvent.created_at)).limit(limit)
    if endpoint_id:
        query = query.where(EndpointLifecycleEvent.endpoint_id == endpoint_id)
    events = db.scalars(query).all()
    return [build_lifecycle_event_response(event) for event in events]
