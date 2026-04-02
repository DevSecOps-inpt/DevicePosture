from datetime import datetime

from pydantic import BaseModel, ConfigDict

from posture_shared.models.telemetry import EndpointTelemetry


class TelemetryIngestResponse(BaseModel):
    endpoint_id: str
    record_id: int
    stored_at: datetime


class EndpointSummary(BaseModel):
    endpoint_id: str
    hostname: str
    last_seen: datetime
    last_collected_at: datetime | None = None
    expected_interval_seconds: int | None = None
    activity_grace_multiplier: int | None = None
    activity_timeout_seconds: int | None = None
    activity_status: str = "unknown"
    is_active: bool | None = None
    seconds_since_seen: float | None = None


class TelemetryRecordResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    endpoint_id: str
    hostname: str
    collected_at: datetime
    source_ip: str | None = None
    collector_type: str
    telemetry_type: str
    core_ipv4: str | None = None
    core_os_name: str | None = None
    core_os_version: str | None = None
    core_os_build: str | None = None
    raw_payload: dict


class LifecycleEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    endpoint_id: str
    event_type: str
    previous_status: str | None = None
    current_status: str | None = None
    matched_policy_id: int | None = None
    matched_policy_name: str | None = None
    execution_state: str
    details: dict
    created_at: datetime


def build_record_response(record, endpoint) -> TelemetryRecordResponse:
    return TelemetryRecordResponse(
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
        raw_payload=record.raw_payload,
    )


def build_lifecycle_event_response(event) -> LifecycleEventResponse:
    return LifecycleEventResponse(
        id=event.id,
        endpoint_id=event.endpoint_id,
        event_type=event.event_type,
        previous_status=event.previous_status,
        current_status=event.current_status,
        matched_policy_id=event.matched_policy_id,
        matched_policy_name=event.matched_policy_name,
        execution_state=event.execution_state,
        details=event.details,
        created_at=event.created_at,
    )
