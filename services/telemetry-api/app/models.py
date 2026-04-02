from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    last_ipv4: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expected_interval_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    activity_grace_multiplier: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_activity_status: Mapped[str | None] = mapped_column(String(32), nullable=True)

    telemetry_records: Mapped[list["TelemetryRecord"]] = relationship(
        back_populates="endpoint",
        cascade="all, delete-orphan",
    )
    lifecycle_events: Mapped[list["EndpointLifecycleEvent"]] = relationship(
        back_populates="endpoint",
        cascade="all, delete-orphan",
    )


class TelemetryRecord(Base):
    __tablename__ = "telemetry_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_ref: Mapped[int] = mapped_column(ForeignKey("endpoints.id"), index=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    collector_type: Mapped[str] = mapped_column(String(64), default="unknown")
    telemetry_type: Mapped[str] = mapped_column(String(64), default="endpoint_posture")
    core_ipv4: Mapped[str | None] = mapped_column(String(64), nullable=True)
    core_os_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    core_os_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    core_os_build: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_payload: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    endpoint: Mapped[Endpoint] = relationship(back_populates="telemetry_records")


class EndpointLifecycleEvent(Base):
    __tablename__ = "endpoint_lifecycle_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_ref: Mapped[int] = mapped_column(ForeignKey("endpoints.id"), index=True)
    endpoint_id: Mapped[str] = mapped_column(String(128), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    previous_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    current_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    matched_policy_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    matched_policy_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    execution_state: Mapped[str] = mapped_column(String(32), default="pending")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    endpoint: Mapped[Endpoint] = relationship(back_populates="lifecycle_events")
