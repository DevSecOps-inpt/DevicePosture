from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    policy_scope: Mapped[str] = mapped_column(String(32), default="posture", index=True)
    lifecycle_event_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    target_action: Mapped[str] = mapped_column(String(32), default="quarantine")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    conditions: Mapped[list[dict]] = mapped_column(JSON, default=list)
    execution: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    assignments: Mapped[list["PolicyAssignmentModel"]] = relationship(
        back_populates="policy",
        cascade="all, delete-orphan",
    )


class PolicyAssignmentModel(Base):
    __tablename__ = "policy_assignments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id"), index=True)
    assignment_type: Mapped[str] = mapped_column(String(32), index=True)
    assignment_value: Mapped[str] = mapped_column(String(255), index=True)

    policy: Mapped[Policy] = relationship(back_populates="assignments")


class ConditionGroupModel(Base):
    __tablename__ = "condition_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    group_type: Mapped[str] = mapped_column(String(32), index=True)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    values: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
