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


class AuthProviderModel(Base):
    __tablename__ = "auth_providers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    protocol: Mapped[str] = mapped_column(String(32), index=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    priority: Mapped[int] = mapped_column(Integer, default=100, index=True)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AuthProviderDirectoryGroupModel(Base):
    __tablename__ = "auth_provider_directory_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider_id: Mapped[int] = mapped_column(ForeignKey("auth_providers.id"), index=True)
    group_key: Mapped[str] = mapped_column(String(255), index=True)
    group_name: Mapped[str] = mapped_column(String(255), index=True)
    group_dn: Mapped[str | None] = mapped_column(String(1024), nullable=True, index=True)
    is_computer_group: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class UserAccountModel(Base):
    __tablename__ = "user_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    auth_source: Mapped[str] = mapped_column(String(32), default="local", index=True)
    external_provider_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    local_password_hash: Mapped[str | None] = mapped_column(String(512), nullable=True)
    external_subject: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    external_groups: Mapped[list[str]] = mapped_column(JSON, default=list)
    roles: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
