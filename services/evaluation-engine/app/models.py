from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EvaluationResultModel(Base):
    __tablename__ = "evaluation_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[str] = mapped_column(String(128), index=True)
    policy_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    policy_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    compliant: Mapped[bool] = mapped_column(Boolean, index=True)
    recommended_action: Mapped[str] = mapped_column(String(32))
    reasons: Mapped[list[dict]] = mapped_column(JSON, default=list)
    raw_result: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
