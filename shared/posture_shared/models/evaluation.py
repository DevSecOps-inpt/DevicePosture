from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


class EvaluationReason(BaseModel):
    check_type: str
    message: str


class ComplianceDecision(BaseModel):
    endpoint_id: str
    endpoint_ip: str | None = None
    policy_id: int | None = None
    policy_name: str | None = None
    compliant: bool
    recommended_action: Literal["allow", "quarantine", "block"] = "allow"
    reasons: list[EvaluationReason] = Field(default_factory=list)
    execution_plan: dict = Field(default_factory=dict)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    telemetry_timestamp: datetime | None = None
