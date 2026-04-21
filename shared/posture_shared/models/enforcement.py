from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


class EnforcementAction(BaseModel):
    adapter: str = "fortigate"
    action: Literal["quarantine", "allow", "block", "remove_from_group", "sync_group", "move_between_groups"] = "quarantine"
    endpoint_id: str
    ip_address: str
    group_name: str | None = None
    adapter_profile: str | None = None
    decision: dict = Field(default_factory=dict)
    requested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EnforcementResult(BaseModel):
    adapter: str
    action: str
    endpoint_id: str
    status: Literal["success", "skipped", "failed"]
    details: dict = Field(default_factory=dict)
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
