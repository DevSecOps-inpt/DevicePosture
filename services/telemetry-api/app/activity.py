from datetime import datetime, timezone

from app.models import Endpoint
from app.schemas import EndpointSummary


DEFAULT_ACTIVITY_GRACE_MULTIPLIER = 3


def _to_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def compute_endpoint_activity(
    *,
    last_seen: datetime | None,
    expected_interval_seconds: int | None,
    grace_multiplier: int | None,
    now: datetime | None = None,
) -> tuple[str, bool | None, int | None, float | None]:
    normalized_last_seen = _to_utc(last_seen)
    if normalized_last_seen is None or expected_interval_seconds is None or expected_interval_seconds <= 0:
        return "unknown", None, None, None

    multiplier = max(1, grace_multiplier or DEFAULT_ACTIVITY_GRACE_MULTIPLIER)
    timeout_seconds = expected_interval_seconds * multiplier
    checked_at = now or datetime.now(timezone.utc)
    lag_seconds = max(0.0, (checked_at - normalized_last_seen).total_seconds())
    is_active = lag_seconds <= timeout_seconds
    return ("active" if is_active else "inactive"), is_active, timeout_seconds, lag_seconds


def build_endpoint_summary(endpoint: Endpoint) -> EndpointSummary:
    activity_status, is_active, activity_timeout_seconds, seconds_since_seen = compute_endpoint_activity(
        last_seen=endpoint.last_seen,
        expected_interval_seconds=endpoint.expected_interval_seconds,
        grace_multiplier=endpoint.activity_grace_multiplier,
    )
    return EndpointSummary(
        endpoint_id=endpoint.endpoint_id,
        hostname=endpoint.hostname,
        last_seen=endpoint.last_seen,
        last_collected_at=endpoint.last_collected_at,
        expected_interval_seconds=endpoint.expected_interval_seconds,
        activity_grace_multiplier=endpoint.activity_grace_multiplier,
        activity_timeout_seconds=activity_timeout_seconds,
        activity_status=activity_status,
        is_active=is_active,
        seconds_since_seen=seconds_since_seen,
    )
