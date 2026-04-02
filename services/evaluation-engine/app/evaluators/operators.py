from __future__ import annotations

from typing import Any


def normalize_operator(raw_operator: str | None) -> str:
    value = (raw_operator or "").strip().lower()
    aliases = {
        ">": "greater_than",
        "gt": "greater_than",
        "greater than": "greater_than",
        ">=": "greater_than_or_equal",
        "gte": "greater_than_or_equal",
        "greater than or equal": "greater_than_or_equal",
        "<": "less_than",
        "lt": "less_than",
        "less than": "less_than",
        "<=": "less_than_or_equal",
        "lte": "less_than_or_equal",
        "less than or equal": "less_than_or_equal",
        "exists_in": "exists_in",
        "exists in": "exists_in",
        "in": "exists_in",
        "contains_any": "exists_in",
        "does_not_exist_in": "does_not_exist_in",
        "does not exist in": "does_not_exist_in",
        "not_in": "does_not_exist_in",
        "contains_none": "does_not_exist_in",
        "contains_all": "contains_all",
    }
    return aliases.get(value, "exists_in")


def normalize_list(value: Any) -> list[str]:
    if isinstance(value, list):
        raw_items = value
    elif isinstance(value, str):
        raw_items = [item.strip() for item in value.split(",")]
    else:
        raw_items = []
    return [str(item).strip() for item in raw_items if str(item).strip()]


def evaluate_membership(
    *,
    actual_values: set[str],
    expected_values: set[str],
    operator: str,
) -> bool:
    if not expected_values:
        return True
    if operator == "does_not_exist_in":
        return len(actual_values.intersection(expected_values)) == 0
    if operator == "contains_all":
        return expected_values.issubset(actual_values)
    return len(actual_values.intersection(expected_values)) > 0


def evaluate_numeric(
    *,
    actual: int,
    expected: int,
    operator: str,
) -> bool:
    if operator == "greater_than":
        return actual > expected
    if operator == "greater_than_or_equal":
        return actual >= expected
    if operator == "less_than":
        return actual < expected
    if operator == "less_than_or_equal":
        return actual <= expected
    return actual == expected
