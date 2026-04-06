from __future__ import annotations

import re
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
        "contains": "contains_all",
        "contains all": "contains_all",
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
    actual_items = {str(item).strip() for item in actual_values if str(item).strip()}
    expected_items = {str(item).strip() for item in expected_values if str(item).strip()}
    if not expected_items:
        return False

    def _matches(actual: str, expected: str) -> bool:
        actual_normalized = actual.strip()
        expected_normalized = expected.strip()
        if "*" not in expected_normalized:
            return actual_normalized.casefold() == expected_normalized.casefold()
        # Support shell-style "*" wildcard inside string values.
        wildcard_pattern = "^" + re.escape(expected_normalized).replace(r"\*", ".*") + "$"
        return re.match(wildcard_pattern, actual_normalized, flags=re.IGNORECASE) is not None

    def _any_match(expected: str) -> bool:
        return any(_matches(actual, expected) for actual in actual_items)

    if operator == "does_not_exist_in":
        return not any(_any_match(expected) for expected in expected_items)
    if operator == "contains_all":
        return all(_any_match(expected) for expected in expected_items)
    return any(_any_match(expected) for expected in expected_items)


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
