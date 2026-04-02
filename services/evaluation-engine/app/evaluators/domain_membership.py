from __future__ import annotations

from typing import Any

from posture_shared.interfaces.evaluators import EvaluatorPlugin
from posture_shared.models.evaluation import EvaluationReason
from posture_shared.models.policy import PolicyCondition
from posture_shared.models.telemetry import EndpointTelemetry

from app.evaluators.operators import normalize_list, normalize_operator


def _extract_domain_membership(telemetry: EndpointTelemetry) -> tuple[bool, str, str]:
    extras = telemetry.extras if isinstance(telemetry.extras, dict) else {}
    membership = extras.get("domain_membership")
    membership_dict = membership if isinstance(membership, dict) else {}

    raw_joined = membership_dict.get("joined")
    if raw_joined is None:
        raw_joined = extras.get("domain_joined")
    if raw_joined is None:
        raw_joined = extras.get("is_domain_joined")

    domain_name = (
        membership_dict.get("domain_name")
        or membership_dict.get("dns_domain")
        or membership_dict.get("fqdn")
        or extras.get("domain_name")
        or extras.get("domain_dns_name")
        or extras.get("ad_domain")
        or ""
    )
    domain_dn = (
        membership_dict.get("distinguished_name")
        or membership_dict.get("domain_dn")
        or extras.get("domain_dn")
        or extras.get("domain_distinguished_name")
        or ""
    )

    domain_name_text = str(domain_name).strip().lower()
    domain_dn_text = str(domain_dn).strip().lower()

    if isinstance(raw_joined, bool):
        joined = raw_joined
    elif isinstance(raw_joined, str):
        joined = raw_joined.strip().lower() in {"true", "1", "yes", "joined"}
    else:
        joined = bool(domain_name_text or domain_dn_text)

    return joined, domain_name_text, domain_dn_text


def _domain_suffix_from_base_dn(base_dn: str | None) -> str | None:
    text = (base_dn or "").strip().lower()
    if not text:
        return None
    labels: list[str] = []
    for part in text.split(","):
        section = part.strip()
        if section.startswith("dc="):
            value = section[3:].strip()
            if value:
                labels.append(value)
    if not labels:
        return None
    return ".".join(labels)


def _matches_tree(
    *,
    domain_name: str,
    domain_dn: str,
    suffixes: list[str],
    base_dn: str | None,
) -> bool:
    normalized_suffixes = [item.strip().lower() for item in suffixes if item and item.strip()]
    normalized_base_dn = (base_dn or "").strip().lower()
    derived_suffix = _domain_suffix_from_base_dn(normalized_base_dn)
    if derived_suffix and derived_suffix not in normalized_suffixes:
        normalized_suffixes.append(derived_suffix)

    if normalized_suffixes and domain_name:
        for suffix in normalized_suffixes:
            if domain_name == suffix or domain_name.endswith(f".{suffix}"):
                return True

    if normalized_base_dn and domain_dn:
        if domain_dn.endswith(normalized_base_dn):
            return True

    if not normalized_suffixes and not normalized_base_dn:
        # No tree hint is configured for the selected LDAP provider.
        # In this fallback mode, any joined domain is considered in-tree.
        return True

    return False


class DomainMembershipEvaluator(EvaluatorPlugin):
    condition_type = "domain_membership"

    def evaluate(
        self,
        telemetry: EndpointTelemetry,
        condition: PolicyCondition,
    ) -> list[EvaluationReason]:
        operator = normalize_operator(condition.operator)
        value: Any = condition.value
        value_dict = value if isinstance(value, dict) else {}

        provider_name = str(value_dict.get("provider_name") or "selected LDAP provider").strip()
        base_dn = str(value_dict.get("provider_base_dn") or "").strip() or None
        suffixes = normalize_list(value_dict.get("allowed_domain_suffixes"))

        joined, domain_name, domain_dn = _extract_domain_membership(telemetry)
        in_tree = joined and _matches_tree(
            domain_name=domain_name,
            domain_dn=domain_dn,
            suffixes=suffixes,
            base_dn=base_dn,
        )

        if operator == "does_not_exist_in":
            if not in_tree:
                return []
            return [
                EvaluationReason(
                    check_type=self.condition_type,
                    message=f"Endpoint domain is within LDAP tree for '{provider_name}' while condition requires exclusion",
                )
            ]

        if in_tree:
            return []

        if not joined:
            return [
                EvaluationReason(
                    check_type=self.condition_type,
                    message=f"Endpoint is not domain-joined for LDAP policy '{provider_name}'",
                )
            ]

        target_tree = ", ".join(suffixes) if suffixes else (base_dn or "configured LDAP tree")
        domain_observed = domain_name or domain_dn or "unknown-domain"
        return [
            EvaluationReason(
                check_type=self.condition_type,
                message=f"Endpoint domain '{domain_observed}' is not within LDAP tree '{target_tree}' for '{provider_name}'",
            )
        ]
