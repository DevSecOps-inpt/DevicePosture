from __future__ import annotations

from typing import Any

import requests

from app.config import HTTP_TIMEOUT_SECONDS, INTER_SERVICE_API_KEY, POLICY_SERVICE_URL
from posture_shared.interfaces.evaluators import EvaluatorPlugin
from posture_shared.models.evaluation import EvaluationReason
from posture_shared.models.policy import PolicyCondition
from posture_shared.models.telemetry import EndpointTelemetry

from app.evaluators.operators import normalize_list, normalize_operator

_session = requests.Session()


def _auth_headers() -> dict[str, str]:
    if not INTER_SERVICE_API_KEY:
        return {}
    return {"X-API-Key": INTER_SERVICE_API_KEY}


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


def _verify_with_policy_service(
    *,
    provider_id: int,
    telemetry: EndpointTelemetry,
    domain_name: str,
    domain_dn: str,
    required_group_dns: list[str],
) -> tuple[dict[str, Any] | None, str | None]:
    payload = {
        "endpoint_id": telemetry.endpoint_id,
        "hostname": telemetry.hostname,
        "domain_name": domain_name or None,
        "domain_dn": domain_dn or None,
        "required_group_dns": required_group_dns,
    }
    try:
        response = _session.post(
            f"{POLICY_SERVICE_URL}/domain-membership/verify",
            params={"provider_id": provider_id},
            json=payload,
            headers=_auth_headers(),
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            return None, "Invalid domain verification response"
        return data, None
    except requests.RequestException as exc:
        return None, f"Failed to verify endpoint domain membership: {exc}"


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
        provider_id = value_dict.get("provider_id")
        provider_id_int = provider_id if isinstance(provider_id, int) else None
        required_group_dns = [
            item.strip().lower()
            for item in normalize_list(value_dict.get("required_group_dns"))
            if item.strip()
        ]

        joined, domain_name, domain_dn = _extract_domain_membership(telemetry)
        local_in_tree = joined and _matches_tree(
            domain_name=domain_name,
            domain_dn=domain_dn,
            suffixes=suffixes,
            base_dn=base_dn,
        )

        verification: dict[str, Any] | None = None
        if provider_id_int is not None:
            verification, verify_error = _verify_with_policy_service(
                provider_id=provider_id_int,
                telemetry=telemetry,
                domain_name=domain_name,
                domain_dn=domain_dn,
                required_group_dns=required_group_dns,
            )
            if verify_error:
                return [
                    EvaluationReason(
                        check_type=self.condition_type,
                        message=f"{verify_error} for LDAP policy '{provider_name}'",
                    )
                ]

        in_tree = bool(verification.get("ok")) if verification is not None else local_in_tree

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

        if verification is not None:
            message = str(verification.get("message") or "").strip()
            return [
                EvaluationReason(
                    check_type=self.condition_type,
                    message=message or f"Endpoint failed LDAP domain membership verification for '{provider_name}'",
                )
            ]

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
