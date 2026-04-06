from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from posture_shared.models.telemetry import EndpointTelemetry


@dataclass(frozen=True, slots=True)
class AntivirusSignature:
    family: str
    product_tokens: frozenset[str]
    process_names: frozenset[str]
    service_names: frozenset[str]


@dataclass(frozen=True, slots=True)
class AntivirusDetection:
    installed_families: set[str]
    active_families: set[str]
    family_states: dict[str, set[str]]


ANTIVIRUS_SIGNATURES: tuple[AntivirusSignature, ...] = (
    AntivirusSignature(
        family="microsoft_defender",
        product_tokens=frozenset({"windows defender", "microsoft defender", "defender"}),
        process_names=frozenset({"msmpeng.exe", "nisserv.exe"}),
        service_names=frozenset({"windefend", "sense"}),
    ),
    AntivirusSignature(
        family="crowdstrike",
        product_tokens=frozenset({"crowdstrike", "falcon"}),
        process_names=frozenset({"csfalconservice.exe", "falconsensor.exe"}),
        service_names=frozenset({"csfalconservice"}),
    ),
    AntivirusSignature(
        family="sentinelone",
        product_tokens=frozenset({"sentinelone"}),
        process_names=frozenset({"sentinelagent.exe", "sentinelservicehost.exe"}),
        service_names=frozenset({"sentinelagent", "sentinelservicehost"}),
    ),
    AntivirusSignature(
        family="sophos",
        product_tokens=frozenset({"sophos"}),
        process_names=frozenset({"savservice.exe", "sophoshealthservice.exe"}),
        service_names=frozenset(
            {"sophos endpoint defense service", "sophos mcs agent", "sophosmcsagent"}
        ),
    ),
    AntivirusSignature(
        family="mcafee",
        product_tokens=frozenset({"mcafee", "trellix"}),
        process_names=frozenset({"mcshield.exe", "mfemms.exe", "masvc.exe"}),
        service_names=frozenset({"mcshield", "masvc", "mfemms", "mfevtps"}),
    ),
    AntivirusSignature(
        family="bitdefender",
        product_tokens=frozenset({"bitdefender"}),
        process_names=frozenset({"bdagent.exe", "vsserv.exe", "epsecurityservice.exe"}),
        service_names=frozenset({"epsecurityservice", "vsserv"}),
    ),
    AntivirusSignature(
        family="kaspersky",
        product_tokens=frozenset({"kaspersky"}),
        process_names=frozenset({"avp.exe", "kavfs.exe"}),
        service_names=frozenset({"avp", "kavfs"}),
    ),
    AntivirusSignature(
        family="trend_micro",
        product_tokens=frozenset({"trend micro", "trendmicro"}),
        process_names=frozenset({"ntrtscan.exe", "coreframeworkhost.exe", "pccntmon.exe"}),
        service_names=frozenset({"ntrtscan", "tmlisten"}),
    ),
    AntivirusSignature(
        family="eset",
        product_tokens=frozenset({"eset"}),
        process_names=frozenset({"ekrn.exe", "egui.exe"}),
        service_names=frozenset({"ekrn"}),
    ),
    AntivirusSignature(
        family="symantec",
        product_tokens=frozenset({"symantec", "norton"}),
        process_names=frozenset({"ccsvchst.exe", "smc.exe"}),
        service_names=frozenset({"sepmasterservice", "smc"}),
    ),
    AntivirusSignature(
        family="avast",
        product_tokens=frozenset({"avast"}),
        process_names=frozenset({"avastsvc.exe", "aswengsrv.exe", "avastui.exe"}),
        service_names=frozenset({"avastsvc"}),
    ),
    AntivirusSignature(
        family="avg",
        product_tokens=frozenset({"avg"}),
        process_names=frozenset({"avgsvc.exe", "avgui.exe"}),
        service_names=frozenset({"avgsvc"}),
    ),
    AntivirusSignature(
        family="malwarebytes",
        product_tokens=frozenset({"malwarebytes"}),
        process_names=frozenset({"mbamservice.exe", "mbamtray.exe"}),
        service_names=frozenset({"mbamservice"}),
    ),
)

FAMILY_ALIASES: dict[str, str] = {
    "windows_defender": "microsoft_defender",
    "defender": "microsoft_defender",
    "microsoft defender": "microsoft_defender",
    "crowd strike": "crowdstrike",
    "trend micro": "trend_micro",
    "trendmicro": "trend_micro",
}


def _build_exact_index(attribute: str) -> dict[str, set[str]]:
    index: dict[str, set[str]] = {}
    for signature in ANTIVIRUS_SIGNATURES:
        for marker in getattr(signature, attribute):
            key = marker.strip().lower()
            if not key:
                continue
            index.setdefault(key, set()).add(signature.family)
    return index


PROCESS_FAMILY_INDEX = _build_exact_index("process_names")
SERVICE_FAMILY_INDEX = _build_exact_index("service_names")


def _lowered(values: Iterable[str]) -> set[str]:
    return {value.strip().lower() for value in values if value and value.strip()}


def _is_running_status(value: str | None) -> bool:
    normalized = (value or "").strip().lower()
    return normalized in {"running", "started", "start_pending"}


def normalize_antivirus_family_value(value: str) -> str:
    lowered = value.strip().lower().replace("-", "_")
    lowered = " ".join(lowered.split())
    if lowered in FAMILY_ALIASES:
        return FAMILY_ALIASES[lowered]
    return lowered.replace(" ", "_")


def _match_families_by_exact_markers(markers: set[str], index: dict[str, set[str]]) -> set[str]:
    detected: set[str] = set()
    for marker in markers:
        detected.update(index.get(marker, set()))
    return detected


def _match_families_by_product_tokens(identifiers: set[str]) -> set[str]:
    detected: set[str] = set()
    for signature in ANTIVIRUS_SIGNATURES:
        if any(token in identifier for token in signature.product_tokens for identifier in identifiers):
            detected.add(signature.family)
    return detected


def _families_for_identifier(identifier: str) -> set[str]:
    detected: set[str] = set()
    candidate = identifier.strip().lower()
    if not candidate:
        return detected
    for signature in ANTIVIRUS_SIGNATURES:
        if any(token in candidate for token in signature.product_tokens):
            detected.add(signature.family)
    return detected


def _running_process_names(telemetry: EndpointTelemetry) -> set[str]:
    return _lowered([process.name for process in telemetry.processes if process.name])


def _service_names(telemetry: EndpointTelemetry, *, running_only: bool) -> set[str]:
    names: set[str] = set()
    for service in telemetry.services:
        if not service.name:
            continue
        if running_only and not _is_running_status(service.status):
            continue
        names.add(service.name.strip().lower())
    return names


def _product_identifiers(telemetry: EndpointTelemetry) -> set[str]:
    return _lowered(
        [
            product.identifier or product.name
            for product in telemetry.antivirus_products
            if (product.identifier or product.name)
        ]
    )


def _parse_product_state_int(value: str | None) -> int | None:
    raw = (value or "").strip().lower()
    if not raw:
        return None
    try:
        if raw.startswith("0x"):
            return int(raw, 16)
        if any(char in "abcdef" for char in raw):
            return int(raw, 16)
        return int(raw, 10)
    except ValueError:
        return None


def parse_antivirus_product_state(value: str | None) -> str:
    state_int = _parse_product_state_int(value)
    if state_int is None:
        return "unknown"

    # SecurityCenter2 AntivirusProduct.productState commonly encodes mode in the second byte.
    # We keep this conservative: explicit "off" is honored, otherwise a set on-bit can still mark active.
    mode = (state_int >> 8) & 0xFF
    mapping = {
        0x00: "off",
        0x01: "expired",
        0x10: "on",
        0x11: "on_snoozed",
    }
    if mode in mapping:
        return mapping[mode]

    if state_int & 0x1000:
        return "on"
    return "unknown"


def detect_antivirus_runtime(telemetry: EndpointTelemetry) -> AntivirusDetection:
    runtime_families = set()
    runtime_families.update(
        _match_families_by_exact_markers(_running_process_names(telemetry), PROCESS_FAMILY_INDEX)
    )
    runtime_families.update(
        _match_families_by_exact_markers(_service_names(telemetry, running_only=True), SERVICE_FAMILY_INDEX)
    )

    installed_families = set(runtime_families)
    installed_families.update(
        _match_families_by_exact_markers(_service_names(telemetry, running_only=False), SERVICE_FAMILY_INDEX)
    )
    installed_families.update(_match_families_by_product_tokens(_product_identifiers(telemetry)))

    family_states: dict[str, set[str]] = {}
    for product in telemetry.antivirus_products:
        identifier = (product.identifier or product.name or "").strip().lower()
        if not identifier:
            continue
        state = parse_antivirus_product_state(product.state)
        families = _families_for_identifier(identifier)
        for family in families:
            family_states.setdefault(family, set()).add(state)
            installed_families.add(family)

    active_families = set(runtime_families)
    for family, states in family_states.items():
        if states.intersection({"on", "on_snoozed", "expired"}):
            active_families.add(family)
            continue
        if "off" in states:
            active_families.discard(family)

    normalized_installed = {normalize_antivirus_family_value(item) for item in installed_families}
    normalized_active = {normalize_antivirus_family_value(item) for item in active_families}
    normalized_states = {
        normalize_antivirus_family_value(family): set(states)
        for family, states in family_states.items()
    }

    return AntivirusDetection(
        installed_families=normalized_installed,
        active_families=normalized_active,
        family_states=normalized_states,
    )


def detect_antivirus_families(telemetry: EndpointTelemetry) -> set[str]:
    return detect_antivirus_runtime(telemetry).installed_families


def detect_active_antivirus_families(telemetry: EndpointTelemetry) -> set[str]:
    return detect_antivirus_runtime(telemetry).active_families
