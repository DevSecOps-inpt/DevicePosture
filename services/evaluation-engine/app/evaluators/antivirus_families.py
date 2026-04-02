from __future__ import annotations

from typing import Iterable

from posture_shared.models.telemetry import EndpointTelemetry


ANTIVIRUS_FAMILY_PROCESSES: dict[str, set[str]] = {
    "microsoft_defender": {"msmpeng.exe", "nisserv.exe"},
    "crowdstrike": {"csfalconservice.exe", "falconsensor.exe"},
    "sentinelone": {"sentinelagent.exe", "sentinelservicehost.exe"},
    "sophos": {"savservice.exe", "sophoshealthservice.exe"},
    "mcafee": {"mcshield.exe", "mfemms.exe"},
    "bitdefender": {"bdagent.exe", "vsserv.exe"},
    "kaspersky": {"avp.exe"},
    "trend_micro": {"ntrtscan.exe", "coreframeworkhost.exe"},
    "eset": {"ekrn.exe", "egui.exe"},
    "symantec": {"ccsvchst.exe", "smc.exe"},
}

ANTIVIRUS_FAMILY_IDENTIFIERS: dict[str, set[str]] = {
    "microsoft_defender": {"windows defender", "microsoft defender", "defender"},
    "crowdstrike": {"crowdstrike", "falcon"},
    "sentinelone": {"sentinelone"},
    "sophos": {"sophos"},
    "mcafee": {"mcafee"},
    "bitdefender": {"bitdefender"},
    "kaspersky": {"kaspersky"},
    "trend_micro": {"trend micro", "trendmicro"},
    "eset": {"eset"},
    "symantec": {"symantec", "norton"},
}


def _lowered(values: Iterable[str]) -> set[str]:
    return {value.strip().lower() for value in values if value and value.strip()}


def detect_antivirus_families(telemetry: EndpointTelemetry) -> set[str]:
    detected_families: set[str] = set()
    process_names = _lowered([process.name for process in telemetry.processes if process.name])
    detected_identifiers = _lowered(
        [
            product.identifier or product.name
            for product in telemetry.antivirus_products
            if (product.identifier or product.name)
        ]
    )

    for family, process_markers in ANTIVIRUS_FAMILY_PROCESSES.items():
        if process_names.intersection(process_markers):
            detected_families.add(family)
            continue

        identifier_markers = ANTIVIRUS_FAMILY_IDENTIFIERS.get(family, set())
        for detected in detected_identifiers:
            if any(marker in detected for marker in identifier_markers):
                detected_families.add(family)
                break

    return detected_families
