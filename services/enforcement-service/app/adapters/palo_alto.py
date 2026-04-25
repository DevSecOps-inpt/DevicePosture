from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from typing import Any

import requests

from app.config import HTTP_RETRIES, HTTP_TIMEOUT_SECONDS
from posture_shared.interfaces.adapters import EnforcementAdapter
from posture_shared.models.enforcement import EnforcementAction, EnforcementResult


def _coerce_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_group_mappings(raw: Any) -> list[dict[str, str | None]]:
    if not isinstance(raw, list):
        return []

    mappings: list[dict[str, str | None]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        mappings.append(
            {
                "app_group_id": _normalize_text(item.get("app_group_id")) or None,
                "app_group_key": _normalize_text(item.get("app_group_key")) or None,
                "app_group_display_name": _normalize_text(item.get("app_group_display_name")) or None,
                "palo_tag_name": _normalize_text(item.get("palo_tag_name")) or None,
                "palo_dag_name": _normalize_text(item.get("palo_dag_name")) or None,
            }
        )
    return mappings


def _xpath_literal(value: str) -> str:
    if "'" not in value:
        return f"'{value}'"
    if '"' not in value:
        return f'"{value}"'
    parts = value.split("'")
    rendered: list[str] = []
    for index, item in enumerate(parts):
        if item:
            rendered.append(f"'{item}'")
        if index != len(parts) - 1:
            rendered.append('"\'"')
    return f"concat({', '.join(rendered)})"


class PaloAltoAdapterError(RuntimeError):
    """Raised when the PAN-OS XML API call fails or the adapter config is invalid."""


class PaloAltoXmlApiClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        verify_tls: bool,
        timeout: float,
        retries: int,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.retries = max(1, retries)
        self._session = session or requests.Session()
        self._session.trust_env = False

    def _response_message(self, root: ET.Element) -> str:
        attribute_messages = [
            item.get("message", "").strip()
            for item in root.findall(".//*[@message]")
            if item.get("message", "").strip()
        ]
        if attribute_messages:
            return "; ".join(attribute_messages)

        lines = [line.text.strip() for line in root.findall(".//line") if line.text and line.text.strip()]
        if lines:
            return "; ".join(lines)

        message = root.findtext(".//msg")
        if message and message.strip():
            return message.strip()

        result_text = root.findtext(".//result")
        if result_text and result_text.strip():
            return result_text.strip()

        return "PAN-OS XML API returned an unspecified error"

    def _request(self, payload: dict[str, Any]) -> ET.Element:
        headers = {"X-PAN-KEY": self.api_key}
        last_error: Exception | None = None

        for attempt in range(1, self.retries + 1):
            try:
                response = self._session.post(
                    f"{self.base_url}/api/",
                    data=payload,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_tls,
                )
                response.raise_for_status()
                root = ET.fromstring(response.text or "")
                if root.get("status") != "success":
                    raise PaloAltoAdapterError(self._response_message(root))
                return root
            except (requests.RequestException, ET.ParseError, PaloAltoAdapterError) as exc:
                last_error = exc
                if attempt == self.retries:
                    raise PaloAltoAdapterError(str(exc)) from exc
                time.sleep(attempt)

        raise PaloAltoAdapterError(str(last_error or "Unknown PAN-OS request failure"))

    def op_command(self, command_xml: str) -> ET.Element:
        return self._request({"type": "op", "cmd": command_xml})

    def config_get(self, xpath: str) -> ET.Element:
        return self._request({"type": "config", "action": "get", "xpath": xpath})

    def user_id_message(self, message_xml: str, *, vsys: str | None = None) -> ET.Element:
        payload: dict[str, Any] = {"type": "user-id", "cmd": message_xml}
        if vsys:
            payload["vsys"] = vsys
        return self._request(payload)

    def get_system_info(self) -> dict[str, str | None]:
        root = self.op_command("<show><system><info></info></system></show>")
        system = root.find(".//system")
        if system is None:
            return {
                "hostname": None,
                "serial": None,
                "sw_version": None,
                "model": None,
            }
        return {
            "hostname": system.findtext("hostname"),
            "serial": system.findtext("serial"),
            "sw_version": system.findtext("sw-version"),
            "model": system.findtext("model"),
        }

    def dag_exists(self, *, vsys: str, dag_name: str) -> bool:
        xpath = (
            "/config/devices/entry[@name='localhost.localdomain']"
            f"/vsys/entry[@name={_xpath_literal(vsys)}]"
            f"/address-group/entry[@name={_xpath_literal(dag_name)}]"
        )
        try:
            root = self.config_get(xpath)
        except PaloAltoAdapterError as exc:
            message = str(exc).lower()
            if "no such node" in message or "not present" in message:
                return False
            raise

        entry = root.find(".//result/entry")
        if entry is not None:
            return True
        return root.find(".//entry") is not None

    def register_ip_tag(self, *, ip_address: str, tag_name: str, vsys: str, timeout_seconds: int | None = None) -> None:
        root = ET.Element("uid-message")
        ET.SubElement(root, "version").text = "1.0"
        ET.SubElement(root, "type").text = "update"
        payload = ET.SubElement(root, "payload")
        register = ET.SubElement(payload, "register")
        entry = ET.SubElement(register, "entry", {"ip": ip_address})
        tag = ET.SubElement(entry, "tag")
        attributes = {"timeout": str(timeout_seconds)} if timeout_seconds and timeout_seconds > 0 else {}
        member = ET.SubElement(tag, "member", attributes)
        member.text = tag_name
        try:
            self.user_id_message(ET.tostring(root, encoding="unicode"), vsys=vsys)
        except PaloAltoAdapterError as exc:
            message = str(exc).lower()
            if "already exists" in message and "ignore" in message:
                return
            raise

    def unregister_ip_tag(self, *, ip_address: str, tag_name: str, vsys: str) -> None:
        root = ET.Element("uid-message")
        ET.SubElement(root, "version").text = "1.0"
        ET.SubElement(root, "type").text = "update"
        payload = ET.SubElement(root, "payload")
        unregister = ET.SubElement(payload, "unregister")
        entry = ET.SubElement(unregister, "entry", {"ip": ip_address})
        tag = ET.SubElement(entry, "tag")
        member = ET.SubElement(tag, "member")
        member.text = tag_name
        try:
            self.user_id_message(ET.tostring(root, encoding="unicode"), vsys=vsys)
        except PaloAltoAdapterError as exc:
            message = str(exc).lower()
            if ("does not exist" in message or "not found" in message or "not exist" in message) and "ignore" in message:
                return
            raise


class PaloAltoAdapter(EnforcementAdapter):
    name = "palo_alto"

    def build_settings(self, adapter_settings: dict | None = None) -> dict[str, Any]:
        adapter_settings = adapter_settings or {}
        base_url = _normalize_text(adapter_settings.get("base_url"))
        hostname = _normalize_text(adapter_settings.get("hostname"))
        if not base_url and hostname:
            base_url = hostname if hostname.startswith(("http://", "https://")) else f"https://{hostname}"

        api_key = _normalize_text(adapter_settings.get("api_key") or adapter_settings.get("token"))
        timeout = float(adapter_settings.get("timeout_seconds", HTTP_TIMEOUT_SECONDS))
        retries = int(adapter_settings.get("retries", HTTP_RETRIES))
        verify_tls = _coerce_bool(adapter_settings.get("verify_tls"), True)
        vsys = _normalize_text(adapter_settings.get("vsys") or adapter_settings.get("scope") or "vsys1") or "vsys1"

        return {
            "base_url": base_url.rstrip("/"),
            "api_key": api_key,
            "verify_tls": verify_tls,
            "timeout": timeout,
            "retries": max(1, retries),
            "vsys": vsys,
            "group_mappings": _normalize_group_mappings(adapter_settings.get("group_mappings")),
        }

    def _client(self, settings: dict[str, Any]) -> PaloAltoXmlApiClient:
        if not settings.get("base_url"):
            raise PaloAltoAdapterError("Palo Alto base_url is required")
        if not settings.get("api_key"):
            raise PaloAltoAdapterError("Palo Alto api_key is required")
        return PaloAltoXmlApiClient(
            base_url=str(settings["base_url"]),
            api_key=str(settings["api_key"]),
            verify_tls=bool(settings["verify_tls"]),
            timeout=float(settings["timeout"]),
            retries=int(settings["retries"]),
        )

    def resolve_group_mapping(
        self,
        settings: dict[str, Any],
        *,
        group_name: str | None,
        group_id: str | None,
    ) -> dict[str, str | None]:
        normalized_group_name = _normalize_text(group_name).lower()
        normalized_group_id = _normalize_text(group_id).lower()

        for mapping in settings.get("group_mappings", []):
            if not isinstance(mapping, dict):
                continue
            candidate_id = _normalize_text(mapping.get("app_group_id") or mapping.get("app_group_key")).lower()
            candidate_name = _normalize_text(mapping.get("app_group_display_name")).lower()

            matches_id = normalized_group_id and candidate_id == normalized_group_id
            matches_name = normalized_group_name and candidate_name == normalized_group_name
            if matches_id or matches_name:
                if not _normalize_text(mapping.get("palo_tag_name")):
                    raise PaloAltoAdapterError("Palo Alto group mapping is missing palo_tag_name")
                return {
                    "app_group_id": _normalize_text(mapping.get("app_group_id") or mapping.get("app_group_key")) or None,
                    "app_group_display_name": _normalize_text(mapping.get("app_group_display_name")) or group_name,
                    "palo_tag_name": _normalize_text(mapping.get("palo_tag_name")) or None,
                    "palo_dag_name": _normalize_text(mapping.get("palo_dag_name")) or None,
                }

        missing_reference = group_id or group_name or "unknown"
        raise PaloAltoAdapterError(f"No Palo Alto group mapping configured for app group '{missing_reference}'")

    def validate_mapping(
        self,
        settings: dict[str, Any],
        *,
        group_name: str | None,
        group_id: str | None,
    ) -> dict[str, str | None]:
        return self.resolve_group_mapping(settings, group_name=group_name, group_id=group_id)

    def check_connection(self, settings: dict[str, Any]) -> dict[str, Any]:
        client = self._client(settings)
        system = client.get_system_info()
        validated_mappings: list[dict[str, Any]] = []
        for mapping in settings.get("group_mappings", []):
            if not isinstance(mapping, dict):
                continue
            dag_name = _normalize_text(mapping.get("palo_dag_name"))
            mapping_summary = {
                "app_group_id": mapping.get("app_group_id") or mapping.get("app_group_key"),
                "app_group_display_name": mapping.get("app_group_display_name"),
                "palo_tag_name": mapping.get("palo_tag_name"),
                "palo_dag_name": dag_name or None,
                "dag_exists": None,
            }
            if dag_name:
                mapping_summary["dag_exists"] = client.dag_exists(vsys=str(settings["vsys"]), dag_name=dag_name)
            validated_mappings.append(mapping_summary)

        return {
            "base_url": settings["base_url"],
            "vsys": settings["vsys"],
            "hostname": system.get("hostname"),
            "serial": system.get("serial"),
            "sw_version": system.get("sw_version"),
            "model": system.get("model"),
            "mapping_checks": validated_mappings,
        }

    def assign_ip_to_group(
        self,
        *,
        settings: dict[str, Any],
        ip_address: str,
        group_name: str | None,
        group_id: str | None,
    ) -> dict[str, Any]:
        mapping = self.resolve_group_mapping(settings, group_name=group_name, group_id=group_id)
        client = self._client(settings)
        client.register_ip_tag(
            ip_address=ip_address,
            tag_name=str(mapping["palo_tag_name"]),
            vsys=str(settings["vsys"]),
        )
        return {
            "operation": "registered",
            "ip_address": ip_address,
            "app_group_id": mapping.get("app_group_id"),
            "app_group_display_name": mapping.get("app_group_display_name"),
            "palo_tag_name": mapping.get("palo_tag_name"),
            "palo_dag_name": mapping.get("palo_dag_name"),
            "vsys": settings["vsys"],
        }

    def remove_ip_from_group(
        self,
        *,
        settings: dict[str, Any],
        ip_address: str,
        group_name: str | None,
        group_id: str | None,
    ) -> dict[str, Any]:
        mapping = self.resolve_group_mapping(settings, group_name=group_name, group_id=group_id)
        client = self._client(settings)
        client.unregister_ip_tag(
            ip_address=ip_address,
            tag_name=str(mapping["palo_tag_name"]),
            vsys=str(settings["vsys"]),
        )
        return {
            "operation": "unregistered",
            "ip_address": ip_address,
            "app_group_id": mapping.get("app_group_id"),
            "app_group_display_name": mapping.get("app_group_display_name"),
            "palo_tag_name": mapping.get("palo_tag_name"),
            "palo_dag_name": mapping.get("palo_dag_name"),
            "vsys": settings["vsys"],
        }

    def move_ip_between_groups(
        self,
        *,
        settings: dict[str, Any],
        ip_address: str,
        old_group_name: str | None,
        old_group_id: str | None,
        new_group_name: str | None,
        new_group_id: str | None,
    ) -> dict[str, Any]:
        previous = self.resolve_group_mapping(settings, group_name=old_group_name, group_id=old_group_id)
        target = self.resolve_group_mapping(settings, group_name=new_group_name, group_id=new_group_id)
        client = self._client(settings)

        previous_tag = str(previous["palo_tag_name"])
        target_tag = str(target["palo_tag_name"])

        if previous_tag == target_tag:
            return {
                "operation": "noop",
                "message": "Source and target mappings resolve to the same Palo Alto tag",
                "ip_address": ip_address,
                "palo_tag_name": target_tag,
                "vsys": settings["vsys"],
            }

        client.unregister_ip_tag(ip_address=ip_address, tag_name=previous_tag, vsys=str(settings["vsys"]))
        client.register_ip_tag(ip_address=ip_address, tag_name=target_tag, vsys=str(settings["vsys"]))
        return {
            "operation": "moved",
            "ip_address": ip_address,
            "from": previous,
            "to": target,
            "vsys": settings["vsys"],
        }

    def sync_group(
        self,
        *,
        settings: dict[str, Any],
        group_name: str | None,
        group_id: str | None,
        group_ips: list[str],
    ) -> dict[str, Any]:
        mapping = self.resolve_group_mapping(settings, group_name=group_name, group_id=group_id)
        client = self._client(settings)
        registered: list[dict[str, Any]] = []
        for ip_address in group_ips:
            client.register_ip_tag(
                ip_address=ip_address,
                tag_name=str(mapping["palo_tag_name"]),
                vsys=str(settings["vsys"]),
            )
            registered.append({"ip_address": ip_address, "operation": "registered"})

        return {
            "operation": "sync_register_only",
            "message": "Palo Alto sync_group registers the provided IP/tag mappings and does not remove other existing registrations.",
            "app_group_id": mapping.get("app_group_id"),
            "app_group_display_name": mapping.get("app_group_display_name"),
            "palo_tag_name": mapping.get("palo_tag_name"),
            "palo_dag_name": mapping.get("palo_dag_name"),
            "vsys": settings["vsys"],
            "registered_count": len(registered),
            "registered": registered,
        }

    def execute(self, action: EnforcementAction) -> EnforcementResult:
        if action.action not in {"quarantine", "remove_from_group", "sync_group", "move_between_groups"}:
            return EnforcementResult(
                adapter=self.name,
                action=action.action,
                endpoint_id=action.endpoint_id,
                status="skipped",
                details={"message": "Unsupported Palo Alto action for this adapter"},
            )

        adapter_settings = action.decision.get("adapter_settings", {}) if action.decision else {}
        group_id = None
        if action.decision:
            group_id = _normalize_text(action.decision.get("group_id")) or None
        settings = self.build_settings(adapter_settings)

        try:
            if action.action == "move_between_groups":
                old_group_name = None
                old_group_id = None
                new_group_name = action.group_name
                new_group_id = group_id
                if action.decision:
                    old_group_name = _normalize_text(action.decision.get("old_group_name")) or None
                    old_group_id = _normalize_text(action.decision.get("old_group_id")) or None
                    new_group_name = _normalize_text(action.decision.get("new_group_name")) or action.group_name or None
                    new_group_id = _normalize_text(action.decision.get("new_group_id")) or group_id
                details = self.move_ip_between_groups(
                    settings=settings,
                    ip_address=action.ip_address,
                    old_group_name=old_group_name,
                    old_group_id=old_group_id,
                    new_group_name=new_group_name,
                    new_group_id=new_group_id,
                )
            elif action.action == "quarantine":
                details = self.assign_ip_to_group(
                    settings=settings,
                    ip_address=action.ip_address,
                    group_name=action.group_name,
                    group_id=group_id,
                )
            elif action.action == "remove_from_group":
                details = self.remove_ip_from_group(
                    settings=settings,
                    ip_address=action.ip_address,
                    group_name=action.group_name,
                    group_id=group_id,
                )
            else:
                group_ips = action.decision.get("group_ips", []) if action.decision else []
                if not isinstance(group_ips, list):
                    group_ips = []
                details = self.sync_group(
                    settings=settings,
                    group_name=action.group_name,
                    group_id=group_id,
                    group_ips=[_normalize_text(item) for item in group_ips if _normalize_text(item)],
                )
            return EnforcementResult(
                adapter=self.name,
                action=action.action,
                endpoint_id=action.endpoint_id,
                status="success",
                details=details,
            )
        except (PaloAltoAdapterError, requests.RequestException) as exc:
            return EnforcementResult(
                adapter=self.name,
                action=action.action,
                endpoint_id=action.endpoint_id,
                status="failed",
                details={
                    "error": str(exc),
                    "ip_address": action.ip_address,
                    "group_name": action.group_name,
                    "group_id": group_id,
                    "vsys": settings.get("vsys"),
                },
            )
