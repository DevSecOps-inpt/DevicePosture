import time

import requests

from app.config import (
    FORTIGATE_BASE_URL,
    FORTIGATE_QUARANTINE_GROUP,
    FORTIGATE_TOKEN,
    FORTIGATE_VDOM,
    HTTP_RETRIES,
    HTTP_TIMEOUT_SECONDS,
)
from posture_shared.interfaces.adapters import EnforcementAdapter
from posture_shared.models.enforcement import EnforcementAction, EnforcementResult


class FortiGateAdapter(EnforcementAdapter):
    name = "fortigate"

    def __init__(self) -> None:
        self._session = requests.Session()
        self._session.trust_env = False

    def execute(self, action: EnforcementAction) -> EnforcementResult:
        if action.action not in {"quarantine", "remove_from_group", "sync_group"}:
            return EnforcementResult(
                adapter=self.name,
                action=action.action,
                endpoint_id=action.endpoint_id,
                status="skipped",
                details={"message": "Unsupported FortiGate action for this adapter"},
            )

        settings = self._resolve_settings(action)
        address_name = self._address_name(action.endpoint_id)
        try:
            if action.action == "quarantine":
                address_result = self._ensure_address(settings, address_name, action.ip_address)
                group_result = self._ensure_group_member(settings, address_name)
                return EnforcementResult(
                    adapter=self.name,
                    action=action.action,
                    endpoint_id=action.endpoint_id,
                    status="success",
                    details={
                        "address": address_result,
                        "group": group_result,
                        "ip_address": action.ip_address,
                        "group_name": settings["group_name"],
                    },
                )

            if action.action == "remove_from_group":
                group_result = self._remove_group_member(settings, address_name)
                return EnforcementResult(
                    adapter=self.name,
                    action=action.action,
                    endpoint_id=action.endpoint_id,
                    status="success",
                    details={
                        "group": group_result,
                        "ip_address": action.ip_address,
                        "group_name": settings["group_name"],
                    },
                )

            group_ips = action.decision.get("group_ips", [])
            synced = self._sync_group_ips(settings, group_ips)
            return EnforcementResult(
                adapter=self.name,
                action=action.action,
                endpoint_id=action.endpoint_id,
                status="success",
                details={
                    "group_name": settings["group_name"],
                    "synced_ip_count": len(synced),
                    "synced": synced,
                },
            )
        except requests.RequestException as exc:
            return EnforcementResult(
                adapter=self.name,
                action=action.action,
                endpoint_id=action.endpoint_id,
                status="failed",
                details={"error": str(exc), "ip_address": action.ip_address, "group_name": settings["group_name"]},
            )

    def build_settings(self, adapter_settings: dict | None = None, group_name: str | None = None) -> dict:
        adapter_settings = adapter_settings or {}
        base_url = adapter_settings.get("base_url") or FORTIGATE_BASE_URL
        token = adapter_settings.get("token") or FORTIGATE_TOKEN
        vdom = adapter_settings.get("vdom") or FORTIGATE_VDOM
        resolved_group_name = group_name or adapter_settings.get("quarantine_group") or FORTIGATE_QUARANTINE_GROUP
        timeout = float(adapter_settings.get("timeout_seconds", HTTP_TIMEOUT_SECONDS))
        retries = int(adapter_settings.get("retries", HTTP_RETRIES))
        return {
            "base_url": str(base_url).rstrip("/"),
            "token": token,
            "vdom": vdom,
            "group_name": resolved_group_name,
            "timeout": timeout,
            "retries": max(1, retries),
        }

    def check_connection(self, settings: dict) -> dict:
        response = self._request(settings, "GET", "/api/v2/monitor/system/status")
        payload = response.json() if response.content else {}
        results = payload.get("results", {}) if isinstance(payload, dict) else {}
        version = None
        if isinstance(results, dict):
            version = results.get("version") or results.get("build")
        return {
            "http_status": response.status_code,
            "version": version,
            "base_url": settings["base_url"],
            "vdom": settings["vdom"],
        }

    def _resolve_settings(self, action: EnforcementAction) -> dict:
        adapter_settings = action.decision.get("adapter_settings", {}) if action.decision else {}
        return self.build_settings(adapter_settings=adapter_settings, group_name=action.group_name)

    def _request(self, settings: dict, method: str, path: str, payload: dict | None = None) -> requests.Response:
        url = f"{settings['base_url']}{path}?vdom={settings['vdom']}"
        headers = {
            "Authorization": f"Bearer {settings['token']}",
            "Content-Type": "application/json",
        }
        last_error: requests.RequestException | None = None
        for attempt in range(1, settings["retries"] + 1):
            try:
                # Do not use host-level proxy env variables for local/private firewall APIs.
                # This avoids false failures when corporate proxy settings are present.
                response = self._session.request(
                    method=method,
                    url=url,
                    json=payload,
                    headers=headers,
                    timeout=settings["timeout"],
                    verify=False,
                )
                if response.status_code >= 400:
                    response.raise_for_status()
                return response
            except requests.RequestException as exc:
                last_error = exc
                if attempt == settings["retries"]:
                    raise
                time.sleep(attempt)
        raise last_error  # pragma: no cover

    def _address_name(self, endpoint_id: str) -> str:
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in endpoint_id.lower())
        return f"posture-{safe[:40]}"

    def _ensure_address(self, settings: dict, address_name: str, ip_address: str) -> dict:
        path = f"/api/v2/cmdb/firewall/address/{address_name}"
        create_payload = {"name": address_name, "subnet": f"{ip_address} 255.255.255.255"}
        try:
            self._request(settings, "GET", path)
            self._request(settings, "PUT", path, create_payload)
            return {"name": address_name, "operation": "updated"}
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                self._request(settings, "POST", "/api/v2/cmdb/firewall/address", create_payload)
                return {"name": address_name, "operation": "created"}
            raise

    def _get_group_members(self, settings: dict) -> list[dict]:
        path = f"/api/v2/cmdb/firewall/addrgrp/{settings['group_name']}"
        response = self._request(settings, "GET", path)
        payload = response.json() if response.content else {}
        results = payload.get("results") if isinstance(payload, dict) else None

        # FortiGate responses can return either:
        # - {"results": {"member": [...]}}
        # - {"results": [{"member": [...]}]}
        if isinstance(results, dict):
            members = results.get("member", [])
            return members if isinstance(members, list) else []

        if isinstance(results, list):
            for item in results:
                if not isinstance(item, dict):
                    continue
                members = item.get("member")
                if isinstance(members, list):
                    return members
            return []

        return []

    def _update_group_members(self, settings: dict, members: list[dict]) -> None:
        path = f"/api/v2/cmdb/firewall/addrgrp/{settings['group_name']}"
        payload = {"name": settings["group_name"], "member": members}
        self._request(settings, "PUT", path, payload)

    def _ensure_group_member(self, settings: dict, address_name: str) -> dict:
        members = self._get_group_members(settings)
        names = {item["name"] for item in members if "name" in item}
        if address_name in names:
            return {"group": settings["group_name"], "operation": "already_present"}

        members.append({"name": address_name})
        self._update_group_members(settings, members)
        return {"group": settings["group_name"], "operation": "added"}

    def _remove_group_member(self, settings: dict, address_name: str) -> dict:
        members = self._get_group_members(settings)
        before = len(members)
        members = [member for member in members if member.get("name") != address_name]
        if len(members) == before:
            return {"group": settings["group_name"], "operation": "already_absent"}
        self._update_group_members(settings, members)
        return {"group": settings["group_name"], "operation": "removed"}

    def _sync_group_ips(self, settings: dict, group_ips: list[str]) -> list[dict]:
        synced: list[dict] = []
        for ip_address in group_ips:
            address_name = self._address_name(ip_address)
            address_result = self._ensure_address(settings, address_name, ip_address)
            group_result = self._ensure_group_member(settings, address_name)
            synced.append({"ip_address": ip_address, "address": address_result, "group": group_result})
        return synced
