import time
from typing import Any

import requests

from app.config import (
    FORTIGATE_BASE_URL,
    FORTIGATE_QUARANTINE_GROUP,
    FORTIGATE_TOKEN,
    FORTIGATE_VERIFY_TLS,
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
        self._consecutive_failures = 0
        self._opened_until = 0.0
        self._failure_threshold = 5
        self._cooldown_seconds = 60

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
        try:
            if action.action == "quarantine":
                candidate_names = self._candidate_address_names(action.endpoint_id, action.ip_address)
                address_name = candidate_names[0]
                address_result = self._ensure_address(settings, address_name, action.ip_address)
                group_result = self._ensure_group_member(settings, address_name)
                verification = self._verify_group_membership(
                    settings,
                    required_present={address_name},
                    required_absent=set(),
                )
                if not verification["ok"]:
                    return EnforcementResult(
                        adapter=self.name,
                        action=action.action,
                        endpoint_id=action.endpoint_id,
                        status="failed",
                        details={
                            "message": "FortiGate group verification failed after add",
                            "address": address_result,
                            "group": group_result,
                            "verification": verification,
                            "ip_address": action.ip_address,
                            "group_name": settings["group_name"],
                        },
                    )
                return EnforcementResult(
                    adapter=self.name,
                    action=action.action,
                    endpoint_id=action.endpoint_id,
                    status="success",
                    details={
                        "address": address_result,
                        "group": group_result,
                        "verification": verification,
                        "ip_address": action.ip_address,
                        "group_name": settings["group_name"],
                    },
                )

            if action.action == "remove_from_group":
                candidate_names = self._candidate_address_names(action.endpoint_id, action.ip_address)
                group_results: list[dict[str, str]] = []
                for address_name in candidate_names:
                    group_results.append(self._remove_group_member(settings, address_name))
                verification = self._verify_group_membership(
                    settings,
                    required_present=set(),
                    required_absent=set(candidate_names),
                )
                if not verification["ok"]:
                    return EnforcementResult(
                        adapter=self.name,
                        action=action.action,
                        endpoint_id=action.endpoint_id,
                        status="failed",
                        details={
                            "message": "FortiGate group verification failed after remove",
                            "group_results": group_results,
                            "verification": verification,
                            "ip_address": action.ip_address,
                            "group_name": settings["group_name"],
                        },
                    )
                return EnforcementResult(
                    adapter=self.name,
                    action=action.action,
                    endpoint_id=action.endpoint_id,
                    status="success",
                    details={
                        "group": group_results,
                        "verification": verification,
                        "ip_address": action.ip_address,
                        "group_name": settings["group_name"],
                    },
                )

            group_ips = action.decision.get("group_ips", [])
            sync_result = self._sync_group_ips(settings, group_ips)
            if not sync_result["verification"]["ok"]:
                return EnforcementResult(
                    adapter=self.name,
                    action=action.action,
                    endpoint_id=action.endpoint_id,
                    status="failed",
                    details={
                        "group_name": settings["group_name"],
                        "synced_ip_count": len(sync_result["synced"]),
                        "synced": sync_result["synced"],
                        "removed": sync_result["removed"],
                        "verification": sync_result["verification"],
                        "message": "FortiGate group verification failed after sync",
                    },
                )
            return EnforcementResult(
                adapter=self.name,
                action=action.action,
                endpoint_id=action.endpoint_id,
                status="success",
                details={
                    "group_name": settings["group_name"],
                    "synced_ip_count": len(sync_result["synced"]),
                    "synced": sync_result["synced"],
                    "removed": sync_result["removed"],
                    "verification": sync_result["verification"],
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
        now = time.time()
        if self._opened_until > now:
            raise requests.RequestException(
                f"FortiGate circuit breaker open until {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(self._opened_until))}"
            )
        if self._opened_until and self._opened_until <= now:
            self._opened_until = 0.0
            self._consecutive_failures = 0
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
                    verify=FORTIGATE_VERIFY_TLS,
                )
                if response.status_code >= 400:
                    response.raise_for_status()
                self._consecutive_failures = 0
                self._opened_until = 0.0
                return response
            except requests.RequestException as exc:
                last_error = exc
                self._consecutive_failures += 1
                if self._consecutive_failures >= self._failure_threshold:
                    self._opened_until = time.time() + self._cooldown_seconds
                if attempt == settings["retries"]:
                    raise
                time.sleep(attempt)
        raise last_error  # pragma: no cover

    def _address_name(self, identifier: str) -> str:
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in identifier.lower())
        return f"posture-{safe[:40]}"

    def _candidate_address_names(self, endpoint_id: str, ip_address: str) -> list[str]:
        names: list[str] = []
        preferred = self._address_name(ip_address)
        fallback = self._address_name(endpoint_id)
        for item in (preferred, fallback):
            if item not in names:
                names.append(item)
        return names

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

    def _group_member_names(self, settings: dict) -> set[str]:
        members = self._get_group_members(settings)
        return {str(item.get("name")) for item in members if isinstance(item, dict) and item.get("name")}

    def _verify_group_membership(
        self,
        settings: dict,
        *,
        required_present: set[str],
        required_absent: set[str],
    ) -> dict[str, Any]:
        actual_names = self._group_member_names(settings)
        missing = sorted(required_present - actual_names)
        still_present = sorted(actual_names.intersection(required_absent))
        return {
            "ok": len(missing) == 0 and len(still_present) == 0,
            "missing": missing,
            "still_present": still_present,
            "group_member_count": len(actual_names),
        }

    def _sync_group_ips(self, settings: dict, group_ips: list[str]) -> dict[str, Any]:
        synced: list[dict] = []
        desired_members: list[dict[str, str]] = []
        desired_names: set[str] = set()
        for ip_address in group_ips:
            address_name = self._address_name(ip_address)
            address_result = self._ensure_address(settings, address_name, ip_address)
            synced.append({"ip_address": ip_address, "address": address_result})
            if address_name not in desired_names:
                desired_names.add(address_name)
                desired_members.append({"name": address_name})

        current_members = self._get_group_members(settings)
        keep_non_posture_members = True
        retained_non_posture = [
            {"name": item["name"]}
            for item in current_members
            if isinstance(item, dict)
            and isinstance(item.get("name"), str)
            and not str(item.get("name")).startswith("posture-")
        ]
        final_members = retained_non_posture + desired_members if keep_non_posture_members else desired_members

        current_names = {str(item.get("name")) for item in current_members if isinstance(item, dict) and item.get("name")}
        final_names = {item["name"] for item in final_members}
        removed = sorted(name for name in current_names if name.startswith("posture-") and name not in final_names)

        if final_names != current_names:
            self._update_group_members(settings, final_members)

        actual_names = self._group_member_names(settings)
        actual_posture_names = {name for name in actual_names if name.startswith("posture-")}
        verification = {
            "ok": desired_names.issubset(actual_names) and len(actual_posture_names - desired_names) == 0,
            "expected_posture_members": sorted(desired_names),
            "actual_posture_members": sorted(actual_posture_names),
            "missing_posture_members": sorted(desired_names - actual_names),
            "unexpected_posture_members": sorted(actual_posture_names - desired_names),
            "group_member_count": len(actual_names),
        }
        return {"synced": synced, "removed": removed, "verification": verification}
