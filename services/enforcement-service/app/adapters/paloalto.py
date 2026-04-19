import threading
import time
import xml.etree.ElementTree as ET
from typing import Any

import requests

from app.config import (
    HTTP_RETRIES,
    HTTP_TIMEOUT_SECONDS,
    PALOALTO_API_VERSION,
    PALOALTO_BASE_URL,
    PALOALTO_PLACEHOLDER_IP,
    PALOALTO_QUARANTINE_GROUP,
    PALOALTO_SCOPE,
    PALOALTO_TOKEN,
    PALOALTO_VERIFY_TLS,
)
from posture_shared.interfaces.adapters import EnforcementAdapter
from posture_shared.models.enforcement import EnforcementAction, EnforcementResult


class PaloAltoAdapter(EnforcementAdapter):
    name = "paloalto"

    def __init__(self) -> None:
        self._session = requests.Session()
        self._session.trust_env = False
        self._consecutive_failures = 0
        self._opened_until = 0.0
        self._failure_threshold = 5
        self._cooldown_seconds = 60
        self._cache_ttl_seconds = 30.0
        self._cache_lock = threading.Lock()
        self._group_exists_cache: dict[str, float] = {}
        self._group_members_cache: dict[str, tuple[float, list[str]]] = {}
        self._resource_locks_guard = threading.Lock()
        self._resource_locks: dict[str, threading.RLock] = {}

    def execute(self, action: EnforcementAction) -> EnforcementResult:
        if action.action not in {"quarantine", "remove_from_group", "sync_group"}:
            return EnforcementResult(
                adapter=self.name,
                action=action.action,
                endpoint_id=action.endpoint_id,
                status="skipped",
                details={"message": "Unsupported Palo Alto action for this adapter"},
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
                            "message": "Palo Alto group verification failed after add",
                            "address": address_result,
                            "group": group_result,
                            "verification": verification,
                            "ip_address": action.ip_address,
                            "group_name": settings["group_name"],
                            "scope": settings["scope"],
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
                        "scope": settings["scope"],
                    },
                )

            if action.action == "remove_from_group":
                candidate_names = self._candidate_address_names(action.endpoint_id, action.ip_address)
                group_result = self._remove_group_members(settings, candidate_names)
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
                            "message": "Palo Alto group verification failed after remove",
                            "group": group_result,
                            "verification": verification,
                            "ip_address": action.ip_address,
                            "group_name": settings["group_name"],
                            "scope": settings["scope"],
                        },
                    )
                return EnforcementResult(
                    adapter=self.name,
                    action=action.action,
                    endpoint_id=action.endpoint_id,
                    status="success",
                    details={
                        "group": group_result,
                        "verification": verification,
                        "ip_address": action.ip_address,
                        "group_name": settings["group_name"],
                        "scope": settings["scope"],
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
                        "scope": settings["scope"],
                        "synced_ip_count": len(sync_result["synced"]),
                        "synced": sync_result["synced"],
                        "removed": sync_result["removed"],
                        "verification": sync_result["verification"],
                        "message": "Palo Alto group verification failed after sync",
                    },
                )
            return EnforcementResult(
                adapter=self.name,
                action=action.action,
                endpoint_id=action.endpoint_id,
                status="success",
                details={
                    "group_name": settings["group_name"],
                    "scope": settings["scope"],
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
                details={
                    "error": str(exc),
                    "ip_address": action.ip_address,
                    "group_name": settings["group_name"],
                    "scope": settings["scope"],
                },
            )

    def build_settings(self, adapter_settings: dict | None = None, group_name: str | None = None) -> dict:
        adapter_settings = adapter_settings or {}
        base_url = adapter_settings.get("base_url") or PALOALTO_BASE_URL
        token = adapter_settings.get("token") or PALOALTO_TOKEN
        scope = (adapter_settings.get("scope") or PALOALTO_SCOPE or "shared").strip()
        resolved_group_name = (
            group_name
            or adapter_settings.get("target_group")
            or adapter_settings.get("quarantine_group")
            or PALOALTO_QUARANTINE_GROUP
        )
        timeout = float(adapter_settings.get("timeout_seconds", HTTP_TIMEOUT_SECONDS))
        retries = int(adapter_settings.get("retries", HTTP_RETRIES))
        api_version = str(adapter_settings.get("api_version") or PALOALTO_API_VERSION).strip() or PALOALTO_API_VERSION
        verify_tls = self._parse_bool(adapter_settings.get("verify_tls"), default=PALOALTO_VERIFY_TLS)
        placeholder_ip = str(adapter_settings.get("placeholder_ip") or PALOALTO_PLACEHOLDER_IP).strip()
        return {
            "base_url": str(base_url).rstrip("/"),
            "token": token,
            "scope": scope or "shared",
            "group_name": resolved_group_name,
            "timeout": timeout,
            "retries": max(1, retries),
            "api_version": api_version,
            "verify_tls": verify_tls,
            "placeholder_ip": placeholder_ip or PALOALTO_PLACEHOLDER_IP,
        }

    def check_connection(self, settings: dict) -> dict:
        response = self._request_xml_version(settings)
        root = ET.fromstring(response.text)
        status = str(root.attrib.get("status", "")).lower()
        if status != "success":
            raise requests.RequestException("Palo Alto XML API returned non-success status for type=version")
        version = root.findtext(".//sw-version") or root.findtext(".//version")
        model = root.findtext(".//model")
        return {
            "http_status": response.status_code,
            "version": version,
            "model": model,
            "base_url": settings["base_url"],
            "scope": settings["scope"],
        }

    def _resolve_settings(self, action: EnforcementAction) -> dict:
        adapter_settings = action.decision.get("adapter_settings", {}) if action.decision else {}
        return self.build_settings(adapter_settings=adapter_settings, group_name=action.group_name)

    def _request_xml_version(self, settings: dict) -> requests.Response:
        url = f"{settings['base_url']}/api/"
        params = {"type": "version", "key": settings["token"]}
        return self._request(
            settings=settings,
            method="GET",
            url=url,
            params=params,
            json_payload=None,
            allow_not_found=False,
        )

    def _request_rest(
        self,
        settings: dict,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        payload: dict | None = None,
        allow_not_found: bool = False,
    ) -> requests.Response:
        url = f"{settings['base_url']}{path}"
        query = dict(params or {})
        headers = {
            "X-PAN-KEY": str(settings["token"]),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        response = self._request(
            settings=settings,
            method=method,
            url=url,
            params=query,
            json_payload=payload,
            headers=headers,
            allow_not_found=allow_not_found,
        )
        if allow_not_found and response.status_code == 404:
            return response
        self._raise_if_palo_error_payload(response)
        return response

    def _request(
        self,
        *,
        settings: dict,
        method: str,
        url: str,
        params: dict[str, Any] | None,
        json_payload: dict | None,
        headers: dict[str, str] | None = None,
        allow_not_found: bool = False,
    ) -> requests.Response:
        now = time.time()
        if self._opened_until > now:
            raise requests.RequestException(
                f"Palo Alto circuit breaker open until {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(self._opened_until))}"
            )
        if self._opened_until and self._opened_until <= now:
            self._opened_until = 0.0
            self._consecutive_failures = 0

        last_error: requests.RequestException | None = None
        for attempt in range(1, settings["retries"] + 1):
            try:
                response = self._session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_payload,
                    headers=headers,
                    timeout=settings["timeout"],
                    verify=settings["verify_tls"],
                )
                if allow_not_found and response.status_code == 404:
                    return response
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

    def _raise_if_palo_error_payload(self, response: requests.Response) -> None:
        payload = self._safe_json(response)
        if not payload:
            return
        status = str(payload.get("@status") or payload.get("status") or "").strip().lower()
        if status == "error":
            message = self._extract_palo_error_message(payload)
            raise requests.RequestException(message)

    def _extract_palo_error_message(self, payload: dict[str, Any]) -> str:
        candidates = [
            payload.get("message"),
            payload.get("msg"),
            payload.get("details"),
            payload.get("result"),
        ]
        for candidate in candidates:
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
        if isinstance(payload.get("result"), dict):
            inner = payload.get("result", {})
            msg = inner.get("msg") or inner.get("message")
            if isinstance(msg, str) and msg.strip():
                return msg.strip()
        return "Palo Alto API reported an error"

    def _safe_json(self, response: requests.Response) -> dict[str, Any]:
        if not response.content:
            return {}
        try:
            payload = response.json()
        except ValueError:
            return {}
        if isinstance(payload, dict):
            return payload
        return {}

    def _address_name(self, identifier: str) -> str:
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in identifier.lower())
        return f"posture-{safe[:40]}"

    def _placeholder_address_name(self, group_name: str) -> str:
        safe_group = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in group_name.lower())
        return f"posture-placeholder-{safe_group[:24]}"

    def _candidate_address_names(self, endpoint_id: str, ip_address: str) -> list[str]:
        names: list[str] = []
        preferred = self._address_name(ip_address)
        fallback = self._address_name(endpoint_id)
        for item in (preferred, fallback):
            if item not in names:
                names.append(item)
        return names

    def _location_query(self, settings: dict) -> dict[str, str]:
        scope = str(settings["scope"] or "").strip()
        lowered = scope.lower()
        if lowered.startswith("vsys:"):
            vsys_name = scope.split(":", 1)[1].strip() or "vsys1"
            return {"location": "vsys", "vsys": vsys_name}
        if lowered in {"", "shared"}:
            return {"location": "shared"}
        return {"location": "device-group", "device-group": scope}

    def _address_path(self, settings: dict) -> str:
        return f"/restapi/v{settings['api_version']}/Objects/Addresses"

    def _group_path(self, settings: dict) -> str:
        return f"/restapi/v{settings['api_version']}/Objects/AddressGroups"

    def _cache_key(self, settings: dict, group_name: str) -> str:
        return "|".join(
            [
                str(settings.get("base_url") or "").lower(),
                str(settings.get("scope") or "").lower(),
                str(group_name or "").lower(),
            ]
        )

    def _get_resource_lock(self, kind: str, key: str) -> threading.RLock:
        lock_key = f"{kind}|{key}"
        with self._resource_locks_guard:
            lock = self._resource_locks.get(lock_key)
            if lock is None:
                lock = threading.RLock()
                self._resource_locks[lock_key] = lock
            return lock

    def _mark_group_exists_cached(self, cache_key: str) -> None:
        expiry = time.time() + self._cache_ttl_seconds
        with self._cache_lock:
            self._group_exists_cache[cache_key] = expiry

    def _is_group_exists_cached(self, cache_key: str) -> bool:
        now = time.time()
        with self._cache_lock:
            expiry = self._group_exists_cache.get(cache_key, 0.0)
            if expiry > now:
                return True
            if cache_key in self._group_exists_cache:
                del self._group_exists_cache[cache_key]
            return False

    def _clear_group_exists_cache(self, cache_key: str) -> None:
        with self._cache_lock:
            self._group_exists_cache.pop(cache_key, None)

    def _set_group_members_cache(self, cache_key: str, members: list[str]) -> None:
        expiry = time.time() + self._cache_ttl_seconds
        with self._cache_lock:
            self._group_members_cache[cache_key] = (expiry, list(members))

    def _get_group_members_cache(self, cache_key: str) -> list[str] | None:
        now = time.time()
        with self._cache_lock:
            cached = self._group_members_cache.get(cache_key)
            if cached is None:
                return None
            expiry, members = cached
            if expiry <= now:
                del self._group_members_cache[cache_key]
                return None
            return list(members)

    def _clear_group_members_cache(self, cache_key: str) -> None:
        with self._cache_lock:
            self._group_members_cache.pop(cache_key, None)

    def _extract_entries(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        if not isinstance(payload, dict):
            return []
        result = payload.get("result")
        if isinstance(result, dict) and "entry" in result:
            result = result["entry"]
        if isinstance(result, dict):
            return [result]
        if isinstance(result, list):
            return [entry for entry in result if isinstance(entry, dict)]
        entry = payload.get("entry")
        if isinstance(entry, dict):
            return [entry]
        if isinstance(entry, list):
            return [item for item in entry if isinstance(item, dict)]
        return []

    def _extract_group_members(self, entry: dict[str, Any]) -> list[str]:
        static = entry.get("static")
        if not isinstance(static, dict):
            return []
        members = static.get("member", [])
        if isinstance(members, str):
            return [members]
        if isinstance(members, list):
            resolved: list[str] = []
            for item in members:
                if isinstance(item, str) and item:
                    if item not in resolved:
                        resolved.append(item)
            return resolved
        return []

    def _get_group_entry(self, settings: dict, group_name: str) -> dict[str, Any] | None:
        params = {**self._location_query(settings), "name": group_name}
        response = self._request_rest(
            settings,
            "GET",
            self._group_path(settings),
            params=params,
            allow_not_found=True,
        )
        if response.status_code == 404:
            return None
        entries = self._extract_entries(self._safe_json(response))
        if not entries:
            return None
        for entry in entries:
            if str(entry.get("@name") or "") == group_name:
                return entry
        return entries[0]

    def _create_group(self, settings: dict, group_name: str, members: list[str]) -> dict[str, str]:
        params = self._location_query(settings)
        payload = {"entry": [{"@name": group_name, "static": {"member": members}}]}
        self._request_rest(settings, "POST", self._group_path(settings), params=params, payload=payload)
        return {"group": group_name, "operation": "created"}

    def _update_group_members(self, settings: dict, group_name: str, members: list[str]) -> None:
        params = {**self._location_query(settings), "name": group_name}
        payload = {"entry": [{"@name": group_name, "static": {"member": members}}]}
        self._request_rest(settings, "PUT", self._group_path(settings), params=params, payload=payload)

    def _ensure_address(self, settings: dict, address_name: str, ip_address: str) -> dict[str, str]:
        params = {**self._location_query(settings), "name": address_name}
        payload = {"entry": [{"@name": address_name, "ip-netmask": f"{ip_address}/32"}]}
        try:
            self._request_rest(settings, "PUT", self._address_path(settings), params=params, payload=payload)
            return {"name": address_name, "operation": "updated"}
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                create_params = self._location_query(settings)
                self._request_rest(
                    settings,
                    "POST",
                    self._address_path(settings),
                    params=create_params,
                    payload=payload,
                )
                return {"name": address_name, "operation": "created"}
            raise

    def _dedupe_members(self, members: list[str]) -> list[str]:
        deduped: list[str] = []
        for member in members:
            if member and member not in deduped:
                deduped.append(member)
        return deduped

    def _ensure_group_member(self, settings: dict, address_name: str) -> dict[str, str]:
        group_name = str(settings["group_name"])
        cache_key = self._cache_key(settings, group_name)
        lock = self._get_resource_lock("group", cache_key)
        placeholder_name = self._placeholder_address_name(group_name)

        with lock:
            cached_members = self._get_group_members_cache(cache_key)
            if cached_members is not None and self._is_group_exists_cached(cache_key):
                members = cached_members
            else:
                group_entry = self._get_group_entry(settings, group_name)
                if group_entry is None:
                    self._create_group(settings, group_name, [address_name])
                    self._mark_group_exists_cached(cache_key)
                    self._set_group_members_cache(cache_key, [address_name])
                    return {"group": group_name, "operation": "created_with_member"}
                members = self._extract_group_members(group_entry)
                self._mark_group_exists_cached(cache_key)
                self._set_group_members_cache(cache_key, members)

            changed = False
            if placeholder_name in members:
                members = [member for member in members if member != placeholder_name]
                changed = True
            if address_name not in members:
                members.append(address_name)
                changed = True
            members = self._dedupe_members(members)
            if not members:
                members = [address_name]
                changed = True

            if changed:
                self._update_group_members(settings, group_name, members)
                self._set_group_members_cache(cache_key, members)
                self._mark_group_exists_cached(cache_key)
                return {"group": group_name, "operation": "added"}

            return {"group": group_name, "operation": "already_present"}

    def _remove_group_members(self, settings: dict, address_names: list[str]) -> dict[str, Any]:
        group_name = str(settings["group_name"])
        cache_key = self._cache_key(settings, group_name)
        lock = self._get_resource_lock("group", cache_key)
        placeholder_name = self._placeholder_address_name(group_name)
        address_set = set(address_names)

        with lock:
            group_entry = self._get_group_entry(settings, group_name)
            if group_entry is None:
                self._clear_group_exists_cache(cache_key)
                self._clear_group_members_cache(cache_key)
                return {"group": group_name, "operation": "already_absent", "removed": []}

            members = self._extract_group_members(group_entry)
            before_members = list(members)
            members = [member for member in members if member not in address_set]
            removed = sorted(set(before_members) - set(members))

            if not members:
                self._ensure_address(settings, placeholder_name, settings["placeholder_ip"])
                members = [placeholder_name]

            members = self._dedupe_members(members)
            if members != before_members:
                self._update_group_members(settings, group_name, members)
                self._set_group_members_cache(cache_key, members)
                self._mark_group_exists_cached(cache_key)
                operation = "removed" if removed else "updated_placeholder"
                return {"group": group_name, "operation": operation, "removed": removed}

            self._set_group_members_cache(cache_key, members)
            self._mark_group_exists_cached(cache_key)
            return {"group": group_name, "operation": "already_absent", "removed": []}

    def _group_member_names(self, settings: dict) -> set[str]:
        group_name = str(settings["group_name"])
        cache_key = self._cache_key(settings, group_name)
        cached_members = self._get_group_members_cache(cache_key)
        if cached_members is not None:
            return set(cached_members)
        group_entry = self._get_group_entry(settings, group_name)
        if group_entry is None:
            self._clear_group_exists_cache(cache_key)
            self._clear_group_members_cache(cache_key)
            return set()
        members = self._extract_group_members(group_entry)
        self._set_group_members_cache(cache_key, members)
        self._mark_group_exists_cached(cache_key)
        return set(members)

    def _verify_group_membership(
        self,
        settings: dict,
        *,
        required_present: set[str],
        required_absent: set[str],
    ) -> dict[str, Any]:
        group_name = str(settings["group_name"])
        placeholder_name = self._placeholder_address_name(group_name)
        actual_names = self._group_member_names(settings)
        missing = sorted(required_present - actual_names)
        still_present = sorted(name for name in actual_names.intersection(required_absent) if name != placeholder_name)
        return {
            "ok": len(missing) == 0 and len(still_present) == 0,
            "missing": missing,
            "still_present": still_present,
            "group_member_count": len(actual_names),
        }

    def _is_posture_managed_name(self, address_name: str) -> bool:
        return address_name.startswith("posture-")

    def _sync_group_ips(self, settings: dict, group_ips: list[str]) -> dict[str, Any]:
        group_name = str(settings["group_name"])
        cache_key = self._cache_key(settings, group_name)
        lock = self._get_resource_lock("group", cache_key)
        placeholder_name = self._placeholder_address_name(group_name)

        synced: list[dict[str, Any]] = []
        desired_members: list[str] = []
        desired_names: set[str] = set()
        for ip_address in group_ips:
            address_name = self._address_name(ip_address)
            address_result = self._ensure_address(settings, address_name, ip_address)
            synced.append({"ip_address": ip_address, "address": address_result})
            if address_name not in desired_names:
                desired_names.add(address_name)
                desired_members.append(address_name)

        with lock:
            group_entry = self._get_group_entry(settings, group_name)
            if group_entry is None:
                initial_members = list(desired_members)
                if not initial_members:
                    self._ensure_address(settings, placeholder_name, settings["placeholder_ip"])
                    initial_members = [placeholder_name]
                self._create_group(settings, group_name, initial_members)
                self._mark_group_exists_cached(cache_key)
                self._set_group_members_cache(cache_key, initial_members)
                current_members = []
            else:
                current_members = self._extract_group_members(group_entry)

            retained_non_posture = [name for name in current_members if not self._is_posture_managed_name(name)]
            final_members = self._dedupe_members(retained_non_posture + desired_members)

            if not final_members:
                self._ensure_address(settings, placeholder_name, settings["placeholder_ip"])
                final_members = [placeholder_name]

            if final_members != current_members:
                self._update_group_members(settings, group_name, final_members)
            self._set_group_members_cache(cache_key, final_members)
            self._mark_group_exists_cached(cache_key)

            current_posture = {
                name
                for name in current_members
                if self._is_posture_managed_name(name) and name != placeholder_name
            }
            final_posture = {
                name
                for name in final_members
                if self._is_posture_managed_name(name) and name != placeholder_name
            }
            removed = sorted(current_posture - final_posture)

        actual_names = self._group_member_names(settings)
        actual_posture_names = {
            name
            for name in actual_names
            if self._is_posture_managed_name(name) and name != placeholder_name
        }
        verification = {
            "ok": desired_names.issubset(actual_names) and len(actual_posture_names - desired_names) == 0,
            "expected_posture_members": sorted(desired_names),
            "actual_posture_members": sorted(actual_posture_names),
            "missing_posture_members": sorted(desired_names - actual_names),
            "unexpected_posture_members": sorted(actual_posture_names - desired_names),
            "group_member_count": len(actual_names),
            "placeholder_member": placeholder_name if placeholder_name in actual_names else None,
        }
        return {"synced": synced, "removed": removed, "verification": verification}

    def _parse_bool(self, raw_value: Any, *, default: bool) -> bool:
        if raw_value is None:
            return default
        if isinstance(raw_value, bool):
            return raw_value
        text = str(raw_value).strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off"}:
            return False
        return default
