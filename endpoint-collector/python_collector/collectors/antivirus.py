from collectors.base import CollectorModule
from utils import ensure_list, run_powershell_json


class AntivirusCollector(CollectorModule):
    name = "antivirus_products"

    def collect(self) -> dict:
        try:
            payload = run_powershell_json(
                r"""
                $products = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct |
                  Select-Object displayName, productState
                $mp = $null
                try {
                  $mp = Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AMServiceEnabled, TamperProtectionSource
                } catch {
                  $mp = $null
                }
                @{
                  products = $products
                  mp_status = $mp
                } | ConvertTo-Json -Compress -Depth 5
                """
            )
        except Exception:
            payload = {}

        products_payload = ensure_list((payload or {}).get("products", []))
        mp_status = (payload or {}).get("mp_status") or {}
        products = []
        for item in products_payload:
            name = item.get("displayName")
            if not name:
                continue
            identifier = name.lower()
            is_defender = "defender" in identifier
            products.append(
                {
                    "name": name,
                    "identifier": identifier,
                    "state": str(item.get("productState")) if item.get("productState") else None,
                    "real_time_protection_enabled": bool(mp_status.get("RealTimeProtectionEnabled")) if is_defender and mp_status.get("RealTimeProtectionEnabled") is not None else None,
                    "antivirus_enabled": bool(mp_status.get("AntivirusEnabled")) if is_defender and mp_status.get("AntivirusEnabled") is not None else None,
                    "am_service_enabled": bool(mp_status.get("AMServiceEnabled")) if is_defender and mp_status.get("AMServiceEnabled") is not None else None,
                    "tamper_protection_source": str(mp_status.get("TamperProtectionSource")) if is_defender and mp_status.get("TamperProtectionSource") else None,
                }
            )
        return {"antivirus_products": products}
