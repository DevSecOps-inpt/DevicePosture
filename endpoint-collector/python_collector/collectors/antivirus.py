from collectors.base import CollectorModule
from utils import ensure_list, run_powershell_json


class AntivirusCollector(CollectorModule):
    name = "antivirus_products"

    def collect(self) -> dict:
        try:
            payload = run_powershell_json(
                r"""
                Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct |
                  Select-Object displayName, productState |
                  ConvertTo-Json -Compress
                """
            )
        except Exception:
            payload = []

        products = []
        for item in ensure_list(payload):
            name = item.get("displayName")
            if not name:
                continue
            products.append(
                {
                    "name": name,
                    "identifier": name.lower(),
                    "state": str(item.get("productState")) if item.get("productState") else None,
                }
            )
        return {"antivirus_products": products}
