from collectors.base import CollectorModule
from utils import ensure_list, run_powershell_json


class HotfixCollector(CollectorModule):
    name = "hotfixes"

    def collect(self) -> dict:
        try:
            payload = run_powershell_json(
                r"""
                Get-HotFix |
                  Select-Object HotFixID, Description, InstalledOn |
                  ConvertTo-Json -Compress
                """
            )
        except Exception:
            payload = []

        hotfixes = []
        for item in ensure_list(payload):
            hotfixes.append(
                {
                    "id": item.get("HotFixID"),
                    "description": item.get("Description"),
                    "installed_on": str(item.get("InstalledOn")) if item.get("InstalledOn") else None,
                }
            )
        return {"hotfixes": hotfixes}
