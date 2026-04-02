from collectors.base import CollectorModule
from utils import ensure_list, run_powershell_json


class ServiceCollector(CollectorModule):
    name = "services"

    def collect(self) -> dict:
        try:
            payload = run_powershell_json(
                r"""
                Get-Service |
                  Select-Object Name, DisplayName, Status, StartType |
                  ConvertTo-Json -Compress
                """
            )
        except Exception:
            payload = []

        services = []
        for item in ensure_list(payload):
            services.append(
                {
                    "name": item.get("Name"),
                    "display_name": item.get("DisplayName"),
                    "status": str(item.get("Status")) if item.get("Status") else None,
                    "start_type": str(item.get("StartType")) if item.get("StartType") else None,
                }
            )
        return {"services": services}
