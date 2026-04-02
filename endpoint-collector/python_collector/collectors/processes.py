from collectors.base import CollectorModule
from utils import ensure_list, run_powershell_json


class ProcessCollector(CollectorModule):
    name = "processes"

    def collect(self) -> dict:
        try:
            payload = run_powershell_json(
                r"""
                Get-Process |
                  Select-Object Id, ProcessName |
                  ConvertTo-Json -Compress
                """
            )
        except Exception:
            payload = []

        processes = []
        for item in ensure_list(payload):
            processes.append({"pid": item.get("Id"), "name": item.get("ProcessName")})
        return {"processes": processes}
