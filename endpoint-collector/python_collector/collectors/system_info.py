import os
import socket

from collectors.base import CollectorModule
from utils import run_powershell_json


class SystemInfoCollector(CollectorModule):
    name = "system_info"

    def collect(self) -> dict:
        try:
            payload = run_powershell_json(
                r"""
                $machineGuid = $null
                try {
                  $machineGuid = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid'
                } catch {}
                $os = Get-CimInstance Win32_OperatingSystem
                $ip = Get-NetIPAddress -AddressFamily IPv4 |
                  Where-Object { $_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1' } |
                  Select-Object -First 1 -ExpandProperty IPAddress
                [pscustomobject]@{
                  endpoint_id = $machineGuid
                  hostname = $env:COMPUTERNAME
                  ipv4 = $ip
                  os_name = $os.Caption
                  os_version = $os.Version
                  os_build = $os.BuildNumber
                } | ConvertTo-Json -Compress
                """
            )
        except Exception:
            payload = {}

        hostname = payload.get("hostname") or os.environ.get("COMPUTERNAME") or socket.gethostname()
        endpoint_id = payload.get("endpoint_id") or hostname
        return {
            "endpoint_id": endpoint_id,
            "hostname": hostname,
            "network": {"ipv4": payload.get("ipv4")},
            "os": {
                "name": payload.get("os_name"),
                "version": payload.get("os_version"),
                "build": str(payload.get("os_build")) if payload.get("os_build") is not None else None,
            },
        }
