# Endpoint Collectors

The recommended Windows endpoint agent is the PowerShell collector because it runs on a normal Windows installation without requiring Python or extra dependencies.

Collectors currently included:

- `powershell/device_posture_collector.ps1`: Windows-native agent with JSON config, background loop, and plugin-style collectors
- `python_collector`: optional Python collector kept for development and local testing
- `linux/`: placeholder for a future Linux-native collector

## Windows PowerShell agent structure

```text
endpoint-collector/powershell/
|-- collector.config.json
|-- device_posture_collector.ps1
|-- install_collector_task.ps1
|-- uninstall_collector_task.ps1
`-- collectors/
    |-- antivirus.ps1
    |-- hotfixes.ps1
    |-- processes.ps1
    |-- services.ps1
    `-- system_info.ps1
```

## What each PowerShell file does

- `device_posture_collector.ps1`: loads config, loads collector plugins, builds normalized JSON, sends telemetry, and runs the periodic loop
- `collector.config.json`: agent interval, heartbeat grace multiplier, API URL, retries, headers, logging path, enabled collectors
- `collectors/*.ps1`: one plugin per data source
- `install_collector_task.ps1`: installs the background agent as a Windows startup scheduled task
- `uninstall_collector_task.ps1`: removes the scheduled task

## Example PowerShell config

```json
{
  "agent": {
    "name": "windows-powershell-agent",
    "interval_seconds": 300,
    "active_grace_multiplier": 3,
    "log_path": "C:\\ProgramData\\DevicePosture\\collector.log",
    "write_payload_file": ""
  },
  "transport": {
    "enabled": true,
    "url": "http://127.0.0.1:8001/telemetry",
    "timeout_seconds": 10,
    "retry_count": 3,
    "bearer_token": "",
    "headers": {}
  },
  "collectors": {
    "enabled": [
      "system_info",
      "hotfixes",
      "services",
      "processes",
      "antivirus"
    ],
    "settings": {}
  }
}
```

## Run once on Windows

```powershell
powershell -ExecutionPolicy Bypass -File .\endpoint-collector\powershell\device_posture_collector.ps1 -Mode Once
powershell -ExecutionPolicy Bypass -File .\endpoint-collector\powershell\device_posture_collector.ps1 -Mode Once -ApiUrl http://127.0.0.1:8001/telemetry
```

## Run as a background agent

```powershell
powershell -ExecutionPolicy Bypass -File .\endpoint-collector\powershell\device_posture_collector.ps1 -Mode Run -ConfigPath .\endpoint-collector\powershell\collector.config.json -Quiet
```

## Install the agent to start with Windows

```powershell
powershell -ExecutionPolicy Bypass -File .\endpoint-collector\powershell\install_collector_task.ps1
```

Remove it later with:

```powershell
powershell -ExecutionPolicy Bypass -File .\endpoint-collector\powershell\uninstall_collector_task.ps1
```

The startup task is the install-free Windows-friendly way to keep the agent running in the background.

## Heartbeat / activity tracking

Each telemetry payload now includes a sanitized runtime snapshot from the endpoint:

- `agent.interval_seconds`
- `agent.active_grace_multiplier`
- `agent.enabled_collectors`
- `agent.transport_enabled`

The backend uses `interval_seconds * active_grace_multiplier` as the heartbeat timeout. With the default settings, an agent configured for `60` seconds is marked inactive after `180` seconds without telemetry.

## How to extend the PowerShell agent

1. Add a new `.ps1` file under `endpoint-collector/powershell/collectors/`.
2. Register it with `Register-Collector -Name "your_collector" -ScriptBlock { ... }`.
3. Return a partial payload hashtable.
4. Add the collector name to `collectors.enabled` in `collector.config.json`.

This is ready for future plugins such as:

- registry collection
- certificate checks
- domain membership
- antivirus vendor-specific checks

## Python collector structure

```text
endpoint-collector/python_collector/
|-- collector.py
|-- http_client.py
|-- utils.py
`-- collectors/
    |-- __init__.py
    |-- antivirus.py
    |-- base.py
    |-- hotfixes.py
    |-- processes.py
    |-- services.py
    `-- system_info.py
```

## Example normalized JSON

```json
{
  "schema_version": "1.0",
  "collector_type": "windows-powershell-agent",
  "endpoint_id": "6f6d5f9c-b8f6-4f77-bbf8-aaaaaaaaaaaa",
  "hostname": "WS-001",
  "collected_at": "2026-03-31T01:00:00Z",
  "agent": {
    "name": "windows-powershell-agent",
    "interval_seconds": 300,
    "active_grace_multiplier": 3,
    "enabled_collectors": [
      "system_info",
      "hotfixes",
      "services",
      "processes",
      "antivirus"
    ],
    "transport_enabled": true
  },
  "network": {
    "ipv4": "192.168.1.25"
  },
  "os": {
    "name": "Microsoft Windows 11 Pro",
    "version": "10.0.22631",
    "build": "22631"
  },
  "hotfixes": [
    {
      "id": "KB5039212",
      "description": "Security Update",
      "installed_on": "2026-03-20"
    }
  ],
  "services": [
    {
      "name": "WinDefend",
      "display_name": "Microsoft Defender Antivirus Service",
      "status": "Running",
      "start_type": "Auto"
    }
  ],
  "processes": [
    {
      "pid": 884,
      "name": "MsMpEng"
    }
  ],
  "antivirus_products": [
    {
      "name": "Microsoft Defender Antivirus",
      "identifier": "microsoft defender antivirus",
      "state": "397568"
    }
  ],
  "extras": {}
}
```
