# MVP Telemetry Payload Contract

This document defines the JSON contracts used by the MVP PowerShell collector and `telemetry-api`.

The collector sends four payload types. Only posture payloads trigger policy evaluation by default. Heartbeat and inventory payloads update liveness or inventory state without enforcement.

## Common Rules

- `Content-Type` must be `application/json`.
- Gzip is supported when `Content-Encoding: gzip` is present, but the MVP collector defaults gzip off for easier troubleshooting.
- `endpoint_ref` is the preferred endpoint identifier.
- `endpoint_id` is accepted as an alias when `endpoint_ref` is missing.
- `ip_address`, `current_ip`, and `network.ipv4` are accepted as IP aliases.
- `sent_at`, `collected_at`, and `timestamp` are accepted as timestamp aliases.
- Validation errors return JSON with `error`, `payload_type`, `missing_fields`, and `invalid_fields`.

## Heartbeat

Endpoint:

```text
POST /telemetry/heartbeat
```

Required fields:

- `payload_type`: `heartbeat`
- `endpoint_ref`: stable endpoint identifier
- `hostname`: endpoint hostname

Optional fields:

- `ip_address`
- `heartbeat_interval_seconds`
- `interval_seconds`
- `sequence_number`
- `sent_at`

Example request:

```json
{
  "payload_type": "heartbeat",
  "endpoint_ref": "pc-01",
  "hostname": "PC-01",
  "ip_address": "10.10.10.10",
  "heartbeat_interval_seconds": 3,
  "sequence_number": 1,
  "sent_at": "2026-05-13T00:00:00Z"
}
```

Example response:

```json
{
  "status": "accepted",
  "endpoint_id": "pc-01",
  "endpoint_ref": "pc-01",
  "record_id": null,
  "stored_at": "2026-05-13T00:00:00Z",
  "payload_type": "heartbeat",
  "evaluation_triggered": false,
  "resync_required": false,
  "reason": null
}
```

Heartbeat updates endpoint liveness and never triggers policy evaluation.

## Posture Snapshot

Endpoint:

```text
POST /telemetry/posture
```

Required fields:

- `payload_type`: `posture_snapshot` or `posture`
- `endpoint_ref`: stable endpoint identifier
- `hostname`: endpoint hostname

Optional fields:

- `ip_address`
- `posture_interval_seconds`
- `sequence_number`
- `sent_at`
- `posture.system_info`
- `posture.antivirus`
- `posture.required_services`
- `posture.forbidden_processes_found`
- `posture.security_processes_found`

Example request:

```json
{
  "payload_type": "posture_snapshot",
  "endpoint_ref": "pc-01",
  "hostname": "PC-01",
  "ip_address": "10.10.10.10",
  "posture_interval_seconds": 3,
  "sequence_number": 1,
  "sent_at": "2026-05-13T00:00:00Z",
  "posture": {
    "system_info": {
      "name": "Windows",
      "version": "11",
      "build": "22631"
    },
    "antivirus": [],
    "required_services": [],
    "forbidden_processes_found": [],
    "security_processes_found": []
  }
}
```

Example response:

```json
{
  "status": "accepted",
  "endpoint_id": "pc-01",
  "endpoint_ref": "pc-01",
  "record_id": 10,
  "stored_at": "2026-05-13T00:00:00Z",
  "payload_type": "posture_snapshot",
  "evaluation_triggered": true,
  "resync_required": false,
  "reason": null
}
```

Posture snapshots update liveness, store the latest posture record, and trigger policy evaluation by default.

## Inventory Full

Endpoint:

```text
POST /telemetry/inventory/full
```

Required fields:

- `payload_type`: `inventory_full`
- `endpoint_ref`: stable endpoint identifier
- `baseline_id`: inventory baseline identifier
- `sequence_number`: baseline sequence number

Optional fields:

- `hostname`
- `ip_address`
- `category`: `all`, `services`, `processes`, `hotfixes`, or `software`
- `sent_at`
- `inventory.services`
- `inventory.processes`
- `inventory.hotfixes`
- `inventory.software`

Example request:

```json
{
  "payload_type": "inventory_full",
  "endpoint_ref": "pc-01",
  "hostname": "PC-01",
  "ip_address": "10.10.10.10",
  "category": "all",
  "baseline_id": "baseline-001",
  "sequence_number": 1,
  "sent_at": "2026-05-13T00:00:00Z",
  "inventory": {
    "services": [],
    "processes": [],
    "hotfixes": [],
    "software": []
  }
}
```

Inventory full updates liveness and inventory baseline state. It does not trigger policy evaluation by default.

## Inventory Delta

Endpoint:

```text
POST /telemetry/inventory/delta
```

Required fields:

- `payload_type`: `inventory_delta`
- `endpoint_ref`: stable endpoint identifier
- `baseline_id`
- `sequence_number`
- `current_hash`
- `changes`

Optional fields:

- `category`
- `previous_hash`
- `sent_at`

Example request:

```json
{
  "payload_type": "inventory_delta",
  "endpoint_ref": "pc-01",
  "category": "services",
  "baseline_id": "baseline-001",
  "sequence_number": 2,
  "previous_hash": "hash-001",
  "current_hash": "hash-002",
  "changes": {
    "added": [],
    "updated": [],
    "removed": []
  },
  "sent_at": "2026-05-13T00:00:00Z"
}
```

Example resync response:

```json
{
  "status": "resync_required",
  "endpoint_id": "pc-01",
  "endpoint_ref": "pc-01",
  "record_id": null,
  "stored_at": "2026-05-13T00:00:00Z",
  "payload_type": "inventory_delta",
  "evaluation_triggered": false,
  "resync_required": true,
  "reason": "baseline_mismatch"
}
```

Inventory delta updates liveness. If the baseline or sequence is invalid, the API returns a structured `resync_required` response instead of a generic `400`.

## Manual Validation

From `endpoint-collector/powershell`:

```powershell
.\test-send-heartbeat.ps1 -BaseUrl http://127.0.0.1:8011
.\test-send-posture.ps1 -BaseUrl http://127.0.0.1:8011
.\test-send-inventory-full.ps1 -BaseUrl http://127.0.0.1:8011
```

If `POSTURE_API_KEY` is enabled on the API, pass `-ApiKey`.
