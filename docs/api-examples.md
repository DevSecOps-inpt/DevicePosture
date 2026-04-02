# API Examples

## Telemetry API

Run locally:

```powershell
cd C:\Users\essag\Documents\Playground\services\telemetry-api
uvicorn app.main:app --reload --port 8001
```

Important routes:

- `POST /telemetry`
- `GET /endpoints`
- `GET /endpoints/{endpoint_id}/latest`
- `GET /endpoints/{endpoint_id}/history`
- `GET /lifecycle-events`

Sample request:

```powershell
curl -X POST http://127.0.0.1:8001/telemetry ^
  -H "Content-Type: application/json" ^
  -d "{\"schema_version\":\"1.0\",\"collector_type\":\"python-windows\",\"endpoint_id\":\"ws-001\",\"hostname\":\"WS-001\",\"collected_at\":\"2026-03-31T01:00:00Z\",\"network\":{\"ipv4\":\"192.168.1.25\"},\"os\":{\"name\":\"Microsoft Windows 11 Pro\",\"version\":\"10.0.22631\",\"build\":\"22631\"},\"hotfixes\":[{\"id\":\"KB5039212\"}],\"services\":[],\"processes\":[],\"antivirus_products\":[{\"name\":\"Microsoft Defender Antivirus\",\"identifier\":\"microsoft defender antivirus\"}],\"extras\":{}}"
```

## Policy Service

Run locally:

```powershell
cd C:\Users\essag\Documents\Playground\services\policy-service
uvicorn app.main:app --reload --port 8002
```

Important routes:

- `POST /policies`
- `GET /policies`
- `GET /policies/{policy_id}`
- `PUT /policies/{policy_id}`
- `DELETE /policies/{policy_id}`
- `POST /policies/{policy_id}/assignments`
- `GET /policy-match/{endpoint_id}`
- `GET /lifecycle-policy-match/{event_type}/{endpoint_id}`

Example policy JSON:

```json
{
  "name": "Windows 11 baseline",
  "description": "Require Windows 11 build, required KBs, and an allowed antivirus",
  "target_action": "quarantine",
  "is_active": true,
  "conditions": [
    {
      "type": "os_version",
      "field": "os",
      "operator": "windows_build_gte",
      "value": {
        "name": "Microsoft Windows 11 Pro",
        "min_build": 22631
      }
    },
    {
      "type": "required_kbs",
      "field": "hotfixes",
      "operator": "contains_all",
      "value": ["KB5039212", "KB5039302"]
    },
    {
      "type": "allowed_antivirus",
      "field": "antivirus_products",
      "operator": "contains_any",
      "value": ["microsoft defender antivirus", "crowdstrike falcon"]
    }
  ]
}
```

Create the policy:

```powershell
curl -X POST http://127.0.0.1:8002/policies ^
  -H "Content-Type: application/json" ^
  -d "@policy.json"
```

Example lifecycle policy JSON:

```json
{
  "name": "On First Seen",
  "description": "Runs when endpoint reports telemetry for the first time",
  "policy_scope": "lifecycle",
  "lifecycle_event_type": "first_seen",
  "target_action": "allow",
  "is_active": true,
  "conditions": []
}
```

Assign it to a default target:

```powershell
curl -X POST http://127.0.0.1:8002/policies/1/assignments ^
  -H "Content-Type: application/json" ^
  -d "{\"assignment_type\":\"default\",\"assignment_value\":\"default\"}"
```

## Evaluation Engine

Run locally:

```powershell
cd C:\Users\essag\Documents\Playground\services\evaluation-engine
$env:TELEMETRY_API_URL="http://127.0.0.1:8001"
$env:POLICY_SERVICE_URL="http://127.0.0.1:8002"
$env:ENFORCEMENT_SERVICE_URL="http://127.0.0.1:8004"
uvicorn app.main:app --reload --port 8003
```

Important routes:

- `POST /evaluate/{endpoint_id}`
- `GET /results/{endpoint_id}/latest`
- `GET /results/{endpoint_id}`

Evaluate an endpoint:

```powershell
curl -X POST http://127.0.0.1:8003/evaluate/ws-001
```

Example decision JSON:

```json
{
  "endpoint_id": "ws-001",
  "endpoint_ip": "192.168.1.25",
  "policy_id": 1,
  "policy_name": "Windows 11 baseline",
  "compliant": false,
  "recommended_action": "quarantine",
  "reasons": [
    {
      "check_type": "required_kbs",
      "message": "Missing required KB patches: KB5039302"
    }
  ],
  "evaluated_at": "2026-03-31T01:05:00Z",
  "telemetry_timestamp": "2026-03-31T01:00:00Z"
}
```

## Enforcement Service

Run locally:

```powershell
cd C:\Users\essag\Documents\Playground\services\enforcement-service
$env:FORTIGATE_BASE_URL="https://fortigate.example.local"
$env:FORTIGATE_TOKEN="your-token"
$env:FORTIGATE_QUARANTINE_GROUP="NON_COMPLIANT_ENDPOINTS"
uvicorn app.main:app --reload --port 8004
```

Important routes:

- `POST /decisions`
- `POST /actions`
- `GET /enforcement/{endpoint_id}/latest`
- `GET /audit-events`

Example direct action payload:

```json
{
  "adapter": "fortigate",
  "action": "quarantine",
  "endpoint_id": "ws-001",
  "ip_address": "192.168.1.25",
  "decision": {
    "policy_name": "Windows 11 baseline"
  }
}
```

Example enforcement response:

```json
{
  "adapter": "fortigate",
  "action": "quarantine",
  "endpoint_id": "ws-001",
  "status": "success",
  "details": {
    "address": {
      "name": "posture-ws-001",
      "operation": "created"
    },
    "group": {
      "group": "NON_COMPLIANT_ENDPOINTS",
      "operation": "added"
    },
    "ip_address": "192.168.1.25"
  },
  "completed_at": "2026-03-31T01:05:05Z"
}
```

## Event and audit model

The MVP persists audit events instead of publishing to Kafka or RabbitMQ. Current event types:

- `endpoint.evaluated`
- `endpoint.compliant`
- `endpoint.non_compliant`
- `endpoint.quarantined`

These are intentionally generic so a later event bus can reuse the same payload shapes.
