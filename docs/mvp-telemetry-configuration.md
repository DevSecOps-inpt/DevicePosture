# MVP Telemetry Configuration

The MVP collector now separates telemetry by purpose instead of sending one
large inventory payload every few seconds. This keeps posture verification
near-real-time while preserving full inventory visibility.

## Payload Types

| Payload type | Default interval | Triggers policy evaluation | Purpose |
| --- | ---: | --- | --- |
| `heartbeat` | `3s` | No | Proves endpoint liveness with a tiny payload. |
| `posture_snapshot` | `3s` | Yes | Sends compact security posture used for near-real-time trust decisions. |
| `inventory_full` | `900s` | No | Sends a full services/processes/hotfixes/software baseline. |
| `inventory_delta` | `10s` or on change | No | Sends inventory changes protected by baseline, sequence, and hash metadata. |

Heartbeat and posture can both run every 3 seconds because they serve different
jobs. Heartbeat is intentionally tiny and only updates liveness. Posture is
compact but security-relevant, so it can safely trigger policy evaluation
without repeatedly sending full process/service/hotfix inventories.

## Collector Intervals

PowerShell collector config:

```json
"scheduling": {
  "heartbeat_interval_seconds": 3,
  "posture_interval_seconds": 3,
  "inventory_delta_interval_seconds": 10,
  "inventory_full_interval_seconds": 900,
  "send_full_inventory_on_startup": true,
  "send_full_inventory_on_resync_required": true
}
```

For saturated EVE-NG labs, start by increasing inventory intervals, not posture
intervals:

```json
"inventory_delta_interval_seconds": 30,
"inventory_full_interval_seconds": 1800
```

If CPU or WMI collection is still heavy, increase `posture_interval_seconds` to
`5` or `10`. Keep `heartbeat_interval_seconds` short when possible so endpoint
activity status remains responsive.

## Posture Snapshot

`posture_snapshot` carries security decision data:

- Antivirus status.
- OS name, version, and build.
- Domain membership if available.
- Critical patch summary.
- Required services status.
- Forbidden/risky process findings.
- Security process findings.

Configure required services and process rules in
`endpoint-collector/powershell/collector.config.json`:

```json
"posture_snapshot": {
  "required_services": ["WinDefend", "SecurityHealthService"],
  "security_processes": ["MsMpEng", "SecurityHealthSystray"],
  "forbidden_processes": ["mimikatz", "psexesvc"],
  "critical_patches": ["KB5034441"]
}
```

Do not remove posture collectors just to reduce payload size. Tune intervals and
inventory categories first so posture verification remains strong.

## Inventory Full And Delta

`inventory_full` is the baseline. It is sent at startup, periodically, and when
the server requests resync.

`inventory_delta` includes:

- `baseline_id`
- `sequence_number`
- `previous_hash`
- `current_hash`
- per-category added/updated/removed changes

If the telemetry API detects a baseline mismatch, sequence gap, or hash
mismatch, it returns `resync_required=true`. The collector then sends a fresh
`inventory_full` when `send_full_inventory_on_resync_required` is enabled.

## Telemetry API Environment

The telemetry API accepts these configuration values:

```env
HEARTBEAT_INTERVAL_SECONDS=3
ACTIVITY_GRACE_MULTIPLIER=3
ENDPOINT_INACTIVE_AFTER_SECONDS=9
ACTIVITY_CHECK_INTERVAL_SECONDS=3
STATUS_CHANGE_COOLDOWN_SECONDS=6
MAX_TELEMETRY_BODY_BYTES=10485760
ACCEPT_GZIP_TELEMETRY=true
POSTURE_TRIGGERS_EVALUATION=true
FORCE_EVALUATION_ON_EVERY_POSTURE=true
SKIP_EVALUATION_IF_POSTURE_HASH_UNCHANGED=false
INVENTORY_FULL_TRIGGERS_EVALUATION=false
INVENTORY_DELTA_TRIGGERS_EVALUATION=false
INVENTORY_RESYNC_ON_SEQUENCE_GAP=true
INVENTORY_RESYNC_ON_HASH_MISMATCH=true
PROCESS_POSTURE_IN_BACKGROUND=true
PROCESS_INVENTORY_IN_BACKGROUND=true
LOG_TELEMETRY_PAYLOAD_SIZE=true
LOG_TELEMETRY_PROCESSING_DURATION=true
SLOW_TELEMETRY_WARNING_MS=1000
SLOW_EVALUATION_WARNING_MS=3000
```

For MVP behavior, `FORCE_EVALUATION_ON_EVERY_POSTURE=true` and
`SKIP_EVALUATION_IF_POSTURE_HASH_UNCHANGED=false` keep posture evaluation
dynamic and autonomous even when the snapshot hash does not change.

## API Endpoints

New typed endpoints:

```text
POST /telemetry/heartbeat
POST /telemetry/posture
POST /telemetry/inventory/full
POST /telemetry/inventory/delta
```

Backward compatibility:

```text
POST /telemetry
```

The legacy endpoint still accepts the existing full telemetry payload and
triggers policy evaluation.

## Gzip

Collector-side:

```json
"payload": {
  "gzip_enabled": true
}
```

Telemetry API-side:

```env
ACCEPT_GZIP_TELEMETRY=true
```

Disable gzip only when debugging raw payloads or when an intermediate proxy does
not preserve `Content-Encoding: gzip`.
