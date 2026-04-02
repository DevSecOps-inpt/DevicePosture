# Architecture Notes

## Small MVP service boundaries

- `telemetry-api` owns endpoint telemetry history.
- `policy-service` owns policy definitions and assignments.
- `evaluation-engine` owns compliance decisions.
- `enforcement-service` owns audit trails and adapter execution.

Each service keeps its own SQLite database for the MVP. That avoids premature coupling while still keeping the system easy to run locally.

## Why this stays modular without overengineering

- Shared models provide a common contract, but each service still owns its persistence.
- Policy conditions are generic objects instead of separate tables per check type.
- Evaluators and adapters are registered in small registries instead of dynamic plugin loading. Later, those registries can be replaced with entry points or module discovery.
- The enforcement layer uses HTTP plus audit events today, but its event types already map to a future message bus.

## Event flow

- `endpoint.telemetry.received`
- `endpoint.evaluated`
- `endpoint.non_compliant`
- `endpoint.quarantined`

The current MVP persists those events in SQLite. A future version can publish the same event shapes to Kafka or RabbitMQ without changing upstream producers.
