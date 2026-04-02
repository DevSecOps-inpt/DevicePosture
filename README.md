# Device Posture MVP

Small modular monorepo for a first working device posture platform MVP.

## Goals

- Collect Windows endpoint telemetry
- Store telemetry in a FastAPI service
- Store expandable posture policies
- Evaluate endpoint compliance
- Quarantine non-compliant endpoints through a FortiGate adapter
- Keep every major component extension-friendly

## High-level architecture

1. `endpoint-collector` gathers endpoint facts and posts normalized JSON to `telemetry-api`.
2. `telemetry-api` stores a normalized endpoint core plus raw telemetry payloads in SQLite.
3. `policy-service` stores posture policies and resolves the effective policy for an endpoint.
4. `evaluation-engine` fetches telemetry and policy, runs evaluator plugins, stores a compliance decision, and optionally forwards it to `enforcement-service`.
5. `enforcement-service` logs audit events and routes quarantine actions to an adapter implementation such as FortiGate.

## Design principles

- Python-first and FastAPI-first
- SQLite for each service in the MVP
- Small modules with clear responsibilities
- Generic condition and event models so new checks can be added later
- Plugin and adapter interfaces for collectors, evaluators, and enforcement targets
- Raw JSON preserved everywhere it matters so the schema can grow safely

## Folder tree

```text
.
|-- README.md
|-- docs/
|   `-- architecture.md
|-- shared/
|   `-- posture_shared/
|       |-- __init__.py
|       |-- interfaces/
|       |   |-- __init__.py
|       |   |-- adapters.py
|       |   |-- collectors.py
|       |   `-- evaluators.py
|       `-- models/
|           |-- __init__.py
|           |-- enforcement.py
|           |-- evaluation.py
|           |-- policy.py
|           `-- telemetry.py
|-- services/
|   |-- telemetry-api/
|   |   |-- requirements.txt
|   |   `-- app/
|   |-- policy-service/
|   |   |-- requirements.txt
|   |   `-- app/
|   |-- evaluation-engine/
|   |   |-- requirements.txt
|   |   `-- app/
|   `-- enforcement-service/
|       |-- requirements.txt
|       `-- app/
|-- endpoint-collector/
|   |-- powershell/
|   |-- linux/
|   `-- python_collector/
`-- frontend/
    |-- README.md
    `-- src/
```

## Module responsibilities

- `shared/posture_shared`: common models and extension interfaces shared across services and collectors.
- `services/telemetry-api`: telemetry ingestion, endpoint inventory, raw telemetry history.
- `services/policy-service`: posture policy CRUD and policy assignment resolution.
- `services/evaluation-engine`: plugin-based compliance evaluation and result persistence.
- `services/enforcement-service`: audit/event persistence, decision orchestration, and adapter execution.
- `endpoint-collector/powershell`: Windows-native endpoint agent with JSON config, periodic background mode, and plugin-style collectors.
- `endpoint-collector/python_collector`: optional Python collector kept for development and local testing.
- `endpoint-collector/linux`: placeholder for a future Linux-native collector.
- `frontend`: Next.js admin console for endpoint operations, policy management, adapter monitoring, and platform workflows.

## Core internal data models

- Endpoint telemetry:
  - `endpoint_id`
  - `hostname`
  - `collected_at`
  - `network.ipv4`
  - `os.name`, `os.version`, `os.build`
  - `hotfixes[]`
  - `services[]`
  - `processes[]`
  - `antivirus_products[]`
  - `extras`
- Policy:
  - `id`, `name`, `description`, `target_action`
  - `conditions[]` where each condition has `type`, `operator`, `field`, `value`
  - assignments by endpoint, group, or default
- Compliance decision:
  - `endpoint_id`
  - `policy_id`
  - `compliant`
  - `recommended_action`
  - `reasons[]`
  - `evaluated_at`
- Enforcement action/result:
  - `adapter`
  - `action`
  - `endpoint_id`
  - `ip_address`
  - `status`
  - `details`

## Extension points

- Collectors:
  - add new PowerShell collector plugins for registry, certificates, domain membership, AV-specific queries
  - reserve a parallel Linux collector that follows the same telemetry contract later
- Evaluators:
  - add new evaluator classes keyed by `condition.type`
  - examples: registry key, certificate, file existence, domain membership, vulnerability score
- Enforcement adapters:
  - implement `EnforcementAdapter` for FortiGate, Palo Alto, Cisco, Slack, email, ticketing

## Recommended implementation order

1. Shared contracts and repo structure
2. `telemetry-api`
3. `policy-service`
4. `evaluation-engine`
5. `enforcement-service` with FortiGate adapter
6. Windows collectors
7. Optional admin UI

## Local development

Each service is intentionally standalone. Use a dedicated virtual environment per service or a single root virtual environment during development.

## Dev runner

Use the root helper script to set up dependencies and run components separately from the repo root:

```powershell
.\scripts\dev.ps1 -Action setup
.\scripts\dev.ps1 -Action run -Component telemetry-api
.\scripts\dev.ps1 -Action run -Component policy-service
.\scripts\dev.ps1 -Action run -Component evaluation-engine
.\scripts\dev.ps1 -Action run -Component enforcement-service
.\scripts\dev.ps1 -Action run -Component python-collector
.\scripts\dev.ps1 -Action run -Component python-collector-service
.\scripts\dev.ps1 -Action run -Component powershell-collector
.\scripts\dev.ps1 -Action run -Component powershell-collector-service
.\scripts\dev.ps1 -Action run -Component frontend
```

To start the four backend services in the background together and manage them as one local server:

```powershell
.\scripts\dev.ps1 -Action start-all
.\scripts\dev.ps1 -Action status
.\scripts\dev.ps1 -Action stop
```

Background service logs are written to `.logs/`.

For a Linux server, use the Bash runner:

```bash
./scripts/dev.sh setup
./scripts/dev.sh run telemetry-api
./scripts/dev.sh run policy-service
./scripts/dev.sh run evaluation-engine
./scripts/dev.sh run enforcement-service
./scripts/dev.sh run python-collector-service
./scripts/dev.sh run frontend
./scripts/dev.sh start-all
./scripts/dev.sh status
./scripts/dev.sh stop
```

Notes for Linux:
- the Bash runner manages the backend services and the Python collector
- the Windows-native PowerShell collector remains Windows-only by design
- a Linux-native collector is planned, but not implemented yet
- you can override service URLs or FortiGate settings with environment variables before launching

## Frontend

The admin UI now lives in `frontend/` and is now a routed multi-section admin console with:

- dashboard overview and health summaries
- endpoint inventory and detail views
- policy list and policy detail pages
- objects, adapters, extensions, events, tasks, alerts, and settings pages
- reusable tables, filters, cards, badges, and modal forms
- typed mock data structured for later backend integration

Run it directly:

```powershell
cd .\frontend
npm install
npm run dev
```

Or through the repo runner:

```powershell
.\scripts\dev.ps1 -Action run -Component frontend
```

On Linux:

```bash
cd ./frontend
npm install
npm run dev
```

Install the shared package first from the repo root:

```powershell
pip install -e .\shared
```

Then install each service dependencies from the service directory so the editable `../../shared` path resolves correctly:

```powershell
cd .\services\telemetry-api
pip install -r requirements.txt
cd ..\policy-service
pip install -r requirements.txt
cd ..\evaluation-engine
pip install -r requirements.txt
cd ..\enforcement-service
pip install -r requirements.txt
```

## Startup order

1. Start `telemetry-api`
2. Start `policy-service`
3. Start `enforcement-service`
4. Start `evaluation-engine`
5. Run a collector from a Windows endpoint

For native Windows deployment, prefer the PowerShell agent and install it as a startup scheduled task:

```powershell
powershell -ExecutionPolicy Bypass -File .\endpoint-collector\powershell\install_collector_task.ps1
```

## End-to-end MVP run

1. Create a policy in `policy-service`.
2. Assign it to an endpoint or create a default assignment.
3. Run the Windows collector and post telemetry to `telemetry-api`.
4. Call `evaluation-engine` for the endpoint.
5. If the result is non-compliant with action `quarantine`, `enforcement-service` logs the event and calls the FortiGate adapter.

See `docs/api-examples.md` for sample payloads, example policy JSON, and local `curl` commands.

## Smoke test

To exercise the full local flow quickly:

```powershell
.\scripts\smoke_test.ps1
```

The smoke test intentionally points the FortiGate adapter at a closed local port, so you can verify the full quarantine pipeline and failed-enforcement audit path without needing a real firewall.

See `frontend/README.md` for frontend-specific configuration and service URL overrides.
