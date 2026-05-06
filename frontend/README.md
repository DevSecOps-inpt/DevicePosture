# Frontend Admin Console

Multi-section admin dashboard for the device posture platform.

## Stack

- Next.js
- React
- TypeScript
- Tailwind CSS
- lucide-react icons

## Current shape

The frontend is now structured as a real operations console instead of a single-page MVP surface.

Important:

- test records and placeholder entities were removed
- endpoints, policies, evaluations, enforcement, alerts, and events now rely on backend data where APIs exist
- modules without backend support now show empty states instead of placeholder records

Main routes:

- `/dashboard`
- `/endpoints`
- `/endpoints/[id]`
- `/policies`
- `/policies/[id]`
- `/objects`
- `/adapters`
- `/adapters/[id]`
- `/extensions`
- `/events`
- `/tasks`
- `/alerts`
- `/settings`

## Folder structure

```text
frontend/
|-- app/
|-- components/
|   |-- layout/
|   |-- modules/
|   `-- ui/
|-- data/
|-- hooks/
|-- lib/
`-- types/
```

## Notes

- modules are wired for typed API integration, and unsupported areas currently render empty states
- the dashboard layout is persistent across routes
- pages are split by operational domain and reuse shared cards, tables, filters, badges, and modal patterns

## Run locally

```powershell
cd C:\Users\essag\Documents\Playground\frontend
npm install
npm run dev
```

The browser talks only to same-origin Next.js API routes under `/api/backend/*`.
The Next.js server then forwards requests to the internal FastAPI services.
Set backend URLs and the shared API key as server-only environment variables for the Next.js process:

```powershell
$env:TELEMETRY_API_URL = "http://127.0.0.1:8011"
$env:POLICY_SERVICE_URL = "http://127.0.0.1:8002"
$env:EVALUATION_ENGINE_URL = "http://127.0.0.1:8003"
$env:ENFORCEMENT_SERVICE_URL = "http://127.0.0.1:8004"
$env:POSTURE_API_KEY = "<secret>"
```

Do not use `NEXT_PUBLIC_*` for backend service URLs or `POSTURE_API_KEY`; those values would be exposed to browser code.

## Build

```powershell
npm run build
```
