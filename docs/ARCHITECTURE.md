# Vanguard AI Architecture

## High-level Flow
1. Security telemetry is ingested via API endpoints and future collector integrations.
2. Events are normalized and persisted in PostgreSQL.
3. Detection engine evaluates rule conditions and anomaly scoring.
4. Alerts are generated and surfaced to analyst workflows.
5. UI enables triage, investigation, and disposition.

## Monorepo Layout
- `backend/`: FastAPI API, detection service abstractions, auth and RBAC foundations.
- `frontend/`: React analyst console for SOC operations.
- `docs/`: architecture, ops, style references.

## Planned Services
- Ingestion service (batch + streaming)
- Detection service (rules + ML scoring)
- Alert lifecycle and case management
- Audit logging and compliance reporting
