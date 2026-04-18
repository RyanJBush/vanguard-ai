# Style Guide

## Backend (Python)
- Python 3.11+
- FastAPI for API contracts
- SQLAlchemy 2.x ORM style
- Ruff lint rules as baseline quality gate
- Business logic in `app/services`

## Frontend (React)
- TypeScript + React function components
- Keep UI components presentational; move data fetch/state to page-level hooks
- Tailwind for utility-first styling
- Recharts for dashboard and telemetry visualizations
- ESLint + Prettier required before merge

## Security Engineering Conventions
- Prefer explicit schemas for every external payload
- Add event taxonomy mapping and MITRE ATT&CK references as detections evolve
- Every alert state transition should be auditable
