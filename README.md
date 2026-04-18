# Vanguard AI

Vanguard AI is a production-style SOC threat detection monorepo that demonstrates practical security engineering across backend APIs, detection pipelines, and an analyst-facing frontend console.

## Current State
- Backend MVP: JWT auth + RBAC, event ingestion, detection pipeline, alert lifecycle, metrics APIs.
- Frontend MVP: recruiter-ready SOC console connected to backend APIs with authenticated workflows.
Vanguard AI is a production-style SOC threat detection monorepo that demonstrates practical security engineering across backend APIs, detection pipelines, data modeling, and analyst workflows.

## Current State
This repository now includes a backend MVP for:
- JWT-based demo auth with RBAC roles (`admin`, `analyst`, `viewer`)
- Event ingestion and validation
- Detection pipeline execution on ingestion
- Automatic alert generation
- Alert lifecycle updates (`open`, `investigating`, `resolved`)
- Summary metrics for SOC dashboards
- Seed script for realistic demo telemetry

## Monorepo Structure

```text
vanguard-ai/
  backend/
  frontend/
  docs/
  README.md
  LICENSE
  CONTRIBUTING.md
  .gitignore
  .editorconfig
  Makefile
  docker-compose.yml
```

## Frontend Screens / Routes
- `/login`
- `/dashboard`
- `/events`
- `/alerts`
- `/alerts/:alertId`
- `/detections`
- `/settings`

## Backend API Highlights
Base URL: `http://localhost:8000/api/v1`

- `POST /auth/login`
- `GET /auth/me`
- `POST /events`
- `GET /events`
- `GET /detections`
- `GET /alerts`
- `GET /alerts/{id}`
- `PATCH /alerts/{id}/status`
- `GET /alerts/{id}/notes`
- `POST /alerts/{id}/notes`
- `GET /metrics/summary`
- `GET /health`
## Backend API Highlights
Base URL: `http://localhost:8000/api/v1`

- `POST /auth/login` – demo JWT login
- `GET /auth/me` – current user context
- `POST /events` – ingest security event and trigger detections
- `GET /events` – list events
- `GET /detections` – list detections
- `GET /alerts` – list alerts
- `PATCH /alerts/{id}/status` – update alert status
- `GET /metrics/summary` – dashboard summary metrics
- `GET /health` – service health

## Demo Credentials
- `admin / admin123`
- `analyst / analyst123`
- `viewer / viewer123`

## Required Environment Variables
### Backend (`backend/.env`)
Copy `backend/.env.example` to `backend/.env` and update values:
- `APP_NAME`
- `APP_ENV`
- `APP_DEBUG`
- `API_V1_PREFIX`
- `SECRET_KEY`
- `ALGORITHM`
- `ACCESS_TOKEN_EXPIRE_MINUTES`
- `DATABASE_URL`

### Frontend (`frontend/.env`)
- `VITE_API_BASE_URL` (default `http://localhost:8000/api/v1`)

## Local Setup

## Local Setup

### Prerequisites
- Python 3.11+
- Node.js 20+
- Docker + Docker Compose

### Option A: local processes
```bash
make bootstrap
make run-backend
make run-frontend
```

### Option B: containers
```bash
docker compose up --build
```

## Seed Demo Data
After backend is running:
```bash
cd backend
python -m scripts.seed_demo_data
```

## Quality Commands
```bash
make lint
make test
```

## Next Milestones
- Frontend integration with authenticated API calls
- Alert triage workflows and investigation notes UI
- Detection management UI and tuning controls
- Migrations + production auth hardening
