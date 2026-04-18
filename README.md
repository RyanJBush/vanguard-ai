# Vanguard AI

Vanguard AI is a production-style SOC threat detection monorepo that demonstrates practical security engineering across backend APIs, detection pipelines, and an analyst-facing frontend console.

## Current State
- Backend MVP: JWT auth + RBAC, event ingestion, detection pipeline, alert lifecycle, metrics APIs.
- Frontend MVP: recruiter-ready SOC console connected to backend APIs with authenticated workflows.

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

## Demo Credentials
- `admin / admin123`
- `analyst / analyst123`
- `viewer / viewer123`

## Required Environment Variables
### Backend (`backend/.env`)
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
```bash
cd backend
python -m scripts.seed_demo_data
```

## Quality Commands
```bash
make lint
make test
```
