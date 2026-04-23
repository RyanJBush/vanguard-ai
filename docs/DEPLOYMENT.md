# Deployment Guide

## Docker Compose (recommended for demo)

```bash
docker compose up --build -d
docker compose ps
```

Services:
- Frontend: http://localhost:5173
- Backend: http://localhost:8000/docs
- Postgres: localhost:5432

## Health Checks

Verify platform readiness:

```bash
curl -s http://localhost:8000/health
curl -s http://localhost:8000/ready
curl -s http://localhost:8000/health/dependencies
```

## Local non-Docker startup

```bash
cp .env.example .env
make install
make backend-dev
# separate terminal
make frontend-dev
```

## CI expectations

Before pushing:

```bash
make lint
make test
make build
```

The GitHub Actions workflow runs backend lint/tests and frontend lint/build on each PR and push to `main`.
