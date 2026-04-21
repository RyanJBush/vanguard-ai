# Vanguard AI

Vanguard AI is an AI-powered SOC threat detection platform that ingests security telemetry, applies rule + anomaly detections, and streamlines analyst triage workflows.

## Overview

This repository is a production-style monorepo with:
- **Backend**: FastAPI, SQLAlchemy, JWT auth with RBAC
- **Frontend**: React + Vite + Tailwind CSS + Recharts
- **Database**: PostgreSQL
- **Detection/ML**: pandas + scikit-learn with practical SOC detection logic
- **DevEx**: Docker Compose, Makefile, GitHub Actions CI

## Architecture

```text
/backend   -> FastAPI API, detection pipeline, persistence, tests
/frontend  -> SOC dashboard UI and API service clients
/docs      -> Architecture, ports, and style guide
```

Additional architecture notes are in [/docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Core Features (MVP)

- Secure login and identity endpoints (`/api/auth/login`, `/api/auth/me`)
- Event ingestion and querying (`/api/events`)
- Automated detections and alert generation on ingestion
- Alert triage workflow including status updates
- SOC dashboard KPIs, severity charting, event/alert tables, and filtering
- Role-based access controls for Admin, Analyst, and Viewer

## API Endpoints

- `GET /health`
- `GET /ready`
- `GET /health/dependencies`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/events`
- `GET /api/events`
- `GET /api/events/{id}`
- `GET /api/events/scenarios`
- `POST /api/events/scenarios/{scenario_key}/seed`
- `GET /api/alerts`
- `GET /api/alerts/{id}`
- `PATCH /api/alerts/{id}/status`
- `PATCH /api/alerts/{id}/assign`
- `GET /api/alerts/{id}/notes`
- `POST /api/alerts/{id}/notes`
- `GET /api/alerts/{id}/timeline`
- `POST /api/alerts/{id}/feedback`
- `GET /api/alerts/{id}/ai-summary`
- `GET /api/alerts/{id}/ai-triage`
- `GET /api/detections`
- `GET /api/detections/catalog`
- `GET /api/incidents`
- `POST /api/incidents`
- `GET /api/incidents/{id}`
- `PATCH /api/incidents/{id}/status`
- `GET /api/incidents/{id}/ai-wrapup`
- `GET /api/jobs`
- `POST /api/jobs/process-pending`
- `GET /api/platform/feature-flags`
- `PATCH /api/platform/feature-flags/{flag_key}`
- `GET /api/platform/audit-logs`
- `GET /api/metrics/summary`
- `GET /api/metrics/kpis`
- `GET /api/metrics/detection-comparison`
- `GET /api/metrics/jobs`
- `GET /api/metrics/detection-quality`
- `GET /api/metrics/scenario-benchmarks`

## Quick Start

### Prerequisites
- Docker + Docker Compose
- Python 3.12+
- Node.js 20+

### Run with Docker

```bash
docker compose up --build
```

- Frontend: http://localhost:5173
- Backend API: http://localhost:8000/docs
- PostgreSQL: localhost:5432

### Local Development

```bash
make install
make lint
make test
make build
```

### Demo Credentials

- `admin / admin123`
- `analyst / analyst123`
- `deteng / deteng123`
- `viewer / viewer123`

## Screenshots

- Dashboard (SOC overview):  
  ![Vanguard AI Dashboard](https://github.com/user-attachments/assets/7695e968-457f-43a1-a8f3-56a7216791dd)

## Roadmap

- Add streaming ingestion and queue-based processing
- Expand investigation notes and case management workflows
- Integrate threat intel enrichment and response automation
- Add tenant isolation enhancements and audit trails

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Ports](docs/PORTS.md)
- [Style Guide](docs/STYLEGUIDE.md)
- [Contributing](CONTRIBUTING.md)

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
