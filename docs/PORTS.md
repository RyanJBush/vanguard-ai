# Ports

| Service | Port | Notes |
|---|---:|---|
| Frontend (Vite) | 5173 | Analyst web UI |
| Backend (FastAPI) | 8000 | REST API (`/health`, `/api/v1/*`) |
| PostgreSQL | 5432 | Primary relational store |

## Hostnames in docker-compose
- `frontend`: calls backend via `http://backend:8000`
- `backend`: connects to db via `postgresql+psycopg://vanguard:vanguard@db:5432/vanguard_ai`
