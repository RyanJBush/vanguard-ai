# Architecture

Vanguard AI uses a monorepo with a FastAPI backend and React frontend.

- **Backend**: API-first service with clean separation across `routers`, `services`, `schemas`, `models`, and `db` modules.
- **Detection pipeline**: Rule and anomaly-based detections run during event ingestion and emit alerts.
- **Frontend**: Enterprise SOC dashboard UI powered by React, Vite, Tailwind CSS, and Recharts.
- **Data layer**: PostgreSQL stores users, organizations, events, detections, alerts, and investigation notes.
