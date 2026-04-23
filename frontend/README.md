# Vanguard AI Frontend

React + Vite SOC interface for Vanguard AI.

## Requirements
- Node.js 20+
- Backend API running on `http://localhost:8000` (or set `VITE_API_BASE_URL`)

## Run

```bash
npm install
npm run dev
```

## Build + Lint

```bash
npm run lint
npm run build
```

## Auth

The UI stores a JWT token in `localStorage` under `vanguard_token` and sends it as a bearer token on API requests.
