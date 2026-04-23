# Demo Runbook

## 1) Start stack

```bash
docker compose up --build
```

## 2) Log in

- URL: http://localhost:5173
- Demo users:
  - `admin / admin123`
  - `analyst / analyst123`
  - `deteng / deteng123`
  - `viewer / viewer123`

Use `admin` for full demo functionality.

## 3) Show end-to-end flow

1. Go to **Events**.
2. Seed `Credential Access: Password Spray` scenario.
3. Open **Alerts** and inspect a generated alert.
4. In **Alert Investigation**:
   - update status,
   - assign analyst,
   - add note,
   - run AI summary/triage,
   - submit true/false-positive feedback.
5. Go to **Incidents** and group alerts into an incident.
6. Update incident status and generate AI wrap-up.
7. Go to **Dashboard** and review KPIs + correlation hotspots.

## 4) Optional deferred-processing demo

1. Ingest events via API with deferred mode:

```bash
curl -X POST http://localhost:8000/api/events/batch \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"defer_detection": true, "events": [{"source":"identity_provider","source_ip":"198.51.100.50","username":"jdoe","event_type":"login_failed","message":"Failed login"}]}'
```

2. Open **Detections** and click **Process Pending Jobs**.
3. Return to **Alerts** and confirm alert creation.

## 5) Troubleshooting

- If backend is unreachable, verify `VITE_API_BASE_URL` and backend health endpoint.
- If no alerts appear, confirm feature flags are enabled in platform endpoints.
- If auth fails, clear browser local storage key `vanguard_token` and re-login.
