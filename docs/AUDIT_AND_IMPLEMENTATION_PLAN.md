# Vanguard AI Audit and Phased Implementation Plan

## Executive Summary
Vanguard AI is already close to a runnable MVP: backend APIs, RBAC/JWT auth, seeded demo data, detection + alert generation, and a functional React dashboard are present. Tests are strong (121 passing), which suggests core flows work.

The highest-value gaps are **production hardening** (security defaults, token/session controls, rate limiting, audit depth), **ingestion realism** (normalization pipelines and richer log schemas), **detection depth** (rule lifecycle, correlation graph, evaluation harness), and **investigation UX** (case timelines, entity pivots, richer evidence context).

---

## 1) Codebase Audit

### 1.1 Repository and runtime structure
- Monorepo layout is clean: `backend/` FastAPI service, `frontend/` Vite React app, `docs/` operational/design docs, root Docker Compose and Makefile.
- Backend startup auto-creates schema and seeds demo users/data from startup hook, which reduces friction for first-run.
- Frontend consumes backend KPI, alerts, and metrics endpoints and already includes SOC-centric pages (alerts, incidents, detections, events, settings).

### 1.2 Backend services and API quality
**Strengths**
- API surface is broad and mostly coherent for SOC workflows (auth, events, alerts, detections, incidents, jobs, metrics, platform controls).
- Pagination helpers and sort/filter basics exist on high-cardinality endpoints.
- Event ingestion supports immediate or deferred detection via detection jobs.
- Alert workflow includes assignment, status transitions, notes, timeline, and analyst feedback.

**Issues / gaps**
1. **No explicit request rate limiting** on login, ingestion, and write-heavy endpoints.
2. **JWT defaults unsafe for production** (`change-me-in-production` fallback is permissive if env not set).
3. **No token revocation/session versioning**, so compromised token remains valid until expiration.
4. **Potential cross-tenant access edge case**: `get_current_user()` resolves user by username from token subject without also binding organization/issuer claims; secure but minimal.
5. **Startup event uses deprecated FastAPI `@app.on_event("startup")`** (warning seen in tests).
6. **Validation depth is thin for ingestion payloads** (e.g., free-form `severity`, `event_type`, `source` without strict enums/normalizers).
7. **Detection processing is DB-transaction coupled** with request path for non-deferred mode; this can create latency spikes under load.
8. **No ingestion authentication variant for machine sources** (API key/HMAC/mTLS).

### 1.3 Data models and persistence
**Strengths**
- Good foundational entities: events, detections, alerts, incidents, notes, timeline, audit logs, feedback, jobs, feature flags.
- Supports dedup metadata (`correlation_id`, `dedup_count`, first/last seen) for analyst noise reduction.

**Issues / gaps**
1. **No migration framework in workflow** (Alembic not evident in repo structure); relying on `create_all()` is risky for production schema evolution.
2. **Stringly-typed severities/event types** increase drift and inconsistent querying.
3. **No explicit uniqueness constraints for some business invariants** (e.g., duplicate feature flags per org/key).
4. **Limited indexes for investigative filters** (username+occurred_at, severity+status composites, etc. would improve scale).

### 1.4 Detection logic and alert generation
**Strengths**
- Includes both rule-like and anomaly-like detections.
- MITRE technique fields and recommended next steps are included and surfaced.
- Deduplication/correlation based on correlation keys and time windows is implemented.

**Issues / gaps**
1. **Detection catalog/rules are code-bound**, not admin-manageable with versioning and lifecycle states.
2. **Anomaly model is simplistic** (single feature, per-request fitting); not robust for production drift/noise.
3. **No per-rule precision/recall tracking loop** connected to analyst feedback.
4. **No suppression/allow-list framework** beyond `known_benign` event metadata.

### 1.5 Frontend/dashboard experience
**Strengths**
- Dashboard includes KPI cards, severity distribution, scenario coverage, and hotspots.
- Dedicated pages for alerts/incidents/detections/events are present.

**Issues / gaps**
1. **Settings page is placeholder** (explicitly marked MVP placeholder).
2. **Investigation ergonomics can improve**: deeper evidence panels, entity graph pivots, richer triage timeline composition.
3. **No explicit dark/light theme toggles or analyst personalization controls.**
4. **Potential large-table UX constraints** (saved filters, column visibility, bulk actions, keyboard triage not obvious).

### 1.6 Tests, CI/CD, and deployment readiness
**Strengths**
- Backend test suite is substantial and passing (`121 passed`).
- Dockerfiles + docker-compose present; docs include deployment and runbook sections.

**Issues / gaps**
1. Add smoke/integration tests across frontend-backend with seeded scenarios.
2. Add performance/security gates in CI (dependency scan, SAST, auth brute-force tests, rate-limit tests).
3. Add environment validation step that fails fast for insecure production settings.

---

## 2) Prioritized Improvements (High Impact)

### Priority 0 (Critical to production trust)
1. Enforce secure config defaults and startup checks.
2. Add rate limiting and abuse protections (login + ingest + mutation routes).
3. Move from `create_all()`-style evolution to migrations.
4. Harden auth: token rotation/revocation strategy and claim validation improvements.

### Priority 1 (Core SOC realism)
1. Ingestion normalization pipeline for multiple log types (auth, endpoint, cloud audit, DNS, proxy).
2. Rule lifecycle system (draft/enabled/disabled, versioned rules, test harness).
3. Enhanced correlation/dedup: entity+time+tactic clustering and incident auto-group suggestions.
4. Measurable detection quality loop from analyst feedback (precision/recall/FPR by rule).

### Priority 2 (Analyst productivity & product polish)
1. Investigation workspace upgrades: timeline narratives, evidence bundles, IOC/entity pivots.
2. Dashboard enhancements: trend lines, SLA breach cards, MTTA/MTTR by severity, top noisy rules.
3. Better triage UX: bulk actions, saved views, badge semantics, keyboard shortcuts.

---

## 3) Phased Implementation Plan

## Phase 1 — Runnable + Critical Fixes
**Objective:** Ensure secure, stable, reproducible runtime for local + staging.

**Modules/files to modify**
- Backend config/security/bootstrap: `backend/app/config.py`, `backend/app/main.py`, `backend/app/security.py`, `backend/app/db.py`
- Infra/docs: `docker-compose.yml`, `README.md`, deployment docs
- Add migrations scaffold (new `backend/alembic/`)

**Concrete tasks**
1. Replace deprecated startup hook with lifespan context manager.
2. Add strict env validation in non-dev environments (reject default JWT secret).
3. Introduce Alembic migrations baseline and remove schema drift risks.
4. Add health/readiness checks that validate DB connectivity and migration head.
5. Add basic API rate limit middleware/dependency (especially `/api/auth/login`, `/api/events`, alert mutations).

**Dependencies**
- None; foundational.

**Success criteria**
- App boots via Docker and local commands without warnings/errors.
- Production-mode startup fails on insecure config.
- Migration commands create/upgrade schema consistently.
- Brute-force login attempts are throttled.

## Phase 2 — Core Ingestion + Detection Flow
**Objective:** Make ingestion and detection pipeline realistic and extensible.

**Modules/files to modify**
- Ingestion and schemas: `backend/app/routers/events.py`, `backend/app/schemas.py`
- Detection path: `backend/app/services/detection_service.py`, `backend/app/services/job_service.py`
- New normalization module: `backend/app/services/normalization.py` (new)

**Concrete tasks**
1. Define canonical normalized event schema and per-source adapters.
2. Support multiple log types with validation (auth, endpoint, cloudtrail-like, DNS/proxy).
3. Move synchronous heavy detection to queued path by default (keep optional sync for demos/tests).
4. Add ingestion idempotency key support to prevent duplicate event spam.
5. Add ingestion metrics (throughput, reject counts, normalization failures).

**Dependencies**
- Phase 1 migrations/config hardening.

**Success criteria**
- Seed and external log payloads normalize into consistent fields.
- Deferred processing reliably transitions jobs queued→processing→completed/failed.
- Duplicate submissions with same idempotency key are safely ignored/merged.

## Phase 3 — Advanced Detection + Correlation
**Objective:** Increase detection fidelity and reduce false positives.

**Modules/files to modify**
- Rule catalog: `backend/app/services/detection_catalog.py`
- Detection execution and persistence: `backend/app/services/detection_service.py`
- Metrics endpoints: `backend/app/routers/metrics.py`
- New rule management endpoints: `backend/app/routers/detections.py` (+ possible new admin router pieces)

**Concrete tasks**
1. Expand MITRE-mapped detections with tactic/technique metadata and kill-chain context.
2. Implement configurable rule states, per-rule thresholds, and suppression windows.
3. Improve anomaly layer: offline baseline fit + sliding window scoring (not fit-per-request).
4. Add correlation scoring and incident grouping hints by user/IP/host/tactic/time.
5. Track per-rule metrics: TP/FP/FN approximations from analyst feedback, precision/recall/FPR.

**Dependencies**
- Phase 2 normalized data.

**Success criteria**
- Detection catalog can be tuned without code edits (or via minimal config store).
- Alert noise decreases via dedup/correlation quality improvements.
- Metrics endpoint surfaces actionable per-rule quality stats.

## Phase 4 — Investigation Workflows + Dashboards
**Objective:** Make analyst triage/investigation feel complete.

**Modules/files to modify**
- Backend workflows: `backend/app/routers/alerts.py`, `backend/app/routers/incidents.py`, `backend/app/models.py`, `backend/app/schemas.py`
- Frontend pages/components: `frontend/src/pages/AlertsPage.jsx`, `AlertDetailPage.jsx`, `IncidentsPage.jsx`, `DashboardPage.jsx`, `frontend/src/components/*`

**Concrete tasks**
1. Add richer case model (linked entities, containment steps, evidentiary artifacts).
2. Add analyst notes templates/playbooks and timeline auto-summaries.
3. Build filterable/savable views and bulk status/assignment actions.
4. Expand dashboard charts: alert trend over time, top noisy entities, SLA breaches, analyst workload.
5. Add confidence/severity badges and rule-quality indicators in UI.

**Dependencies**
- Phase 3 metrics and correlation outputs.

**Success criteria**
- Analysts can triage, investigate, and close incidents without leaving product context.
- Dashboard supports operational decisions (workload balancing, noisy-rule tuning).

## Phase 5 — Security Hardening, QA, Docs, and Release
**Objective:** Ship a polished, defensible, deployable product.

**Modules/files to modify**
- Security/audit: `backend/app/dependencies.py`, `backend/app/security.py`, `backend/app/services/audit.py`, platform routers
- Tests/CI: `backend/tests/*`, frontend tests, GitHub workflows
- Docs/ops: README, deployment runbooks, seed/demo scripts

**Concrete tasks**
1. Harden RBAC policy matrix and add endpoint-level authorization tests.
2. Add immutable audit trails for sensitive operations (rule changes, role changes, incident closures).
3. Add dependency/SAST/container scans and performance regression tests in CI.
4. Add realistic seed datasets and scripted demo scenarios with expected outcomes.
5. Final UX polish: accessibility, loading/empty/error states, dark mode preferences.

**Dependencies**
- Phases 1–4.

**Success criteria**
- Security checks pass in CI; critical findings resolved.
- End-to-end demo path is deterministic and documented.
- Release artifacts and deployment instructions are complete and reproducible.

---

## 4) Clarifications Needed (only if proceeding to implementation)
1. Should production persistence target PostgreSQL only, with SQLite limited to local/dev?
2. Do you want synchronous detection retained for demo UX, or fully async in all non-test environments?
3. Should machine-to-machine ingestion auth be API key, mTLS, or signed webhook style?
