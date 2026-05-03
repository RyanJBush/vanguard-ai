"""
Extended test coverage for previously undertested modules:
  - security.py          (hash/verify password, JWT roundtrip)
  - ai_assistant.py      (all three functions, all severity/branch paths)
  - pagination.py        (boundary clamping)
  - detection_catalog.py (list_detection_definitions)
  - seed_scenarios.py    (build_scenario_events for each scenario)
  - feature_flags.py     (idempotency, is_detection_enabled branches)
  - audit.py             (write_audit_log persists record)
  - detection_service.py (_as_naive_utc, default_occurred_at, per-rule detect_event
                          paths, disabled flag suppression, persist dedup/fallback/
                          known_benign)
  - API integration      (correlation-hotspots, alert filters, sort order,
                          unauthenticated 401, invalid analyst assignment)
  - RBAC                 (analyst/viewer on alert-status PATCH and notes POST)
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

os.environ["VANGUARD_DATABASE_URL"] = "sqlite:///./test_extended.db"

from app.db import Base, get_db
from app.main import app
from app.models import (
    Alert,
    AlertStatus,
    AuditLog,
    Detection,
    Event,
    FeatureFlag,
    Organization,
    Role,
    User,
)
from app.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.services.ai_assistant import (
    build_alert_summary,
    build_incident_wrapup,
    build_triage_recommendation,
)
from app.services.audit import write_audit_log
from app.services.detection_catalog import list_detection_definitions
from app.services.detection_service import (
    _as_naive_utc,
    default_occurred_at,
    detect_event,
    persist_detections_and_alerts,
)
from app.services.feature_flags import ensure_default_feature_flags, is_detection_enabled
from app.services.pagination import paginate_query
from app.services.seed_scenarios import build_scenario_events

# ---------------------------------------------------------------------------
# Shared DB / client fixtures
# ---------------------------------------------------------------------------

TEST_DATABASE_URL = "sqlite:///./test_extended.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    org = Organization(name="Extended Test Org")
    db.add(org)
    db.flush()
    for username, role, password in [
        ("admin", Role.admin, "admin123"),
        ("analyst", Role.analyst, "analyst123"),
        ("viewer", Role.viewer, "viewer123"),
    ]:
        db.add(
            User(
                username=username,
                full_name=username.title(),
                password_hash=hash_password(password),
                role=role,
                organization_id=org.id,
            )
        )
    db.commit()
    db.close()


@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client():
    def override_get_db():
        db: Session = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def _auth(client: TestClient, username: str, password: str) -> dict[str, str]:
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _org_id(db: Session) -> int:
    return db.query(Organization).first().id


def _user_id(db: Session, username: str) -> int:
    return db.query(User).filter(User.username == username).first().id


# ---------------------------------------------------------------------------
# Helper: create a minimal event in the DB
# ---------------------------------------------------------------------------

def _make_event(
    db: Session,
    *,
    org_id: int,
    event_type: str = "login_failed",
    source_ip: str = "10.0.0.1",
    username: str | None = "jdoe",
    message: str = "test event",
    occurred_at: datetime | None = None,
    metadata: dict | None = None,
    severity: str = "medium",
) -> Event:
    event = Event(
        organization_id=org_id,
        source="identity_provider",
        source_ip=source_ip,
        username=username,
        event_type=event_type,
        severity=severity,
        message=message,
        event_metadata=metadata or {},
        occurred_at=occurred_at or datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.add(event)
    db.flush()
    return event


# ===========================================================================
# security.py
# ===========================================================================


class TestSecurity:
    def test_hash_and_verify_password_correct(self):
        hashed = hash_password("s3cret!")
        assert verify_password("s3cret!", hashed) is True

    def test_verify_password_wrong_returns_false(self):
        hashed = hash_password("correct")
        assert verify_password("wrong", hashed) is False

    def test_two_hashes_of_same_password_differ(self):
        # pbkdf2_sha256 salts each hash
        h1 = hash_password("pw")
        h2 = hash_password("pw")
        assert h1 != h2

    def test_create_and_decode_access_token_roundtrip(self):
        token = create_access_token(subject="alice", role="analyst")
        payload = decode_access_token(token)
        assert payload["sub"] == "alice"
        assert payload["role"] == "analyst"


# ===========================================================================
# ai_assistant.py
# ===========================================================================


class TestAiAssistant:
    def _make_alert(self, severity: str, mitre: list[str], dedup: int = 1) -> SimpleNamespace:
        return SimpleNamespace(
            title="Test Alert",
            severity=severity,
            confidence_score=0.85,
            dedup_count=dedup,
            mitre_techniques=mitre,
            correlation_id="brute_force_login_rule:10.0.0.1",
            recommended_next_steps="Investigate source IP",
        )

    def _make_incident(self, alert_severities: list[str], status: str, summary: str) -> SimpleNamespace:
        alerts = [SimpleNamespace(severity=s) for s in alert_severities]
        return SimpleNamespace(
            title="Incident Alpha",
            alerts=alerts,
            status=SimpleNamespace(value=status),
            summary=summary,
        )

    # build_alert_summary -------------------------------------------------

    def test_build_alert_summary_with_mitre_techniques(self):
        alert = self._make_alert("high", ["T1110", "T1078"], dedup=3)
        result = build_alert_summary(alert)
        assert "T1110" in result
        assert "T1078" in result
        assert "3" in result  # dedup_count
        assert "0.85" in result

    def test_build_alert_summary_with_no_mitre_techniques(self):
        alert = self._make_alert("low", [])
        result = build_alert_summary(alert)
        assert "no ATT&CK tags" in result

    # build_triage_recommendation ------------------------------------------

    def test_triage_recommendation_critical_severity_is_p1(self):
        alert = self._make_alert("critical", ["T1110"])
        _, priority = build_triage_recommendation(alert)
        assert priority == "P1"

    def test_triage_recommendation_high_severity_is_p1(self):
        alert = self._make_alert("high", [])
        reco, priority = build_triage_recommendation(alert)
        assert priority == "P1"
        assert "P1" in reco

    def test_triage_recommendation_medium_severity_is_p2(self):
        alert = self._make_alert("medium", [])
        _, priority = build_triage_recommendation(alert)
        assert priority == "P2"

    def test_triage_recommendation_low_severity_is_p3(self):
        alert = self._make_alert("low", [], )
        _, priority = build_triage_recommendation(alert)
        assert priority == "P3"

    def test_triage_recommendation_includes_next_steps_when_present(self):
        alert = self._make_alert("high", [])
        reco, _ = build_triage_recommendation(alert)
        assert "Investigate source IP" in reco

    def test_triage_recommendation_fallback_when_no_next_steps(self):
        alert = SimpleNamespace(
            severity="low",
            correlation_id="x:y",
            recommended_next_steps=None,
        )
        reco, _ = build_triage_recommendation(alert)
        assert "collect supporting evidence." in reco

    # build_incident_wrapup ------------------------------------------------

    def test_incident_wrapup_counts_high_critical(self):
        incident = self._make_incident(
            ["critical", "high", "medium", "low"], status="closed", summary="wrap up"
        )
        result = build_incident_wrapup(incident)
        assert "4" in result           # total alerts
        assert "2 high/critical" in result
        assert "closed" in result
        assert "wrap up" in result

    def test_incident_wrapup_no_summary_uses_fallback(self):
        incident = self._make_incident([], status="investigating", summary="")
        result = build_incident_wrapup(incident)
        assert "No analyst summary provided." in result

    def test_incident_wrapup_no_high_critical_alerts(self):
        incident = self._make_incident(["low", "medium"], status="open", summary="triage")
        result = build_incident_wrapup(incident)
        assert "0 high/critical" in result


# ===========================================================================
# pagination.py
# ===========================================================================


class TestPagination:
    """Use a real SQLAlchemy query against the test DB."""

    def test_page_clamped_to_minimum_of_one(self, db_session: Session):
        org_id = _org_id(db_session)
        query = db_session.query(Event).filter(Event.organization_id == org_id)
        _, _, safe_page, _ = paginate_query(query, page=0, page_size=10)
        assert safe_page == 1

    def test_page_size_clamped_to_maximum_of_200(self, db_session: Session):
        org_id = _org_id(db_session)
        query = db_session.query(Event).filter(Event.organization_id == org_id)
        _, _, _, safe_page_size = paginate_query(query, page=1, page_size=300)
        assert safe_page_size == 200

    def test_page_size_clamped_to_minimum_of_one(self, db_session: Session):
        org_id = _org_id(db_session)
        query = db_session.query(Event).filter(Event.organization_id == org_id)
        _, _, _, safe_page_size = paginate_query(query, page=1, page_size=0)
        assert safe_page_size == 1

    def test_pagination_returns_correct_slice(self, db_session: Session):
        org_id = _org_id(db_session)
        for _ in range(5):
            _make_event(db_session, org_id=org_id)
        db_session.flush()

        query = db_session.query(Event).filter(Event.organization_id == org_id)
        items, total, safe_page, safe_page_size = paginate_query(query, page=2, page_size=2)
        assert total == 5
        assert safe_page == 2
        assert safe_page_size == 2
        assert len(items) == 2


# ===========================================================================
# detection_catalog.py
# ===========================================================================


class TestDetectionCatalog:
    EXPECTED_KEYS = {
        "brute_force_login_rule",
        "unusual_login_hour_anomaly",
        "privilege_escalation_indicator",
        "high_volume_failed_access_anomaly",
        "threat_intel_match_indicator",
        "impossible_travel_login_anomaly",
        "abnormal_request_spike_rule",
        "suspicious_ip_behavior_rule",
    }

    def test_list_returns_all_definitions(self):
        definitions = list_detection_definitions()
        assert len(definitions) == len(self.EXPECTED_KEYS)
        assert {d.key for d in definitions} == self.EXPECTED_KEYS

    def test_each_definition_has_required_fields(self):
        for defn in list_detection_definitions():
            assert defn.title
            assert defn.severity
            assert defn.description
            assert defn.recommendation
            assert defn.mitre_techniques
            assert defn.dedup_window_minutes > 0


# ===========================================================================
# seed_scenarios.py
# ===========================================================================


class TestSeedScenarios:
    def test_credential_access_password_spray_event_count_and_fields(self):
        now = datetime(2026, 4, 20, 12, 0, tzinfo=timezone.utc)
        events = build_scenario_events(
            scenario_key="credential_access_password_spray",
            organization_id=1,
            now=now,
        )
        # range(12, 5, -1) produces 7 events
        assert len(events) == 7
        assert all(e.event_type == "login_failed" for e in events)
        assert all(e.source == "auth" for e in events)
        assert all(e.source_ip == "198.51.100.23" for e in events)

    def test_identity_privilege_escalation_event_count_and_types(self):
        now = datetime(2026, 4, 20, 12, 0, tzinfo=timezone.utc)
        events = build_scenario_events(
            scenario_key="identity_privilege_escalation",
            organization_id=1,
            now=now,
        )
        assert len(events) == 2
        event_types = {e.event_type for e in events}
        assert "privilege_change" in event_types
        assert "login_success" in event_types

    def test_command_and_control_egress_sources(self):
        now = datetime(2026, 4, 20, 12, 0, tzinfo=timezone.utc)
        events = build_scenario_events(
            scenario_key="command_and_control_egress",
            organization_id=1,
            now=now,
        )
        assert {e.source for e in events} == {"endpoint", "firewall"}


# ===========================================================================
# feature_flags.py
# ===========================================================================


class TestFeatureFlags:
    def test_ensure_default_feature_flags_creates_all_defaults(self, db_session: Session):
        org_id = _org_id(db_session)
        ensure_default_feature_flags(db_session, org_id)
        db_session.flush()

        keys = {
            key
            for (key,) in db_session.query(FeatureFlag.key)
            .filter(FeatureFlag.organization_id == org_id)
            .all()
        }
        assert "brute_force_login_rule" in keys
        assert "unusual_login_hour_anomaly" in keys

    def test_ensure_default_feature_flags_is_idempotent(self, db_session: Session):
        org_id = _org_id(db_session)
        ensure_default_feature_flags(db_session, org_id)
        db_session.flush()
        first_count = (
            db_session.query(FeatureFlag).filter(FeatureFlag.organization_id == org_id).count()
        )

        # second call must not create duplicates
        ensure_default_feature_flags(db_session, org_id)
        db_session.flush()
        second_count = (
            db_session.query(FeatureFlag).filter(FeatureFlag.organization_id == org_id).count()
        )
        assert first_count == second_count

    def test_is_detection_enabled_returns_true_when_no_flag(self, db_session: Session):
        org_id = _org_id(db_session)
        # No FeatureFlag row exists → should default to True
        result = is_detection_enabled(
            db_session, organization_id=org_id, detection_key="nonexistent_detection"
        )
        assert result is True

    def test_is_detection_enabled_returns_false_when_disabled(self, db_session: Session):
        org_id = _org_id(db_session)
        db_session.add(
            FeatureFlag(
                organization_id=org_id,
                key="brute_force_login_rule",
                enabled=False,
                description="",
            )
        )
        db_session.flush()
        result = is_detection_enabled(
            db_session, organization_id=org_id, detection_key="brute_force_login_rule"
        )
        assert result is False

    def test_is_detection_enabled_returns_true_when_enabled(self, db_session: Session):
        org_id = _org_id(db_session)
        db_session.add(
            FeatureFlag(
                organization_id=org_id,
                key="brute_force_login_rule",
                enabled=True,
                description="",
            )
        )
        db_session.flush()
        result = is_detection_enabled(
            db_session, organization_id=org_id, detection_key="brute_force_login_rule"
        )
        assert result is True


# ===========================================================================
# audit.py
# ===========================================================================


class TestAudit:
    def test_write_audit_log_persists_record(self, db_session: Session):
        org_id = _org_id(db_session)
        user_id = _user_id(db_session, "admin")

        write_audit_log(
            db_session,
            organization_id=org_id,
            actor_id=user_id,
            action="test_action",
            target_type="event",
            target_id=42,
            details="unit test entry",
        )
        db_session.flush()

        log = db_session.query(AuditLog).filter(AuditLog.action == "test_action").first()
        assert log is not None
        assert log.organization_id == org_id
        assert log.actor_id == user_id
        assert log.target_type == "event"
        assert log.target_id == 42
        assert log.details == "unit test entry"

    def test_write_audit_log_with_null_actor_and_target(self, db_session: Session):
        org_id = _org_id(db_session)
        write_audit_log(
            db_session,
            organization_id=org_id,
            actor_id=None,
            action="system_event",
            target_type="system",
            target_id=None,
            details="no actor",
        )
        db_session.flush()
        log = db_session.query(AuditLog).filter(AuditLog.action == "system_event").first()
        assert log is not None
        assert log.actor_id is None
        assert log.target_id is None


# ===========================================================================
# detection_service.py  (utility functions + detect_event paths)
# ===========================================================================


class TestDetectionServiceUtils:
    def test_as_naive_utc_strips_timezone(self):
        aware = datetime(2026, 4, 20, 12, 0, 0, tzinfo=timezone.utc)
        result = _as_naive_utc(aware)
        assert result.tzinfo is None
        assert result.hour == 12

    def test_as_naive_utc_leaves_naive_datetime_unchanged(self):
        naive = datetime(2026, 4, 20, 9, 30, 0)
        result = _as_naive_utc(naive)
        assert result == naive

    def test_default_occurred_at_returns_now_for_none(self):
        before = datetime.now(timezone.utc).replace(tzinfo=None)
        result = default_occurred_at(None)
        after = datetime.now(timezone.utc).replace(tzinfo=None)
        assert before <= result <= after

    def test_default_occurred_at_returns_provided_value(self):
        ts = datetime(2025, 1, 15, 8, 0, 0)
        assert default_occurred_at(ts) == ts


class TestDetectEventRules:
    """Unit tests for each detection rule branch in detect_event()."""

    def _setup(self, db: Session):
        ensure_default_feature_flags(db, _org_id(db))
        db.flush()

    # privilege_escalation_indicator via event_type -------------------------

    def test_privilege_change_event_triggers_privilege_escalation(self, db_session: Session):
        self._setup(db_session)
        org_id = _org_id(db_session)
        event = _make_event(
            db_session,
            org_id=org_id,
            event_type="privilege_change",
            message="Role updated",
        )
        signals = detect_event(db_session, event)
        assert any(s.name == "privilege_escalation_indicator" for s in signals)

    def test_role_update_event_triggers_privilege_escalation(self, db_session: Session):
        self._setup(db_session)
        org_id = _org_id(db_session)
        event = _make_event(
            db_session,
            org_id=org_id,
            event_type="role_update",
            message="Role changed",
        )
        signals = detect_event(db_session, event)
        assert any(s.name == "privilege_escalation_indicator" for s in signals)

    def test_admin_in_message_triggers_privilege_escalation(self, db_session: Session):
        self._setup(db_session)
        org_id = _org_id(db_session)
        event = _make_event(
            db_session,
            org_id=org_id,
            event_type="access_granted",
            message="User granted Admin rights",
        )
        signals = detect_event(db_session, event)
        assert any(s.name == "privilege_escalation_indicator" for s in signals)

    # threat_intel_match_indicator ------------------------------------------

    def test_threat_intel_match_triggers_detection(self, db_session: Session):
        self._setup(db_session)
        org_id = _org_id(db_session)
        event = _make_event(
            db_session,
            org_id=org_id,
            event_type="connection_allowed",
            source_ip="203.0.113.44",
            metadata={"threat_intel_match": True, "ioc": "203.0.113.44"},
        )
        signals = detect_event(db_session, event)
        assert any(s.name == "threat_intel_match_indicator" for s in signals)

    def test_no_threat_intel_match_skips_detection(self, db_session: Session):
        self._setup(db_session)
        org_id = _org_id(db_session)
        event = _make_event(
            db_session,
            org_id=org_id,
            event_type="connection_allowed",
            metadata={"threat_intel_match": False},
        )
        signals = detect_event(db_session, event)
        assert not any(s.name == "threat_intel_match_indicator" for s in signals)

    # impossible_travel_login_anomaly ---------------------------------------

    def test_impossible_travel_triggers_when_geo_differs(self, db_session: Session):
        self._setup(db_session)
        org_id = _org_id(db_session)
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        # prior login from "US" 30 minutes ago
        _make_event(
            db_session,
            org_id=org_id,
            event_type="login_success",
            username="traveler",
            occurred_at=now - timedelta(minutes=30),
            metadata={"geolocation": "US"},
        )
        db_session.flush()

        # new login from "DE" (different geo, within 45-minute window)
        current = _make_event(
            db_session,
            org_id=org_id,
            event_type="login_success",
            username="traveler",
            occurred_at=now.replace(hour=12),  # daytime – avoids unusual_hour trigger
            metadata={"geolocation": "DE"},
        )
        db_session.flush()
        # Use noon today to guarantee hour is in-hours
        current.occurred_at = now.replace(hour=12) if now.hour != 12 else now
        db_session.flush()

        signals = detect_event(db_session, current)
        assert any(s.name == "impossible_travel_login_anomaly" for s in signals)

    def test_impossible_travel_skips_when_same_geo(self, db_session: Session):
        self._setup(db_session)
        org_id = _org_id(db_session)
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        _make_event(
            db_session,
            org_id=org_id,
            event_type="login_success",
            username="same_geo_user",
            occurred_at=now - timedelta(minutes=10),
            metadata={"geolocation": "US"},
        )
        db_session.flush()

        current = _make_event(
            db_session,
            org_id=org_id,
            event_type="login_success",
            username="same_geo_user",
            occurred_at=now.replace(hour=12),
            metadata={"geolocation": "US"},
        )
        db_session.flush()

        signals = detect_event(db_session, current)
        assert not any(s.name == "impossible_travel_login_anomaly" for s in signals)

    # unusual_login_hour_anomaly -------------------------------------------

    def test_login_success_after_hours_triggers_unusual_hour(self, db_session: Session):
        self._setup(db_session)
        org_id = _org_id(db_session)
        occurred = datetime(2026, 4, 20, 2, 0, 0)  # 02:00 – before 06:00
        event = _make_event(
            db_session,
            org_id=org_id,
            event_type="login_success",
            occurred_at=occurred,
            metadata={},
        )
        signals = detect_event(db_session, event)
        assert any(s.name == "unusual_login_hour_anomaly" for s in signals)

    def test_login_success_business_hours_skips_unusual_hour(self, db_session: Session):
        self._setup(db_session)
        org_id = _org_id(db_session)
        occurred = datetime(2026, 4, 20, 10, 0, 0)  # 10:00 – within 06-20 window
        event = _make_event(
            db_session,
            org_id=org_id,
            event_type="login_success",
            occurred_at=occurred,
            metadata={},
        )
        signals = detect_event(db_session, event)
        assert not any(s.name == "unusual_login_hour_anomaly" for s in signals)

    # high_volume_failed_access_anomaly ------------------------------------

    def test_high_volume_failed_access_triggers_at_threshold(self, db_session: Session):
        self._setup(db_session)
        org_id = _org_id(db_session)
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        # Insert 20 prior failed-login events in the past 5 minutes
        for i in range(20):
            _make_event(
                db_session,
                org_id=org_id,
                event_type="login_failed",
                source_ip=f"10.0.{i}.1",
                occurred_at=now - timedelta(minutes=5),
            )
        db_session.flush()

        # 21st event should trigger the anomaly
        trigger = _make_event(
            db_session,
            org_id=org_id,
            event_type="login_failed",
            source_ip="10.99.99.1",
            occurred_at=now,
        )
        db_session.flush()
        signals = detect_event(db_session, trigger)
        assert any(s.name == "high_volume_failed_access_anomaly" for s in signals)

    # feature flag disabled suppresses signal ------------------------------

    def test_disabled_feature_flag_suppresses_brute_force_signal(self, db_session: Session):
        org_id = _org_id(db_session)
        # ensure flags exist first, then disable brute_force_login_rule
        ensure_default_feature_flags(db_session, org_id)
        db_session.flush()
        flag = (
            db_session.query(FeatureFlag)
            .filter(
                FeatureFlag.organization_id == org_id,
                FeatureFlag.key == "brute_force_login_rule",
            )
            .first()
        )
        flag.enabled = False
        db_session.flush()

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        for _ in range(5):
            _make_event(
                db_session,
                org_id=org_id,
                event_type="login_failed",
                source_ip="192.168.0.1",
                occurred_at=now - timedelta(minutes=1),
            )
        db_session.flush()

        trigger = _make_event(
            db_session,
            org_id=org_id,
            event_type="login_failed",
            source_ip="192.168.0.1",
            occurred_at=now,
        )
        db_session.flush()
        signals = detect_event(db_session, trigger)
        assert not any(s.name == "brute_force_login_rule" for s in signals)


class TestPersistDetectionsAndAlerts:
    """Unit tests for persist_detections_and_alerts()."""

    def _signal(self, name: str = "brute_force_login_rule", correlation_entity: str = "10.0.0.1"):
        from app.services.detection_service import _signal_from_catalog
        from app.services.detection_catalog import DETECTION_CATALOG

        defn = DETECTION_CATALOG[name]
        return _signal_from_catalog(defn, confidence=0.82, explanation="test", correlation_entity=correlation_entity)

    def _custom_signal(self):
        """Signal whose name is NOT in DETECTION_CATALOG (tests the fallback title path)."""
        from app.services.detection_service import DetectionSignal

        return DetectionSignal(
            name="custom_unknown_detection_xyz",
            severity="low",
            confidence=0.5,
            explanation="custom",
            mitre_techniques=[],
            recommendation="do nothing",
            dedup_window_minutes=30,
            correlation_entity="1.2.3.4",
            detection_method="rule",
        )

    def test_persist_creates_detection_and_alert(self, db_session: Session):
        ensure_default_feature_flags(db_session, _org_id(db_session))
        org_id = _org_id(db_session)
        event = _make_event(db_session, org_id=org_id, event_type="login_failed")
        sig = self._signal()

        detections, alerts = persist_detections_and_alerts(db_session, event, [sig])
        db_session.flush()

        assert len(detections) == 1
        assert len(alerts) == 1
        assert detections[0].detection_type == "brute_force_login_rule"
        assert alerts[0].dedup_count == 1

    def test_persist_dedup_updates_existing_alert(self, db_session: Session):
        ensure_default_feature_flags(db_session, _org_id(db_session))
        org_id = _org_id(db_session)
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        event1 = _make_event(
            db_session, org_id=org_id, event_type="login_failed", source_ip="10.0.0.1",
            occurred_at=now - timedelta(minutes=5),
        )
        sig = self._signal(correlation_entity="10.0.0.1")
        _, alerts1 = persist_detections_and_alerts(db_session, event1, [sig])
        db_session.flush()
        assert alerts1[0].dedup_count == 1

        # Second event with same correlation → dedup
        event2 = _make_event(
            db_session, org_id=org_id, event_type="login_failed", source_ip="10.0.0.1",
            occurred_at=now,
        )
        sig2 = self._signal(correlation_entity="10.0.0.1")
        _, alerts2 = persist_detections_and_alerts(db_session, event2, [sig2])
        db_session.flush()

        # Same alert object, dedup_count incremented
        assert alerts1[0].id == alerts2[0].id
        assert alerts2[0].dedup_count == 2

    def test_persist_fallback_title_for_unknown_detection_type(self, db_session: Session):
        org_id = _org_id(db_session)
        event = _make_event(db_session, org_id=org_id)
        sig = self._custom_signal()

        detections, _ = persist_detections_and_alerts(db_session, event, [sig])
        db_session.flush()

        assert len(detections) == 1
        # Fallback: name.replace("_", " ").title()
        assert detections[0].title == "Custom Unknown Detection Xyz"

    def test_persist_known_benign_event_skips_all_signals(self, db_session: Session):
        org_id = _org_id(db_session)
        event = _make_event(
            db_session, org_id=org_id, metadata={"known_benign": True}
        )
        sig = self._custom_signal()

        detections, alerts = persist_detections_and_alerts(db_session, event, [sig])
        db_session.flush()

        assert detections == []
        assert alerts == []


# ===========================================================================
# API integration – previously uncovered endpoints and filter paths
# ===========================================================================


class TestCorrelationHotspotsEndpoint:
    def test_returns_empty_list_with_no_alerts(self, client: TestClient):
        headers = _auth(client, "admin", "admin123")
        resp = client.get("/api/metrics/correlation-hotspots", headers=headers)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_returns_hotspot_entries_after_alert_creation(self, client: TestClient):
        headers = _auth(client, "admin", "admin123")
        payload = {
            "source": "identity_provider",
            "source_ip": "10.0.5.5",
            "username": "jdoe",
            "event_type": "login_failed",
            "message": "Failed login",
        }
        for _ in range(5):
            client.post("/api/events", json=payload, headers=headers)

        resp = client.get("/api/metrics/correlation-hotspots", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) >= 1
        assert all("correlation_id" in item for item in body)
        assert all("alert_count" in item for item in body)
        assert all("max_dedup_count" in item for item in body)
        assert all("avg_confidence" in item for item in body)

    def test_limit_parameter_is_respected(self, client: TestClient):
        headers = _auth(client, "admin", "admin123")
        # Seed several different correlation IDs by varying the source IP
        for ip_suffix in range(10):
            payload = {
                "source": "identity_provider",
                "source_ip": f"10.1.0.{ip_suffix}",
                "username": f"user{ip_suffix}",
                "event_type": "login_failed",
                "message": "Failed login",
            }
            for _ in range(5):
                client.post("/api/events", json=payload, headers=headers)

        resp = client.get("/api/metrics/correlation-hotspots?limit=3", headers=headers)
        assert resp.status_code == 200
        assert len(resp.json()) <= 3


class TestAlertFilterAndSort:
    def _seed_alerts(self, client: TestClient, headers: dict) -> list[int]:
        """Create one high-severity and one low-severity alert, return their IDs."""
        alert_ids: list[int] = []
        for sev, ip in [("high", "10.2.0.1"), ("low", "10.2.0.2")]:
            payload = {
                "source": "identity_provider",
                "source_ip": ip,
                "username": "jdoe",
                "event_type": "login_failed",
                "message": "Failed login",
                "severity": sev,
            }
            for _ in range(5):
                client.post("/api/events", json=payload, headers=headers)
        all_alerts = client.get("/api/alerts", headers=headers).json()["items"]
        return [a["id"] for a in all_alerts]

    def test_filter_by_severity_high(self, client: TestClient):
        headers = _auth(client, "admin", "admin123")
        self._seed_alerts(client, headers)
        resp = client.get("/api/alerts?severity=high", headers=headers)
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert all(item["severity"] == "high" for item in items)

    def test_filter_by_status_open(self, client: TestClient):
        headers = _auth(client, "admin", "admin123")
        ids = self._seed_alerts(client, headers)
        # Close one alert
        client.patch(
            f"/api/alerts/{ids[0]}/status",
            json={"status": "closed"},
            headers=headers,
        )
        resp = client.get("/api/alerts?status=open", headers=headers)
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert all(item["status"] == "open" for item in items)

    def test_filter_by_status_closed(self, client: TestClient):
        headers = _auth(client, "admin", "admin123")
        ids = self._seed_alerts(client, headers)
        client.patch(
            f"/api/alerts/{ids[0]}/status",
            json={"status": "closed"},
            headers=headers,
        )
        resp = client.get("/api/alerts?status=closed", headers=headers)
        assert resp.status_code == 200
        assert len(resp.json()["items"]) >= 1
        assert all(item["status"] == "closed" for item in resp.json()["items"])

    def test_sort_by_last_seen_at_ascending(self, client: TestClient):
        headers = _auth(client, "admin", "admin123")
        self._seed_alerts(client, headers)
        resp = client.get(
            "/api/alerts?sort_by=last_seen_at&sort_order=asc", headers=headers
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        if len(items) >= 2:
            assert items[0]["last_seen_at"] <= items[-1]["last_seen_at"]


class TestUnauthenticatedAccess:
    """Requests without a valid token must be rejected."""

    @pytest.mark.parametrize(
        "method,path",
        [
            ("GET", "/api/alerts"),
            ("GET", "/api/events"),
            ("GET", "/api/incidents"),
            ("GET", "/api/metrics/summary"),
            ("GET", "/api/detections"),
            ("GET", "/api/platform/feature-flags"),
        ],
    )
    def test_unauthenticated_request_returns_401(
        self, client: TestClient, method: str, path: str
    ):
        if method == "GET":
            resp = client.get(path)
        else:
            resp = client.post(path, json={})
        assert resp.status_code == 401


class TestAlertAssignment:
    def _get_alert_id(self, client: TestClient, headers: dict) -> int:
        payload = {
            "source": "identity_provider",
            "source_ip": "10.3.0.1",
            "username": "jdoe",
            "event_type": "login_failed",
            "message": "Failed login",
        }
        for _ in range(5):
            client.post("/api/events", json=payload, headers=headers)
        return client.get("/api/alerts", headers=headers).json()["items"][0]["id"]

    def test_assign_viewer_user_as_analyst_returns_400(self, client: TestClient):
        headers = _auth(client, "admin", "admin123")
        alert_id = self._get_alert_id(client, headers)

        # Get the viewer's user ID
        db = TestingSessionLocal()
        viewer_id = _user_id(db, "viewer")
        db.close()

        resp = client.patch(
            f"/api/alerts/{alert_id}/assign",
            json={"analyst_id": viewer_id},
            headers=headers,
        )
        assert resp.status_code == 400
        assert "Admin or Analyst" in resp.json()["detail"]

    def test_unassign_alert_by_passing_null_analyst_id(self, client: TestClient):
        headers = _auth(client, "admin", "admin123")
        alert_id = self._get_alert_id(client, headers)

        # First assign the admin user
        db = TestingSessionLocal()
        admin_id = _user_id(db, "admin")
        db.close()

        client.patch(
            f"/api/alerts/{alert_id}/assign",
            json={"analyst_id": admin_id},
            headers=headers,
        )
        # Then unassign
        resp = client.patch(
            f"/api/alerts/{alert_id}/assign",
            json={"analyst_id": None},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["assigned_analyst_id"] is None


# ===========================================================================
# RBAC – additional role combinations
# ===========================================================================


class TestRbacAlertOperations:
    def _get_alert_id(self, client: TestClient, admin_headers: dict) -> int:
        payload = {
            "source": "identity_provider",
            "source_ip": "10.4.0.1",
            "username": "jdoe",
            "event_type": "login_failed",
            "message": "Failed login",
        }
        for _ in range(5):
            client.post("/api/events", json=payload, headers=admin_headers)
        return client.get("/api/alerts", headers=admin_headers).json()["items"][0]["id"]

    def test_viewer_cannot_patch_alert_status(self, client: TestClient):
        admin_headers = _auth(client, "admin", "admin123")
        viewer_headers = _auth(client, "viewer", "viewer123")
        alert_id = self._get_alert_id(client, admin_headers)

        resp = client.patch(
            f"/api/alerts/{alert_id}/status",
            json={"status": "triaged"},
            headers=viewer_headers,
        )
        assert resp.status_code == 403

    def test_viewer_cannot_add_alert_notes(self, client: TestClient):
        admin_headers = _auth(client, "admin", "admin123")
        viewer_headers = _auth(client, "viewer", "viewer123")
        alert_id = self._get_alert_id(client, admin_headers)

        resp = client.post(
            f"/api/alerts/{alert_id}/notes",
            json={"note": "Viewer sneaky note"},
            headers=viewer_headers,
        )
        assert resp.status_code == 403

    def test_analyst_can_patch_alert_status(self, client: TestClient):
        admin_headers = _auth(client, "admin", "admin123")
        analyst_headers = _auth(client, "analyst", "analyst123")
        alert_id = self._get_alert_id(client, admin_headers)

        resp = client.patch(
            f"/api/alerts/{alert_id}/status",
            json={"status": "triaged"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "triaged"

    def test_analyst_can_add_alert_notes(self, client: TestClient):
        admin_headers = _auth(client, "admin", "admin123")
        analyst_headers = _auth(client, "analyst", "analyst123")
        alert_id = self._get_alert_id(client, admin_headers)

        resp = client.post(
            f"/api/alerts/{alert_id}/notes",
            json={"note": "analyst investigation note"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert "analyst investigation note" in resp.json()["note"]

    def test_analyst_cannot_process_jobs(self, client: TestClient):
        analyst_headers = _auth(client, "analyst", "analyst123")
        resp = client.post("/api/jobs/process-pending", headers=analyst_headers)
        assert resp.status_code == 403

    def test_viewer_cannot_access_platform_feature_flags(self, client: TestClient):
        viewer_headers = _auth(client, "viewer", "viewer123")
        resp = client.get("/api/platform/feature-flags", headers=viewer_headers)
        assert resp.status_code == 403
