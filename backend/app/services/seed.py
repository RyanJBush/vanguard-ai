from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.models import Event, Organization, Role, User
from app.security import hash_password
from app.services.detection_service import detect_event, persist_detections_and_alerts


def seed_demo_data(db: Session) -> None:
    if db.query(User).count() > 0:
        return

    org = Organization(name="Vanguard Demo Org")
    db.add(org)
    db.flush()

    users = [
        User(
            username="admin",
            full_name="Avery Admin",
            password_hash=hash_password("admin123"),
            role=Role.admin,
            organization_id=org.id,
        ),
        User(
            username="analyst",
            full_name="Sam Analyst",
            password_hash=hash_password("analyst123"),
            role=Role.analyst,
            organization_id=org.id,
        ),
        User(
            username="deteng",
            full_name="Devon Detection Engineer",
            password_hash=hash_password("deteng123"),
            role=Role.detection_engineer,
            organization_id=org.id,
        ),
        User(
            username="viewer",
            full_name="Viv Viewer",
            password_hash=hash_password("viewer123"),
            role=Role.viewer,
            organization_id=org.id,
        ),
    ]
    db.add_all(users)

    now = datetime.now(UTC).replace(tzinfo=None)
    events = [
        Event(
            organization_id=org.id,
            source="auth",
            source_ip="10.8.2.44",
            username="jdoe",
            event_type="login_failed",
            severity="medium",
            message="Failed login attempt due to invalid password",
            occurred_at=now - timedelta(minutes=8),
            event_metadata={
                "log_type": "auth",
                "geolocation": "US",
                "hostname": "wkstn-101",
                "department": "Finance",
                "user_role": "Analyst",
                "asset_criticality": "medium",
                "scenario": "password_spray_attempt",
            },
        ),
        Event(
            organization_id=org.id,
            source="auth",
            source_ip="192.168.22.5",
            username="jdoe",
            event_type="login_success",
            severity="low",
            message="User login succeeded",
            occurred_at=now - timedelta(hours=1),
            event_metadata={
                "log_type": "auth",
                "geolocation": "DE",
                "hostname": "vpn-jump-02",
                "department": "Finance",
                "user_role": "Analyst",
                "asset_criticality": "medium",
                "scenario": "suspicious_after_hours_access",
            },
        ),
        Event(
            organization_id=org.id,
            source="cloud",
            source_ip="10.10.4.1",
            username="svc-backup",
            event_type="privilege_change",
            severity="high",
            message="Admin role granted to service account",
            occurred_at=now - timedelta(minutes=20),
            event_metadata={
                "log_type": "cloud",
                "geolocation": "US",
                "hostname": "aws-iam-control",
                "department": "Platform",
                "user_role": "Service",
                "asset_criticality": "high",
                "ticket": "INC-1088",
                "scenario": "cloud_privilege_escalation",
            },
        ),
        Event(
            organization_id=org.id,
            source="endpoint",
            source_ip="10.6.4.12",
            username="jdoe",
            event_type="process_execution",
            severity="medium",
            message="PowerShell launched encoded command",
            occurred_at=now - timedelta(minutes=18),
            event_metadata={
                "log_type": "endpoint",
                "geolocation": "US",
                "hostname": "wkstn-101",
                "department": "Finance",
                "user_role": "Analyst",
                "asset_criticality": "medium",
                "scenario": "initial_access_payload_execution",
            },
        ),
        Event(
            organization_id=org.id,
            source="firewall",
            source_ip="203.0.113.44",
            username=None,
            event_type="connection_allowed",
            severity="high",
            message="Outbound connection to known command-and-control IP",
            occurred_at=now - timedelta(minutes=16),
            event_metadata={
                "log_type": "firewall",
                "geolocation": "US",
                "hostname": "edge-fw-01",
                "department": "Network",
                "user_role": "N/A",
                "asset_criticality": "critical",
                "threat_intel_match": True,
                "scenario": "c2_egress_channel",
            },
        ),
    ]

    brute_force_ip = "198.51.100.23"
    for minute_offset in range(12, 5, -1):
        events.append(
            Event(
                organization_id=org.id,
                source="auth",
                source_ip=brute_force_ip,
                username="finance-user",
                event_type="login_failed",
                severity="medium",
                message="Failed login due to invalid password",
                occurred_at=now - timedelta(minutes=minute_offset),
                event_metadata={
                    "log_type": "auth",
                    "geolocation": "RU",
                    "hostname": "idp-prod-01",
                    "department": "Finance",
                    "user_role": "Analyst",
                    "asset_criticality": "high",
                    "scenario": "password_spray_attempt",
                },
            )
        )

    db.add_all(events)
    db.flush()
    for event in events:
        signals = detect_event(db, event)
        persist_detections_and_alerts(db, event, signals)
    db.commit()
