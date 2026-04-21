from dataclasses import dataclass
from datetime import datetime, timedelta

from app.models import Event


@dataclass(frozen=True)
class SeedScenarioDefinition:
    key: str
    title: str
    description: str
    log_types: tuple[str, ...]
    expected_detections: tuple[str, ...]


SCENARIO_DEFINITIONS: dict[str, SeedScenarioDefinition] = {
    "credential_access_password_spray": SeedScenarioDefinition(
        key="credential_access_password_spray",
        title="Credential Access: Password Spray",
        description="Simulated distributed failed logins from one external source against finance users.",
        log_types=("auth",),
        expected_detections=("brute_force_login_rule", "high_volume_failed_access_anomaly"),
    ),
    "identity_privilege_escalation": SeedScenarioDefinition(
        key="identity_privilege_escalation",
        title="Cloud Identity Privilege Escalation",
        description="Unauthorized service-account role escalation followed by suspicious access.",
        log_types=("cloud", "auth"),
        expected_detections=("privilege_escalation_indicator", "unusual_login_hour_anomaly"),
    ),
    "command_and_control_egress": SeedScenarioDefinition(
        key="command_and_control_egress",
        title="Endpoint to C2 Egress",
        description="Endpoint execution and firewall telemetry indicating command-and-control traffic.",
        log_types=("endpoint", "firewall"),
        expected_detections=("high_volume_failed_access_anomaly",),
    ),
}


def list_seed_scenarios() -> list[SeedScenarioDefinition]:
    return list(SCENARIO_DEFINITIONS.values())


def build_scenario_events(*, scenario_key: str, organization_id: int, now: datetime) -> list[Event]:
    if scenario_key not in SCENARIO_DEFINITIONS:
        raise ValueError(f"Unsupported scenario: {scenario_key}")

    if scenario_key == "credential_access_password_spray":
        attacker_ip = "198.51.100.23"
        return [
            Event(
                organization_id=organization_id,
                source="auth",
                source_ip=attacker_ip,
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
                    "scenario": scenario_key,
                    "known_benign": False,
                },
            )
            for minute_offset in range(12, 5, -1)
        ]

    if scenario_key == "identity_privilege_escalation":
        return [
            Event(
                organization_id=organization_id,
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
                    "scenario": scenario_key,
                    "threat_intel_match": False,
                    "known_benign": False,
                },
            ),
            Event(
                organization_id=organization_id,
                source="auth",
                source_ip="192.168.22.5",
                username="svc-backup",
                event_type="login_success",
                severity="low",
                message="Service account login succeeded after-hours",
                occurred_at=now - timedelta(hours=1),
                event_metadata={
                    "log_type": "auth",
                    "geolocation": "DE",
                    "hostname": "vpn-jump-02",
                    "department": "Platform",
                    "user_role": "Service",
                    "asset_criticality": "high",
                    "scenario": scenario_key,
                    "known_benign": False,
                },
            ),
        ]

    return [
        Event(
            organization_id=organization_id,
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
                "scenario": scenario_key,
                "known_benign": False,
            },
        ),
        Event(
            organization_id=organization_id,
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
                "scenario": scenario_key,
                "threat_intel_match": True,
                "known_benign": False,
            },
        ),
    ]
