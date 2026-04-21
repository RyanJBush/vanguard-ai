from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionDefinition:
    key: str
    title: str
    severity: str
    default_confidence: float
    mitre_techniques: tuple[str, ...]
    mitre_tactics: tuple[str, ...]
    recommendation: str
    description: str
    dedup_window_minutes: int = 30


DETECTION_CATALOG: dict[str, DetectionDefinition] = {
    "brute_force_login_rule": DetectionDefinition(
        key="brute_force_login_rule",
        title="Brute Force Login Attempts",
        severity="high",
        default_confidence=0.82,
        mitre_techniques=("T1110",),
        mitre_tactics=("Credential Access",),
        recommendation="Investigate source IP, lock impacted accounts, and enforce MFA.",
        description="Detects repeated failed authentication attempts from a shared source.",
        dedup_window_minutes=45,
    ),
    "unusual_login_hour_anomaly": DetectionDefinition(
        key="unusual_login_hour_anomaly",
        title="Unusual Login Hour",
        severity="medium",
        default_confidence=0.78,
        mitre_techniques=("T1078",),
        mitre_tactics=("Initial Access", "Persistence"),
        recommendation="Validate user activity and correlate with endpoint and VPN telemetry.",
        description="Flags successful logins during off-hours for identity abuse triage.",
        dedup_window_minutes=60,
    ),
    "privilege_escalation_indicator": DetectionDefinition(
        key="privilege_escalation_indicator",
        title="Privilege Escalation Activity",
        severity="critical",
        default_confidence=0.92,
        mitre_techniques=("T1078", "T1098"),
        mitre_tactics=("Privilege Escalation", "Persistence"),
        recommendation="Review identity change history and rollback unauthorized role grants.",
        description="Detects potentially unauthorized elevation of identity or role privileges.",
        dedup_window_minutes=120,
    ),
    "high_volume_failed_access_anomaly": DetectionDefinition(
        key="high_volume_failed_access_anomaly",
        title="High Volume Failed Access",
        severity="high",
        default_confidence=0.80,
        mitre_techniques=("T1110", "T1078"),
        mitre_tactics=("Credential Access", "Initial Access"),
        recommendation="Analyze failed access sources and block suspicious addresses.",
        description="Anomaly on concentrated login and access failures over a short rolling window.",
        dedup_window_minutes=30,
    ),
}


def list_detection_definitions() -> list[DetectionDefinition]:
    return list(DETECTION_CATALOG.values())
