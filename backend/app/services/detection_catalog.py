from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionDefinition:
    key: str
    title: str
    severity: str
    default_confidence: float
    mitre_techniques: list[str]
    recommendation: str
    dedup_window_minutes: int = 30


DETECTION_CATALOG: dict[str, DetectionDefinition] = {
    "brute_force_login_rule": DetectionDefinition(
        key="brute_force_login_rule",
        title="Brute Force Login Attempts",
        severity="high",
        default_confidence=0.82,
        mitre_techniques=["T1110"],
        recommendation="Investigate source IP, lock impacted accounts, and enforce MFA.",
        dedup_window_minutes=45,
    ),
    "unusual_login_hour_anomaly": DetectionDefinition(
        key="unusual_login_hour_anomaly",
        title="Unusual Login Hour",
        severity="medium",
        default_confidence=0.78,
        mitre_techniques=["T1078"],
        recommendation="Validate user activity and correlate with endpoint and VPN telemetry.",
        dedup_window_minutes=60,
    ),
    "privilege_escalation_indicator": DetectionDefinition(
        key="privilege_escalation_indicator",
        title="Privilege Escalation Activity",
        severity="critical",
        default_confidence=0.92,
        mitre_techniques=["T1078", "T1098"],
        recommendation="Review identity change history and rollback unauthorized role grants.",
        dedup_window_minutes=120,
    ),
    "high_volume_failed_access_anomaly": DetectionDefinition(
        key="high_volume_failed_access_anomaly",
        title="High Volume Failed Access",
        severity="high",
        default_confidence=0.80,
        mitre_techniques=["T1110", "T1078"],
        recommendation="Analyze failed access sources and block suspicious addresses.",
        dedup_window_minutes=30,
    ),
}
