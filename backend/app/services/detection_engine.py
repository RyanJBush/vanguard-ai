from dataclasses import dataclass
from datetime import datetime

from app.models import Event


@dataclass
class DetectionFinding:
    rule_name: str
    severity: str
    confidence: float
    description: str


class DetectionEngine:
    def evaluate_event(self, event: Event) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        payload = event.payload or {}

        if event.event_type == "failed_login" and int(payload.get("failed_count", 0)) >= 5:
            findings.append(
                DetectionFinding(
                    rule_name="brute_force_login",
                    severity="high",
                    confidence=0.9,
                    description="Multiple failed login attempts detected.",
                )
            )

        hour = event.occurred_at.hour
        if event.event_type == "login" and (hour < 6 or hour > 22):
            findings.append(
                DetectionFinding(
                    rule_name="unusual_login_hour",
                    severity="medium",
                    confidence=0.65,
                    description=f"Login observed at unusual hour ({hour}:00 UTC).",
                )
            )

        if event.event_type in {"role_change", "sudo_grant", "admin_role_assigned"}:
            findings.append(
                DetectionFinding(
                    rule_name="privilege_escalation_indicator",
                    severity="critical",
                    confidence=0.95,
                    description="Potential privilege escalation pattern identified.",
                )
            )

        if event.event_type == "access_denied" and int(payload.get("failed_access_count", 0)) >= 20:
            findings.append(
                DetectionFinding(
                    rule_name="failed_access_spike_anomaly",
                    severity="medium",
                    confidence=0.55,
                    description="Anomalous spike in failed access attempts.",
                )
            )

        return findings


detection_engine = DetectionEngine()
