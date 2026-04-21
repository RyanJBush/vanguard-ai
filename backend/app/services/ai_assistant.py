from app.models import Alert, Incident


def build_alert_summary(alert: Alert) -> str:
    mitre = ", ".join(alert.mitre_techniques) if alert.mitre_techniques else "no ATT&CK tags"
    return (
        f"Alert '{alert.title}' is {alert.severity} severity with confidence "
        f"{round(alert.confidence_score, 2)}. Correlated count: {alert.dedup_count}. "
        f"Mapped techniques: {mitre}."
    )


def build_triage_recommendation(alert: Alert) -> tuple[str, str]:
    if alert.severity in {"critical", "high"}:
        priority = "P1"
    elif alert.severity == "medium":
        priority = "P2"
    else:
        priority = "P3"

    recommendation = (
        f"Prioritize {priority} triage. Validate source entity for correlation ID {alert.correlation_id}, "
        f"review timeline artifacts, and execute: {alert.recommended_next_steps or 'collect supporting evidence.'}"
    )
    return recommendation, priority


def build_incident_wrapup(incident: Incident) -> str:
    total_alerts = len(incident.alerts)
    severities = [alert.severity for alert in incident.alerts]
    critical_count = len([value for value in severities if value in {"critical", "high"}])
    return (
        f"Incident '{incident.title}' includes {total_alerts} linked alerts, with {critical_count} high/critical. "
        f"Current status is {incident.status.value}. Summary: {incident.summary or 'No analyst summary provided.'}"
    )
