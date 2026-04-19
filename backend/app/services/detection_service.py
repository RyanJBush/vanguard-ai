from datetime import UTC, datetime, timedelta

import pandas as pd
from sklearn.ensemble import IsolationForest
from sqlalchemy.orm import Session

from app.models import Alert, Detection, Event


class DetectionSignal:
    def __init__(self, name: str, severity: str, confidence: float, explanation: str):
        self.name = name
        self.severity = severity
        self.confidence = confidence
        self.explanation = explanation


def _failed_logins_same_ip(db: Session, event: Event) -> int:
    cutoff = event.occurred_at - timedelta(hours=1)
    return (
        db.query(Event)
        .filter(
            Event.organization_id == event.organization_id,
            Event.source_ip == event.source_ip,
            Event.event_type == "login_failed",
            Event.occurred_at >= cutoff,
        )
        .count()
    )


def _failed_access_recent(db: Session, event: Event, minutes: int = 10) -> int:
    cutoff = event.occurred_at - timedelta(minutes=minutes)
    return (
        db.query(Event)
        .filter(
            Event.organization_id == event.organization_id,
            Event.event_type.in_(["login_failed", "access_denied"]),
            Event.occurred_at >= cutoff,
        )
        .count()
    )


def detect_event(db: Session, event: Event) -> list[DetectionSignal]:
    signals: list[DetectionSignal] = []

    if event.event_type == "login_failed" and event.source_ip:
        failures = _failed_logins_same_ip(db, event)
        if failures >= 5:
            signals.append(
                DetectionSignal(
                    "brute_force_login_rule",
                    "high",
                    min(0.99, 0.7 + failures / 20),
                    f"{failures} failed login attempts from {event.source_ip} in the past hour.",
                )
            )

    if event.event_type == "login_success":
        hour = event.occurred_at.hour
        if hour < 6 or hour > 20:
            signals.append(
                DetectionSignal(
                    "unusual_login_hour_anomaly",
                    "medium",
                    0.78,
                    f"Successful login by {event.username or 'unknown user'} at {hour:02d}:00 UTC.",
                )
            )

    if event.event_type in {"privilege_change", "role_update"} or "admin" in event.message.lower():
        signals.append(
            DetectionSignal(
                "privilege_escalation_indicator",
                "critical",
                0.92,
                "Event indicates elevated privilege assignment or administrative access expansion.",
            )
        )

    if event.event_type in {"login_failed", "access_denied"}:
        failed_volume = _failed_access_recent(db, event)
        if failed_volume >= 20:
            confidence = 0.8
            history = (
                db.query(Event.occurred_at)
                .filter(
                    Event.organization_id == event.organization_id,
                    Event.event_type.in_(["login_failed", "access_denied"]),
                    Event.occurred_at >= event.occurred_at - timedelta(hours=6),
                )
                .all()
            )
            if len(history) >= 30:
                frame = pd.DataFrame({"minute": [ts.occurred_at.minute for ts in history]})
                model = IsolationForest(random_state=42, contamination=0.1)
                preds = model.fit_predict(frame)
                anomaly_ratio = float((preds == -1).sum() / len(preds))
                confidence = min(0.97, 0.75 + anomaly_ratio)
            signals.append(
                DetectionSignal(
                    "high_volume_failed_access_anomaly",
                    "high",
                    confidence,
                    f"{failed_volume} failed access events observed in a 10-minute window.",
                )
            )

    return signals


def persist_detections_and_alerts(db: Session, event: Event, signals: list[DetectionSignal]):
    detections: list[Detection] = []
    alerts: list[Alert] = []
    for signal in signals:
        detection = Detection(
            event_id=event.id,
            organization_id=event.organization_id,
            detection_type=signal.name,
            confidence_score=signal.confidence,
            explanation=signal.explanation,
        )
        db.add(detection)
        db.flush()

        alert = Alert(
            organization_id=event.organization_id,
            event_id=event.id,
            detection_id=detection.id,
            title=signal.name.replace("_", " ").title(),
            severity=signal.severity,
            confidence_score=signal.confidence,
            explanation=signal.explanation,
        )
        db.add(alert)
        detections.append(detection)
        alerts.append(alert)

    db.flush()
    return detections, alerts


def default_occurred_at(value: datetime | None) -> datetime:
    return value or datetime.now(UTC).replace(tzinfo=None)
