from datetime import UTC, datetime, timedelta

import pandas as pd
from sklearn.ensemble import IsolationForest
from sqlalchemy import and_
from sqlalchemy.orm import Session

from app.models import Alert, AlertStatus, Detection, Event
from app.services.detection_catalog import DETECTION_CATALOG, DetectionDefinition


class DetectionSignal:
    def __init__(
        self,
        name: str,
        severity: str,
        confidence: float,
        explanation: str,
        mitre_techniques: list[str],
        recommendation: str,
        dedup_window_minutes: int,
        correlation_entity: str,
    ):
        self.name = name
        self.severity = severity
        self.confidence = confidence
        self.explanation = explanation
        self.mitre_techniques = mitre_techniques
        self.recommendation = recommendation
        self.dedup_window_minutes = dedup_window_minutes
        self.correlation_entity = correlation_entity

    @property
    def correlation_id(self) -> str:
        return f"{self.name}:{self.correlation_entity}"


def _signal_from_catalog(
    definition: DetectionDefinition,
    confidence: float,
    explanation: str,
    correlation_entity: str,
) -> DetectionSignal:
    return DetectionSignal(
        name=definition.key,
        severity=definition.severity,
        confidence=confidence,
        explanation=explanation,
        mitre_techniques=definition.mitre_techniques,
        recommendation=definition.recommendation,
        dedup_window_minutes=definition.dedup_window_minutes,
        correlation_entity=correlation_entity,
    )


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
            definition = DETECTION_CATALOG["brute_force_login_rule"]
            signals.append(
                _signal_from_catalog(
                    definition=definition,
                    confidence=min(0.99, 0.7 + failures / 20),
                    explanation=f"{failures} failed login attempts from {event.source_ip} in the past hour.",
                    correlation_entity=event.source_ip,
                ),
            )

    if event.event_type == "login_success":
        hour = event.occurred_at.hour
        if hour < 6 or hour > 20:
            definition = DETECTION_CATALOG["unusual_login_hour_anomaly"]
            signals.append(
                _signal_from_catalog(
                    definition=definition,
                    confidence=0.78,
                    explanation=(
                        f"Successful login by {event.username or 'unknown user'} at {hour:02d}:00 UTC."
                    ),
                    correlation_entity=event.username or event.source_ip or "unknown_user",
                ),
            )

    if event.event_type in {"privilege_change", "role_update"} or "admin" in event.message.lower():
        definition = DETECTION_CATALOG["privilege_escalation_indicator"]
        signals.append(
            _signal_from_catalog(
                definition=definition,
                confidence=0.92,
                explanation=(
                    "Event indicates elevated privilege assignment or administrative access expansion."
                ),
                correlation_entity=event.username or "service_account",
            ),
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
            definition = DETECTION_CATALOG["high_volume_failed_access_anomaly"]
            signals.append(
                _signal_from_catalog(
                    definition=definition,
                    confidence=confidence,
                    explanation=f"{failed_volume} failed access events observed in a 10-minute window.",
                    correlation_entity=event.source_ip or event.username or "org_scope",
                ),
            )

    return signals


def persist_detections_and_alerts(db: Session, event: Event, signals: list[DetectionSignal]):
    detections: list[Detection] = []
    alerts: list[Alert] = []
    for signal in signals:
        detection_definition = DETECTION_CATALOG.get(signal.name)
        detection = Detection(
            event_id=event.id,
            organization_id=event.organization_id,
            detection_type=signal.name,
            title=detection_definition.title if detection_definition else signal.name.replace("_", " ").title(),
            severity=signal.severity,
            confidence_score=signal.confidence,
            explanation=signal.explanation,
            mitre_techniques=signal.mitre_techniques,
            recommended_next_steps=signal.recommendation,
        )
        db.add(detection)
        db.flush()

        dedup_cutoff = event.occurred_at - timedelta(minutes=signal.dedup_window_minutes)
        existing_alert = (
            db.query(Alert)
            .filter(
                and_(
                    Alert.organization_id == event.organization_id,
                    Alert.correlation_id == signal.correlation_id,
                    Alert.status.in_(
                        [
                            AlertStatus.open,
                            AlertStatus.triaged,
                            AlertStatus.investigating,
                            AlertStatus.escalated,
                        ]
                    ),
                    Alert.last_seen_at >= dedup_cutoff,
                )
            )
            .order_by(Alert.last_seen_at.desc())
            .first()
        )

        if existing_alert:
            existing_alert.dedup_count += 1
            existing_alert.last_seen_at = max(existing_alert.last_seen_at, event.occurred_at)
            existing_alert.confidence_score = max(existing_alert.confidence_score, signal.confidence)
            if existing_alert.id not in {alert.id for alert in alerts}:
                alerts.append(existing_alert)
            detections.append(detection)
            continue

        alert = Alert(
            organization_id=event.organization_id,
            event_id=event.id,
            detection_id=detection.id,
            title=detection.title,
            severity=signal.severity,
            confidence_score=signal.confidence,
            explanation=signal.explanation,
            mitre_techniques=signal.mitre_techniques,
            correlation_id=signal.correlation_id,
            dedup_count=1,
            first_seen_at=event.occurred_at,
            last_seen_at=event.occurred_at,
        )
        db.add(alert)
        detections.append(detection)
        alerts.append(alert)

    db.flush()
    return detections, alerts


def default_occurred_at(value: datetime | None) -> datetime:
    return value or datetime.now(UTC).replace(tzinfo=None)
