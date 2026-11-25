"""
incident_service.py — Incident Creation, Correlation & Lifecycle Service (Member B / FR-6).

Provides centralized incident creation, correlation of HIGH/CRITICAL file events
into actionable incidents in SQLite, status transitions, and append-only audit
logging via AuditService.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

import models
from services.audit_service import AuditService

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class IncidentService:
    """Manages security incident creation, event correlation, and lifecycle."""

    @staticmethod
    def create_incident(
        db: Session,
        severity: str,
        risk_score: float,
        description: Optional[str] = None,
        evidence: Optional[List[str]] = None,
        user_id: Optional[int] = None,
    ) -> models.Incident:
        """Create and persist a new Incident record and emit an audit entry."""
        incident = models.Incident(
            incident_id=f"INC-{str(uuid.uuid4())[:8].upper()}",
            severity=severity,
            risk_score=round(float(risk_score), 2),
            description=description,
            evidence=list(evidence or []),
            status="open",
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)

        AuditService.log_incident_created(db, user_id, incident)
        return incident

    @staticmethod
    def correlate_or_create_incident(
        db: Session,
        event: models.FileEvent,
        description: Optional[str] = None,
        user_id: Optional[int] = None,
        correlation_window_seconds: int = 120,
        min_risk_score: float = 65.0,
    ) -> Optional[models.Incident]:
        """
        If a FileEvent crosses the incident threshold (HIGH/CRITICAL or risk >= 65),
        attach it to a recent open incident for the same folder or create a new one.
        """
        is_high_risk = (
            event.severity in {"HIGH", "CRITICAL"}
            or float(event.risk_score) >= min_risk_score
        )
        if not is_high_risk:
            return None

        folder_tag = f"[Folder #{event.folder_id}]"
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
            seconds=correlation_window_seconds
        )

        existing = (
            db.query(models.Incident)
            .filter(
                models.Incident.status.in_(["open", "investigating"]),
                models.Incident.created_at >= cutoff,
                models.Incident.description.like(f"{folder_tag}%"),
            )
            .order_by(models.Incident.created_at.desc())
            .first()
        )

        if existing is not None:
            # Escalate severity and risk_score if the new event is more severe
            if SEVERITY_RANK.get(event.severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
                existing.severity = event.severity
            existing.risk_score = max(float(existing.risk_score), float(event.risk_score))

            merged = list(existing.evidence or [])
            for item in (event.evidence or []):
                if item not in merged and len(merged) < 25:
                    merged.append(item)
            existing.evidence = merged
            existing.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)

            event.incident_id = existing.id
            db.commit()
            db.refresh(existing)
            db.refresh(event)
            return existing

        summary = description or (
            f"{folder_tag} Suspicious {event.module or 'security'} activity on "
            f"'{event.file_name}' ({event.event_type})"
        )
        incident = IncidentService.create_incident(
            db=db,
            severity=event.severity,
            risk_score=event.risk_score,
            description=summary,
            evidence=list(event.evidence or []),
            user_id=user_id,
        )
        event.incident_id = incident.id
        db.commit()
        db.refresh(event)
        return incident

    @staticmethod
    def update_status(
        db: Session,
        incident_id: str,
        new_status: str,
        user_id: Optional[int] = None,
    ) -> Optional[models.Incident]:
        """Transition an incident status and record an audit log entry."""
        incident = (
            db.query(models.Incident)
            .filter(models.Incident.incident_id == incident_id)
            .first()
        )
        if not incident:
            return None

        old_status = incident.status
        incident.status = new_status
        db.commit()
        db.refresh(incident)

        AuditService.log_incident_status_updated(
            db=db,
            user_id=user_id,
            incident_id=incident.incident_id,
            old_status=old_status,
            new_status=new_status,
        )
        return incident
