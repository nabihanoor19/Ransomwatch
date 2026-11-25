import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_
from sqlalchemy.orm import Session
from typing import List, Optional

from database import get_db
import models
import schemas
from auth import get_current_active_user

router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"]
)


# ------------------------------------------------------------------
# POST /incidents — Record a new detection incident
# ------------------------------------------------------------------
@router.post(
    "",
    response_model=schemas.IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record a new ransomware detection incident"
)
def create_incident(
    incident_in: schemas.IncidentCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    incident = models.Incident(
        incident_id=f"INC-{str(uuid.uuid4())[:8].upper()}",
        severity=incident_in.severity,
        risk_score=incident_in.risk_score,
        description=incident_in.description,
        evidence=incident_in.evidence,
        status="open"
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    db.add(models.AuditLog(
        user_id=current_user.id,
        action="INCIDENT_CREATED",
        resource_type="incidents",
        resource_id=incident.incident_id,
        status="success",
        details={
            "incident_id": incident.incident_id,
            "severity": incident.severity,
            "risk_score": incident.risk_score
        }
    ))
    db.commit()

    return incident


# ------------------------------------------------------------------
# GET /incidents — List all incidents (with Task 9 filters)
# ------------------------------------------------------------------
@router.get(
    "",
    response_model=List[schemas.IncidentResponse],
    summary="List recorded incidents with optional severity, status, module, and date range filters"
)
def list_incidents(
    skip: int = 0,
    limit: int = 50,
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    incident_status: Optional[str] = Query(None, alias="status", description="Filter by status: open, investigating, resolved"),
    module: Optional[str] = Query(None, description="Filter by detection module: entropy, canary, rules, anomaly, monitor"),
    start_date: Optional[datetime] = Query(None, description="Filter incidents created at or after this ISO timestamp"),
    end_date: Optional[datetime] = Query(None, description="Filter incidents created at or before this ISO timestamp"),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    query = db.query(models.Incident)

    if severity:
        query = query.filter(models.Incident.severity == severity.upper())
    if incident_status:
        query = query.filter(models.Incident.status == incident_status.lower())
    if start_date:
        query = query.filter(models.Incident.created_at >= start_date.replace(tzinfo=None))
    if end_date:
        query = query.filter(models.Incident.created_at <= end_date.replace(tzinfo=None))
    if module:
        mod_lower = module.lower()
        linked_ids = (
            db.query(models.FileEvent.incident_id)
            .filter(
                models.FileEvent.incident_id.isnot(None),
                models.FileEvent.module == mod_lower,
            )
            .distinct()
        )
        query = query.filter(
            or_(
                models.Incident.id.in_(linked_ids),
                models.Incident.description.ilike(f"%{mod_lower}%"),
            )
        )

    return (
        query.order_by(models.Incident.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


# ------------------------------------------------------------------
# GET /incidents/{incident_id} — Get a single incident's full details
# ------------------------------------------------------------------
@router.get(
    "/{incident_id}",
    response_model=schemas.IncidentResponse,
    summary="Get full details of a single incident by its incident_id (e.g. INC-AB12CD34)"
)
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    incident = db.query(models.Incident).filter(
        models.Incident.incident_id == incident_id
    ).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


# ------------------------------------------------------------------
# PATCH /incidents/{incident_id} — Update incident status
# ------------------------------------------------------------------
@router.patch(
    "/{incident_id}",
    response_model=schemas.IncidentResponse,
    summary="Update the status of an incident: open → investigating → resolved"
)
def update_incident_status(
    incident_id: str,
    update_in: schemas.IncidentStatusUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    incident = db.query(models.Incident).filter(
        models.Incident.incident_id == incident_id
    ).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    old_status = incident.status
    incident.status = update_in.status
    db.commit()
    db.refresh(incident)

    db.add(models.AuditLog(
        user_id=current_user.id,
        action="INCIDENT_STATUS_UPDATED",
        resource_type="incidents",
        resource_id=incident.incident_id,
        status="success",
        details={
            "incident_id": incident.incident_id,
            "old_status": old_status,
            "new_status": incident.status
        }
    ))
    db.commit()

    return incident
