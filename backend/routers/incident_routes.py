import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

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
# GET /incidents — List all incidents
# ------------------------------------------------------------------
@router.get(
    "",
    response_model=List[schemas.IncidentResponse],
    summary="List all recorded incidents (newest first)"
)
def list_incidents(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    return (
        db.query(models.Incident)
        .order_by(models.Incident.created_at.desc())
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
