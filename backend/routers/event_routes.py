import uuid
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from database import get_db
import models
import schemas
from auth import get_current_active_user

router = APIRouter(
    prefix="/events",
    tags=["File Events"]
)


# ------------------------------------------------------------------
# POST /events — Receive a new file event from the detection engine
# ------------------------------------------------------------------
@router.post(
    "",
    response_model=schemas.FileEventResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a detected file event from the security engine"
)
def create_event(
    event_in: schemas.FileEventCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    # Verify the folder exists
    folder = db.query(models.MonitoredFolder).filter(
        models.MonitoredFolder.id == event_in.folder_id
    ).first()
    if not folder:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Monitored folder with id={event_in.folder_id} not found"
        )

    event = models.FileEvent(
        event_id=str(uuid.uuid4()),
        event_type=event_in.event_type,
        file_name=event_in.file_name,
        module=event_in.module,
        folder_id=event_in.folder_id,
        severity=event_in.severity,
        risk_score=event_in.risk_score,
        evidence=event_in.evidence
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    from services.audit_service import AuditService
    AuditService.log_file_event_received(db, current_user.id, event)

    return event


# ------------------------------------------------------------------
# GET /events — List events with optional filters
# ------------------------------------------------------------------
@router.get(
    "",
    response_model=List[schemas.FileEventResponse],
    summary="Retrieve file events with optional severity and folder filters"
)
def list_events(
    skip: int = 0,
    limit: int = 50,
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    folder_id: Optional[int] = Query(None, description="Filter by folder ID"),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    query = db.query(models.FileEvent)

    if severity:
        query = query.filter(models.FileEvent.severity == severity.upper())
    if folder_id:
        query = query.filter(models.FileEvent.folder_id == folder_id)

    return query.order_by(models.FileEvent.timestamp.desc()).offset(skip).limit(limit).all()


# ------------------------------------------------------------------
# GET /events/{event_id} — Retrieve a single event by its UUID
# ------------------------------------------------------------------
@router.get(
    "/{event_id}",
    response_model=schemas.FileEventResponse,
    summary="Get details of a specific file event by its event_id (UUID)"
)
def get_event(
    event_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    event = db.query(models.FileEvent).filter(
        models.FileEvent.event_id == event_id
    ).first()
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return event
