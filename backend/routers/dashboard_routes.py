from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List

from database import get_db
import models
import schemas
from auth import get_current_active_user

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"]
)


# ------------------------------------------------------------------
# GET /dashboard/stats — Summary counts for the dashboard
# ------------------------------------------------------------------
@router.get(
    "/stats",
    response_model=schemas.DashboardStats,
    summary="Get overall system statistics for the dashboard"
)
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    return schemas.DashboardStats(
        total_monitored_folders=db.query(models.MonitoredFolder).count(),
        active_folders=db.query(models.MonitoredFolder).filter(
            models.MonitoredFolder.status == "active"
        ).count(),
        total_events=db.query(models.FileEvent).count(),
        total_incidents=db.query(models.Incident).count(),
        open_incidents=db.query(models.Incident).filter(
            models.Incident.status == "open"
        ).count(),
        investigating_incidents=db.query(models.Incident).filter(
            models.Incident.status == "investigating"
        ).count(),
        resolved_incidents=db.query(models.Incident).filter(
            models.Incident.status == "resolved"
        ).count()
    )


# ------------------------------------------------------------------
# GET /dashboard/recent-events — 10 most recent file events
# ------------------------------------------------------------------
@router.get(
    "/recent-events",
    response_model=List[schemas.RecentEvent],
    summary="Get the 10 most recent file events for the activity feed"
)
def get_recent_events(
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    return (
        db.query(models.FileEvent)
        .order_by(models.FileEvent.timestamp.desc())
        .limit(limit)
        .all()
    )


# ------------------------------------------------------------------
# GET /dashboard/severity — Count of incidents broken down by severity
# ------------------------------------------------------------------
@router.get(
    "/severity",
    response_model=schemas.SeverityCount,
    summary="Get incident counts broken down by severity level"
)
def get_severity_breakdown(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    def count(sev: str) -> int:
        return db.query(models.Incident).filter(models.Incident.severity == sev).count()

    return schemas.SeverityCount(
        LOW=count("LOW"),
        MEDIUM=count("MEDIUM"),
        HIGH=count("HIGH"),
        CRITICAL=count("CRITICAL")
    )
