from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from database import get_db
import models
import schemas
from auth import get_current_active_user

router = APIRouter(
    prefix="/operator",
    tags=["Operator & Admin Operations"],
    dependencies=[Depends(get_current_active_user)]
)


# -------------------------------------------------------------------
# 1. VIEW DASHBOARD
# -------------------------------------------------------------------
@router.get(
    "/dashboard",
    summary="View dashboard summary statistics (Admin & Operator)"
)
def get_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
) -> Dict[str, Any]:
    monitored_count = db.query(models.MonitoredFolder).count()
    events_count = db.query(models.FileEvent).count()
    open_incidents_count = db.query(models.Incident).filter(models.Incident.status == "open").count()

    return {
        "status": "healthy",
        "monitored_folders": monitored_count,
        "total_events": events_count,
        "open_incidents": open_incidents_count,
        "operator": current_user.username,
        "role": current_user.role
    }


# -------------------------------------------------------------------
# 2. START MONITORING (Register Monitored Folder)
# -------------------------------------------------------------------
@router.post(
    "/monitored-folders",
    response_model=schemas.FolderResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new folder to monitor (Admin & Operator)"
)
def create_monitored_folder(
    folder_in: schemas.FolderCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    folder = models.MonitoredFolder(
        folder_path=folder_in.folder_path,
        folder_name=folder_in.folder_name,
        status="active",
        created_by=current_user.id
    )
    db.add(folder)
    db.commit()
    db.refresh(folder)

    # Log action to audit log
    audit_entry = models.AuditLog(
        user_id=current_user.id,
        action="MONITORING_STARTED",
        resource_type="monitored_folders",
        resource_id=str(folder.id),
        status="success",
        details={"path": folder.folder_path, "name": folder.folder_name}
    )
    db.add(audit_entry)
    db.commit()

    return folder


# -------------------------------------------------------------------
# 3. VIEW INCIDENTS
# -------------------------------------------------------------------
@router.get(
    "/incidents",
    response_model=List[schemas.IncidentResponse],
    summary="View all security incidents (Admin & Operator)"
)
def list_incidents(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    return db.query(models.Incident).offset(skip).limit(limit).all()


# -------------------------------------------------------------------
# 4. EXPORT REPORTS
# -------------------------------------------------------------------
@router.get(
    "/reports/export",
    summary="Export security activity summary report (Admin & Operator)"
)
def export_report(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
) -> Dict[str, Any]:
    return {
        "report_id": "REP-LATEST",
        "generated_by": current_user.username,
        "role": current_user.role,
        "total_monitored": db.query(models.MonitoredFolder).count(),
        "total_incidents": db.query(models.Incident).count(),
        "summary": "All systems operating normally."
    }
