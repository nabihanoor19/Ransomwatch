from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Any, Dict, List

from database import SessionLocal, get_db
import models
import schemas
from auth import get_current_active_user, require_admin
from security.pipeline import monitor_manager

router = APIRouter(
    prefix="/monitor",
    tags=["Folder Monitoring"]
)


# ------------------------------------------------------------------
# POST /monitor/folders — Register a new sandbox folder
# ------------------------------------------------------------------
@router.post(
    "/folders",
    response_model=schemas.FolderResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a folder for ransomware monitoring"
)
def register_folder(
    folder_in: schemas.FolderCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    # Prevent duplicate folder paths
    existing = db.query(models.MonitoredFolder).filter(
        models.MonitoredFolder.folder_path == folder_in.folder_path
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Folder path '{folder_in.folder_path}' is already registered."
        )

    folder = models.MonitoredFolder(
        folder_path=folder_in.folder_path,
        folder_name=folder_in.folder_name,
        status="stopped",           # starts in stopped state
        created_by=current_user.id
    )
    db.add(folder)
    db.commit()
    db.refresh(folder)

    db.add(models.AuditLog(
        user_id=current_user.id,
        action="FOLDER_REGISTERED",
        resource_type="monitored_folders",
        resource_id=str(folder.id),
        status="success",
        details={"path": folder.folder_path, "name": folder.folder_name}
    ))
    db.commit()

    return folder


# ------------------------------------------------------------------
# GET /monitor/folders — List all registered folders
# ------------------------------------------------------------------
@router.get(
    "/folders",
    response_model=List[schemas.FolderResponse],
    summary="List all registered monitored folders"
)
def list_folders(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    return db.query(models.MonitoredFolder).offset(skip).limit(limit).all()


# ------------------------------------------------------------------
# POST /monitor/start/{folder_id} — Start monitoring a folder
# ------------------------------------------------------------------
@router.post(
    "/start/{folder_id}",
    response_model=schemas.FolderResponse,
    summary="Start monitoring a registered folder"
)
def start_monitoring(
    folder_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    folder = db.query(models.MonitoredFolder).filter(
        models.MonitoredFolder.id == folder_id
    ).first()
    if not folder:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found")
    if folder.status == "active":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Folder is already being monitored")

    folder.status = "active"
    db.commit()
    db.refresh(folder)

    monitor_manager.start_monitoring(
        folder_id=folder.id,
        folder_path=folder.folder_path,
        db_factory=SessionLocal,
        user_id=current_user.id,
    )

    db.add(models.AuditLog(
        user_id=current_user.id,
        action="MONITORING_STARTED",
        resource_type="monitored_folders",
        resource_id=str(folder.id),
        status="success",
        details={"folder_name": folder.folder_name, "path": folder.folder_path}
    ))
    db.commit()

    return folder


# ------------------------------------------------------------------
# POST /monitor/stop/{folder_id} — Stop monitoring a folder
# ------------------------------------------------------------------
@router.post(
    "/stop/{folder_id}",
    response_model=schemas.FolderResponse,
    summary="Stop monitoring a registered folder"
)
def stop_monitoring(
    folder_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    folder = db.query(models.MonitoredFolder).filter(
        models.MonitoredFolder.id == folder_id
    ).first()
    if not folder:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found")
    if folder.status == "stopped":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Folder monitoring is already stopped")

    monitor_manager.stop_monitoring(folder.id)

    folder.status = "stopped"
    db.commit()
    db.refresh(folder)

    db.add(models.AuditLog(
        user_id=current_user.id,
        action="MONITORING_STOPPED",
        resource_type="monitored_folders",
        resource_id=str(folder.id),
        status="success",
        details={"folder_name": folder.folder_name, "path": folder.folder_path}
    ))
    db.commit()

    return folder


# ------------------------------------------------------------------
# GET /monitor/status/{folder_id} — Inspect live watcher & canary status
# ------------------------------------------------------------------
@router.get(
    "/status/{folder_id}",
    summary="Get live watchdog observer and canary status for a monitored folder"
)
def get_monitoring_status(
    folder_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
) -> Dict[str, Any]:
    folder = db.query(models.MonitoredFolder).filter(
        models.MonitoredFolder.id == folder_id
    ).first()
    if not folder:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found")

    live_status = monitor_manager.get_status(folder.id)
    live_status["db_status"] = folder.status
    live_status["folder_name"] = folder.folder_name
    return live_status


# ------------------------------------------------------------------
# POST /monitor/scan/{folder_id} — Verify canary integrity on demand
# ------------------------------------------------------------------
@router.post(
    "/scan/{folder_id}",
    summary="Verify canary file integrity on demand for a monitored folder"
)
def scan_folder_canaries(
    folder_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
) -> Dict[str, Any]:
    folder = db.query(models.MonitoredFolder).filter(
        models.MonitoredFolder.id == folder_id
    ).first()
    if not folder:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found")

    alerts = monitor_manager.verify_canaries(
        folder_id=folder.id,
        db=db,
        user_id=current_user.id,
    )
    return {
        "folder_id": folder.id,
        "alerts_triggered": len(alerts),
        "alerts": alerts,
    }
