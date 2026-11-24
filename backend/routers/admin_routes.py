from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from database import get_db
import models
import schemas
from auth import require_admin, hash_password

router = APIRouter(
    prefix="/admin",
    tags=["Administration (Admin Only)"],
    dependencies=[Depends(require_admin)]
)


# ------------------------------------------------------------------
# GET /admin/users — List all users
# ------------------------------------------------------------------
@router.get(
    "/users",
    response_model=List[schemas.UserResponse],
    summary="List all registered users"
)
def list_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(models.User).offset(skip).limit(limit).all()


# ------------------------------------------------------------------
# PATCH /admin/users/{id} — Update a user's role or active status
# ------------------------------------------------------------------
@router.patch(
    "/users/{user_id}",
    response_model=schemas.UserResponse,
    summary="Update a user's role or active status (Admin only)"
)
def update_user(
    user_id: int,
    update_in: schemas.UserUpdate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Prevent admin from locking themselves out
    if user.id == admin.id and update_in.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot deactivate their own account."
        )

    changes = {}
    if update_in.is_active is not None:
        user.is_active = update_in.is_active
        changes["is_active"] = update_in.is_active
    if update_in.role is not None:
        user.role = update_in.role
        changes["role"] = update_in.role

    db.commit()
    db.refresh(user)

    db.add(models.AuditLog(
        user_id=admin.id,
        action="ADMIN_UPDATE_USER",
        resource_type="users",
        resource_id=str(user.id),
        status="success",
        details={"target_username": user.username, "changes": changes}
    ))
    db.commit()

    return user


# ------------------------------------------------------------------
# GET /admin/configurations — List all detection configurations
# ------------------------------------------------------------------
@router.get(
    "/configurations",
    response_model=List[schemas.ConfigurationResponse],
    summary="List all detection configurations and thresholds"
)
def get_configurations(db: Session = Depends(get_db)):
    return db.query(models.Configuration).all()


# ------------------------------------------------------------------
# PATCH /admin/configurations/{id} — Update a specific rule by name
# ------------------------------------------------------------------
@router.patch(
    "/configurations/{rule_name}",
    response_model=schemas.ConfigurationResponse,
    summary="Update (or create) a detection threshold or system configuration rule"
)
def update_configuration(
    rule_name: str,
    config_in: schemas.ConfigurationUpdate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin)
):
    config = db.query(models.Configuration).filter(
        models.Configuration.rule_name == rule_name
    ).first()

    if not config:
        # Auto-create if it doesn't exist yet
        config = models.Configuration(
            rule_name=rule_name,
            value=config_in.value,
            is_enabled=config_in.is_enabled if config_in.is_enabled is not None else True,
            updated_by=admin.id
        )
        db.add(config)
    else:
        if config_in.value is not None:
            config.value = config_in.value
        if config_in.is_enabled is not None:
            config.is_enabled = config_in.is_enabled
        config.updated_by = admin.id

    db.commit()
    db.refresh(config)

    db.add(models.AuditLog(
        user_id=admin.id,
        action="ADMIN_UPDATE_CONFIG",
        resource_type="configurations",
        resource_id=rule_name,
        status="success",
        details={"rule_name": rule_name, "new_value": config.value}
    ))
    db.commit()

    return config


# ------------------------------------------------------------------
# GET /admin/audit-logs — View system audit trail
# ------------------------------------------------------------------
@router.get(
    "/audit-logs",
    response_model=List[schemas.AuditLogResponse],
    summary="View full system audit trail (newest first)"
)
def get_audit_logs(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return (
        db.query(models.AuditLog)
        .order_by(models.AuditLog.timestamp.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
