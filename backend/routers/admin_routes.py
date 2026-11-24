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


# -------------------------------------------------------------------
# 1. MANAGE USERS (Admin Only)
# -------------------------------------------------------------------
@router.get(
    "/users",
    response_model=List[schemas.UserResponse],
    summary="List all registered users"
)
def list_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(models.User).offset(skip).limit(limit).all()


@router.post(
    "/users",
    response_model=schemas.UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a user with designated role (Admin only)"
)
def create_user_by_admin(
    user_data: schemas.UserCreate,
    role: str = "operator",
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin)
):
    if role not in ["admin", "operator"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be 'admin' or 'operator'."
        )

    if db.query(models.User).filter(models.User.username == user_data.username).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")
    if db.query(models.User).filter(models.User.email == user_data.email).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")

    new_user = models.User(
        username=user_data.username,
        email=user_data.email,
        password_hash=hash_password(user_data.password),
        role=role,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    audit_entry = models.AuditLog(
        user_id=admin.id,
        action="ADMIN_CREATE_USER",
        resource_type="users",
        resource_id=str(new_user.id),
        status="success",
        details={"created_username": new_user.username, "assigned_role": new_user.role}
    )
    db.add(audit_entry)
    db.commit()

    return new_user


@router.patch(
    "/users/{user_id}/status",
    response_model=schemas.UserResponse,
    summary="Activate or deactivate a user account"
)
def update_user_status(
    user_id: int,
    is_active: bool,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Prevent an admin from disabling their own account
    if user.id == admin.id and not is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot deactivate their own account."
        )

    user.is_active = is_active
    db.commit()
    db.refresh(user)

    audit_entry = models.AuditLog(
        user_id=admin.id,
        action="ADMIN_UPDATE_USER_STATUS",
        resource_type="users",
        resource_id=str(user.id),
        status="success",
        details={"target_username": user.username, "new_active_status": is_active}
    )
    db.add(audit_entry)
    db.commit()

    return user


# -------------------------------------------------------------------
# 2. VIEW AUDIT LOGS (Admin Only)
# -------------------------------------------------------------------
@router.get(
    "/audit-logs",
    response_model=List[schemas.AuditLogResponse],
    summary="View system audit logs"
)
def get_audit_logs(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).offset(skip).limit(limit).all()


# -------------------------------------------------------------------
# 3. CHANGE DETECTION THRESHOLDS & CONFIGURATIONS (Admin Only)
# -------------------------------------------------------------------
@router.get(
    "/configurations",
    response_model=List[schemas.ConfigurationResponse],
    summary="List all detection configurations and thresholds"
)
def get_configurations(db: Session = Depends(get_db)):
    return db.query(models.Configuration).all()


@router.put(
    "/configurations/{rule_name}",
    response_model=schemas.ConfigurationResponse,
    summary="Update or set detection threshold / system configuration"
)
def set_configuration(
    rule_name: str,
    config_in: schemas.ConfigurationCreate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin)
):
    config = db.query(models.Configuration).filter(models.Configuration.rule_name == rule_name).first()
    if not config:
        config = models.Configuration(
            rule_name=rule_name,
            value=config_in.value,
            is_enabled=config_in.is_enabled,
            updated_by=admin.id
        )
        db.add(config)
    else:
        config.value = config_in.value
        config.is_enabled = config_in.is_enabled
        config.updated_by = admin.id

    db.commit()
    db.refresh(config)

    audit_entry = models.AuditLog(
        user_id=admin.id,
        action="ADMIN_UPDATE_CONFIG",
        resource_type="configurations",
        resource_id=rule_name,
        status="success",
        details={"rule_name": rule_name, "value": config_in.value}
    )
    db.add(audit_entry)
    db.commit()

    return config
