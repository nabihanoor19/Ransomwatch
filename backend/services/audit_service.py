import logging
from typing import Any, Dict, Optional
from datetime import datetime
from sqlalchemy.orm import Session
import models

# -------------------------------------------------------------------
# Secure Audit Logger (Fallback & Console/File Mirroring)
# -------------------------------------------------------------------
logger = logging.getLogger("ransomwatch.audit")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] AUDIT [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Sensitive keys that must be scrubbed from audit details
SENSITIVE_KEYS = {
    "password",
    "password_hash",
    "secret",
    "secret_key",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "api_key",
    "credit_card",
    "credentials",
    "auth"
}


def redact_sensitive_data(data: Any) -> Any:
    """
    Recursively scans and redacts sensitive information such as passwords,
    API keys, and bearer tokens from audit details.
    """
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            if any(sensitive in str(key).lower() for sensitive in SENSITIVE_KEYS):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = redact_sensitive_data(value)
        return sanitized
    elif isinstance(data, list):
        return [redact_sensitive_data(item) for item in data]
    return data


# -------------------------------------------------------------------
# Centralized Audit Service
# -------------------------------------------------------------------
class AuditService:
    @staticmethod
    def log_event(
        db: Session,
        action: str,
        status: str = "success",
        user_id: Optional[int] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Optional[models.AuditLog]:
        """
        Records an append-only audit log entry in the database.
        Automatically redacts sensitive fields and mirrors the event
        to the secure audit logger.
        Safely handles database exceptions to ensure audit trail continuity.
        """
        # Redact sensitive information
        clean_details = redact_sensitive_data(details or {})

        # Primary persistence: Database record
        audit_entry = models.AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            status=status,
            details=clean_details,
            timestamp=datetime.utcnow()
        )

        # Fallback & Mirror logging: writes to standard logger
        log_msg = f"ACTION={action} STATUS={status} USER_ID={user_id} RESOURCE={resource_type}:{resource_id} DETAILS={clean_details}"
        if status == "success":
            logger.info(log_msg)
        else:
            logger.warning(log_msg)

        try:
            db.add(audit_entry)
            db.commit()
            db.refresh(audit_entry)
            return audit_entry
        except Exception as e:
            db.rollback()
            # Critical fallback: record failure so evidence is never silently lost
            logger.critical(f"DATABASE AUDIT LOG FAILURE for {action}: {e} | DATA={log_msg}")
            return None

    # --- Domain-Specific Convenience Methods ---

    @staticmethod
    def log_login_success(db: Session, user: models.User):
        return AuditService.log_event(
            db=db,
            action="USER_LOGIN",
            status="success",
            user_id=user.id,
            resource_type="auth",
            resource_id=str(user.id),
            details={"username": user.username, "role": user.role}
        )

    @staticmethod
    def log_login_failure(db: Session, attempted_identifier: str, reason: str = "Incorrect credentials"):
        return AuditService.log_event(
            db=db,
            action="USER_LOGIN_FAILED",
            status="failure",
            user_id=None,
            resource_type="auth",
            resource_id=attempted_identifier,
            details={"attempted_identifier": attempted_identifier, "reason": reason}
        )

    @staticmethod
    def log_logout(db: Session, user: models.User):
        return AuditService.log_event(
            db=db,
            action="USER_LOGOUT",
            status="success",
            user_id=user.id,
            resource_type="auth",
            resource_id=str(user.id),
            details={"username": user.username}
        )

    @staticmethod
    def log_folder_registered(db: Session, user_id: int, folder: models.MonitoredFolder):
        return AuditService.log_event(
            db=db,
            action="FOLDER_REGISTERED",
            status="success",
            user_id=user_id,
            resource_type="monitored_folders",
            resource_id=str(folder.id),
            details={"path": folder.folder_path, "name": folder.folder_name}
        )

    @staticmethod
    def log_monitoring_started(db: Session, user_id: int, folder: models.MonitoredFolder):
        return AuditService.log_event(
            db=db,
            action="MONITORING_STARTED",
            status="success",
            user_id=user_id,
            resource_type="monitored_folders",
            resource_id=str(folder.id),
            details={"path": folder.folder_path, "name": folder.folder_name}
        )

    @staticmethod
    def log_monitoring_stopped(db: Session, user_id: int, folder: models.MonitoredFolder):
        return AuditService.log_event(
            db=db,
            action="MONITORING_STOPPED",
            status="success",
            user_id=user_id,
            resource_type="monitored_folders",
            resource_id=str(folder.id),
            details={"path": folder.folder_path, "name": folder.folder_name}
        )

    @staticmethod
    def log_file_event_received(db: Session, user_id: int, event: models.FileEvent):
        return AuditService.log_event(
            db=db,
            action="FILE_EVENT_RECEIVED",
            status="success",
            user_id=user_id,
            resource_type="file_events",
            resource_id=event.event_id,
            details={
                "event_type": event.event_type,
                "file_name": event.file_name,
                "module": event.module,
                "severity": event.severity,
                "risk_score": event.risk_score,
                "folder_id": event.folder_id
            }
        )

    @staticmethod
    def log_incident_created(db: Session, user_id: int, incident: models.Incident):
        return AuditService.log_event(
            db=db,
            action="INCIDENT_CREATED",
            status="success",
            user_id=user_id,
            resource_type="incidents",
            resource_id=incident.incident_id,
            details={
                "incident_id": incident.incident_id,
                "severity": incident.severity,
                "risk_score": incident.risk_score,
                "description": incident.description
            }
        )

    @staticmethod
    def log_incident_status_updated(db: Session, user_id: int, incident_id: str, old_status: str, new_status: str):
        return AuditService.log_event(
            db=db,
            action="INCIDENT_STATUS_UPDATED",
            status="success",
            user_id=user_id,
            resource_type="incidents",
            resource_id=incident_id,
            details={"incident_id": incident_id, "old_status": old_status, "new_status": new_status}
        )

    @staticmethod
    def log_report_exported(db: Session, user_id: int, format: str, summary: Dict[str, Any]):
        return AuditService.log_event(
            db=db,
            action="REPORT_EXPORTED",
            status="success",
            user_id=user_id,
            resource_type="reports",
            resource_id=format,
            details={"format": format, "summary": summary}
        )

    @staticmethod
    def log_config_changed(db: Session, user_id: int, rule_name: str, new_value: Any):
        return AuditService.log_event(
            db=db,
            action="ADMIN_CONFIGURATION_CHANGED",
            status="success",
            user_id=user_id,
            resource_type="configurations",
            resource_id=rule_name,
            details={"rule_name": rule_name, "new_value": new_value}
        )

    @staticmethod
    def log_unauthorized_attempt(db: Session, user_id: int, username: str, role: str, resource: str, reason: str):
        return AuditService.log_event(
            db=db,
            action="ADMIN_ACCESS_DENIED",
            status="failure",
            user_id=user_id,
            resource_type="admin_endpoint",
            resource_id=resource,
            details={
                "username": username,
                "role": role,
                "reason": reason,
                "unauthorized_access_attempt": True
            }
        )
