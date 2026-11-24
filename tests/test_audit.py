import pytest
import sys
from pathlib import Path
from fastapi.testclient import TestClient

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from main import app
from database import SessionLocal
import models
from auth import hash_password
from services.audit_service import AuditService, redact_sensitive_data

client = TestClient(app)

@pytest.fixture(scope="function", autouse=True)
def clean_audit_state():
    db = SessionLocal()
    db.query(models.AuditLog).delete()
    db.query(models.FileEvent).delete()
    db.query(models.Incident).delete()
    db.query(models.MonitoredFolder).delete()
    db.query(models.Configuration).delete()
    db.query(models.User).filter(
        models.User.email.like("%@audit-test.com")
    ).delete()
    db.commit()
    db.close()
    yield


def seed_admin_and_operator():
    db = SessionLocal()
    admin = models.User(
        username="audit_admin",
        email="admin@audit-test.com",
        password_hash=hash_password("AdminPass123!"),
        role="admin",
        is_active=True
    )
    op = models.User(
        username="audit_operator",
        email="operator@audit-test.com",
        password_hash=hash_password("OperatorPass123!"),
        role="operator",
        is_active=True
    )
    db.add(admin)
    db.add(op)
    db.commit()
    db.close()

    admin_token = client.post("/auth/login", data={"username": "admin@audit-test.com", "password": "AdminPass123!"}).json()["access_token"]
    op_token = client.post("/auth/login", data={"username": "operator@audit-test.com", "password": "OperatorPass123!"}).json()["access_token"]
    return admin_token, op_token


# ============================================================
# 1. TEST REDACTION OF SENSITIVE KEYS
# ============================================================
def test_redact_sensitive_data():
    sample = {
        "username": "alice",
        "password": "SuperSecretPassword123!",
        "access_token": "eyJhbGciOi...",
        "nested": {
            "api_key": "xyz-123",
            "safe_field": "ok"
        },
        "items": [
            {"secret": "hidden_val"},
            {"public": "viewable"}
        ]
    }
    redacted = redact_sensitive_data(sample)
    assert redacted["password"] == "[REDACTED]"
    assert redacted["access_token"] == "[REDACTED]"
    assert redacted["nested"]["api_key"] == "[REDACTED]"
    assert redacted["nested"]["safe_field"] == "ok"
    assert redacted["items"][0]["secret"] == "[REDACTED]"
    assert redacted["items"][1]["public"] == "viewable"


# ============================================================
# 2. TEST LOGIN SUCCESS & FAILURE LOGGING
# ============================================================
def test_login_success_and_failure_audit_logging():
    seed_admin_and_operator()

    # Success
    client.post("/auth/login", data={"username": "operator@audit-test.com", "password": "OperatorPass123!"})
    # Failure
    client.post("/auth/login", data={"username": "operator@audit-test.com", "password": "WrongPassword!"})

    db = SessionLocal()
    success_log = db.query(models.AuditLog).filter(models.AuditLog.action.in_(["USER_LOGIN", "USER_LOGIN_SUCCESS"])).first()
    failure_log = db.query(models.AuditLog).filter(models.AuditLog.action == "USER_LOGIN_FAILED").first()
    assert success_log is not None
    assert failure_log is not None
    assert failure_log.status == "failure"
    # Ensure password itself was not logged
    assert "WrongPassword!" not in str(failure_log.details)
    db.close()


# ============================================================
# 3. TEST FOLDER & MONITORING AUDIT LOGGING
# ============================================================
def test_folder_and_monitoring_audit_logging():
    admin_token, op_token = seed_admin_and_operator()
    h = {"Authorization": f"Bearer {op_token}"}

    # Register folder
    reg = client.post("/monitor/folders", headers=h, json={"folder_path": "D:/audit_sandbox", "folder_name": "AuditBox"})
    folder_id = reg.json()["id"]

    # Start and stop monitoring
    client.post(f"/monitor/start/{folder_id}", headers=h)
    client.post(f"/monitor/stop/{folder_id}", headers=h)

    db = SessionLocal()
    reg_log = db.query(models.AuditLog).filter(models.AuditLog.action == "FOLDER_REGISTERED").first()
    start_log = db.query(models.AuditLog).filter(models.AuditLog.action == "MONITORING_STARTED").first()
    stop_log = db.query(models.AuditLog).filter(models.AuditLog.action == "MONITORING_STOPPED").first()

    assert reg_log is not None
    assert start_log is not None
    assert stop_log is not None
    db.close()


# ============================================================
# 4. TEST FILE EVENT & INCIDENT AUDIT LOGGING
# ============================================================
def test_file_event_and_incident_audit_logging():
    admin_token, op_token = seed_admin_and_operator()
    h = {"Authorization": f"Bearer {op_token}"}

    reg = client.post("/monitor/folders", headers=h, json={"folder_path": "D:/event_box", "folder_name": "EventBox"})
    folder_id = reg.json()["id"]

    # Post event
    client.post("/events", headers=h, json={
        "event_type": "file_modified",
        "file_name": "test.txt",
        "module": "entropy",
        "folder_id": folder_id,
        "severity": "HIGH",
        "risk_score": 80.0,
        "evidence": ["High entropy"]
    })

    # Post incident
    inc_res = client.post("/incidents", headers=h, json={
        "severity": "CRITICAL",
        "risk_score": 90.0,
        "description": "Critical breach",
        "evidence": []
    })
    inc_id = inc_res.json()["incident_id"]

    # Update incident
    client.patch(f"/incidents/{inc_id}", headers=h, json={"status": "investigating"})

    db = SessionLocal()
    evt_log = db.query(models.AuditLog).filter(models.AuditLog.action == "FILE_EVENT_RECEIVED").first()
    inc_log = db.query(models.AuditLog).filter(models.AuditLog.action == "INCIDENT_CREATED").first()
    stat_log = db.query(models.AuditLog).filter(models.AuditLog.action == "INCIDENT_STATUS_UPDATED").first()

    assert evt_log is not None
    assert inc_log is not None
    assert stat_log is not None
    db.close()


# ============================================================
# 5. TEST REPORT & CONFIG AUDIT LOGGING
# ============================================================
def test_report_and_config_audit_logging():
    admin_token, op_token = seed_admin_and_operator()

    # Report export
    client.get("/reports/export?format=json", headers={"Authorization": f"Bearer {op_token}"})

    # Config change (admin only)
    client.patch("/admin/configurations/audit_thresh", headers={"Authorization": f"Bearer {admin_token}"}, json={"value": 5.0, "is_enabled": True})

    db = SessionLocal()
    rep_log = db.query(models.AuditLog).filter(models.AuditLog.action == "REPORT_EXPORTED").first()
    cfg_log = db.query(models.AuditLog).filter(models.AuditLog.action.in_(["ADMIN_CONFIGURATION_CHANGED", "ADMIN_UPDATE_CONFIG"])).first()

    assert rep_log is not None
    assert cfg_log is not None
    db.close()


# ============================================================
# 6. TEST APPEND-ONLY GUARANTEE (No modification/deletion APIs)
# ============================================================
def test_audit_logs_are_append_only():
    admin_token, _ = seed_admin_and_operator()
    h = {"Authorization": f"Bearer {admin_token}"}

    # Attempt to delete audit logs
    res_del = client.delete("/admin/audit-logs", headers=h)
    assert res_del.status_code == 405  # Method Not Allowed

    # Attempt to patch audit logs
    res_patch = client.patch("/admin/audit-logs", headers=h, json={"action": "HACKED"})
    assert res_patch.status_code == 405  # Method Not Allowed
