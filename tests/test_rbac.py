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

client = TestClient(app)


@pytest.fixture(scope="function", autouse=True)
def clean_rbac_data():
    def do_cleanup():
        db = SessionLocal()
        try:
            db.query(models.AuditLog).delete()
            db.query(models.Configuration).delete()
            db.query(models.MonitoredFolder).delete()
            db.query(models.User).filter(
                models.User.username.in_(["rbac_admin", "rbac_operator"])
            ).delete()
            db.commit()
        finally:
            db.close()

    do_cleanup()
    yield
    do_cleanup()


def get_tokens():
    """Seed an admin + operator in the DB and return their JWT tokens."""
    db = SessionLocal()
    db.add(models.User(
        username="rbac_admin",
        email="rbac_admin@rbac-example.com",
        password_hash=hash_password("AdminPass123!"),
        role="admin",
        is_active=True
    ))
    db.add(models.User(
        username="rbac_operator",
        email="rbac_operator@rbac-example.com",
        password_hash=hash_password("OperatorPass123!"),
        role="operator",
        is_active=True
    ))
    db.commit()
    db.close()

    admin_token = client.post("/auth/login", data={"username": "rbac_admin@rbac-example.com", "password": "AdminPass123!"}).json()["access_token"]
    op_token = client.post("/auth/login", data={"username": "rbac_operator@rbac-example.com", "password": "OperatorPass123!"}).json()["access_token"]
    return admin_token, op_token


# ===================================================================
# 1. Shared endpoints reachable by BOTH roles
# ===================================================================
def test_operator_endpoints_accessible_by_both_roles():
    admin_token, op_token = get_tokens()

    # /dashboard/stats is accessible to both
    op_res = client.get("/dashboard/stats", headers={"Authorization": f"Bearer {op_token}"})
    assert op_res.status_code == 200
    assert "total_incidents" in op_res.json()

    admin_res = client.get("/dashboard/stats", headers={"Authorization": f"Bearer {admin_token}"})
    assert admin_res.status_code == 200

    # Unauthenticated -> 401
    anon_res = client.get("/dashboard/stats")
    assert anon_res.status_code == 401


# ===================================================================
# 2. Admin endpoints return 403 for operators
# ===================================================================
def test_admin_endpoints_return_403_for_operators():
    _, op_token = get_tokens()
    h = {"Authorization": f"Bearer {op_token}"}

    assert client.get("/admin/users", headers=h).status_code == 403
    assert client.get("/admin/audit-logs", headers=h).status_code == 403
    assert client.patch(
        "/admin/configurations/entropy_threshold", headers=h,
        json={"value": 7.5, "is_enabled": True}
    ).status_code == 403


# ===================================================================
# 3. Denied access attempt is recorded in audit_logs
# ===================================================================
def test_record_denied_administrative_access_attempt_in_audit_log():
    _, op_token = get_tokens()

    client.get("/admin/audit-logs", headers={"Authorization": f"Bearer {op_token}"})

    db = SessionLocal()
    log = db.query(models.AuditLog).filter(models.AuditLog.action == "ADMIN_ACCESS_DENIED").first()
    assert log is not None
    assert log.status == "failure"
    assert log.details["username"] == "rbac_operator"
    db.close()


# ===================================================================
# 4. Admin can reach all admin endpoints
# ===================================================================
def test_admin_endpoints_accessible_by_admin():
    admin_token, _ = get_tokens()
    h = {"Authorization": f"Bearer {admin_token}"}

    # List users
    assert client.get("/admin/users", headers=h).status_code == 200

    # Update configuration via PATCH
    res = client.patch(
        "/admin/configurations/entropy_threshold",
        headers=h,
        json={"value": 7.8, "is_enabled": True}
    )
    assert res.status_code == 200
    assert res.json()["value"] == 7.8

    # View audit logs
    assert client.get("/admin/audit-logs", headers=h).status_code == 200
