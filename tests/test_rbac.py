import pytest
import sys
from pathlib import Path
from fastapi.testclient import TestClient

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from main import app
from database import SessionLocal
import models
from auth import hash_password

client = TestClient(app)

@pytest.fixture(scope="function", autouse=True)
def clean_rbac_data():
    """Cleans up test users and audit logs before and after each test."""
    def do_cleanup():
        db = SessionLocal()
        try:
            db.query(models.AuditLog).delete()
            db.query(models.Configuration).delete()
            db.query(models.MonitoredFolder).delete()
            db.query(models.User).filter(
                (models.User.email.like("%@rbac-example.com")) |
                (models.User.username.in_(["rbac_admin", "rbac_operator"]))
            ).delete()
            db.commit()
        finally:
            db.close()

    do_cleanup()
    yield
    do_cleanup()


def get_tokens():
    """Helper to seed and return tokens for an Admin and an Operator."""
    db = SessionLocal()
    admin = models.User(
        username="rbac_admin",
        email="admin@rbac-example.com",
        password_hash=hash_password("AdminPass123!"),
        role="admin",
        is_active=True
    )
    operator = models.User(
        username="rbac_operator",
        email="operator@rbac-example.com",
        password_hash=hash_password("OperatorPass123!"),
        role="operator",
        is_active=True
    )
    db.add(admin)
    db.add(operator)
    db.commit()
    db.close()

    # Login admin
    res_admin = client.post("/auth/login", data={"username": "admin@rbac-example.com", "password": "AdminPass123!"})
    admin_token = res_admin.json()["access_token"]

    # Login operator
    res_op = client.post("/auth/login", data={"username": "operator@rbac-example.com", "password": "OperatorPass123!"})
    op_token = res_op.json()["access_token"]

    return admin_token, op_token


# ===================================================================
# 1. TEST OPERATOR ENDPOINTS PERMISSIONS (Admin: Yes, Operator: Yes)
# ===================================================================
def test_operator_endpoints_accessible_by_both_roles():
    admin_token, op_token = get_tokens()

    # Operator accessing /operator/dashboard -> 200 OK
    op_dash = client.get("/operator/dashboard", headers={"Authorization": f"Bearer {op_token}"})
    assert op_dash.status_code == 200
    assert op_dash.json()["role"] == "operator"

    # Admin accessing /operator/dashboard -> 200 OK
    admin_dash = client.get("/operator/dashboard", headers={"Authorization": f"Bearer {admin_token}"})
    assert admin_dash.status_code == 200
    assert admin_dash.json()["role"] == "admin"

    # Unauthenticated accessing /operator/dashboard -> 401 Unauthorized
    anon_dash = client.get("/operator/dashboard")
    assert anon_dash.status_code == 401


# ===================================================================
# 2. TEST ADMIN ENDPOINTS BLOCKED FOR OPERATORS (HTTP 403)
# ===================================================================
def test_admin_endpoints_return_403_for_operators():
    admin_token, op_token = get_tokens()

    # 1. Operator trying to list users (/admin/users) -> 403 Forbidden
    res1 = client.get("/admin/users", headers={"Authorization": f"Bearer {op_token}"})
    assert res1.status_code == 403
    assert "Insufficient permissions" in res1.json()["detail"]

    # 2. Operator trying to view audit logs (/admin/audit-logs) -> 403 Forbidden
    res2 = client.get("/admin/audit-logs", headers={"Authorization": f"Bearer {op_token}"})
    assert res2.status_code == 403
    assert "Insufficient permissions" in res2.json()["detail"]

    # 3. Operator trying to modify configurations (/admin/configurations) -> 403 Forbidden
    res3 = client.put(
        "/admin/configurations/entropy_threshold",
        headers={"Authorization": f"Bearer {op_token}"},
        json={"rule_name": "entropy_threshold", "value": 7.5, "is_enabled": True}
    )
    assert res3.status_code == 403
    assert "Insufficient permissions" in res3.json()["detail"]


# ===================================================================
# 3. TEST RECORDING DENIED ADMINISTRATIVE ACCESS ATTEMPTS
# ===================================================================
def test_record_denied_administrative_access_attempt_in_audit_log():
    admin_token, op_token = get_tokens()

    # Operator attempts unauthorized administrative action
    res = client.get("/admin/audit-logs", headers={"Authorization": f"Bearer {op_token}"})
    assert res.status_code == 403

    # Verify that the server recorded this violation in the audit_logs table
    db = SessionLocal()
    denied_log = db.query(models.AuditLog).filter(models.AuditLog.action == "ADMIN_ACCESS_DENIED").first()
    assert denied_log is not None
    assert denied_log.status == "failure"
    assert denied_log.details["role"] == "operator"
    assert denied_log.details["username"] == "rbac_operator"
    assert "Insufficient permissions" in denied_log.details["reason"]
    db.close()


# ===================================================================
# 4. TEST ADMIN ENDPOINTS ACCESSIBLE BY ADMIN
# ===================================================================
def test_admin_endpoints_accessible_by_admin():
    admin_token, _ = get_tokens()

    # 1. Admin listing users -> 200 OK
    res_users = client.get("/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_users.status_code == 200
    assert len(res_users.json()) >= 2

    # 2. Admin updating configuration / threshold -> 200 OK
    res_config = client.put(
        "/admin/configurations/entropy_threshold",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"rule_name": "entropy_threshold", "value": 7.8, "is_enabled": True}
    )
    assert res_config.status_code == 200
    assert res_config.json()["value"] == 7.8

    # 3. Admin viewing audit logs -> 200 OK
    res_logs = client.get("/admin/audit-logs", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_logs.status_code == 200
    assert len(res_logs.json()) >= 1
