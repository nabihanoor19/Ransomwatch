import pytest
import sys
from datetime import timedelta
from pathlib import Path
from fastapi.testclient import TestClient

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from main import app
from database import SessionLocal
import models
from auth import hash_password, create_access_token

client = TestClient(app)

@pytest.fixture(scope="function", autouse=True)
def clean_test_users():
    """Cleans up test users before and after each test run for total test isolation."""
    def do_cleanup():
        db = SessionLocal()
        try:
            db.query(models.AuditLog).delete()
            db.query(models.User).filter(
                (models.User.email.like("%@example.com")) |
                (models.User.username.like("%test%")) |
                (models.User.username.like("%user%")) |
                (models.User.username.in_(["hacker_admin", "inactive_operator", "superadmin", "logout_user"]))
            ).delete()
            db.commit()
        finally:
            db.close()

    do_cleanup()
    yield
    do_cleanup()


# ===================================================================
# SCENARIO 1: Correct credentials -> Login successful
# ===================================================================
def test_scenario_1_correct_credentials_login_successful():
    reg_res = client.post(
        "/auth/register",
        json={
            "username": "valid_operator",
            "email": "operator@example.com",
            "password": "Password123!"
        }
    )
    assert reg_res.status_code == 201

    login_res = client.post(
        "/auth/login",
        data={
            "username": "operator@example.com",
            "password": "Password123!"
        }
    )
    assert login_res.status_code == 200
    data = login_res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert len(data["access_token"]) > 20


# ===================================================================
# SCENARIO 2: Wrong password -> 401 Unauthorized
# ===================================================================
def test_scenario_2_wrong_password_returns_401():
    client.post(
        "/auth/register",
        json={
            "username": "wrong_pwd_user",
            "email": "operator@example.com",
            "password": "CorrectPassword123!"
        }
    )

    login_res = client.post(
        "/auth/login",
        data={
            "username": "operator@example.com",
            "password": "IncorrectPassword!"
        }
    )
    assert login_res.status_code == 401
    assert login_res.json()["detail"] == "Incorrect username/email or password"


# ===================================================================
# SCENARIO 3: Unknown email -> Generic authentication failure
# ===================================================================
def test_scenario_3_unknown_email_generic_failure():
    login_res = client.post(
        "/auth/login",
        data={
            "username": "does_not_exist@example.com",
            "password": "AnyPassword123!"
        }
    )
    assert login_res.status_code == 401
    assert login_res.json()["detail"] == "Incorrect username/email or password"


# ===================================================================
# SCENARIO 4: Expired token -> Access denied
# ===================================================================
def test_scenario_4_expired_token_access_denied():
    reg_res = client.post(
        "/auth/register",
        json={
            "username": "expired_token_user",
            "email": "operator@example.com",
            "password": "Password123!"
        }
    )
    user_id = reg_res.json()["id"]

    expired_token = create_access_token(
        data={"sub": str(user_id)},
        expires_delta=timedelta(minutes=-10)
    )

    res = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"}
    )
    assert res.status_code == 401
    assert "Could not validate credentials" in res.json()["detail"]


# ===================================================================
# SCENARIO 5: Missing token -> Access denied
# ===================================================================
def test_scenario_5_missing_token_access_denied():
    res = client.get("/auth/me")
    assert res.status_code == 401
    assert res.json()["detail"] == "Not authenticated"


# ===================================================================
# SCENARIO 6: Inactive user -> Access denied
# ===================================================================
def test_scenario_6_inactive_user_access_denied():
    db = SessionLocal()
    inactive_user = models.User(
        username="inactive_operator",
        email="inactive@example.com",
        password_hash=hash_password("Password123!"),
        role="operator",
        is_active=False
    )
    db.add(inactive_user)
    db.commit()
    db.refresh(inactive_user)
    user_id = inactive_user.id
    db.close()

    login_res = client.post(
        "/auth/login",
        data={
            "username": "inactive@example.com",
            "password": "Password123!"
        }
    )
    assert login_res.status_code == 400
    assert "Account is inactive" in login_res.json()["detail"]

    token = create_access_token(data={"sub": str(user_id)})
    me_res = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert me_res.status_code == 400
    assert "Inactive user account" in me_res.json()["detail"]


# ===================================================================
# SCENARIO 7: Public attempt to create admin -> Rejected
# ===================================================================
def test_scenario_7_public_attempt_to_create_admin_rejected():
    res = client.post(
        "/auth/register",
        json={
            "username": "hacker_admin",
            "email": "hacker@example.com",
            "password": "Password123!",
            "role": "admin"
        }
    )
    assert res.status_code == 201
    data = res.json()
    assert data["role"] == "operator"

    db = SessionLocal()
    db_user = db.query(models.User).filter(models.User.username == "hacker_admin").first()
    assert db_user.role == "operator"
    db.close()

    login_res = client.post(
        "/auth/login",
        data={"username": "hacker@example.com", "password": "Password123!"}
    )
    token = login_res.json()["access_token"]
    admin_check = client.get(
        "/auth/admin-only",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert admin_check.status_code == 403
    assert "Administrator privileges required" in admin_check.json()["detail"]


# ===================================================================
# SCENARIO 8: Logout & Invalidation strategy
# ===================================================================
def test_scenario_8_logout_and_session_invalidation():
    # 1. Register & login
    client.post(
        "/auth/register",
        json={
            "username": "logout_user",
            "email": "logout@example.com",
            "password": "Password123!"
        }
    )
    login_res = client.post(
        "/auth/login",
        data={"username": "logout@example.com", "password": "Password123!"}
    )
    token = login_res.json()["access_token"]

    # 2. Call logout endpoint
    logout_res = client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert logout_res.status_code == 200
    assert "Successfully logged out" in logout_res.json()["message"]

    # 3. Verify audit log recorded USER_LOGOUT
    db = SessionLocal()
    audit_entry = db.query(models.AuditLog).filter(models.AuditLog.action == "USER_LOGOUT").first()
    assert audit_entry is not None
    assert audit_entry.status == "success"
    db.close()
