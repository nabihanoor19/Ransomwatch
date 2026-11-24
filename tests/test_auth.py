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
def clean_test_users():
    """Cleans up test users before and after each test run for total isolation."""
    def do_cleanup():
        db = SessionLocal()
        try:
            db.query(models.AuditLog).delete()
            db.query(models.User).filter(
                (models.User.email.like("%@example.com")) |
                (models.User.username.in_([
                    "auth_test_operator",
                    "test_operator",
                    "dup_user_1",
                    "dup_user_2",
                    "login_user",
                    "wrong_pwd_user",
                    "me_user",
                    "operator_test",
                    "superadmin"
                ]))
            ).delete()
            db.commit()
        finally:
            db.close()

    do_cleanup()
    yield
    do_cleanup()


def test_register_user_success():
    response = client.post(
        "/auth/register",
        json={
            "username": "auth_test_operator",
            "email": "operator@example.com",
            "password": "Password123!"
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "auth_test_operator"
    assert data["email"] == "operator@example.com"
    assert data["role"] == "operator"
    assert "password" not in data
    assert "password_hash" not in data


def test_register_duplicate_email():
    payload = {
        "username": "dup_user_1",
        "email": "dup@example.com",
        "password": "Password123!"
    }
    res1 = client.post("/auth/register", json=payload)
    assert res1.status_code == 201

    payload2 = {
        "username": "dup_user_2",
        "email": "dup@example.com",
        "password": "Password123!"
    }
    res2 = client.post("/auth/register", json=payload2)
    assert res2.status_code == 400
    assert "Email already registered" in res2.json()["detail"]


def test_login_success_and_jwt():
    # Register first
    client.post(
        "/auth/register",
        json={
            "username": "login_user",
            "email": "operator@example.com",
            "password": "Password123!"
        }
    )

    # Login with credentials
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


def test_login_invalid_password():
    client.post(
        "/auth/register",
        json={
            "username": "wrong_pwd_user",
            "email": "operator@example.com",
            "password": "CorrectPassword123"
        }
    )

    login_res = client.post(
        "/auth/login",
        data={
            "username": "operator@example.com",
            "password": "WrongPassword!"
        }
    )
    assert login_res.status_code == 401


def test_protected_me_endpoint():
    # 1. Without token -> 401
    res = client.get("/auth/me")
    assert res.status_code == 401

    # 2. Register & Login
    client.post(
        "/auth/register",
        json={
            "username": "me_user",
            "email": "operator@example.com",
            "password": "Password123!"
        }
    )
    login_res = client.post(
        "/auth/login",
        data={"username": "operator@example.com", "password": "Password123!"}
    )
    token = login_res.json()["access_token"]

    # 3. With token -> 200
    me_res = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert me_res.status_code == 200
    assert me_res.json()["username"] == "me_user"


def test_rbac_admin_vs_operator():
    # Create operator
    client.post(
        "/auth/register",
        json={"username": "operator_test", "email": "operator@example.com", "password": "Password123!"}
    )
    op_login = client.post("/auth/login", data={"username": "operator@example.com", "password": "Password123!"})
    op_token = op_login.json()["access_token"]

    # Operator accessing admin endpoint -> 403 Forbidden
    op_res = client.get("/auth/admin-only", headers={"Authorization": f"Bearer {op_token}"})
    assert op_res.status_code == 403

    # Create admin in database directly
    db = SessionLocal()
    admin_user = models.User(
        username="superadmin",
        email="admin@example.com",
        password_hash=hash_password("AdminPass123!"),
        role="admin",
        is_active=True
    )
    db.add(admin_user)
    db.commit()
    db.close()

    # Admin login & access admin endpoint -> 200 OK
    admin_login = client.post("/auth/login", data={"username": "admin@example.com", "password": "AdminPass123!"})
    admin_token = admin_login.json()["access_token"]

    admin_res = client.get("/auth/admin-only", headers={"Authorization": f"Bearer {admin_token}"})
    assert admin_res.status_code == 200
    assert "elevated access" in admin_res.json()["message"]
