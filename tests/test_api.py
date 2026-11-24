"""
test_api.py — End-to-end tests for all Task 6 API endpoints.
Covers: Monitor, Events, Incidents, Dashboard, Reports, Admin.
"""
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


@pytest.fixture(scope="module")
def admin_token():
    """Create a fresh admin user and return their JWT once for the whole module."""
    db = SessionLocal()
    db.query(models.AuditLog).delete()
    db.query(models.FileEvent).delete()
    db.query(models.Incident).delete()
    db.query(models.MonitoredFolder).delete()
    db.query(models.Configuration).delete()
    db.query(models.User).filter(
        models.User.username.in_(["api_test_admin", "patch_target"])
    ).delete()
    db.commit()

    db.add(models.User(
        username="api_test_admin",
        email="api_admin@apitest-example.com",
        password_hash=hash_password("AdminPass123!"),
        role="admin",
        is_active=True
    ))
    db.commit()
    db.close()

    res = client.post("/auth/login", data={
        "username": "api_admin@apitest-example.com",
        "password": "AdminPass123!"
    })
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def auth_header(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


# ============================================================
# API 2 — FOLDER MONITORING
# ============================================================
class TestMonitorAPI:

    def test_register_folder(self, auth_header):
        res = client.post("/monitor/folders", headers=auth_header, json={
            "folder_path": "D:/test/sandbox",
            "folder_name": "Sandbox"
        })
        assert res.status_code == 201
        data = res.json()
        assert data["folder_path"] == "D:/test/sandbox"
        assert data["status"] == "stopped"

    def test_register_duplicate_folder_rejected(self, auth_header):
        client.post("/monitor/folders", headers=auth_header, json={
            "folder_path": "D:/test/unique_folder",
            "folder_name": "Unique"
        })
        res = client.post("/monitor/folders", headers=auth_header, json={
            "folder_path": "D:/test/unique_folder",
            "folder_name": "Unique"
        })
        assert res.status_code == 400
        assert "already registered" in res.json()["detail"]

    def test_list_folders(self, auth_header):
        res = client.get("/monitor/folders", headers=auth_header)
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_start_and_stop_monitoring(self, auth_header):
        reg = client.post("/monitor/folders", headers=auth_header, json={
            "folder_path": "D:/test/start_stop_folder",
            "folder_name": "StartStop"
        })
        folder_id = reg.json()["id"]

        start = client.post(f"/monitor/start/{folder_id}", headers=auth_header)
        assert start.status_code == 200
        assert start.json()["status"] == "active"

        stop = client.post(f"/monitor/stop/{folder_id}", headers=auth_header)
        assert stop.status_code == 200
        assert stop.json()["status"] == "stopped"

    def test_start_nonexistent_folder_returns_404(self, auth_header):
        res = client.post("/monitor/start/999999", headers=auth_header)
        assert res.status_code == 404


# ============================================================
# API 3 — FILE EVENTS
# ============================================================
class TestEventsAPI:

    @pytest.fixture(scope="class")
    def folder_id(self, auth_header):
        reg = client.post("/monitor/folders", headers=auth_header, json={
            "folder_path": "D:/test/events_folder",
            "folder_name": "EventsFolder"
        })
        return reg.json()["id"]

    def test_create_event(self, auth_header, folder_id):
        res = client.post("/events", headers=auth_header, json={
            "event_type": "file_modified",
            "file_name": "document.docx",
            "module": "entropy",
            "folder_id": folder_id,
            "severity": "HIGH",
            "risk_score": 85.0,
            "evidence": ["High entropy detected", "Rapid modification"]
        })
        assert res.status_code == 201
        data = res.json()
        assert data["severity"] == "HIGH"
        assert data["risk_score"] == 85.0
        assert len(data["event_id"]) > 0

    def test_list_events(self, auth_header):
        res = client.get("/events", headers=auth_header)
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_list_events_filter_by_severity(self, auth_header):
        res = client.get("/events?severity=HIGH", headers=auth_header)
        assert res.status_code == 200
        for ev in res.json():
            assert ev["severity"] == "HIGH"

    def test_get_single_event(self, auth_header, folder_id):
        create = client.post("/events", headers=auth_header, json={
            "event_type": "file_renamed",
            "file_name": "photo.jpg",
            "folder_id": folder_id,
            "severity": "LOW",
            "risk_score": 10.0,
            "evidence": []
        })
        event_id = create.json()["event_id"]
        res = client.get(f"/events/{event_id}", headers=auth_header)
        assert res.status_code == 200
        assert res.json()["event_id"] == event_id

    def test_get_nonexistent_event_returns_404(self, auth_header):
        res = client.get("/events/00000000-0000-0000-0000-000000000000", headers=auth_header)
        assert res.status_code == 404


# ============================================================
# API 4 — INCIDENTS
# ============================================================
class TestIncidentsAPI:

    def test_create_incident(self, auth_header):
        res = client.post("/incidents", headers=auth_header, json={
            "severity": "CRITICAL",
            "risk_score": 95.0,
            "description": "Mass file encryption detected",
            "evidence": ["900 files encrypted in 30s"]
        })
        assert res.status_code == 201
        data = res.json()
        assert data["severity"] == "CRITICAL"
        assert data["status"] == "open"
        assert data["incident_id"].startswith("INC-")

    def test_list_incidents(self, auth_header):
        res = client.get("/incidents", headers=auth_header)
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_get_incident_detail(self, auth_header):
        create = client.post("/incidents", headers=auth_header, json={
            "severity": "HIGH",
            "risk_score": 75.0,
            "description": "Canary file deleted",
            "evidence": ["Canary trigger"]
        })
        inc_id = create.json()["incident_id"]
        res = client.get(f"/incidents/{inc_id}", headers=auth_header)
        assert res.status_code == 200
        assert res.json()["incident_id"] == inc_id

    def test_update_incident_status(self, auth_header):
        create = client.post("/incidents", headers=auth_header, json={
            "severity": "MEDIUM",
            "risk_score": 55.0,
            "description": "Suspicious rename pattern",
            "evidence": []
        })
        inc_id = create.json()["incident_id"]

        # open -> investigating
        res1 = client.patch(f"/incidents/{inc_id}", headers=auth_header, json={"status": "investigating"})
        assert res1.status_code == 200
        assert res1.json()["status"] == "investigating"

        # investigating -> resolved
        res2 = client.patch(f"/incidents/{inc_id}", headers=auth_header, json={"status": "resolved"})
        assert res2.status_code == 200
        assert res2.json()["status"] == "resolved"

    def test_get_nonexistent_incident_returns_404(self, auth_header):
        res = client.get("/incidents/INC-ZZZZZZZZ", headers=auth_header)
        assert res.status_code == 404


# ============================================================
# API 5 — DASHBOARD
# ============================================================
class TestDashboardAPI:

    def test_dashboard_stats(self, auth_header):
        res = client.get("/dashboard/stats", headers=auth_header)
        assert res.status_code == 200
        data = res.json()
        assert "total_incidents" in data
        assert "total_events" in data
        assert "open_incidents" in data

    def test_recent_events(self, auth_header):
        res = client.get("/dashboard/recent-events", headers=auth_header)
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_severity_breakdown(self, auth_header):
        res = client.get("/dashboard/severity", headers=auth_header)
        assert res.status_code == 200
        data = res.json()
        assert "LOW" in data
        assert "CRITICAL" in data

    def test_dashboard_requires_auth(self):
        res = client.get("/dashboard/stats")
        assert res.status_code == 401


# ============================================================
# API 6 — ADMINISTRATION
# ============================================================
class TestAdminAPI:

    def test_list_users(self, auth_header):
        res = client.get("/admin/users", headers=auth_header)
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_patch_user_role_and_status(self, auth_header):
        db = SessionLocal()
        new_user = models.User(
            username="patch_target",
            email="patch@apitest-example.com",
            password_hash=hash_password("Test1234!"),
            role="operator",
            is_active=True
        )
        db.add(new_user)
        db.commit()
        user_id = new_user.id
        db.close()

        res = client.patch(f"/admin/users/{user_id}", headers=auth_header, json={"is_active": False})
        assert res.status_code == 200
        assert res.json()["is_active"] is False

    def test_patch_configuration(self, auth_header):
        res = client.patch(
            "/admin/configurations/entropy_threshold",
            headers=auth_header,
            json={"value": 7.5, "is_enabled": True}
        )
        assert res.status_code == 200
        assert res.json()["value"] == 7.5

    def test_get_audit_logs(self, auth_header):
        res = client.get("/admin/audit-logs", headers=auth_header)
        assert res.status_code == 200
        assert isinstance(res.json(), list)
        assert len(res.json()) > 0


# ============================================================
# API 7 — REPORTS
# ============================================================
class TestReportsAPI:

    def test_export_json_report(self, auth_header):
        res = client.get("/reports/export?format=json", headers=auth_header)
        assert res.status_code == 200
        data = res.json()
        assert "report_generated_at" in data
        assert "incidents" in data
        assert "summary" in data

    def test_export_csv_report(self, auth_header):
        res = client.get("/reports/export?format=csv", headers=auth_header)
        assert res.status_code == 200
        assert "text/csv" in res.headers["content-type"]
        content = res.content.decode()
        assert "RansomWatch Security Report" in content
        assert "incident_id" in content

    def test_export_requires_auth(self):
        res = client.get("/reports/export")
        assert res.status_code == 401
