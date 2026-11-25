"""
test_task9.py — Task 9 Dashboard Data, Incident Filtering & Sanitized Report Tests
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from auth import hash_password
from database import SessionLocal
import models
from main import app

client = TestClient(app)


@pytest.fixture(scope="module")
def auth_header():
    db = SessionLocal()
    try:
        db.query(models.User).filter(models.User.username == "task9_admin").delete()
        db.commit()
        db.add(models.User(
            username="task9_admin",
            email="task9_admin@test.local",
            password_hash=hash_password("Task9Pass1!"),
            role="admin",
            is_active=True,
        ))
        db.commit()
    finally:
        db.close()

    res = client.post("/auth/login", data={
        "username": "task9_admin@test.local",
        "password": "Task9Pass1!",
    })
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def test_dashboard_stats_includes_all_task9_fields(auth_header):
    res = client.get("/dashboard/stats", headers=auth_header)
    assert res.status_code == 200, res.text
    data = res.json()
    for field in [
        "total_events",
        "suspicious_events",
        "total_incidents",
        "critical_incidents",
        "monitored_folders",
        "monitoring_status",
    ]:
        assert field in data, f"Missing Task 9 field: {field}"
    assert data["monitoring_status"] in {"active", "stopped"}


def test_dashboard_recent_events_chronological(auth_header):
    res = client.get("/dashboard/recent-events?limit=5", headers=auth_header)
    assert res.status_code == 200, res.text
    items = res.json()
    assert len(items) <= 5
    timestamps = [item["timestamp"] for item in items]
    assert timestamps == sorted(timestamps, reverse=True)


def test_incidents_filters_severity_status_module_and_date(auth_header):
    # Create a folder + HIGH entropy event so an incident is linked to module='entropy'
    folder_res = client.post(
        "/monitor/folders",
        json={"folder_path": "/tmp/task9_filter_box", "folder_name": "Task9 Filter Box"},
        headers=auth_header,
    )
    if folder_res.status_code == 400:
        folders = client.get("/monitor/folders", headers=auth_header).json()
        fid = next(f["id"] for f in folders if f["folder_path"] == "/tmp/task9_filter_box")
    else:
        assert folder_res.status_code == 201
        fid = folder_res.json()["id"]

    ev_res = client.post(
        "/events",
        json={
            "module": "entropy",
            "event_type": "file_modified",
            "file_name": "secret_leak_test.docx",
            "folder_id": fid,
            "severity": "CRITICAL",
            "risk_score": 96.0,
            "evidence": ["password=supersecret123", "=CMD('calc')"],
        },
        headers=auth_header,
    )
    assert ev_res.status_code == 201, ev_res.text

    # Filter by severity=CRITICAL
    r_sev = client.get("/incidents?severity=CRITICAL", headers=auth_header)
    assert r_sev.status_code == 200
    assert all(i["severity"] == "CRITICAL" for i in r_sev.json())

    # Filter by status=open
    r_status = client.get("/incidents?status=open", headers=auth_header)
    assert r_status.status_code == 200
    assert all(i["status"] == "open" for i in r_status.json())

    # Filter by module=entropy
    r_mod = client.get("/incidents?module=entropy", headers=auth_header)
    assert r_mod.status_code == 200
    assert len(r_mod.json()) >= 1

    # Filter by date range (today - 1 day to today + 1 day)
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
    end = (now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
    r_date = client.get(f"/incidents?start_date={start}&end_date={end}", headers=auth_header)
    assert r_date.status_code == 200
    assert len(r_date.json()) >= 1


def test_report_export_has_task9_fields_and_is_sanitized(auth_header):
    # JSON report check
    json_res = client.get("/reports/export?format=json", headers=auth_header)
    assert json_res.status_code == 200, json_res.text
    incidents = json_res.json()["incidents"]
    assert len(incidents) >= 1

    sample = incidents[0]
    for required_key in [
        "incident_id",
        "timestamp",
        "severity",
        "risk_score",
        "detection_reason",
        "supporting_evidence",
        "recommended_action",
        "status",
    ]:
        assert required_key in sample, f"Missing report field: {required_key}"

    # Verify secret string from earlier test was redacted
    full_json_text = json_res.text
    assert "supersecret123" not in full_json_text
    assert "[REDACTED]" in full_json_text

    # CSV report check (headers + formula injection neutralization)
    csv_res = client.get("/reports/export?format=csv", headers=auth_header)
    assert csv_res.status_code == 200, csv_res.text
    csv_text = csv_res.content.decode("utf-8")
    assert "recommended_action" in csv_text
    assert "supporting_evidence" in csv_text
    assert "supersecret123" not in csv_text
    assert "'=CMD" in csv_text or "[REDACTED]" in csv_text
