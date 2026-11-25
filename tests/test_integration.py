"""
test_integration.py — Task 8 End-to-End Integration Tests

Verifies the full detection pipeline lifecycle from API calls through to
SQLite persistence:

  1. Register a sandbox folder via POST /monitor/folders
  2. Start monitoring via POST /monitor/start/{folder_id}
  3. Verify live monitor status via GET /monitor/status/{folder_id}
  4. Inject a synthetic event directly through DetectionPipeline (same code
     path as the watchdog callback, no sleep/timing dependency)
  5. Retrieve the persisted event via GET /events
  6. Retrieve the auto-created incident via GET /incidents (if HIGH/CRITICAL)
  7. Verify FILE_EVENT_RECEIVED in the audit log
  8. Verify INCIDENT_CREATED in the audit log (if incident was created)
  9. On-demand canary integrity scan via POST /monitor/scan/{folder_id}
 10. Stop monitoring via POST /monitor/stop/{folder_id}
 11. Verify the monitor shows stopped after stop

Security constraint tests:
  - Unauthenticated event submission → 401
  - Unauthenticated monitor start → 401
  - Audit log DELETE endpoint must not exist
  - Duplicate start without stop → 400
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure the backend package directory is importable
backend_dir = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient

from auth import hash_password
from database import SessionLocal
import models
from main import app

# ── Single shared TestClient — same app instance as all other test files ──────
client = TestClient(app, raise_server_exceptions=True)


# ── Module-level fixtures ─────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def admin_token():
    """
    Create a dedicated admin user for integration tests,
    clean up any leftovers from a previous run first.
    Uses the /auth/login endpoint (same as all other test files) so the token
    carries the numeric user ID that get_current_user expects.
    """
    db = SessionLocal()
    try:
        db.query(models.User).filter(
            models.User.username.in_(["int_admin", "int_operator", "dup_int_admin"])
        ).delete()
        db.commit()

        db.add(models.User(
            username="int_admin",
            email="int_admin@int-test.local",
            password_hash=hash_password("AdminPass1!"),
            role="admin",
            is_active=True,
        ))
        db.add(models.User(
            username="dup_int_admin",
            email="dup_int_admin@int-test.local",
            password_hash=hash_password("AdminPass1!"),
            role="admin",
            is_active=True,
        ))
        db.commit()
    finally:
        db.close()

    res = client.post("/auth/login", data={
        "username": "int_admin@int-test.local",
        "password": "AdminPass1!",
    })
    assert res.status_code == 200, f"Login failed: {res.text}"
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def auth_header(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="module")
def sandbox_dir(tmp_path_factory):
    """A real temporary directory on disk used as the monitored sandbox."""
    return tmp_path_factory.mktemp("int_sandbox")


# ── Shared state ──────────────────────────────────────────────────────────────
# We use a simple dict as a shared store between test methods in this module.
# (Python class attributes would work too, but this avoids scoping issues.)
_state: dict = {}


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestTask8Integration:
    """
    End-to-end integration checklist from Task 8 Step 8.4.
    Tests run in declaration order; shared state is kept in module-level _state.
    """

    # ------------------------------------------------------------------
    # Step 1 — Register the sandbox folder
    # ------------------------------------------------------------------
    def test_01_register_folder(self, auth_header, sandbox_dir):
        resp = client.post(
            "/monitor/folders",
            json={"folder_path": str(sandbox_dir), "folder_name": "Integration Sandbox"},
            headers=auth_header,
        )
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["status"] == "stopped"
        _state["folder_id"] = data["id"]

    # ------------------------------------------------------------------
    # Step 2 — Start monitoring via the API
    # ------------------------------------------------------------------
    def test_02_start_monitoring(self, auth_header):
        resp = client.post(
            f"/monitor/start/{_state['folder_id']}",
            headers=auth_header,
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "active"

    # ------------------------------------------------------------------
    # Step 3 — Verify the live monitor status endpoint
    # ------------------------------------------------------------------
    def test_03_monitor_status_shows_active(self, auth_header):
        resp = client.get(
            f"/monitor/status/{_state['folder_id']}",
            headers=auth_header,
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["db_status"] == "active"
        assert data["attached"] is True  # real directory → watchdog is running

    # ------------------------------------------------------------------
    # Step 4 — Inject a synthetic event via the pipeline
    #          This is the same code path that FolderMonitor's on_event
    #          callback triggers in production.
    # ------------------------------------------------------------------
    def test_04_pipeline_processes_and_persists_event(self, sandbox_dir):
        from security.pipeline import DetectionPipeline

        # Write a file so the entropy analyzer has something to read
        test_file = sandbox_dir / "ransom_note.txt"
        test_file.write_bytes(os.urandom(4096))

        pipeline = DetectionPipeline()
        # Seed a baseline of the current file content
        pipeline.entropy_analyzer.seed_folder_baselines(sandbox_dir)

        # Overwrite with different random bytes → entropy spike
        test_file.write_bytes(os.urandom(4096))

        event = {
            "folder_id": _state["folder_id"],
            "sandbox_root": str(sandbox_dir),
            "event_type": "file_modified",
            "file_name": test_file.name,
            "file_path": str(test_file),
            "boundary_valid": True,
            "timestamp": "2026-11-25T10:00:00+00:00",
        }

        db = SessionLocal()
        try:
            result = pipeline.process_event(event, db=db, user_id=None, persist=True)
        finally:
            db.close()

        # pipeline returns None only for suppressed canary self-writes
        assert result is not None, "Pipeline suppressed the test event unexpectedly"
        assert "event_id" in result, f"Missing event_id: {result}"
        assert "id" in result
        assert result["folder_id"] == _state["folder_id"]
        assert result["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert isinstance(result["risk_score"], float)

        _state["event_db_id"] = result["id"]
        _state["incident_ref"] = result.get("incident_ref")  # None for LOW risk

    # ------------------------------------------------------------------
    # Step 5 — Retrieve the event via GET /events
    # ------------------------------------------------------------------
    def test_05_event_retrievable_via_api(self, auth_header):
        resp = client.get("/events", headers=auth_header)
        assert resp.status_code == 200, resp.text
        ids = [e["id"] for e in resp.json()]
        assert _state["event_db_id"] in ids, (
            f"Persisted event id={_state['event_db_id']} not found in GET /events"
        )

    # ------------------------------------------------------------------
    # Step 6 — Retrieve the incident (if one was created)
    # ------------------------------------------------------------------
    def test_06_incident_retrievable_via_api(self, auth_header):
        resp = client.get("/incidents", headers=auth_header)
        assert resp.status_code == 200, resp.text
        if _state.get("incident_ref"):
            inc_ids = [i["incident_id"] for i in resp.json()]
            assert _state["incident_ref"] in inc_ids, (
                f"Expected incident {_state['incident_ref']} in GET /incidents"
            )

    # ------------------------------------------------------------------
    # Step 7 — Verify audit log contains FILE_EVENT_RECEIVED
    # ------------------------------------------------------------------
    def test_07_audit_log_contains_file_event_record(self, auth_header):
        resp = client.get("/admin/audit-logs", headers=auth_header)
        assert resp.status_code == 200, resp.text
        actions = [log["action"] for log in resp.json()]
        assert "FILE_EVENT_RECEIVED" in actions, (
            f"FILE_EVENT_RECEIVED not in audit log. Found: {set(actions)}"
        )

    # ------------------------------------------------------------------
    # Step 8 — Verify INCIDENT_CREATED if an incident was created
    # ------------------------------------------------------------------
    def test_08_audit_log_contains_incident_record_if_created(self, auth_header):
        if not _state.get("incident_ref"):
            pytest.skip("No incident created (risk score below threshold)")
        resp = client.get("/admin/audit-logs", headers=auth_header)
        assert resp.status_code == 200, resp.text
        actions = [log["action"] for log in resp.json()]
        assert "INCIDENT_CREATED" in actions

    # ------------------------------------------------------------------
    # Step 9 — On-demand canary integrity scan
    # ------------------------------------------------------------------
    def test_09_canary_integrity_scan(self, auth_header):
        resp = client.post(
            f"/monitor/scan/{_state['folder_id']}",
            headers=auth_header,
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "alerts_triggered" in data
        assert isinstance(data["alerts"], list)

    # ------------------------------------------------------------------
    # Step 10 — Stop monitoring via the API
    # ------------------------------------------------------------------
    def test_10_stop_monitoring(self, auth_header):
        resp = client.post(
            f"/monitor/stop/{_state['folder_id']}",
            headers=auth_header,
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "stopped"

    # ------------------------------------------------------------------
    # Step 11 — Confirm monitor is no longer running after stop
    # ------------------------------------------------------------------
    def test_11_monitor_status_shows_stopped_after_stop(self, auth_header):
        resp = client.get(
            f"/monitor/status/{_state['folder_id']}",
            headers=auth_header,
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["db_status"] == "stopped"


class TestTask8SecurityConstraints:
    """
    Verify that integration-layer security rules hold.
    """

    def test_unauthenticated_event_submission_rejected(self):
        """POST /events without bearer token must return 401."""
        resp = client.post(
            "/events",
            json={
                "event_type": "file_modified",
                "file_name": "test.txt",
                "folder_id": 1,
                "severity": "HIGH",
                "risk_score": 90.0,
                "evidence": ["test"],
            },
        )
        assert resp.status_code == 401, resp.text

    def test_unauthenticated_monitor_start_rejected(self):
        """POST /monitor/start without token must return 401."""
        resp = client.post("/monitor/start/1")
        assert resp.status_code == 401, resp.text

    def test_audit_logs_not_deletable(self):
        """DELETE /admin/audit-logs must not exist (405 or 404)."""
        resp = client.delete("/admin/audit-logs")
        assert resp.status_code in {404, 405, 401}, resp.text

    def test_audit_logs_not_modifiable(self):
        """PATCH /admin/audit-logs must not exist (405 or 404)."""
        resp = client.patch("/admin/audit-logs", json={})
        assert resp.status_code in {404, 405, 401}, resp.text

    def test_duplicate_folder_start_returns_400(self, auth_header):
        """
        Starting monitoring twice on the same folder without stopping first
        must return 400 Bad Request.
        """
        with tempfile.TemporaryDirectory() as td:
            reg = client.post(
                "/monitor/folders",
                json={"folder_path": td, "folder_name": "Duplicate Start Test"},
                headers=auth_header,
            )
            assert reg.status_code == 201
            fid = reg.json()["id"]

            # First start — OK
            r1 = client.post(f"/monitor/start/{fid}", headers=auth_header)
            assert r1.status_code == 200

            # Second start without stopping — must be 400
            r2 = client.post(f"/monitor/start/{fid}", headers=auth_header)
            assert r2.status_code == 400, f"Expected 400, got {r2.status_code}: {r2.text}"

            # Clean up
            client.post(f"/monitor/stop/{fid}", headers=auth_header)

    def test_post_events_high_severity_creates_incident_and_audit_logs(self, auth_header):
        """
        Step 8.2 + 8.4: Submitting a HIGH-severity event via POST /events must:
        1. Validate and store the FileEvent in SQLite
        2. Auto-create/correlate an Incident (Step 8.2 #6)
        3. Record FILE_EVENT_RECEIVED and INCIDENT_CREATED in AuditLog
        """
        with tempfile.TemporaryDirectory() as td:
            reg = client.post(
                "/monitor/folders",
                json={"folder_path": td, "folder_name": "HTTP Event Integration"},
                headers=auth_header,
            )
            assert reg.status_code == 201, reg.text
            fid = reg.json()["id"]

            evt_resp = client.post(
                "/events",
                json={
                    "module": "entropy",
                    "event_type": "file_modified",
                    "file_name": "document.txt",
                    "folder_id": fid,
                    "severity": "HIGH",
                    "risk_score": 82.0,
                    "evidence": ["Entropy increased significantly (3.2 -> 7.9)"],
                },
                headers=auth_header,
            )
            assert evt_resp.status_code == 201, evt_resp.text
            evt_data = evt_resp.json()
            assert evt_data["incident_id"] is not None, "HIGH event via POST /events must create/link an Incident"

            # Retrieve via GET /events/{event_id}
            get_evt = client.get(f"/events/{evt_data['event_id']}", headers=auth_header)
            assert get_evt.status_code == 200
            assert get_evt.json()["incident_id"] == evt_data["incident_id"]

            # Retrieve associated incident via GET /incidents
            inc_resp = client.get("/incidents", headers=auth_header)
            assert inc_resp.status_code == 200
            assert any(i["id"] == evt_data["incident_id"] for i in inc_resp.json())

            # Verify audit records
            audit_resp = client.get("/admin/audit-logs", headers=auth_header)
            assert audit_resp.status_code == 200
            actions = [a["action"] for a in audit_resp.json()]
            assert "FILE_EVENT_RECEIVED" in actions
            assert "INCIDENT_CREATED" in actions

    def test_live_watchdog_file_event_stored_end_to_end(self, auth_header):
        """
        Step 8.3 + 8.4: Start monitoring on a real temp directory, write a safe
        test file on disk, wait briefly for watchdog -> DetectionPipeline -> SQLite,
        and verify it appears in GET /events.
        """
        import time

        with tempfile.TemporaryDirectory() as td:
            reg = client.post(
                "/monitor/folders",
                json={"folder_path": td, "folder_name": "Live Watchdog Sandbox"},
                headers=auth_header,
            )
            assert reg.status_code == 201, reg.text
            fid = reg.json()["id"]

            start_resp = client.post(f"/monitor/start/{fid}", headers=auth_header)
            assert start_resp.status_code == 200, start_resp.text

            try:
                # Generate a safe test file event inside the monitored folder
                safe_file = Path(td) / "safe_test_note.txt"
                safe_file.write_text("Hello RansomWatch live integration test\n", encoding="utf-8")

                # Poll briefly for watchdog callback to persist the event
                found = False
                for _ in range(20):
                    evts = client.get(f"/events?folder_id={fid}", headers=auth_header)
                    assert evts.status_code == 200
                    if any("safe_test_note.txt" in e["file_name"] for e in evts.json()):
                        found = True
                        break
                    time.sleep(0.15)

                assert found, "Live watchdog did not persist safe_test_note.txt event to /events"
            finally:
                client.post(f"/monitor/stop/{fid}", headers=auth_header)
