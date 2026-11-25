"""
test_detection.py — Unit & Integration tests for Rule Engine, Anomaly Detector,
DetectionPipeline, IncidentService, and live FastAPI monitoring integration (B.4–B.6).
"""

import os
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

import models
from auth import hash_password
from database import SessionLocal
from main import app
from security.anomaly import AnomalyDetector, generate_normal_training_samples
from security.pipeline import DetectionPipeline, monitor_manager
from security.rules import RuleEngine

client = TestClient(app)


@pytest.fixture(scope="module")
def detection_auth_header():
    db = SessionLocal()
    db.query(models.AuditLog).delete()
    db.query(models.FileEvent).delete()
    db.query(models.Incident).delete()
    db.query(models.MonitoredFolder).delete()
    db.query(models.Configuration).delete()
    db.query(models.User).filter(
        models.User.username.in_(["det_admin", "det_operator"])
    ).delete()
    db.commit()

    db.add(
        models.User(
            username="det_admin",
            email="det_admin@detection-test.com",
            password_hash=hash_password("AdminPass123!"),
            role="admin",
            is_active=True,
        )
    )
    db.commit()
    db.close()

    res = client.post(
        "/auth/login",
        data={"username": "det_admin@detection-test.com", "password": "AdminPass123!"},
    )
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_rule_engine_benign_vs_ransomware_burst():
    engine = RuleEngine()
    base_t = 1000.0

    # 1. Single normal edit -> LOW
    low_res = engine.evaluate(
        folder_id=1,
        event_type="file_modified",
        file_name="notes.txt",
        entropy_result={"current_entropy": 4.2, "entropy_delta": 0.1},
        now_ts=base_t,
    )
    assert low_res["severity"] == "LOW"
    assert low_res["triggered_rules"] == []

    # 2. Rapid modifications + bulk renames + suspicious extension + high entropy -> CRITICAL
    for idx in range(5):
        engine.evaluate(
            folder_id=2,
            event_type="file_modified",
            file_name=f"file_{idx}.docx",
            entropy_result={"current_entropy": 7.9, "entropy_delta": 3.4},
            now_ts=base_t + idx * 0.2,
        )

    for idx in range(4):
        final_res = engine.evaluate(
            folder_id=2,
            event_type="file_renamed",
            file_name=f"file_{idx}.docx",
            dest_name=f"file_{idx}.docx.locked",
            entropy_result={"current_entropy": 7.95, "entropy_delta": 3.5},
            now_ts=base_t + 1.5 + idx * 0.2,
        )

    assert final_res["severity"] == "CRITICAL"
    assert final_res["risk_score"] == 100.0
    assert "rapid_modification_rule" in final_res["rule_names"]
    assert "bulk_rename_rule" in final_res["rule_names"]
    assert "suspicious_extension_rule" in final_res["rule_names"]
    assert "high_entropy_rule" in final_res["rule_names"]


def test_anomaly_detector_false_positive_and_detection_rates():
    detector = AnomalyDetector(contamination=0.03, random_state=42)

    normal_eval = generate_normal_training_samples(n_samples=100, random_state=99)
    anomalous_eval = [
        {
            "event_rate": 2.5,
            "modify_count": 12.0,
            "rename_count": 10.0,
            "delete_count": 2.0,
            "create_count": 1.0,
            "mean_entropy": 7.85,
            "max_entropy": 7.98,
            "mean_entropy_delta": 3.2,
            "suspicious_ext_ratio": 0.85,
        }
        for _ in range(25)
    ]

    metrics = detector.evaluate_false_positives(normal_eval, anomalous_eval)
    assert metrics["false_positive_rate"] <= 0.10
    assert metrics["true_positive_rate"] >= 0.90
    assert metrics["avg_latency_ms"] < 50.0

    anom_score = detector.score_window(anomalous_eval[0])
    assert anom_score["is_anomaly"] is True
    assert anom_score["risk_score"] >= 60.0
    assert len(anom_score["top_deviations"]) >= 1
    assert "IsolationForest" in anom_score["evidence"][0]


def test_detection_pipeline_with_dynamic_db_threshold_and_incident_creation(tmp_path, detection_auth_header):
    sandbox = tmp_path / "pipeline_sandbox"
    sandbox.mkdir()
    doc = sandbox / "finance.csv"
    doc.write_text("date,amount,category\n" * 40, encoding="utf-8")

    # Register folder via API
    reg = client.post(
        "/monitor/folders",
        headers=detection_auth_header,
        json={"folder_path": str(sandbox), "folder_name": "PipelineBox"},
    )
    assert reg.status_code == 201
    folder_id = reg.json()["id"]

    # Admin updates threshold configuration in SQLite
    cfg_res = client.patch(
        "/admin/configurations/entropy_threshold",
        headers=detection_auth_header,
        json={"value": 7.4, "is_enabled": True},
    )
    assert cfg_res.status_code == 200

    pipeline = DetectionPipeline()
    init_info = pipeline.initialize_folder(folder_id=folder_id, folder_path=sandbox)
    assert init_info["canaries_deployed"] == 3
    assert init_info["baselines_seeded"] >= 1

    db = SessionLocal()
    try:
        # 1. Benign modification -> LOW, no incident created
        doc.write_text("date,amount,category\n2026-11-25,100,Office\n" * 40, encoding="utf-8")
        benign_res = pipeline.process_event(
            {
                "folder_id": folder_id,
                "sandbox_root": str(sandbox),
                "event_type": "file_modified",
                "file_name": "finance.csv",
                "file_path": str(doc),
            },
            db=db,
            persist=True,
        )
        assert benign_res["severity"] == "LOW"
        assert benign_res["incident_id"] is None

        # 2. High-entropy synthetic encryption overwrite -> HIGH/CRITICAL + auto Incident
        doc.write_bytes(os.urandom(4096))
        attack_res = pipeline.process_event(
            {
                "folder_id": folder_id,
                "sandbox_root": str(sandbox),
                "event_type": "file_modified",
                "file_name": "finance.csv",
                "file_path": str(doc),
            },
            db=db,
            persist=True,
        )
        assert attack_res["severity"] in {"HIGH", "CRITICAL"}
        assert attack_res["risk_score"] >= 65.0
        assert attack_res["incident_id"] is not None
        assert attack_res["incident_ref"].startswith("INC-")

        # 3. Boundary escape rejected as CRITICAL
        outside_path = tmp_path / "outside_secret.txt"
        outside_path.write_text("secret", encoding="utf-8")
        escape_res = pipeline.process_event(
            {
                "folder_id": folder_id,
                "sandbox_root": str(sandbox),
                "event_type": "file_modified",
                "file_name": "../outside_secret.txt",
                "file_path": str(outside_path),
            },
            db=db,
            persist=True,
        )
        assert escape_res["severity"] == "CRITICAL"
        assert escape_res["risk_score"] == 100.0
    finally:
        db.close()

    # Verify results appear through Member A's APIs
    events_res = client.get(f"/events?folder_id={folder_id}", headers=detection_auth_header)
    assert events_res.status_code == 200
    assert len(events_res.json()) >= 3

    incidents_res = client.get("/incidents", headers=detection_auth_header)
    assert incidents_res.status_code == 200
    assert len(incidents_res.json()) >= 1


def test_live_monitor_api_start_canary_scan_and_stop(tmp_path, detection_auth_header):
    sandbox = tmp_path / "live_api_sandbox"
    sandbox.mkdir()
    (sandbox / "notes.txt").write_text("Normal team notes " * 25, encoding="utf-8")

    reg = client.post(
        "/monitor/folders",
        headers=detection_auth_header,
        json={"folder_path": str(sandbox), "folder_name": "LiveAPIBox"},
    )
    assert reg.status_code == 201
    folder_id = reg.json()["id"]

    start_res = client.post(f"/monitor/start/{folder_id}", headers=detection_auth_header)
    assert start_res.status_code == 200
    assert start_res.json()["status"] == "active"

    try:
        status_res = client.get(f"/monitor/status/{folder_id}", headers=detection_auth_header)
        assert status_res.status_code == 200
        assert status_res.json()["running"] is True

        # Wait briefly and tamper with a deployed canary file on disk
        time.sleep(0.25)
        canary_file = sandbox / ".rw_canary_credentials.txt"
        assert canary_file.exists()
        canary_file.write_bytes(os.urandom(512))

        # Wait for watchdog delivery (and/or verify via scan endpoint)
        time.sleep(0.6)
        scan_res = client.post(f"/monitor/scan/{folder_id}", headers=detection_auth_header)
        assert scan_res.status_code == 200
    finally:
        stop_res = client.post(f"/monitor/stop/{folder_id}", headers=detection_auth_header)
        assert stop_res.status_code == 200
        assert stop_res.json()["status"] == "stopped"
        assert monitor_manager.get_status(folder_id)["running"] is False

    events_res = client.get(f"/events?folder_id={folder_id}", headers=detection_auth_header)
    assert events_res.status_code == 200
    assert any(ev["severity"] == "CRITICAL" for ev in events_res.json())
