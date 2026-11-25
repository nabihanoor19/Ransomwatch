"""
test_canary.py — Unit tests for Member B's Canary Decoy File Manager (FR-3).
"""

import sys
from pathlib import Path

import pytest

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from security.canary import CanaryManager


def test_deploy_canaries_and_self_write_suppression(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    mgr = CanaryManager(self_write_suppress_seconds=2.0)
    deployed = mgr.deploy_canaries(sandbox)
    assert len(deployed) == 3
    for item in deployed:
        assert Path(item["file_path"]).exists()
        assert mgr.is_canary(item["file_path"]) is True

    # Initial creation event during deployment window must not false-alarm
    first = Path(deployed[0]["file_path"])
    assert mgr.inspect_event("file_created", first) is None


def test_canary_rejects_traversal_and_missing_folder(tmp_path):
    mgr = CanaryManager()
    with pytest.raises(ValueError):
        mgr.deploy_canaries(tmp_path / "does_not_exist")

    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    with pytest.raises(ValueError):
        mgr.deploy_canaries(sandbox, filenames=["../escape.txt"])


def test_canary_detects_modify_rename_and_delete(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    mgr = CanaryManager(self_write_suppress_seconds=0.0)
    deployed = mgr.deploy_canaries(sandbox)
    c_mod = Path(deployed[0]["file_path"])
    c_ren = Path(deployed[1]["file_path"])
    c_del = Path(deployed[2]["file_path"])

    # 1. Modify canary content -> CRITICAL
    c_mod.write_bytes(b"ENCRYPTED_PAYLOAD_DATA" * 10)
    mod_alert = mgr.inspect_event("file_modified", c_mod)
    assert mod_alert is not None
    assert mod_alert["severity"] == "CRITICAL"
    assert mod_alert["risk_score"] >= 95.0
    assert mod_alert["module"] == "canary"
    assert any("modified" in e.lower() for e in mod_alert["evidence"])

    # 2. Rename canary -> CRITICAL
    renamed_dest = sandbox / f"{c_ren.name}.locked"
    c_ren.rename(renamed_dest)
    ren_alert = mgr.inspect_event("file_renamed", c_ren, dest_path=renamed_dest)
    assert ren_alert is not None
    assert ren_alert["severity"] == "CRITICAL"
    assert ren_alert["risk_score"] >= 95.0
    assert any("renamed" in e.lower() for e in ren_alert["evidence"])

    # 3. Delete canary -> CRITICAL (100)
    c_del.unlink()
    del_alert = mgr.inspect_event("file_deleted", c_del)
    assert del_alert is not None
    assert del_alert["severity"] == "CRITICAL"
    assert del_alert["risk_score"] == 100.0
    assert any("deleted" in e.lower() for e in del_alert["evidence"])


def test_canary_verify_integrity_and_cleanup(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    mgr = CanaryManager(self_write_suppress_seconds=0.0)
    deployed = mgr.deploy_canaries(sandbox)
    target = Path(deployed[0]["file_path"])
    target.write_text("tampered silently", encoding="utf-8")

    alerts = mgr.verify_integrity()
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "CRITICAL"

    removed = mgr.cleanup_canaries(sandbox)
    assert removed == 3
    assert mgr.list_canaries() == []
