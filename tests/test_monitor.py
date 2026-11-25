"""
test_monitor.py — Unit tests for Member B's Sandbox Folder Monitor (FR-1).
"""

import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from monitor.folder_monitor import (
    BackendEventClient,
    FolderMonitor,
    is_within_sandbox,
    validate_sandbox_path,
)


def test_validate_sandbox_path_and_boundary_checks(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("top secret", encoding="utf-8")

    assert validate_sandbox_path(sandbox) == sandbox.resolve()

    with pytest.raises(ValueError):
        validate_sandbox_path("")
    with pytest.raises(ValueError):
        validate_sandbox_path("bad\x00dir")
    with pytest.raises(FileNotFoundError):
        validate_sandbox_path(tmp_path / "missing")

    regular_file = sandbox / "file.txt"
    regular_file.write_text("ok", encoding="utf-8")
    with pytest.raises(NotADirectoryError):
        validate_sandbox_path(regular_file)

    assert is_within_sandbox(sandbox / "sub" / "doc.txt", sandbox) is True
    assert is_within_sandbox(sandbox / ".." / "outside" / "secret.txt", sandbox) is False
    assert is_within_sandbox(outside / "secret.txt", sandbox) is False
    assert is_within_sandbox("bad\x00file", sandbox) is False


def test_folder_monitor_detects_create_modify_rename_delete(tmp_path):
    sandbox = tmp_path / "live_sandbox"
    sandbox.mkdir()

    captured = []
    cond = threading.Condition()

    def on_evt(payload):
        with cond:
            captured.append(payload)
            cond.notify_all()

    def wait_for_type(expected_type: str, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        with cond:
            while not any(e["event_type"] == expected_type for e in captured):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                cond.wait(timeout=remaining)
            return True

    monitor = FolderMonitor(folder_id=1, folder_path=sandbox, on_event=on_evt)
    monitor.start()
    assert monitor.is_running() is True

    try:
        sample = sandbox / "alpha.txt"
        sample.write_text("initial content", encoding="utf-8")
        assert wait_for_type("file_created")

        sample.write_text("modified content with extra bytes", encoding="utf-8")
        assert wait_for_type("file_modified")

        renamed = sandbox / "alpha.locked"
        sample.rename(renamed)
        assert wait_for_type("file_renamed")

        renamed.unlink()
        assert wait_for_type("file_deleted")
    finally:
        monitor.stop()

    assert monitor.is_running() is False
    observed_types = {evt["event_type"] for evt in captured}
    assert {"file_created", "file_modified", "file_renamed", "file_deleted"}.issubset(
        observed_types
    )
    assert all(evt["boundary_valid"] is True for evt in captured)
    assert all(evt["folder_id"] == 1 for evt in captured)


def test_folder_monitor_flags_boundary_violation_on_simulated_escape(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("escape", encoding="utf-8")

    captured = []
    monitor = FolderMonitor(folder_id=7, folder_path=sandbox, on_event=captured.append)
    monitor.simulate_raw_event("file_modified", outside_file)

    assert len(captured) == 1
    assert captured[0]["boundary_valid"] is False
    assert monitor.stats()["boundary_violations"] == 1


def test_backend_event_client_posts_contract_payload():
    client = BackendEventClient(base_url="http://127.0.0.1:8000", token="test-jwt")
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"id": 1, "event_id": "EVT-123", "severity": "HIGH"}
    mock_resp.raise_for_status.return_value = None
    client._session.post = MagicMock(return_value=mock_resp)

    res = client.send_event(
        {
            "event_type": "file_modified",
            "file_name": "budget.xlsx",
            "module": "entropy",
            "folder_id": 1,
            "severity": "HIGH",
            "risk_score": 85.5,
            "evidence": ["Shannon entropy 7.94 exceeds threshold 7.50"],
        }
    )

    assert res["event_id"] == "EVT-123"
    client._session.post.assert_called_once()
    call_kwargs = client._session.post.call_args.kwargs
    assert call_kwargs["json"]["folder_id"] == 1
    assert call_kwargs["json"]["severity"] == "HIGH"
