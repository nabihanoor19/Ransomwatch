"""
test_entropy.py — Unit tests for Member B's Shannon Entropy & Change Detection (FR-2).
"""

import os
import sys
from pathlib import Path

import pytest

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from security.entropy import (
    EntropyAnalyzer,
    calculate_sha256,
    calculate_shannon_entropy,
    safe_read_file,
)


def test_shannon_entropy_edge_and_known_distributions():
    assert calculate_shannon_entropy(b"") == 0.0
    assert calculate_shannon_entropy(b"A" * 1024) == 0.0

    plain_text = b"Quarterly financial summary for Q4 2026. Revenue increased steadily. " * 20
    text_entropy = calculate_shannon_entropy(plain_text)
    assert 3.0 <= text_entropy <= 5.5

    high_entropy_bytes = bytes(range(256)) * 16
    assert calculate_shannon_entropy(high_entropy_bytes) == 8.0


def test_safe_read_file_validations(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    inside = sandbox / "notes.txt"
    inside.write_bytes(b"hello world")

    outside = tmp_path / "secret.txt"
    outside.write_bytes(b"outside secret")

    data, truncated, size = safe_read_file(inside, sandbox_root=sandbox)
    assert data == b"hello world"
    assert truncated is False
    assert size == 11

    # Boundary escape rejected
    with pytest.raises(PermissionError):
        safe_read_file(sandbox / ".." / "secret.txt", sandbox_root=sandbox)

    # Null byte rejected
    with pytest.raises(ValueError):
        safe_read_file("bad\x00path.txt")

    # Directory rejected
    with pytest.raises(ValueError):
        safe_read_file(sandbox, sandbox_root=sandbox)

    # Oversized file handled safely: truncated vs rejected
    big_file = sandbox / "large.bin"
    big_file.write_bytes(b"X" * 2048)
    sampled, was_trunc, actual = safe_read_file(
        big_file, sandbox_root=sandbox, max_bytes=512, allow_truncate=True
    )
    assert len(sampled) == 512
    assert was_trunc is True
    assert actual == 2048

    with pytest.raises(ValueError):
        safe_read_file(
            big_file, sandbox_root=sandbox, max_bytes=512, allow_truncate=False
        )


def test_entropy_analyzer_baseline_normal_and_encrypted_spike(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    doc = sandbox / "report.txt"
    plain = b"Annual audit report section one. " * 40
    doc.write_bytes(plain)

    analyzer = EntropyAnalyzer(entropy_threshold=7.5, delta_threshold=1.5)
    baseline = analyzer.register_baseline(doc, sandbox_root=sandbox)
    assert baseline["sha256"] == calculate_sha256(plain)
    assert baseline["entropy"] < 5.5

    # Normal text edit -> LOW severity, not suspicious
    doc.write_bytes(plain + b"Updated paragraph two with normal prose.")
    normal_res = analyzer.analyze_file(doc, sandbox_root=sandbox)
    assert normal_res["is_suspicious"] is False
    assert normal_res["severity"] == "LOW"
    assert normal_res["hash_changed"] is True
    assert "raw_content" not in normal_res

    # Synthetic encryption overwrite (high-entropy random bytes) -> HIGH/CRITICAL
    encrypted_like = os.urandom(4096)
    doc.write_bytes(encrypted_like)
    enc_res = analyzer.analyze_file(doc, sandbox_root=sandbox)
    assert enc_res["is_suspicious"] is True
    assert enc_res["severity"] in {"HIGH", "CRITICAL"}
    assert enc_res["risk_score"] >= 70.0
    assert enc_res["current_entropy"] >= 7.5
    assert enc_res["entropy_delta"] >= 1.5
    assert "HIGH_ENTROPY" in enc_res["indicators"]
    assert "ENTROPY_SPIKE" in enc_res["indicators"]
    assert any("exceeds threshold" in item for item in enc_res["evidence"])
