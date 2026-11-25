"""
entropy.py — Shannon Entropy & File Integrity Change Detection (Member B / FR-2).

Safely reads files within a designated sandbox boundary, calculates Shannon entropy
(0.0 - 8.0 bits/byte) and SHA-256 digests without retaining raw file contents,
compares changes against per-file baselines, and emits explainable risk evidence.
"""

from __future__ import annotations

import hashlib
import math
import os
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

DEFAULT_ENTROPY_THRESHOLD: float = 7.5
DEFAULT_DELTA_THRESHOLD: float = 1.5
DEFAULT_MAX_FILE_BYTES: int = 10 * 1024 * 1024  # 10 MB read cap
MODEL_VERSION: str = "shannon-entropy-v1.0"


def _is_within_sandbox(target: Path, sandbox_root: Path) -> bool:
    """Return True if resolved target path is inside resolved sandbox_root."""
    try:
        resolved_root = Path(os.path.realpath(str(sandbox_root)))
        # Reject symlinks whose target escapes the sandbox
        if target.is_symlink():
            link_target = Path(os.path.realpath(str(target)))
            return link_target == resolved_root or link_target.is_relative_to(resolved_root)
        resolved_target = Path(os.path.realpath(str(target)))
        return resolved_target == resolved_root or resolved_target.is_relative_to(resolved_root)
    except (OSError, ValueError):
        return False


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy in bits per byte (range 0.0 to 8.0).

    Empty byte sequences return 0.0.
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def calculate_sha256(data: bytes) -> str:
    """Return hexadecimal SHA-256 digest of bytes without retaining raw content."""
    return hashlib.sha256(data).hexdigest()


def safe_read_file(
    file_path: Union[str, Path],
    sandbox_root: Optional[Union[str, Path]] = None,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
    allow_truncate: bool = True,
) -> Tuple[bytes, bool, int]:
    """
    Safely read a regular file with boundary and size validation.

    Returns:
        (data_bytes, was_truncated, actual_file_size)

    Raises:
        ValueError: On null bytes, invalid path, non-regular file, or oversized file
                    when allow_truncate is False.
        PermissionError: On sandbox boundary violation or OS permission failure.
        FileNotFoundError: When the file does not exist.
    """
    raw_str = str(file_path)
    if not raw_str or "\x00" in raw_str:
        raise ValueError("Invalid file path: empty or contains null byte")

    target = Path(raw_str)

    if sandbox_root is not None:
        root_path = Path(str(sandbox_root))
        if not _is_within_sandbox(target, root_path):
            raise PermissionError(
                f"Folder boundary violation: '{target}' is outside sandbox '{root_path}'"
            )

    if not target.exists():
        raise FileNotFoundError(f"File not found: '{target}'")

    if not target.is_file():
        raise ValueError(f"Target path is not a regular file: '{target}'")

    actual_size = target.stat().st_size
    truncated = False

    if actual_size > max_bytes:
        if not allow_truncate:
            raise ValueError(
                f"File size ({actual_size} bytes) exceeds maximum allowed ({max_bytes} bytes)"
            )
        truncated = True

    with open(target, "rb") as fh:
        data = fh.read(max_bytes)

    return data, truncated, actual_size


class EntropyAnalyzer:
    """
    Stateful, thread-safe Shannon entropy and hash-change analyzer.

    Retains only metadata (entropy, SHA-256 hash, size, timestamp) per file path;
    never stores raw file contents in memory or logs.
    """

    def __init__(
        self,
        entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
        delta_threshold: float = DEFAULT_DELTA_THRESHOLD,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    ) -> None:
        if not (0.0 <= entropy_threshold <= 8.0):
            raise ValueError("entropy_threshold must be between 0.0 and 8.0")
        if delta_threshold < 0.0:
            raise ValueError("delta_threshold must be non-negative")
        if max_file_bytes <= 0:
            raise ValueError("max_file_bytes must be positive")

        self.entropy_threshold = float(entropy_threshold)
        self.delta_threshold = float(delta_threshold)
        self.max_file_bytes = int(max_file_bytes)
        self._baselines: Dict[str, Dict[str, object]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _normalize_key(file_path: Union[str, Path]) -> str:
        return os.path.realpath(str(file_path))

    def get_baseline(self, file_path: Union[str, Path]) -> Optional[Dict[str, object]]:
        """Return stored baseline metadata for a file if present."""
        key = self._normalize_key(file_path)
        with self._lock:
            entry = self._baselines.get(key)
            return dict(entry) if entry is not None else None

    def remove_baseline(self, file_path: Union[str, Path]) -> None:
        """Remove a file from the baseline cache (e.g., on deletion)."""
        key = self._normalize_key(file_path)
        with self._lock:
            self._baselines.pop(key, None)

    def clear_baselines(self) -> None:
        """Clear all stored file baselines."""
        with self._lock:
            self._baselines.clear()

    def register_baseline(
        self,
        file_path: Union[str, Path],
        sandbox_root: Optional[Union[str, Path]] = None,
    ) -> Dict[str, object]:
        """Measure and store initial entropy and SHA-256 baseline for a file."""
        data, truncated, actual_size = safe_read_file(
            file_path,
            sandbox_root=sandbox_root,
            max_bytes=self.max_file_bytes,
            allow_truncate=True,
        )
        entropy_val = calculate_shannon_entropy(data)
        file_hash = calculate_sha256(data)
        now_iso = datetime.now(timezone.utc).isoformat()

        record: Dict[str, object] = {
            "entropy": entropy_val,
            "sha256": file_hash,
            "size": actual_size,
            "truncated": truncated,
            "updated_at": now_iso,
        }
        key = self._normalize_key(file_path)
        with self._lock:
            self._baselines[key] = record
        return dict(record)

    def seed_folder_baselines(
        self,
        sandbox_root: Union[str, Path],
        exclude_names: Optional[set[str]] = None,
    ) -> int:
        """Scan existing files in sandbox_root and record initial entropy baselines."""
        root = Path(str(sandbox_root))
        if not root.exists() or not root.is_dir():
            return 0
        count = 0
        excluded = exclude_names or set()
        for item in root.rglob("*"):
            if item.is_file() and item.name not in excluded:
                try:
                    self.register_baseline(item, sandbox_root=root)
                    count += 1
                except (OSError, ValueError, PermissionError):
                    continue
        return count

    def analyze_file(
        self,
        file_path: Union[str, Path],
        sandbox_root: Optional[Union[str, Path]] = None,
        entropy_threshold: Optional[float] = None,
        delta_threshold: Optional[float] = None,
    ) -> Dict[str, object]:
        """
        Analyze a file's current Shannon entropy and SHA-256 against its baseline.

        Returns an explainable detection payload compatible with RansomWatch's pipeline.
        """
        eff_entropy_thr = (
            float(entropy_threshold)
            if entropy_threshold is not None
            else self.entropy_threshold
        )
        eff_delta_thr = (
            float(delta_threshold)
            if delta_threshold is not None
            else self.delta_threshold
        )

        target = Path(str(file_path))
        now_iso = datetime.now(timezone.utc).isoformat()
        data, truncated, actual_size = safe_read_file(
            target,
            sandbox_root=sandbox_root,
            max_bytes=self.max_file_bytes,
            allow_truncate=True,
        )

        current_entropy = calculate_shannon_entropy(data)
        current_hash = calculate_sha256(data)

        key = self._normalize_key(target)
        with self._lock:
            prev = self._baselines.get(key)
            initial_entropy: Optional[float] = (
                float(prev["entropy"]) if prev is not None else None
            )
            initial_hash: Optional[str] = (
                str(prev["sha256"]) if prev is not None else None
            )
            self._baselines[key] = {
                "entropy": current_entropy,
                "sha256": current_hash,
                "size": actual_size,
                "truncated": truncated,
                "updated_at": now_iso,
            }

        entropy_delta = (
            round(current_entropy - initial_entropy, 4)
            if initial_entropy is not None
            else 0.0
        )
        hash_changed = initial_hash is not None and current_hash != initial_hash

        evidence: List[str] = []
        indicators: List[str] = []
        risk_score = 0.0

        if truncated:
            evidence.append(
                f"Oversized file sampled safely at first {self.max_file_bytes} bytes "
                f"(actual size: {actual_size} bytes)"
            )

        if current_entropy >= eff_entropy_thr:
            indicators.append("HIGH_ENTROPY")
            evidence.append(
                f"Shannon entropy {current_entropy:.2f} exceeds threshold {eff_entropy_thr:.2f}"
            )
            # Scale contribution between 55 and 85 depending on how close to 8.0
            excess = min(max(current_entropy - eff_entropy_thr, 0.0), 1.0)
            risk_score = max(risk_score, 65.0 + excess * 25.0)

        if initial_entropy is not None and entropy_delta >= eff_delta_thr:
            indicators.append("ENTROPY_SPIKE")
            evidence.append(
                f"Entropy increased significantly by +{entropy_delta:.2f} "
                f"(from {initial_entropy:.2f} to {current_entropy:.2f})"
            )
            spike_score = min(90.0, 45.0 + entropy_delta * 12.0)
            risk_score = max(risk_score, spike_score)
            if current_entropy >= eff_entropy_thr and hash_changed:
                risk_score = min(100.0, max(risk_score, 85.0))

        if hash_changed:
            indicators.append("CONTENT_HASH_CHANGED")
            evidence.append(
                f"SHA-256 content digest changed ({initial_hash[:12]}... -> {current_hash[:12]}...)"
            )
            if risk_score == 0.0:
                risk_score = 10.0

        if not evidence:
            evidence.append(
                f"Normal Shannon entropy {current_entropy:.2f} (threshold {eff_entropy_thr:.2f})"
            )

        risk_score = round(min(100.0, max(0.0, risk_score)), 2)

        if risk_score >= 85.0:
            severity = "CRITICAL"
        elif risk_score >= 65.0:
            severity = "HIGH"
        elif risk_score >= 35.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        is_suspicious = (
            "HIGH_ENTROPY" in indicators or "ENTROPY_SPIKE" in indicators
        )

        return {
            "module": "entropy",
            "file_name": target.name,
            "file_path": str(target),
            "initial_entropy": initial_entropy,
            "current_entropy": current_entropy,
            "entropy_delta": entropy_delta,
            "initial_hash": initial_hash,
            "current_hash": current_hash,
            "hash_changed": hash_changed,
            "file_size": actual_size,
            "truncated": truncated,
            "is_suspicious": is_suspicious,
            "severity": severity,
            "risk_score": risk_score,
            "indicators": indicators,
            "evidence": evidence,
            "thresholds": {
                "entropy_threshold": eff_entropy_thr,
                "delta_threshold": eff_delta_thr,
            },
            "model_version": MODEL_VERSION,
            "timestamp": now_iso,
        }
