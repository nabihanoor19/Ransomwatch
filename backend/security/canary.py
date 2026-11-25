"""
canary.py — Decoy Canary File Deployment & Tamper Detection (Member B / FR-3).

Generates harmless decoy files inside a designated sandbox folder, tracks their
cryptographic SHA-256 hashes, ignores RansomWatch's own deployment writes, and
triggers CRITICAL/HIGH explainable alerts whenever a canary is modified,
deleted, or renamed.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Union

DEFAULT_CANARY_SPECS: Dict[str, str] = {
    ".rw_canary_credentials.txt": (
        "# RansomWatch Synthetic Canary File (Do Not Modify)\n"
        "account_label=synthetic_decoy_vault\n"
        "canary_marker=RW-CANARY-TOKEN-001\n"
        "note=Harmless test fixture for ransomware tamper detection.\n"
    ),
    "~canary_payroll_2026.csv": (
        "employee_id,department,status,canary_marker\n"
        "EMP-0001,Finance,Active,RW-CANARY-TOKEN-002\n"
        "EMP-0002,Security,Active,RW-CANARY-TOKEN-002\n"
    ),
    "_canary_recovery_keys.json": (
        '{\n'
        '  "notice": "RansomWatch synthetic canary decoy",\n'
        '  "canary_marker": "RW-CANARY-TOKEN-003",\n'
        '  "vault_id": "SYNTHETIC-DECOY-003"\n'
        '}\n'
    ),
}

MODEL_VERSION: str = "canary-tripwire-v1.0"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _validate_relative_filename(filename: str) -> str:
    if not filename or "\x00" in filename:
        raise ValueError("Invalid canary filename")
    p = Path(filename)
    if p.is_absolute() or len(p.parts) != 1 or p.name in {".", ".."}:
        raise ValueError(
            f"Canary filename must be a single relative filename inside sandbox: '{filename}'"
        )
    return p.name


class CanaryManager:
    """
    Thread-safe manager for deploying, tracking, and verifying decoy canary files.
    """

    def __init__(self, self_write_suppress_seconds: float = 2.0) -> None:
        self._canaries: Dict[str, Dict[str, object]] = {}
        self._suppress_until: Dict[str, float] = {}
        self._suppress_seconds = float(self_write_suppress_seconds)
        self._lock = threading.Lock()

    @staticmethod
    def _normalize_path(file_path: Union[str, Path]) -> str:
        return os.path.normcase(os.path.abspath(str(file_path)))

    def deploy_canaries(
        self,
        sandbox_root: Union[str, Path],
        filenames: Optional[List[str]] = None,
    ) -> List[Dict[str, object]]:
        """
        Generate and register decoy canary files inside sandbox_root.

        Validates sandbox_root is an existing directory and prevents path traversal.
        """
        root = Path(os.path.realpath(str(sandbox_root)))
        if not root.exists() or not root.is_dir():
            raise ValueError(f"Sandbox folder does not exist or is not a directory: '{sandbox_root}'")

        target_names = filenames if filenames is not None else list(DEFAULT_CANARY_SPECS.keys())
        deployed: List[Dict[str, object]] = []

        for raw_name in target_names:
            safe_name = _validate_relative_filename(raw_name)
            canary_path = root / safe_name

            # Verify resolved destination remains strictly inside sandbox_root
            if Path(os.path.realpath(str(canary_path.parent))) != root:
                raise PermissionError(f"Canary path escapes sandbox: '{canary_path}'")

            content = DEFAULT_CANARY_SPECS.get(
                safe_name,
                f"# RansomWatch Synthetic Canary ({safe_name})\ncanary_marker=RW-CANARY-CUSTOM\n",
            )

            key = self._normalize_path(canary_path)
            with self._lock:
                self._suppress_until[key] = time.monotonic() + self._suppress_seconds

            if not canary_path.exists():
                canary_path.write_text(content, encoding="utf-8")

            digest = _sha256_file(canary_path)
            size = canary_path.stat().st_size
            now_iso = datetime.now(timezone.utc).isoformat()

            record: Dict[str, object] = {
                "file_name": safe_name,
                "file_path": str(canary_path),
                "sandbox_root": str(root),
                "sha256": digest,
                "size": size,
                "created_at": now_iso,
            }
            with self._lock:
                self._canaries[key] = record
                self._suppress_until[key] = time.monotonic() + self._suppress_seconds

            deployed.append(dict(record))

        return deployed

    def register_canary(
        self,
        file_path: Union[str, Path],
        sandbox_root: Optional[Union[str, Path]] = None,
    ) -> Dict[str, object]:
        """Register an existing file as a monitored canary decoy."""
        target = Path(str(file_path))
        if sandbox_root is not None:
            root = Path(os.path.realpath(str(sandbox_root)))
            resolved_target = Path(os.path.realpath(str(target)))
            if not resolved_target.is_relative_to(root):
                raise PermissionError(
                    f"Canary registration rejected: '{target}' is outside '{root}'"
                )

        if not target.exists() or not target.is_file():
            raise FileNotFoundError(f"Canary file does not exist: '{target}'")

        digest = _sha256_file(target)
        size = target.stat().st_size
        now_iso = datetime.now(timezone.utc).isoformat()
        key = self._normalize_path(target)

        record: Dict[str, object] = {
            "file_name": target.name,
            "file_path": str(target),
            "sandbox_root": str(sandbox_root or target.parent),
            "sha256": digest,
            "size": size,
            "created_at": now_iso,
        }
        with self._lock:
            self._canaries[key] = record
        return dict(record)

    def is_canary(self, file_path: Union[str, Path]) -> bool:
        """Return True if file_path corresponds to a registered canary file."""
        key = self._normalize_path(file_path)
        with self._lock:
            return key in self._canaries

    def is_self_write_suppressed(self, file_path: Union[str, Path]) -> bool:
        """Return True if file_path is within the initial deployment suppression window."""
        key = self._normalize_path(file_path)
        with self._lock:
            deadline = self._suppress_until.get(key)
            if deadline is None:
                return False
            if time.monotonic() <= deadline:
                return True
            self._suppress_until.pop(key, None)
            return False

    def get_canary_names(self) -> set[str]:
        """Return the set of registered canary filenames."""
        with self._lock:
            return {str(rec["file_name"]) for rec in self._canaries.values()}

    def list_canaries(self) -> List[Dict[str, object]]:
        """Return metadata copies for all registered canary files."""
        with self._lock:
            return [dict(rec) for rec in self._canaries.values()]

    def inspect_event(
        self,
        event_type: str,
        file_path: Union[str, Path],
        dest_path: Optional[Union[str, Path]] = None,
    ) -> Optional[Dict[str, object]]:
        """
        Inspect a filesystem event against registered canary files.

        Returns an explainable CRITICAL/HIGH alert dict if a canary was tampered with,
        or None if the path is not a canary (or is an expected self-deployment event).
        """
        src_key = self._normalize_path(file_path)
        dest_key = self._normalize_path(dest_path) if dest_path else None

        with self._lock:
            record = self._canaries.get(src_key)
            matched_key = src_key
            if record is None and dest_key is not None:
                record = self._canaries.get(dest_key)
                matched_key = dest_key
            if record is None:
                return None

            # Ignore RansomWatch's own creation/initial write of decoy files
            deadline = self._suppress_until.get(matched_key)
            if event_type in {"file_created", "file_modified"} and deadline is not None:
                if time.monotonic() <= deadline:
                    if event_type == "file_created":
                        return None
                    # If modified during deployment window, check if hash actually differs
                    p_check = Path(str(file_path))
                    if p_check.exists() and _sha256_file(p_check) == record["sha256"]:
                        return None

            canary_record = dict(record)

        file_name = str(canary_record["file_name"])
        expected_hash = str(canary_record["sha256"])
        now_iso = datetime.now(timezone.utc).isoformat()
        evidence: List[str] = []
        actual_hash: Optional[str] = None
        severity = "CRITICAL"
        risk_score = 98.0

        if event_type == "file_deleted":
            risk_score = 100.0
            severity = "CRITICAL"
            evidence.append(f"Canary decoy file '{file_name}' was deleted")
            evidence.append(
                "Immediate high-confidence ransomware or unauthorized tampering indicator"
            )
        elif event_type == "file_renamed":
            dest_name = Path(str(dest_path)).name if dest_path else "<unknown>"
            risk_score = 96.0
            severity = "CRITICAL"
            evidence.append(
                f"Canary decoy file '{file_name}' was renamed/moved to '{dest_name}'"
            )
            evidence.append(
                "Renaming decoy files matches mass-encryption extension-rewriting behavior"
            )
        elif event_type == "file_modified":
            target = Path(str(file_path))
            if target.exists() and target.is_file():
                try:
                    actual_hash = _sha256_file(target)
                except OSError:
                    actual_hash = None

            if actual_hash is not None and actual_hash != expected_hash:
                risk_score = 98.0
                severity = "CRITICAL"
                evidence.append(f"Canary decoy file '{file_name}' content was modified")
                evidence.append(
                    f"SHA-256 integrity mismatch (expected {expected_hash[:12]}..., "
                    f"got {actual_hash[:12]}...)"
                )
            else:
                risk_score = 80.0
                severity = "HIGH"
                evidence.append(
                    f"Canary decoy file '{file_name}' received a write/metadata touch event"
                )
        elif event_type == "file_created":
            # Overwriting or recreating a previously registered canary outside deployment window
            target = Path(str(file_path))
            if target.exists() and target.is_file():
                try:
                    actual_hash = _sha256_file(target)
                except OSError:
                    actual_hash = None
            if actual_hash != expected_hash:
                risk_score = 95.0
                severity = "CRITICAL"
                evidence.append(f"Canary decoy file '{file_name}' was overwritten")
            else:
                return None
        else:
            return None

        return {
            "module": "canary",
            "rule_name": "canary_tamper_rule",
            "event_type": event_type,
            "file_name": file_name,
            "file_path": str(canary_record["file_path"]),
            "dest_path": str(dest_path) if dest_path else None,
            "expected_hash": expected_hash,
            "actual_hash": actual_hash,
            "is_canary_triggered": True,
            "severity": severity,
            "risk_score": risk_score,
            "evidence": evidence,
            "model_version": MODEL_VERSION,
            "timestamp": now_iso,
        }

    def verify_integrity(self) -> List[Dict[str, object]]:
        """
        Verify integrity of all registered canary files on disk.

        Detects missing or silently modified canaries even if an OS event was missed.
        """
        alerts: List[Dict[str, object]] = []
        for rec in self.list_canaries():
            p = Path(str(rec["file_path"]))
            if not p.exists():
                alert = self.inspect_event("file_deleted", p)
                if alert:
                    alerts.append(alert)
                continue
            try:
                current_hash = _sha256_file(p)
            except OSError:
                continue
            if current_hash != rec["sha256"]:
                alert = self.inspect_event("file_modified", p)
                if alert:
                    alerts.append(alert)
        return alerts

    def cleanup_canaries(self, sandbox_root: Optional[Union[str, Path]] = None) -> int:
        """Remove registered canary files created in sandbox_root (or all if None)."""
        removed = 0
        norm_root = (
            os.path.normcase(os.path.realpath(str(sandbox_root)))
            if sandbox_root is not None
            else None
        )
        with self._lock:
            keys_to_remove: List[str] = []
            for key, rec in self._canaries.items():
                rec_root = os.path.normcase(os.path.realpath(str(rec["sandbox_root"])))
                if norm_root is None or rec_root == norm_root:
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                rec = self._canaries.pop(key)
                self._suppress_until.pop(key, None)
                p = Path(str(rec["file_path"]))
                try:
                    if p.exists() and p.is_file():
                        p.unlink()
                        removed += 1
                except OSError:
                    pass
        return removed
