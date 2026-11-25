"""
rules.py — Deterministic Rule & Sliding-Window Heuristic Engine (Member B / FR-4).

Evaluates file events using configurable thresholds (with optional SQLite
Configuration overrides), tracks per-folder sliding time windows for activity
frequency, bulk renaming, rapid modifications, mass deletions, suspicious
extensions, entropy spikes, and canary tampering, and produces reproducible,
explainable risk scores and recommended actions.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

RULE_ENGINE_VERSION: str = "rules-v1.0"

SUSPICIOUS_EXTENSIONS: set[str] = {
    ".locked",
    ".enc",
    ".encrypted",
    ".crypt",
    ".crypted",
    ".ransom",
    ".locky",
    ".wannacry",
    ".ryuk",
    ".cry",
    ".encry",
    ".darkness",
}

DEFAULT_THRESHOLDS: Dict[str, Any] = {
    "entropy_threshold": 7.5,
    "entropy_delta_threshold": 1.5,
    "rapid_mod_count": 5,
    "bulk_rename_count": 4,
    "mass_delete_count": 5,
    "window_seconds": 10.0,
}


def load_thresholds_from_db(db_session: Any) -> Dict[str, Any]:
    """
    Load enabled detection thresholds from SQLite Configuration rows,
    falling back to DEFAULT_THRESHOLDS for any unconfigured rule.
    """
    thresholds = dict(DEFAULT_THRESHOLDS)
    if db_session is None:
        return thresholds

    try:
        import models  # type: ignore

        rows = (
            db_session.query(models.Configuration)
            .filter(models.Configuration.is_enabled == True)  # noqa: E712
            .all()
        )
        for row in rows:
            if row.rule_name in thresholds and row.value is not None:
                try:
                    thresholds[row.rule_name] = float(row.value)
                except (TypeError, ValueError):
                    pass
    except Exception:
        # Never fail detection if DB configuration lookup encounters a transient issue
        pass

    return thresholds


def score_to_severity(risk_score: float) -> str:
    """Map numeric risk score (0-100) to standard RansomWatch severity label."""
    if risk_score >= 85.0:
        return "CRITICAL"
    if risk_score >= 65.0:
        return "HIGH"
    if risk_score >= 35.0:
        return "MEDIUM"
    return "LOW"


def recommended_action_for_severity(severity: str, canary_hit: bool = False) -> str:
    """Return clear, actionable remediation guidance for the alert severity."""
    if canary_hit or severity == "CRITICAL":
        return (
            "CRITICAL: Halt suspicious process immediately, isolate affected sandbox "
            "folder, and verify backup integrity before restoring files."
        )
    if severity == "HIGH":
        return (
            "HIGH: Pause automated workflows in the monitored folder, inspect the "
            "process modifying/renaming files, and escalate to incident investigation."
        )
    if severity == "MEDIUM":
        return (
            "MEDIUM: Review recent file activity and entropy changes in the timeline; "
            "verify whether bulk operations are authorized."
        )
    return "LOW: Routine file activity observed; continue passive monitoring."


@dataclass
class _WindowRecord:
    ts: float
    event_type: str
    file_name: str
    dest_name: Optional[str]
    entropy: Optional[float]
    entropy_delta: float
    suspicious_ext: bool


class RuleEngine:
    """
    Thread-safe sliding-window heuristic engine for ransomware behavior rules.
    """

    def __init__(self, default_thresholds: Optional[Dict[str, Any]] = None) -> None:
        self.default_thresholds = dict(DEFAULT_THRESHOLDS)
        if default_thresholds:
            self.default_thresholds.update(default_thresholds)
        self._windows: Dict[int, Deque[_WindowRecord]] = {}
        self._lock = threading.Lock()

    def reset_window(self, folder_id: Optional[int] = None) -> None:
        """Clear sliding window state for one folder or all folders."""
        with self._lock:
            if folder_id is None:
                self._windows.clear()
            else:
                self._windows.pop(folder_id, None)

    @staticmethod
    def has_suspicious_extension(file_name: Optional[str]) -> bool:
        if not file_name:
            return False
        suffixes = [s.lower() for s in Path(file_name).suffixes]
        return any(s in SUSPICIOUS_EXTENSIONS for s in suffixes)

    def _prune_and_summarize_locked(
        self,
        folder_id: int,
        window_seconds: float,
        now_ts: float,
    ) -> Dict[str, float]:
        dq = self._windows.setdefault(folder_id, deque())
        cutoff = now_ts - window_seconds
        while dq and dq[0].ts < cutoff:
            dq.popleft()

        total = len(dq)
        modify_count = sum(1 for r in dq if r.event_type == "file_modified")
        create_count = sum(1 for r in dq if r.event_type == "file_created")
        delete_count = sum(1 for r in dq if r.event_type == "file_deleted")
        rename_count = sum(1 for r in dq if r.event_type == "file_renamed")
        suspicious_ext_count = sum(1 for r in dq if r.suspicious_ext)

        entropies = [r.entropy for r in dq if r.entropy is not None]
        deltas = [r.entropy_delta for r in dq if r.entropy is not None]

        mean_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        max_entropy = max(entropies) if entropies else 0.0
        mean_entropy_delta = sum(deltas) / len(deltas) if deltas else 0.0
        event_rate = total / max(window_seconds, 0.1)
        suspicious_ext_ratio = suspicious_ext_count / total if total > 0 else 0.0

        return {
            "total_events": float(total),
            "event_rate": round(event_rate, 4),
            "modify_count": float(modify_count),
            "create_count": float(create_count),
            "delete_count": float(delete_count),
            "rename_count": float(rename_count),
            "suspicious_ext_count": float(suspicious_ext_count),
            "suspicious_ext_ratio": round(suspicious_ext_ratio, 4),
            "mean_entropy": round(mean_entropy, 4),
            "max_entropy": round(max_entropy, 4),
            "mean_entropy_delta": round(mean_entropy_delta, 4),
        }

    def get_window_stats(
        self,
        folder_id: int,
        window_seconds: Optional[float] = None,
        now_ts: Optional[float] = None,
    ) -> Dict[str, float]:
        """Return current sliding-window activity statistics for folder_id."""
        w_sec = float(
            window_seconds
            if window_seconds is not None
            else self.default_thresholds["window_seconds"]
        )
        now = time.monotonic() if now_ts is None else float(now_ts)
        with self._lock:
            return self._prune_and_summarize_locked(folder_id, w_sec, now)

    def evaluate(
        self,
        folder_id: int,
        event_type: str,
        file_name: str,
        dest_name: Optional[str] = None,
        entropy_result: Optional[Dict[str, Any]] = None,
        canary_result: Optional[Dict[str, Any]] = None,
        thresholds: Optional[Dict[str, Any]] = None,
        now_ts: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate an incoming event + optional entropy & canary results against all rules.

        Returns an explainable decision dictionary including triggered rules,
        thresholds snapshot, window stats, risk score, severity, and recommended action.
        """
        eff = dict(self.default_thresholds)
        if thresholds:
            eff.update(thresholds)

        window_seconds = float(eff["window_seconds"])
        entropy_thr = float(eff["entropy_threshold"])
        delta_thr = float(eff["entropy_delta_threshold"])
        rapid_mod_thr = int(eff["rapid_mod_count"])
        bulk_rename_thr = int(eff["bulk_rename_count"])
        mass_delete_thr = int(eff["mass_delete_count"])

        now = time.monotonic() if now_ts is None else float(now_ts)
        curr_entropy = (
            float(entropy_result["current_entropy"])
            if entropy_result and entropy_result.get("current_entropy") is not None
            else None
        )
        curr_delta = (
            float(entropy_result.get("entropy_delta", 0.0))
            if entropy_result
            else 0.0
        )
        is_suspicious_ext = self.has_suspicious_extension(dest_name or file_name)

        record = _WindowRecord(
            ts=now,
            event_type=event_type,
            file_name=file_name,
            dest_name=dest_name,
            entropy=curr_entropy,
            entropy_delta=curr_delta,
            suspicious_ext=is_suspicious_ext,
        )

        with self._lock:
            dq = self._windows.setdefault(folder_id, deque())
            dq.append(record)
            stats = self._prune_and_summarize_locked(folder_id, window_seconds, now)

        triggered_rules: List[Dict[str, Any]] = []
        evidence: List[str] = []
        risk_score = 0.0
        canary_hit = False

        # Rule 1: Canary file tamper detection
        if canary_result and canary_result.get("is_canary_triggered"):
            canary_hit = True
            canary_score = float(canary_result.get("risk_score", 95.0))
            risk_score = max(risk_score, canary_score)
            triggered_rules.append(
                {
                    "rule_name": "canary_tamper_rule",
                    "threshold": 1,
                    "observed": event_type,
                    "weight": canary_score,
                    "reason": f"Canary file '{canary_result.get('file_name')}' tampered ({event_type})",
                }
            )
            evidence.extend(canary_result.get("evidence", []))

        # Rule 2: High Shannon entropy
        if curr_entropy is not None and curr_entropy >= entropy_thr:
            weight = 55.0 if curr_delta >= delta_thr else 45.0
            risk_score += weight
            reason = (
                f"Shannon entropy {curr_entropy:.2f} exceeds threshold {entropy_thr:.2f}"
            )
            triggered_rules.append(
                {
                    "rule_name": "high_entropy_rule",
                    "threshold": entropy_thr,
                    "observed": curr_entropy,
                    "weight": weight,
                    "reason": reason,
                }
            )
            evidence.append(reason)

        # Rule 3: Significant entropy increase (spike)
        if curr_entropy is not None and curr_delta >= delta_thr:
            weight = 30.0
            risk_score += weight
            reason = (
                f"Entropy spiked by +{curr_delta:.2f} (threshold +{delta_thr:.2f})"
            )
            triggered_rules.append(
                {
                    "rule_name": "entropy_spike_rule",
                    "threshold": delta_thr,
                    "observed": curr_delta,
                    "weight": weight,
                    "reason": reason,
                }
            )
            evidence.append(reason)

        # Rule 4: Rapid file modification frequency
        mod_count = int(stats["modify_count"])
        if mod_count >= rapid_mod_thr:
            weight = 40.0
            risk_score += weight
            reason = (
                f"Rapid modifications: {mod_count} modifications in {window_seconds:.1f}s "
                f"(threshold {rapid_mod_thr}, rate {stats['event_rate']:.2f} events/s)"
            )
            triggered_rules.append(
                {
                    "rule_name": "rapid_modification_rule",
                    "threshold": rapid_mod_thr,
                    "observed": mod_count,
                    "weight": weight,
                    "reason": reason,
                }
            )
            evidence.append(reason)

        # Rule 5: Bulk renaming
        rename_count = int(stats["rename_count"])
        if rename_count >= bulk_rename_thr:
            weight = 40.0
            risk_score += weight
            reason = (
                f"Bulk renaming detected: {rename_count} renames in {window_seconds:.1f}s "
                f"(threshold {bulk_rename_thr})"
            )
            triggered_rules.append(
                {
                    "rule_name": "bulk_rename_rule",
                    "threshold": bulk_rename_thr,
                    "observed": rename_count,
                    "weight": weight,
                    "reason": reason,
                }
            )
            evidence.append(reason)

        # Rule 6: Suspicious ransomware extension
        if is_suspicious_ext:
            weight = 35.0
            risk_score += weight
            target_label = dest_name or file_name
            reason = f"Suspicious encrypted/ransomware extension observed on '{target_label}'"
            triggered_rules.append(
                {
                    "rule_name": "suspicious_extension_rule",
                    "threshold": "known_ransomware_ext",
                    "observed": Path(target_label).suffix.lower(),
                    "weight": weight,
                    "reason": reason,
                }
            )
            evidence.append(reason)

        # Rule 7: Mass file deletion
        delete_count = int(stats["delete_count"])
        if delete_count >= mass_delete_thr:
            weight = 40.0
            risk_score += weight
            reason = (
                f"Mass deletion detected: {delete_count} deletions in {window_seconds:.1f}s "
                f"(threshold {mass_delete_thr})"
            )
            triggered_rules.append(
                {
                    "rule_name": "mass_deletion_rule",
                    "threshold": mass_delete_thr,
                    "observed": delete_count,
                    "weight": weight,
                    "reason": reason,
                }
            )
            evidence.append(reason)

        risk_score = round(min(100.0, max(0.0, risk_score)), 2)
        severity = score_to_severity(risk_score)
        recommended_action = recommended_action_for_severity(severity, canary_hit=canary_hit)

        if not evidence:
            evidence.append(
                f"Rule check passed: {int(stats['total_events'])} event(s) in "
                f"{window_seconds:.1f}s ({stats['event_rate']:.2f} events/s); no rules triggered"
            )

        # Deduplicate evidence preserving order
        seen: set[str] = set()
        unique_evidence: List[str] = []
        for item in evidence:
            if item not in seen:
                seen.add(item)
                unique_evidence.append(item)

        return {
            "module": "rules",
            "folder_id": folder_id,
            "event_type": event_type,
            "file_name": file_name,
            "severity": severity,
            "risk_score": risk_score,
            "triggered_rules": triggered_rules,
            "rule_names": [r["rule_name"] for r in triggered_rules],
            "window_stats": stats,
            "thresholds_used": {
                "entropy_threshold": entropy_thr,
                "entropy_delta_threshold": delta_thr,
                "rapid_mod_count": rapid_mod_thr,
                "bulk_rename_count": bulk_rename_thr,
                "mass_delete_count": mass_delete_thr,
                "window_seconds": window_seconds,
            },
            "evidence": unique_evidence,
            "recommended_action": recommended_action,
            "model_version": RULE_ENGINE_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
