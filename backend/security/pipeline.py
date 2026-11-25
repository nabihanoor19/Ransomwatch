"""
pipeline.py — End-to-End Detection Pipeline & Monitor Manager (Member B / B.6).

Connects all five Member B detection components into a single explainable
pipeline:
  1. Sandbox Folder Monitor & boundary validation (FR-1)
  2. Shannon Entropy & SHA-256 baseline analysis (FR-2)
  3. Canary Decoy File tamper detection (FR-3)
  4. Deterministic Rule Engine with dynamic DB thresholds (FR-4)
  5. IsolationForest Behavioral Anomaly Detector (FR-4)
  6. Persistence to SQLite FileEvents, Incidents & AuditLogs (FR-6)
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from sqlalchemy.orm import Session

from monitor.folder_monitor import FolderMonitor, is_within_sandbox
from security.anomaly import AnomalyDetector
from security.canary import CanaryManager
from security.entropy import EntropyAnalyzer
from security.rules import (
    RuleEngine,
    load_thresholds_from_db,
    recommended_action_for_severity,
    score_to_severity,
)

logger = logging.getLogger("ransomwatch.pipeline")


class DetectionPipeline:
    """
    Thread-safe orchestrator executing the multi-stage detection sequence
    for every filesystem event inside a monitored sandbox folder.
    """

    def __init__(
        self,
        entropy_analyzer: Optional[EntropyAnalyzer] = None,
        canary_manager: Optional[CanaryManager] = None,
        rule_engine: Optional[RuleEngine] = None,
        anomaly_detector: Optional[AnomalyDetector] = None,
    ) -> None:
        self.entropy_analyzer = entropy_analyzer or EntropyAnalyzer()
        self.canary_manager = canary_manager or CanaryManager()
        self.rule_engine = rule_engine or RuleEngine()
        self.anomaly_detector = anomaly_detector or AnomalyDetector()
        self._lock = threading.Lock()

    def initialize_folder(
        self,
        folder_id: int,
        folder_path: Union[str, Path],
        deploy_canaries: bool = True,
    ) -> Dict[str, Any]:
        """
        Prepare a sandbox folder for live monitoring:
        - Deploy decoy canary files (if deploy_canaries=True)
        - Seed initial Shannon entropy & SHA-256 baselines for existing files
        """
        root = Path(str(folder_path))
        deployed: List[Dict[str, Any]] = []
        if deploy_canaries:
            deployed = self.canary_manager.deploy_canaries(root)
        canary_names = self.canary_manager.get_canary_names()
        seeded_count = self.entropy_analyzer.seed_folder_baselines(
            root,
            exclude_names=canary_names,
        )
        return {
            "folder_id": folder_id,
            "folder_path": str(root),
            "canaries_deployed": len(deployed),
            "baselines_seeded": seeded_count,
        }

    def process_event(
        self,
        event: Dict[str, Any],
        db: Optional[Session] = None,
        user_id: Optional[int] = None,
        persist: bool = True,
        now_ts: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Run the complete detection sequence on a normalized filesystem event.

        Returns the Member-A-compatible event payload + explainable analysis
        metadata, or None if the event is a suppressed self-write during canary
        deployment.
        """
        t_start = time.perf_counter()

        folder_id = int(event["folder_id"])
        event_type = str(event["event_type"])
        file_name = str(event.get("file_name") or Path(str(event["file_path"])).name)
        file_path = str(event["file_path"])
        dest_path = event.get("dest_path")
        dest_name = event.get("dest_name")
        sandbox_root = event.get("sandbox_root")

        # ── Stage 1: Folder boundary validation ──────────────────────────
        boundary_valid = event.get("boundary_valid")
        if boundary_valid is None and sandbox_root is not None:
            boundary_valid = is_within_sandbox(file_path, sandbox_root)
            if dest_path is not None:
                boundary_valid = boundary_valid and is_within_sandbox(
                    dest_path, sandbox_root
                )

        if boundary_valid is False:
            evidence = [
                f"Folder boundary violation: '{file_name}' attempted to escape designated sandbox",
                "Access rejected before content inspection",
            ]
            latency_ms = round((time.perf_counter() - t_start) * 1000.0, 3)
            result = {
                "event_type": event_type,
                "file_name": file_name,
                "module": "monitor",
                "folder_id": folder_id,
                "severity": "CRITICAL",
                "risk_score": 100.0,
                "evidence": evidence,
                "recommended_action": recommended_action_for_severity("CRITICAL"),
                "timestamp": event.get("timestamp")
                or datetime.now(timezone.utc).isoformat(),
                "analysis": {
                    "boundary_valid": False,
                    "latency_ms": latency_ms,
                },
            }
            if persist and db is not None:
                self._persist_result(db, result, user_id=user_id)
            return result

        # ── Stage 2: Canary file check ───────────────────────────────────
        canary_result = self.canary_manager.inspect_event(
            event_type=event_type,
            file_path=file_path,
            dest_path=dest_path,
        )
        if canary_result is None and self.canary_manager.is_canary(file_path):
            # Suppressed initial deployment event
            return None

        # ── Stage 3: Load dynamic thresholds & analyze entropy ───────────
        thresholds = load_thresholds_from_db(db)
        entropy_result: Optional[Dict[str, Any]] = None
        inspect_target = dest_path if (event_type == "file_renamed" and dest_path) else file_path

        if event_type == "file_deleted":
            self.entropy_analyzer.remove_baseline(file_path)
        elif not self.canary_manager.is_canary(file_path):
            target_p = Path(inspect_target)
            if target_p.exists() and target_p.is_file():
                try:
                    entropy_result = self.entropy_analyzer.analyze_file(
                        target_p,
                        sandbox_root=sandbox_root,
                        entropy_threshold=thresholds["entropy_threshold"],
                        delta_threshold=thresholds["entropy_delta_threshold"],
                    )
                except (OSError, ValueError, PermissionError) as exc:
                    entropy_result = {
                        "module": "entropy",
                        "is_suspicious": False,
                        "risk_score": 0.0,
                        "severity": "LOW",
                        "evidence": [f"File could not be analyzed safely: {exc}"],
                    }

        # ── Stage 4: Deterministic rule engine ───────────────────────────
        rule_result = self.rule_engine.evaluate(
            folder_id=folder_id,
            event_type=event_type,
            file_name=file_name,
            dest_name=dest_name,
            entropy_result=entropy_result,
            canary_result=canary_result,
            thresholds=thresholds,
            now_ts=now_ts,
        )

        # ── Stage 5: IsolationForest behavioral anomaly detection ────────
        anomaly_result = self.anomaly_detector.score_window(rule_result["window_stats"])

        # ── Stage 6: Aggregate explainable decision ──────────────────────
        combined_score = float(rule_result["risk_score"])
        if canary_result is not None:
            combined_score = max(combined_score, float(canary_result["risk_score"]))
        if entropy_result is not None and entropy_result.get("is_suspicious"):
            combined_score = max(combined_score, float(entropy_result["risk_score"]))
        if anomaly_result["is_anomaly"]:
            if rule_result["triggered_rules"]:
                combined_score = min(
                    100.0, max(combined_score, float(anomaly_result["risk_score"])) + 10.0
                )
            else:
                combined_score = max(combined_score, float(anomaly_result["risk_score"]))

        final_risk_score = round(min(100.0, max(0.0, combined_score)), 2)
        final_severity = score_to_severity(final_risk_score)
        canary_hit = bool(canary_result and canary_result.get("is_canary_triggered"))

        if canary_hit:
            primary_module = "canary"
        elif entropy_result and entropy_result.get("is_suspicious"):
            primary_module = "entropy"
        elif rule_result["triggered_rules"]:
            primary_module = "rules"
        elif anomaly_result["is_anomaly"]:
            primary_module = "anomaly"
        else:
            primary_module = "monitor"

        evidence: List[str] = []
        if canary_result:
            evidence.extend(canary_result.get("evidence", []))
        if entropy_result and (
            entropy_result.get("is_suspicious") or entropy_result.get("hash_changed")
        ):
            evidence.extend(entropy_result.get("evidence", []))
        for r_item in rule_result["triggered_rules"]:
            if r_item["reason"] not in evidence:
                evidence.append(r_item["reason"])
        if anomaly_result["is_anomaly"]:
            evidence.extend(anomaly_result.get("evidence", []))
        if not evidence:
            evidence.extend(rule_result.get("evidence", []))

        # Include reproducibility metadata in evidence if suspicious
        if final_risk_score >= 35.0:
            rule_list = ", ".join(rule_result["rule_names"]) or "anomaly_model"
            evidence.append(
                f"Decision metadata: rules=[{rule_list}], "
                f"entropy_thr={thresholds['entropy_threshold']}, "
                f"model={anomaly_result['model_version']}"
            )

        # Deduplicate preserving order
        dedup_evidence = list(dict.fromkeys(evidence))
        recommended_action = recommended_action_for_severity(
            final_severity, canary_hit=canary_hit
        )
        latency_ms = round((time.perf_counter() - t_start) * 1000.0, 3)

        result: Dict[str, Any] = {
            "event_type": event_type,
            "file_name": file_name,
            "module": primary_module,
            "folder_id": folder_id,
            "severity": final_severity,
            "risk_score": final_risk_score,
            "evidence": dedup_evidence,
            "recommended_action": recommended_action,
            "timestamp": event.get("timestamp")
            or datetime.now(timezone.utc).isoformat(),
            "analysis": {
                "boundary_valid": True,
                "canary": canary_result,
                "entropy": entropy_result,
                "rules": rule_result,
                "anomaly": anomaly_result,
                "latency_ms": latency_ms,
            },
        }

        if persist and db is not None:
            self._persist_result(db, result, user_id=user_id)

        return result

    @staticmethod
    def _persist_result(
        db: Session,
        result: Dict[str, Any],
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Persist FileEvent, correlate Incident if high risk, and write AuditLog."""
        import models  # type: ignore
        from services.audit_service import AuditService
        from services.incident_service import IncidentService

        db_event = models.FileEvent(
            event_id=str(uuid.uuid4()),
            event_type=result["event_type"],
            file_name=result["file_name"],
            module=result["module"],
            folder_id=result["folder_id"],
            severity=result["severity"],
            risk_score=result["risk_score"],
            evidence=result["evidence"],
        )
        db.add(db_event)
        db.commit()
        db.refresh(db_event)

        AuditService.log_file_event_received(db, user_id, db_event)

        incident = IncidentService.correlate_or_create_incident(
            db=db,
            event=db_event,
            user_id=user_id,
        )

        result["id"] = db_event.id
        result["event_id"] = db_event.event_id
        result["incident_id"] = incident.id if incident else None
        result["incident_ref"] = incident.incident_id if incident else None
        return result


class MonitorManager:
    """
    Manages active `FolderMonitor` instances for FastAPI `/monitor/*` routes.
    """

    def __init__(self, pipeline: Optional[DetectionPipeline] = None) -> None:
        self.pipeline = pipeline or DetectionPipeline()
        self._monitors: Dict[int, FolderMonitor] = {}
        self._lock = threading.Lock()

    def start_monitoring(
        self,
        folder_id: int,
        folder_path: str,
        db_factory: Optional[Callable[[], Session]] = None,
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Start live watchdog monitoring if folder_path exists on disk.

        Returns attachment status; virtual test paths that do not exist on disk
        do not raise so API unit tests using placeholder paths stay compatible.
        """
        target = Path(folder_path)
        if not target.exists() or not target.is_dir():
            return {
                "attached": False,
                "reason": "Folder path does not exist on local disk; DB status updated only",
            }

        with self._lock:
            existing = self._monitors.get(folder_id)
            if existing is not None and existing.is_running():
                return {"attached": True, "already_running": True}

        init_info = self.pipeline.initialize_folder(
            folder_id=folder_id,
            folder_path=target,
            deploy_canaries=True,
        )

        def _handle_event(evt: Dict[str, Any]) -> None:
            if db_factory is None:
                self.pipeline.process_event(evt, db=None, persist=False)
                return
            session = db_factory()
            try:
                self.pipeline.process_event(
                    evt, db=session, user_id=user_id, persist=True
                )
            finally:
                session.close()

        monitor = FolderMonitor(
            folder_id=folder_id,
            folder_path=target,
            on_event=_handle_event,
        )
        monitor.start()

        with self._lock:
            self._monitors[folder_id] = monitor

        return {"attached": True, **init_info}

    def stop_monitoring(self, folder_id: int) -> Dict[str, Any]:
        """Stop live watchdog monitoring for folder_id if running."""
        with self._lock:
            monitor = self._monitors.pop(folder_id, None)
        if monitor is not None:
            monitor.stop()
            return {"stopped": True, **monitor.stats()}
        return {"stopped": False}

    def get_status(self, folder_id: int) -> Dict[str, Any]:
        with self._lock:
            monitor = self._monitors.get(folder_id)
        if monitor is None:
            return {"folder_id": folder_id, "running": False, "attached": False}
        return {"attached": True, **monitor.stats()}

    def verify_canaries(
        self,
        folder_id: int,
        db: Optional[Session] = None,
        user_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Run an on-demand canary integrity verification and persist any alerts."""
        alerts = self.pipeline.canary_manager.verify_integrity()
        results: List[Dict[str, Any]] = []
        for alert in alerts:
            synth_evt = {
                "folder_id": folder_id,
                "sandbox_root": str(Path(str(alert["file_path"])).parent),
                "event_type": alert["event_type"],
                "file_name": alert["file_name"],
                "file_path": alert["file_path"],
                "boundary_valid": True,
                "timestamp": alert["timestamp"],
            }
            processed = self.pipeline.process_event(
                synth_evt,
                db=db,
                user_id=user_id,
                persist=db is not None,
            )
            if processed:
                results.append(processed)
        return results


monitor_manager = MonitorManager()
