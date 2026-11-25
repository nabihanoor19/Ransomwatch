"""
folder_monitor.py — Real-Time Sandbox Folder Monitor (Member B / FR-1).

Watches a designated sandbox folder recursively using `watchdog`, enforces
strict folder-boundary validation (rejecting path traversal and escaping
symlinks), normalizes create/modify/delete/rename events with UTC timestamps,
and delivers them either to an in-process detection pipeline callback or over
HTTP to Member A's `POST /events` API.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Union

import requests
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger("ransomwatch.monitor")


def validate_sandbox_path(
    folder_path: Union[str, Path],
    must_exist: bool = True,
) -> Path:
    """
    Validate and canonicalize a sandbox folder path.

    Rejects empty strings, null bytes, non-existent paths (if must_exist=True),
    and non-directory targets.
    """
    raw = str(folder_path)
    if not raw or not raw.strip() or "\x00" in raw:
        raise ValueError("Invalid sandbox folder path: empty or contains null byte")

    resolved = Path(os.path.realpath(raw))
    if must_exist:
        if not resolved.exists():
            raise FileNotFoundError(f"Sandbox folder does not exist: '{resolved}'")
        if not resolved.is_dir():
            raise NotADirectoryError(f"Sandbox path is not a directory: '{resolved}'")
    return resolved


def is_within_sandbox(
    target_path: Union[str, Path],
    sandbox_root: Union[str, Path],
) -> bool:
    """
    Verify that target_path stays strictly inside sandbox_root.

    Checks both normalized absolute path and symlink-resolved realpath so
    `..` traversal and symlinks pointing outside the sandbox are both blocked.
    """
    raw = str(target_path)
    if not raw or "\x00" in raw:
        return False

    try:
        root_real = Path(os.path.realpath(str(sandbox_root)))
        abs_target = Path(os.path.abspath(raw))
        if not (abs_target == root_real or abs_target.is_relative_to(root_real)):
            return False

        # For existing files or symlinks, also verify the resolved realpath
        if abs_target.is_symlink() or abs_target.exists():
            real_target = Path(os.path.realpath(raw))
            return real_target == root_real or real_target.is_relative_to(root_real)

        # For deleted files, verify parent directory's realpath stays inside root
        real_parent = Path(os.path.realpath(str(abs_target.parent)))
        return real_parent == root_real or real_parent.is_relative_to(root_real)
    except (OSError, ValueError):
        return False


class BackendEventClient:
    """
    HTTP client implementing Member A's `POST /events` Integration Contract.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        token: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = float(timeout)
        self._session = requests.Session()
        if token:
            self.set_token(token)

    def set_token(self, token: str) -> None:
        self._session.headers.update({"Authorization": f"Bearer {token}"})

    def send_event(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Submit a FileEventCreate JSON payload to POST /events."""
        url = f"{self.base_url}/events"
        body = {
            "event_type": payload["event_type"],
            "file_name": payload["file_name"],
            "module": payload.get("module"),
            "folder_id": payload["folder_id"],
            "severity": payload["severity"],
            "risk_score": payload["risk_score"],
            "evidence": payload.get("evidence", []),
        }
        response = self._session.post(url, json=body, timeout=self.timeout)
        response.raise_for_status()
        return response.json()


class SandboxEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler that normalizes filesystem events, validates
    sandbox boundaries, and forwards valid events to a callback.
    """

    def __init__(
        self,
        folder_id: int,
        sandbox_root: Path,
        on_event: Callable[[Dict[str, Any]], Any],
        debounce_seconds: float = 0.0,
    ) -> None:
        super().__init__()
        self.folder_id = int(folder_id)
        self.sandbox_root = Path(os.path.realpath(str(sandbox_root)))
        self.on_event = on_event
        self.debounce_seconds = float(debounce_seconds)
        self._last_modified_ts: Dict[str, float] = {}
        self._lock = threading.Lock()
        self.events_processed: int = 0
        self.boundary_violations: int = 0

    def _safe_relative_name(self, file_path: Union[str, Path]) -> str:
        try:
            rel = Path(os.path.abspath(str(file_path))).relative_to(self.sandbox_root)
            return str(rel).replace("\\", "/")
        except ValueError:
            return Path(str(file_path)).name

    def _dispatch(
        self,
        event_type: str,
        src_path: str,
        dest_path: Optional[str] = None,
    ) -> None:
        now_dt = datetime.now(timezone.utc)
        boundary_ok = is_within_sandbox(src_path, self.sandbox_root)
        if dest_path is not None and not is_within_sandbox(dest_path, self.sandbox_root):
            boundary_ok = False

        if not boundary_ok:
            with self._lock:
                self.boundary_violations += 1
            logger.warning(
                "Sandbox boundary violation detected for folder_id=%s path=%s dest=%s",
                self.folder_id,
                src_path,
                dest_path,
            )

        if event_type == "file_modified" and self.debounce_seconds > 0.0:
            now_mono = now_dt.timestamp()
            norm_src = os.path.normcase(os.path.abspath(src_path))
            with self._lock:
                prev = self._last_modified_ts.get(norm_src, 0.0)
                if (now_mono - prev) < self.debounce_seconds:
                    return
                self._last_modified_ts[norm_src] = now_mono

        payload: Dict[str, Any] = {
            "folder_id": self.folder_id,
            "sandbox_root": str(self.sandbox_root),
            "event_type": event_type,
            "file_name": self._safe_relative_name(src_path),
            "file_path": os.path.abspath(src_path),
            "dest_name": self._safe_relative_name(dest_path) if dest_path else None,
            "dest_path": os.path.abspath(dest_path) if dest_path else None,
            "boundary_valid": boundary_ok,
            "timestamp": now_dt.isoformat(),
        }

        with self._lock:
            self.events_processed += 1

        try:
            self.on_event(payload)
        except Exception as exc:
            logger.error("Error in folder monitor event callback: %s", exc)

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._dispatch("file_created", str(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._dispatch("file_modified", str(event.src_path))

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._dispatch("file_deleted", str(event.src_path))

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._dispatch(
                "file_renamed",
                str(event.src_path),
                dest_path=str(event.dest_path),
            )


class FolderMonitor:
    """
    Manages a `watchdog` Observer lifecycle for a single registered sandbox folder.
    """

    def __init__(
        self,
        folder_id: int,
        folder_path: Union[str, Path],
        on_event: Optional[Callable[[Dict[str, Any]], Any]] = None,
        recursive: bool = True,
        debounce_seconds: float = 0.0,
    ) -> None:
        self.folder_id = int(folder_id)
        self.sandbox_root = validate_sandbox_path(folder_path, must_exist=True)
        self.recursive = bool(recursive)
        self.on_event = on_event or (lambda evt: None)
        self.handler = SandboxEventHandler(
            folder_id=self.folder_id,
            sandbox_root=self.sandbox_root,
            on_event=self.on_event,
            debounce_seconds=debounce_seconds,
        )
        self._observer: Optional[Observer] = None
        self._lock = threading.Lock()

    def start(self) -> None:
        """Attach and start the watchdog filesystem observer."""
        with self._lock:
            if self._observer is not None and self._observer.is_alive():
                return
            observer = Observer()
            observer.schedule(
                self.handler,
                str(self.sandbox_root),
                recursive=self.recursive,
            )
            observer.start()
            self._observer = observer
        # Allow the OS watcher thread to register its directory handle
        time.sleep(0.15)

    def stop(self, timeout: float = 3.0) -> None:
        """Stop and clean up the watchdog filesystem observer."""
        with self._lock:
            observer = self._observer
            self._observer = None
        if observer is not None:
            observer.stop()
            observer.join(timeout=timeout)

    def is_running(self) -> bool:
        with self._lock:
            return self._observer is not None and self._observer.is_alive()

    def simulate_raw_event(
        self,
        event_type: str,
        file_path: Union[str, Path],
        dest_path: Optional[Union[str, Path]] = None,
    ) -> None:
        """Dispatch a synthetic event through boundary validation and handler."""
        self.handler._dispatch(
            event_type=event_type,
            src_path=str(file_path),
            dest_path=str(dest_path) if dest_path is not None else None,
        )

    def stats(self) -> Dict[str, Any]:
        return {
            "folder_id": self.folder_id,
            "sandbox_root": str(self.sandbox_root),
            "running": self.is_running(),
            "events_processed": self.handler.events_processed,
            "boundary_violations": self.handler.boundary_violations,
        }
