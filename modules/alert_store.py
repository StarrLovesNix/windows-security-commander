"""
alert_store.py - Persistent unacknowledged alert store.

HIGH and CRITICAL events are written to data/unacknowledged_alerts.json
and remain visible in the UI until the user explicitly dismisses them.

This solves: "threat fired a toast, I opened the window, it was gone."
The alert stays pinned in the UI across restarts until acknowledged.
"""

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import List

from .events import SecurityEvent, Severity, EventType

logger = logging.getLogger(__name__)

_PERSISTENT_SEVERITIES = {Severity.HIGH, Severity.CRITICAL}

# Event types that are always worth pinning regardless of severity
_ALWAYS_PIN = {
    EventType.AUDIT_CLEAR,
    EventType.ARP_SPOOF,
    EventType.THREAT_IP,
    EventType.LOGIN_BRUTE,
}


class AlertStore:
    """Thread-safe store of unacknowledged high-priority alerts."""

    def __init__(self, data_dir: Path):
        self._path = data_dir / "unacknowledged_alerts.json"
        self._alerts: List[dict] = []
        self._lock = threading.Lock()
        self._load()

    # ------------------------------------------------------------------

    def consider(self, event: SecurityEvent):
        """Add event to the persistent store if it qualifies."""
        if event.severity not in _PERSISTENT_SEVERITIES and event.event_type not in _ALWAYS_PIN:
            return
        with self._lock:
            # Deduplicate by key — don't pile up identical alerts
            key = event.key()
            if any(a["key"] == key for a in self._alerts):
                return
            self._alerts.append({
                "key":         key,
                "timestamp":   event.timestamp.isoformat(),
                "event_type":  event.event_type.value,
                "severity":    event.severity.value,
                "source":      event.source,
                "description": event.description,
                "remediated":  event.remediated,
                "details":     event.details,
            })
            self._save()

    def get_all(self) -> List[dict]:
        with self._lock:
            return list(self._alerts)

    def acknowledge(self, key: str) -> bool:
        """Remove an alert by its key. Returns True if found."""
        with self._lock:
            before = len(self._alerts)
            self._alerts = [a for a in self._alerts if a["key"] != key]
            if len(self._alerts) < before:
                self._save()
                return True
        return False

    def acknowledge_all(self):
        with self._lock:
            self._alerts.clear()
            self._save()

    def count(self) -> int:
        with self._lock:
            return len(self._alerts)

    # ------------------------------------------------------------------

    def _load(self):
        try:
            if self._path.exists():
                self._alerts = json.loads(self._path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Alert store load failed: %s", exc)
            self._alerts = []

    def _save(self):
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(self._alerts, indent=2), encoding="utf-8"
            )
        except Exception as exc:
            logger.warning("Alert store save failed: %s", exc)
