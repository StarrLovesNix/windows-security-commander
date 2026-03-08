"""
alert_history.py - Alert deduplication and cooldown management.

Prevents notification flooding for persistent findings by tracking when
each alert was last emitted. Cooldown periods are per-severity and
configurable in config.json.

Also supports acknowledging findings to permanently suppress them.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Set

from .events import SecurityEvent, Severity

logger = logging.getLogger(__name__)

DEFAULT_COOLDOWN_DAYS: Dict[Severity, int] = {
    Severity.CRITICAL: 0,    # Always alert
    Severity.HIGH:     1,
    Severity.MEDIUM:   3,
    Severity.LOW:      7,
    Severity.INFO:     30,
}


class AlertHistory:
    def __init__(self, config: dict, data_dir: Path):
        self._path = data_dir / "alert_history.json"
        self._history: Dict[str, str] = {}   # key -> last_seen ISO timestamp
        self._acknowledged: Set[str] = set()

        cooldown_cfg = config.get("alert_history", {}).get("cooldown_days", {})
        self._cooldowns: Dict[Severity, timedelta] = {
            sev: timedelta(days=int(cooldown_cfg.get(sev.value, DEFAULT_COOLDOWN_DAYS[sev])))
            for sev in Severity
        }
        self._load()

    # ------------------------------------------------------------------

    def should_alert(self, event: SecurityEvent) -> bool:
        """Return True if this event should trigger a notification."""
        key = event.key()
        if key in self._acknowledged:
            return False
        if key not in self._history:
            return True
        try:
            last_seen = datetime.fromisoformat(self._history[key])
        except ValueError:
            return True
        cooldown = self._cooldowns.get(event.severity, timedelta(days=1))
        return (datetime.now() - last_seen) >= cooldown

    def record(self, event: SecurityEvent):
        """Mark an event as alerted now."""
        self._history[event.key()] = datetime.now().isoformat()
        self._save()

    def acknowledge(self, key: str):
        """Permanently suppress alerts for this event key."""
        self._acknowledged.add(key)
        self._save()

    def unacknowledge(self, key: str):
        self._acknowledged.discard(key)
        self._save()

    # ------------------------------------------------------------------

    def _load(self):
        try:
            if self._path.exists():
                data = json.loads(self._path.read_text())
                self._history = data.get("history", {})
                self._acknowledged = set(data.get("acknowledged", []))
        except Exception as exc:
            logger.debug("Alert history load failed: %s", exc)

    def _save(self):
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps({
                "history": self._history,
                "acknowledged": sorted(self._acknowledged),
            }, indent=2))
        except Exception as exc:
            logger.debug("Alert history save failed: %s", exc)
