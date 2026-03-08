"""
remediation.py - Automated response to detected threats.

All auto-remediation is OFF by default. Enable individual actions in
config.json under the "remediation" key. Every action taken is emitted
as a FIREWALL_BLOCK or PROCESS_KILL event so it appears in the feed.

Supported actions:
  auto_block_brute_force  - Block IPs that triggered LOGIN_BRUTE
  auto_block_c2           - Block IPs confirmed malicious by threat intel
  auto_kill_suspicious    - Kill processes flagged PROC_SUSPICIOUS (use carefully)
"""

import logging
from datetime import datetime
from typing import Set

import psutil

from . import firewall_manager
from .events import EventType, SecurityEvent, Severity, event_queue

logger = logging.getLogger(__name__)


class Remediator:
    def __init__(self, config: dict):
        cfg = config.get("remediation", {})
        self._block_brute = cfg.get("auto_block_brute_force", False)
        self._block_c2 = cfg.get("auto_block_c2", False)
        self._kill_suspicious = cfg.get("auto_kill_suspicious", False)
        self._blocked: Set[str] = set()

    def process_event(self, event: SecurityEvent) -> None:
        """Evaluate an event and apply configured remediation."""

        if event.event_type == EventType.LOGIN_BRUTE and self._block_brute:
            ip = event.details.get("src_ip") or event.source
            if ip and ip not in self._blocked:
                self._block(ip, event, "brute force login")

        elif event.event_type == EventType.THREAT_IP and self._block_c2:
            ip = event.details.get("remote_ip", "")
            if ip and ip not in self._blocked:
                self._block(ip, event, "confirmed malicious IP")

        elif event.event_type == EventType.PROC_SUSPICIOUS and self._kill_suspicious:
            pid = event.details.get("pid")
            if pid:
                self._kill(pid, event)

    # ------------------------------------------------------------------

    def _block(self, ip: str, trigger: SecurityEvent, reason: str):
        success, msg = firewall_manager.block_ip(ip)
        self._blocked.add(ip)
        trigger.remediated = True
        event_queue.put(SecurityEvent(
            timestamp=datetime.now(),
            event_type=EventType.FIREWALL_BLOCK,
            severity=Severity.HIGH,
            source="remediator",
            description=f"Auto-blocked {ip}: {reason} [{msg}]",
            details={"ip": ip, "reason": reason, "success": success},
        ))

    def _kill(self, pid: int, trigger: SecurityEvent):
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            proc.kill()
            trigger.remediated = True
            event_queue.put(SecurityEvent(
                timestamp=datetime.now(),
                event_type=EventType.PROCESS_KILL,
                severity=Severity.HIGH,
                source="remediator",
                description=f"Auto-killed: {name} (PID {pid})",
                details={"pid": pid, "name": name},
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            logger.warning("Could not kill PID %d: %s", pid, exc)
