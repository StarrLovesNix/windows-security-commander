"""
baseline.py - Security baseline capture and deviation detection.

Run with --baseline to snapshot the system's normal state.
On subsequent starts the current state is compared to baseline and
any new listening ports, scheduled tasks, or local users trigger events.

Baseline covers:
  - Listening TCP/UDP ports
  - Running Windows services
  - Scheduled tasks (non-disabled)
  - Local user accounts
  - Startup programs (Win32_StartupCommand)
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import psutil

from .events import EventType, SecurityEvent, Severity, event_queue
from .subprocess_utils import run_hidden

logger = logging.getLogger(__name__)


def _ps(command: str, timeout: int = 20) -> List[str]:
    """Run a PowerShell command that returns a JSON string list."""
    try:
        r = run_hidden(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            timeout=timeout,
        )
        if r.returncode == 0 and r.stdout.strip():
            data = json.loads(r.stdout.strip())
            if isinstance(data, list):
                return [str(x) for x in data]
            return [str(data)]
    except Exception as exc:
        logger.debug("PowerShell query failed: %s", exc)
    return []


class Baseline:
    def __init__(self, config: dict, data_dir: Path):
        self._path = data_dir / "baseline.json"
        self._data: Dict[str, Any] = {}

    def exists(self) -> bool:
        return self._path.exists()

    def capture(self) -> Dict[str, Any]:
        """Snapshot current state and write baseline.json."""
        data = {
            "captured_at": datetime.now().isoformat(),
            "listening_ports": self._listening_ports(),
            "services": self._services(),
            "scheduled_tasks": self._scheduled_tasks(),
            "local_users": self._local_users(),
            "startup_programs": self._startup_programs(),
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(data, indent=2))
        self._data = data
        logger.info(
            "Baseline captured: %d ports, %d services, %d tasks, %d users",
            len(data["listening_ports"]), len(data["services"]),
            len(data["scheduled_tasks"]), len(data["local_users"]),
        )
        return data

    def load(self) -> bool:
        try:
            self._data = json.loads(self._path.read_text())
            return True
        except Exception as exc:
            logger.warning("Could not load baseline: %s", exc)
            return False

    def compare(self) -> List[SecurityEvent]:
        """
        Compare current state to baseline. Emits deviation events and
        returns them as a list. Safe to call even if baseline is absent.
        """
        if not self._data:
            return []

        events: List[SecurityEvent] = []

        def _deviation(desc: str, detail_key: str, detail_val: Any, sev: Severity):
            ev = SecurityEvent(
                timestamp=datetime.now(),
                event_type=EventType.BASELINE_DEV,
                severity=sev,
                source="baseline",
                description=desc,
                details={"deviation": detail_key, detail_key: detail_val},
            )
            events.append(ev)
            event_queue.put(ev)

        current_ports = set(self._listening_ports())
        baseline_ports = set(self._data.get("listening_ports", []))
        for port in sorted(current_ports - baseline_ports):
            _deviation(f"New listening port since baseline: {port}",
                       "port", port, Severity.MEDIUM)

        current_tasks = set(self._scheduled_tasks())
        baseline_tasks = set(self._data.get("scheduled_tasks", []))
        for task in sorted(current_tasks - baseline_tasks):
            _deviation(f"New scheduled task since baseline: {task}",
                       "task", task, Severity.MEDIUM)

        current_users = set(self._local_users())
        baseline_users = set(self._data.get("local_users", []))
        for user in sorted(current_users - baseline_users):
            _deviation(f"New local user account since baseline: {user}",
                       "user", user, Severity.HIGH)

        return events

    # ------------------------------------------------------------------

    def _listening_ports(self) -> List[int]:
        ports = set()
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == "LISTEN" and c.laddr:
                    ports.add(c.laddr.port)
        except Exception:
            pass
        return sorted(ports)

    def _services(self) -> List[str]:
        return _ps(
            'Get-Service | Where-Object {$_.Status -eq "Running"} '
            '| Select-Object -ExpandProperty Name | Sort-Object '
            '| ConvertTo-Json -Compress'
        )

    def _scheduled_tasks(self) -> List[str]:
        return _ps(
            'Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} '
            '| Select-Object -ExpandProperty TaskName | Sort-Object '
            '| ConvertTo-Json -Compress'
        )

    def _local_users(self) -> List[str]:
        return _ps(
            'Get-LocalUser | Select-Object -ExpandProperty Name | Sort-Object '
            '| ConvertTo-Json -Compress'
        )

    def _startup_programs(self) -> List[str]:
        return _ps(
            'Get-CimInstance Win32_StartupCommand '
            '| Select-Object -ExpandProperty Name | Sort-Object '
            '| ConvertTo-Json -Compress'
        )
